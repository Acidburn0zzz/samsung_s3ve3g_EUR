/*
 * drivers/gpu/ion/ion_mem_pool.c
 *
 * Copyright (C) 2011 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/debugfs.h>
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/swap.h>
#include "ion_priv.h"

struct ion_page_pool_item {
	struct page *page;
	struct list_head list;
};

static void *ion_page_pool_alloc_pages(struct ion_page_pool *pool)
{
	struct page *page;

	page = alloc_pages(pool->gfp_mask & ~__GFP_ZERO, pool->order);

	if (!page)
		return NULL;

	if (pool->gfp_mask & __GFP_ZERO)
		if (ion_heap_high_order_page_zero(page, pool->order))
			goto error_free_pages;

	return page;
error_free_pages:
	__free_pages(page, pool->order);
	return NULL;
}

static void ion_page_pool_free_pages(struct ion_page_pool *pool,
				     struct page *page)
{
	__free_pages(page, pool->order);
}

static int ion_page_pool_add(struct ion_page_pool *pool, struct page *page)
{
	struct ion_page_pool_item *item;

	item = kmalloc(sizeof(struct ion_page_pool_item), GFP_KERNEL);
	if (!item)
		return -ENOMEM;

	mutex_lock(&pool->mutex);
	item->page = page;
	if (PageHighMem(page)) {
		list_add_tail(&item->list, &pool->high_items);
		pool->high_count++;
	} else {
		list_add_tail(&item->list, &pool->low_items);
		pool->low_count++;
	}
	mutex_unlock(&pool->mutex);
	return 0;
}

static struct page *ion_page_pool_remove(struct ion_page_pool *pool, bool high)
{
	struct ion_page_pool_item *item;
	struct page *page;

	if (high) {
		BUG_ON(!pool->high_count);
		item = list_first_entry(&pool->high_items,
					struct ion_page_pool_item, list);
		pool->high_count--;
	} else {
		BUG_ON(!pool->low_count);
		item = list_first_entry(&pool->low_items,
					struct ion_page_pool_item, list);
		pool->low_count--;
	}

	list_del(&item->list);
	page = item->page;
	kfree(item);
	return page;
}

void *ion_page_pool_alloc(struct ion_page_pool *pool, bool *from_pool)
{
	struct page *page = NULL;

	BUG_ON(!pool);

	*from_pool = true;

	if (mutex_trylock(&pool->mutex)) {
		if (pool->high_count)
			page = ion_page_pool_remove(pool, true);
		else if (pool->low_count)
			page = ion_page_pool_remove(pool, false);
		mutex_unlock(&pool->mutex);
	}
	if (!page) {
		page = ion_page_pool_alloc_pages(pool);
		*from_pool = false;
	}
	return page;
}

void ion_page_pool_free(struct ion_page_pool *pool, struct page* page)
{
	int ret;

	ret = ion_page_pool_add(pool, page);
	if (ret)
		ion_page_pool_free_pages(pool, page);
}

static int ion_page_pool_total(struct ion_page_pool *pool, bool high)
{
	int total = 0;

	total += high ? (pool->high_count + pool->low_count) *
		(1 << pool->order) :
			pool->low_count * (1 << pool->order);
	return total;
}

int ion_page_pool_shrink(struct ion_page_pool *pool, gfp_t gfp_mask,
				int nr_to_scan)
{
	int nr_freed = 0;
	int i;
	bool high;

	high = gfp_mask & __GFP_HIGHMEM;

	if (current_is_kswapd())
		high = 1;

	if (nr_to_scan == 0)
		return ion_page_pool_total(pool, high);

	for (i = 0; i < nr_to_scan; i++) {
		struct page *page;

		mutex_lock(&pool->mutex);
		if (high && pool->high_count) {
			page = ion_page_pool_remove(pool, true);
		} else if (pool->low_count) {
			page = ion_page_pool_remove(pool, false);
		} else {
			mutex_unlock(&pool->mutex);
			break;
		}
		mutex_unlock(&pool->mutex);
		ion_page_pool_free_pages(pool, page);
		nr_freed += (1 << pool->order);
	}

	return nr_freed;
}

struct ion_page_pool *ion_page_pool_create(gfp_t gfp_mask, unsigned int order)
{
	struct ion_page_pool *pool = kmalloc(sizeof(struct ion_page_pool),
					     GFP_KERNEL);
	if (!pool)
		return NULL;
	pool->high_count = 0;
	pool->low_count = 0;
	INIT_LIST_HEAD(&pool->low_items);
	INIT_LIST_HEAD(&pool->high_items);
	pool->gfp_mask = gfp_mask;
	pool->order = order;
	mutex_init(&pool->mutex);
	plist_node_init(&pool->list, order);

	return pool;
}

void ion_page_pool_destroy(struct ion_page_pool *pool)
{
	kfree(pool);
}

static int __init ion_page_pool_init(void)
{
	return 0;
}

static void __exit ion_page_pool_exit(void)
{
}

module_init(ion_page_pool_init);
module_exit(ion_page_pool_exit);
/*
 * drivers/gpu/ion/ion_heap.c
 *
 * Copyright (C) 2011 Google, Inc.
 * Copyright (c) 2011-2014, The Linux Foundation. All rights reserved.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/err.h>
#include <linux/freezer.h>
#include <linux/ion.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/rtmutex.h>
#include <linux/sched.h>
#include <linux/scatterlist.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/dma-mapping.h>
#include "ion_priv.h"

void *ion_heap_map_kernel(struct ion_heap *heap,
			  struct ion_buffer *buffer)
{
	struct scatterlist *sg;
	int i, j;
	void *vaddr;
	pgprot_t pgprot;
	struct sg_table *table = buffer->sg_table;
	int npages = PAGE_ALIGN(buffer->size) / PAGE_SIZE;
	struct page **pages = vmalloc(sizeof(struct page *) * npages);
	struct page **tmp = pages;

	if (!pages)
		return 0;

	if (buffer->flags & ION_FLAG_CACHED)
		pgprot = PAGE_KERNEL;
	else
		pgprot = pgprot_writecombine(PAGE_KERNEL);

	for_each_sg(table->sgl, sg, table->nents, i) {
		int npages_this_entry = PAGE_ALIGN(sg_dma_len(sg)) / PAGE_SIZE;
		struct page *page = sg_page(sg);
		BUG_ON(i >= npages);
		for (j = 0; j < npages_this_entry; j++) {
			*(tmp++) = page++;
		}
	}
	vaddr = vmap(pages, npages, VM_MAP, pgprot);
	vfree(pages);

	return vaddr;
}

void ion_heap_unmap_kernel(struct ion_heap *heap,
			   struct ion_buffer *buffer)
{
	vunmap(buffer->vaddr);
}

int ion_heap_map_user(struct ion_heap *heap, struct ion_buffer *buffer,
		      struct vm_area_struct *vma)
{
	struct sg_table *table = buffer->sg_table;
	unsigned long addr = vma->vm_start;
	unsigned long offset = vma->vm_pgoff * PAGE_SIZE;
	struct scatterlist *sg;
	int i;

#ifdef CONFIG_TIMA_RKP
        if (buffer->size) {
        /* iommu optimization- needs to be turned ON from
         * the tz side.
         */
                cpu_v7_tima_iommu_opt(vma->vm_start, vma->vm_end, (unsigned long)vma->vm_mm->pgd);
                __asm__ __volatile__ (
                "mcr    p15, 0, r0, c8, c3, 0\n"
                "dsb\n"
                "isb\n");
        }
#endif
	for_each_sg(table->sgl, sg, table->nents, i) {
		struct page *page = sg_page(sg);
		unsigned long remainder = vma->vm_end - addr;
		unsigned long len = sg_dma_len(sg);

		if (offset >= sg_dma_len(sg)) {
			offset -= sg_dma_len(sg);
			continue;
		} else if (offset) {
			page += offset / PAGE_SIZE;
			len = sg_dma_len(sg) - offset;
			offset = 0;
		}
		len = min(len, remainder);
		remap_pfn_range(vma, addr, page_to_pfn(page), len,
				vma->vm_page_prot);
		addr += len;
		if (addr >= vma->vm_end)
			return 0;
	}
	return 0;
}

#define MAX_VMAP_RETRIES 10

/**
 * An optimized page-zero'ing function. vmaps arrays of pages in large
 * chunks to minimize the number of memsets and vmaps/vunmaps.
 *
 * Note that the `pages' array should be composed of all 4K pages.
 *
 * NOTE: This function does not guarantee synchronization of the caches
 * and thus caller is responsible for handling any cache maintenance
 * operations needed.
 */
int ion_heap_pages_zero(struct page **pages, int num_pages)
{
	int i, j, npages_to_vmap;
	void *ptr = NULL;

	/*
	 * As an optimization, we manually zero out all of the pages
	 * in one fell swoop here. To safeguard against insufficient
	 * vmalloc space, we only vmap `npages_to_vmap' at a time,
	 * starting with a conservative estimate of 1/8 of the total
	 * number of vmalloc pages available.
	 */
	npages_to_vmap = ((VMALLOC_END - VMALLOC_START)/8)
			>> PAGE_SHIFT;
	for (i = 0; i < num_pages; i += npages_to_vmap) {
		npages_to_vmap = min(npages_to_vmap, num_pages - i);
		for (j = 0; j < MAX_VMAP_RETRIES && npages_to_vmap;
			++j) {
			ptr = vmap(&pages[i], npages_to_vmap,
					VM_IOREMAP, PAGE_KERNEL);
			if (ptr)
				break;
			else
				npages_to_vmap >>= 1;
		}
		if (!ptr)
			return -ENOMEM;

		memset(ptr, 0, npages_to_vmap * PAGE_SIZE);
		vunmap(ptr);
	}

	return 0;
}

int ion_heap_alloc_pages_mem(struct pages_mem *pages_mem)
{
	struct page **pages;
	unsigned int page_tbl_size;
	pages_mem->free_fn = kfree;
	page_tbl_size = sizeof(struct page *) * (pages_mem->size >> PAGE_SHIFT);
	if (page_tbl_size > SZ_8K) {
		/*
		 * Do fallback to ensure we have a balance between
		 * performance and availability.
		 */
		pages = kmalloc(page_tbl_size,
				__GFP_COMP | __GFP_NORETRY |
				__GFP_NO_KSWAPD | __GFP_NOWARN);
		if (!pages) {
			pages = vmalloc(page_tbl_size);
			pages_mem->free_fn = vfree;
		}
	} else {
		pages = kmalloc(page_tbl_size, GFP_KERNEL);
	}

	if (!pages)
		return -ENOMEM;

	pages_mem->pages = pages;
	return 0;
}

void ion_heap_free_pages_mem(struct pages_mem *pages_mem)
{
	pages_mem->free_fn(pages_mem->pages);
}

int ion_heap_high_order_page_zero(struct page *page, int order)
{
	int i, ret;
	struct pages_mem pages_mem;
	int npages = 1 << order;
	pages_mem.size = npages * PAGE_SIZE;

	if (ion_heap_alloc_pages_mem(&pages_mem))
		return -ENOMEM;

	for (i = 0; i < (1 << order); ++i)
		pages_mem.pages[i] = page + i;

	ret = ion_heap_pages_zero(pages_mem.pages, npages);
	dma_sync_single_for_device(NULL, page_to_phys(page), pages_mem.size,
					DMA_BIDIRECTIONAL);
	ion_heap_free_pages_mem(&pages_mem);
	return ret;
}

int ion_heap_buffer_zero(struct ion_buffer *buffer)
{
	struct sg_table *table = buffer->sg_table;
	struct scatterlist *sg;
	int i, j, ret = 0, npages = 0;
	struct pages_mem pages_mem;

	pages_mem.size = PAGE_ALIGN(buffer->size);

	if (ion_heap_alloc_pages_mem(&pages_mem))
		return -ENOMEM;

	for_each_sg(table->sgl, sg, table->nents, i) {
		struct page *page = sg_page(sg);
		unsigned long len = sg_dma_len(sg);

		for (j = 0; j < len / PAGE_SIZE; j++)
			pages_mem.pages[npages++] = page + j;
	}

	ret = ion_heap_pages_zero(pages_mem.pages, npages);
	dma_sync_sg_for_device(NULL, table->sgl, table->nents,
					DMA_BIDIRECTIONAL);
	ion_heap_free_pages_mem(&pages_mem);
	return ret;
}

void ion_heap_free_page(struct ion_buffer *buffer, struct page *page,
		       unsigned int order)
{
	int i;

	if (!ion_buffer_fault_user_mappings(buffer)) {
		__free_pages(page, order);
		return;
	}
	for (i = 0; i < (1 << order); i++)
		__free_page(page + i);
}

void ion_heap_freelist_add(struct ion_heap *heap, struct ion_buffer * buffer)
{
	rt_mutex_lock(&heap->lock);
	list_add(&buffer->list, &heap->free_list);
	heap->free_list_size += buffer->size;
	rt_mutex_unlock(&heap->lock);
	wake_up(&heap->waitqueue);
}

size_t ion_heap_freelist_size(struct ion_heap *heap)
{
	size_t size;

	rt_mutex_lock(&heap->lock);
	size = heap->free_list_size;
	rt_mutex_unlock(&heap->lock);

	return size;
}

static size_t _ion_heap_freelist_drain(struct ion_heap *heap, size_t size,
				bool skip_pools)
{
	struct ion_buffer *buffer;
	size_t total_drained = 0;

	if (ion_heap_freelist_size(heap) == 0)
		return 0;

	if (size == 0)
		size = ion_heap_freelist_size(heap);
	
	while (true) {
		rt_mutex_lock(&heap->lock);
		if (list_empty(&heap->free_list) || total_drained >= size ) {
			rt_mutex_unlock(&heap->lock);
			break;
		}
		buffer = list_first_entry(&heap->free_list, struct ion_buffer,
				  list);
		list_del(&buffer->list);
		heap->free_list_size -= buffer->size;
		total_drained += buffer->size;
		if (skip_pools)
			buffer->flags |= ION_FLAG_FREED_FROM_SHRINKER;
		rt_mutex_unlock(&heap->lock);
		ion_buffer_destroy(buffer);
	}

	return total_drained;
}

size_t ion_heap_freelist_drain(struct ion_heap *heap, size_t size)
{
	return _ion_heap_freelist_drain(heap, size, false);
}

size_t ion_heap_freelist_drain_from_shrinker(struct ion_heap *heap, size_t size)
{
	return _ion_heap_freelist_drain(heap, size, true);
}

int ion_heap_deferred_free(void *data)
{
	struct ion_heap *heap = data;

	while (true) {
		struct ion_buffer *buffer;

		wait_event_freezable(heap->waitqueue,
				     ion_heap_freelist_size(heap) > 0);

		rt_mutex_lock(&heap->lock);
		if (list_empty(&heap->free_list)) {
			rt_mutex_unlock(&heap->lock);
			continue;
		}
		buffer = list_first_entry(&heap->free_list, struct ion_buffer,
					  list);
		list_del(&buffer->list);
		heap->free_list_size -= buffer->size;
		rt_mutex_unlock(&heap->lock);
		ion_buffer_destroy(buffer);
	}

	return 0;
}

int ion_heap_init_deferred_free(struct ion_heap *heap)
{
	struct sched_param param = { .sched_priority = 0 };

	INIT_LIST_HEAD(&heap->free_list);
	heap->free_list_size = 0;
	rt_mutex_init(&heap->lock);
	init_waitqueue_head(&heap->waitqueue);
	heap->task = kthread_run(ion_heap_deferred_free, heap,
				 "%s", heap->name);
	sched_setscheduler(heap->task, SCHED_IDLE, &param);
	if (IS_ERR(heap->task)) {
		pr_err("%s: creating thread for deferred free failed\n",
		       __func__);
		return PTR_RET(heap->task);
	}
	return 0;
}

struct ion_heap *ion_heap_create(struct ion_platform_heap *heap_data)
{
	struct ion_heap *heap = NULL;

	switch (heap_data->type) {
	case ION_HEAP_TYPE_SYSTEM_CONTIG:
		heap = ion_system_contig_heap_create(heap_data);
		break;
	case ION_HEAP_TYPE_SYSTEM:
		heap = ion_system_heap_create(heap_data);
		break;
	case ION_HEAP_TYPE_CARVEOUT:
		heap = ion_carveout_heap_create(heap_data);
		break;
	case ION_HEAP_TYPE_CHUNK:
		heap = ion_chunk_heap_create(heap_data);
		break;
	default:
		pr_err("%s: Invalid heap type %d\n", __func__,
		       heap_data->type);
		return ERR_PTR(-EINVAL);
	}

	if (IS_ERR_OR_NULL(heap)) {
		pr_err("%s: error creating heap %s type %d base %pa size %u\n",
		       __func__, heap_data->name, heap_data->type,
		       &heap_data->base, heap_data->size);
		return ERR_PTR(-EINVAL);
	}

	heap->name = heap_data->name;
	heap->id = heap_data->id;
	heap->priv = heap_data->priv;
	return heap;
}

void ion_heap_destroy(struct ion_heap *heap)
{
	if (!heap)
		return;

	switch (heap->type) {
	case ION_HEAP_TYPE_SYSTEM_CONTIG:
		ion_system_contig_heap_destroy(heap);
		break;
	case ION_HEAP_TYPE_SYSTEM:
		ion_system_heap_destroy(heap);
		break;
	case ION_HEAP_TYPE_CARVEOUT:
		ion_carveout_heap_destroy(heap);
		break;
	case ION_HEAP_TYPE_CHUNK:
		ion_chunk_heap_destroy(heap);
		break;
	default:
		pr_err("%s: Invalid heap type %d\n", __func__,
		       heap->type);
	}
}

