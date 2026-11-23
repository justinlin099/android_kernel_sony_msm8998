// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/kmemleak.h>

/* non-mmap()'able part of bpf_ringbuf (everything up to consumer page) */
#define RINGBUF_PGOFF \
	(offsetof(struct bpf_ringbuf, consumer_pos) >> PAGE_SHIFT)
/* consumer page and producer page */
#define RINGBUF_POS_PAGES 2

/* Maximum size of ring buffer area is limited by 32-bit page offset within
 * record header, counted in pages. Reserve 8 bits for extensibility, and take
 * into account few extra pages for consumer/producer pages and
 * non-mmap()'able parts. This gives 64GB limit, which seems plenty for single
 * ring buffer.
 */
#define RINGBUF_MAX_DATA_SZ \
	(((1ULL << 24) - RINGBUF_POS_PAGES - RINGBUF_PGOFF) * PAGE_SIZE)

struct bpf_ringbuf {
	wait_queue_head_t waitq;
	u64 mask;
	struct page **pages;
	int nr_pages;
	/* Consumer and producer counters are put into separate pages to allow
	 * mapping consumer page as r/w, but restrict producer page to r/o.
	 * This protects producer position from being modified by user-space
	 * application and ruining in-kernel position tracking.
	 */
	unsigned long consumer_pos __aligned(PAGE_SIZE);
	unsigned long producer_pos __aligned(PAGE_SIZE);
	char data[] __aligned(PAGE_SIZE);
};

struct bpf_ringbuf_map {
	struct bpf_map map;
	struct bpf_ringbuf *rb;
};

static struct bpf_ringbuf *bpf_ringbuf_area_alloc(size_t data_sz)
{
	const gfp_t flags = GFP_KERNEL | __GFP_NORETRY | __GFP_NOWARN |
			    __GFP_ZERO;
	int nr_meta_pages = RINGBUF_PGOFF + RINGBUF_POS_PAGES;
	int nr_data_pages = data_sz >> PAGE_SHIFT;
	int nr_pages = nr_meta_pages + nr_data_pages;
	struct page **pages, *page;
	struct bpf_ringbuf *rb;
	size_t array_size;
	int i;

	/* Each data page is mapped twice to allow "virtual"
	 * continuous read of samples wrapping around the end of ring
	 * buffer area:
	 * ------------------------------------------------------
	 * | meta pages |  real data pages  |  same data pages  |
	 * ------------------------------------------------------
	 * |            | 1 2 3 4 5 6 7 8 9 | 1 2 3 4 5 6 7 8 9 |
	 * ------------------------------------------------------
	 * |            | TA             DA | TA             DA |
	 * ------------------------------------------------------
	 *                               ^^^^^^^
	 *                                  |
	 * Here, no need to worry about special handling of wrapped-around
	 * data due to double-mapped data pages. This works both in kernel and
	 * when mmap()'ed in user-space, simplifying both kernel and
	 * user-space implementations significantly.
	 */
	array_size = (nr_meta_pages + 2 * nr_data_pages) * sizeof(*pages);
	pages = bpf_map_area_alloc(array_size);
	if (!pages)
		return NULL;

	for (i = 0; i < nr_pages; i++) {
		page = alloc_page(flags);
		if (!page) {
			nr_pages = i;
			goto err_free_pages;
		}
		pages[i] = page;
		if (i >= nr_meta_pages)
			pages[nr_data_pages + i] = page;
	}

	rb = vmap(pages, nr_meta_pages + 2 * nr_data_pages,
		  VM_MAP | VM_USERMAP, PAGE_KERNEL);
	if (rb) {
		kmemleak_not_leak(pages);
		rb->pages = pages;
		rb->nr_pages = nr_pages;
		return rb;
	}

err_free_pages:
	for (i = 0; i < nr_pages; i++)
		__free_page(pages[i]);
	kvfree(pages);
	return NULL;
}

static struct bpf_map *ringbuf_map_alloc(union bpf_attr *attr)
{
	struct bpf_ringbuf_map *rb_map;
	u32 data_pages, meta_pages = RINGBUF_PGOFF + RINGBUF_POS_PAGES;
	u64 cost;
	int err;

	if (!capable(CAP_SYS_ADMIN))
		return ERR_PTR(-EPERM);
	if (attr->map_flags || attr->key_size || attr->value_size ||
	    !is_power_of_2(attr->max_entries) ||
	    !PAGE_ALIGNED(attr->max_entries))
		return ERR_PTR(-EINVAL);

#ifdef CONFIG_64BIT
	/* The record header's page offset is limited to 24 bits. */
	if (attr->max_entries > RINGBUF_MAX_DATA_SZ)
		return ERR_PTR(-E2BIG);
#endif

	data_pages = attr->max_entries >> PAGE_SHIFT;
	cost = sizeof(*rb_map) + ((u64)meta_pages + data_pages) * PAGE_SIZE +
	       ((u64)meta_pages + 2 * data_pages) * sizeof(struct page *);
	err = bpf_map_precharge_memlock(DIV_ROUND_UP_ULL(cost, PAGE_SIZE));
	if (err)
		return ERR_PTR(err);

	rb_map = kzalloc(sizeof(*rb_map), GFP_USER);
	if (!rb_map)
		return ERR_PTR(-ENOMEM);

	rb_map->rb = bpf_ringbuf_area_alloc(attr->max_entries);
	if (!rb_map->rb) {
		kfree(rb_map);
		return ERR_PTR(-ENOMEM);
	}

	init_waitqueue_head(&rb_map->rb->waitq);
	rb_map->rb->mask = attr->max_entries - 1;
	rb_map->map.max_entries = attr->max_entries;
	rb_map->map.pages = DIV_ROUND_UP_ULL(cost, PAGE_SIZE);
	return &rb_map->map;
}

static void bpf_ringbuf_free(struct bpf_ringbuf *rb)
{
	/* copy pages pointer and nr_pages to local variable, as we are going
	 * to unmap rb itself with vunmap() below
	 */
	struct page **pages = rb->pages;
	int i, nr_pages = rb->nr_pages;

	vunmap(rb);
	for (i = 0; i < nr_pages; i++)
		__free_page(pages[i]);
	kvfree(pages);
}

static void ringbuf_map_free(struct bpf_map *map)
{
	struct bpf_ringbuf_map *rb_map;

	rb_map = container_of(map, struct bpf_ringbuf_map, map);
	bpf_ringbuf_free(rb_map->rb);
	kfree(rb_map);
}

static void *ringbuf_map_lookup_elem(struct bpf_map *map, void *key)
{
	return NULL;
}

static int ringbuf_map_update_elem(struct bpf_map *map, void *key, void *value,
				   u64 flags)
{
	return -ENOTSUPP;
}

static int ringbuf_map_delete_elem(struct bpf_map *map, void *key)
{
	return -ENOTSUPP;
}

static int ringbuf_map_get_next_key(struct bpf_map *map, void *key,
				    void *next_key)
{
	return -ENOTSUPP;
}

static int ringbuf_map_mmap(struct bpf_map *map, struct vm_area_struct *vma)
{
	struct bpf_ringbuf *rb = container_of(map, struct bpf_ringbuf_map, map)->rb;
	unsigned long pgoff = vma->vm_pgoff;
	unsigned long data_pages = (rb->mask + 1) >> PAGE_SHIFT;
	unsigned long pages = RINGBUF_POS_PAGES + 2 * data_pages;

	if (!(vma->vm_flags & VM_MAYSHARE) || (vma->vm_flags & VM_EXEC))
		return -EINVAL;
	if (pgoff >= pages || vma_pages(vma) > pages - pgoff)
		return -EINVAL;

	if (vma->vm_flags & VM_WRITE) {
		/* Only the consumer position page can be writable. */
		if (pgoff || vma_pages(vma) != 1)
			return -EPERM;
	} else {
		vma->vm_flags &= ~VM_MAYWRITE;
	}
	vma->vm_flags &= ~VM_MAYEXEC;

	return remap_vmalloc_range(vma, rb, pgoff + RINGBUF_PGOFF);
}

static unsigned long ringbuf_avail_data_sz(struct bpf_ringbuf *rb)
{
	unsigned long cons_pos, prod_pos;

	cons_pos = smp_load_acquire(&rb->consumer_pos);
	prod_pos = smp_load_acquire(&rb->producer_pos);
	return prod_pos - cons_pos;
}

static unsigned int ringbuf_map_poll(struct bpf_map *map, struct file *filp,
				     struct poll_table_struct *pts)
{
	struct bpf_ringbuf_map *rb_map;

	rb_map = container_of(map, struct bpf_ringbuf_map, map);
	poll_wait(filp, &rb_map->rb->waitq, pts);

	if (ringbuf_avail_data_sz(rb_map->rb))
		return POLLIN | POLLRDNORM;
	return 0;
}

static const struct bpf_map_ops ringbuf_map_ops = {
	.map_alloc = ringbuf_map_alloc,
	.map_free = ringbuf_map_free,
	.map_mmap = ringbuf_map_mmap,
	.map_poll = ringbuf_map_poll,
	.map_lookup_elem = ringbuf_map_lookup_elem,
	.map_update_elem = ringbuf_map_update_elem,
	.map_delete_elem = ringbuf_map_delete_elem,
	.map_get_next_key = ringbuf_map_get_next_key,
};

static struct bpf_map_type_list ringbuf_map_type = {
	.ops = &ringbuf_map_ops,
	.type = BPF_MAP_TYPE_RINGBUF,
};

static int __init ringbuf_map_init(void)
{
	bpf_register_map_type(&ringbuf_map_type);
	return 0;
}
late_initcall(ringbuf_map_init);
