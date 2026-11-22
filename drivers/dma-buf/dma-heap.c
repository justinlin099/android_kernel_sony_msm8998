/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Framework for userspace DMA-BUF allocations
 *
 * Copyright (C) 2011 Google, Inc.
 * Copyright (C) 2019 Linaro Ltd.
 */

#include <linux/cdev.h>
#include <linux/compat.h>
#include <linux/device.h>
#include <linux/dma-buf.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/idr.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/dma-heap.h>
#include <uapi/linux/dma-heap.h>

#define DEVNAME "dma_heap"

#define NUM_HEAP_MINORS 128

/**
 * struct dma_heap - represents a dmabuf heap in the system
 * @name:		used for debugging/device-node name
 * @ops:		ops struct for this heap
 * @heap_devt		heap device node
 * @list		list head connecting to list of heaps
 * @heap_cdev		heap char device
 *
 * Represents a heap of memory from which buffers can be made.
 */
struct dma_heap {
	const char *name;
	const struct dma_heap_ops *ops;
	void *priv;
	dev_t heap_devt;
	struct list_head list;
	struct cdev *heap_cdev;
};

static LIST_HEAD(heap_list);
static DEFINE_MUTEX(heap_list_lock);
static dev_t dma_heap_devt;
static struct class *dma_heap_class;
static DEFINE_IDR(dma_heap_minors);

static int dma_heap_open(struct inode *inode, struct file *file)
{
	struct dma_heap *heap;

	mutex_lock(&heap_list_lock);
	heap = idr_find(&dma_heap_minors, iminor(inode));
	mutex_unlock(&heap_list_lock);
	if (!heap)
		return -ENODEV;

	file->private_data = heap;
	return nonseekable_open(inode, file);
}

static long dma_heap_ioctl(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	struct dma_heap_allocation_data data;
	struct dma_heap *heap = file->private_data;
	void __user *user = (void __user *)arg;
	struct dma_buf *buffer;
	size_t len;
	int fd;

	if (cmd != DMA_HEAP_IOCTL_ALLOC)
		return -ENOTTY;

	if (copy_from_user(&data, user, sizeof(data)))
		return -EFAULT;

	if (data.fd || !data.len || data.len > SIZE_MAX - (PAGE_SIZE - 1) ||
	    (data.fd_flags & ~DMA_HEAP_VALID_FD_FLAGS) ||
	    (data.fd_flags & O_ACCMODE) == O_ACCMODE ||
	    (data.heap_flags & ~DMA_HEAP_VALID_HEAP_FLAGS))
		return -EINVAL;

	len = PAGE_ALIGN((size_t)data.len);
	fd = get_unused_fd_flags(data.fd_flags);
	if (fd < 0)
		return fd;

	buffer = heap->ops->allocate(heap, len, data.fd_flags, data.heap_flags);
	if (IS_ERR(buffer)) {
		put_unused_fd(fd);
		return PTR_ERR(buffer);
	}

	/* Publish the fd only once userspace has received its number. */
	data.fd = fd;
	if (copy_to_user(user, &data, sizeof(data))) {
		dma_buf_put(buffer);
		put_unused_fd(fd);
		return -EFAULT;
	}

	fd_install(fd, buffer->file);
	return 0;
}

#ifdef CONFIG_COMPAT
static long dma_heap_compat_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	return dma_heap_ioctl(file, cmd, (unsigned long)compat_ptr(arg));
}
#endif

static const struct file_operations dma_heap_fops = {
	.owner          = THIS_MODULE,
	.open		= dma_heap_open,
	.unlocked_ioctl = dma_heap_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= dma_heap_compat_ioctl,
#endif
};

/**
 * dma_heap_get_drvdata() - get per-subdriver data for the heap
 * @heap: DMA-Heap to retrieve private data for
 *
 * Returns:
 * The per-subdriver data for the heap.
 */
void *dma_heap_get_drvdata(struct dma_heap *heap)
{
	return heap->priv;
}

struct dma_heap *dma_heap_add(const struct dma_heap_export_info *exp_info)
{
	struct dma_heap *heap, *entry;
	struct device *dev;
	int minor, ret;

	if (IS_ERR_OR_NULL(dma_heap_class))
		return ERR_PTR(-ENODEV);
	if (!exp_info->name || !*exp_info->name || !exp_info->ops ||
	    !exp_info->ops->allocate)
		return ERR_PTR(-EINVAL);

	heap = kzalloc(sizeof(*heap), GFP_KERNEL);
	if (!heap)
		return ERR_PTR(-ENOMEM);

	heap->name = exp_info->name;
	heap->ops = exp_info->ops;
	heap->priv = exp_info->priv;

	mutex_lock(&heap_list_lock);
	list_for_each_entry(entry, &heap_list, list) {
		if (!strcmp(entry->name, exp_info->name)) {
			ret = -EEXIST;
			goto free_heap;
		}
	}

	minor = idr_alloc(&dma_heap_minors, heap, 0, NUM_HEAP_MINORS,
			  GFP_KERNEL);
	if (minor < 0) {
		ret = minor;
		goto free_heap;
	}

	heap->heap_devt = MKDEV(MAJOR(dma_heap_devt), minor);
	heap->heap_cdev = cdev_alloc();
	if (!heap->heap_cdev) {
		ret = -ENOMEM;
		goto remove_minor;
	}
	heap->heap_cdev->ops = &dma_heap_fops;
	heap->heap_cdev->owner = THIS_MODULE;
	ret = cdev_add(heap->heap_cdev, heap->heap_devt, 1);
	if (ret)
		goto free_cdev;

	dev = device_create(dma_heap_class, NULL, heap->heap_devt, NULL,
			    "%s", heap->name);
	if (IS_ERR(dev)) {
		ret = PTR_ERR(dev);
		goto remove_cdev;
	}

	list_add(&heap->list, &heap_list);
	mutex_unlock(&heap_list_lock);
	return heap;

remove_cdev:
	cdev_del(heap->heap_cdev);
	goto remove_minor;
free_cdev:
	kobject_put(&heap->heap_cdev->kobj);
remove_minor:
	idr_remove(&dma_heap_minors, minor);
free_heap:
	mutex_unlock(&heap_list_lock);
	kfree(heap);
	return ERR_PTR(ret);
}

static char *dma_heap_devnode(struct device *dev, umode_t *mode)
{
	return kasprintf(GFP_KERNEL, "dma_heap/%s", dev_name(dev));
}

static int dma_heap_init(void)
{
	int ret;

	ret = alloc_chrdev_region(&dma_heap_devt, 0, NUM_HEAP_MINORS, DEVNAME);
	if (ret)
		return ret;

	dma_heap_class = class_create(THIS_MODULE, DEVNAME);
	if (IS_ERR(dma_heap_class)) {
		unregister_chrdev_region(dma_heap_devt, NUM_HEAP_MINORS);
		return PTR_ERR(dma_heap_class);
	}
	dma_heap_class->devnode = dma_heap_devnode;

	return 0;
}
subsys_initcall(dma_heap_init);
