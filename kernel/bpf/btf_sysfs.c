// SPDX-License-Identifier: GPL-2.0-only
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>

extern const char __start_BTF[];
extern const char __stop_BTF[];

static ssize_t btf_vmlinux_read(struct file *file, struct kobject *kobj,
				struct bin_attribute *attr, char *buf,
				loff_t offset, size_t count)
{
	return memory_read_from_buffer(buf, count, &offset, __start_BTF, attr->size);
}

static struct bin_attribute btf_vmlinux = {
	.attr = { .name = "vmlinux", .mode = 0444 },
	.read = btf_vmlinux_read,
};

static int __init btf_sysfs_init(void)
{
	struct kobject *kobj;
	int err;

	btf_vmlinux.size = __stop_BTF - __start_BTF;
	if (!btf_vmlinux.size)
		return -EINVAL;

	kobj = kobject_create_and_add("btf", kernel_kobj);
	if (!kobj)
		return -ENOMEM;

	err = sysfs_create_bin_file(kobj, &btf_vmlinux);
	if (err)
		kobject_put(kobj);
	return err;
}
late_initcall(btf_sysfs_init);
