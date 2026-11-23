// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>

extern const char __start_BTF[];
extern const char __stop_BTF[];

#ifdef CONFIG_BPF_DMABUF_ITER
/* BTF v1 records in the native-endian image produced by pahole. */
struct vmlinux_btf_header {
	u16 magic;
	u8 version;
	u8 flags;
	u32 header_len;
	u32 type_offset;
	u32 type_len;
	u32 string_offset;
	u32 string_len;
};

struct vmlinux_btf_type {
	u32 name_offset;
	u32 info;
	u32 size_type;
};

static int btf_type_tail_size(u32 kind, u32 vlen)
{
	switch (kind) {
	case 1:  /* int */
	case 14: /* var */
	case 17: /* decl_tag */
		return 4;
	case 3:  /* array */
		return 12;
	case 4:  /* struct */
	case 5:  /* union */
	case 15: /* datasec */
	case 19: /* enum64 */
		return vlen * 12;
	case 6:  /* enum */
	case 13: /* func_proto */
		return vlen * 8;
	case 2:  /* ptr */
	case 7:  /* fwd */
	case 8:  /* typedef */
	case 9:  /* volatile */
	case 10: /* const */
	case 11: /* restrict */
	case 12: /* func */
	case 16: /* float */
	case 18: /* type_tag */
		return 0;
	default:
		return -EINVAL;
	}
}

u32 bpf_vmlinux_btf_func_id(const char *name)
{
	const struct vmlinux_btf_header *header = (const void *)__start_BTF;
	size_t size = __stop_BTF - __start_BTF, name_len = strlen(name) + 1;
	const char *type, *end, *strings;
	u32 id;

	if (size < sizeof(*header) || header->magic != 0xeb9f ||
	    header->version != 1 || header->flags ||
	    header->header_len < sizeof(*header) ||
	    (header->header_len | header->type_offset) & 3 ||
	    (u64)header->header_len + header->type_offset + header->type_len > size ||
	    (u64)header->header_len + header->string_offset + header->string_len > size)
		return 0;

	type = __start_BTF + header->header_len + header->type_offset;
	end = type + header->type_len;
	strings = __start_BTF + header->header_len + header->string_offset;
	for (id = 1; end - type >= sizeof(struct vmlinux_btf_type); id++) {
		const struct vmlinux_btf_type *record = (const void *)type;
		u32 kind = (record->info >> 24) & 0x1f;
		int tail = btf_type_tail_size(kind, record->info & 0xffff);

		if (tail < 0 || tail > end - type - sizeof(*record))
			return 0;
		if (kind == 12 && record->name_offset < header->string_len &&
		    name_len <= header->string_len - record->name_offset &&
		    !memcmp(strings + record->name_offset, name, name_len))
			return id;
		type += sizeof(*record) + tail;
	}
	return 0;
}
#endif

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
