// SPDX-License-Identifier: GPL-2.0-only
#include <crypto/hash.h>
#include <crypto/sha.h>
#include <linux/bpf.h>
#include <linux/cache.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/vmalloc.h>
#include <linux/xz.h>

struct btf_initramfs_ref {
	u32 raw_size;
	u32 compressed_size;
	u8 sha256[SHA256_DIGEST_SIZE];
};

extern const struct btf_initramfs_ref __start_BTF_ref;

static const char *vmlinux_btf __ro_after_init;
static u32 vmlinux_btf_size __ro_after_init;

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
	const struct vmlinux_btf_header *header = (const void *)vmlinux_btf;
	size_t size = vmlinux_btf_size, name_len = strlen(name) + 1;
	const char *type, *end, *strings;
	u32 id;

	if (size < sizeof(*header) || header->magic != 0xeb9f ||
	    header->version != 1 || header->flags ||
	    header->header_len < sizeof(*header) ||
	    (header->header_len | header->type_offset) & 3 ||
	    (u64)header->header_len + header->type_offset + header->type_len > size ||
	    (u64)header->header_len + header->string_offset + header->string_len > size)
		return 0;

	type = vmlinux_btf + header->header_len + header->type_offset;
	end = type + header->type_len;
	strings = vmlinux_btf + header->header_len + header->string_offset;
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
	return memory_read_from_buffer(buf, count, &offset, vmlinux_btf, attr->size);
}

static struct bin_attribute btf_vmlinux = {
	.attr = { .name = "vmlinux", .mode = 0444 },
	.read = btf_vmlinux_read,
};

static int __init btf_verify_digest(const char *buffer, u32 size,
				   const u8 *expected)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	u8 digest[SHA256_DIGEST_SIZE];
	int err;

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		err = -ENOMEM;
		goto out;
	}
	desc->tfm = tfm;
	desc->flags = 0;
	err = crypto_shash_digest(desc, buffer, size, digest);
	if (!err && memcmp(digest, expected, sizeof(digest)))
		err = -EBADMSG;
	kfree(desc);
out:
	crypto_free_shash(tfm);
	return err;
}

static int __init btf_read_initramfs(void *encoded, u32 size)
{
	struct file *file;
	loff_t position = 0;
	int err = 0;

	file = filp_open("/.lilac-vmlinux.btf.xz", O_RDONLY | O_NOFOLLOW, 0);
	if (IS_ERR(file))
		return PTR_ERR(file);
	if (!S_ISREG(file_inode(file)->i_mode) ||
	    i_size_read(file_inode(file)) != size) {
		err = -EINVAL;
		goto close;
	}
	while (position < size) {
		ssize_t read = kernel_read(file, (char *)encoded + position,
					   size - position, &position);

		if (read <= 0) {
			err = read ? read : -EIO;
			break;
		}
	}
close:
	filp_close(file, NULL);
	return err;
}

static int __init btf_sysfs_init(void)
{
	const struct btf_initramfs_ref *ref = &__start_BTF_ref;
	struct xz_dec *decoder;
	struct kobject *kobj;
	struct xz_buf stream;
	void *encoded;
	void *buffer;
	enum xz_ret result;
	int err;

	if (!ref->raw_size || ref->raw_size > SZ_64M ||
	    !ref->compressed_size || ref->compressed_size > ref->raw_size)
		return -EINVAL;

	encoded = vmalloc(ref->compressed_size);
	if (!encoded)
		return -ENOMEM;
	err = btf_read_initramfs(encoded, ref->compressed_size);
	if (err)
		goto free_encoded;

	buffer = vmalloc(ref->raw_size);
	if (!buffer) {
		err = -ENOMEM;
		goto free_encoded;
	}
	decoder = xz_dec_init(XZ_SINGLE, 0);
	if (!decoder) {
		err = -ENOMEM;
		goto free_buffer;
	}
	stream = (struct xz_buf) {
		.in = encoded,
		.in_size = ref->compressed_size,
		.out = buffer,
		.out_size = ref->raw_size,
	};
	result = xz_dec_run(decoder, &stream);
	xz_dec_end(decoder);
	if (result != XZ_STREAM_END || stream.in_pos != stream.in_size ||
	    stream.out_pos != ref->raw_size) {
		err = -EINVAL;
		goto free_buffer;
	}
	err = btf_verify_digest(buffer, ref->raw_size, ref->sha256);
	if (err)
		goto free_buffer;

	kobj = kobject_create_and_add("btf", kernel_kobj);
	if (!kobj) {
		err = -ENOMEM;
		goto free_buffer;
	}
	vmlinux_btf = buffer;
	vmlinux_btf_size = ref->raw_size;
	btf_vmlinux.size = ref->raw_size;
	err = sysfs_create_bin_file(kobj, &btf_vmlinux);
	if (!err)
		goto free_encoded;

	vmlinux_btf = NULL;
	vmlinux_btf_size = 0;
	kobject_put(kobj);
free_buffer:
	vfree(buffer);
free_encoded:
	vfree(encoded);
	if (err)
		pr_err("BPF: cannot publish initramfs BTF: %d\n", err);
	return err;
}
late_initcall(btf_sysfs_init);
