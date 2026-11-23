// SPDX-License-Identifier: GPL-2.0-only
#include <linux/anon_inodes.h>
#include <linux/bpf.h>
#include <linux/ctype.h>
#include <linux/dma-buf.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <asm/memory.h>

struct bpf_iter__dmabuf {
	struct bpf_iter_meta *meta;
	struct dma_buf *dmabuf;
};

struct dmabuf_iter {
	struct bpf_link *link;
	struct dma_buf *cursor;
	loff_t position;
	bool started;
	u64 session_id;
};

static u32 dmabuf_iter_btf_id;
static atomic64_t dmabuf_iter_sessions = ATOMIC64_INIT(0);

/* libbpf looks up the function's BTF ID, while programs receive a ctx struct. */
__used noinline int bpf_iter_dmabuf(struct bpf_iter_meta *meta, struct dma_buf *dmabuf)
{
	return 0;
}

bool bpf_dmabuf_iter_target(u32 btf_id)
{
	return btf_id && btf_id == dmabuf_iter_btf_id;
}

static bool valid_kernel_range(const void *address, u32 size)
{
	unsigned long start = (unsigned long)address;

	return size && start >= VA_START && start <= ULONG_MAX - (size - 1);
}

BPF_CALL_3(bpf_iter_read_kernel, void *, dst, u32, size, const void *, address)
{
	int err = -EFAULT;

	if (valid_kernel_range(address, size))
		err = probe_kernel_read(dst, address, size);
	if (err)
		memset(dst, 0, size);
	return err;
}

BPF_CALL_3(bpf_iter_read_kernel_str, void *, dst, u32, size, const void *, address)
{
	long ret = -EFAULT;

	if (valid_kernel_range(address, size))
		ret = strncpy_from_unsafe(dst, address, size);
	if (ret < 0)
		memset(dst, 0, size);
	return ret;
}

static const struct bpf_func_proto bpf_iter_read_kernel_proto = {
	.func = bpf_iter_read_kernel,
	.gpl_only = true,
	.ret_type = RET_INTEGER,
	.arg1_type = ARG_PTR_TO_RAW_STACK,
	.arg2_type = ARG_CONST_STACK_SIZE,
	.arg3_type = ARG_ITER_KERNEL_READ_SRC,
};

static const struct bpf_func_proto bpf_iter_read_kernel_str_proto = {
	.func = bpf_iter_read_kernel_str,
	.gpl_only = true,
	.ret_type = RET_INTEGER,
	.arg1_type = ARG_PTR_TO_RAW_STACK,
	.arg2_type = ARG_CONST_STACK_SIZE,
	.arg3_type = ARG_ITER_KERNEL_READ_SRC,
};

#define BPF_ITER_STRING_MAX 128
#define BPF_ITER_STRING_ARGS 6

/* Decode scalar and nofault string arguments before passing them to seq_printf. */
BPF_CALL_5(bpf_iter_seq_printf, struct seq_file *, seq, const char *, fmt,
	   u32, fmt_size, const u64 *, args, u32, data_size)
{
	u64 values[BPF_ITER_ARGS_MAX] = {};
	char strings[BPF_ITER_STRING_ARGS][BPF_ITER_STRING_MAX];
	u32 i, nr_args = 0, nr_strings = 0;

	if (!fmt_size || fmt_size > BPF_ITER_FMT_MAX || fmt[fmt_size - 1] ||
	    data_size % sizeof(u64) || data_size > sizeof(values))
		return -EINVAL;

	for (i = 0; i + 1 < fmt_size; i++) {
		u32 width = 0;

		if (!isascii(fmt[i]) || (!isprint(fmt[i]) && !isspace(fmt[i])))
			return -EINVAL;
		if (fmt[i] != '%')
			continue;
		i++;
		if (fmt[i] == '%')
			continue;
		if (nr_args >= data_size / sizeof(u64))
			return -EINVAL;
		while (fmt[i] && strchr("0 +-", fmt[i]))
			i++;
		while (isdigit(fmt[i])) {
			width = width * 10 + fmt[i++] - '0';
			if (width > BPF_ITER_STRING_MAX)
				return -E2BIG;
		}
		if (fmt[i] == 's') {
			const void *address = (const void *)(unsigned long)args[nr_args];
			char *copy;

			if (nr_strings == BPF_ITER_STRING_ARGS)
				return -E2BIG;
			copy = strings[nr_strings++];
			if (!valid_kernel_range(address, BPF_ITER_STRING_MAX) ||
			    strncpy_from_unsafe(copy, address, BPF_ITER_STRING_MAX) < 0)
				copy[0] = '\0';
			values[nr_args++] = (unsigned long)copy;
			continue;
		}
		if (fmt[i] == 'l' && fmt[++i] == 'l')
			i++;
		if (!fmt[i] || !strchr("diuxX", fmt[i]))
			return -EINVAL;
		values[nr_args] = args[nr_args];
		nr_args++;
	}

	seq_printf(seq, fmt, values[0], values[1], values[2], values[3],
		   values[4], values[5], values[6], values[7], values[8],
		   values[9], values[10], values[11]);
	return seq_has_overflowed(seq) ? -EOVERFLOW : 0;
}

static const struct bpf_func_proto bpf_iter_seq_printf_proto = {
	.func = bpf_iter_seq_printf,
	.gpl_only = true,
	.ret_type = RET_INTEGER,
	.arg1_type = ARG_PTR_TO_SEQ_FILE,
	.arg2_type = ARG_ITER_FMT,
	.arg3_type = ARG_ITER_FMT_SIZE,
	.arg4_type = ARG_ITER_ARGS,
	.arg5_type = ARG_ITER_ARGS_SIZE,
};

static const struct bpf_func_proto *dmabuf_iter_func_proto(enum bpf_func_id id)
{
	switch (id) {
	case BPF_FUNC_probe_read_kernel:
		return &bpf_iter_read_kernel_proto;
	case BPF_FUNC_probe_read_kernel_str:
		return &bpf_iter_read_kernel_str_proto;
	case BPF_FUNC_seq_printf:
		return &bpf_iter_seq_printf_proto;
	default:
		return NULL;
	}
}

static bool dmabuf_iter_ctx_access(int off, int size, enum bpf_access_type type,
				   enum bpf_reg_type *reg_type)
{
	if (type != BPF_READ || size != sizeof(void *))
		return false;
	switch (off) {
	case offsetof(struct bpf_iter__dmabuf, meta):
		*reg_type = PTR_TO_ITER_META;
		return true;
	case offsetof(struct bpf_iter__dmabuf, dmabuf):
		*reg_type = PTR_TO_ITER_BUF_OR_NULL;
		return true;
	default:
		return false;
	}
}

static const struct bpf_verifier_ops dmabuf_iter_verifier_ops = {
	.get_func_proto = dmabuf_iter_func_proto,
	.is_valid_access = dmabuf_iter_ctx_access,
};

static struct bpf_prog_type_list dmabuf_iter_prog_type = {
	.type = BPF_PROG_TYPE_TRACING,
	.ops = &dmabuf_iter_verifier_ops,
};

static void *dmabuf_iter_start(struct seq_file *seq, loff_t *pos)
{
	struct dmabuf_iter *iter = seq->private;

	if (!iter->started || *pos < iter->position) {
		if (iter->cursor)
			dma_buf_put(iter->cursor);
		iter->cursor = dma_buf_iter_next(NULL);
		iter->position = 0;
		iter->started = true;
	}
	while (iter->cursor && iter->position < *pos) {
		iter->cursor = dma_buf_iter_next(iter->cursor);
		iter->position++;
	}
	return iter->cursor;
}

static void *dmabuf_iter_next(struct seq_file *seq, void *entry, loff_t *pos)
{
	struct dmabuf_iter *iter = seq->private;

	iter->position = ++*pos;
	iter->cursor = dma_buf_iter_next(entry);
	return iter->cursor;
}

static void dmabuf_iter_stop(struct seq_file *seq, void *entry)
{
	/* The reader keeps its single cursor reference for the next read. */
}

static int dmabuf_iter_show(struct seq_file *seq, void *entry)
{
	struct dmabuf_iter *iter = seq->private;
	struct bpf_iter_meta meta = {
		.seq = seq,
		.session_id = iter->session_id,
		.seq_num = iter->position,
	};
	struct bpf_iter__dmabuf ctx = {
		.meta = &meta,
		.dmabuf = entry,
	};
	u32 result;

	/* Keep a concurrent rename's previous string valid for the program. */
	rcu_read_lock();
	preempt_disable();
	result = BPF_PROG_RUN(iter->link->prog, &ctx);
	preempt_enable();
	rcu_read_unlock();

	return result > 1 ? -EINVAL : result;
}

static const struct seq_operations dmabuf_iter_seq_ops = {
	.start = dmabuf_iter_start,
	.next = dmabuf_iter_next,
	.stop = dmabuf_iter_stop,
	.show = dmabuf_iter_show,
};

static int dmabuf_iter_release(struct inode *inode, struct file *file)
{
	struct seq_file *seq = file->private_data;
	struct dmabuf_iter *iter;

	if (!seq)
		return 0;
	iter = seq->private;
	if (iter->cursor)
		dma_buf_put(iter->cursor);
	bpf_link_put(iter->link);
	return seq_release_private(inode, file);
}

static const struct file_operations dmabuf_iter_fops = {
	.read = seq_read,
	.release = dmabuf_iter_release,
	.llseek = no_llseek,
};

struct bpf_prog *bpf_dmabuf_iter_file_prog(const struct file *file)
{
	struct seq_file *seq;
	struct dmabuf_iter *iter;

	if (file->f_op != &dmabuf_iter_fops)
		return NULL;
	seq = file->private_data;
	iter = seq->private;
	return iter->link->prog;
}


/* The caller transfers one reference on a successful open. */
static int dmabuf_iter_open_stream(struct file *file, struct bpf_link *link)
{
	struct dmabuf_iter *iter;

	iter = __seq_open_private(file, &dmabuf_iter_seq_ops, sizeof(*iter));
	if (!iter)
		return -ENOMEM;

	iter->link = link;
	iter->session_id = atomic64_inc_return(&dmabuf_iter_sessions);
	nonseekable_open(file_inode(file), file);
	return 0;
}

static int dmabuf_iter_pin_open(struct inode *inode, struct file *file)
{
	struct bpf_link *link;
	int err;

	if (file->f_mode & FMODE_WRITE)
		return -EPERM;
	link = bpf_link_inc(inode->i_private);
	if (IS_ERR(link))
		return PTR_ERR(link);

	err = dmabuf_iter_open_stream(file, link);
	if (err)
		bpf_link_put(link);
	return err;
}

static const struct file_operations dmabuf_iter_pin_fops = {
	.open = dmabuf_iter_pin_open,
	.read = seq_read,
	.release = dmabuf_iter_release,
	.llseek = no_llseek,
};

static void dmabuf_iter_link_dealloc(struct bpf_link *link)
{
	kfree(link);
}

static const struct bpf_link_ops dmabuf_iter_link_ops = {
	.dealloc = dmabuf_iter_link_dealloc,
};

const struct file_operations *bpf_dmabuf_iter_pin_fops(const struct bpf_link *link)
{
	return link->ops == &dmabuf_iter_link_ops ? &dmabuf_iter_pin_fops : NULL;
}

int bpf_dmabuf_iter_link_create(u32 prog_fd)
{
	struct bpf_prog *prog = bpf_prog_get_type(prog_fd, BPF_PROG_TYPE_TRACING);
	struct bpf_link *link;
	int fd;

	if (IS_ERR(prog))
		return PTR_ERR(prog);
	link = kzalloc(sizeof(*link), GFP_USER);
	if (!link) {
		bpf_prog_put(prog);
		return -ENOMEM;
	}

	bpf_link_init(link, &dmabuf_iter_link_ops, prog);
	fd = bpf_link_new_fd(link);
	if (fd < 0)
		bpf_link_put(link);
	return fd;
}

int bpf_dmabuf_iter_create(u32 link_fd)
{
	struct bpf_link *link = bpf_link_get_from_fd(link_fd);
	struct file *file;
	int fd, err;

	if (IS_ERR(link))
		return PTR_ERR(link);
	if (link->ops != &dmabuf_iter_link_ops) {
		fd = -EINVAL;
		goto put_link;
	}
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0)
		goto put_link;

	file = anon_inode_getfile("bpf-iter", &dmabuf_iter_fops, NULL, O_RDONLY);
	if (IS_ERR(file)) {
		put_unused_fd(fd);
		fd = PTR_ERR(file);
		goto put_link;
	}
	err = dmabuf_iter_open_stream(file, link);
	if (err) {
		fput(file);
		put_unused_fd(fd);
		fd = err;
		goto put_link;
	}
	fd_install(fd, file);
	return fd;
put_link:
	bpf_link_put(link);
	return fd;
}

static int __init dmabuf_iter_init(void)
{
	dmabuf_iter_btf_id = bpf_vmlinux_btf_func_id("bpf_iter_dmabuf");
	if (!dmabuf_iter_btf_id) {
		pr_err("DMA-BUF BPF iterator target missing from vmlinux BTF\n");
		return -ENOENT;
	}
	bpf_register_prog_type(&dmabuf_iter_prog_type);
	return 0;
}
late_initcall(dmabuf_iter_init);
