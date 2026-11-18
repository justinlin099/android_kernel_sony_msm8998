/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_ION_IMPORT_H
#define _UAPI_LINUX_ION_IMPORT_H

#include <linux/ioctl.h>
#include <linux/types.h>

/* Cache maintenance for a handle already imported on /dev/ion-import. */
enum ion_import_cache_op {
	ION_IMPORT_CACHE_CLEAN,
	ION_IMPORT_CACHE_INVALIDATE,
	ION_IMPORT_CACHE_CLEAN_INVALIDATE,
};

struct ion_import_cache_data {
	__s32 handle;
	__u32 op;
};

#define ION_IOC_IMPORT_CACHE	_IOW('I', 8, struct ion_import_cache_data)

#endif /* _UAPI_LINUX_ION_IMPORT_H */
