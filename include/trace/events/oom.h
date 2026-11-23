#undef TRACE_SYSTEM
#define TRACE_SYSTEM oom

#if !defined(_TRACE_OOM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_OOM_H
#include <linux/mm.h>
#include <linux/tracepoint.h>

TRACE_EVENT(oom_score_adj_update,

	TP_PROTO(struct task_struct *task),

	TP_ARGS(task),

	TP_STRUCT__entry(
		__field(	pid_t,	pid)
		__array(	char,	comm,	TASK_COMM_LEN )
		__field(	short,	oom_score_adj)
	),

	TP_fast_assign(
		__entry->pid = task->pid;
		memcpy(__entry->comm, task->comm, TASK_COMM_LEN);
		__entry->oom_score_adj = task->signal->oom_score_adj;
	),

	TP_printk("pid=%d comm=%s oom_score_adj=%hd",
		__entry->pid, __entry->comm, __entry->oom_score_adj)
);


TRACE_EVENT(mark_victim,

	TP_PROTO(struct task_struct *task, uid_t uid),

	TP_ARGS(task, uid),

	TP_STRUCT__entry(
		__field(int, pid)
		__string(comm, task->comm)
		__field(unsigned long, total_vm)
		__field(unsigned long, anon_rss)
		__field(unsigned long, file_rss)
		__field(unsigned long, shmem_rss)
		__field(uid_t, uid)
		__field(unsigned long, pgtables)
		__field(short, oom_score_adj)
	),

	TP_fast_assign(
		struct mm_struct *mm = task->mm;
		unsigned long ptes = PTRS_PER_PTE * sizeof(pte_t) *
				     atomic_long_read(&mm->nr_ptes);
		unsigned long pmds = PTRS_PER_PMD * sizeof(pmd_t) *
				     mm_nr_pmds(mm);

		__entry->pid = task_pid_nr(task);
		__assign_str(comm, task->comm);
		__entry->total_vm = READ_ONCE(mm->total_vm) << (PAGE_SHIFT - 10);
		__entry->anon_rss = get_mm_counter(mm, MM_ANONPAGES) << (PAGE_SHIFT - 10);
		__entry->file_rss = get_mm_counter(mm, MM_FILEPAGES) << (PAGE_SHIFT - 10);
		__entry->shmem_rss = get_mm_counter(mm, MM_SHMEMPAGES) << (PAGE_SHIFT - 10);
		__entry->uid = uid;
		__entry->pgtables = (ptes + pmds) >> 10;
		__entry->oom_score_adj = READ_ONCE(task->signal->oom_score_adj);
	),

	TP_printk("pid=%d comm=%s total-vm=%lukB anon-rss=%lukB file-rss:%lukB shmem-rss:%lukB uid=%u pgtables=%lukB oom_score_adj=%hd",
		  __entry->pid, __get_str(comm), __entry->total_vm,
		  __entry->anon_rss, __entry->file_rss, __entry->shmem_rss,
		  __entry->uid, __entry->pgtables, __entry->oom_score_adj)
);

#endif

/* This part must be outside protection */
#include <trace/define_trace.h>
