#ifndef _linux_POSIX_TIMERS_H
#define _linux_POSIX_TIMERS_H

#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/timex.h>
#include <linux/alarmtimer.h>


static inline unsigned long long cputime_to_expires(cputime_t expires)
{
	return (__force unsigned long long)expires;
}

static inline cputime_t expires_to_cputime(unsigned long long expires)
{
	return (__force cputime_t)expires;
}

struct cpu_timer_list {
	struct list_head entry;
	unsigned long long expires, incr;
	struct task_struct *task;
	int firing;
};

/*
 * Bit fields within a clockid:
 *
 * The most significant 29 bits hold either a pid or a file descriptor.
 *
 * Bit 2 indicates whether a cpu clock refers to a thread or a process.
 *
 * Bits 1 and 0 give the type: PROF=0, VIRT=1, SCHED=2, or FD=3.
 *
 * A clockid is invalid if bits 2, 1, and 0 are all set.
 */
#define CPUCLOCK_PID(clock)		((pid_t) ~((clock) >> 3))
#define CPUCLOCK_PERTHREAD(clock) \
	(((clock) & (clockid_t) CPUCLOCK_PERTHREAD_MASK) != 0)

#define CPUCLOCK_PERTHREAD_MASK	4
#define CPUCLOCK_WHICH(clock)	((clock) & (clockid_t) CPUCLOCK_CLOCK_MASK)
#define CPUCLOCK_CLOCK_MASK	3
#define CPUCLOCK_PROF		0
#define CPUCLOCK_VIRT		1
#define CPUCLOCK_SCHED		2
#define CPUCLOCK_MAX		3
#define CLOCKFD			CPUCLOCK_MAX
#define CLOCKFD_MASK		(CPUCLOCK_PERTHREAD_MASK|CPUCLOCK_CLOCK_MASK)

#define MAKE_PROCESS_CPUCLOCK(pid, clock) \
	((~(clockid_t) (pid) << 3) | (clockid_t) (clock))
#define MAKE_THREAD_CPUCLOCK(tid, clock) \
	MAKE_PROCESS_CPUCLOCK((tid), (clock) | CPUCLOCK_PERTHREAD_MASK)

#define FD_TO_CLOCKID(fd)	((~(clockid_t) (fd) << 3) | CLOCKFD)
#define CLOCKID_TO_FD(clk)	((unsigned int) ~((clk) >> 3))

/* POSIX.1b interval timer structure. */
/**
 * 线程创建的posix时钟
 */
struct k_itimer {
	/* 进程链表节点 */
	struct list_head list;		/* free/ allocate list */
	/* 全局哈希表节点 */
	struct hlist_node t_hash;
	/**
	 * 保护本数据结构的spin lock
	 */
	spinlock_t it_lock;
	/**
	 * 以系统中哪一个clock为标准来计算超时时间
	 */
	clockid_t it_clock;		/* which timer type */
	/* imer的ID，在一个进程中唯一标识该timer */
	timer_t it_id;			/* timer id */
	/**
	 * 用于overrun支持
	 * 当前的overrun计数
	 */
	int it_overrun;			/* overrun on pending signal  */
	/**
	 * 上次overrun计数
	 */
	int it_overrun_last;		/* overrun on last delivered signal */
	/**
	 * 该timer对应信号挂入signal pending的状态
	 * LSB bit标识该signal已经挂入signal pending队列，其他的bit作为信号的私有数据
	 */
	int it_requeue_pending;		/* waiting to requeue this timer */
#define REQUEUE_PENDING 1
	/**
	 * timer超期后如何异步通知该进程
	 * 如SIGEV_SIGNAL
	 */
	int it_sigev_notify;		/* notify word of sigevent struct */
	/**
	 * 该timer对应的signal descriptor
	 */
	struct signal_struct *it_signal;
	/**
	 * 处理timer的线程
	 */
	union {
		struct pid *it_pid;	/* pid of process to send signal to */
		struct task_struct *it_process;	/* for clock_nanosleep */
	};
	/* 超期后，该sigquue成员会挂入signal pending队列 */
	struct sigqueue *sigq;		/* signal queue entry. */
	/**
	 * timer interval相关的信息
	 */
	union {
		/* real time clock */
		struct {
			struct hrtimer timer;
			/* one shot为0，否则为周期 */
			ktime_t interval;
		} real;
		struct cpu_timer_list cpu;
		struct {
			unsigned int clock;
			unsigned int node;
			unsigned long incr;
			unsigned long expires;
		} mmtimer;
		/* alarm timer相关的成员 */
		struct {
			struct alarm alarmtimer;
			ktime_t interval;
		} alarm;
		struct rcu_head rcu;
	} it;
};

/**
 * 时钟描述符
 */
struct k_clock {
	/* 获取时间精度 */
	int (*clock_getres) (const clockid_t which_clock, struct timespec *tp);
	/**
	 * 获取和设定当前的时间
	 */
	int (*clock_set) (const clockid_t which_clock,
			  const struct timespec *tp);
	int (*clock_get) (const clockid_t which_clock, struct timespec * tp);
	/**
	 * 根据外部的精确时间信息对本clock进行调整
	 */
	int (*clock_adj) (const clockid_t which_clock, struct timex *tx);
	int (*timer_create) (struct k_itimer *timer);
	/**
	 * 睡眠特定时间
	 */
	int (*nsleep) (const clockid_t which_clock, int flags,
		       struct timespec *, struct timespec __user *);
	long (*nsleep_restart) (struct restart_block *restart_block);
	/**
	 * Posix Timer相关
	 */
	int (*timer_set) (struct k_itimer * timr, int flags,
			  struct itimerspec * new_setting,
			  struct itimerspec * old_setting);
	int (*timer_del) (struct k_itimer * timr);
#define TIMER_RETRY 1
	/**
	 * 获取时钟还有多长时间到期
	 */
	void (*timer_get) (struct k_itimer * timr,
			   struct itimerspec * cur_setting);
};

extern struct k_clock clock_posix_cpu;
extern struct k_clock clock_posix_dynamic;

void posix_timers_register_clock(const clockid_t clock_id, struct k_clock *new_clock);

/* function to call to trigger timer event */
int posix_timer_event(struct k_itimer *timr, int si_private);

void posix_cpu_timer_schedule(struct k_itimer *timer);

void run_posix_cpu_timers(struct task_struct *task);
void posix_cpu_timers_exit(struct task_struct *task);
void posix_cpu_timers_exit_group(struct task_struct *task);

bool posix_cpu_timers_can_stop_tick(struct task_struct *tsk);

void set_process_cpu_timer(struct task_struct *task, unsigned int clock_idx,
			   cputime_t *newval, cputime_t *oldval);

long clock_nanosleep_restart(struct restart_block *restart_block);

void update_rlimit_cpu(struct task_struct *task, unsigned long rlim_new);

#endif
