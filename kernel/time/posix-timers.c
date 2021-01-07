/*
 * linux/kernel/posix-timers.c
 *
 *
 * 2002-10-15  Posix Clocks & timers
 *                           by George Anzinger george@mvista.com
 *
 *			     Copyright (C) 2002 2003 by MontaVista Software.
 *
 * 2004-06-01  Fix CLOCK_REALTIME clock/timer TIMER_ABSTIME bug.
 *			     Copyright (C) 2004 Boris Hu
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * MontaVista Software | 1237 East Arques Avenue | Sunnyvale | CA 94085 | USA
 */

/* These are all the functions necessary to implement
 * POSIX clocks & timers
 */
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/mutex.h>

#include <asm/uaccess.h>
#include <linux/list.h>
#include <linux/init.h>
#include <linux/compiler.h>
#include <linux/hash.h>
#include <linux/posix-clock.h>
#include <linux/posix-timers.h>
#include <linux/syscalls.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/export.h>
#include <linux/hashtable.h>

#include "timekeeping.h"

/*
 * Management arrays for POSIX timers. Timers are now kept in static hash table
 * with 512 entries.
 * Timer ids are allocated by local routine, which selects proper hash head by
 * key, constructed from current->signal address and per signal struct counter.
 * This keeps timer ids unique per process, but now they can intersect between
 * processes.
 */

/*
 * Lets keep our timers in a slab cache :-)
 */
static struct kmem_cache *posix_timers_cache;

/**
 * 全局posix时钟哈希表
 * 512个入口
 */
static DEFINE_HASHTABLE(posix_timers_hashtable, 9);
/**
 * 保护全局posix时钟的锁
 */
static DEFINE_SPINLOCK(hash_lock);

/*
 * we assume that the new SIGEV_THREAD_ID shares no bits with the other
 * SIGEV values.  Here we put out an error if this assumption fails.
 */
#if SIGEV_THREAD_ID != (SIGEV_THREAD_ID & \
                       ~(SIGEV_SIGNAL | SIGEV_NONE | SIGEV_THREAD))
#error "SIGEV_THREAD_ID must not share bit with other SIGEV values!"
#endif

/*
 * parisc wants ENOTSUP instead of EOPNOTSUPP
 */
#ifndef ENOTSUP
# define ENANOSLEEP_NOTSUP EOPNOTSUPP
#else
# define ENANOSLEEP_NOTSUP ENOTSUP
#endif

/*
 * The timer ID is turned into a timer address by idr_find().
 * Verifying a valid ID consists of:
 *
 * a) checking that idr_find() returns other than -1.
 * b) checking that the timer id matches the one in the timer itself.
 * c) that the timer owner is in the callers thread group.
 */

/*
 * CLOCKs: The POSIX standard calls for a couple of clocks and allows us
 *	    to implement others.  This structure defines the various
 *	    clocks.
 *
 * RESOLUTION: Clock resolution is used to round up timer and interval
 *	    times, NOT to report clock times, which are reported with as
 *	    much resolution as the system can muster.  In some cases this
 *	    resolution may depend on the underlying clock hardware and
 *	    may not be quantifiable until run time, and only then is the
 *	    necessary code is written.	The standard says we should say
 *	    something about this issue in the documentation...
 *
 * FUNCTIONS: The CLOCKs structure defines possible functions to
 *	    handle various clock functions.
 *
 *	    The standard POSIX timer management code assumes the
 *	    following: 1.) The k_itimer struct (sched.h) is used for
 *	    the timer.  2.) The list, it_lock, it_clock, it_id and
 *	    it_pid fields are not modified by timer code.
 *
 * Permissions: It is assumed that the clock_settime() function defined
 *	    for each clock will take care of permission checks.	 Some
 *	    clocks may be set able by any user (i.e. local process
 *	    clocks) others not.	 Currently the only set able clock we
 *	    have is CLOCK_REALTIME and its high res counter part, both of
 *	    which we beg off on and pass to do_sys_settimeofday().
 */

/**
 * 静态定义的Posix时钟
 */
static struct k_clock posix_clocks[MAX_CLOCKS];

/*
 * These ones are defined below.
 */
static int common_nsleep(const clockid_t, int flags, struct timespec *t,
			 struct timespec __user *rmtp);
static int common_timer_create(struct k_itimer *new_timer);
static void common_timer_get(struct k_itimer *, struct itimerspec *);
static int common_timer_set(struct k_itimer *, int,
			    struct itimerspec *, struct itimerspec *);
static int common_timer_del(struct k_itimer *timer);

static enum hrtimer_restart posix_timer_fn(struct hrtimer *data);

static struct k_itimer *__lock_timer(timer_t timer_id, unsigned long *flags);

#define lock_timer(tid, flags)						   \
({	struct k_itimer *__timr;					   \
	__cond_lock(&__timr->it_lock, __timr = __lock_timer(tid, flags));  \
	__timr;								   \
})

static int hash(struct signal_struct *sig, unsigned int nr)
{
	return hash_32(hash32_ptr(sig) ^ nr, HASH_BITS(posix_timers_hashtable));
}

static struct k_itimer *__posix_timers_find(struct hlist_head *head,
					    struct signal_struct *sig,
					    timer_t id)
{
	struct k_itimer *timer;

	hlist_for_each_entry_rcu(timer, head, t_hash) {
		if ((timer->it_signal == sig) && (timer->it_id == id))
			return timer;
	}
	return NULL;
}

static struct k_itimer *posix_timer_by_id(timer_t id)
{
	struct signal_struct *sig = current->signal;
	struct hlist_head *head = &posix_timers_hashtable[hash(sig, id)];

	return __posix_timers_find(head, sig, id);
}

static int posix_timer_add(struct k_itimer *timer)
{
	struct signal_struct *sig = current->signal;
	/**
	 * posix_timer_id中记录了上一次分配的ID+1
	 * 问问这里开始分配，成功率较高
	 */
	int first_free_id = sig->posix_timer_id;
	struct hlist_head *head;
	int ret = -ENOENT;

	do {/* 循环，直到找到可用ID */
		spin_lock(&hash_lock);
		head = &posix_timers_hashtable[hash(sig, sig->posix_timer_id)];
		if (!__posix_timers_find(head, sig, sig->posix_timer_id)) {/* 可用ID */
			hlist_add_head_rcu(&timer->t_hash, head);
			ret = sig->posix_timer_id;
		}
		/* 不管3721，都要增加free id */
		if (++sig->posix_timer_id < 0)/* 回绕ID */
			sig->posix_timer_id = 0;
		/* 找了一圈都还没有找到，有点坑爹 */
		if ((sig->posix_timer_id == first_free_id) && (ret == -ENOENT))
			/* Loop over all possible ids completed */
			ret = -EAGAIN;
		spin_unlock(&hash_lock);
	} while (ret == -ENOENT);
	return ret;
}

static inline void unlock_timer(struct k_itimer *timr, unsigned long flags)
{
	spin_unlock_irqrestore(&timr->it_lock, flags);
}

/* Get clock_realtime */
static int posix_clock_realtime_get(clockid_t which_clock, struct timespec *tp)
{
	ktime_get_real_ts(tp);
	return 0;
}

/* Set clock_realtime */
static int posix_clock_realtime_set(const clockid_t which_clock,
				    const struct timespec *tp)
{
	return do_sys_settimeofday(tp, NULL);
}

static int posix_clock_realtime_adj(const clockid_t which_clock,
				    struct timex *t)
{
	return do_adjtimex(t);
}

/*
 * Get monotonic time for posix timers
 */
static int posix_ktime_get_ts(clockid_t which_clock, struct timespec *tp)
{
	ktime_get_ts(tp);
	return 0;
}

/*
 * Get monotonic-raw time for posix timers
 */
static int posix_get_monotonic_raw(clockid_t which_clock, struct timespec *tp)
{
	getrawmonotonic(tp);
	return 0;
}


static int posix_get_realtime_coarse(clockid_t which_clock, struct timespec *tp)
{
	*tp = current_kernel_time();
	return 0;
}

static int posix_get_monotonic_coarse(clockid_t which_clock,
						struct timespec *tp)
{
	*tp = get_monotonic_coarse();
	return 0;
}

static int posix_get_coarse_res(const clockid_t which_clock, struct timespec *tp)
{
	*tp = ktime_to_timespec(KTIME_LOW_RES);
	return 0;
}

static int posix_get_boottime(const clockid_t which_clock, struct timespec *tp)
{
	get_monotonic_boottime(tp);
	return 0;
}

static int posix_get_tai(clockid_t which_clock, struct timespec *tp)
{
	timekeeping_clocktai(tp);
	return 0;
}

static int posix_get_hrtimer_res(clockid_t which_clock, struct timespec *tp)
{
	tp->tv_sec = 0;
	tp->tv_nsec = hrtimer_resolution;
	return 0;
}

/*
 * Initialize everything, well, just everything in Posix clocks/timers ;)
 */
static __init int init_posix_timers(void)
{
	/* real time时钟 */
	struct k_clock clock_realtime = {
		.clock_getres	= posix_get_hrtimer_res,
		.clock_get	= posix_clock_realtime_get,
		.clock_set	= posix_clock_realtime_set,
		.clock_adj	= posix_clock_realtime_adj,
		.nsleep		= common_nsleep,
		.nsleep_restart	= hrtimer_nanosleep_restart,
		.timer_create	= common_timer_create,
		.timer_set	= common_timer_set,
		.timer_get	= common_timer_get,
		.timer_del	= common_timer_del,
	};
	/* monotonic 时钟，没有set接口 */
	struct k_clock clock_monotonic = {
		.clock_getres	= posix_get_hrtimer_res,
		.clock_get	= posix_ktime_get_ts,
		.nsleep		= common_nsleep,
		.nsleep_restart	= hrtimer_nanosleep_restart,
		.timer_create	= common_timer_create,
		.timer_set	= common_timer_set,
		.timer_get	= common_timer_get,
		.timer_del	= common_timer_del,
	};
	struct k_clock clock_monotonic_raw = {
		.clock_getres	= posix_get_hrtimer_res,
		.clock_get	= posix_get_monotonic_raw,
	};
	struct k_clock clock_realtime_coarse = {
		.clock_getres	= posix_get_coarse_res,
		.clock_get	= posix_get_realtime_coarse,
	};
	struct k_clock clock_monotonic_coarse = {
		.clock_getres	= posix_get_coarse_res,
		.clock_get	= posix_get_monotonic_coarse,
	};
	struct k_clock clock_tai = {
		.clock_getres	= posix_get_hrtimer_res,
		.clock_get	= posix_get_tai,
		.nsleep		= common_nsleep,
		.nsleep_restart	= hrtimer_nanosleep_restart,
		.timer_create	= common_timer_create,
		.timer_set	= common_timer_set,
		.timer_get	= common_timer_get,
		.timer_del	= common_timer_del,
	};
	struct k_clock clock_boottime = {
		.clock_getres	= posix_get_hrtimer_res,
		.clock_get	= posix_get_boottime,
		.nsleep		= common_nsleep,
		.nsleep_restart	= hrtimer_nanosleep_restart,
		.timer_create	= common_timer_create,
		.timer_set	= common_timer_set,
		.timer_get	= common_timer_get,
		.timer_del	= common_timer_del,
	};

	posix_timers_register_clock(CLOCK_REALTIME, &clock_realtime);
	posix_timers_register_clock(CLOCK_MONOTONIC, &clock_monotonic);
	posix_timers_register_clock(CLOCK_MONOTONIC_RAW, &clock_monotonic_raw);
	posix_timers_register_clock(CLOCK_REALTIME_COARSE, &clock_realtime_coarse);
	posix_timers_register_clock(CLOCK_MONOTONIC_COARSE, &clock_monotonic_coarse);
	posix_timers_register_clock(CLOCK_BOOTTIME, &clock_boottime);
	posix_timers_register_clock(CLOCK_TAI, &clock_tai);

	posix_timers_cache = kmem_cache_create("posix_timers_cache",
					sizeof (struct k_itimer), 0, SLAB_PANIC,
					NULL);
	return 0;
}

__initcall(init_posix_timers);

static void schedule_next_timer(struct k_itimer *timr)
{
	struct hrtimer *timer = &timr->it.real.timer;

	if (timr->it.real.interval.tv64 == 0)/* one shot类型的，直接退出 */
		return;

	/**
	 * 设定下次超期时间并计算overrun次数
	 */
	timr->it_overrun += (unsigned int) hrtimer_forward(timer,
						timer->base->get_time(),
						timr->it.real.interval);

	/**
	 * 保存该timer的overrun次数
	 * 信号处理函数获取该值，来获知被overrun的次数
	 */
	timr->it_overrun_last = timr->it_overrun;
	/* 为下次初始化overrun */
	timr->it_overrun = -1;
	/**
	 * 清除pending标记并增加信号私有数据域
	 * 私有数据域是信号被发送的次数，将其加1
	 */
	++timr->it_requeue_pending;
	/* 重启复位定时器 */
	hrtimer_restart(timer);
}

/*
 * This function is exported for use by the signal deliver code.  It is
 * called just prior to the info block being released and passes that
 * block to us.  It's function is to update the overrun entry AND to
 * restart the timer.  It should only be called if the timer is to be
 * restarted (i.e. we have flagged this in the sys_private entry of the
 * info block).
 *
 * To protect against the timer going away while the interrupt is queued,
 * we require that the it_requeue_pending flag be set.
 */
/**
 * Posix定时器信号被摘除后，由此函数重启定时器
 */
void do_schedule_next_timer(struct siginfo *info)
{
	struct k_itimer *timr;
	unsigned long flags;

	timr = lock_timer(info->si_tid, &flags);

	if (timr && timr->it_requeue_pending == info->si_sys_private) {
		if (timr->it_clock < 0)/* 动态Posix定时器 */
			posix_cpu_timer_schedule(timr);
		else/* 普通Posix定时器 */
			schedule_next_timer(timr);

		info->si_overrun += timr->it_overrun_last;
	}

	if (timr)
		unlock_timer(timr, flags);
}

int posix_timer_event(struct k_itimer *timr, int si_private)
{
	struct task_struct *task;
	int shared, ret = -1;
	/*
	 * FIXME: if ->sigq is queued we can race with
	 * dequeue_signal()->do_schedule_next_timer().
	 *
	 * If dequeue_signal() sees the "right" value of
	 * si_sys_private it calls do_schedule_next_timer().
	 * We re-queue ->sigq and drop ->it_lock().
	 * do_schedule_next_timer() locks the timer
	 * and re-schedules it while ->sigq is pending.
	 * Not really bad, but not that we want.
	 */
	timr->sigq->info.si_sys_private = si_private;

	rcu_read_lock();
	task = pid_task(timr->it_pid, PIDTYPE_PID);
	if (task) {
		shared = !(timr->it_sigev_notify & SIGEV_THREAD_ID);
		ret = send_sigqueue(timr->sigq, task, shared);
	}
	rcu_read_unlock();
	/* If we failed to send the signal the timer stops. */
	return ret > 0;
}
EXPORT_SYMBOL_GPL(posix_timer_event);

/*
 * This function gets called when a POSIX.1b interval timer expires.  It
 * is used as a callback from the kernel internal timer.  The
 * run_timer_list code ALWAYS calls with interrupts on.

 * This code is for CLOCK_REALTIME* and CLOCK_MONOTONIC* timers.
 */
/**
 * 普通posix时钟到期处理回调函数
 */
static enum hrtimer_restart posix_timer_fn(struct hrtimer *timer)
{
	struct k_itimer *timr;
	unsigned long flags;
	int si_private = 0;
	/**
	 * 对于one shot类型的，需要返回HRTIMER_NORESTART
	 */
	enum hrtimer_restart ret = HRTIMER_NORESTART;

	/* 获取该高精度timer对应的那个k_itimer数据 */
	timr = container_of(timer, struct k_itimer, it.real.timer);
	spin_lock_irqsave(&timr->it_lock, flags);

	if (timr->it.real.interval.tv64 != 0)/* 周期性timer */
		/**
		 * 有可能会有overrun的问题
		 * 这时候，需要传递一个signal的私有数据，以便在queue signal的时候进行标识
		 * ++timr->it_requeue_pending用来标记该timer处于pending状态
		 * 加一就是将LSB设定为1
		 */
		si_private = ++timr->it_requeue_pending;

	/**
	 * 将信号挂入进程（线程）signal pending队列
	 */
	if (posix_timer_event(timr, si_private)) {
		/*
		 * signal was not sent because of sig_ignor
		 * we will not get a call back to restart it AND
		 * it should be restarted.
		 */
		if (timr->it.real.interval.tv64 != 0) {/* 周期性定时器 */
			ktime_t now = hrtimer_cb_get_time(timer);

			/*
			 * FIXME: What we really want, is to stop this
			 * timer completely and restart it in case the
			 * SIG_IGN is removed. This is a non trivial
			 * change which involves sighand locking
			 * (sigh !), which we don't want to do late in
			 * the release cycle.
			 *
			 * For now we just let timers with an interval
			 * less than a jiffie expire every jiffie to
			 * avoid softirq starvation in case of SIG_IGN
			 * and a very small interval, which would put
			 * the timer right back on the softirq pending
			 * list. By moving now ahead of time we trick
			 * hrtimer_forward() to expire the timer
			 * later, while we still maintain the overrun
			 * accuracy, but have some inconsistency in
			 * the timer_gettime() case. This is at least
			 * better than a starved softirq. A more
			 * complex fix which solves also another related
			 * inconsistency is already in the pipeline.
			 */
#ifdef CONFIG_HIGH_RES_TIMERS
			{
				ktime_t kj = ktime_set(0, NSEC_PER_SEC / HZ);

				if (timr->it.real.interval.tv64 < kj.tv64)
					now = ktime_add(now, kj);
			}
#endif
			/* 增加overrun */
			timr->it_overrun += (unsigned int)
				hrtimer_forward(timer, now,
						timr->it.real.interval);
			/* 重新启动时钟，以处理下一次overrun */
			ret = HRTIMER_RESTART;
			++timr->it_requeue_pending;
		}
	}

	unlock_timer(timr, flags);
	return ret;
}

static struct pid *good_sigevent(sigevent_t * event)
{
	struct task_struct *rtn = current->group_leader;

	if ((event->sigev_notify & SIGEV_THREAD_ID ) &&/* 指定由线程来处理信号 */
		(!(rtn = find_task_by_vpid(event->sigev_notify_thread_id)) ||/* 线程确实要存在 */
		 !same_thread_group(rtn, current) ||/* 同一进程组 */
		 (event->sigev_notify & ~SIGEV_THREAD_ID) != SIGEV_SIGNAL))/* 参数不冲突 */
		return NULL;

	if (((event->sigev_notify & ~SIGEV_THREAD_ID) != SIGEV_NONE) &&/* 由信号来处理 */
	    ((event->sigev_signo <= 0) || (event->sigev_signo > SIGRTMAX)))/* 信号编号要正确 */
		return NULL;

	return task_pid(rtn);
}

void posix_timers_register_clock(const clockid_t clock_id,
				 struct k_clock *new_clock)
{
	if ((unsigned) clock_id >= MAX_CLOCKS) {
		printk(KERN_WARNING "POSIX clock register failed for clock_id %d\n",
		       clock_id);
		return;
	}

	if (!new_clock->clock_get) {
		printk(KERN_WARNING "POSIX clock id %d lacks clock_get()\n",
		       clock_id);
		return;
	}
	if (!new_clock->clock_getres) {
		printk(KERN_WARNING "POSIX clock id %d lacks clock_getres()\n",
		       clock_id);
		return;
	}

	posix_clocks[clock_id] = *new_clock;
}
EXPORT_SYMBOL_GPL(posix_timers_register_clock);

static struct k_itimer * alloc_posix_timer(void)
{
	struct k_itimer *tmr;
	tmr = kmem_cache_zalloc(posix_timers_cache, GFP_KERNEL);
	if (!tmr)
		return tmr;
	if (unlikely(!(tmr->sigq = sigqueue_alloc()))) {
		kmem_cache_free(posix_timers_cache, tmr);
		return NULL;
	}
	memset(&tmr->sigq->info, 0, sizeof(siginfo_t));
	return tmr;
}

static void k_itimer_rcu_free(struct rcu_head *head)
{
	struct k_itimer *tmr = container_of(head, struct k_itimer, it.rcu);

	kmem_cache_free(posix_timers_cache, tmr);
}

#define IT_ID_SET	1
#define IT_ID_NOT_SET	0
static void release_posix_timer(struct k_itimer *tmr, int it_id_set)
{
	if (it_id_set) {
		unsigned long flags;
		spin_lock_irqsave(&hash_lock, flags);
		hlist_del_rcu(&tmr->t_hash);
		spin_unlock_irqrestore(&hash_lock, flags);
	}
	put_pid(tmr->it_pid);
	sigqueue_free(tmr->sigq);
	call_rcu(&tmr->it.rcu, k_itimer_rcu_free);
}

/**
 * 转换时钟ID
 */
static struct k_clock *clockid_to_kclock(const clockid_t id)
{
	if (id < 0)/* 不是静态ID */
		return (id & CLOCKFD_MASK) == CLOCKFD ?
			&clock_posix_dynamic : &clock_posix_cpu;

	/**
	 * 静态ID
	 * 如果相应的静态ID没有实现，就返回NULL
	 */
	if (id >= MAX_CLOCKS || !posix_clocks[id].clock_getres)
		return NULL;
	/* 静态ID */
	return &posix_clocks[id];
}

/**
 * 非动态时钟的创建
 */
static int common_timer_create(struct k_itimer *new_timer)
{
	hrtimer_init(&new_timer->it.real.timer, new_timer->it_clock, 0);
	return 0;
}

/* Create a POSIX.1b interval timer. */

/**
 * 创建posix定时器
 * 目前好使的接口，应该多用
 */
SYSCALL_DEFINE3(timer_create, const clockid_t, which_clock,
		struct sigevent __user *, timer_event_spec,
		timer_t __user *, created_timer_id)
{
	/**
	 * 根据clock ID获取内核中的struct k_clock
	 */
	struct k_clock *kc = clockid_to_kclock(which_clock);
	struct k_itimer *new_timer;
	int error, new_timer_id;
	sigevent_t event;
	int it_id_set = IT_ID_NOT_SET;

	/* 哦豁，非法id */
	if (!kc)
		return -EINVAL;
	/* 这种类型的时钟，不允许创建，算球 */
	if (!kc->timer_create)
		return -EOPNOTSUPP;

	/**
	 * 分配一个POSIX timer
	 * 所有成员被初始化为0
	 */
	new_timer = alloc_posix_timer();
	if (unlikely(!new_timer))
		return -EAGAIN;

	spin_lock_init(&new_timer->it_lock);
	/**
	 * 先分配一个ID
	 * 再将该timer加入到全局的哈希表中。
	 */
	new_timer_id = posix_timer_add(new_timer);
	if (new_timer_id < 0) {/* 分配失败，背时的东西 */
		error = new_timer_id;
		goto out;
	}

	it_id_set = IT_ID_SET;
	/**
	 * 初始化该posix timer，设定timer ID，clock ID以及overrun的值。
	 */
	new_timer->it_id = (timer_t) new_timer_id;
	new_timer->it_clock = which_clock;
	new_timer->it_overrun = -1;

	if (timer_event_spec) {/* 用户指定了处理方式 */
		/* 复制用户态参数 */
		if (copy_from_user(&event, timer_event_spec, sizeof (event))) {
			error = -EFAULT;
			goto out;
		}
		rcu_read_lock();
		/* 确定处理定时器的任务ID */
		new_timer->it_pid = get_pid(good_sigevent(&event));
		rcu_read_unlock();
		if (!new_timer->it_pid) {/* 如果id为空，说明参数检查没有通过 */
			error = -EINVAL;
			goto out;
		}
	} else {/* 没有指定参数，设置默认值 */
		memset(&event.sigev_value, 0, sizeof(event.sigev_value));
		/**
		 * 如果用户空间的程序没有指定sigevent_t的参数
		 * 那么内核的缺省行为是发送SIGALRM给调用线程所属的线程组leader。
		 */
		event.sigev_notify = SIGEV_SIGNAL;
		event.sigev_signo = SIGALRM;
		event.sigev_value.sival_int = new_timer->it_id;
		/* 默认由领头进程来处理信号 */
		new_timer->it_pid = get_pid(task_tgid(current));
	}

	new_timer->it_sigev_notify     = event.sigev_notify;
	new_timer->sigq->info.si_signo = event.sigev_signo;
	new_timer->sigq->info.si_value = event.sigev_value;
	new_timer->sigq->info.si_tid   = new_timer->it_id;
	/**
	 * SI_TIMER用来标识该信号是由于posix timer而产生的。
	 */
	new_timer->sigq->info.si_code  = SI_TIMER;

	/* 将分配的timer ID 拷贝回用户空间 */
	if (copy_to_user(created_timer_id,
			 &new_timer_id, sizeof (new_timer_id))) {
		error = -EFAULT;
		goto out;
	}

	/**
	 * 也就是个二传手
	 * 将创建任务交给具体的时钟
	 */
	error = kc->timer_create(new_timer);
	if (error)
		goto out;

	spin_lock_irq(&current->sighand->siglock);
	/* 建立posix timer和当前进程signal descriptor的关系 */
	new_timer->it_signal = current->signal;
	list_add(&new_timer->list, &current->signal->posix_timers);
	spin_unlock_irq(&current->sighand->siglock);

	return 0;
	/*
	 * In the case of the timer belonging to another task, after
	 * the task is unlocked, the timer is owned by the other task
	 * and may cease to exist at any time.  Don't use or modify
	 * new_timer after the unlock call.
	 */
out:
	release_posix_timer(new_timer, it_id_set);
	return error;
}

/*
 * Locking issues: We need to protect the result of the id look up until
 * we get the timer locked down so it is not deleted under us.  The
 * removal is done under the idr spinlock so we use that here to bridge
 * the find to the timer lock.  To avoid a dead lock, the timer id MUST
 * be release with out holding the timer lock.
 */
static struct k_itimer *__lock_timer(timer_t timer_id, unsigned long *flags)
{
	struct k_itimer *timr;

	/*
	 * timer_t could be any type >= int and we want to make sure any
	 * @timer_id outside positive int range fails lookup.
	 */
	if ((unsigned long long)timer_id > INT_MAX)
		return NULL;

	rcu_read_lock();
	timr = posix_timer_by_id(timer_id);
	if (timr) {
		spin_lock_irqsave(&timr->it_lock, *flags);
		if (timr->it_signal == current->signal) {
			rcu_read_unlock();
			return timr;
		}
		spin_unlock_irqrestore(&timr->it_lock, *flags);
	}
	rcu_read_unlock();

	return NULL;
}

/*
 * Get the time remaining on a POSIX.1b interval timer.  This function
 * is ALWAYS called with spin_lock_irq on the timer, thus it must not
 * mess with irq.
 *
 * We have a couple of messes to clean up here.  First there is the case
 * of a timer that has a requeue pending.  These timers should appear to
 * be in the timer list with an expiry as if we were to requeue them
 * now.
 *
 * The second issue is the SIGEV_NONE timer which may be active but is
 * not really ever put in the timer list (to save system resources).
 * This timer may be expired, and if so, we will do it here.  Otherwise
 * it is the same as a requeue pending timer WRT to what we should
 * report.
 */
/**
 * 获得posix定时器的设置
 */
static void
common_timer_get(struct k_itimer *timr, struct itimerspec *cur_setting)
{
	ktime_t now, remaining, iv;
	struct hrtimer *timer = &timr->it.real.timer;

	memset(cur_setting, 0, sizeof(struct itimerspec));

	/**
	 * 获取该posix timer对应的timer period值
	 */
	iv = timr->it.real.interval;

	/* interval timer ? */
	if (iv.tv64)/* 周期性定时器 */
		/* interval timer需返回timer period */
		cur_setting->it_interval = ktime_to_timespec(iv);
	else if (!hrtimer_active(timer) &&
		 (timr->it_sigev_notify & ~SIGEV_THREAD_ID) != SIGEV_NONE)/* one shot */
		return;/* 返回0就行了 */

	/* 先取得当前时间点的值 */
	now = timer->base->get_time();

	/*
	 * When a requeue is pending or this is a SIGEV_NONE
	 * timer move the expiry time forward by intervals, so
	 * expiry is > now.
	 */
	if (iv.tv64 && (timr->it_requeue_pending & REQUEUE_PENDING ||/* 周期性定时器，并且信号被挂起 */
	    (timr->it_sigev_notify & ~SIGEV_THREAD_ID) == SIGEV_NONE))/* 轮询方式的定时器 */
	    	/*  如果超时，就重置定时器并增加it_overrun */
		timr->it_overrun += (unsigned int) hrtimer_forward(timer, now, iv);

	/* 计算剩余时间 */
	remaining = ktime_sub(hrtimer_get_expires(timer), now);
	/* Return 0 only, when the timer is expired and not pending */
	if (remaining.tv64 <= 0) {/* 已经超期 */
		/*
		 * A single shot SIGEV_NONE timer must return 0, when
		 * it is expired !
		 */
		if ((timr->it_sigev_notify & ~SIGEV_THREAD_ID) != SIGEV_NONE)
			cur_setting->it_value.tv_nsec = 1;
	} else
		/* 返回剩余时间信息 */
		cur_setting->it_value = ktime_to_timespec(remaining);
}

/* Get the time remaining on a POSIX.1b interval timer. */
/**
 * 获取一个posix timer剩余时间
 */
SYSCALL_DEFINE2(timer_gettime, timer_t, timer_id,
		struct itimerspec __user *, setting)
{
	struct itimerspec cur_setting;
	struct k_itimer *timr;
	struct k_clock *kc;
	unsigned long flags;
	int ret = 0;

	/**
	 * 根据timer ID找到对应的posix timer
	 */
	timr = lock_timer(timer_id, &flags);
	if (!timr)
		return -EINVAL;

	/**
	 * 根据clock ID获取内核中的struct k_clock
	 */
	kc = clockid_to_kclock(timr->it_clock);
	if (WARN_ON_ONCE(!kc || !kc->timer_get))
		ret = -EINVAL;
	else
		/* 调用具体clock的get timer函数 */
		kc->timer_get(timr, &cur_setting);

	unlock_timer(timr, flags);

	/* 将结果copy到用户空间 */
	if (!ret && copy_to_user(setting, &cur_setting, sizeof (cur_setting)))
		return -EFAULT;

	return ret;
}

/*
 * Get the number of overruns of a POSIX.1b interval timer.  This is to
 * be the overrun of the timer last delivered.  At the same time we are
 * accumulating overruns on the next timer.  The overrun is frozen when
 * the signal is delivered, either at the notify time (if the info block
 * is not queued) or at the actual delivery time (as we are informed by
 * the call back to do_schedule_next_timer().  So all we need to do is
 * to pick up the frozen overrun.
 */
SYSCALL_DEFINE1(timer_getoverrun, timer_t, timer_id)
{
	struct k_itimer *timr;
	int overrun;
	unsigned long flags;

	timr = lock_timer(timer_id, &flags);
	if (!timr)
		return -EINVAL;

	overrun = timr->it_overrun_last;
	unlock_timer(timr, flags);

	return overrun;
}

/* Set a POSIX.1b interval timer. */
/* timr->it_lock is taken. */
static int
common_timer_set(struct k_itimer *timr, int flags,
		 struct itimerspec *new_setting, struct itimerspec *old_setting)
{
	/**
	 * 获取该posix timer对应的高精度timer
	 */
	struct hrtimer *timer = &timr->it.real.timer;
	enum hrtimer_mode mode;

	if (old_setting)/* 获取旧的timer设定 */
		common_timer_get(timr, old_setting);

	/* disable the timer */
	timr->it.real.interval.tv64 = 0;
	/*
	 * careful here.  If smp we could be in the "fire" routine which will
	 * be spinning as we hold the lock.  But this is ONLY an SMP issue.
	 */
	/**
	 * 停掉该高精度timer
	 */
	if (hrtimer_try_to_cancel(timer) < 0)
		return TIMER_RETRY;/* 竟然停止不掉? */

	/**
	 * it_requeue_pending状态flag中的信号私有数据加一
	 * 这个私有数据是[31:1]，因此代码中加2
	 * 并且清除pending flag
	 */
	timr->it_requeue_pending = (timr->it_requeue_pending + 2) & 
		~REQUEUE_PENDING;
	/* 上次的overrun count要被清除 */
	timr->it_overrun_last = 0;

	/* switch off the timer when it_value is zero */
	/**
	 * 新设定的时间值等于0 
	 * 说明仅仅是想停止掉该定时器
	 */
	if (!new_setting->it_value.tv_sec && !new_setting->it_value.tv_nsec)
		return 0;

	/* 重新初始化高精度定时器 */
	mode = flags & TIMER_ABSTIME ? HRTIMER_MODE_ABS : HRTIMER_MODE_REL;
	hrtimer_init(&timr->it.real.timer, timr->it_clock, mode);
	timr->it.real.timer.function = posix_timer_fn;

	hrtimer_set_expires(timer, timespec_to_ktime(new_setting->it_value));

	/* Convert interval */
	/**
	 * 设置interval的值
	 * 通过该值可以设定周期性timer
	 * 用户空间传入的参数是timespec
	 * 需转换成ktime的时间格式
	 */
	timr->it.real.interval = timespec_to_ktime(new_setting->it_interval);

	/* SIGEV_NONE timers are not queued ! See common_timer_get */
	/* 对于轮询类型的posix timer，我们并不会真正启动该timer */
	if (((timr->it_sigev_notify & ~SIGEV_THREAD_ID) == SIGEV_NONE)) {
		/* Setup correct expiry time for relative timers */
		if (mode == HRTIMER_MODE_REL) {/* 非绝对时间 */
			/* 在当前时间上面加上相对时间 */
			hrtimer_add_expires(timer, timer->base->get_time());
		}
		return 0;
	}

	/* 启动高精度timer */
	hrtimer_start_expires(timer, mode);
	return 0;
}

/* Set a POSIX.1b interval timer */
/**
 * 设置posix时钟的值
 *	flag:	相对时间还是绝对时间
 *	new_setting:	如果值为0，则停止时钟
 */
SYSCALL_DEFINE4(timer_settime, timer_t, timer_id, int, flags,
		const struct itimerspec __user *, new_setting,
		struct itimerspec __user *, old_setting)
{
	struct k_itimer *timr;
	struct itimerspec new_spec, old_spec;
	int error = 0;
	unsigned long flag;
	struct itimerspec *rtn = old_setting ? &old_spec : NULL;
	struct k_clock *kc;

	if (!new_setting)
		return -EINVAL;

	if (copy_from_user(&new_spec, new_setting, sizeof (new_spec)))
		return -EFAULT;

	if (!timespec_valid(&new_spec.it_interval) ||
	    !timespec_valid(&new_spec.it_value))
		return -EINVAL;
retry:
	timr = lock_timer(timer_id, &flag);
	if (!timr)
		return -EINVAL;

	kc = clockid_to_kclock(timr->it_clock);
	if (WARN_ON_ONCE(!kc || !kc->timer_set))
		error = -EINVAL;
	else
		error = kc->timer_set(timr, flags, &new_spec, rtn);

	unlock_timer(timr, flag);
	if (error == TIMER_RETRY) {
		rtn = NULL;	// We already got the old time...
		goto retry;
	}

	if (old_setting && !error &&
	    copy_to_user(old_setting, &old_spec, sizeof (old_spec)))
		error = -EFAULT;

	return error;
}

static int common_timer_del(struct k_itimer *timer)
{
	timer->it.real.interval.tv64 = 0;

	if (hrtimer_try_to_cancel(&timer->it.real.timer) < 0)
		return TIMER_RETRY;
	return 0;
}

static inline int timer_delete_hook(struct k_itimer *timer)
{
	struct k_clock *kc = clockid_to_kclock(timer->it_clock);

	if (WARN_ON_ONCE(!kc || !kc->timer_del))
		return -EINVAL;
	return kc->timer_del(timer);
}

/* Delete a POSIX.1b interval timer. */
/**
 * 删除posix定时器
 */
SYSCALL_DEFINE1(timer_delete, timer_t, timer_id)
{
	struct k_itimer *timer;
	unsigned long flags;

retry_delete:
	timer = lock_timer(timer_id, &flags);
	if (!timer)
		return -EINVAL;

	if (timer_delete_hook(timer) == TIMER_RETRY) {
		unlock_timer(timer, flags);
		goto retry_delete;
	}

	spin_lock(&current->sighand->siglock);
	list_del(&timer->list);
	spin_unlock(&current->sighand->siglock);
	/*
	 * This keeps any tasks waiting on the spin lock from thinking
	 * they got something (see the lock code above).
	 */
	timer->it_signal = NULL;

	unlock_timer(timer, flags);
	release_posix_timer(timer, IT_ID_SET);
	return 0;
}

/*
 * return timer owned by the process, used by exit_itimers
 */
static void itimer_delete(struct k_itimer *timer)
{
	unsigned long flags;

retry_delete:
	spin_lock_irqsave(&timer->it_lock, flags);

	if (timer_delete_hook(timer) == TIMER_RETRY) {
		unlock_timer(timer, flags);
		goto retry_delete;
	}
	list_del(&timer->list);
	/*
	 * This keeps any tasks waiting on the spin lock from thinking
	 * they got something (see the lock code above).
	 */
	timer->it_signal = NULL;

	unlock_timer(timer, flags);
	release_posix_timer(timer, IT_ID_SET);
}

/*
 * This is called by do_exit or de_thread, only when there are no more
 * references to the shared signal_struct.
 */
void exit_itimers(struct signal_struct *sig)
{
	struct k_itimer *tmr;

	while (!list_empty(&sig->posix_timers)) {
		tmr = list_entry(sig->posix_timers.next, struct k_itimer, list);
		itimer_delete(tmr);
	}
}

SYSCALL_DEFINE2(clock_settime, const clockid_t, which_clock,
		const struct timespec __user *, tp)
{
	struct k_clock *kc = clockid_to_kclock(which_clock);
	struct timespec new_tp;

	if (!kc || !kc->clock_set)
		return -EINVAL;

	if (copy_from_user(&new_tp, tp, sizeof (*tp)))
		return -EFAULT;

	return kc->clock_set(which_clock, &new_tp);
}

SYSCALL_DEFINE2(clock_gettime, const clockid_t, which_clock,
		struct timespec __user *,tp)
{
	struct k_clock *kc = clockid_to_kclock(which_clock);
	struct timespec kernel_tp;
	int error;

	if (!kc)
		return -EINVAL;

	error = kc->clock_get(which_clock, &kernel_tp);

	if (!error && copy_to_user(tp, &kernel_tp, sizeof (kernel_tp)))
		error = -EFAULT;

	return error;
}

SYSCALL_DEFINE2(clock_adjtime, const clockid_t, which_clock,
		struct timex __user *, utx)
{
	struct k_clock *kc = clockid_to_kclock(which_clock);
	struct timex ktx;
	int err;

	if (!kc)
		return -EINVAL;
	if (!kc->clock_adj)
		return -EOPNOTSUPP;

	if (copy_from_user(&ktx, utx, sizeof(ktx)))
		return -EFAULT;

	err = kc->clock_adj(which_clock, &ktx);

	if (err >= 0 && copy_to_user(utx, &ktx, sizeof(ktx)))
		return -EFAULT;

	return err;
}

/**
 * 获取时钟精度
 */
SYSCALL_DEFINE2(clock_getres, const clockid_t, which_clock,
		struct timespec __user *, tp)
{
	struct k_clock *kc = clockid_to_kclock(which_clock);
	struct timespec rtn_tp;
	int error;

	if (!kc)
		return -EINVAL;

	error = kc->clock_getres(which_clock, &rtn_tp);

	if (!error && tp && copy_to_user(tp, &rtn_tp, sizeof (rtn_tp)))
		error = -EFAULT;

	return error;
}

/*
 * nanosleep for monotonic and realtime clocks
 */
static int common_nsleep(const clockid_t which_clock, int flags,
			 struct timespec *tsave, struct timespec __user *rmtp)
{
	return hrtimer_nanosleep(tsave, rmtp, flags & TIMER_ABSTIME ?
				 HRTIMER_MODE_ABS : HRTIMER_MODE_REL,
				 which_clock);
}

SYSCALL_DEFINE4(clock_nanosleep, const clockid_t, which_clock, int, flags,
		const struct timespec __user *, rqtp,
		struct timespec __user *, rmtp)
{
	struct k_clock *kc = clockid_to_kclock(which_clock);
	struct timespec t;

	if (!kc)
		return -EINVAL;
	if (!kc->nsleep)
		return -ENANOSLEEP_NOTSUP;

	if (copy_from_user(&t, rqtp, sizeof (struct timespec)))
		return -EFAULT;

	if (!timespec_valid(&t))
		return -EINVAL;

	return kc->nsleep(which_clock, flags, &t, rmtp);
}

/*
 * This will restart clock_nanosleep. This is required only by
 * compat_clock_nanosleep_restart for now.
 */
long clock_nanosleep_restart(struct restart_block *restart_block)
{
	clockid_t which_clock = restart_block->nanosleep.clockid;
	struct k_clock *kc = clockid_to_kclock(which_clock);

	if (WARN_ON_ONCE(!kc || !kc->nsleep_restart))
		return -EINVAL;

	return kc->nsleep_restart(restart_block);
}
