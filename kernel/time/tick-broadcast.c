/*
 * linux/kernel/time/tick-broadcast.c
 *
 * This file contains functions which emulate a local clock-event
 * device via a broadcast event source.
 *
 * Copyright(C) 2005-2006, Thomas Gleixner <tglx@linutronix.de>
 * Copyright(C) 2005-2007, Red Hat, Inc., Ingo Molnar
 * Copyright(C) 2006-2007, Timesys Corp., Thomas Gleixner
 *
 * This code is licenced under the GPL version 2. For details see
 * kernel-base/COPYING.
 */
#include <linux/cpu.h>
#include <linux/err.h>
#include <linux/hrtimer.h>
#include <linux/interrupt.h>
#include <linux/percpu.h>
#include <linux/profile.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/module.h>

#include "tick-internal.h"

/*
 * Broadcast support for broken x86 hardware, where the local apic
 * timer stops in C3 state.
 */

/**
 * 进行tick广播的设备
 */
static struct tick_device tick_broadcast_device;
/**
 * 在周期性TICK模式下
 * 哪些CPU可能需要TICK广播
 */
static cpumask_var_t tick_broadcast_mask;
/**
 * 在周期性TICK模式下
 * 哪些CPU可能进入了IDLE
 */
static cpumask_var_t tick_broadcast_on;
static cpumask_var_t tmpmask;
static DEFINE_RAW_SPINLOCK(tick_broadcast_lock);
/**
 * 是否强制使用tick广播，而不是用本地时钟
 * 用于x86
 * 参见http://lwn.net/Articles/286432/
 */
static int tick_broadcast_forced;

#ifdef CONFIG_TICK_ONESHOT
static void tick_broadcast_clear_oneshot(int cpu);
static void tick_resume_broadcast_oneshot(struct clock_event_device *bc);
#else
static inline void tick_broadcast_clear_oneshot(int cpu) { }
static inline void tick_resume_broadcast_oneshot(struct clock_event_device *bc) { }
#endif

/*
 * Debugging: see timer_list.c
 */
struct tick_device *tick_get_broadcast_device(void)
{
	return &tick_broadcast_device;
}

struct cpumask *tick_get_broadcast_mask(void)
{
	return tick_broadcast_mask;
}

/*
 * Start the device in periodic mode
 */
static void tick_broadcast_start_periodic(struct clock_event_device *bc)
{
	if (bc)
		tick_setup_periodic(bc, 1);
}

/*
 * Check, if the device can be utilized as broadcast device:
 */
static bool tick_check_broadcast_device(struct clock_event_device *curdev,
					struct clock_event_device *newdev)
{
	if ((newdev->features & CLOCK_EVT_FEAT_DUMMY) ||/* 这种设备当然不行 */
	    (newdev->features & CLOCK_EVT_FEAT_PERCPU) ||/* 每CPU设备也不行 */
	    (newdev->features & CLOCK_EVT_FEAT_C3STOP))/* 本来就是为了解决C3STOP的 */
		return false;

	/* 比原来的还不如 */
	if (tick_broadcast_device.mode == TICKDEV_MODE_ONESHOT &&
	    !(newdev->features & CLOCK_EVT_FEAT_ONESHOT))
		return false;

	/* 比较精度，如果精度不行，也不要 */
	return !curdev || newdev->rating > curdev->rating;
}

/*
 * Conditionally install/replace broadcast device
 */
/**
 * 安装/替换系统中broadcast tick device
 */
void tick_install_broadcast_device(struct clock_event_device *dev)
{
	/* 获取当前的broadcast tick device */
	struct clock_event_device *cur = tick_broadcast_device.evtdev;

	/* 时钟设备是否有能力作为广播设备 */
	if (!tick_check_broadcast_device(cur, dev))
		return;

	/* 对模块引用 */
	if (!try_module_get(dev->owner))
		return;

	/**
	 * 用新的clock event device来替换旧的
	 * 因此需要将旧的clock event device（如果存在的话）从active 队列中摘除
	 * 并设定CLOCK_EVT_MODE_UNUSED状态
	 * 挂入released clockevent队列。
	 * 对于新的clockevent device，需要设定为CLOCK_EVT_MODE_SHUTDOWN状态。
	 */
	clockevents_exchange_device(cur, dev);
	if (cur)
		cur->event_handler = clockevents_handle_noop;
	tick_broadcast_device.evtdev = dev;
	/**
	 * 只要有一个需要TICK广播
	 * 那么我们就要启动broadcast tick device的运作，使之进入周期性tick的mode。
	 */
	if (!cpumask_empty(tick_broadcast_mask))
		tick_broadcast_start_periodic(dev);
	/*
	 * Inform all cpus about this. We might be in a situation
	 * where we did not switch to oneshot mode because the per cpu
	 * devices are affected by CLOCK_EVT_FEAT_C3STOP and the lack
	 * of a oneshot capable broadcast device. Without that
	 * notification the systems stays stuck in periodic mode
	 * forever.
	 */
	/**
	 * broadcast tick设备的clock event device具备one shot能力
	 */
	if (dev->features & CLOCK_EVT_FEAT_ONESHOT)
		/**
		 * 异步通知到各个CPU
		 * 看是否有机会让per cpu tick device也切换到one shot的状态
		 */
		tick_clock_notify();
}

/*
 * Check, if the device is the broadcast device
 */
int tick_is_broadcast_device(struct clock_event_device *dev)
{
	return (dev && tick_broadcast_device.evtdev == dev);
}

int tick_broadcast_update_freq(struct clock_event_device *dev, u32 freq)
{
	int ret = -ENODEV;

	if (tick_is_broadcast_device(dev)) {
		raw_spin_lock(&tick_broadcast_lock);
		ret = __clockevents_update_freq(dev, freq);
		raw_spin_unlock(&tick_broadcast_lock);
	}
	return ret;
}


static void err_broadcast(const struct cpumask *mask)
{
	pr_crit_once("Failed to broadcast timer tick. Some CPUs may be unresponsive.\n");
}

static void tick_device_setup_broadcast_func(struct clock_event_device *dev)
{
	if (!dev->broadcast)
		dev->broadcast = tick_broadcast;
	if (!dev->broadcast) {
		pr_warn_once("%s depends on broadcast, but no broadcast function available\n",
			     dev->name);
		dev->broadcast = err_broadcast;
	}
}

/*
 * Check, if the device is disfunctional and a place holder, which
 * needs to be handled by the broadcast device.
 */
/**
 * 检查当前per cpu tick device的HW timer的特性并确定是否要启用broadcast tick设备
 */
int tick_device_uses_broadcast(struct clock_event_device *dev, int cpu)
{
	struct clock_event_device *bc = tick_broadcast_device.evtdev;
	unsigned long flags;
	int ret = 0;

	raw_spin_lock_irqsave(&tick_broadcast_lock, flags);

	/*
	 * Devices might be registered with both periodic and oneshot
	 * mode disabled. This signals, that the device needs to be
	 * operated from the broadcast device and is a placeholder for
	 * the cpu local device.
	 */
	 /**
	  * 如果有CLOCK_EVT_FEAT_DUMMY标志
	  */
	if (!tick_device_is_functional(dev)) {
		/* 工作于周期性模式 */
		dev->event_handler = tick_handle_periodic;
		/* 由广播设备生成时钟 */
		tick_device_setup_broadcast_func(dev);
		/* 把自己加入到广播接收方 */
		cpumask_set_cpu(cpu, tick_broadcast_mask);
		/* 使广播设备开始工作 */
		if (tick_broadcast_device.mode == TICKDEV_MODE_PERIODIC)
			tick_broadcast_start_periodic(bc);
		else
			tick_broadcast_setup_oneshot(bc);
		ret = 1;
	} else {
		/*
		 * Clear the broadcast bit for this cpu if the
		 * device is not power state affected.
		 */
		/* 本地时钟可以搞定一切 */
		if (!(dev->features & CLOCK_EVT_FEAT_C3STOP))
			/* 把当前CPU从掩码中清除，表示本CPU不需要接收广播 */
			cpumask_clear_cpu(cpu, tick_broadcast_mask);
		else
			/* 否则 设定发送广播的函数为tick_broadcast */
			tick_device_setup_broadcast_func(dev);

		/*
		 * Clear the broadcast bit if the CPU is not in
		 * periodic broadcast on state.
		 */
		if (!cpumask_test_cpu(cpu, tick_broadcast_on))
			cpumask_clear_cpu(cpu, tick_broadcast_mask);

		switch (tick_broadcast_device.mode) {
		case TICKDEV_MODE_ONESHOT:
			/*
			 * If the system is in oneshot mode we can
			 * unconditionally clear the oneshot mask bit,
			 * because the CPU is running and therefore
			 * not in an idle state which causes the power
			 * state affected device to stop. Let the
			 * caller initialize the device.
			 */
			tick_broadcast_clear_oneshot(cpu);
			ret = 0;
			break;

		case TICKDEV_MODE_PERIODIC:
			/*
			 * If the system is in periodic mode, check
			 * whether the broadcast device can be
			 * switched off now.
			 */
			if (cpumask_empty(tick_broadcast_mask) && bc)
				clockevents_shutdown(bc);
			/*
			 * If we kept the cpu in the broadcast mask,
			 * tell the caller to leave the per cpu device
			 * in shutdown state. The periodic interrupt
			 * is delivered by the broadcast device, if
			 * the broadcast device exists and is not
			 * hrtimer based.
			 */
			if (bc && !(bc->features & CLOCK_EVT_FEAT_HRTIMER))
				ret = cpumask_test_cpu(cpu, tick_broadcast_mask);
			break;
		default:
			break;
		}
	}
	raw_spin_unlock_irqrestore(&tick_broadcast_lock, flags);
	return ret;
}

#ifdef CONFIG_GENERIC_CLOCKEVENTS_BROADCAST
int tick_receive_broadcast(void)
{
	struct tick_device *td = this_cpu_ptr(&tick_cpu_device);
	struct clock_event_device *evt = td->evtdev;

	if (!evt)
		return -ENODEV;

	if (!evt->event_handler)
		return -EINVAL;

	evt->event_handler(evt);
	return 0;
}
#endif

/*
 * Broadcast the event to the cpus, which are set in the mask (mangled).
 */
static bool tick_do_broadcast(struct cpumask *mask)
{
	int cpu = smp_processor_id();
	struct tick_device *td;
	bool local = false;

	/*
	 * Check, if the current cpu is in the mask
	 */
	/**
	 * 是否本cpu也需要broadcast tick 设备的服务
	 */
	if (cpumask_test_cpu(cpu, mask)) {
		struct clock_event_device *bc = tick_broadcast_device.evtdev;

		/* 本CPU的事件处理由上层调用者处理 */
		cpumask_clear_cpu(cpu, mask);
		/*
		 * We only run the local handler, if the broadcast
		 * device is not hrtimer based. Otherwise we run into
		 * a hrtimer recursion.
		 *
		 * local timer_interrupt()
		 *   local_handler()
		 *     expire_hrtimers()
		 *       bc_handler()
		 *         local_handler()
		 *	     expire_hrtimers()
		 */
		/* 本CPU是高精度时钟，那么不用在这里调用TICK回调 */
		local = !(bc->features & CLOCK_EVT_FEAT_HRTIMER);
	}

	if (!cpumask_empty(mask)) {/* 除了本CPU，还有其他CPU需要广播 */
		/*
		 * It might be necessary to actually check whether the devices
		 * have different broadcast functions. For now, just use the
		 * one of the first device. This works as long as we have this
		 * misfeature only on x86 (lapic)
		 */
		/* 那就真的向其他CPU广播TICK了 */
		td = &per_cpu(tick_cpu_device, cpumask_first(mask));
		td->evtdev->broadcast(mask);
	}
	/* 如果返回true，则上层调用本CPU的事件回调 */
	return local;
}

/*
 * Periodic broadcast:
 * - invoke the broadcast handlers
 */
static bool tick_do_periodic_broadcast(void)
{
	/**
	 * cpu_online_mask记录了on line的cpu
	 * tick_broadcast_mask记录了申请broad cast服务的cpu
	 * 因此只需要处理那些CPU处于online状态并且申请了broad cast服务的cpu
	 */
	cpumask_and(tmpmask, cpu_online_mask, tick_broadcast_mask);
	return tick_do_broadcast(tmpmask);
}

/*
 * Event handler for periodic broadcast ticks
 */
/**
 * broadcast device的事件处理函数
 */
static void tick_handle_periodic_broadcast(struct clock_event_device *dev)
{
	struct tick_device *td = this_cpu_ptr(&tick_cpu_device);
	bool bc_local;

	raw_spin_lock(&tick_broadcast_lock);

	/* Handle spurious interrupts gracefully */
	if (clockevent_state_shutdown(tick_broadcast_device.evtdev)) {
		raw_spin_unlock(&tick_broadcast_lock);
		return;
	}

	/**
	 * 向其他核广播TICK事件
	 */
	bc_local = tick_do_periodic_broadcast();

	if (clockevent_state_oneshot(dev)) {/* one shot模式 */
		/* 设置下次时钟触发时间 */
		ktime_t next = ktime_add(dev->next_event, tick_period);

		clockevents_program_event(dev, next, true);
	}
	raw_spin_unlock(&tick_broadcast_lock);

	/*
	 * We run the handler of the local cpu after dropping
	 * tick_broadcast_lock because the handler might deadlock when
	 * trying to switch to oneshot mode.
	 */
	/**
	 * 如果本CPU也需要处理tick回调
	 * 则调用本地TICK处理函数
	 */
	if (bc_local)
		td->evtdev->event_handler(td->evtdev);
}

/**
 * tick_broadcast_control - Enable/disable or force broadcast mode
 * @mode:	The selected broadcast mode
 *
 * Called when the system enters a state where affected tick devices
 * might stop. Note: TICK_BROADCAST_FORCE cannot be undone.
 *
 * Called with interrupts disabled, so clockevents_lock is not
 * required here because the local clock event device cannot go away
 * under us.
 */
void tick_broadcast_control(enum tick_broadcast_mode mode)
{
	struct clock_event_device *bc, *dev;
	struct tick_device *td;
	int cpu, bc_stopped;

	td = this_cpu_ptr(&tick_cpu_device);
	dev = td->evtdev;

	/*
	 * Is the device not affected by the powerstate ?
	 */
	if (!dev || !(dev->features & CLOCK_EVT_FEAT_C3STOP))
		return;

	if (!tick_device_is_functional(dev))
		return;

	raw_spin_lock(&tick_broadcast_lock);
	cpu = smp_processor_id();
	bc = tick_broadcast_device.evtdev;
	bc_stopped = cpumask_empty(tick_broadcast_mask);

	switch (mode) {
	case TICK_BROADCAST_FORCE:
		tick_broadcast_forced = 1;
	case TICK_BROADCAST_ON:
		cpumask_set_cpu(cpu, tick_broadcast_on);
		if (!cpumask_test_and_set_cpu(cpu, tick_broadcast_mask)) {
			/*
			 * Only shutdown the cpu local device, if:
			 *
			 * - the broadcast device exists
			 * - the broadcast device is not a hrtimer based one
			 * - the broadcast device is in periodic mode to
			 *   avoid a hickup during switch to oneshot mode
			 */
			if (bc && !(bc->features & CLOCK_EVT_FEAT_HRTIMER) &&
			    tick_broadcast_device.mode == TICKDEV_MODE_PERIODIC)
				clockevents_shutdown(dev);
		}
		break;

	case TICK_BROADCAST_OFF:
		if (tick_broadcast_forced)
			break;
		cpumask_clear_cpu(cpu, tick_broadcast_on);
		if (!tick_device_is_functional(dev))
			break;
		if (cpumask_test_and_clear_cpu(cpu, tick_broadcast_mask)) {
			if (tick_broadcast_device.mode ==
			    TICKDEV_MODE_PERIODIC)
				tick_setup_periodic(dev, 0);
		}
		break;
	}

	if (bc) {
		if (cpumask_empty(tick_broadcast_mask)) {
			if (!bc_stopped)
				clockevents_shutdown(bc);
		} else if (bc_stopped) {
			if (tick_broadcast_device.mode == TICKDEV_MODE_PERIODIC)
				tick_broadcast_start_periodic(bc);
			else
				tick_broadcast_setup_oneshot(bc);
		}
	}
	raw_spin_unlock(&tick_broadcast_lock);
}
EXPORT_SYMBOL_GPL(tick_broadcast_control);

/*
 * Set the periodic handler depending on broadcast on/off
 */
void tick_set_periodic_handler(struct clock_event_device *dev, int broadcast)
{
	if (!broadcast)
		dev->event_handler = tick_handle_periodic;
	else
		dev->event_handler = tick_handle_periodic_broadcast;
}

#ifdef CONFIG_HOTPLUG_CPU
/*
 * Remove a CPU from broadcasting
 */
void tick_shutdown_broadcast(unsigned int cpu)
{
	struct clock_event_device *bc;
	unsigned long flags;

	raw_spin_lock_irqsave(&tick_broadcast_lock, flags);

	bc = tick_broadcast_device.evtdev;
	cpumask_clear_cpu(cpu, tick_broadcast_mask);
	cpumask_clear_cpu(cpu, tick_broadcast_on);

	if (tick_broadcast_device.mode == TICKDEV_MODE_PERIODIC) {
		if (bc && cpumask_empty(tick_broadcast_mask))
			clockevents_shutdown(bc);
	}

	raw_spin_unlock_irqrestore(&tick_broadcast_lock, flags);
}
#endif

void tick_suspend_broadcast(void)
{
	struct clock_event_device *bc;
	unsigned long flags;

	raw_spin_lock_irqsave(&tick_broadcast_lock, flags);

	bc = tick_broadcast_device.evtdev;
	if (bc)
		clockevents_shutdown(bc);

	raw_spin_unlock_irqrestore(&tick_broadcast_lock, flags);
}

/*
 * This is called from tick_resume_local() on a resuming CPU. That's
 * called from the core resume function, tick_unfreeze() and the magic XEN
 * resume hackery.
 *
 * In none of these cases the broadcast device mode can change and the
 * bit of the resuming CPU in the broadcast mask is safe as well.
 */
bool tick_resume_check_broadcast(void)
{
	if (tick_broadcast_device.mode == TICKDEV_MODE_ONESHOT)
		return false;
	else
		return cpumask_test_cpu(smp_processor_id(), tick_broadcast_mask);
}

void tick_resume_broadcast(void)
{
	struct clock_event_device *bc;
	unsigned long flags;

	raw_spin_lock_irqsave(&tick_broadcast_lock, flags);

	bc = tick_broadcast_device.evtdev;

	if (bc) {
		clockevents_tick_resume(bc);

		switch (tick_broadcast_device.mode) {
		case TICKDEV_MODE_PERIODIC:
			if (!cpumask_empty(tick_broadcast_mask))
				tick_broadcast_start_periodic(bc);
			break;
		case TICKDEV_MODE_ONESHOT:
			if (!cpumask_empty(tick_broadcast_mask))
				tick_resume_broadcast_oneshot(bc);
			break;
		}
	}
	raw_spin_unlock_irqrestore(&tick_broadcast_lock, flags);
}

#ifdef CONFIG_TICK_ONESHOT

static cpumask_var_t tick_broadcast_oneshot_mask;
static cpumask_var_t tick_broadcast_pending_mask;
static cpumask_var_t tick_broadcast_force_mask;

/*
 * Exposed for debugging: see timer_list.c
 */
struct cpumask *tick_get_broadcast_oneshot_mask(void)
{
	return tick_broadcast_oneshot_mask;
}

/*
 * Called before going idle with interrupts disabled. Checks whether a
 * broadcast event from the other core is about to happen. We detected
 * that in tick_broadcast_oneshot_control(). The callsite can use this
 * to avoid a deep idle transition as we are about to get the
 * broadcast IPI right away.
 */
int tick_check_broadcast_expired(void)
{
	return cpumask_test_cpu(smp_processor_id(), tick_broadcast_force_mask);
}

/*
 * Set broadcast interrupt affinity
 */
static void tick_broadcast_set_affinity(struct clock_event_device *bc,
					const struct cpumask *cpumask)
{
	if (!(bc->features & CLOCK_EVT_FEAT_DYNIRQ))
		return;

	if (cpumask_equal(bc->cpumask, cpumask))
		return;

	bc->cpumask = cpumask;
	irq_set_affinity(bc->irq, bc->cpumask);
}

static void tick_broadcast_set_event(struct clock_event_device *bc, int cpu,
				     ktime_t expires)
{
	if (!clockevent_state_oneshot(bc))
		clockevents_switch_state(bc, CLOCK_EVT_STATE_ONESHOT);

	clockevents_program_event(bc, expires, 1);
	tick_broadcast_set_affinity(bc, cpumask_of(cpu));
}

static void tick_resume_broadcast_oneshot(struct clock_event_device *bc)
{
	clockevents_switch_state(bc, CLOCK_EVT_STATE_ONESHOT);
}

/*
 * Called from irq_enter() when idle was interrupted to reenable the
 * per cpu device.
 */
void tick_check_oneshot_broadcast_this_cpu(void)
{
	if (cpumask_test_cpu(smp_processor_id(), tick_broadcast_oneshot_mask)) {
		struct tick_device *td = this_cpu_ptr(&tick_cpu_device);

		/*
		 * We might be in the middle of switching over from
		 * periodic to oneshot. If the CPU has not yet
		 * switched over, leave the device alone.
		 */
		if (td->mode == TICKDEV_MODE_ONESHOT) {
			clockevents_switch_state(td->evtdev,
					      CLOCK_EVT_STATE_ONESHOT);
		}
	}
}

/*
 * Handle oneshot mode broadcasting
 */
static void tick_handle_oneshot_broadcast(struct clock_event_device *dev)
{
	struct tick_device *td;
	ktime_t now, next_event;
	int cpu, next_cpu = 0;
	bool bc_local;

	raw_spin_lock(&tick_broadcast_lock);
	dev->next_event.tv64 = KTIME_MAX;
	next_event.tv64 = KTIME_MAX;
	cpumask_clear(tmpmask);
	now = ktime_get();
	/* Find all expired events */
	for_each_cpu(cpu, tick_broadcast_oneshot_mask) {
		td = &per_cpu(tick_cpu_device, cpu);
		if (td->evtdev->next_event.tv64 <= now.tv64) {
			cpumask_set_cpu(cpu, tmpmask);
			/*
			 * Mark the remote cpu in the pending mask, so
			 * it can avoid reprogramming the cpu local
			 * timer in tick_broadcast_oneshot_control().
			 */
			cpumask_set_cpu(cpu, tick_broadcast_pending_mask);
		} else if (td->evtdev->next_event.tv64 < next_event.tv64) {
			next_event.tv64 = td->evtdev->next_event.tv64;
			next_cpu = cpu;
		}
	}

	/*
	 * Remove the current cpu from the pending mask. The event is
	 * delivered immediately in tick_do_broadcast() !
	 */
	cpumask_clear_cpu(smp_processor_id(), tick_broadcast_pending_mask);

	/* Take care of enforced broadcast requests */
	cpumask_or(tmpmask, tmpmask, tick_broadcast_force_mask);
	cpumask_clear(tick_broadcast_force_mask);

	/*
	 * Sanity check. Catch the case where we try to broadcast to
	 * offline cpus.
	 */
	if (WARN_ON_ONCE(!cpumask_subset(tmpmask, cpu_online_mask)))
		cpumask_and(tmpmask, tmpmask, cpu_online_mask);

	/*
	 * Wakeup the cpus which have an expired event.
	 */
	bc_local = tick_do_broadcast(tmpmask);

	/*
	 * Two reasons for reprogram:
	 *
	 * - The global event did not expire any CPU local
	 * events. This happens in dyntick mode, as the maximum PIT
	 * delta is quite small.
	 *
	 * - There are pending events on sleeping CPUs which were not
	 * in the event mask
	 */
	if (next_event.tv64 != KTIME_MAX)
		tick_broadcast_set_event(dev, next_cpu, next_event);

	raw_spin_unlock(&tick_broadcast_lock);

	if (bc_local) {
		td = this_cpu_ptr(&tick_cpu_device);
		td->evtdev->event_handler(td->evtdev);
	}
}

static int broadcast_needs_cpu(struct clock_event_device *bc, int cpu)
{
	if (!(bc->features & CLOCK_EVT_FEAT_HRTIMER))
		return 0;
	if (bc->next_event.tv64 == KTIME_MAX)
		return 0;
	return bc->bound_on == cpu ? -EBUSY : 0;
}

static void broadcast_shutdown_local(struct clock_event_device *bc,
				     struct clock_event_device *dev)
{
	/*
	 * For hrtimer based broadcasting we cannot shutdown the cpu
	 * local device if our own event is the first one to expire or
	 * if we own the broadcast timer.
	 */
	if (bc->features & CLOCK_EVT_FEAT_HRTIMER) {
		if (broadcast_needs_cpu(bc, smp_processor_id()))
			return;
		if (dev->next_event.tv64 < bc->next_event.tv64)
			return;
	}
	clockevents_switch_state(dev, CLOCK_EVT_STATE_SHUTDOWN);
}

int __tick_broadcast_oneshot_control(enum tick_broadcast_state state)
{
	struct clock_event_device *bc, *dev;
	int cpu, ret = 0;
	ktime_t now;

	/*
	 * If there is no broadcast device, tell the caller not to go
	 * into deep idle.
	 */
	if (!tick_broadcast_device.evtdev)
		return -EBUSY;

	dev = this_cpu_ptr(&tick_cpu_device)->evtdev;

	raw_spin_lock(&tick_broadcast_lock);
	bc = tick_broadcast_device.evtdev;
	cpu = smp_processor_id();

	if (state == TICK_BROADCAST_ENTER) {
		/*
		 * If the current CPU owns the hrtimer broadcast
		 * mechanism, it cannot go deep idle and we do not add
		 * the CPU to the broadcast mask. We don't have to go
		 * through the EXIT path as the local timer is not
		 * shutdown.
		 */
		ret = broadcast_needs_cpu(bc, cpu);
		if (ret)
			goto out;

		/*
		 * If the broadcast device is in periodic mode, we
		 * return.
		 */
		if (tick_broadcast_device.mode == TICKDEV_MODE_PERIODIC) {
			/* If it is a hrtimer based broadcast, return busy */
			if (bc->features & CLOCK_EVT_FEAT_HRTIMER)
				ret = -EBUSY;
			goto out;
		}

		if (!cpumask_test_and_set_cpu(cpu, tick_broadcast_oneshot_mask)) {
			WARN_ON_ONCE(cpumask_test_cpu(cpu, tick_broadcast_pending_mask));

			/* Conditionally shut down the local timer. */
			broadcast_shutdown_local(bc, dev);

			/*
			 * We only reprogram the broadcast timer if we
			 * did not mark ourself in the force mask and
			 * if the cpu local event is earlier than the
			 * broadcast event. If the current CPU is in
			 * the force mask, then we are going to be
			 * woken by the IPI right away; we return
			 * busy, so the CPU does not try to go deep
			 * idle.
			 */
			if (cpumask_test_cpu(cpu, tick_broadcast_force_mask)) {
				ret = -EBUSY;
			} else if (dev->next_event.tv64 < bc->next_event.tv64) {
				tick_broadcast_set_event(bc, cpu, dev->next_event);
				/*
				 * In case of hrtimer broadcasts the
				 * programming might have moved the
				 * timer to this cpu. If yes, remove
				 * us from the broadcast mask and
				 * return busy.
				 */
				ret = broadcast_needs_cpu(bc, cpu);
				if (ret) {
					cpumask_clear_cpu(cpu,
						tick_broadcast_oneshot_mask);
				}
			}
		}
	} else {
		if (cpumask_test_and_clear_cpu(cpu, tick_broadcast_oneshot_mask)) {
			clockevents_switch_state(dev, CLOCK_EVT_STATE_ONESHOT);
			/*
			 * The cpu which was handling the broadcast
			 * timer marked this cpu in the broadcast
			 * pending mask and fired the broadcast
			 * IPI. So we are going to handle the expired
			 * event anyway via the broadcast IPI
			 * handler. No need to reprogram the timer
			 * with an already expired event.
			 */
			if (cpumask_test_and_clear_cpu(cpu,
				       tick_broadcast_pending_mask))
				goto out;

			/*
			 * Bail out if there is no next event.
			 */
			if (dev->next_event.tv64 == KTIME_MAX)
				goto out;
			/*
			 * If the pending bit is not set, then we are
			 * either the CPU handling the broadcast
			 * interrupt or we got woken by something else.
			 *
			 * We are not longer in the broadcast mask, so
			 * if the cpu local expiry time is already
			 * reached, we would reprogram the cpu local
			 * timer with an already expired event.
			 *
			 * This can lead to a ping-pong when we return
			 * to idle and therefor rearm the broadcast
			 * timer before the cpu local timer was able
			 * to fire. This happens because the forced
			 * reprogramming makes sure that the event
			 * will happen in the future and depending on
			 * the min_delta setting this might be far
			 * enough out that the ping-pong starts.
			 *
			 * If the cpu local next_event has expired
			 * then we know that the broadcast timer
			 * next_event has expired as well and
			 * broadcast is about to be handled. So we
			 * avoid reprogramming and enforce that the
			 * broadcast handler, which did not run yet,
			 * will invoke the cpu local handler.
			 *
			 * We cannot call the handler directly from
			 * here, because we might be in a NOHZ phase
			 * and we did not go through the irq_enter()
			 * nohz fixups.
			 */
			now = ktime_get();
			if (dev->next_event.tv64 <= now.tv64) {
				cpumask_set_cpu(cpu, tick_broadcast_force_mask);
				goto out;
			}
			/*
			 * We got woken by something else. Reprogram
			 * the cpu local timer device.
			 */
			tick_program_event(dev->next_event, 1);
		}
	}
out:
	raw_spin_unlock(&tick_broadcast_lock);
	return ret;
}

/*
 * Reset the one shot broadcast for a cpu
 *
 * Called with tick_broadcast_lock held
 */
static void tick_broadcast_clear_oneshot(int cpu)
{
	cpumask_clear_cpu(cpu, tick_broadcast_oneshot_mask);
	cpumask_clear_cpu(cpu, tick_broadcast_pending_mask);
}

static void tick_broadcast_init_next_event(struct cpumask *mask,
					   ktime_t expires)
{
	struct tick_device *td;
	int cpu;

	for_each_cpu(cpu, mask) {
		td = &per_cpu(tick_cpu_device, cpu);
		if (td->evtdev)
			td->evtdev->next_event = expires;
	}
}

/**
 * tick_broadcast_setup_oneshot - setup the broadcast device
 */
void tick_broadcast_setup_oneshot(struct clock_event_device *bc)
{
	int cpu = smp_processor_id();

	/* Set it up only once ! */
	if (bc->event_handler != tick_handle_oneshot_broadcast) {
		int was_periodic = clockevent_state_periodic(bc);

		bc->event_handler = tick_handle_oneshot_broadcast;

		/*
		 * We must be careful here. There might be other CPUs
		 * waiting for periodic broadcast. We need to set the
		 * oneshot_mask bits for those and program the
		 * broadcast device to fire.
		 */
		cpumask_copy(tmpmask, tick_broadcast_mask);
		cpumask_clear_cpu(cpu, tmpmask);
		cpumask_or(tick_broadcast_oneshot_mask,
			   tick_broadcast_oneshot_mask, tmpmask);

		if (was_periodic && !cpumask_empty(tmpmask)) {
			clockevents_switch_state(bc, CLOCK_EVT_STATE_ONESHOT);
			tick_broadcast_init_next_event(tmpmask,
						       tick_next_period);
			tick_broadcast_set_event(bc, cpu, tick_next_period);
		} else
			bc->next_event.tv64 = KTIME_MAX;
	} else {
		/*
		 * The first cpu which switches to oneshot mode sets
		 * the bit for all other cpus which are in the general
		 * (periodic) broadcast mask. So the bit is set and
		 * would prevent the first broadcast enter after this
		 * to program the bc device.
		 */
		tick_broadcast_clear_oneshot(cpu);
	}
}

/*
 * Select oneshot operating mode for the broadcast device
 */
void tick_broadcast_switch_to_oneshot(void)
{
	struct clock_event_device *bc;
	unsigned long flags;

	raw_spin_lock_irqsave(&tick_broadcast_lock, flags);

	tick_broadcast_device.mode = TICKDEV_MODE_ONESHOT;
	bc = tick_broadcast_device.evtdev;
	if (bc)
		tick_broadcast_setup_oneshot(bc);

	raw_spin_unlock_irqrestore(&tick_broadcast_lock, flags);
}

#ifdef CONFIG_HOTPLUG_CPU
void hotplug_cpu__broadcast_tick_pull(int deadcpu)
{
	struct clock_event_device *bc;
	unsigned long flags;

	raw_spin_lock_irqsave(&tick_broadcast_lock, flags);
	bc = tick_broadcast_device.evtdev;

	if (bc && broadcast_needs_cpu(bc, deadcpu)) {
		/* This moves the broadcast assignment to this CPU: */
		clockevents_program_event(bc, bc->next_event, 1);
	}
	raw_spin_unlock_irqrestore(&tick_broadcast_lock, flags);
}

/*
 * Remove a dead CPU from broadcasting
 */
void tick_shutdown_broadcast_oneshot(unsigned int cpu)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&tick_broadcast_lock, flags);

	/*
	 * Clear the broadcast masks for the dead cpu, but do not stop
	 * the broadcast device!
	 */
	cpumask_clear_cpu(cpu, tick_broadcast_oneshot_mask);
	cpumask_clear_cpu(cpu, tick_broadcast_pending_mask);
	cpumask_clear_cpu(cpu, tick_broadcast_force_mask);

	raw_spin_unlock_irqrestore(&tick_broadcast_lock, flags);
}
#endif

/*
 * Check, whether the broadcast device is in one shot mode
 */
int tick_broadcast_oneshot_active(void)
{
	return tick_broadcast_device.mode == TICKDEV_MODE_ONESHOT;
}

/*
 * Check whether the broadcast device supports oneshot.
 */
bool tick_broadcast_oneshot_available(void)
{
	struct clock_event_device *bc = tick_broadcast_device.evtdev;

	return bc ? bc->features & CLOCK_EVT_FEAT_ONESHOT : false;
}

#else
int __tick_broadcast_oneshot_control(enum tick_broadcast_state state)
{
	struct clock_event_device *bc = tick_broadcast_device.evtdev;

	if (!bc || (bc->features & CLOCK_EVT_FEAT_HRTIMER))
		return -EBUSY;

	return 0;
}
#endif

void __init tick_broadcast_init(void)
{
	zalloc_cpumask_var(&tick_broadcast_mask, GFP_NOWAIT);
	zalloc_cpumask_var(&tick_broadcast_on, GFP_NOWAIT);
	zalloc_cpumask_var(&tmpmask, GFP_NOWAIT);
#ifdef CONFIG_TICK_ONESHOT
	zalloc_cpumask_var(&tick_broadcast_oneshot_mask, GFP_NOWAIT);
	zalloc_cpumask_var(&tick_broadcast_pending_mask, GFP_NOWAIT);
	zalloc_cpumask_var(&tick_broadcast_force_mask, GFP_NOWAIT);
#endif
}
