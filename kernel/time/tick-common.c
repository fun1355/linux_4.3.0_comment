/*
 * linux/kernel/time/tick-common.c
 *
 * This file contains the base functions to manage periodic tick
 * related events.
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
#include <linux/module.h>
#include <trace/events/power.h>

#include <asm/irq_regs.h>

#include "tick-internal.h"

/*
 * Tick devices
 */
DEFINE_PER_CPU(struct tick_device, tick_cpu_device);
/*
 * Tick next event: keeps track of the tick time
 */
/**
 * 周期性TICK的下一个周期
 */
ktime_t tick_next_period;
/**
 * 周期性TICK的周期间隔
 */
ktime_t tick_period;

/*
 * tick_do_timer_cpu is a timer core internal variable which holds the CPU NR
 * which is responsible for calling do_timer(), i.e. the timekeeping stuff. This
 * variable has two functions:
 *
 * 1) Prevent a thundering herd issue of a gazillion of CPUs trying to grab the
 *    timekeeping lock all at once. Only the CPU which is assigned to do the
 *    update is handling it.
 *
 * 2) Hand off the duty in the NOHZ idle case by setting the value to
 *    TICK_DO_TIMER_NONE, i.e. a non existing CPU. So the next cpu which looks
 *    at it will take over and keep the time keeping alive.  The handover
 *    procedure also covers cpu hotplug.
 */
/**
 * 哪一个CPU上的 tick设备作为全局tick
 * 更新jiffies，更新系统的wall time，更新系统的平均负载
 */
int tick_do_timer_cpu __read_mostly = TICK_DO_TIMER_BOOT;

/*
 * Debugging: see timer_list.c
 */
struct tick_device *tick_get_device(int cpu)
{
	return &per_cpu(tick_cpu_device, cpu);
}

/**
 * tick_is_oneshot_available - check for a oneshot capable event device
 */
/**
 * 检查本地TICK设备是否适合进入one shot模式
 */
int tick_is_oneshot_available(void)
{
	struct clock_event_device *dev = __this_cpu_read(tick_cpu_device.evtdev);

	/* 设备是否支持one shot模式 */
	if (!dev || !(dev->features & CLOCK_EVT_FEAT_ONESHOT))
		return 0;
	/* C3时，设备也不会停止，这个太好了 */
	if (!(dev->features & CLOCK_EVT_FEAT_C3STOP))
		return 1;
	/* 如果C3时会停止，那就得看广播设备是否可用 */
	return tick_broadcast_oneshot_available();
}

/*
 * Periodic tick
 */
static void tick_periodic(int cpu)
{
	/* 全局时钟 */
	if (tick_do_timer_cpu == cpu) {
		write_seqlock(&jiffies_lock);

		/* Keep track of the next tick event */
		tick_next_period = ktime_add(tick_next_period, tick_period);

		/* 修改jiffies，计算系统负荷。 */
		do_timer(1);
		write_sequnlock(&jiffies_lock);
		/* 更新系统时间 */
		update_wall_time();
	}

	/**
	 * 更新当前系统运行时间
	 */
	update_process_times(user_mode(get_irq_regs()));
	/* 处理profile */
	profile_tick(CPU_PROFILING);
}

/*
 * Event handler for periodic ticks
 */
/**
 * 周期性时钟中断回调
 */
void tick_handle_periodic(struct clock_event_device *dev)
{
	int cpu = smp_processor_id();
	ktime_t next = dev->next_event;

	/* 周期性tick中要处理的内容 */
	tick_periodic(cpu);

#if defined(CONFIG_HIGH_RES_TIMERS) || defined(CONFIG_NO_HZ_COMMON)
	/*
	 * The cpu might have transitioned to HIGHRES or NOHZ mode via
	 * update_process_times() -> run_local_timers() ->
	 * hrtimer_run_queues().
	 */
	if (dev->event_handler != tick_handle_periodic)
		return;
#endif

	/**
	 * 不是one shot模式
	 * 就不必对one shot进行编程了
	 */
	if (!clockevent_state_oneshot(dev))
		return;
	for (;;) {
		/*
		 * Setup the next period for devices, which do not have
		 * periodic mode:
		 */
		/* 计算下一个周期性tick触发的时间 */
		next = ktime_add(next, tick_period);

		/* 设定下一个clock event触发的时间 */
		if (!clockevents_program_event(dev, next, false))
			return;
		/*
		 * Have to be careful here. If we're in oneshot mode,
		 * before we call tick_periodic() in a loop, we need
		 * to be sure we're using a real hardware clocksource.
		 * Otherwise we could get trapped in an infinite
		 * loop, as the tick_periodic() increments jiffies,
		 * which then will increment time, possibly causing
		 * the loop to trigger again and again.
		 */
		/* 竟然设置失败了，应该是下一个中断又到期了 */
		if (timekeeping_valid_for_hres())
			/* 补充执行一下，然后设置再下一个定时器 */
			tick_periodic(cpu);
	}
}

/*
 * Setup the device for a periodic tick
 */
/**
 * 将时钟设备设置为周期性模式
 */
void tick_setup_periodic(struct clock_event_device *dev, int broadcast)
{
	/**
	 * 对于tick device ，设定event handler为tick_handle_periodic
	 * 对于broadcast tick device，event handler被设定为tick_handle_periodic_broadcast
	 */
	tick_set_periodic_handler(dev, broadcast);

	/* Broadcast setup ? */
	if (!tick_device_is_functional(dev))
		return;

	if ((dev->features & CLOCK_EVT_FEAT_PERIODIC) && /* 设备支持周期性模式 */
	    !tick_broadcast_oneshot_active()) {/* 并且目前one shot还不可用 */
	    	/* 直接设定为周期性模式即可 */
		clockevents_switch_state(dev, CLOCK_EVT_STATE_PERIODIC);
	} else {
		unsigned long seq;
		ktime_t next;

		do {
			seq = read_seqbegin(&jiffies_lock);
			/**
			 * 获取下一个周期性tick触发的时间
			 */
			next = tick_next_period;
		} while (read_seqretry(&jiffies_lock, seq));

		/**
		 * 模式设定
		 */
		clockevents_switch_state(dev, CLOCK_EVT_STATE_ONESHOT);

		for (;;) {
			/* 事件编程 */
			if (!clockevents_program_event(dev, next, false))
				return;
			/* 计算下一个周期性tick触发的时间 */
			next = ktime_add(next, tick_period);
		}
	}
}

/*
 * Setup the tick device
 */
static void tick_setup_device(struct tick_device *td,
			      struct clock_event_device *newdev, int cpu,
			      const struct cpumask *cpumask)
{
	ktime_t next_event;
	void (*handler)(struct clock_event_device *) = NULL;

	/*
	 * First device setup ?
	 */
	if (!td->evtdev) {
		/*
		 * If no cpu took the do_timer update, assign it to
		 * this cpu:
		 */
		/**
		 * 前系统中没有global tick设备
		 */
		if (tick_do_timer_cpu == TICK_DO_TIMER_BOOT) {
			/**
			 * 那么可以考虑选择该tick设备作为global设备
			 * 进行系统时间和jiffies的更新
			 */
			if (!tick_nohz_full_cpu(cpu))
				tick_do_timer_cpu = cpu;
			else
				tick_do_timer_cpu = TICK_DO_TIMER_NONE;
			/* 设置这两个变量，全局tick可以开工了 */
			tick_next_period = ktime_get();
			tick_period = ktime_set(0, NSEC_PER_SEC / HZ);
		}

		/*
		 * Startup in periodic mode first.
		 */
		/**
		 * 最初都设置为周期性的
		 */
		td->mode = TICKDEV_MODE_PERIODIC;
	} else {
		/**
		 * 旧的clockevent设备就要退居二线了
		 * 将其handler修改为clockevents_handle_noop
		 */
		handler = td->evtdev->event_handler;
		next_event = td->evtdev->next_event;
		td->evtdev->event_handler = clockevents_handle_noop;
	}

	/* 终于修成正果了 */
	td->evtdev = newdev;

	/*
	 * When the device is not per cpu, pin the interrupt to the
	 * current cpu:
	 */
	/* 当然还没有在该CPU上产生中断 */
	if (!cpumask_equal(newdev->cpumask, cpumask))
		/* 让中断亲和到本CPU */
		irq_set_affinity(newdev->irq, cpumask);

	/*
	 * When global broadcasting is active, check if the current
	 * device is registered as a placeholder for broadcast mode.
	 * This allows us to handle this x86 misfeature in a generic
	 * way. This function also returns !=0 when we keep the
	 * current active broadcast state for this CPU.
	 */
	/* 广播设备，不能修改它的模式 */
	if (tick_device_uses_broadcast(newdev, cpu))
		return;

	if (td->mode == TICKDEV_MODE_PERIODIC)
		/**
		 * 如果底层的clock event device支持periodic模式
		 * 那么直接调用clockevents_set_mode设定模式就OK了
		 */
		tick_setup_periodic(newdev, 0);
	else
		/**
		 * 如果底层的clock event device不支持periodic模式
		 * 而tick device目前是周期性tick mode
		 * 那么要稍微复杂一些
		 * 需要用clock event device的one shot模式来实现周期性tick
		 */
		tick_setup_oneshot(newdev, handler, next_event);
}

void tick_install_replacement(struct clock_event_device *newdev)
{
	struct tick_device *td = this_cpu_ptr(&tick_cpu_device);
	int cpu = smp_processor_id();

	clockevents_exchange_device(td->evtdev, newdev);
	tick_setup_device(td, newdev, cpu, cpumask_of(cpu));
	if (newdev->features & CLOCK_EVT_FEAT_ONESHOT)
		tick_oneshot_notify();
}

static bool tick_check_percpu(struct clock_event_device *curdev,
			      struct clock_event_device *newdev, int cpu)
{
	if (!cpumask_test_cpu(cpu, newdev->cpumask))
		return false;
	if (cpumask_equal(newdev->cpumask, cpumask_of(cpu)))
		return true;
	/* Check if irq affinity can be set */
	if (newdev->irq >= 0 && !irq_can_set_affinity(newdev->irq))
		return false;
	/* Prefer an existing cpu local device */
	if (curdev && cpumask_equal(curdev->cpumask, cpumask_of(cpu)))
		return false;
	return true;
}

static bool tick_check_preferred(struct clock_event_device *curdev,
				 struct clock_event_device *newdev)
{
	/* Prefer oneshot capable device */
	if (!(newdev->features & CLOCK_EVT_FEAT_ONESHOT)) {
		if (curdev && (curdev->features & CLOCK_EVT_FEAT_ONESHOT))
			return false;
		if (tick_oneshot_mode_active())
			return false;
	}

	/*
	 * Use the higher rated one, but prefer a CPU local device with a lower
	 * rating than a non-CPU local device
	 */
	return !curdev ||
		newdev->rating > curdev->rating ||
	       !cpumask_equal(curdev->cpumask, newdev->cpumask);
}

/*
 * Check whether the new device is a better fit than curdev. curdev
 * can be NULL !
 */
bool tick_check_replacement(struct clock_event_device *curdev,
			    struct clock_event_device *newdev)
{
	if (!tick_check_percpu(curdev, newdev, smp_processor_id()))
		return false;

	return tick_check_preferred(curdev, newdev);
}

/*
 * Check, if the new registered device should be used. Called with
 * clockevents_lock held and interrupts disabled.
 */
/**
 * 在注册时钟设备的时候，调用此函数
 * 检查是否将其初始化为Tick设备
 */
void tick_check_new_device(struct clock_event_device *newdev)
{
	struct clock_event_device *curdev;
	struct tick_device *td;
	int cpu;

	cpu = smp_processor_id();
	/* 获取当前cpu的tick device */
	td = &per_cpu(tick_cpu_device, cpu);
	curdev = td->evtdev;

	/* cpu local device ? */
	/**
	 * 这是本CPU可用的tick设备吗
	 * 检查其CPU掩码
	 * 以及中断亲和性
	 */
	if (!tick_check_percpu(curdev, newdev, cpu))
		/* 如果不是，那么看能不能做为广播设备 */
		goto out_bc;

	/* Preference decision */
	/**
	 * 看看是不是比目前的tick设备更好
	 */
	if (!tick_check_preferred(curdev, newdev))
		goto out_bc;

	/* 增加模块引用计数 */
	if (!try_module_get(newdev->owner))
		return;

	/*
	 * Replace the eventually existing device by the new
	 * device. If the current device is the broadcast device, do
	 * not give it back to the clockevents layer !
	 */
	/**
	 * 当前Tick设备是广播设备
	 */
	if (tick_is_broadcast_device(curdev)) {
		/* 把广播设备关闭 */
		clockevents_shutdown(curdev);
		/* 防止clockevents_exchange_device将其从链表中摘除 */
		curdev = NULL;
	}
	/* 通知clockevent layer */
	clockevents_exchange_device(curdev, newdev);
	/* 启动新设备 */
	tick_setup_device(td, newdev, cpu, cpumask_of(cpu));
	/* 设备支持one shot */
	if (newdev->features & CLOCK_EVT_FEAT_ONESHOT)
		tick_oneshot_notify();
	return;

out_bc:
	/*
	 * Can the new device be used as a broadcast device ?
	 */
	tick_install_broadcast_device(newdev);
}

/**
 * tick_broadcast_oneshot_control - Enter/exit broadcast oneshot mode
 * @state:	The target state (enter/exit)
 *
 * The system enters/leaves a state, where affected devices might stop
 * Returns 0 on success, -EBUSY if the cpu is used to broadcast wakeups.
 *
 * Called with interrupts disabled, so clockevents_lock is not
 * required here because the local clock event device cannot go away
 * under us.
 */
int tick_broadcast_oneshot_control(enum tick_broadcast_state state)
{
	struct tick_device *td = this_cpu_ptr(&tick_cpu_device);

	if (!(td->evtdev->features & CLOCK_EVT_FEAT_C3STOP))
		return 0;

	return __tick_broadcast_oneshot_control(state);
}
EXPORT_SYMBOL_GPL(tick_broadcast_oneshot_control);

#ifdef CONFIG_HOTPLUG_CPU
/*
 * Transfer the do_timer job away from a dying cpu.
 *
 * Called with interrupts disabled. Not locking required. If
 * tick_do_timer_cpu is owned by this cpu, nothing can change it.
 */
void tick_handover_do_timer(void)
{
	if (tick_do_timer_cpu == smp_processor_id()) {
		int cpu = cpumask_first(cpu_online_mask);

		tick_do_timer_cpu = (cpu < nr_cpu_ids) ? cpu :
			TICK_DO_TIMER_NONE;
	}
}

/*
 * Shutdown an event device on a given cpu:
 *
 * This is called on a life CPU, when a CPU is dead. So we cannot
 * access the hardware device itself.
 * We just set the mode and remove it from the lists.
 */
void tick_shutdown(unsigned int cpu)
{
	struct tick_device *td = &per_cpu(tick_cpu_device, cpu);
	struct clock_event_device *dev = td->evtdev;

	td->mode = TICKDEV_MODE_PERIODIC;
	if (dev) {
		/*
		 * Prevent that the clock events layer tries to call
		 * the set mode function!
		 */
		clockevent_set_state(dev, CLOCK_EVT_STATE_DETACHED);
		clockevents_exchange_device(dev, NULL);
		dev->event_handler = clockevents_handle_noop;
		td->evtdev = NULL;
	}
}
#endif

/**
 * tick_suspend_local - Suspend the local tick device
 *
 * Called from the local cpu for freeze with interrupts disabled.
 *
 * No locks required. Nothing can change the per cpu device.
 */
void tick_suspend_local(void)
{
	struct tick_device *td = this_cpu_ptr(&tick_cpu_device);

	clockevents_shutdown(td->evtdev);
}

/**
 * tick_resume_local - Resume the local tick device
 *
 * Called from the local CPU for unfreeze or XEN resume magic.
 *
 * No locks required. Nothing can change the per cpu device.
 */
void tick_resume_local(void)
{
	struct tick_device *td = this_cpu_ptr(&tick_cpu_device);
	bool broadcast = tick_resume_check_broadcast();

	clockevents_tick_resume(td->evtdev);
	if (!broadcast) {
		if (td->mode == TICKDEV_MODE_PERIODIC)
			tick_setup_periodic(td->evtdev, 0);
		else
			tick_resume_oneshot();
	}
}

/**
 * tick_suspend - Suspend the tick and the broadcast device
 *
 * Called from syscore_suspend() via timekeeping_suspend with only one
 * CPU online and interrupts disabled or from tick_unfreeze() under
 * tick_freeze_lock.
 *
 * No locks required. Nothing can change the per cpu device.
 */
void tick_suspend(void)
{
	tick_suspend_local();
	tick_suspend_broadcast();
}

/**
 * tick_resume - Resume the tick and the broadcast device
 *
 * Called from syscore_resume() via timekeeping_resume with only one
 * CPU online and interrupts disabled.
 *
 * No locks required. Nothing can change the per cpu device.
 */
void tick_resume(void)
{
	tick_resume_broadcast();
	tick_resume_local();
}

#ifdef CONFIG_SUSPEND
static DEFINE_RAW_SPINLOCK(tick_freeze_lock);
static unsigned int tick_freeze_depth;

/**
 * tick_freeze - Suspend the local tick and (possibly) timekeeping.
 *
 * Check if this is the last online CPU executing the function and if so,
 * suspend timekeeping.  Otherwise suspend the local tick.
 *
 * Call with interrupts disabled.  Must be balanced with %tick_unfreeze().
 * Interrupts must not be enabled before the subsequent %tick_unfreeze().
 */
void tick_freeze(void)
{
	raw_spin_lock(&tick_freeze_lock);

	tick_freeze_depth++;
	if (tick_freeze_depth == num_online_cpus()) {
		trace_suspend_resume(TPS("timekeeping_freeze"),
				     smp_processor_id(), true);
		timekeeping_suspend();
	} else {
		tick_suspend_local();
	}

	raw_spin_unlock(&tick_freeze_lock);
}

/**
 * tick_unfreeze - Resume the local tick and (possibly) timekeeping.
 *
 * Check if this is the first CPU executing the function and if so, resume
 * timekeeping.  Otherwise resume the local tick.
 *
 * Call with interrupts disabled.  Must be balanced with %tick_freeze().
 * Interrupts must not be enabled after the preceding %tick_freeze().
 */
void tick_unfreeze(void)
{
	raw_spin_lock(&tick_freeze_lock);

	if (tick_freeze_depth == num_online_cpus()) {
		timekeeping_resume();
		trace_suspend_resume(TPS("timekeeping_freeze"),
				     smp_processor_id(), false);
	} else {
		tick_resume_local();
	}

	tick_freeze_depth--;

	raw_spin_unlock(&tick_freeze_lock);
}
#endif /* CONFIG_SUSPEND */

/**
 * tick_init - initialize the tick control
 */
void __init tick_init(void)
{
	tick_broadcast_init();
	tick_nohz_init();
}
