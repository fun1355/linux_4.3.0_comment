#ifndef _UAPI_LINUX_TIME_H
#define _UAPI_LINUX_TIME_H

#include <linux/types.h>


#ifndef _STRUCT_TIMESPEC
#define _STRUCT_TIMESPEC
/**
 * 纳秒精度的时间
 * 满足POSIX标准
 */
struct timespec {
	__kernel_time_t	tv_sec;			/* seconds */
	long		tv_nsec;		/* nanoseconds */
};
#endif

/**
 * 微秒精度的时间
 */
struct timeval {
	__kernel_time_t		tv_sec;		/* seconds */
	__kernel_suseconds_t	tv_usec;	/* microseconds */
};

struct timezone {
	int	tz_minuteswest;	/* minutes west of Greenwich */
	int	tz_dsttime;	/* type of dst correction */
};


/*
 * Names of the interval timers, and structure
 * defining a timer setting:
 */
/**
 * real-time
 * 基于CLOCK_REALTIME计时，超时后发送SIGALRM信号
 * 和alarm函数一样
 */
#define	ITIMER_REAL		0
/**
 * 只有当该进程的用户空间代码执行的时候才计时
 * 超时后发送SIGVTALRM信号
 */
#define	ITIMER_VIRTUAL		1
/**
 * 只有该进程执行的时候才计时，不论是执行用户空间代码还是陷入内核执行（例如系统调用）
 * 超时后发送SIGPROF信号。
 */
#define	ITIMER_PROF		2

struct itimerspec {
	struct timespec it_interval;	/* timer period */
	struct timespec it_value;	/* timer expiration */
};

/**
 * getitimer的定时器值
 */
struct itimerval {
	/**
	 * 间隔时间
	 */
	struct timeval it_interval;	/* timer interval */
	/**
	 * 下次定时器开始时间
	 */
	struct timeval it_value;	/* current value */
};

/*
 * The IDs of the various system clocks (for POSIX.1b interval timers):
 */
/**
 * 真实世界的时钟，即墙上时钟
 * 可以对该系统时钟进行修改，产生不连续的时间间断点。
 * 也可以通过NTP对该时钟进行调整
 */
#define CLOCK_REALTIME			0
/**
 * 真实世界的时钟，单调递增。
 * 不能手动调整，但是可以通过NTP协议进行调整
 * 其基准点不一定是linux epoch
 * 一般会把系统启动的时间点设定为其基准点
 */
#define CLOCK_MONOTONIC			1
/**
 * 基于进程或者线程执行时间来计算的时间
 * 参考clock_getcpuclockid
 */
#define CLOCK_PROCESS_CPUTIME_ID	2
#define CLOCK_THREAD_CPUTIME_ID		3
/**
 * 与CLOCK_MONOTONIC类似
 * 但是不允许NTP对其进行调整
 * 启动时设置为0
 */
#define CLOCK_MONOTONIC_RAW		4
/**
 * CLOCK_REALTIME_COARSE、CLOCK_MONOTONIC_COARSE的概念和CLOCK_REALTIME、CLOCK_MONOTONIC类似
 * 但是精度是比较粗的版本。
 */
#define CLOCK_REALTIME_COARSE		5
#define CLOCK_MONOTONIC_COARSE		6
/**
 * 和CLOCK_MONOTONIC类似，也是单调上涨
 * 在系统初始化的时候设定的基准数值是0
 * 不过CLOCK_BOOTTIME计算系统suspend的时间
 */
#define CLOCK_BOOTTIME			7
/**
 * 主要用于Alarmtimer，这种timer是基于RTC的
 */
#define CLOCK_REALTIME_ALARM		8
#define CLOCK_BOOTTIME_ALARM		9
#define CLOCK_SGI_CYCLE			10	/* Hardware specific */
/**
 * 原子钟的时间
 * 和基于UTC的CLOCK_REALTIME类似，不过没有闰秒
 */
#define CLOCK_TAI			11

#define MAX_CLOCKS			16
#define CLOCKS_MASK			(CLOCK_REALTIME | CLOCK_MONOTONIC)
#define CLOCKS_MONO			CLOCK_MONOTONIC

/*
 * The various flags for setting POSIX.1b interval timers:
 */
#define TIMER_ABSTIME			0x01

#endif /* _UAPI_LINUX_TIME_H */
