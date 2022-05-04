#ifndef __BSD_LAYER_H__
#define __BSD_LAYER_H__

#include <stdbool.h>
#include <stdio.h>

#include <uk/arch/atomic.h>
#include <uk/assert.h>
#include <uk/errptr.h>
#include <uk/mutex.h>
#include <uk/wait.h>
#include <uk/wait_types.h>
#include <hyperv-x86/delay.h>

#define PAGE_SIZE __PAGE_SIZE
#define PAGE_SHIFT __PAGE_SHIFT

#define MAXCPU 1
#define curcpu 0
#define mp_ncpus 1

#define curcpu 0
#define bootverbose 1

typedef unsigned char u_char;
typedef unsigned int u_int;
typedef unsigned long u_long;

typedef bool boolean_t;

struct device {
};

typedef struct device *device_t;
#define device_printf(dev, fmt, ...) uk_pr_info( "%p: " fmt, &dev, ##__VA_ARGS__ )
#define panic( ... ) UK_CRASH( __VA_ARGS__ )

#define __printflike( ... )

#define nitems(items) (int)(sizeof(items)/sizeof(items[0]))

#define __aligned __align


#define mtx_sleep(wq, condition, lock, priority, msg, deadline) \
    uk_waitq_wait_event_deadline_locked(wq, condition, ukplat_monotonic_clock() + deadline, \
					    uk_mutex_lock, uk_mutex_unlock, lock)

#define wakeup(wq) \
    uk_waitq_wake_up(wq)

#define mtx uk_mutex
#define mtx_init(lock) uk_mutex_init(lock)
#define mtx_lock(lock) \
    uk_mutex_lock(lock)

#define mtx_unlock(lock) \
    uk_mutex_unlock(lock)

#define mtx_lock_spin(lock) \
    uk_mutex_lock(lock)


#define mtx_unlock_spin(lock) \
    uk_mutex_unlock(lock)


// Check copyright
#ifndef	__DEVOLATILE
#define	__DEVOLATILE(type, var)	((type)(uintptr_t)(volatile void *)(var))
#endif

#ifndef KASSERT
#ifdef CONFIG_LIBUKDEBUG_ENABLE_ASSERT
#define KASSERT(x, msg)							\
	do {								\
		if (unlikely(!(x))) {					\
			uk_pr_crit("Assertion failure: %s\n",		\
				   STRINGIFY(x));			\
			uk_pr_crit msg;			\
			uk_pr_crit("\n");			\
			/* TODO: stack trace */				\
			ukplat_terminate(UKPLAT_CRASH);			\
		}							\
	} while (0)
#endif
#endif

#ifndef DELAY
#define DELAY(delay) udelay(delay)
#endif

typedef void (*task_fn_t)(void *context);

struct iovec { void *iov_base; size_t iov_len; };

#define TAILQ_HEAD UK_TAILQ_HEAD
#define TAILQ_ENTRY UK_TAILQ_ENTRY
#define TAILQ_INIT UK_TAILQ_INIT
#define TAILQ_EMPTY UK_TAILQ_EMPTY
#define TAILQ_FOREACH UK_TAILQ_FOREACH
#define TAILQ_INSERT_TAIL UK_TAILQ_INSERT_TAIL
#define TAILQ_REMOVE UK_TAILQ_REMOVE

#define sx uk_mutex
#define sx_init(lock) uk_mutex_init(lock)
#define sx_lock(lock) uk_mutex_lock(lock)
#define sx_xlock(lock) uk_mutex_lock(lock)
#define sx_xunlock(lock) uk_mutex_unlock(lock)

#define sbintime_t int
#define boolean_t int
#define FALSE 0
#define TRUE 1

#define atomic_add_int(src, val) 	__atomic_fetch_add(src, val, __ATOMIC_SEQ_CST)
#define atomic_subtract_int(src, val) 	__atomic_fetch_sub(src, val, __ATOMIC_SEQ_CST)

// #define atomic_fetchadd_int(src, val) 	__atomic_fetch_add(src, val, __ATOMIC_SEQ_CST)

/*
 * Atomically add the value of v to the integer pointed to by p and return
 * the previous value of *p.
 */
static __inline u_int
atomic_fetchadd_int(volatile u_int *p, u_int v)
{

	__asm __volatile(
	" lock; xaddl	%0,%1 ;		"
	"# atomic_fetchadd_int"
	: "+r" (v),			/* 0 */
	  "+m" (*p)			/* 1 */
	: : "cc");
	return (v);
}

/*
 * Atomically add the value of v to the long integer pointed to by p and return
 * the previous value of *p.
 */
static __inline u_long
atomic_fetchadd_long(volatile u_long *p, u_long v)
{

	__asm __volatile(
	" lock;	xaddq	%0,%1 ;		"
	"# atomic_fetchadd_long"
	: "+r" (v),			/* 0 */
	  "+m" (*p)			/* 1 */
	: : "cc");
	return (v);
}

static __inline int
atomic_testandset_int(volatile u_int *p, u_int v)
{
	u_char res;

	__asm __volatile(
	" lock;	btsl	%2,%1 ;		"
	"# atomic_testandset_int"
	: "=@ccc" (res),		/* 0 */
	  "+m" (*p)			/* 1 */
	: "Ir" (v & 0x1f)		/* 2 */
	: "cc");
	return (res);
}

static __inline int
atomic_testandset_long(volatile u_long *p, u_int v)
{
	u_char res;

	__asm __volatile(
	" lock;	btsq	%2,%1 ;		"
	"# atomic_testandset_long"
	: "=@ccc" (res),		/* 0 */
	  "+m" (*p)			/* 1 */
	: "Jr" ((u_long)(v & 0x3f))	/* 2 */
	: "cc");
	return (res);
}

static __inline int
atomic_testandclear_int(volatile u_int *p, u_int v)
{
	u_char res;

	__asm __volatile(
	" lock;	btrl	%2,%1 ;		"
	"# atomic_testandclear_int"
	: "=@ccc" (res),		/* 0 */
	  "+m" (*p)			/* 1 */
	: "Ir" (v & 0x1f)		/* 2 */
	: "cc");
	return (res);
}

static __inline int
atomic_testandclear_long(volatile u_long *p, u_int v)
{
	u_char res;

	__asm __volatile(
	" lock;	btrq	%2,%1 ;		"
	"# atomic_testandclear_long"
	: "=@ccc" (res),		/* 0 */
	  "+m" (*p)			/* 1 */
	: "Jr" ((u_long)(v & 0x3f))	/* 2 */
	: "cc");
	return (res);
}

/* Read the current value and store a new value in the destination. */
static __inline u_int
atomic_swap_int(volatile u_int *p, u_int v)
{

	__asm __volatile(
	"	xchgl	%1,%0 ;		"
	"# atomic_swap_int"
	: "+r" (v),			/* 0 */
	  "+m" (*p));			/* 1 */
	return (v);
}

static __inline u_long
atomic_swap_long(volatile u_long *p, u_long v)
{

	__asm __volatile(
	"	xchgq	%1,%0 ;		"
	"# atomic_swap_long"
	: "+r" (v),			/* 0 */
	  "+m" (*p));			/* 1 */
	return (v);
}

#define __predict_false unlikely

#define __compiler_membar() mb()

#endif /* __BSD_LAYER_H__ */
