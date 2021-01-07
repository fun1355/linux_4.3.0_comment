#ifndef _LINUX_SLAB_DEF_H
#define	_LINUX_SLAB_DEF_H

#include <linux/reciprocal_div.h>

/*
 * Definitions unique to the original Linux SLAB allocator.
 */

/**
 * slab分配器描述符
 */
struct kmem_cache {
	/**
	 * 为每个CPU缓存的临时对象，可以加快每个CPU上的分配过程
	 * 类似于伙伴系统中的PCP
	 */
	struct array_cache __percpu *cpu_cache;

/* 1) Cache tunables. Protected by slab_mutex */
	/**
	 * 由slab_mutex保护
	 * batchcount一次性向缓存中添加多少个对象
	 * limit缓存对象数量限制
	 */
	unsigned int batchcount;
	unsigned int limit;
	unsigned int shared;

	//slab头部大小??
	unsigned int size;
	//加快内部计算过程用的临时变量
	struct reciprocal_value reciprocal_buffer_size;
/* 2) touched by every alloc & free from the backend */

	//slab对象属性，如CFLGS_OFF_SLAB
	unsigned int flags;		/* constant flags */
	//每个slab中的对象个数
	unsigned int num;		/* # of objs per slab */

/* 3) cache_grow/shrink */
	/* order of pgs per slab (2^n) */
	//扩充或者收缩slab时，分配或者释放的内存order。
	unsigned int gfporder;

	/* force GFP flags, e.g. GFP_DMA */
	//分配内存的GFP标志，依赖于上层调用方式。
	gfp_t allocflags;

	//着色范围。
	size_t colour;			/* cache colouring range */
	//两次着色之间的差
	unsigned int colour_off;	/* colour offset */
	//当kmem_cache位于slab外面时，预先分配的kmem_cache对象指针及其数量。
	struct kmem_cache *freelist_cache;
	unsigned int freelist_size;

	/* constructor func */
	//分配slab时的回调
	void (*ctor)(void *obj);

/* 4) cache creation/removal */
	//显示在proc/slabinfo中的名称
	const char *name;
	//通过此字段将对象链接到cache_chain链表
	struct list_head list;
	//引用计数
	int refcount;
	//slab对象大小
	int object_size;
	int align;

/* 5) statistics */
#ifdef CONFIG_DEBUG_SLAB
	unsigned long num_active;
	unsigned long num_allocations;
	unsigned long high_mark;
	unsigned long grown;
	unsigned long reaped;
	unsigned long errors;
	unsigned long max_freeable;
	unsigned long node_allocs;
	unsigned long node_frees;
	unsigned long node_overflow;
	atomic_t allochit;
	atomic_t allocmiss;
	atomic_t freehit;
	atomic_t freemiss;

	/*
	 * If debugging is enabled, then the allocator can add additional
	 * fields and/or padding to every object. size contains the total
	 * object size including these internal fields, the following two
	 * variables contain the offset to the user object and its size.
	 */
	int obj_offset;
#endif /* CONFIG_DEBUG_SLAB */
#ifdef CONFIG_MEMCG_KMEM
	struct memcg_cache_params memcg_params;
#endif

	/**
	 * 按节点管理的kmem_cache_node描述符。
	 * 每个kmem_cache_node管理空闲、满、可用slab
	 */
	struct kmem_cache_node *node[MAX_NUMNODES];
};

#endif	/* _LINUX_SLAB_DEF_H */
