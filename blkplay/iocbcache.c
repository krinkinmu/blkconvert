#include <stdlib.h>
#include <libaio.h>

#include "stack.h"

struct cache_entry {
	union {
		struct stack_head link;
		struct iocb iocb;
	} u;
};


static struct stack_head *stack;


static struct iocb *STACK_ENTRY(struct stack_head *link)
{
	return (struct iocb *)link;
}

static struct cache_entry *CACHE_ENTRY(struct iocb *iocb)
{
	return (struct cache_entry *)iocb;
}

struct iocb *iocb_alloc(void)
{
	if (!stack_empty(stack))
		return STACK_ENTRY(stack_pop(&stack));
	return (struct iocb *)malloc(sizeof(struct cache_entry));
}

void iocb_free(struct iocb *iocb)
{
	stack_push(&stack, &CACHE_ENTRY(iocb)->u.link);
}

void iocb_cache_create(void)
{
	/* Have nothing to do, just for symmetry */
}

void iocb_cache_destroy(void)
{
	while (!stack_empty(stack))
		free(stack_pop(&stack));
}
