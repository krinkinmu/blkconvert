#ifndef __STACK_H__
#define __STACK_H__

struct stack_head {
	struct stack_head *next;
};

static inline void stack_push(struct stack_head **stack,
			struct stack_head *node)
{
	node->next = *stack;
	*stack = node;
}

static inline struct stack_head *stack_pop(struct stack_head **stack)
{
	struct stack_head *node = *stack;

	if (node)
		*stack = node->next;
	return node;
}

static inline int stack_empty(const struct stack_head *stack)
{
	return stack == 0;
}

#endif /*__STACK_H__*/
