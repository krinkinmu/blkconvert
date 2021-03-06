#include "list.h"

static inline void list_link_between(struct list_head *prev,
			struct list_head *next, struct list_head *new)
{
	prev->next = new;
	next->prev = new;
	new->prev = prev;
	new->next = next;
}

void list_link_after(struct list_head *pos, struct list_head *new)
{ list_link_between(pos, pos->next, new); }

void list_link_before(struct list_head *pos, struct list_head *new)
{ list_link_between(pos->prev, pos, new); }

void list_unlink(struct list_head *pos)
{
	pos->prev->next = pos->next;
	pos->next->prev = pos->prev;
}

static void __list_splice(struct list_head *prev, struct list_head *next,
			struct list_head *head, struct list_head *tail)
{
	prev->next = head;
	head->prev = prev;

	tail->next = next;
	next->prev = tail;
}

void list_splice(struct list_head *pos, struct list_head *lst)
{
	if (list_empty(lst))
		return;
	__list_splice(pos, pos->next, lst->next, lst->prev);
	list_head_init(lst);
}

void list_splice_tail(struct list_head *pos, struct list_head *lst)
{ list_splice(pos->prev, lst); }
