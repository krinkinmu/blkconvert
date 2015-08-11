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
