#ifndef __LIST_H__
#define __LIST_H__

#include "common.h"

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

#define list_entry(ptr, type, field) continer_of(ptr, type, field)

static inline void list_init(struct list_head *head)
{ head->next = head->prev = head; }

static inline int list_empty(const struct list_head *head)
{ return head->next == head; }

void list_link_after(struct list_head *pos, struct list_head *new);
void list_link_before(struct list_head *pos, struct list_head *new);
void list_unlink(struct list_head *pos);

#endif /*__LIST_H__*/
