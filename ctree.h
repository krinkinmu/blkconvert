#ifndef __CTREE_H__
#define __CTREE_H__

#include <stddef.h>
#include <stdlib.h>

#include "common.h"

struct ctree {
	struct ctree *left;
	struct ctree *right;
	size_t size;
	int prio;
};

#define centry(ptr, type, field) container_of(ptr, type, field)

static inline void cinit(struct ctree *tree)
{
	tree->left = tree->right = 0;
	tree->size = 1;
	tree->prio = rand();
}

static inline size_t csize(const struct ctree *tree)
{ return tree ? tree->size : 0; }

struct ctree *cmerge(struct ctree *l, struct ctree *r);
void csplit(struct ctree *tree, size_t idx, struct ctree **l,
			struct ctree **r);

static inline struct ctree *cappend(struct ctree *tree, struct ctree *new)
{ return cmerge(tree, new); }

static inline struct ctree *cextract(struct ctree *tree, size_t idx,
			struct ctree **node)
{
	struct ctree *l, *r;

	csplit(tree, idx, &l, &r);
	csplit(r, 1, node, &r);
	return cmerge(l, r);
}

#endif /*__CTREE_H__*/
