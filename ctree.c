#include "ctree.h"

struct ctree *cmerge(struct ctree *l, struct ctree *r)
{
	if (!l)
		return r;
	if (!r)
		return l;

	if (l->prio > r->prio) {
		l->right = cmerge(l->right, r);
		l->size = csize(l->left) + csize(l->right) + 1;
		return l;
	}
	r->left = cmerge(l, r->left);
	r->size = csize(r->left) + csize(r->right) + 1;
	return r;
}

void csplit(struct ctree *tree, size_t idx, struct ctree **l, struct ctree **r)
{
	size_t cur;

	if (!tree) {
		*l = *r = 0;
		return;
	}

	cur = csize(tree->left) + 1;
	if (cur <= idx) {
		csplit(tree->right, idx - cur, &tree->right, r);
		*l = tree;
	} else {
		csplit(tree->left, idx, l, &tree->left);
		*r = tree;
	}
	tree->size = csize(tree->left) + csize(tree->right) + 1;
}
