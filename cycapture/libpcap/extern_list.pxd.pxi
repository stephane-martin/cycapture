

cdef extern from "list.h" nogil:
    struct list_head:
        list_head *next
        list_head *prev
    void INIT_LIST_HEAD(list_head *l)
    void list_add(list_head *new, list_head *head)
    void list_add_tail(list_head *new, list_head *head)
    void list_del(list_head *entry)
    void list_replace(list_head *old, list_head *new)
    int list_is_last(const list_head *l, const list_head *head)
    int list_empty(const list_head *head)
    int list_is_singular(const list_head *head)
