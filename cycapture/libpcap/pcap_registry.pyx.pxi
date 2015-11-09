# -*- coding: utf-8 -*-

lock = create_error_check_lock()
cdef list_head registry_pcap
INIT_LIST_HEAD(&registry_pcap)


cdef void registry_pcap_set_stopping() nogil:
    cdef thread_pcap_node* current = registry_pcap_get_node()
    if current is not NULL:
        current.asked_to_stop = 1
        pcap_breakloop(current.handle)

cdef int registry_pcap_has() nogil:
    return registry_pcap_get_node() is not NULL

cdef int registry_pcap_has_stopping() nogil:
    cdef thread_pcap_node* current = registry_pcap_get_node()
    if current is NULL:
        return 1
    return current.asked_to_stop

cdef thread_pcap_node* registry_pcap_get_node() nogil:
    """
    Returns the pcap_handle for the current thread.
    """
    global registry_pcap

    cdef uint32_t thread = pthread_hash()
    cdef list_head* cursor = registry_pcap.next
    cdef thread_pcap_node* node
    while cursor != &registry_pcap:
        node = <thread_pcap_node*>( <char *>cursor - <unsigned long> (&(<thread_pcap_node*>0).link) )
        if node.thread == thread:
            return node
        cursor = cursor.next
    return NULL

cdef registry_pcap_set(pcap_t* handle):
    global lock, registry_pcap
    if registry_pcap_has():
        raise RuntimeError("register_pcap_for_thread: this thread already has a pcap handle")

    cdef thread_pcap_node* node

    if pthread_mutex_lock(lock) != 0:
        raise RuntimeError("register_pcap_for_thread: locking failed!!!")
    try:
        node = <thread_pcap_node*> malloc(sizeof(thread_pcap_node))
        if node is NULL:
            raise RuntimeError('register_pcap_for_thread: malloc failed!!!')
        node.thread = pthread_hash()
        node.handle = handle
        node.asked_to_stop = 0
        list_add_tail(&node.link, &registry_pcap)
    finally:
        pthread_mutex_unlock(lock)


cdef registry_pcap_unset():
    global lock, registry_pcap
    cdef list_head* cursor
    cdef list_head* nextnext
    cdef thread_pcap_node* node
    cdef uint32_t thread = pthread_hash()
    if not registry_pcap_has():
        return "Warning: unregister_pcap_for_thread: current thread doesnt have a pcap handle"

    if pthread_mutex_lock(lock) != 0:
        raise RuntimeError("unregister_pcap_for_thread: locking failed!!!")

    try:
        cursor = registry_pcap.next
        nextnext = cursor.next
        while cursor != &registry_pcap:
            node = <thread_pcap_node*>( <char *>cursor - <unsigned long> (&(<thread_pcap_node*>0).link) )
            if node.thread == thread:
                list_del(&node.link)
                free(node)
                break
            cursor = nextnext
            nextnext = cursor.next
    finally:
        pthread_mutex_unlock(lock)
