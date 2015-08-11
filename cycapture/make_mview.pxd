# -*- coding: utf-8 -*-

cdef extern from "Python.h":
    ctypedef struct PyObject:
        Py_ssize_t ob_refcnt
    enum: PyBUF_FULL_RO, PyBUF_FULL
    # we declare "object" as return type to deal with python references
    object PyMemoryView_FromBuffer(Py_buffer*)
    int PyBuffer_FillInfo(Py_buffer* view, PyObject* obj, void *buf, Py_ssize_t, int, int infoflags)
    ctypedef struct PyMemoryViewObject:
        Py_buffer view


# needed cause cython doesn't allow to make read-only typed memoryviews
cdef object make_mview_from_const_uchar_buf(const unsigned char* buf, int size)
cdef object make_mview_from_uchar_buf(unsigned char* buf, int size)
cdef void* mview_get_addr(void* mview)
