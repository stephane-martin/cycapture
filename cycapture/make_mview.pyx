from cpython.mem cimport PyMem_Malloc, PyMem_Free

cdef object make_mview_from_const_uchar_buf(const unsigned char* buf, int size):
    cdef Py_buffer* viewinfo = <Py_buffer*> PyMem_Malloc(sizeof(Py_buffer))
    cdef int res
    if viewinfo != NULL:
        res = PyBuffer_FillInfo(viewinfo, NULL, <void*> buf, size, 1, PyBUF_FULL_RO)
        if res == 0:
            return PyMemoryView_FromBuffer(viewinfo)
        else:
            PyMem_Free(viewinfo)
            raise RuntimeError("PyBuffer_FillInfo failed with -1")
    else:
        raise MemoryError


cdef object make_mview_from_uchar_buf(unsigned char* buf, int size):
    cdef Py_buffer* viewinfo = <Py_buffer*> PyMem_Malloc(sizeof(Py_buffer))
    cdef int res
    if viewinfo != NULL:
        res = PyBuffer_FillInfo(viewinfo, NULL, <void*> buf, size, 1, PyBUF_FULL)
        if res == 0:
            return PyMemoryView_FromBuffer(viewinfo)
        else:
            PyMem_Free(viewinfo)
            raise RuntimeError("PyBuffer_FillInfo failed with -1")
    else:
        raise MemoryError
