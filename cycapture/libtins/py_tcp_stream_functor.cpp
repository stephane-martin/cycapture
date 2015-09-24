#include "py_tcp_stream_functor.h"

// we need PyTCPStreamType and PyTCPStreamObject
#include "_tins.h"
#include <iostream>

namespace Tins {

    PyObject* std_string_to_pyobj(const std::string s) {
        return PyString_FromStringAndSize(s.c_str(), (Py_ssize_t) s.size());
    }

    PyObject* make_mview(const TCPStream::payload_type& payload) {
        // make a python memoryview corresponding to the vector<uint8_t> payload
        const uint8_t* buf = &(payload[0]);
        size_t buf_size = payload.size();
        Py_buffer* viewinfo = (Py_buffer*) PyMem_Malloc(sizeof(Py_buffer));
        if (viewinfo == 0) {
            throw std::bad_alloc();     // malloc error
        }
        if (PyBuffer_FillInfo(viewinfo, 0, (void*) buf, (Py_ssize_t) buf_size, 1, PyBUF_FULL_RO) != 0) {
            PyMem_Free((void*) viewinfo);
            throw std::runtime_error("PyBuffer_FillInfo failed in TCPStreamPyFunctor::make_mview");
        }
        PyObject* mview = PyMemoryView_FromBuffer(viewinfo);       // new reference
        if (mview == 0) {
            PyMem_Free((void*) viewinfo);
            throw std::runtime_error("PyMemoryView_FromBuffer failed in TCPStreamPyFunctor::make_mview");
        }
        return mview;
    }

    PyObject* py_tcp_stream_factory(std::string caddr, std::string saddr, int cport, int sport, uint64_t id,
                                           int finished, PyObject* cmview, PyObject* smview) {

        PyObject* client_addr = std_string_to_pyobj(caddr);
        PyObject* server_addr = std_string_to_pyobj(saddr);
        PyObject* client_port = Py_BuildValue("i", cport);
        PyObject* server_port = Py_BuildValue("i", sport);
        PyObject* identifier = Py_BuildValue("K", (long long unsigned int) id);
        PyObject* is_finished = Py_BuildValue("i", finished);

        // build a python TCPStream object from args (we just call the class object just as in normal python)
        PyObject *tcp_stream_obj = PyObject_CallFunctionObjArgs(
            (PyObject *) &PyTCPStreamType,
            client_addr, server_addr, client_port, server_port, identifier, is_finished, cmview, smview,
            NULL
        );

        // decrement the arguments
        Py_DECREF(client_addr);
        Py_DECREF(server_addr);
        Py_DECREF(client_port);
        Py_DECREF(server_port);
        Py_DECREF(identifier);
        Py_DECREF(is_finished);

        return tcp_stream_obj;
    }

    TCPStreamPyFunctor::TCPStreamPyFunctor(PyObject* callabl) {
        if (callabl == NULL) {
            throw std::runtime_error("TCPStreamPyFunctor: argument is NULL");
        }
        if (!PyCallable_Check(callabl)) {
            throw std::runtime_error("TCPStreamPyFunctor: argument is not a callable");
        }
        callback = callabl;
        Py_INCREF(callback);
    }

    TCPStreamPyFunctor::~TCPStreamPyFunctor() {
        if (callback != NULL) {
            Py_DECREF(callback);
        }
    }


    bool TCPStreamPyFunctor::operator()(TCPStream& stream) const {
        PyObject* client_mview = make_mview(stream.client_payload());       // new reference
        PyObject* server_mview = NULL;
        try {
            server_mview = make_mview(stream.server_payload());
        } catch(std::runtime_error&) {
            Py_DECREF(client_mview);
            throw;
        } catch(std::bad_alloc&) {
            Py_DECREF(client_mview);
            throw;
        }

        // create the TCPStream python object
        PyObject* py_stream = py_tcp_stream_factory(
            stream.stream_info().client_addr.to_string(),
            stream.stream_info().server_addr.to_string(),
            (int) stream.stream_info().client_port,
            (int) stream.stream_info().server_port,
            stream.id(),
            (int) stream.is_finished(),
            client_mview,
            server_mview
        );

        if (py_stream == NULL) {
            Py_DECREF(client_mview);
            Py_DECREF(server_mview);

            if (!PyErr_Occurred()) {
                throw std::runtime_error("Creating the TCPStream pyobject failed in TCPStreamPyFunctor::operator()");
            } else {
                // python already set an exception
                return false;
            }
        }

        // call the python callback
        PyObject* result = PyObject_CallFunctionObjArgs(callback, py_stream, NULL);     // new reference
        if (result == NULL) {
            Py_DECREF(client_mview);
            Py_DECREF(server_mview);
            Py_DECREF(py_stream);

            if (!PyErr_Occurred()) {
                throw std::runtime_error("Calling python callback failed in TCPStreamPyFunctor::operator()");
            } else {
                // python already set an exception
                return false;
            }
        }

        // cleaning
        Py_DECREF(client_mview);
        Py_DECREF(server_mview);
        Py_DECREF(py_stream);

        // return the result as a C bool
        if (PyObject_IsTrue(result) == 1) {
            Py_DECREF(result);
            return true;
        } else {
            Py_DECREF(result);
            return false;
        }
    }
}
