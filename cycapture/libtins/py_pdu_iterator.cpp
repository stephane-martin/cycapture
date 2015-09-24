#include "py_pdu_iterator.h"

// we need PyPDUType and PyPDUObject
#include "_tins.h"


namespace Tins {

    PDUIterator::PDUIterator() {
        py_iterator = 0;
        current_pdu = 0;
        current_py_pdu = 0;
    }

    PDUIterator::PDUIterator(PyObject* it) {
        if (it == 0) {
            // the provider python iterator is NULL: by convention, we consider that an end iterator is required
            py_iterator = 0;
            current_pdu = 0;
            current_py_pdu = 0;
            return;
        }
        if (!PyIter_Check(it)) {
            // this is not a python iterator : by convention, we consider that an end iterator is required
            py_iterator = 0;
            current_pdu = 0;
            current_py_pdu = 0;
            return;
        }

        Py_INCREF(it);            // prevent the iterator to be garbage collected
        py_iterator = it;

        load_next_obj();

    }

    PDUIterator::~PDUIterator() {
        if (py_iterator != 0) {
            Py_DECREF(py_iterator);
            py_iterator = 0;
        }
        if (current_py_pdu != 0) {
            Py_DECREF(current_py_pdu);
            current_py_pdu = 0;
        }

    }

    void PDUIterator::load_next_obj() {
        if (py_iterator == 0) {
            // we already reached the end
            return;
        }
        if (current_py_pdu != 0) {
            // decrement the previous object that was given by PyIter_Next
            Py_DECREF(current_py_pdu);
        }

        current_py_pdu = PyIter_Next(py_iterator);    // new python reference -> need Py_DECREF
        if (current_py_pdu == 0) {
            if (PyErr_Occurred()) {
                std::cout << "exception occured :(" << std::endl;
            } else {
                std::cout << "the iterator was empty... end of iteration" << std::endl;
            }
            Py_DECREF(py_iterator);     // decrement the python iterator reference
            py_iterator = 0;
            current_pdu = 0;
            return;
        }

        // check if current_py_pdu is a python PDU
        if (!PyObject_IsInstance(current_py_pdu, reinterpret_cast<PyObject*>(&PyPDUType))) {
            // we ignore the current object and check the next one
            std::cout << "some non-PDU was in iterator"  << std::endl;
            load_next_obj();
            return;
        }
        PyPDUObject* tmp = (PyPDUObject*) current_py_pdu;
        current_pdu = tmp->base_ptr;
    }

    PDU& PDUIterator::operator*() {
        if (current_pdu == 0) {
            // what to do ?!
            throw std::runtime_error("bleh");
        }
        return *current_pdu;

    }

}
