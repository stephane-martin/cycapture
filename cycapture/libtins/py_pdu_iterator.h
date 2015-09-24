#ifndef libtins_pdu_iterator
#define libtins_pdu_iterator

#include "Python.h"
#include "tins/pdu.h"
#include <iostream>

//extern PyTypeObject PyPDUType;

namespace Tins {
    class PDUIterator {

    public:

        PDUIterator();
        PDUIterator(PyObject* it);
        ~PDUIterator();

        PDU& operator*();

        inline PDUIterator& operator=(const PDUIterator& other) {
            py_iterator = other.py_iterator;
            current_pdu = other.current_pdu;
            current_py_pdu = other.current_py_pdu;
            return *this;
        }

        inline PDUIterator operator++(int lambda) {
            PDUIterator tmp(*this);
            operator++();
            return tmp;
        }

        inline PDUIterator& operator++() {
            std::cout << "method iterator ++" << std::endl;
            load_next_obj();
            return *this;
        }

        inline friend bool operator==(const PDUIterator& lhs, const PDUIterator& rhs) {
            std::cout << "method iterator ==" << std::endl;
            return (lhs.py_iterator == 0 && rhs.py_iterator == 0);

        }

        inline friend bool operator!=(const PDUIterator& lhs, const PDUIterator& rhs) {
            std::cout << "method iterator !=" << std::endl;
            return !(lhs == rhs);
        }



    private:
        PyObject* py_iterator;
        PDU* current_pdu;
        PyObject* current_py_pdu;
        void load_next_obj();
    };





}

#endif
