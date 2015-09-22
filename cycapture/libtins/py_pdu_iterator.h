#ifndef libtins_pdu_iterator
#define libtins_pdu_iterator

#include "Python.h"
#include "tins/pdu.h"

//extern PyTypeObject PyPDUType;

namespace Tins {
    class PDUIterator {

    public:
        typedef PDU value_type;
        typedef PDU* pointer;
        typedef PDU& reference;

        PDUIterator();
        PDUIterator(PyObject* it);
        ~PDUIterator();

        reference operator*();

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
            next_obj();
            return *this;
        }

        inline friend bool operator==(const PDUIterator& lhs, const PDUIterator& rhs) {
            return (lhs.py_iterator == 0 && rhs.py_iterator == 0);
        }

        inline friend bool operator!=(const PDUIterator& lhs, const PDUIterator& rhs) {
            return !(lhs == rhs);
        }



    private:
        PyObject* py_iterator;
        PDU* current_pdu;
        PyObject* current_py_pdu;
        void next_obj();
    };





}

#endif
