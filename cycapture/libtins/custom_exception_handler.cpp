#include <new>
#include <typeinfo>
#include <stdexcept>
#include <ios>
#include "Python.h"
// #include "libtins_exceptions.h" (no need, extern keyword below)
#include "tins/exceptions.h"
#include "custom_exception_handler.h"

// the objects will be loaded at runtime
extern PyObject *libtins_exception;
extern PyObject *option_not_found;
extern PyObject *malformed_packet;
extern PyObject *pdu_not_found;
extern PyObject *invalid_interface;
extern PyObject *field_not_present;
extern PyObject *socket_open_error;
extern PyObject *socket_close_error;
extern PyObject *socket_write_error;
extern PyObject *invalid_socket_type;
extern PyObject *unknown_link_type;
extern PyObject *malformed_option;
extern PyObject *bad_tins_cast;
extern PyObject *protocol_disabled;
// option_payload_too_large seems not present in libtins 3.2
//    extern PyObject *option_payload_too_large;


namespace Cycapture {

void custom_exception_handler() {
    // Catch a handful of different errors here and turn them into the
    // equivalent Python errors.
    try {
        if (PyErr_Occurred())
            ; // let the latest Python exn pass through and ignore the current one
        else
            throw;
    } catch (const Tins::option_not_found& exn) {
        PyErr_SetString(option_not_found, exn.what());
    } catch (const Tins::malformed_packet& exn) {
        PyErr_SetString(malformed_packet, exn.what());
    } catch (const Tins::pdu_not_found& exn) {
        PyErr_SetString(pdu_not_found, exn.what());
    } catch (const Tins::invalid_interface& exn) {
        PyErr_SetString(invalid_interface, exn.what());
    } catch (const Tins::field_not_present& exn) {
        PyErr_SetString(field_not_present, exn.what());
    } catch (const Tins::socket_open_error& exn) {
        PyErr_SetString(socket_open_error, exn.what());
    } catch (const Tins::socket_close_error& exn) {
        PyErr_SetString(socket_close_error, exn.what());
    } catch (const Tins::socket_write_error& exn) {
        PyErr_SetString(socket_write_error, exn.what());
    } catch (const Tins::invalid_socket_type& exn) {
        PyErr_SetString(invalid_socket_type, exn.what());
    } catch (const Tins::unknown_link_type& exn) {
        PyErr_SetString(unknown_link_type, exn.what());
    } catch (const Tins::malformed_option& exn) {
        PyErr_SetString(malformed_option, exn.what());
    } catch (const Tins::bad_tins_cast& exn) {
        PyErr_SetString(bad_tins_cast, exn.what());
    } catch (const Tins::protocol_disabled& exn) {
        PyErr_SetString(protocol_disabled, exn.what());

  // } catch (const Tins::option_payload_too_large& exn) {
  //   PyErr_SetString(option_payload_too_large, exn.what());

    } catch (const std::bad_alloc& exn) {
        PyErr_SetString(PyExc_MemoryError, exn.what());
    } catch (const std::bad_cast& exn) {
        PyErr_SetString(PyExc_TypeError, exn.what());
    } catch (const std::domain_error& exn) {
        PyErr_SetString(PyExc_ValueError, exn.what());
    } catch (const std::invalid_argument& exn) {
        PyErr_SetString(PyExc_ValueError, exn.what());
    } catch (const std::ios_base::failure& exn) {
        // Unfortunately, in standard C++ we have no way of distinguishing EOF
        // from other errors here; be careful with the exception mask
        PyErr_SetString(PyExc_IOError, exn.what());
    } catch (const std::out_of_range& exn) {
        // Change out_of_range to IndexError
        PyErr_SetString(PyExc_IndexError, exn.what());
    } catch (const std::overflow_error& exn) {
        PyErr_SetString(PyExc_OverflowError, exn.what());
    } catch (const std::range_error& exn) {
        PyErr_SetString(PyExc_ArithmeticError, exn.what());
    } catch (const std::underflow_error& exn) {
        PyErr_SetString(PyExc_ArithmeticError, exn.what());
    } catch (const std::exception& exn) {
        PyErr_SetString(PyExc_RuntimeError, exn.what());
    } catch (...) {
        PyErr_SetString(PyExc_RuntimeError, "Unknown exception");
    }
}

}
