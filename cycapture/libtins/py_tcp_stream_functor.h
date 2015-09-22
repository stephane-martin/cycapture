#ifndef libtins_tcp_stream_pyfunctor
#define libtins_tcp_stream_pyfunctor

#include "Python.h"
#include "tins/tcp_stream.h"

namespace Tins {

    PyObject* std_string_to_pyobj(const std::string s);
    PyObject* make_mview(const TCPStream::payload_type& payload);
    PyObject* py_tcp_stream_factory(std::string caddr, std::string saddr, int cport, int sport, uint64_t id,
                                    int finished, PyObject* cmview, PyObject* smview);

    class TCPStreamPyFunctor {
    public:
        TCPStreamPyFunctor(PyObject* callabl);
        ~TCPStreamPyFunctor();
        bool operator()(TCPStream& stream) const;
    private:
        PyObject* callback;
    };
}

#endif
