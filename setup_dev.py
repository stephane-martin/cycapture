# -*- coding: utf-8 -*-

from setup import run_setup, extensions, Extension, LibpcapDep, LibtinsDep, IS_WINDOWS

extensions[:] = []

make_mview_extension = Extension(
    name="cycapture._make_mview",
    sources=["cycapture/_make_mview.pyx"]
)
extensions.append(make_mview_extension)

pthread_extension = Extension(
    name="cycapture._pthreadwrap",
    sources=["cycapture/_pthreadwrap.pyx", "cycapture/murmur.c"]
)
extensions.append(pthread_extension)

if not IS_WINDOWS:
    signal_extension = Extension(
        name="cycapture._signal",
        sources=["cycapture/_signal.pyx"]
    )
    extensions.append(signal_extension)

# build libpcap and the cycapture.libpcap python extension
pcap_extension = Extension(
    name="cycapture.libpcap._pcap",
    sources=["cycapture/libpcap/_pcap.pyx"]
)
libpcap_dep = LibpcapDep()
# noinspection PyTypeChecker
libpcap_dep.add_to_extension(pcap_extension)
extensions.append(pcap_extension)

tins_dep = LibtinsDep(libpcap_dep)

tins_exceptions_extension = Extension(
    name="cycapture.libtins._py_exceptions",
    sources=[
        "cycapture/libtins/_py_exceptions.pyx",
        "cycapture/libtins/custom_exception_handler.cpp"
    ],
    language="c++"
)

# noinspection PyTypeChecker
tins_dep.add_to_extension(tins_exceptions_extension)
extensions.append(tins_exceptions_extension)

# build libtins and cycapture.libtins python extension
tins_extension = Extension(
    name="cycapture.libtins._tins",
    sources=[
        "cycapture/libtins/_tins.pyx",
        "cycapture/libtins/wrap.cpp",
        "cycapture/libtins/py_tcp_stream_functor.cpp",
        "cycapture/libtins/py_pdu_iterator.cpp"
    ],
    language="c++"
)
# noinspection PyTypeChecker
tins_dep.add_to_extension(tins_extension)
extensions.append(tins_extension)

if __name__ == '__main__':
    run_setup()


