# encoding: utf-8

"""
Small cython wrapper around libpcap
"""

DEF ON_WINDOWS = UNAME_SYSNAME == "Windows"

import logging
import struct as struct_module
import threading
from io import UnsupportedOperation
from time import sleep
from collections import deque
from os.path import exists, dirname, abspath
import os

from enum import IntEnum

from ..libtins import LibtinsException as TinEx
from ..libtins import PDU

from .exceptions import PcapException, AlreadyActivated, SetTimeoutError, SetDirectionError, SetBufferSizeError
from .exceptions import SetSnapshotLengthError, SetPromiscModeError, SetMonitorModeError, SetNonblockingModeError
from .exceptions import ActivationError, NotActivatedError, SniffingError, PermissionDenied, PromiscPermissionDenied
from .exceptions import PcapExceptionFactory


def make_enum(typename, label, docstring, values):
    cls = IntEnum(typename, values)
    cls.__name__ = label
    cls.__doc__ = docstring + "\n\nAttributes: " + ", ".join(['``{}``'.format(attr) for attr in cls.__members__.keys()])
    return cls

include "definitions.pyx.pxi"
include "pcap_registry.pyx.pxi"
include "utils_func.pyx.pxi"
include "sniffer.pyx.pxi"
include "blocking_sniffer.pyx.pxi"
IF not ON_WINDOWS:
    include "nonblocking_sniffer.pyx.pxi"
include "writer.pyx.pxi"
include "iterator.pyx.pxi"
include "offline_filter.pyx.pxi"

logger = logging.getLogger('cycapture')
libpcap_version = <bytes> pcap_lib_version()
LibtinsException = TinEx

