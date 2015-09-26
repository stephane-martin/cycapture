# encoding: utf-8

"""
Small cython wrapper around libpcap
"""

import logging
import struct as struct_module
import threading
from io import UnsupportedOperation
from time import sleep
from collections import deque
from os.path import exists

from enum import Enum

from ..libtins import LibtinsException as TinEx
from ..libtins import PDU

from .exceptions import PcapException, AlreadyActivated, SetTimeoutError, SetDirectionError, SetBufferSizeError
from .exceptions import SetSnapshotLengthError, SetPromiscModeError, SetMonitorModeError, SetNonblockingModeError
from .exceptions import ActivationError, NotActivatedError, SniffingError, PermissionDenied, PromiscPermissionDenied
from .exceptions import PcapExceptionFactory


include "definitions.pyx.pxi"
include "utils_func.pyx.pxi"
include "sniffer.pyx.pxi"
include "writer.pyx.pxi"
include "iterator.pyx.pxi"
include "offline_filter.pyx.pxi"


lock = create_error_check_lock()
INIT_LIST_HEAD(&thread_pcap_global_list)
logger = logging.getLogger('cycapture')
libpcap_version = <bytes> pcap_lib_version()
LibtinsException = TinEx

