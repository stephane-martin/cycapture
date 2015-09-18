# -*- coding: utf-8 -*-

__author__ = 'stef'

class PcapException(Exception):
    pass

class AlreadyActivated(PcapException):
    pass

class ActivationError(PcapException):
    pass

class NotActivatedError(PcapException):
    pass

class SetTimeoutError(PcapException):
    pass

class SetDirectionError(PcapException):
    pass

class SetBufferSizeError(PcapException):
    pass

class SetSnapshotLengthError(PcapException):
    pass

class SetPromiscModeError(PcapException):
    pass

class SetMonitorModeError(PcapException):
    pass

class SetNonblockingModeError(PcapException):
    pass

class SniffingError(PcapException):
    pass

class PermissionDenied(PcapException, OSError):
    pass

class PromiscPermissionDenied(PermissionDenied):
    pass


def PcapExceptionFactory(return_code, error_msg=b'', default=PcapException):
    # PCAP_ERROR = -1
    # PCAP_ERROR_BREAK = -2
    # PCAP_ERROR_NOT_ACTIVATED = -3
    # PCAP_ERROR_ACTIVATED = -4
    # PCAP_ERROR_NO_SUCH_DEVICE = -5
    # PCAP_ERROR_RFMON_NOTSUP = -6
    # PCAP_ERROR_NOT_RFMON = -7
    # PCAP_ERROR_PERM_DENIED = -8
    # PCAP_ERROR_IFACE_NOT_UP = -9
    # PCAP_ERROR_CANTSET_TSTAMP_TYPE = -10
    # PCAP_ERROR_PROMISC_PERM_DENIED = -11
    # PCAP_ERROR_TSTAMP_PRECISION_NOTSUP = -12
    return_code = int(return_code)
    error_msg = bytes(error_msg)

    if return_code == -3:
        return NotActivatedError(error_msg)
    elif return_code == -4:
        return AlreadyActivated(error_msg)
    elif return_code == -8:
        return PermissionDenied(error_msg)
    elif return_code == -11:
        return PromiscPermissionDenied(error_msg)
    else:
        return default(error_msg)
