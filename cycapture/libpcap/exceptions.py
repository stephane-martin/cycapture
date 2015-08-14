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

