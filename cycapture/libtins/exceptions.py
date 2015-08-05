__author__ = 'stef'

class LibtinsException(Exception):
    pass

class MalformedAddress(LibtinsException, ValueError):
    pass

class OptionNotFound(LibtinsException):
    pass
