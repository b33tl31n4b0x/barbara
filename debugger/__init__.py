# TODO:
# - Treat signals the child receives
# - Comments and docs!!!
# - Delete superfluous definitions from header files
# - Redesign package structure
# - make the debugger able to attach to a process

from ctypes import c_ulonglong, Structure, CDLL, byref,\
                   get_errno, c_long, c_ulong
from os import fork, execl, WIFSTOPPED, waitpid, kill, strerror
from .__Debugger import *
