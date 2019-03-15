from ctypes import CDLL, byref, get_errno, c_long, c_ulong
from os import fork, execl, WIFSTOPPED, waitpid, kill, strerror
from .__c_defs import *


def get_reg_64(regs: user_regs_struct, name: str) -> int:
    reg_name, mask = reg_mask_map[name]
    reg = getattr(regs, reg_name)
    reg_val = reg & mask
    if not mask & 0xff:
        reg_val <<= 8

    return reg_val


def set_reg_64(regs: user_regs_struct, name: str, value: int)\
                   -> user_regs_struct:
    reg_name, mask = reg_mask_map[name]
    if not mask & 0xff:
        value <<= 8

    reg_old = getattr(regs, reg_name)
    reg_new = (reg_old & (0xffffffffffffffff ^ mask)) | value
    setattr(regs, reg_name, reg_new)
    return regs


class Breakpoint:
    def __init__(self, dbg, addr: int, permanent: bool = False):
        self.__address = addr
        self.__patched_byte = dbg.read_from_addr(addr, 1)
        self.__permanent = permanent
        dbg.write_to_addr(addr, b"\xcc")

    @property
    def patched_byte(self) -> bytes:
        return self.__patched_byte

    @property
    def address(self) -> int:
        return self.__address

    @property
    def permanent(self) -> bool:
        return self.__permanent

    @permanent.setter
    def permanent(self, value: bool) -> None:
        if not (value is True or value is False):
            raise TypeError("type bool expected")
        else:
            self.__permanent = value


class Hook(Breakpoint):
    def __init__(self, dbg, addr: int, func, permanent: bool = True,
                 silent: bool = False):
        self.__name = func.__name__
        self.__procedure = func
        self.__silent = silent
        super().__init__(dbg, addr, permanent=permanent)

    @property
    def name(self):
        return self.__name

    @property
    def silent(self):
        return self.__silent

    @silent.setter
    def silent(self, silent: bool):
        self.__silent = silent

    @property
    def procedure(self):
        return self.__procedure

    @procedure.setter
    def procedure(self, func):
        if not callable(func):
            raise TypeError("{0} is not callable".format(type(func)))
        else:
            self.__procedure = func
            self.__name = func.__name__


class DebuggerException(Exception):
    def __init__(self, msg: str = ""):
        self.__str__ = msg
        super().__init__()


class BreakpointHit(Exception):
    def __init__(self, bp):
        self.__str__ = "Breakpoint hit"
        self.__bp = bp
        super().__init__()

    @property
    def breakpoint(self):
        return self.__bp


class DebuggerBase:
    def __init__(self, ignore_ptrace_errors: bool = True):
        self.__libc_ptrace = CDLL("libc.so.6", use_errno=True).ptrace
        self.__breakpoints = list()
        self.__child_alive = False
        self.__regs = user_regs_struct()
        self.__ignore_ptrace_errors = ignore_ptrace_errors
        self.__restore = None
        self.__child_pid = None

    def __del__(self):
        if self.__child_alive:
            kill(self.__child_pid, 9)

    def __ptrace(self, *args) -> c_long:
        result = self.__libc_ptrace(*args)
        errno = get_errno()

        if errno != 0 and not self.__ignore_ptrace_errors:
            raise OSError(errno, strerror(errno))
        return result

    def __debugger_handover(self):
        # restore permanent breakpoints
        if self.__restore:
            self.add_breakpoint(self.__restore)
            self.__restore = None

        # wait for the child to finish, refresh regs and check for
        # breakpoint
        _, s = waitpid(self.__child_pid, 0)

        if WIFSTOPPED(s):
            self.__regs = self.__get_regs()
            restore = self.__ignore_ptrace_errors
            self.__ignore_ptrace_errors = True
            if self.__regs.rip-1 in self.breakpoints:
                self.__breakpoint_hook()
            self.__ignore_ptrace_errors = restore
        else:
            self.__child_alive = False

    def __breakpoint_hook(self):
        rip_reset = self.__regs.rip - 1
        bp = self.breakpoints[rip_reset]
        self.__breakpoints.remove(bp)

        self.write_to_addr(rip_reset, bp.patched_byte)
        self.set_reg("rip", rip_reset)

        if bp.permanent:
            self.__restore = bp
        else:
            self.__restore = None

        raise BreakpointHit(bp)

    def load(self, path: str, *args):
        if self.__child_alive:
            raise ChildProcessError("Already tracing a program")

        pid = fork()
        if not pid:
            self.__ptrace(PTRACE_TRACEME, 0, 0, 0)
            args = [path] if not args else args

            # turn off address space randomisation for child process
            pers = CDLL("libc.so.6").personality(c_ulong(0xffffffff))
            CDLL("libc.so.6").personality(pers | ADDR_NO_RANDOMIZE)
            errno = get_errno()
            if errno != 0:
                print(strerror(errno))

            execl(path, *args)
        else:
            self.__child_pid = pid
            self.__child_alive = True
            waitpid(self.__child_pid, 0)
            self.__regs = self.__get_regs()

    def step(self):
        if not self.__child_alive:
            raise ChildProcessError("Child not running")
        self.__ptrace(PTRACE_SINGLESTEP, self.__child_pid, 0, 0)
        self.__debugger_handover()

    def continue_(self):
        if not self.__child_alive:
            raise ChildProcessError("Child not running")
        self.__ptrace(PTRACE_CONT, self.__child_pid, 0, 0)
        self.__debugger_handover()

    def __get_regs(self):
        self.__ptrace(PTRACE_GETREGS, self.__child_pid, 0, byref(self.__regs))
        return self.__regs

    def get_reg(self, name: str):
        return get_reg_64(self.__regs, name)

    def set_reg(self, name: str, value: int):
        self.__regs = set_reg_64(self.__regs, name, value)

        self.__ptrace(PTRACE_SETREGS, self.__child_pid, 0,
                      byref(self.__regs))

    def read_from_addr(self, addr: int, length: int) -> bytes:
        data = b''
        while len(data) < length:
            le_bytes = self.__ptrace(PTRACE_PEEKTEXT, self.__child_pid,
                                     addr, 0)
            data += bytes([0x000000ff & (le_bytes >> i*8) for i in range(4)])
            addr += 4
        return data[:length]

    # for some reason, PTRACE_PEEKTEXT reads 4 bytes while PTRACE_POKETEXT
    # writes 8 bytes. this makes things a little more complicated
    def write_to_addr(self, addr: int, data: bytes):
        length = len(data)
        # calculate number of bytes that must be read and appended to data
        # such that len(data) is a multiple of 8
        overlap = 8 - (length % 8) if length % 8 > 0 else 0

        # add the required padding to data
        if overlap != 0:
            o_start = int(length / 8) + 8 - overlap
            padding = self.read_from_addr(addr + o_start, overlap)
            data = data[:o_start] + padding

        # write the data word by word
        for i in range(0, len(data), 8):
            self.__ptrace(PTRACE_POKETEXT, self.__child_pid,
                          addr + i,
                          c_long(int.from_bytes(data[i:i+8], "little")))

    def new_breakpoint(self, address: int, permanent: bool = False):
        bp = Breakpoint(self, address, permanent=permanent)
        add_breakpoint(bp)

    def add_breakpoint(self, breakpoint):
        if breakpoint not in self.breakpoints:
            self.__breakpoints.append(breakpoint)
        else:
            msg = "Breakpoint at 0x{0:x} already set"
            raise DebuggerException(msg.format(bp.address))

    @property
    def child_running(self):
        return self.__child_alive

    @property
    def breakpoints(self):
        return {bp.address: bp for bp in self.__breakpoints}

    @property
    def child_pid(self):
        return self.__child_pid

    @property
    def ignore_ptrace_errors(self):
        return self.__ignore_ptrace_errors

    @ignore_ptrace_errors.setter
    def ignore_ptrace_errors(self, v):
        if v:
            self.__ignore_ptrace_errors = True
        else:
            self.__ignore_ptrace_errors = False


class DebuggerExtended(DebuggerBase):
    def __handle_breakpoint(self, bp):
        if hasattr(bp, "procedure"):
            bp.procedure(self)

        if not hasattr(bp, "procedure") or not bp.silent:
            raise BreakpointHit(bp)

    def continue_(self):
        try:
            super().continue_()
        except BreakpointHit as hit:
            self.__handle_breakpoint(hit.breakpoint)

        # if no BreakpointHit exception was thrown, continue
        self.continue_()

    def step(self):
        try:
            super().step()
        except BreakpointHit as hit:
            self.__handle_breakpoint(hit.breakpoint)

    def hook(self, addr, permanent: bool = True, silent: bool = False):
        def _hook(func):
            hook = Hook(self, addr, func, permanent=permanent, silent=silent)
            self.add_breakpoint(hook)
            return hook
        return _hook

    def stepping(self):
        while self.child_running:
            self.step()
            yield self.get_reg("rip")
