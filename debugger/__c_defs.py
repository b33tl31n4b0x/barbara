from ctypes import c_ulonglong, Structure

# used by C-function "personality" (imported from libc.so.6)
ADDR_NO_RANDOMIZE = 0x0040000

# definitions from asm/ptrace-abi.h
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13

# from linux/ptrace.h
PTRACE_TRACEME = 0
PTRACE_PEEKTEXT = 1
PTRACE_PEEKDATA = 2
PTRACE_PEEKUSER = 3
PTRACE_POKETEXT = 4
PTRACE_POKEDATA = 5
PTRACE_POKEUSER = 6
PTRACE_CONT = 7
PTRACE_SINGLESTEP = 9
PTRACE_ATTACH = 16
PTRACE_DETACH = 17


# from sys/user.h
class user_regs_struct(Structure):
    _fields_ = [("r15", c_ulonglong),
                ("r14", c_ulonglong),
                ("r13", c_ulonglong),
                ("r12", c_ulonglong),
                ("rbp", c_ulonglong),
                ("rbx", c_ulonglong),
                ("r11", c_ulonglong),
                ("r10", c_ulonglong),
                ("r9", c_ulonglong),
                ("r8", c_ulonglong),
                ("rax", c_ulonglong),
                ("rcx", c_ulonglong),
                ("rdx", c_ulonglong),
                ("rsi", c_ulonglong),
                ("rdi", c_ulonglong),
                ("orig_rax", c_ulonglong),
                ("rip", c_ulonglong),
                ("cs", c_ulonglong),
                ("eflags", c_ulonglong),
                ("rsp", c_ulonglong),
                ("ss", c_ulonglong),
                ("fs_base", c_ulonglong),
                ("gs_base", c_ulonglong),
                ("ds", c_ulonglong),
                ("es", c_ulonglong),
                ("fs", c_ulonglong),
                ("gs", c_ulonglong)]


reg_mask_map = {"rax": ("rax", 0xffffffffffffffff),
                "eax": ("rax", 0x00000000ffffffff),
                "ax": ("rax", 0x000000000000ffff),
                "ah": ("rax", 0x000000000000ff00),
                "al": ("rax", 0x00000000000000ff),
                "rbx": ("rbx", 0xffffffffffffffff),
                "ebx": ("rbx", 0x00000000ffffffff),
                "bx": ("rbx", 0x000000000000ffff),
                "bh": ("rbx", 0x000000000000ff00),
                "bl": ("rbx", 0x00000000000000ff),
                "rcx": ("rcx", 0xffffffffffffffff),
                "ecx": ("rcx", 0x00000000ffffffff),
                "cx": ("rcx", 0x000000000000ffff),
                "ch": ("rcx", 0x000000000000ff00),
                "cl": ("rcx", 0x00000000000000ff),
                "rdx": ("rdx", 0xffffffffffffffff),
                "edx": ("rdx", 0x00000000ffffffff),
                "dx": ("rdx", 0x000000000000ffff),
                "dh": ("rdx", 0x000000000000ff00),
                "dl": ("rdx", 0x00000000000000ff),
                "r8": ("r8", 0xffffffffffffffff),
                "r8d": ("r8", 0x00000000ffffffff),
                "r8w": ("r8", 0x000000000000ffff),
                "r8l": ("r8", 0x00000000000000ff),
                "r9": ("r9", 0xffffffffffffffff),
                "r9d": ("r9", 0x00000000ffffffff),
                "r9w": ("r9", 0x000000000000ffff),
                "r9l": ("r9", 0x00000000000000ff),
                "r10": ("r10", 0xffffffffffffffff),
                "r10d": ("r10", 0x00000000ffffffff),
                "r10w": ("r10", 0x000000000000ffff),
                "r10l": ("r10", 0x00000000000000ff),
                "r11": ("r11", 0xffffffffffffffff),
                "r11d": ("r11", 0x00000000ffffffff),
                "r11w": ("r11", 0x000000000000ffff),
                "r11l": ("r11", 0x00000000000000ff),
                "r12": ("r12", 0xffffffffffffffff),
                "r12d": ("r12", 0x00000000ffffffff),
                "r12w": ("r12", 0x000000000000ffff),
                "r12l": ("r12", 0x00000000000000ff),
                "r13": ("r13", 0xffffffffffffffff),
                "r13d": ("r13", 0x00000000ffffffff),
                "r13w": ("r13", 0x000000000000ffff),
                "r13l": ("r13", 0x00000000000000ff),
                "r14": ("r14", 0xffffffffffffffff),
                "r14d": ("r14", 0x00000000ffffffff),
                "r14w": ("r14", 0x000000000000ffff),
                "r14l": ("r14", 0x00000000000000ff),
                "r15": ("r15", 0xffffffffffffffff),
                "r15d": ("r15", 0x00000000ffffffff),
                "r15w": ("r15", 0x000000000000ffff),
                "r15l": ("r15", 0x00000000000000ff),
                "r16": ("r16", 0xffffffffffffffff),
                "r16d": ("r16", 0x00000000ffffffff),
                "r16w": ("r16", 0x000000000000ffff),
                "r16l": ("r16", 0x00000000000000ff),
                "rdi": ("rdi", 0xffffffffffffffff),
                "edi": ("rdi", 0x00000000ffffffff),
                "di": ("rdi", 0x000000000000ffff),
                "dil": ("rdi", 0x00000000000000ff),
                "rsi": ("rsi", 0xffffffffffffffff),
                "esi": ("rsi", 0x00000000ffffffff),
                "si": ("rsi", 0x000000000000ffff),
                "sil": ("rsi", 0x00000000000000ff),
                "rbp": ("rbp", 0xffffffffffffffff),
                "ebp": ("rbp", 0x00000000ffffffff),
                "bp": ("rbp", 0x000000000000ffff),
                "bpl": ("rbp", 0x00000000000000ff),
                "rsp": ("rsp", 0xffffffffffffffff),
                "rip": ("rip", 0xffffffffffffffff)}
