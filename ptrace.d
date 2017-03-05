/** D wrapper for Linux' ptrace API.
 * See also http://forum.dlang.org/post/jn9ea4$dtt$1@digitalmars.com
 */
module ptrace;

import core.stdc.stdio;
import core.sys.posix.sys.types;

enum __ptrace_request
{
    PTRACE_TRACEME = 0,
    PTRACE_PEEKTEXT = 1,
    PTRACE_PEEKDATA = 2,
    PTRACE_PEEKUSER = 3,
    PTRACE_POKETEXT = 4,
    PTRACE_POKEDATA = 5,
    PTRACE_POKEUSER = 6,
    PTRACE_CONT = 7,
    PTRACE_KILL = 8,
    PTRACE_SINGLESTEP = 9,
    PTRACE_GETREGS = 12,
    PTRACE_SETREGS = 13,
    PTRACE_GETFPREGS = 14,
    PTRACE_SETFPREGS = 15,
    PTRACE_ATTACH = 16,
    PTRACE_DETACH = 17,
    PTRACE_GETFPXREGS = 18,
    PTRACE_SETFPXREGS = 19,
    PTRACE_SYSCALL = 24,
    PTRACE_SETOPTIONS = 0x4200,
    PTRACE_GETEVENTMSG = 0x4201,
    PTRACE_GETSIGINFO = 0x4202,
    PTRACE_SETSIGINFO = 0x4203
}

extern(C) long ptrace(__ptrace_request request,
                      pid_t pid,
                      void *addr,
                      void *data);
