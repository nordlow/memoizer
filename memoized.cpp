#include <sys/ptrace.h>
#include <bits/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syscall.h>

// C library
#include <unistd.h>
#include <cstdlib>
#include <cstdio>
#include <cerrno>
#include <cassert>
#include <cstring>
#include <cinttypes>

// OpenSSL
#include <openssl/sha.h>

// STL
#include <vector>
#include <string>
#include <map>

// system calls
#include "syscalls.h"
#include "syscallents.h"

/* cheap trick for reading syscall number / return value. */
#ifdef __amd64__
#define eax rax
#define orig_eax orig_rax
#else
#endif

#ifndef offsetof
#define offsetof(a, b) __builtin_offsetof(a,b)
#endif

#define getReg(child, name) __get_reg(child, offsetof(struct user, regs.name))

long __get_reg(pid_t child, int off)
{
    long val = ptrace(PTRACE_PEEKUSER, child, off);
    assert(errno == 0);
    return val;
}

typedef unsigned long ulong;

typedef std::vector<std::string> Paths;

/// System calls executed.
typedef std::vector<std::string> DoneSyscalls[MAX_SYSCALL_NUM + 1];

/// Paths by pid.
typedef std::map<pid_t, Paths> PathsByPid;

/// Trace results.
struct Trace
{
    DoneSyscalls doneSyscalls;

    /// Read-only opened file paths by pid.
    PathsByPid inPathsByPid;
    /// Write-only opened file paths by pid.
    PathsByPid outPathsByPid;
    /// Stated file paths by pid.
    PathsByPid statPathsByPid;

    SHA256_CTX inputHash;
};

/** Wait for system call in `child`. */
int waitForChildPidSyscall(pid_t child)
{
    while (true)
    {
        // tracee is stopped at the next entry to or exit from a system call
        ptrace(PTRACE_SYSCALL, child, 0, 0);

        int status;
        waitpid(child, &status, 0); // wait for child

        if (WIFSTOPPED(status) &&    // if child stopped and
            WSTOPSIG(status) & 0x80) // highest bit set
        {
            return 0;
        }

        if (WIFEXITED(status))  // if child exited
        {
            return 1;
        }

        fprintf(stderr, "[stopped status:%d stopsignal:%x]\n", status, WSTOPSIG(status));
    }
}

const char *syscallNameOfNumber(int syscallNumber)
{
    if (syscallNumber <= MAX_SYSCALL_NUM)
    {
        struct syscall_entry *ent = &syscalls[syscallNumber];
        if (ent->name)
        {
            return ent->name;
        }
    }
    static char buf[128];
    snprintf(buf, sizeof buf, "sys_%d", syscallNumber);
    return buf;
}

ulong pidSyscallArg(pid_t child, int which)
{
    switch (which)
    {
#ifdef __amd64__
    case 0: return getReg(child, rdi);
    case 1: return getReg(child, rsi);
    case 2: return getReg(child, rdx);
    case 3: return getReg(child, r10);
    case 4: return getReg(child, r8);
    case 5: return getReg(child, r9);
#else
    case 0: return getReg(child, ebx);
    case 1: return getReg(child, ecx);
    case 2: return getReg(child, edx);
    case 3: return getReg(child, esi);
    case 4: return getReg(child, edi);
    case 5: return getReg(child, ebp);
#endif
    default: return -1L;
    }
}

/** Allocate and return a copy of a null-terminated C string at `addr`. */
char *readString(pid_t child, unsigned long addr)
{
    uint allocated = 4096;
    char *val = reinterpret_cast<char*>(malloc(allocated));
    int read = 0;
    unsigned long tmp;
    while (true)
    {
        if (read + sizeof(tmp) > allocated)
        {
            allocated *= 2;
            val = reinterpret_cast<char*>(realloc(val, allocated));
        }
        tmp = ptrace(PTRACE_PEEKDATA, child, addr + read);
        if (errno != 0)
        {
            val[read] = 0;
            break;
        }
        memcpy(val + read, &tmp, sizeof(tmp));
        if (memchr(&tmp, 0, sizeof(tmp)) != NULL)
        {
            break;
        }
        read += sizeof(tmp);
    }
    return val;
}

/** Allocate and return a copy of a null-terminated C string at `addr`.
    TODO templatize T on struct stat when moving to D
 */
struct stat readStat(pid_t child, unsigned long addr)
{
    struct stat stat;
    uint8_t* statPtr = reinterpret_cast<uint8_t*>(&stat); // TODO byte
    int read = 0;
    while (true)
    {
        unsigned long tmp = ptrace(PTRACE_PEEKDATA, child, addr + read);
        if (errno != 0)
        {
            fprintf(stderr, "memoized: error: cannot read ptrace(PTRACE_PEEKDATA)\n");
            break;
        }
        memcpy(statPtr + read, &tmp, sizeof(tmp));
        if (memchr(&tmp, 0, sizeof(tmp)) != NULL)
        {
            break;
        }
        read += sizeof(tmp);
    }
    return stat;
}

void printSyscallArgs(pid_t child, int num)
{
    const char * sname = syscallNameOfNumber(num);
    struct syscall_entry *ent = NULL;
    int nargs = SYSCALL_MAXARGS;
    int i;
    char *strval;
    const bool show = false;

    if (num <= MAX_SYSCALL_NUM && syscalls[num].name)
    {
        ent = &syscalls[num];
        nargs = ent->nargs;
    }
    for (i = 0; i < nargs; i++) // incorrectly always 6
    {
        const ulong arg = pidSyscallArg(child, i);
        const int type = ent ? ent->args[i] : ARG_PTR;

        if (strcmp(sname, "execve") == 0)
        {
            if (i == 0)
            {
                strval = readString(child, arg);
                if (show) fprintf(stderr, "\"%s\"", strval);
                free(strval);
                goto done;
            }
        }
        else if (strcmp(sname, "open") == 0 ||
                 strcmp(sname, "utime") == 0 ||
                 strcmp(sname, "access") == 0 ||
                 strcmp(sname, "mount") == 0 ||
                 strcmp(sname, "link") == 0 ||
                 strcmp(sname, "unlink") == 0 ||
                 strcmp(sname, "mkdir") == 0 ||
                 strcmp(sname, "stat") == 0 ||
                 strcmp(sname, "lstat") == 0 ||
                 strcmp(sname, "statfs") == 0 ||
                 strcmp(sname, "creat") == 0 ||
                 strcmp(sname, "chdir") == 0 ||
                 strcmp(sname, "chown") == 0 ||
                 strcmp(sname, "lchown") == 0 ||
                 strcmp(sname, "chmod") == 0 ||
                 strcmp(sname, "mknod") == 0)
        {
            if (i == 0)
            {
                strval = readString(child, arg);
                if (show) fprintf(stderr, "\"%s\"", strval);
                free(strval);
                goto done;
            }
        }
        else if (strcmp(sname, "mount") == 0 ||
                 strcmp(sname, "link") == 0 ||
                 strcmp(sname, "mkdirat") == 0 ||
                 strcmp(sname, "openat") == 0 ||
                 strcmp(sname, "fchmodat") == 0 ||
                 strcmp(sname, "fstatat") == 0) // TODO calculate full path from dirfd and pathname
        {
            if (i == 1)
            {
                strval = readString(child, arg);
                if (show) fprintf(stderr, "\"%s\"", strval);
                free(strval);
                goto done;
            }
        }
        else if (strcmp(sname, "mount") == 0)
        {
            if (i == 2)
            {
                strval = readString(child, arg);
                if (show) fprintf(stderr, "\"%s\"", strval);
                free(strval);
                goto done;
            }
        }

        // generic printing
        switch (type)
        {
        case ARG_INT:
            if (show) fprintf(stderr, "%ld", arg);
            break;
        case ARG_STR:
            strval = readString(child, arg);
            if (show) fprintf(stderr, "\"%s\"", strval);
            free(strval);
            break;
        default:
            if (show) fprintf(stderr, "0x%lx", arg);
            break;
        }

        done:

        if (i != nargs - 1)     /* if not parameter */
        {
            if (show) fprintf(stderr, ", ");
        }
    }
}

/// Print newline to `file`.
void endl(FILE* file = stderr)
{
    fprintf(file, "\n");
}

void printSyscall(pid_t child, long syscall_num, long retval)
{
    fprintf(stderr, "%d %s(", child, syscallNameOfNumber(syscall_num));
    printSyscallArgs(child, syscall_num);
    fprintf(stderr, ") = ");
    fprintf(stderr, "%ld", retval);
}

void handleSyscall(pid_t child,
                   Trace& trace)
{
    const bool show = false;
    long syscall_num;                    // syscall number
    syscall_num = getReg(child, orig_eax);
    assert(errno == 0);

    // return value
    long retval = getReg(child, eax);
    assert(errno == 0);
    if (retval == -38)          // on call entry
    {
        // nothing useful to do here for now
    }
    else                        // on call return
    {
        if (retval >= 0)        // on successful return
        {
            //  file io successful return

            if (syscall_num == SYS_open ||
                syscall_num == SYS_openat ||
                syscall_num == SYS_creat ||
                syscall_num == SYS_stat ||
                syscall_num == SYS_statfs ||
                syscall_num == SYS_lstat ||
                syscall_num == SYS_access) // file system syscalls with path as first argument
            {
                // TODO prevent allocation
                char* const pathC = readString(child, pidSyscallArg(child, 0)); // TODO prevent allocation
                std::string path = pathC;
                free(pathC);    // TODO prevent deallocation

                trace.doneSyscalls[syscall_num].push_back(path);

                if (show)
                {
                    printSyscall(child, syscall_num, retval);
                }

                switch (syscall_num)
                {
                case SYS_stat:
                case SYS_lstat: // TODO specialcase on lstat
                {
                    const struct stat stat = readStat(child, pidSyscallArg(child, 1));

                    const time_t ctime = stat.st_ctime; // creation
                    const time_t mtime = stat.st_mtime; // modification
                    const time_t atime = stat.st_atime; // access

                    if (ctime)
                    {
                        if (show) { fprintf(stderr, " ctime:%lu", ctime); }
                    }
                    if (mtime)
                    {
                        if (show) { fprintf(stderr, " mtime:%lu", mtime); }
                    }
                    if (atime)
                    {
                        if (show) { fprintf(stderr, " atime:%lu", atime); }
                    }

                    break;
                }
                case SYS_open:
                {
                    // decode open arguments
                    const auto flags = pidSyscallArg(child, 1);

                    // mode in case a new file is created
                    const auto mode = pidSyscallArg(child, 2);

                    // true if this open only reads from file
                    const bool read_flag = ((flags & (O_RDONLY)) ||
                                            (flags & (O_CLOEXEC)) ||
                                            (flags & (O_NOCTTY)) ||
                                            (flags == 0));

                    // true if this open only writes to file
                    const bool write_flag = ((flags & (O_WRONLY)) ||
                                             (flags & (O_RDWR |
                                                       O_CREAT |
                                                       O_TRUNC)) ||
                                             (flags & (O_WRONLY |
                                                       O_CREAT |
                                                       O_TRUNC)));

                    // assure that we decoded correctly
                    assert(read_flag || write_flag);

                    if (read_flag)
                    {
                        trace.inPathsByPid[child].push_back(std::string(path));
                    }

                    if (write_flag)
                    {
                        trace.outPathsByPid[child].push_back(std::string(path));
                    }

                    if (show)
                    {
                        fprintf(stderr, " ------- flags:%lx, mode:%lx, flags:", flags, mode);

                        const bool verbose = true;
                        if (verbose)
                        {
                            // print flags
                            if (flags & O_RDONLY) { fprintf(stderr, " O_RDONLY"); }
                            if (flags & O_WRONLY) { fprintf(stderr, " O_WRONLY"); }
                            if (flags & O_RDWR) { fprintf(stderr, " O_RDWR"); }
                            if (flags & O_DIRECTORY) { fprintf(stderr, " O_DIRECTORY"); }
                            if (flags & O_CREAT) { fprintf(stderr, " O_CREAT"); }
                            if (flags & O_TRUNC) { fprintf(stderr, " O_TRUNC"); }
                            if (flags & O_APPEND) { fprintf(stderr, " O_APPEND"); }
                            if (flags & O_CLOEXEC) { fprintf(stderr, " O_CLOEXEC"); }
                            if (flags & O_DIRECT) { fprintf(stderr, " O_DIRECT"); }
                            if (flags & O_DSYNC) { fprintf(stderr, " O_DSYNC"); }
                            if (flags & O_EXCL) { fprintf(stderr, " O_EXCL"); }
                            if (flags & O_LARGEFILE) { fprintf(stderr, " O_LARGEFILE"); }
                            if (flags & O_NOATIME) { fprintf(stderr, " O_NOATIME"); }
                            if (flags & O_NOCTTY) { fprintf(stderr, " O_NOCTTY"); }
                            if (flags & O_NOFOLLOW) { fprintf(stderr, " O_NOFOLLOW"); }

                            if (read_flag) { fprintf(stderr, " READ"); }
                            if (write_flag) { fprintf(stderr, " WRITE"); }
                        }
                    }

                    break;
                }
                default:
                    break;
                }

                if (show)
                {
                    endl();
                }
            }
            if (syscall_num == SYS_execve ||
                syscall_num == SYS_vfork)
            {
            }

            const bool verbose = false;
            if (verbose)
            {
                printSyscall(child, syscall_num, retval);
                endl();
            }
        }
        else                    // on failure return
        {
        }
    }
}

int doChild(int argc, char **argv)
{
    char *args [argc+1];
    int i;
    for (i = 0; i < argc; i++)
    {
        args[i] = argv[i];
    }
    args[argc] = NULL;

    ptrace(PTRACE_TRACEME);
    fprintf(stderr, "memoized: info: execvp:%s\n", args[0]);
    kill(getpid(), SIGSTOP);    // stop it directly

    return execvp(args[0], args);
}

int ptraceTopChild(pid_t top_child, Trace& trace)
{
    SHA256_Init(&trace.inputHash);
    // int SHA256_Update(SHA256_CTX *c, const void *data, size_t len);
    // int SHA256_Final(unsigned char *md, SHA256_CTX *c);

    while (true)
    {
        int status;
        const pid_t child = waitpid(-1, &status, __WALL); // wait for next child event
        if (child < 0)
        {
            return -1;          // failed
        }

        const int event = status >> 16;
        switch (event)
        {
        case PTRACE_EVENT_CLONE:
        case PTRACE_EVENT_FORK:
        case PTRACE_EVENT_VFORK:
        {
            // get pid of sub-child
            long newpid;
            ptrace(PTRACE_GETEVENTMSG, child, NULL, (long) &newpid);

            ptrace(PTRACE_SYSCALL, newpid, NULL, NULL);
            fprintf(stderr, "memoized: info: attached to offspring %ld\n", newpid);
            break;
        }
        default:
            if (WIFEXITED(status))
            {
                fprintf(stderr, "memoized: info: child %d exited\n", child);
                if (child == top_child)
                {
                    return 0;     // top child exited, we're done
                }
            }
            else if (WIFSTOPPED(status)) // stopped
            {
                const long stopsig = WSTOPSIG(status);
                if (stopsig & 0x80) // highest bit set
                {
                    fprintf(stderr, "child:%d TODO handle highest bit set\n", child);
                }
                else            // normal case
                {
                    // fprintf(stderr, "child:%d stopped with signal %ld\n", child, stopsig);
                    handleSyscall(child, trace);
                }
            }
            else
            {
                fprintf(stderr, "child:%d TODO handle other status:%d\n", child, status);
            }
            break;
        }

        ptrace(PTRACE_SYSCALL, child, NULL, NULL);
    }
}

void attachAndPtraceTopChild(pid_t top_child)
{
    const long traceRetVal = ptrace(PTRACE_ATTACH, top_child, NULL, NULL);
    if (traceRetVal == 0)             // success
    {
        fprintf(stderr, "memoized: info: attached to %d\n",top_child);
    }
    else
    {
        fprintf(stderr, "error: attach failed with return code %ld\n", traceRetVal);
    }

    const long opt = (PTRACE_O_EXITKILL |
                      PTRACE_O_TRACEEXEC |
                      PTRACE_O_TRACEFORK |
                      PTRACE_O_TRACECLONE |
                      PTRACE_O_TRACEVFORK |
                      PTRACE_O_TRACEVFORKDONE);
    ptrace(PTRACE_SETOPTIONS, top_child, NULL, opt);

    Trace trace;

    ptraceTopChild(top_child, trace);
}

int main(int argc, char **argv)
{
    pid_t child;
    int push = 1;
    int syscall = -1;

    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s [-s <syscall int>|-n <syscall name>] <program> <args>\n", argv[0]);
        exit(1);
    }

    if (strcmp(argv[1], "-s") == 0)
    {
        syscall = atoi(argv[2]);
        if (syscall > MAX_SYSCALL_NUM || syscall < 0)
        {
            fprintf(stderr, "error: %s is an invalid syscall\n", argv[2]);
            exit(1);
        }
        push = 3;
    }

    if (strcmp(argv[1], "-n") == 0)
    {
        char *syscallname = argv[2];
        struct syscall_entry *ent;
        uint i;

        for (i = 0; i < sizeof(syscalls)/sizeof(*syscalls); i++)
        {
            ent = &syscalls[i];
            if (strcmp(syscallname, ent->name) == 0)
            {
                syscall = i;
                break;
            }
        }

        if (syscall == -1)
        {
            fprintf(stderr, "error: %s is an invalid syscall\n", argv[2]);
            exit(1);
        }

        push = 3;
    }


    child = fork();
    if (child == -1)            /* fork failed */
    {
        fprintf(stderr, "error: Failed to fork()\n");
        exit(child);
    }

    if (child == 0)             /* in the child */
    {
        return doChild(argc-push, argv+push);
    }
    else                        /* in the parent */
    {
        attachAndPtraceTopChild(child);
    }
}

// int do_trace_top(pid_t root_child, int syscall_req)
// {
//     int status;
//     int retval;

//     waitpid(root_child, &status, 0);

//     assert(WIFSTOPPED(status));

//     ptrace(PTRACE_SETOPTIONS, root_child, 0,
//            PTRACE_O_TRACESYSGOOD |
//            PTRACE_O_EXITKILL |

//            PTRACE_O_TRACECLONE |
//            PTRACE_O_TRACEEXEC |
//            PTRACE_O_TRACEFORK |
//            PTRACE_O_TRACEVFORK |
//            PTRACE_O_TRACEVFORKDONE
//            );

//     const uint max_childs = 4096;
//     uint child_count = 0;
//     pid_t childs[max_childs];

//     childs[0] = root_child;
//     child_count = 1;

//     while (true)                /* TODO while children not empty */
//     {
//         for (uint childs_index = 0; childs_index != child_count; ++childs_index)
//         {
//             const pid_t child = childs[childs_index];
//             if (false)
//                 fprintf(stderr, "child:%d\n", child);

//             if (waitForChildPidSyscall(child) != 0)
//             {
//                 goto done;      /* TODO remove child from list of children */
//             }

//             /* pre syscall */

//             handleSyscall(child, syscall_req);
//             fprintf(stderr, "\n");

//             if (waitForChildPidSyscall(child) != 0)
//             {
//                 goto done;      /* TODO remove child from list of children */
//             }

//             /* post syscall */

//             handleSyscall(child, syscall_req);

//             retval = getReg(child, eax);
//             assert(errno == 0);

//             fprintf(stderr, "%d\n", retval);
//         }
//     }

//  done:

//     return 0;
// }
