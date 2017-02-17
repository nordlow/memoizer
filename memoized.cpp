#include <sys/ptrace.h>
#include <bits/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <syscall.h>

#include <unistd.h>
#include <cstdlib>
#include <cstdio>
#include <cerrno>
#include <cassert>
#include <cstring>

#include <openssl/sha.h>

#include "syscalls.h"
#include "syscallents.h"

#include <vector>
#include <string>

/* cheap trick for reading syscall number / return value. */
#ifdef __amd64__
#define eax rax
#define orig_eax orig_rax
#else
#endif

#ifndef offsetof
#define offsetof(a, b) __builtin_offsetof(a,b)
#endif

#define get_reg(child, name) __get_reg(child, offsetof(struct user, regs.name))

long __get_reg(pid_t child, int off)
{
    long val = ptrace(PTRACE_PEEKUSER, child, off);
    assert(errno == 0);
    return val;
}

typedef std::vector<std::string> DoneSyscalls[MAX_SYSCALL_NUM + 1];

/** Wait for system call in `child`. */
int wait_for_syscall(pid_t child)
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

const char *syscall_name_of_number(int syscall_number)
{
    if (syscall_number <= MAX_SYSCALL_NUM)
    {
        struct syscall_entry *ent = &syscalls[syscall_number];
        if (ent->name)
        {
            return ent->name;
        }
    }
    static char buf[128];
    snprintf(buf, sizeof buf, "sys_%d", syscall_number);
    return buf;
}

long get_syscall_arg(pid_t child, int which)
{
    switch (which)
    {
#ifdef __amd64__
    case 0: return get_reg(child, rdi);
    case 1: return get_reg(child, rsi);
    case 2: return get_reg(child, rdx);
    case 3: return get_reg(child, r10);
    case 4: return get_reg(child, r8);
    case 5: return get_reg(child, r9);
#else
    case 0: return get_reg(child, ebx);
    case 1: return get_reg(child, ecx);
    case 2: return get_reg(child, edx);
    case 3: return get_reg(child, esi);
    case 4: return get_reg(child, edi);
    case 5: return get_reg(child, ebp);
#endif
    default: return -1L;
    }
}

/** Allocate and return a copy of a null-terminated C string at `addr`. */
char *read_string(pid_t child, unsigned long addr)
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
        memcpy(val + read, &tmp, sizeof tmp);
        if (memchr(&tmp, 0, sizeof tmp) != NULL)
        {
            break;
        }
        read += sizeof tmp;
    }
    return val;
}

void print_syscall_args(pid_t child, int num)
{
    const char * sname = syscall_name_of_number(num);
    struct syscall_entry *ent = NULL;
    int nargs = SYSCALL_MAXARGS;
    int i;
    char *strval;

    if (num <= MAX_SYSCALL_NUM && syscalls[num].name)
    {
        ent = &syscalls[num];
        nargs = ent->nargs;
    }
    for (i = 0; i < nargs; i++)
    {
        const long arg = get_syscall_arg(child, i);
        const int type = ent ? ent->args[i] : ARG_PTR;

        if (strcmp(sname, "execve") == 0)
        {
            if (i == 0)
            {
                strval = read_string(child, arg);
                fprintf(stderr, "\"%s\"", strval);
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
                strval = read_string(child, arg);
                fprintf(stderr, "\"%s\"", strval);
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
                strval = read_string(child, arg);
                fprintf(stderr, "\"%s\"", strval);
                free(strval);
                goto done;
            }
        }
        else if (strcmp(sname, "mount") == 0)
        {
            if (i == 2)
            {
                strval = read_string(child, arg);
                fprintf(stderr, "\"%s\"", strval);
                free(strval);
                goto done;
            }
        }

        // generic printing
        switch (type)
        {
        case ARG_INT:
            fprintf(stderr, "%ld", arg);
            break;
        case ARG_STR:
            strval = read_string(child, arg);
            fprintf(stderr, "\"%s\"", strval);
            free(strval);
            break;
        default:
            fprintf(stderr, "0x%lx", arg);
            break;
        }

        done:

        if (i != nargs - 1)     /* if not parameter */
        {
            fprintf(stderr, ", ");
        }
    }
}

void print_syscall(pid_t child,
                   DoneSyscalls& done_syscalls)
{
    long num;                    // syscall number
    num = get_reg(child, orig_eax);
    assert(errno == 0);

    // return value
    long retval = get_reg(child, eax);
    assert(errno == 0);
    if (retval == -38)          // on call entry
    {
    }
    else                        // on call return
    {
        if (retval >= 0)        // on successful return
        {
            if (num == SYS_open ||
                num == SYS_stat ||
                num == SYS_lstat ||
                num == SYS_access)
            {
                const char* path = "";
                done_syscalls[num].push_back(std::string(path));
                // on file io successful return
            }
            if (num == SYS_execve ||
                num == SYS_vfork)
            {
            }

            const bool verbose = false;
            if (verbose)
            {
                fprintf(stderr, "%d %s(", child, syscall_name_of_number(num));
                print_syscall_args(child, num);
                fprintf(stderr, ") = ");
                fprintf(stderr, "%ld", retval);
                fprintf(stderr, "\n");
            }
        }
        else                    // on failure return
        {
        }
    }
}

int do_child(int argc, char **argv)
{
    char *args [argc+1];
    int i;
    for (i = 0; i < argc; i++)
    {
        args[i] = argv[i];
    }
    args[argc] = NULL;

    ptrace(PTRACE_TRACEME);
    fprintf(stderr, "info: execvp:%s\n", args[0]);
    kill(getpid(), SIGSTOP);    // stop it directly

    return execvp(args[0], args);
}

int ptrace_of_top_child(pid_t top_child)
{
    SHA256_CTX hash;
    SHA256_Init(&hash);
    // int SHA256_Update(SHA256_CTX *c, const void *data, size_t len);
    // int SHA256_Final(unsigned char *md, SHA256_CTX *c);

    DoneSyscalls done_syscalls;

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
            fprintf(stderr, "info: attached to offspring %ld\n", newpid);
            break;
        }
        default:
            if (WIFEXITED(status))
            {
                fprintf(stderr, "info: child %d exited\n", child);
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
                    print_syscall(child, done_syscalls);
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

void attach_and_ptrace_process(pid_t top_child)
{
    const long trace = ptrace(PTRACE_ATTACH, top_child, NULL, NULL);
    if (trace == 0)             // success
    {
        fprintf(stderr, "info: attached to %d\n",top_child);
    }
    else
    {
        fprintf(stderr, "error: attach failed with return code %ld\n", trace);
    }

    const long opt = (PTRACE_O_EXITKILL |
                      PTRACE_O_TRACEEXEC |
                      PTRACE_O_TRACEFORK |
                      PTRACE_O_TRACECLONE |
                      PTRACE_O_TRACEVFORK |
                      PTRACE_O_TRACEVFORKDONE);
    ptrace(PTRACE_SETOPTIONS, top_child, NULL, opt);

    ptrace_of_top_child(top_child);
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
        return do_child(argc-push, argv+push);
    }
    else                        /* in the parent */
    {
        attach_and_ptrace_process(child);
        /* return do_trace_top(child, syscall); */
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

//             if (wait_for_syscall(child) != 0)
//             {
//                 goto done;      /* TODO remove child from list of children */
//             }

//             /* pre syscall */

//             print_syscall(child, syscall_req);
//             fprintf(stderr, "\n");

//             if (wait_for_syscall(child) != 0)
//             {
//                 goto done;      /* TODO remove child from list of children */
//             }

//             /* post syscall */

//             print_syscall(child, syscall_req);

//             retval = get_reg(child, eax);
//             assert(errno == 0);

//             fprintf(stderr, "%d\n", retval);
//         }
//     }

//  done:

//     return 0;
// }
