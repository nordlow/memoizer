// TODO add check for non-existing PROGRAM in call: ./memoized PROGRAM, for
// instance when `foo` is given when `./foo` should be given

// TODO atomic_z_compress with mktemp and rename

// TODO read from cache with z_decompress()

// TODO Alternatively use http://stackoverflow.com/questions/5649030/how-can-i-easily-compress-and-decompress-files-using-zlib

// DECOMPRESS:
// char buf[1024*1024*16];
// gzFile *fi = (gzFile *)gzopen("file.gz","rb");
// gzrewind(fi);
// while(!gzeof(fi))
// {
//     int len = gzread(fi,buf,sizeof(buf));
//         //buf contains len bytes of decompressed data
// }
// gzclose(fi);
// For compression

// COMPRESS
// gzFile *fi = (gzFile *)gzopen("file.gz","wb");
// gzwrite(fi,"my decompressed data",strlen("my decompressed data"));
// gzclose(fi);

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

// STL
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <algorithm>
#include <array>
#include <memory>
#include <iostream>
#include <stdexcept>

#include "zpipe.h"

/// Run command `cmd`.
std::string exec(const char* cmd)
{
    const size_t buflen = 4096;
    std::array<char, buflen> buffer;
    std::string result;
    std::shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");
    while (!feof(pipe.get()))
    {
        if (fgets(buffer.data(), buflen, pipe.get()) != NULL)
        {
            result += buffer.data();
        }
    }
    return result;
}

// OpenSSL
#include <openssl/sha.h>

// system calls
#include "syscalls.h"
#include "syscallents.h"

#ifndef PATH_MAX
#include <sys/param.h>
#endif

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

const bool show = false;

long __get_reg(pid_t child, int off)
{
    long val = ptrace(PTRACE_PEEKUSER, child, off);
    assert(errno == 0);
    return val;
}

typedef unsigned long ulong;

typedef std::string Path;
typedef std::unordered_set<Path> Paths;
typedef std::unordered_set<pid_t> Pids;

typedef std::vector<Path> DoneSyscalls[MAX_SYSCALL_NUM + 1];
typedef std::unordered_map<Path, timespec> TimespecByPath;

bool operator < (const timespec& lhs,
                 const timespec& rhs)
{
    if (lhs.tv_sec == rhs.tv_sec)
    {
        return lhs.tv_nsec < rhs.tv_nsec;
    }
    else
    {
        return lhs.tv_sec < rhs.tv_sec;
    }
}

struct PidMtime
{
    PidMtime(pid_t pid_, struct timespec mtim_)
    {
        this->pid = pid_;
        this->mtim = mtim_;
    }
    pid_t pid;
    struct timespec mtim;
};

typedef std::vector<PidMtime> PidMtimes;

typedef std::unordered_map<pid_t, Path> PathByPid;

/// Unordered paths.
typedef std::unordered_set<Path> PathUSet;

/// Ordered paths.
typedef std::set<Path> PathOSet;

/// Trace results for a specific process.
struct Trace1
{
    /// Current working directory path.
    Path cwdPath;

    /// System calls.
    DoneSyscalls doneSyscalls;

    /// Absolute:
    /// Read-only opened absolute file paths.
    PathUSet absReadPaths;
    /// Write-only opened absolute file paths.
    PathUSet absWritePaths;
    /// Stated absolute file paths.
    PathUSet absStatPaths;

    /// Relative:
    /// Read-only opened relative file paths.
    PathUSet relReadPaths;
    /// Write-only opened relative file paths.
    PathUSet relWritePaths;
    /// Stated relative file paths.
    PathUSet relStatPaths;

    TimespecByPath maxTimespecByStatPath;

    // SHA256_CTX inputHash;
    // SHA256_Init(&traces.inputHash);
    // int SHA256_Update(SHA256_CTX *c, const void *data, size_t len);
    // int SHA256_Final(unsigned char *md, SHA256_CTX *c);
};

/// All current traces.
struct Traces
{
    Path homePath;
    Path topCwdPath;            // cwd path of top child

    /// Traces by process `pid_t`.
    std::unordered_map<pid_t, Trace1> trace1ByPid;
};

bool startsWith(const std::string& whole, const char* part)
{
    return whole.find(part) == 0;
}

bool isHashableFilePath(const Path& path)
{
    return (path != "/tmp" &&
            (!startsWith(path, "/tmp/")) &&
            (!startsWith(path, "/dev/urandom")));
}

template<typename T>
std::vector<T> toSortedVector(const std::unordered_set<T>& uset)
{
    std::vector<T> vec(uset.begin(), uset.end());
    std::sort(vec.begin(), vec.end());
    return vec;
}

void gitShowRemoteOrigin()
{
    const auto execString = exec("git remote show origin");
    fprintf(stdout, "%s", execString.c_str());
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
char *readCString(pid_t child, unsigned long addr)
{
    uint allocated = 4096;
    char *val = reinterpret_cast<char*>(malloc(allocated));
    uint count = 0;
    while (true)
    {
        long tmp;
        if (count + sizeof(tmp) > allocated)
        {
            allocated *= 2;
            val = reinterpret_cast<char*>(realloc(val, allocated));
        }
        tmp = ptrace(PTRACE_PEEKDATA, child, addr + count);
        if (errno != 0)
        {
            val[count] = 0;
            break;
        }
        memcpy(val + count, &tmp, sizeof(tmp));
        if (memchr(&tmp, 0, sizeof(tmp)) != NULL) // if null terminator ound
        {
            break;
        }
        count += sizeof(tmp);
    }
    return val;
}

std::string readCxxString(pid_t child, unsigned long addr)
{
    // TODO prevent allocation by reading directy into preallocated std::string
    char* const pathC = readCString(child, addr);
    std::string path = pathC;
    free(pathC);
    return path;
}

/** Allocate and return a copy of a null-terminated C string at `addr`.
    TODO templatize T on struct stat when moving to D
 */
struct stat readStat(pid_t child, unsigned long addr)
{
    struct stat data;
    uint8_t* statPtr = reinterpret_cast<uint8_t*>(&data); // TODO byte
    assert(sizeof(data) % sizeof(long) == 0); // require even number of chunks for now
    uint count = 0;
    while (count < sizeof(data))
    {
        const long tmp = ptrace(PTRACE_PEEKDATA, child, addr + count);
        if (errno != 0)
        {
            fprintf(stderr, "memoized: error: cannot read ptrace(PTRACE_PEEKDATA)\n");
            break;
        }
        memcpy(statPtr + count, &tmp, sizeof(tmp));
        count += sizeof(tmp);
    }
    return data;
}

void printSyscallArgs(pid_t child, int num)
{
    const char * sname = syscallNameOfNumber(num);
    struct syscall_entry *ent = NULL;
    int nargs = SYSCALL_MAXARGS;
    int i;

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
                char* strval = readCString(child, arg);
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
                char* strval = readCString(child, arg);
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
                char* strval = readCString(child, arg);
                if (show) fprintf(stderr, "\"%s\"", strval);
                free(strval);
                goto done;
            }
        }
        else if (strcmp(sname, "mount") == 0)
        {
            if (i == 2)
            {
                char* strval = readCString(child, arg);
                if (show) fprintf(stderr, "\"%s\"", strval);
                free(strval);
                goto done;
            }
        }

        // generic printing
        switch (type)
        {
        case ARG_INT:
        {
            if (show) fprintf(stderr, "%ld", arg);
            break;
        }
        case ARG_STR:
        {
            char* strval = readCString(child, arg);
            if (show) fprintf(stderr, "\"%s\"", strval);
            free(strval);
            break;
        }
        default:
        {
            if (show) fprintf(stderr, "0x%lx", arg);
            break;
        }
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
    fprintf(stderr, "%ld;", retval);
}

bool isAbsolutePath(const Path& path)
{
    return !path.empty() && path[0] == '/';
}

/// Create tree cache directories if it doesn't exist.
void assertCacheDirTree(Traces& traces)
{
    const mode_t mode = 0777;
    // Python os.makedirs()
    mkdir((traces.homePath + "/.cache").c_str(), mode);
    mkdir((traces.homePath + "/.cache/memoized").c_str(), mode);
    mkdir((traces.homePath + "/.cache/memoized/artifacts").c_str(), mode);
    mkdir((traces.homePath + "/.cache/memoized/calls").c_str(), mode);
}

/// Create tree cache directories if it doesn't exist.
Path getArtifactPath(const Traces& traces,
                     const char* filePath,
                     const char* fileExtension)
{
    return traces.homePath + "/.cache/memoized/artifacts" + "/" + filePath + "." + fileExtension;
}

/** Lookup path of file descriptor `fd` of process with pid `pid` and put into
    `linkDestPath`.

    See https://stackoverflow.com/questions/1188757
*/
ssize_t lookupPidFdPath(pid_t pid, int fd,
                        char* linkDestPath, size_t linkDestPathBufSize) // out parameter
{
    char fdPath[64]; // actual maximum length is 37 for 64-bit system
    snprintf(fdPath, sizeof(fdPath), "/proc/%d/%d", pid, fd);
    const ssize_t ret = readlink(fdPath, linkDestPath, linkDestPathBufSize); // get path
    if (ret < 0)
    {
        // fprintf(stderr, "memoized: error: failed to lookup pid:%d fd:%d fdPath:%s\n", pid, fd, fdPath);
    }
    return ret;
}

/** Lookup current working directory of process with pid `pid` and put into
    `cwdPath`.

    See https://stackoverflow.com/questions/1188757
*/
ssize_t lookupPidCwdPath(pid_t pid,
                         char* cwdPath, size_t cwdPathBufSize) // out parameter
{
    char fdPath[64]; // actual maximum length is 37 for 64-bit system
    snprintf(fdPath, sizeof(fdPath), "/proc/%d/cwd", pid);
    const ssize_t ret = readlink(fdPath, cwdPath, cwdPathBufSize); // get path
    if (ret < 0)
    {
        fprintf(stderr, "memoized: error: failed to lookup cwd of pid:%d fdPath:%s\n", pid, fdPath);
    }
    else
    {
        cwdPath[ret] = '\0';
    }
    return ret;
}

Path buildPath(const Path& a,
               const Path& b)
{
    return a + "/" + b;
}

Path buildPath(const Path& a,
               const char* b)
{
    return a + "/" + b;
}

void dln(const char* hint, const char *str)
{
    fprintf(stderr, "memoized: debug: %s:%s\n", hint, str);
}

Path buildAbsPath(Traces& traces, pid_t child, const Path& path)
{
    const Path cachedCwdPath = traces.trace1ByPid[child].cwdPath;
    if (!cachedCwdPath.empty()) // if a chdir has been called by child use it
    {
#ifndef NDEBUG                  // debug {}
        char trueCwdPath[PATH_MAX];
        const ssize_t cwdRet = lookupPidCwdPath(child, trueCwdPath, sizeof(trueCwdPath));
        if (cwdRet >= 0)
        {
            // fprintf(stderr, "cachedCwdPath:%s\n", cachedCwdPath.c_str());
            // fprintf(stderr, "trueCwdPath:%s\n", trueCwdPath);
            assert(cachedCwdPath == trueCwdPath); // check against current value
        }
#endif
        return buildPath(cachedCwdPath, path);
    }
    else
    {
        char trueCwdPath[PATH_MAX];
        const ssize_t cwdRet = lookupPidCwdPath(child, trueCwdPath, sizeof(trueCwdPath));
        assert(cwdRet >= 0);
        return buildPath(trueCwdPath, path);
    }
}

void handleSyscall(pid_t child, Traces& traces)
{
    const long syscall_num = getReg(child, orig_eax);
    assert(errno == 0);

    // return value
    long retval = getReg(child, eax);
    assert(errno == 0);
    if (retval == -38)          // on call entry
    {
        // printSyscall(child, syscall_num, retval); endl(stderr);
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
                const Path path = readCxxString(child, pidSyscallArg(child, 0)); // TODO prevent allocation

                if (show) { printSyscall(child, syscall_num, retval); }

                char linkDestPath[PATH_MAX];
                if (syscall_num == SYS_open ||
                    syscall_num == SYS_openat ||
                    syscall_num == SYS_creat)
                {
                    const ssize_t fdRet = lookupPidFdPath(child,
                                                          (int)retval, // to file descriptor
                                                          linkDestPath, sizeof(linkDestPath));
                    if (fdRet >= 0)
                    {
                        if (show)
                        {
                            fprintf(stderr, "%s is actually %s", path.c_str(), linkDestPath);
                        }
                    }
                }

                traces.trace1ByPid[child].doneSyscalls[syscall_num].push_back(path);

                switch (syscall_num)
                {
                case SYS_stat:
                case SYS_lstat: // TODO specialcase on lstat
                {
                    const struct stat stat = readStat(child, pidSyscallArg(child, 1));
                    struct timespec mtime = stat.st_mtim; // modification time

                    if (isAbsolutePath(path))
                    {
                        traces.trace1ByPid[child].absStatPaths.insert(path);
                    }
                    else
                    {
                        const Path absPath = buildAbsPath(traces, child, path);
                        if (startsWith(absPath, traces.topCwdPath.c_str()))
                        {
                            const Path relPath = absPath.substr(traces.topCwdPath.size() + 1,
                                                                absPath.size());
                            // fprintf(stderr, "stat relPath:%s\n", relPath.c_str());
                            traces.trace1ByPid[child].relStatPaths.insert(relPath);
                        }
                        else
                        {
                            // fprintf(stderr, "stat absPath:%s\n", absPath.c_str());
                            traces.trace1ByPid[child].absStatPaths.insert(absPath);
                        }
                    }

                    auto hit = traces.trace1ByPid[child].maxTimespecByStatPath.find(path);
                    if (hit != traces.trace1ByPid[child].maxTimespecByStatPath.end()) // if hit
                    {
                        if (traces.trace1ByPid[child].maxTimespecByStatPath[Path(path)] < mtime) // if more recent
                        {
                            traces.trace1ByPid[child].maxTimespecByStatPath[Path(path)] = mtime; // store more recent
                        }
                    }
                    else
                    {
                        traces.trace1ByPid[child].maxTimespecByStatPath[Path(path)] = mtime;
                    }

                    if (show)
                    {
                        fprintf(stderr, " st_mtime:%ld.%09ld", mtime.tv_sec, mtime.tv_nsec);
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
                    const bool read_flag = (((flags & (O_RDONLY)) ||
                                             (flags & (O_CLOEXEC)) ||
                                             (flags & (O_NOCTTY)) ||
                                             (flags == 0)) &&
                                            (!(flags & O_TRUNC)));

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
                        // TODO functionize:
                        if (isAbsolutePath(path))
                        {
                            traces.trace1ByPid[child].absReadPaths.insert(path);
                        }
                        else
                        {
                            const Path absPath = buildAbsPath(traces, child, path);
                            if (startsWith(absPath, traces.topCwdPath.c_str()))
                            {
                                const Path relPath = absPath.substr(traces.topCwdPath.size() + 1,
                                                                    absPath.size());
                                // fprintf(stderr, "read relPath:%s\n", relPath.c_str());
                                traces.trace1ByPid[child].relReadPaths.insert(relPath);
                            }
                            else
                            {
                                // fprintf(stderr, "read absPath:%s\n", absPath.c_str());
                                traces.trace1ByPid[child].absReadPaths.insert(absPath);
                            }
                        }
                    }

                    if (write_flag)
                    {
                        // TODO functionize:
                        if (isAbsolutePath(path))
                        {
                            traces.trace1ByPid[child].absWritePaths.insert(path);
                        }
                        else
                        {
                            const Path absPath = buildAbsPath(traces, child, path);
                            if (startsWith(absPath, traces.topCwdPath.c_str()))
                            {
                                const Path relPath = absPath.substr(traces.topCwdPath.size() + 1,
                                                                    absPath.size());
                                // fprintf(stderr, "write relPath:%s\n", relPath.c_str());
                                traces.trace1ByPid[child].relWritePaths.insert(relPath);
                            }
                            else
                            {
                                // fprintf(stderr, "write absPath:%s\n", absPath.c_str());
                                traces.trace1ByPid[child].absWritePaths.insert(absPath);
                            }
                        }
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
            else if (syscall_num == SYS_execve ||
                     syscall_num == SYS_vfork ||
                     syscall_num == SYS_clone)
            {
                // fprintf(stderr, "syscall_num:%d\n", syscall_num);
                // printSyscall(child, syscall_num, retval);
                // endl(stderr);
                // endl(stderr);
            }
            else if (syscall_num == SYS_fstat)
            {
                if (false)
                {
                    fprintf(stderr, "memoized: TODO handle system call fstat()\n");
                }
            }
            else if (syscall_num == SYS_chdir)
            {
                traces.trace1ByPid[child].cwdPath = readCxxString(child, pidSyscallArg(child, 0));
                if (show)
                {
                    printSyscall(child, syscall_num, retval);
                    endl(stderr);
                }
            }
            else if (syscall_num == SYS_getcwd)
            {
                if (false)
                {
                    const Path path = readCxxString(child, pidSyscallArg(child, 0)); // TODO prevent allocation
                    fprintf(stderr, "memoized: TODO handle getcwd(%s)\n", path.c_str());
                }
            }
            else
            {
                // fprintf(stderr, "memoized: syscall_num:%d\n", syscall_num);
                // printSyscall(child, syscall_num, retval);
                // endl(stderr);
                // endl(stderr);
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
    if (show)
    {
        fprintf(stderr, "memoized: info: execvp:%s\n", args[0]);
    }
    kill(getpid(), SIGSTOP);    // stop it directly before executions starts

    return execvp(args[0], args);
}

int ptraceTopChild(pid_t topChild, Traces& traces)
{
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
            ptrace(PTRACE_GETEVENTMSG, child, NULL, (long)&newpid);
            ptrace(PTRACE_SYSCALL, newpid, NULL, NULL);
            if (show)
            {
                fprintf(stderr, "memoized: info: attached to offspring %ld\n", newpid);
            }
            break;
        }
        default:
            if (WIFEXITED(status))
            {
                if (show)
                {
                    fprintf(stderr, "memoized: info: child %d exited\n", child);
                }
                if (child == topChild)
                {
                    return 0;     // top child exited, we're done
                }
            }
            else if (WIFSTOPPED(status)) // stopped
            {
                const long stopsig = WSTOPSIG(status);
                if (stopsig & 0x80) // highest bit set
                {
                    fprintf(stderr, "memoized: child:%d TODO handle highest bit set\n", child);
                }
                else            // normal case
                {
                    // fprintf(stderr, "child:%d stopped with signal %ld\n", child, stopsig);
                    handleSyscall(child, traces);
                }
            }
            else
            {
                fprintf(stderr, "memoized: child:%d TODO handle other status:%d\n", child, status);
            }
            break;
        }

        ptrace(PTRACE_SYSCALL, child, NULL, NULL);
    }
}


int tryAttachToPid(pid_t child)
{
    const uint tryCountMax = 1000;
    for (uint tryCount = 0; tryCount < tryCountMax; ++tryCount)
    {
        const long traceRetVal = ptrace(PTRACE_ATTACH, child, NULL, NULL);
        if (traceRetVal == 0)             // success
        {
            if (show)
            {
                fprintf(stderr, "memoized: memoized: info: attached to child with pid=%d\n", child);
            }
            goto ok;
        }
        else
        {
            fprintf(stderr, "memoized: warning: attach failed with return code %ld\n", traceRetVal);
        }
    }
    fprintf(stderr, "memoized: error: attach failed %d times\n", tryCountMax);
    return -1;
ok:
    return 0;
}

int attachAndPtraceTopChild(Traces& traces, pid_t topChild)
{
    const int retVal = tryAttachToPid(topChild);
    if (retVal < 0) { return retVal; }

    const long opt = (PTRACE_O_EXITKILL |
                      PTRACE_O_TRACEEXEC |
                      PTRACE_O_TRACEFORK |
                      PTRACE_O_TRACECLONE |
                      PTRACE_O_TRACEVFORK |
                      PTRACE_O_TRACEVFORKDONE);
    ptrace(PTRACE_SETOPTIONS, topChild, NULL, opt);

    ptraceTopChild(topChild, traces);

    return 0;
}

void SHA256_hashString(const unsigned char hash[SHA256_DIGEST_LENGTH],
                       char digestHexStringBuf[2*SHA256_DIGEST_LENGTH + 1])
{
    for (uint i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(digestHexStringBuf + (i * 2), "%02x", hash[i]);
    }
    digestHexStringBuf[64] = '\0'; // set null terminator
}

/** SHA-256 digest file with path `path` into `digestHexStringBuf`.
   See also: http://stackoverflow.com/questions/7853156/calculate-sha256-of-a-file-using-openssl-libcrypto-in-c
   */
int SHA256_Digest_File(const char* path,
                       char digestHexStringBuf[2*SHA256_DIGEST_LENGTH + 1])
{
    FILE* file = fopen(path, "rb");
    if (!file)
    {
        return -1;
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    const int bufSize = 32768;
    char* buffer = reinterpret_cast<char*>(malloc(bufSize));

    if (!buffer)
    {
        fclose(file);
        return -1;
    }

    int bytesRead = 0;
    while((bytesRead = fread(buffer, 1, bufSize, file)))
    {
        SHA256_Update(&sha256, buffer, bytesRead);
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);

    SHA256_hashString(hash, digestHexStringBuf);

    fclose(file);
    free(buffer);

    return 0;
}

// TODO handle abrupt termination by first writing to temporary and then moving it cache atomically
void compressToCache(const Traces& traces, const Path& sourcePath)
{
    char digestHexStringBuf[2*SHA256_DIGEST_LENGTH + 1];
    assert(SHA256_Digest_File(sourcePath.c_str(), digestHexStringBuf) >= 0);

    const Path destPath = getArtifactPath(traces, digestHexStringBuf, "z");

    if (access(destPath.c_str(), F_OK) == -1) // if fname doesn't exit
    {
        if (true)
        {
            fprintf(stderr,
                    "memoized: compressing artifact `%s` to `%s` ... ",
                    sourcePath.c_str(),
                    destPath.c_str());
            fflush(stderr);
        }

        FILE* dest = fopen(destPath.c_str(), "w+");
        assert(dest);

        FILE* source = fopen(sourcePath.c_str(), "r");
        assert(source);
        z_compress(source, dest, Z_DEFAULT_COMPRESSION);
        fclose(source);
        fclose(dest);

        if (true)
        {
            fprintf(stderr, "done\n");
        }
    }
    else
    {
        if (true)
        {
            fprintf(stderr,
                    "memoized: artifact `%s` already compressed to `%s`\n",
                    sourcePath.c_str(),
                    destPath.c_str());
        }
    }
}

int main(int argc, char* argv[], char* envp[])
{
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
            fprintf(stderr, "memoized: error: %s is an invalid syscall\n", argv[2]);
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
            fprintf(stderr, "memoized: error: %s is an invalid syscall\n", argv[2]);
            exit(1);
        }

        push = 3;
    }

    const pid_t topChild = fork();
    if (topChild == -1)            /* fork failed */
    {
        fprintf(stderr, "memoized: error: Failed to fork()\n");
        exit(topChild);
    }

    if (topChild == 0)             /* in the top child */
    {
        return doChild(argc-push, argv+push);
    }
    else                        /* in the parent */
    {
        Traces traces;
        traces.homePath = getenv("HOME");

        char cwdBuf[PATH_MAX];
        const char* cwd = getcwd(cwdBuf, PATH_MAX);
        traces.topCwdPath = cwd;

        std::string progPath = argv[0];
        std::string progAbsPath = cwd + ("/" + progPath);

        const int attachRetVal = attachAndPtraceTopChild(traces, topChild);
        if (attachRetVal < 0)
        {
            exit(attachRetVal);
        }

        assertCacheDirTree(traces);

        // TODO calculate chash from `pwd` `argv` and 'env' used in child

        // post process
        const Path call_file = (traces.homePath + "/.cache/memoized/calls/first.txt");
        FILE* fi = fopen(call_file.c_str(), "wb");

        const char* indentation = "    ";

        fprintf(fi, "program:\n");
        fprintf(fi, "    %s TODO st_mtime and sha256:\n", progAbsPath.c_str());

        fprintf(fi, "call:\n");
        for (int i = 1; i != argc; ++i) // all but first argument
        {
            fprintf(fi, "%s%s\n", indentation, argv[i]);
        }

        fprintf(fi, "cwd: %s\n", cwd);

        bool first = false;

        // collect all paths
        PathOSet allAbsWritePaths;
        PathOSet allAbsReadPaths;
        PathOSet allAbsStatPaths;
        PathOSet allRelWritePaths;
        PathOSet allRelReadPaths;
        PathOSet allRelStatPaths;
        for (auto const& ent : traces.trace1ByPid)
        {
            const Trace1& trace1 = ent.second;
            for (auto const& path : trace1.absWritePaths)
            {
                allAbsWritePaths.insert(path);
            }
            for (auto const& path : trace1.absReadPaths)
            {
                allAbsReadPaths.insert(path);
            }
            for (auto const& path : trace1.absStatPaths)
            {
                allAbsStatPaths.insert(path);
            }
            for (auto const& path : trace1.relWritePaths)
            {
                allRelWritePaths.insert(path);
            }
            for (auto const& path : trace1.relReadPaths)
            {
                allRelReadPaths.insert(path);
            }
            for (auto const& path : trace1.relStatPaths)
            {
                allRelStatPaths.insert(path);
            }
        }

        first = true;
        for (const Path& path : allRelWritePaths)
        {
            if (isHashableFilePath(path))
            {
                compressToCache(traces, path);
                if (first) { fprintf(fi, "relative writes:\n"); first = false; }
                fprintf(fi, "%s%s\n", indentation, path.c_str());
            }
        }

        first = true;
        for (const Path& path : allRelReadPaths)
        {
            if (isHashableFilePath(path))
            {
                if (first) { fprintf(fi, "relative reads:\n"); first = false; }
                fprintf(fi, "%s%s\n", indentation, path.c_str());
            }
        }

        first = true;
        for (auto const& ent : traces.trace1ByPid)
        {
            // const pid_t child = ent.first;
            const Trace1& trace1 = ent.second;
            for (const Path& path : toSortedVector(trace1.relStatPaths))
            {
                if (isHashableFilePath(path))
                {
                    if (first) { fprintf(fi, "relative stats:\n"); first = false; }
                    fprintf(fi, "%s%s", indentation, path.c_str());
                    auto hit = trace1.maxTimespecByStatPath.find(Path(path));
                    if (hit != trace1.maxTimespecByStatPath.end()) // if hit
                    {
                        fprintf(fi,
                                " %ld.%09ld",
                                hit->second.tv_sec,
                                hit->second.tv_nsec);
                    }
                    endl(fi);
                }
            }
        }

        first = true;
        for (const Path& path : allAbsWritePaths)
        {
            if (isHashableFilePath(path))
            {
                compressToCache(traces, path);
                if (first) { fprintf(fi, "absolute writes:\n"); first = false; }
                fprintf(fi, "%s%s\n", indentation, path.c_str());
            }
        }

        first = true;
        for (const Path& path : allAbsReadPaths)
        {
            if (isHashableFilePath(path))
            {
                if (first) { fprintf(fi, "absolute reads:\n"); first = false; }
                fprintf(fi, "%s%s\n", indentation, path.c_str());
            }
        }

        first = true;
        for (auto const& ent : traces.trace1ByPid)
        {
            // const pid_t child = ent.first;
            const Trace1& trace1 = ent.second;
            for (const Path& path : toSortedVector(trace1.absStatPaths))
            {
                if (isHashableFilePath(path))
                {
                    if (first) { fprintf(fi, "absolute stats:\n"); first = false; }
                    fprintf(fi, "%s%s", indentation, path.c_str());
                    auto hit = trace1.maxTimespecByStatPath.find(Path(path));
                    if (hit != trace1.maxTimespecByStatPath.end()) // if hit
                    {
                        fprintf(fi,
                                " %ld.%09ld",
                                hit->second.tv_sec,
                                hit->second.tv_nsec);
                    }
                    endl(fi);
                }
            }
        }

        const bool sortedEnv = true;

        fprintf(fi, "environment:\n");
        if (sortedEnv)
        {
            std::vector<std::string> env;
            for (int i = 0; envp[i]; ++i)
            {
                env.push_back(envp[i]);
            }
            std::sort(env.begin(), env.end());

            for (int i = 0; envp[i]; ++i)
            {
                fprintf(fi, "%s%s\n", indentation, env[i].c_str());
            }
        }
        else
        {
            for (int i = 0; envp[i]; ++i)
            {
                fprintf(fi, "%s%s\n", indentation, envp[i]);
            }
        }

        fclose(fi);
    }
}

/** Wait for system call in `child`. */
// int waitForChildPidSyscall(pid_t child)
// {
//     while (true)
//     {
//         // tracee is stopped at the next entry to or exit from a system call
//         ptrace(PTRACE_SYSCALL, child, 0, 0);

//         int status;
//         waitpid(child, &status, 0); // wait for child

//         if (WIFSTOPPED(status) &&    // if child stopped and
//             WSTOPSIG(status) & 0x80) // highest bit set
//         {
//             return 0;
//         }

//         if (WIFEXITED(status))  // if child exited
//         {
//             return 1;
//         }

//         fprintf(stderr, "[stopped status:%d stopsignal:%x]\n", status, WSTOPSIG(status));
//     }
// }
