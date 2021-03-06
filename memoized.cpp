// TODO search for: lookup absolute path for this
// TODO search for: memoize this call

// TODO add check for non-existing PROGRAM in call: ./memoized PROGRAM, for
// instance when `foo` is given when `./foo` should be given

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

    /// Read-only opened (executable) file (shared library) paths.
    PathUSet execPaths;

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

    /// Full path of top child executable.
    Path topChildExecPath;

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
            (!startsWith(path, "/dev/urandom")) &&
            (!startsWith(path, "/dev/null")));
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

struct timespec statModTimespec_C(const char* path)
{
    struct stat st;
    assert(stat(path, &st) == 0);
    return st.st_mtim; // modification time
}

struct timespec statModTimespec(const Path& path)
{
    return statModTimespec_C(path.c_str());
}

/** Allocate and return a copy of a null-terminated C string at `addr`.
    TODO templatize T on struct stat when moving to D
 */
struct stat ptraceReadStat(pid_t child, unsigned long addr)
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
        else if (strcmp(sname, "open") == 0 || // TODO use std.algorithm.among() when porting to Dlang
                 strcmp(sname, "utime") == 0 ||
                 strcmp(sname, "utimes") == 0 ||
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
                 strcmp(sname, "mknod") == 0 ||
                 strcmp(sname, "remove") == 0)
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

Path realPath(const char* path)
{
    char pathBuf[PATH_MAX];
    return Path(realpath(path, pathBuf));
}

Path getCwdPath()
{
    char pathBuf[PATH_MAX];
    return Path(getcwd(pathBuf, PATH_MAX));
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
                     const char* fileName,
                     const char* fileExtension)
{
    return traces.homePath + "/.cache/memoized/artifacts" + "/" + fileName + "." + fileExtension;
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

void updateMaxTime(TimespecByPath& timespecByPath,
                   const Path& path,
                   const struct timespec& mtim)
{
    auto hit = timespecByPath.find(path);
    if (hit != timespecByPath.end()) // if hit
    {
        if (timespecByPath[path] < mtim) // if more recent
        {
            timespecByPath[path] = mtim; // store more recent
        }
    }
    else
    {
        timespecByPath[path] = mtim;
    }
}

void updateRelAbsPaths(Traces& traces,
                       pid_t child,
                       PathUSet& relPaths,
                       PathUSet& absPaths,
                       const Path& path)
{
    if (isAbsolutePath(path))
    {
        absPaths.insert(path);
    }
    else
    {
        const Path absPath = buildAbsPath(traces, child, path);
        if (startsWith(absPath, traces.topCwdPath.c_str()))
        {
            const Path relPath = absPath.substr(traces.topCwdPath.size() + 1,
                                                absPath.size());
            relPaths.insert(relPath);
        }
        else
        {
            absPaths.insert(absPath);
        }
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
        if (show)
        {
            printSyscall(child, syscall_num, retval); fprintf(stderr, " entering...\n");
        }
        // nothing useful to do here for now
    }
    else                        // on call return
    {
        if (show)
        {
            printSyscall(child, syscall_num, retval); fprintf(stderr, " done\n");
        }
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
                    const struct stat stat = ptraceReadStat(child, pidSyscallArg(child, 1));
                    struct timespec mtim = stat.st_mtim; // modification time

                    if (isAbsolutePath(path))
                    {
                        traces.trace1ByPid[child].absStatPaths.insert(path);
                        updateMaxTime(traces.trace1ByPid[child].maxTimespecByStatPath, path, mtim);
                    }
                    else
                    {
                        const Path absPath = buildAbsPath(traces, child, path);
                        if (startsWith(absPath, traces.topCwdPath.c_str()))
                        {
                            const Path relPath = absPath.substr(traces.topCwdPath.size() + 1,
                                                                absPath.size());
                            traces.trace1ByPid[child].relStatPaths.insert(relPath);
                            updateMaxTime(traces.trace1ByPid[child].maxTimespecByStatPath, relPath, mtim);
                        }
                        else
                        {
                            traces.trace1ByPid[child].absStatPaths.insert(absPath);
                            updateMaxTime(traces.trace1ByPid[child].maxTimespecByStatPath, absPath, mtim);
                        }
                    }

                    if (show)
                    {
                        fprintf(stderr, " st_mtime:%ld.%09ld", mtim.tv_sec, mtim.tv_nsec);
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
                    const bool readFlag = (((flags & (O_RDONLY)) ||
                                             (flags & (O_CLOEXEC)) ||
                                             (flags & (O_NOCTTY)) ||
                                             (flags == 0)) &&
                                            (!(flags & O_TRUNC)));

                    // true if this open only writes to file
                    const bool writeFlag = ((flags & (O_WRONLY)) ||
                                             (flags & (O_RDWR |
                                                       O_CREAT |
                                                       O_TRUNC)) ||
                                             (flags & (O_WRONLY |
                                                       O_CREAT |
                                                       O_TRUNC)));

                    // true if this open a file containing executable cod
                    const bool execFlag = flags & O_CLOEXEC;

                    // assure that we decoded correctly
                    assert(readFlag || writeFlag);

                    if (readFlag)
                    {
                        if (execFlag)
                        {
                            traces.trace1ByPid[child].execPaths.insert(path);
                        }
                        else
                        {
                            updateRelAbsPaths(traces,
                                              child,
                                              traces.trace1ByPid[child].relReadPaths,
                                              traces.trace1ByPid[child].absReadPaths,
                                              path);
                        }
                    }

                    if (writeFlag)
                    {
                        updateRelAbsPaths(traces,
                                          child,
                                          traces.trace1ByPid[child].relWritePaths,
                                          traces.trace1ByPid[child].absWritePaths,
                                          path);
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

                            if (readFlag) { fprintf(stderr, " READ"); }
                            if (writeFlag) { fprintf(stderr, " WRITE"); }
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
            else if (syscall_num == SYS_rename) // follow renames
            {
                const Path oldPath = readCxxString(child, pidSyscallArg(child, 0)); // TODO prevent allocation
                const Path newPath = readCxxString(child, pidSyscallArg(child, 1)); // TODO prevent allocation

                const Path oldAbsPath = buildAbsPath(traces, child, oldPath);
                const Path newAbsPath = buildAbsPath(traces, child, newPath);

                auto relWriteOldHit = traces.trace1ByPid[child].relWritePaths.find(oldAbsPath);
                if (relWriteOldHit != traces.trace1ByPid[child].relWritePaths.end()) // if relative hit
                {
                    traces.trace1ByPid[child].relWritePaths.erase(relWriteOldHit);
                    traces.trace1ByPid[child].relWritePaths.insert(newAbsPath);
                }
                else
                {
                    auto absWriteOldHit = traces.trace1ByPid[child].absWritePaths.find(oldAbsPath);
                    if (absWriteOldHit != traces.trace1ByPid[child].absWritePaths.end()) // if absolute hit
                    {
                        traces.trace1ByPid[child].absWritePaths.erase(absWriteOldHit);
                        traces.trace1ByPid[child].absWritePaths.insert(newAbsPath);
                    }
                    else
                    {
                        for (auto const& writePath: traces.trace1ByPid[child].absWritePaths)
                        {
                            fprintf(stderr, "writePath:%s\n", writePath.c_str());
                        }
                        fprintf(stderr,
                                "memoized: warning: TODO handle rename(oldPath:%s, newPath:%s) from childPid:%d\n",
                                oldPath.c_str(),
                                newPath.c_str(),
                                child);
                    }
                }

                if (show)
                {
                    fprintf(stderr,
                            "rename(oldPath:%s, newPath:%s)\n",
                            oldPath.c_str(),
                            newPath.c_str());
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
    char* args[argc+1];
    for (int i = 0; i < argc; i++)
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

std::string execPathOfPid(pid_t pid)
{
    char pathBuf[PATH_MAX];
    char procPathBuf[PATH_MAX];
    snprintf(procPathBuf, sizeof(procPathBuf), "/proc/%d/exe", pid);
    ssize_t count = readlink(procPathBuf, pathBuf, PATH_MAX);
    return std::string(pathBuf, (count > 0) ? count : 0);
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

typedef char SHA256HexCString[2*SHA256_DIGEST_LENGTH + 1];

void SHA256_hashString(const unsigned char hash[SHA256_DIGEST_LENGTH],
                       SHA256HexCString hexCharBuf)
{
    for (uint i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(hexCharBuf + (i * 2), "%02x", hash[i]);
    }
    hexCharBuf[64] = '\0'; // set null terminator
}

/** SHA-256 digest file with path `path` into `hexCharBuf`.
   See also: http://stackoverflow.com/questions/7853156/calculate-sha256-of-a-file-using-openssl-libcrypto-in-c
   */
int SHA256_Digest_File_C(const char* path,
                         SHA256HexCString hexCharBuf)
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

    SHA256_hashString(hash, hexCharBuf);

    fclose(file);
    free(buffer);

    return 0;
}

int SHA256_Digest_File(const Path& path,
                       SHA256HexCString hexCharBuf)
{
    return SHA256_Digest_File_C(path.c_str(), hexCharBuf);
}

/** Compress `sourcePath` to artifact cache if it isn't already that.

    TODO handle abrupt termination by first writing to temporary and then moving it cache atomically
 */
bool assertCompressedToCache(const Traces& traces, const Path& sourcePath)
{
    // fprintf(stderr, "path:%s\n", sourcePath.c_str());

    SHA256HexCString hexCharBuf;
    assert(SHA256_Digest_File(sourcePath, hexCharBuf) >= 0);

    const Path destPath = getArtifactPath(traces, hexCharBuf, "zlib_compressed_data");

    const bool needsWrite = access(destPath.c_str(), F_OK) == -1;
    if (needsWrite)
    {
        if (true)
        {
            fprintf(stderr,
                    "memoized: compressing artifact `%s` to `%s` ... ",
                    sourcePath.c_str(),
                    destPath.c_str());
            fflush(stderr);
        }

        // atomically compress from `sourcePath` to `destPath`

        // create temporary file for output writing
        char tempName[PATH_MAX];
        sprintf(tempName, "/tmp/memoized_artifact_XXXXXX");
        const int tempFd = mkstemp(tempName);
        assert(tempFd != -1);
        FILE* tempFile = fdopen(tempFd, "w");

        // open source
        FILE* source = fopen(sourcePath.c_str(), "r");
        assert(source);

        // compress source to tempfile
        z_compress(source, tempFile, Z_DEFAULT_COMPRESSION); // compress to temporary

        // close temporary before moving it
        assert(fclose(tempFile) == 0); // also closes tempFd

        // atomically move it to artifact cache
        rename(tempName, destPath.c_str());

        // close source
        assert(fclose(source) == 0);

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
    return needsWrite;
}

int fprintFilePathState(FILE* fi,
                        const char* indentation,
                        const Path& path)
{
    struct timespec progModTime = statModTimespec(path); // TODO memoize this call

    SHA256HexCString progHexCharBuf;
    assert(SHA256_Digest_File(path, progHexCharBuf) >= 0); // TODO memoize this call

    return fprintf(fi, "%s%s %ld.%09ld %s\n",
                   indentation,
                   progHexCharBuf,
                   progModTime.tv_sec,
                   progModTime.tv_nsec,
                   path.c_str());
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

        for (uint i = 0; i < sizeof(syscalls)/sizeof(*syscalls); i++)
        {
            struct syscall_entry *ent = &syscalls[i];
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

        assert(argc >= 2);
        traces.topChildExecPath = argv[1]; // TODO lookup absolute path for this
        traces.homePath = getenv("HOME");
        traces.topCwdPath = getCwdPath();

        const int attachRetVal = attachAndPtraceTopChild(traces, topChild);
        if (attachRetVal < 0)
        {
            exit(attachRetVal);
        }

        assertCacheDirTree(traces);

        // TODO calculate chash from `pwd` `argv` and 'env' used in child

        // post process

        // create temporary fingerprint file
        char tempStateName[PATH_MAX];
        sprintf(tempStateName, "/tmp/memoized_state_fingerprint_XXXXXX");
        const int tempStateFd = mkstemp(tempStateName);
        assert(tempStateFd != -1);
        FILE* tempStateFile = fdopen(tempStateFd, "w");

        const char* indentation = "    ";

        bool first = false;

        // collect all paths
        PathOSet allAbsWritePaths;
        PathOSet allAbsReadPaths;
        PathOSet allAbsStatPaths;
        PathOSet allRelWritePaths;
        PathOSet allRelReadPaths;
        PathOSet allRelStatPaths;
        PathOSet allExecPaths;
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
            for (auto const& path : trace1.execPaths)
            {
                allExecPaths.insert(path);
            }
        }

        fprintf(tempStateFile, "executable:\n");
        fprintFilePathState(tempStateFile, indentation, traces.topChildExecPath);

        first = true;
        for (const Path& path : allExecPaths)
        {
            if (isHashableFilePath(path))
            {
                if (first) { fprintf(tempStateFile, "executable reads (libraries):\n"); first = false; }
                fprintFilePathState(tempStateFile, indentation, path);
            }
        }

        fprintf(tempStateFile, "call:\n");
        for (int i = 1; i != argc; ++i) // all but first argument
        {
            fprintf(tempStateFile, "%s%s\n", indentation, argv[i]);
        }

        fprintf(tempStateFile, "cwd: %s\n", traces.topCwdPath.c_str());

        // relative writes
        first = true;
        for (const Path& path : allRelWritePaths)
        {
            if (isHashableFilePath(path))
            {
                assertCompressedToCache(traces, path);
                if (first) { fprintf(tempStateFile, "relative writes:\n"); first = false; }
                fprintFilePathState(tempStateFile, indentation, path);
            }
        }

        // relative reads
        first = true;
        for (const Path& path : allRelReadPaths)
        {
            if (isHashableFilePath(path))
            {
                if (first) { fprintf(tempStateFile, "relative reads:\n"); first = false; }
                fprintFilePathState(tempStateFile, indentation, path);
            }
        }

        // relative stats
        first = true;
        for (auto const& ent : traces.trace1ByPid)
        {
            const Trace1& trace1 = ent.second;
            for (const Path& path : toSortedVector(trace1.relStatPaths))
            {
                if (isHashableFilePath(path))
                {
                    if (first) { fprintf(tempStateFile, "relative stats:\n"); first = false; }
                    fprintf(tempStateFile, "%s%s", indentation, path.c_str());
                    auto hit = trace1.maxTimespecByStatPath.find(Path(path));
                    if (hit != trace1.maxTimespecByStatPath.end()) // if hit
                    {
                        fprintf(tempStateFile,
                                " %ld.%09ld",
                                hit->second.tv_sec,
                                hit->second.tv_nsec);
                    }
                    else
                    {
                        fprintf(stderr, "memoized: warning: TODO stat() file %s again\n", path.c_str());
                    }
                    endl(tempStateFile);
                }
            }
        }

        // absolute writes
        first = true;
        for (const Path& path : allAbsWritePaths)
        {
            if (isHashableFilePath(path))
            {
                assertCompressedToCache(traces, path);
                if (first) { fprintf(tempStateFile, "absolute writes:\n"); first = false; }
                fprintFilePathState(tempStateFile, indentation, path);
            }
        }

        // absolute reads
        first = true;
        for (const Path& path : allAbsReadPaths)
        {
            if (isHashableFilePath(path))
            {
                if (first) { fprintf(tempStateFile, "absolute reads:\n"); first = false; }
                fprintFilePathState(tempStateFile, indentation, path);
            }
        }

        // absolute stats
        first = true;
        for (auto const& ent : traces.trace1ByPid)
        {
            const Trace1& trace1 = ent.second;
            for (const Path& path : toSortedVector(trace1.absStatPaths))
            {
                if (isHashableFilePath(path))
                {
                    if (first) { fprintf(tempStateFile, "absolute stats:\n"); first = false; }
                    fprintf(tempStateFile, "%s%s", indentation, path.c_str());

                    auto hit = trace1.maxTimespecByStatPath.find(path);
                    if (hit != trace1.maxTimespecByStatPath.end()) // if hit
                    {
                        fprintf(tempStateFile,
                                " %ld.%09ld",
                                hit->second.tv_sec,
                                hit->second.tv_nsec);
                    }
                    else
                    {
                        fprintf(stderr, "memoized: warning: TODO stat(\"%s\")\n", path.c_str());
                    }

                    endl(tempStateFile);
                }
            }
        }

        const bool sortedEnv = true;

        fprintf(tempStateFile, "environment:\n");
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
                fprintf(tempStateFile, "%s%s\n", indentation, env[i].c_str());
            }
        }
        else
        {
            for (int i = 0; envp[i]; ++i)
            {
                fprintf(tempStateFile, "%s%s\n", indentation, envp[i]);
            }
        }

        fclose(tempStateFile);

        // atomically move temporary state file to call state path
        SHA256HexCString progHexCharBuf;
        assert(SHA256_Digest_File(traces.topChildExecPath, progHexCharBuf) >= 0); // TODO memoize this call
        const Path tempStateFilePath = (traces.homePath +
                                        "/.cache/memoized/calls/executable_content=SHA256-" +
                                        progHexCharBuf);
        rename(tempStateName, tempStateFilePath.c_str());
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
