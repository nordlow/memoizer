module syscalls;

enum SYSCALL_MAXARGS = 6;

enum Arg
{
    INT,
    PTR,
    STR
}

struct syscall_entry
{
    string name;
    uint nargs;
    Arg[SYSCALL_MAXARGS] args;
}
