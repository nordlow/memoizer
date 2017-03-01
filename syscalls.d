enum SYSCALL_MAXARGS = 6;

enum argtype
{
    ARG_INT,
    ARG_PTR,
    ARG_STR
}

struct syscall_entry
{
    string name;
    int nargs;
    argtype[SYSCALL_MAXARGS] args;
}
