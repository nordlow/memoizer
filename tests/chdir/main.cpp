#include <iostream>
#include <string>
#include <cassert>
#include <cstdio>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

using std::cout;
using std::endl;
using std::hex;
using std::dec;

int main(int argc, const char * argv[], const char * envp[])
{
    chdir("/etc");

    struct stat st;
    assert(stat("passwd", &st) == 0);

    const int fd = open("passwd", O_RDONLY);
    assert(fd);

    printf("All ok!\n");

    return 0;
}
