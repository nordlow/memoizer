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

    printf("All ok!\n");

    int fd = open("passwd", 0777);
    assert(fd);

    return 0;
}
