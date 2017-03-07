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
    const int new_fd = open("test_output", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    assert(new_fd);
    assert(close(new_fd) >= 0);

    const int main_fd = open("main.cpp", O_RDONLY);
    assert(main_fd);
    assert(close(main_fd) >= 0);

    chdir("/etc");

    struct stat st;
    assert(stat("passwd", &st) == 0);

    const int passwd_fd = open("passwd", O_RDONLY);
    assert(passwd_fd);
    assert(close(passwd_fd) >= 0);

    printf("All ok!\n");

    return 0;
}
