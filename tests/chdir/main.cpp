#include <iostream>
#include <string>
#include <cassert>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

using std::cout;
using std::endl;
using std::hex;
using std::dec;

int main(int argc, const char * argv[], const char * envp[])
{
    chdir("/etc");

    struct stat st;
    assert(stat("passwd", &st) == 0);

    std::cout << "All ok!" << endl;

    return 0;
}
