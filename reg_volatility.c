#include <stdio.h>
#include <stdlib.h>

int function() {
    printf("I don't use anything but eh ! \\o/\n");
}

int main(int argc, char** argv) {

    printf("argc: %d, argv: %p\n", argc, argv);
    function();

    return 0;
}
