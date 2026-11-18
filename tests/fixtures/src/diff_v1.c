#include <stdio.h>

int compute(int x) {
    return x * 2 + 1;
}

int helper(int x) {
    return x - 7;
}

int legacy_func(int x) {
    return x ^ 0x1234;
}

int main(void) {
    printf("v1: %d %d %d\n", compute(3), helper(20), legacy_func(5));
    return 0;
}
