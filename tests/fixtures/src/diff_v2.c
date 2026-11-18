#include <stdio.h>

int compute(int x) {
    /* changed implementation: extra operation */
    int y = x * 2 + 1;
    return y ^ 0x5a;
}

int helper(int x) {
    return x - 7;
}

int new_feature(int x) {
    return x * x + 3;
}

int main(void) {
    printf("v2: %d %d %d\n", compute(3), helper(20), new_feature(5));
    return 0;
}
