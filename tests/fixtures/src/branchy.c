#include <stdio.h>

/* if/else chains, loop with back-edge, switch (jump table at -O2) */

int classify(int x) {
    if (x < 0) {
        return -1;
    } else if (x == 0) {
        return 0;
    }
    return 1;
}

int sum_to(int n) {
    int s = 0;
    for (int i = 0; i < n; i++) {
        s += i;
    }
    return s;
}

static volatile int sink;

int dispatch(int code) {
    /* distinct side effects per case so -O2 must emit a real jump table
       (a table of code pointers, not a folded value lookup) */
    switch (code) {
    case 0: sink += 1; return 100;
    case 1: sink ^= 0x5a; return -3;
    case 2: sink *= 3; return 7777;
    case 3: sink -= 9; return 42;
    case 4: sink |= 0x100; return -999;
    case 5: sink += code * 2; return 65536;
    case 6: sink = ~sink; return 7;
    case 7: sink /= 2; return 31337;
    default: return -1;
    }
}

int fib(int n) {
    if (n < 2) return n;
    return fib(n - 1) + fib(n - 2);
}

int main(void) {
    printf("%d %d %d %d\n", classify(-5), sum_to(10), dispatch(3), fib(10));
    return 0;
}
