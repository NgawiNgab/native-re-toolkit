#include <stdio.h>

static int call_counter = 0;

int add(int a, int b) {
    call_counter++;
    return a + b;
}

static int mul(int a, int b) {
    call_counter++;
    return a * b;
}

/* stack buffer -> forces stack canary with -fstack-protector-all */
int vulnerable_copy(const char *s) {
    char buf[64];
    int i = 0;
    while (s[i] && i < 63) {
        buf[i] = s[i];
        i++;
    }
    buf[i] = 0;
    return i;
}

int main(void) {
    int x = add(2, 3);
    int y = mul(4, 5);
    char msg[16];
    vulnerable_copy("hi");
    snprintf(msg, sizeof(msg), "n=%d", x);
    printf("Hello, %d %d\n", x, y);
    return 0;
}
