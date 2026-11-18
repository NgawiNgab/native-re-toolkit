#include <stdio.h>

/* UTF-16LE and UTF-16BE strings as explicit byte arrays. */
__attribute__((used)) static const char wide_le[] = {
    'H', 0, 'e', 0, 'l', 0, 'l', 0, 'o', 0,
    ' ', 0, 'W', 0, 'i', 0, 'd', 0, 'e', 0, 0, 0,
};

__attribute__((used)) static const char wide_be[] = {
    0, 'W', 0, 'i', 0, 'd', 0, 'e', 0, 'B', 0, 'E', 0, '!', 0, 0,
};

__attribute__((used)) static const char plain_ascii[] = "plain ascii marker string";

int main(void) {
    printf("%zu %zu %s\n", sizeof(wide_le), sizeof(wide_be), plain_ascii);
    return 0;
}
