#include <stdio.h>

int main(void) {
#if !defined(__STDC_VERSION__)
    printf("C Standard: C89 / C90 (or K&R)\n");
#elif __STDC_VERSION__ == 199409L
    printf("C Standard: C94 / C95\n");
#elif __STDC_VERSION__ == 199901L
    printf("C Standard: C99\n");
#elif __STDC_VERSION__ == 201112L
    printf("C Standard: C11\n");
#elif __STDC_VERSION__ == 201710L
    printf("C Standard: C17 / C18\n");
#elif __STDC_VERSION__ >= 202311L
    printf("C Standard: C23 (macro: %ldL)\n", __STDC_VERSION__);
#else
    printf("C Standard: Custom or newer (__STDC_VERSION__ = %ldL)\n", __STDC_VERSION__);
#endif
    return 0;
}
