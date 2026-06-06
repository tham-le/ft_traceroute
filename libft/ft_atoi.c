#include "libft.h"

int ft_atoi(const char *s) {
    long val  = 0;
    int  sign = 1;

    while (*s == ' ' || (*s >= '\t' && *s <= '\r'))
        s++;
    if (*s == '-' || *s == '+')
        sign = (*s++ == '-') ? -1 : 1;
    while (*s >= '0' && *s <= '9')
        val = val * 10 + (*s++ - '0');
    return (int)(val * sign);
}
