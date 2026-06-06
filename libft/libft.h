#ifndef LIBFT_H
#define LIBFT_H

#include <stddef.h>

void   *ft_memset(void *b, int c, size_t len);
void   *ft_memcpy(void *dst, const void *src, size_t n);
size_t  ft_strlen(const char *s);
int     ft_strcmp(const char *s1, const char *s2);
int     ft_atoi(const char *s);
int     ft_strncmp(const char *s1, const char *s2, size_t n);

#endif
