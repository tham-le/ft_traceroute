NAME	=	libft.a
CC		=	cc
CFLAGS	=	-Wall -Wextra -Werror

SRC		=	ft_memset.c ft_strlen.c ft_strcmp.c
OBJ		=	$(SRC:.c=.o)

all: $(NAME)

$(NAME):	$(OBJ)
	ar rcs $(NAME) $(OBJ)

%.o: %.c libft.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)

fclean:	clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re
