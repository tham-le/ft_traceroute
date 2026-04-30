
NAME	=	ft_traceroute
CC		=	cc
CFLAGS	=	-Wall -Wextra -Werror

SRC		=	main.c traceroute.c args.c
OBJ		= $(SRC:.c=.o)

all: $(NAME)

$(NAME):	$(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(NAME)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)

fclean:	clean
	rm -f $(NAME)

re: fclean all
