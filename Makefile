
NAME	=	ft_traceroute
CC		=	cc
CFLAGS	=	-Wall -Wextra -Werror

LIBFT_DIR =	libft
LIBFT	=	$(LIBFT_DIR)/libft.a

SRC		=	main.c traceroute.c args.c
OBJ		= $(SRC:.c=.o)

all: $(NAME)

$(NAME):	$(OBJ) $(LIBFT)
	$(CC) $(CFLAGS) $(OBJ) $(LIBFT) -o $(NAME)

$(LIBFT):
	$(MAKE) -C $(LIBFT_DIR)

%.o: %.c
	$(CC) $(CFLAGS) -I $(LIBFT_DIR) -c $< -o $@

clean:
	rm -f $(OBJ)
	$(MAKE) -C $(LIBFT_DIR) clean

fclean:	clean
	rm -f $(NAME)
	$(MAKE) -C $(LIBFT_DIR) fclean

re: fclean all

.PHONY: all clean fclean re
