
NAME	=	ft_traceroute
CC		=	cc
CFLAGS	=	-Wall -Wextra -Werror

SRCDIR	=	src
LIBFT_DIR =	libft
LIBFT	=	$(LIBFT_DIR)/libft.a

SRC		=	main.c traceroute.c args.c net.c packet.c display.c
OBJ		= $(SRC:.c=.o)

all: $(NAME)

$(OBJ): ft_traceroute.h $(LIBFT_DIR)/libft.h

$(NAME):	$(OBJ) $(LIBFT)
	$(CC) $(CFLAGS) $(OBJ) $(LIBFT) -o $(NAME)

$(LIBFT):
	$(MAKE) -C $(LIBFT_DIR)

%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -I . -I $(LIBFT_DIR) -c $< -o $@

clean:
	rm -f $(OBJ)
	$(MAKE) -C $(LIBFT_DIR) clean

fclean:	clean
	rm -f $(NAME)
	$(MAKE) -C $(LIBFT_DIR) fclean

re: fclean all

docker:
	docker build -t ft_traceroute .

docker-shell:
	docker run -it --rm --cap-add=NET_RAW --entrypoint bash ft_traceroute

.PHONY: all clean fclean re docker docker-shell
