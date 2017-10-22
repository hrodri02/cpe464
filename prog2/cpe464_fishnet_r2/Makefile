CC =  gcc
CFLAGS = -Wall -Werror -g

all: fishnode-Linux-i686

fishnode-Linux-i686: goldentrout.o fishnode.o libfish-Linux-x86_64.a
	$(CC) $(CFLAGS) goldentrout.o fishnode.o -o $@ libfish-Linux-x86_64.a

goldentrout.o: goldentrout.c
	$(CC) $(CFLAGS) -c goldentrout.c

fishnode.o: fishnode.c
	$(CC) $(CFLAGS) -c fishnode.c

handin: README
	handin bellardo 464_p2 fish.h libfish-Linux-x86_64.a fishnode.h fishnode.c README Makefile smartalloc.h smartalloc.c goldentrout.c

clean:
	rm *.o fishnode-Linux-i686 
