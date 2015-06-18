TARGETS = hsts-check
OBJ = hsts-check.o
CC = gcc
CFLAGS = -Wall -g
LIBS = -lssl

all: $(TARGETS)

hsts-check: $(OBJ)
	$(CC) -o $@ $(OBJ) $(LIBS)

clean:
	rm -f $(TARGETS)
	rm -f *.o
	rm -f core *.core
