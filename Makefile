BIN=how_quic.out
IDIR=./include
SRCDIR=./src
CC=gcc
CFLAGS=-I$(IDIR)
ODIR=obj
LIBS=-lpcap

INCLUDES = $(wildcard include/*.h)
DEPS = $(patsubt %,$(IDIR)/%,$(INCLUDES))

SRC = $(wildcard src/*.c)
_OBJ = $(patsubst src/%.c, %.o, $(SRC))
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: $(SRCDIR)/%.c $(DEPS)
	$(CC) -g -c -o $@ $< $(CFLAGS)
	@echo "Compiled "$<" successfully!"

.PHONY: main.out

$(BIN): $(OBJ)
	$(CC) -g -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean memcheck

memcheck:
	valgrind --show-leak-kinds=all --leak-check=full --track-origins=yes \
	./$(BIN)

clean:
	rm -f $(ODIR)/*.o *.out