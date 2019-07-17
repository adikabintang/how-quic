BIN=how_quic.out
CC=gcc
IDIR=./include
SRCDIR=./src
LOG_SOURCE=./third_party/log.c/src
CFLAGS=-I$(IDIR) -I$(LOG_SOURCE)
ODIR=obj
LIBS=-lpcap

INCLUDES = $(wildcard include/*.h)
DEPS = $(patsubt %,$(IDIR)/%,$(INCLUDES))

SRC = $(wildcard src/*.c)
	
_OBJ = $(patsubst src/%.c, %.o, $(SRC))
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: $(SRCDIR)/%.c $(DEPS)
	mkdir -p $(ODIR)
	$(CC) -g -c -o $@ $< $(CFLAGS)
	@echo "Compiled "$<" successfully!\n"
	
.PHONY: main.out all

all: $(OBJ) $(ODIR)/log.o
	$(CC) -g -o $(BIN) $^ $(CFLAGS) $(LIBS)

## compiling log.c
$(ODIR)/log.o: $(LOG_SOURCE)/log.c
	$(CC) -g -c -o $@ $< -I$(LOG_SOURCE) -DLOG_USE_COLOR
	@echo "Compiled "$<" successfully!\n"
## end of compiling log.


.PHONY: clean memcheck

memcheck:
	valgrind --show-leak-kinds=all --leak-check=full --track-origins=yes \
	./$(BIN)

clean:
	rm -f $(ODIR)/*.o *.out