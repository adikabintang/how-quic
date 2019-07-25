BIN=how_quic.out
CC=gcc
IDIR=./include
SRCDIR=./src
LOG_SOURCE=./third_party/log.c/src
CFLAGS=-I$(IDIR) -I$(LOG_SOURCE)
ODIR=obj
LIBS=-lpcap

DEBUGFLAGS=-O0 -D _DEBUG
RELEASEFLAGS=-O2
TRACEFLAGS=-O0 -D _TRACE

INCLUDES = $(wildcard include/*.h)
DEPS = $(patsubt %,$(IDIR)/%,$(INCLUDES))

SRC = $(wildcard src/*.c)
	
_OBJ = $(patsubst src/%.c, %.o, $(SRC))
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: $(SRCDIR)/%.c $(DEPS)
	mkdir -p $(ODIR)
	$(CC) -g -c -o $@ $< $(CFLAGS) $(RELEASEFLAGS)
	@echo "Compiled "$<" successfully!\n"
	
.PHONY: how_quic.out all clean memcheck

all: $(OBJ) $(ODIR)/log.o
	$(CC) -g -o $(BIN) $^ $(CFLAGS) $(LIBS)

## compiling log.c
$(ODIR)/log.o: $(LOG_SOURCE)/log.c
	$(CC) -g -c -o $@ $< -I$(LOG_SOURCE) -DLOG_USE_COLOR $(RELEASEFLAGS)
	@echo "Compiled "$<" successfully!\n"
## end of compiling log.

memcheck:
	valgrind --show-leak-kinds=all --leak-check=full --track-origins=yes \
	./$(BIN)

clean:
	rm -f $(ODIR)/*.o *.out