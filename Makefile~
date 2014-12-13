CC=gcc
LPCAP=-lpcap
LPTHREAD=-lpthread

SRC=portScanner.c ps_setup.c ps_lib.c
OBJ=$(SRC:.c=.o)
BIN=portScanner

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LPCAP) $(LPTHREAD) -g -o $(BIN) $(OBJ)


%.o:%.c
	$(CC) -c $(LPCAP) $(LPTHREAD) -g -o $@ $<

$(SRC):

clean:
	rm -rf $(OBJ) $(BIN)
