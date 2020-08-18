INCLUDE = ../include

# Compilation flags.
CFLAGS = -std=c11 -Wall -Wextra
CPPFLAGS = -I$(INCLUDE)
DEBUGFLAGS = -g

# Disable implicit rules
.SUFFIXES:

# Special rules and targets.
.PHONY: all clean help

# Rules and targets.
all: simple_find_chunk_keys double_find_chunk_keys
simple: simple_find_chunk_keys
double: double_find_chunk_keys

simple_find_chunk_keys: simple_find_chunk_keys.o tools.o cipher.o key.o
	$(CC) $(CFLAGS) -o $@ $^

double_find_chunk_keys: double_find_chunk_keys.o tools.o cipher.o key.o
	$(CC) $(CFLAGS) -o $@ $^

simple_find_chunk_keys.o: simple_find_chunk_keys.c $(INCLUDE)/tools.h $(INCLUDE)/cipher.h $(INCLUDE)/find_chunk_keys.h  $(INCLUDE)/sbox.h 
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEBUGFLAGS) -c $<

double_find_chunk_keys.o: double_find_chunk_keys.c $(INCLUDE)/tools.h $(INCLUDE)/find_chunk_keys.h $(INCLUDE)/sbox.h $(INCLUDE)/cipher.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEBUGFLAGS) -c $<

tools.o: tools.c $(INCLUDE)/tools.h  $(INCLUDE)/key.h $(INCLUDE)/cipher.h $(INCLUDE)/sbox.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEBUGFLAGS) -c $<

key.o: key.c  $(INCLUDE)/key.h $(INCLUDE)/cipher.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEBUGFLAGS) -c $<

cipher.o: cipher.c $(INCLUDE)/key.h $(INCLUDE)/cipher.h $(INCLUDE)/sbox.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEBUGFLAGS) -c $<

clean:
	rm -f *.o aes_whitebox simple_find_chunk_keys double_find_chunk_keys *~

help:
	@echo "Usage:"
	@echo -e "  make [all]\t\tRun the target dcomputation"
	@echo -e "  make dcomputation\t\tBuild executable dcomputation"
	@echo -e "  make clean\t\tRemove all files produced by the compilation"
	@echo -e "  make help\t\tDisplay this help"
