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
all: exhaustive_search_key

exhaustive_search_key:  exhaustive_search_key.o key.o cipher.o tools.o
	$(CC) $(CFLAGS) -o $@ $^

exhaustive_search_key.o: exhaustive_search_key.c $(INCLUDE)/state.h $(INCLUDE)/define.h $(INCLUDE)/cipher.h $(INCLUDE)/key.h $(INCLUDE)/sbox.h $(INCLUDE)/tools.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEBUGFLAGS) -c $<

key.o: key.c $(INCLUDE)/state.h $(INCLUDE)/key.h $(INCLUDE)/cipher.h $(INCLUDE)/tools.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEBUGFLAGS) -c $<

cipher.o: cipher.c $(INCLUDE)/state.h $(INCLUDE)/key.h $(INCLUDE)/cipher.h $(INCLUDE)/sbox.h  $(INCLUDE)/tools.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEBUGFLAGS) -c $<

tools.o: tools.c $(INCLUDE)/tools.h  $(INCLUDE)/key.h $(INCLUDE)/cipher.h $(INCLUDE)/sbox.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEBUGFLAGS) -c $<

clean:
	rm -f *.o exhaustive_search_key  *~

help:
	@echo "Usage:"
	@echo -e "  make [all]\t\tRun the target dcomputation"
	@echo -e "  make dcomputation\t\tBuild executable dcomputation"
	@echo -e "  make clean\t\tRemove all files produced by the compilation"
	@echo -e "  make help\t\tDisplay this help"
