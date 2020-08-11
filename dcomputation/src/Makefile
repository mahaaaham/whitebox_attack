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
all: dcomputation

dcomputation: dcomputation.o
	$(CC) $(CFLAGS) -o $@ $^

dcomputation.o: dcomputation.c $(INCLUDE)/dcomputation.h 
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEBUGFLAGS) -c $<

clean:
	rm -f *.o dcomputation *~

help:
	@echo "Usage:"
	@echo -e "  make [all]\t\tRun the target dcomputation"
	@echo -e "  make dcomputation\t\tBuild executable dcomputation"
	@echo -e "  make clean\t\tRemove all files produced by the compilation"
	@echo -e "  make help\t\tDisplay this help"
