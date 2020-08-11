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
all: aes_whitebox attack_aes_whitebox

attack: attack_aes_whitebox

aes_whitebox: aes_whitebox.o
	$(CC) $(CFLAGS) -o $@ $^

aes_whitebox.o: aes_whitebox.c $(INCLUDE)/aes_whitebox.h $(INCLUDE)/sbox.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEBUGFLAGS) -c $<

attack_aes_whitebox: attack_aes_whitebox.o
	$(CC) $(CFLAGS) -o $@ $^

attack_aes_whitebox.o: attack_aes_whitebox.c $(INCLUDE)/tools_attack.h $(INCLUDE)/attack_aes_whitebox.h 
	$(CC) $(CFLAGS) $(CPPFLAGS) $(DEBUGFLAGS) -c $<

clean:
	rm -f *.o aes_whitebox attack_aes_whitebox *~

help:
	@echo "Usage:"
	@echo -e "  make [all]\t\tRun the target dcomputation"
	@echo -e "  make dcomputation\t\tBuild executable dcomputation"
	@echo -e "  make clean\t\tRemove all files produced by the compilation"
	@echo -e "  make help\t\tDisplay this help"
