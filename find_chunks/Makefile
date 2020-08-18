INCLUDE = include
SRC = src

# Disable built-in rules
.SUFFIXES:

# Special rules and targets
.PHONY: all build clean help

# Rules and targets
all: build

simple:  
	$(MAKE) -C $(SRC) simple
	cp $(SRC)/simple_find_chunk_keys  simple_find_chunk_keys

double:  
	$(MAKE) -C $(SRC) double
	cp $(SRC)/double_find_chunk_keys  double_find_chunk_keys

build:
	$(MAKE) -C $(SRC) all
	cp $(SRC)/double_find_chunk_keys  double_find_chunk_keys
	cp $(SRC)/simple_find_chunk_keys  simple_find_chunk_keys

clean:
	rm -f aes_whitebox double_find_chunk_key simple_find_chunk_keys find_key *~
	cd $(INCLUDE) && rm -f *~
	$(MAKE) -C $(SRC) clean

help:
	@echo "Usage:"
	@echo -e "  make [all]\t\tRun the target build"
	@echo -e "  make build\t\tBuild executable aes"
	@echo -e "  make clean\t\tRemove all files produced by the compilation"
	@echo -e "  make help\t\tDisplay this help"
