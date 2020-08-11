INCLUDE = include
SRC = src

# Disable built-in rules
.SUFFIXES:

# Special rules and targets
.PHONY: all build clean help

# Rules and targets
all: build

attack:  
	$(MAKE) -C $(SRC) attack
	cp $(SRC)/attack_aes_whitebox attack_aes_whitebox

build:
	$(MAKE) -C $(SRC) all
	cp $(SRC)/aes_whitebox aes_whitebox
	cp $(SRC)/attack_aes_whitebox attack_aes_whitebox

clean:
	rm -f aes_whitebox attack_aes_whitebox *~
	cd $(INCLUDE) && rm -f *~
	$(MAKE) -C $(SRC) clean

help:
	@echo "Usage:"
	@echo -e "  make [all]\t\tRun the target build"
	@echo -e "  make build\t\tBuild executable aes"
	@echo -e "  make clean\t\tRemove all files produced by the compilation"
	@echo -e "  make help\t\tDisplay this help"
