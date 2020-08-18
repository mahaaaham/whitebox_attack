#ifndef TOOLS_H
#define TOOLS_H

#include <stdint.h>

uint8_t compute_difference (uint8_t state, uint8_t mod_state, uint8_t chunk_last_round_key);

void read_from_file (char *input_file, uint8_t *buffer);

void print_state(uint8_t state[4][4]);

void print_column(uint8_t column[4]);

void print_key(uint8_t key[16]);

uint8_t random_byte ();

#endif /* TOOLS */
