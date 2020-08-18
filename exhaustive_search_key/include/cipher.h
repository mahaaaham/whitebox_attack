#ifndef CIPHER_H
#define CIPHER_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>


extern bool verbose;

extern const uint8_t sbox[256];
extern const uint8_t inv_sbox[256];


/* Implementation of the add_round_key subroutine from the aes algorithm */
void
add_round_key (uint8_t state[4][4], uint8_t key_schedule[16 * 11], size_t round);

/* Implementation of the sub_bytes subroutine from the aes algorithm */
void
sub_bytes (uint8_t state[4][4]);

/* Implementation of the inv_sub_bytes subroutine from the aes algorithm */
void
inv_sub_bytes (uint8_t state[4][4]);

/* Implementation of the shift_row subroutine from the aes algorithm */
void shift_row (uint8_t state[4][4]);

/* Implementation of the inv_shift_row subroutine from the aes algorithm */
void inv_shift_row (uint8_t state[4][4]);

/* Rijndael field multiplication */
uint8_t rijndael_mult(uint8_t a, uint8_t b);

/* Implementation of the mix_columns subroutine from the aes algorithm */
void mix_columns (uint8_t state[4][4]);

/* Implementation of the inv_mix_columns subroutine from the aes algorithm */
void inv_mix_columns (uint8_t state[4][4]);

/* Aes cipher.
 * Returns in the state the input enciphered with the key_schedule. */
void cipher (uint8_t state[4][4], uint8_t input[4][4], uint8_t key_schedule[16 * 11]);

/* Aes inverse cipher.
 * Returns in the state the input deciphered with the key_schedule. */
void inv_cipher (uint8_t state[4][4], uint8_t input[4][4], uint8_t key_schedule[16 * 11]);


#endif /* CIPHER_H */
