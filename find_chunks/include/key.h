#ifndef KEY_H
#define KEY_H

#include <stdint.h>
#include <stdio.h>

void key_free (uint8_t *key);

/* Reads up to 4 * NB bytes from 'key_file' and stores them in 'key'.
 * Memory for 'key' is supposed to have already been allocated.
 * 'key_file' is supposed to be open.
 * Returns the number of bytes read or -1 if a non hexa digit is detected. */
int key_read (uint8_t *key, FILE *key_file);

/* Implementation of the key expansion routine from the aes algorithm.
 * Generates the key schedule (both memory allocation and filling).
 * Returns a pointer to it or NULL if the allocation fails. */
void key_expansion (uint8_t key[16], uint8_t key_schedule[16 * 11]);

/* Implementation of the rot_word subroutine from the aes algorithm */
void rot_word (uint8_t *word);

/* Implementation of the sub_word subroutine from the aes algorithm */
void sub_word (uint8_t *word);  

void inv_key_expansion (uint8_t key[16], uint8_t last_key[16]);

void test_inv_key_expansion();

#endif /* KEY_H */
