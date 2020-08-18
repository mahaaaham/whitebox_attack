#include "cipher.h"

#include <stdlib.h>
#include <stdio.h>

#define NB 4
#define NK 4
#define WORD 4
#define NR 10

/* Implementation of the add_round_key subroutine from the aes algorithm */
void
add_round_key (uint8_t state[4][4], uint8_t key_schedule[16 * 11], size_t round)
{
  for (int j = 0; j < NB; ++j)
    for (int i = 0; i < 4; ++i)
      state[i][j] ^= key_schedule[round * WORD * NK + 4 * j + i];
  
}


/* Implementation of the sub_bytes subroutine from the aes algorithm */
void
sub_bytes (uint8_t state[4][4])
{
  for (int i = 0; i < 4; ++i)
    for (int j = 0; j < NB; ++j)
      state[i][j] = sbox[state[i][j]];
  
}


/* Implementation of the inv_sub_bytes subroutine from the aes algorithm */
void
inv_sub_bytes (uint8_t state[4][4])
{
  for (int i = 0; i < 4; ++i)
    for (int j = 0; j < NB; ++j)
      state[i][j] = inv_sbox[state[i][j]];
  
}


/* Implementation of the shift_row subroutine from the aes algorithm */
void
shift_row (uint8_t state[4][4])
{
  uint8_t tmp;

  /* Row 1: shift left once */
  tmp = state[1][0];
  state[1][0] = state[1][1];
  state[1][1] = state[1][2];
  state[1][2] = state[1][3];
  state[1][3] = tmp;

  /* Row 2: shift left twice */
  tmp = state[2][0];
  state[2][0] = state[2][2];
  state[2][2] = tmp;
  tmp = state[2][1];
  state[2][1] = state[2][3];
  state[2][3] = tmp;

  /* Row 3: shift left 3 times */
  tmp = state[3][0];
  state[3][0] = state[3][3];
  state[3][3] = state[3][2];
  state[3][2] = state[3][1];
  state[3][1] = tmp;

}


/* Implementation of the inv_shift_row subroutine from the aes algorithm */
void
inv_shift_row (uint8_t state[4][4])
{
  uint8_t tmp;

  /* Row 1: shift right once */
  tmp = state[1][0];
  state[1][0] = state[1][3];
  state[1][3] = state[1][2];
  state[1][2] = state[1][1];
  state[1][1] = tmp;

  /* Row 2: shift right twice */
  tmp = state[2][0];
  state[2][0] = state[2][2];
  state[2][2] = tmp;
  tmp = state[2][1];
  state[2][1] = state[2][3];
  state[2][3] = tmp;

  /* Row 3: shift right 3 times */
  tmp = state[3][0];
  state[3][0] = state[3][1];
  state[3][1] = state[3][2];
  state[3][2] = state[3][3];
  state[3][3] = tmp;

}


/* Thanks to wikipedia "Finite Field Arithmetic" article */
uint8_t
rijndael_mult (uint8_t a, uint8_t b)
{
  uint8_t p = 0;
  
  while (a && b) 
    {
      if (b & 1) 
	p ^= a;
      
      /* GF modulo:
       * if a >= 128, then it will overflow when shifted left, so reduce */
      if (a & 0x80) 
	a = (a << 1) ^ 0x11b; /* XOR with the primitive polynomial 
			       * x^8 + x^4 + x^3 + x + 1 (0b1_0001_1011) */
      else
	a <<= 1; /* equivalent to a * 2 */
      
      b >>= 1; /* equivalent to b // 2 */
    }
  
  return p;
}


void
mix_columns (uint8_t state[4][4])
{
  for (int c = 0; c < 4; ++c)
    {
      uint8_t s0 = rijndael_mult (0x02, state[0][c])
	^ rijndael_mult (0x03, state[1][c])
	^ state[2][c]
	^ state[3][c];
      uint8_t s1 = state[0][c]
	^ rijndael_mult (0x02, state[1][c])
	^ rijndael_mult (0x03, state[2][c])
	^ state[3][c];
      uint8_t s2 = state[0][c]
	^ state[1][c]
	^ rijndael_mult (0x02, state[2][c])
	^ rijndael_mult (0x03, state[3][c]);
      uint8_t s3 = rijndael_mult (0x03, state[0][c]) 
	^ state[1][c]
	^ state[2][c] 
	^ rijndael_mult (0x02, state[3][c]);

      state[0][c] = s0;
      state[1][c] = s1;
      state[2][c] = s2;
      state[3][c] = s3;
    }
  
}


void 
inv_mix_columns (uint8_t state[4][4])
{
  for (int c = 0; c < 4; ++c)
    {
      uint8_t s0 = rijndael_mult (0x0e, state[0][c])
	^ rijndael_mult (0x0b, state[1][c]) 
	^ rijndael_mult (0x0d, state[2][c]) 
	^ rijndael_mult (0x09, state[3][c]);
      uint8_t s1 = rijndael_mult (0x09, state[0][c])
	^ rijndael_mult (0x0e, state[1][c]) 
	^ rijndael_mult (0x0b, state[2][c]) 
	^ rijndael_mult (0x0d, state[3][c]);
      uint8_t s2 = rijndael_mult (0x0d, state[0][c])
	^ rijndael_mult (0x09, state[1][c])
	^ rijndael_mult (0x0e, state[2][c])
	^ rijndael_mult (0x0b, state[3][c]);
      uint8_t s3 = rijndael_mult (0x0b, state[0][c])
	^ rijndael_mult (0x0d, state[1][c])
	^ rijndael_mult (0x09, state[2][c])
	^ rijndael_mult (0x0e, state[3][c]);

      state[0][c] = s0;
      state[1][c] = s1;
      state[2][c] = s2;
      state[3][c] = s3;
    }

}


void
cipher (uint8_t state[4][4], uint8_t input[4][4], uint8_t key_schedule[16 * 11])
{
  /* Initialisation of the state */
  for (int i = 0; i < 4; ++i)
    for (int j = 0; j < 4; ++j)
      state[i][j] = input[i][j];
  

  /* Start enciphering */
  add_round_key (state, key_schedule, 0);

  for (int round = 1; round < 10; ++round)
    {

      sub_bytes (state);
      shift_row (state);
      mix_columns (state);
      add_round_key (state, key_schedule, round);
    }

  sub_bytes (state);
  shift_row (state);
  add_round_key (state, key_schedule, 10);
}


void
inv_cipher (uint8_t state[4][4], uint8_t input[4][4], uint8_t key_schedule[16 * 11])
{
  /* Initialisation of the state */
  for (int i = 0; i < 4; ++i)
    for (int j = 0; j < NB; ++j)
      state[i][j] = input[i][j];

  /* Start deciphering */
  add_round_key (state, key_schedule, NR);

  for (int round = NR - 1; round > 0; --round)
    {
      
      inv_shift_row (state);
      inv_sub_bytes (state);
      add_round_key (state, key_schedule, round);
      inv_mix_columns (state);
    }


  inv_shift_row (state);
  inv_sub_bytes (state);
  add_round_key (state, key_schedule, 0);
}
