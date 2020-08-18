#include "cipher.h"

#include <stdlib.h>
#include <stdio.h>

#define NB 4
#define NK 4
#define WORD 4
#define NR 10

#define SHIFT_ROW(state) { \
  uint8_t tmp; \
  /* Row 1: shift left once */ \
  tmp = state[1][0]; \
  state[1][0] = state[1][1]; \
  state[1][1] = state[1][2]; \
  state[1][2] = state[1][3]; \
  state[1][3] = tmp; \
  /* Row 2: shift left twice */ \
  tmp = state[2][0]; \
  state[2][0] = state[2][2]; \
  state[2][2] = tmp; \
  tmp = state[2][1]; \
  state[2][1] = state[2][3]; \
  state[2][3] = tmp; \
  /* Row 3: shift left 3 times */\
  tmp = state[3][0];\
  state[3][0] = state[3][3];\
  state[3][3] = state[3][2];\
  state[3][2] = state[3][1];\
  state[3][1] = tmp;\
}



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
old_mix_columns (uint8_t state[4][4])
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
mix_columns(uint8_t state[4][4]) 
{
    unsigned char r[4][4];
    for (int i = 0; i <4; i++)
      for (int j = 0; j <4; j++)
	r[i][j] = (unsigned char)state[i][j];

    unsigned char a[4];
    unsigned char b[4];
    unsigned char h;

    /* The array 'a' is simply a copy of the input array 'r'

     * The array 'b' is each element of the array 'a' multiplied by 2

     * in Rijndael's Galois field

     * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */

    for (int i = 0; i<4; i++)
      {
	for (char c = 0; c < 4; c++) 
	  {
	    a[c] = r[c][i];
	    /* h is 0xff if the high bit of r[c] is set, 0 otherwise */
	    h = (unsigned char)((signed char)r[c][i] >> 7); /* arithmetic right shift, thus shifting in either zeros or ones */
	    b[c] = r[c][i] << 1; /* implicitly removes high bit because b[c] is an 8-bit char, so we xor by 0x1b and not 0x11b in the next line */
	    b[c] ^= 0x1B & h; /* Rijndael's Galois field */
	  }

	r[0][i] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; /* 2 * a0 + a3 + a2 + 3 * a1 */
	r[1][i] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; /* 2 * a1 + a0 + a3 + 3 * a2 */
	r[2][i] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; /* 2 * a2 + a1 + a0 + 3 * a3 */
	r[3][i] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; /* 2 * a3 + a2 + a1 + 3 * a0 */
      }

  for (int i = 0; i <4; i++)
    for (int j = 0; j <4; j++)
      state[i][j] = (uint8_t )r[i][j];

  return;
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

      /* subbyte */
      for (int i = 0; i < 4; ++i)
	for (int j = 0; j < NB; ++j)
	  state[i][j] = sbox[state[i][j]];


      SHIFT_ROW (state);
      mix_columns (state);
      /* addroundkey */
      for (int j = 0; j < NB; ++j)
	for (int i = 0; i < 4; ++i)
	  state[i][j] ^= key_schedule[round * WORD * NK + 4 * j + i];


    }

  /* subbyte */
  for (int i = 0; i < 4; ++i)
    for (int j = 0; j < NB; ++j)
      state[i][j] = sbox[state[i][j]];
  sub_bytes (state);
  SHIFT_ROW (state);
  /* addroundkey */
  for (int j = 0; j < NB; ++j)
    for (int i = 0; i < 4; ++i)
      state[i][j] ^= key_schedule[10 * WORD * NK + 4 * j + i];
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

int test_mix_column ()
{
  uint8_t old_state[4][4] = {{219, 219, 219, 219} ,{19, 19 ,19 ,19} , {83, 83, 83, 83}, {69, 69, 69, 69}};
  uint8_t state[4][4] = {{219, 219, 219, 219} ,{19, 19 ,19 ,19} , {83, 83, 83, 83}, {69, 69, 69, 69}};

  old_mix_columns (old_state);
  mix_columns (state);

  for (int i = 0; i<4; i++)
    for (int j = 0; j<4; j++)
      {
	if (old_state[i][j] != state[i][j])
	  {
	    fprintf(stderr, "MIX COLUMNS TEST FAILED");
	  }
      }

  fprintf(stderr, "\nOLD STATE AFTER MIX\n");
  for (int i = 0; i<4; i++)
    {
      fprintf(stderr, "%d", old_state[i][0]);
    }
  fprintf(stderr, "\nSTATE AFTER MIX\n");
  for (int i = 0; i<4; i++)
    {
      fprintf(stderr, "%d", state[i][0]);
    }


  fprintf(stderr, "MIX COLUMNS TEST SUCCEED");
   return EXIT_SUCCESS;
}
