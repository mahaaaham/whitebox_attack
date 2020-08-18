#include "key.h"

#include <stdlib.h>
#include <ctype.h>


/* rcon[0] isn't used */
static const uint8_t rcon[11] = 
  { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };


void
rot_word (uint8_t *word)
{
  uint8_t tmp = word[0];
  
  word[0] = word[1];
  word[1] = word[2];
  word[2] = word[3];
  word[3] = tmp;
}

void
inv_rot_word (uint8_t *word)
{
  uint8_t tmp = word[2];
  
  word[2] = word[1];
  word[1] = word[0];
  word[0] = word[3];
  word[3] = tmp;
}

void
sub_word (uint8_t *word)
{
  word[0] = sbox[word[0]];
  word[1] = sbox[word[1]];
  word[2] = sbox[word[2]];
  word[3] = sbox[word[3]];

}
void
inv_sub_word (uint8_t *word)
{
  word[0] = inv_sbox[word[0]];
  word[1] = inv_sbox[word[1]];
  word[2] = inv_sbox[word[2]];
  word[3] = inv_sbox[word[3]];
}

  


/* Frees the key */
void
key_free (uint8_t *key)
{
  free (key);
}


/* Reads up to 4 * NB bytes from 'key_file' and stores them in 'key'.
 * Memory for 'key' is supposed to have already been allocated.
 * 'key_file' is supposed to be open.
 * Returns the number of bytes read or -1 if a non hexa digit is detected. */
int
key_read (uint8_t *key, FILE *key_file)
{
  int ch1, ch2;
  int cnt = 0; /* Number of bytes read so far */

  do
    {
      do
	ch1 = fgetc (key_file);
      while isspace (ch1);

      if (ch1 == EOF)
	break;

      if ((ch1 < '0') || (('9' < ch1) && (ch1 < 'A'))
	  || (('F' < ch1) && (ch1 < 'a')) || ('f' < ch1))
	return -1;
      
      do
	ch2 = fgetc (key_file);
      while isspace (ch2);

      if ((ch2 < '0') || (('9' < ch2) && (ch2 < 'A'))
	  || (('F' < ch2) && (ch2 < 'a')) || ('f' < ch2))
	return -1;

      key[cnt] = (((ch1 % 32) + 9) % 25) * 16 + ((ch2 % 32) + 9) % 25;
    }
  while (++cnt < 4 * NB);
    
  return cnt;
}


void
key_expansion (uint8_t key[16], uint8_t key_schedule[16 * 11])
{
  uint8_t tmp[4];
  int i = 0;
  while (i < NK)
    {
      key_schedule [i * WORD] = key [i * WORD];
      key_schedule [i * WORD + 1] = key [i * WORD + 1];
      key_schedule [i * WORD + 2] = key [i * WORD + 2];
      key_schedule [i * WORD + 3] = key [i * WORD + 3];
      ++i;
    }

  while (i < NB * (NR + 1))
    {
      tmp[0] = key_schedule [i * WORD - 4];
      tmp[1] = key_schedule [i * WORD - 3];
      tmp[2] = key_schedule [i * WORD - 2];
      tmp[3] = key_schedule [i * WORD - 1];
      if (i % NK == 0)
	{
	  rot_word (tmp);
	  sub_word (tmp); 
	  tmp[0] ^= rcon[(i) / NK];
	}
      key_schedule [i * WORD ] = key_schedule [(i - NK) * WORD] ^ tmp[0];
      key_schedule [i * WORD + 1] = key_schedule [(i - NK) * WORD + 1] ^ tmp[1];
      key_schedule [i * WORD + 2] = key_schedule [(i - NK) * WORD + 2] ^ tmp[2];
      key_schedule [i * WORD + 3] = key_schedule [(i - NK) * WORD + 3] ^ tmp[3];
      ++i;
    }
}


void
inv_key_expansion (uint8_t key[16], uint8_t last_key[16])
{
  uint8_t key_schedule[16 * 11];
  for (int j = 0; j < 16 * 11; j++)
    {
      key_schedule [j] = 0;
    }

  uint8_t tmp[4];
  /* We set the last_key in the last position of key_schedule */
  for (int j = 0; j < 16; j++)
    {
      key_schedule [(10 * 16) + j] = last_key [j];
      /* fprintf(stderr, "Ox%x ", key_schedule [(10 * 16) + j]); */
    }
  /* fprintf(stderr, "\n"); */

  /* We set i as the number of the word to compute. There is 4*11 WORD and we
     already set the four last one, so we set: */
  int i = 10 * 4 - 1; 
  while (i >= 0)
    {

      /* i is the number of the word we want to compute */
      /* we take the word i + 3 */
      tmp[0] = key_schedule [(i+3) * WORD];
      tmp[1] = key_schedule [(i+3) * WORD + 1];
      tmp[2] = key_schedule [(i+3) * WORD + 2];
      tmp[3] = key_schedule [(i+3) * WORD + 3];

      /* We apply a fonction of the word i+3 */
      if ((i) % 4 == 0)
	{
	  rot_word (tmp);
	  sub_word (tmp); 
	  tmp[0] ^= rcon[(i+4) / NK];
	}

      /* Creation of the word  i using key_schedule on word i-1 (tmp) and
      the word i-4: 
			  W_i = W_(i+4) + F(W_(i+3))  */
      key_schedule [i * WORD ] = key_schedule [(i + 4) * WORD] ^ tmp[0]; 
      key_schedule [i * WORD + 1] = key_schedule [(i + 4) * WORD + 1] ^ tmp[1];
      key_schedule [i * WORD + 2] = key_schedule [(i + 4) * WORD + 2] ^ tmp[2];
      key_schedule [i * WORD + 3] = key_schedule [(i + 4) * WORD + 3] ^ tmp[3];
      i--;
    }


  /* We take the key as the four first words of the key_schedule */
  for (int j = 0; j < 16; j++)
    {
      key[j] = key_schedule [j];
    }

  /* fprintf(stderr, "Print inversed key_schedule:\n"); */
  /* for (int k = 0; k < 11; k++) */
  /*   { */
  /*     for (int j = 0; j < 16; j++) */
	/* { */
	  /* fprintf(stderr, " 0x%x " ,key_schedule[k * 16 + j]); */
	/* } */
	  /* fprintf(stderr, "\n"); */
  /*   } */
  /* fprintf(stderr, "\n"); */
  /* fprintf(stderr, "\n"); */

  return;
}

void last_key_expansion(uint8_t key_schedule[16*11], uint8_t last_key[16])
{
  for (int j = 0; j < 16 * 11; j++)
    {
      key_schedule [j] = 0;
    }

  uint8_t tmp[4];
  /* We set the last_key in the last position of key_schedule */
  for (int j = 0; j < 16; j++)
    {
      key_schedule [(10 * 16) + j] = last_key [j];
      /* fprintf(stderr, "Ox%x ", key_schedule [(10 * 16) + j]); */
    }
  /* fprintf(stderr, "\n"); */

  /* We set i as the number of the word to compute. There is 4*11 WORD and we
     already set the four last one, so we set: */
  int i = 10 * 4 - 1; 
  while (i >= 0)
    {

      /* i is the number of the word we want to compute */
      /* we take the word i + 3 */
      tmp[0] = key_schedule [(i+3) * WORD];
      tmp[1] = key_schedule [(i+3) * WORD + 1];
      tmp[2] = key_schedule [(i+3) * WORD + 2];
      tmp[3] = key_schedule [(i+3) * WORD + 3];

      /* We apply a fonction of the word i+3 */
      if ((i) % 4 == 0)
	{
	  rot_word (tmp);
	  sub_word (tmp); 
	  tmp[0] ^= rcon[(i+4) / NK];
	}

      /* Creation of the word  i using key_schedule on word i-1 (tmp) and
      the word i-4: 
			  W_i = W_(i+4) + F(W_(i+3))  */
      key_schedule [i * WORD ] = key_schedule [(i + 4) * WORD] ^ tmp[0]; 
      key_schedule [i * WORD + 1] = key_schedule [(i + 4) * WORD + 1] ^ tmp[1];
      key_schedule [i * WORD + 2] = key_schedule [(i + 4) * WORD + 2] ^ tmp[2];
      key_schedule [i * WORD + 3] = key_schedule [(i + 4) * WORD + 3] ^ tmp[3];
      i--;
    }

  return;
}

void test_inv_key_expansion()
{
uint8_t key[16] = 
  {0x03, 0x02, 0x04, 0x08, 
   0x11, 0x02, 0x03, 0x04, 
   0x11, 0x13, 0xa1, 0xa2, 
   0xab, 0xbb, 0xcc, 0xdd };

uint8_t key_schedule[16 * 11];
uint8_t last_key[16];


fprintf(stderr, "Begin of the test:\n");

fprintf(stderr, "key_schedule...");
key_expansion (key, key_schedule);

for (int j = 0; j < 16; j++)
  {
    last_key[j] = key_schedule [(10 * 16) + j];
  }
fprintf(stderr, "     DONE \n");

fprintf(stderr, "Print key_schedule:\n");
for (int k = 0; k < 11; k++)
  {
    for (int j = 0; j < 16; j++)
      {
	fprintf(stderr, " 0x%x " ,key_schedule[k * 16 + j]);
      }
	fprintf(stderr, "\n");
  }
fprintf(stderr, "\n");


uint8_t possible_key[16];
fprintf(stderr, "inv_key_expansion:\n");
inv_key_expansion (possible_key, last_key);
fprintf(stderr, "     DONE \n");

for (int j = 0; j < 16; j++)
  {
    if (key[j] != possible_key [j])
      {
	fprintf(stderr, "Test inv_key_expansion FAILED:\n");
	/* return; */
      }
  }

fprintf(stderr, "key : ");
for (int j=0; j<16; j++)
  {
    fprintf(stderr, " 0x%x", key[j]);
  }
fprintf(stderr, "\npossible_key : ");


for (int j=0; j<16; j++)
  {
    fprintf(stderr, " 0x%x", possible_key[j]);
  }

fprintf(stderr, "\nTest inv_key_expansion SUCCEED\n\n");
return;
}
