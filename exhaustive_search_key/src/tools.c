#include "tools.h"
#include "sbox.h"

#include <unistd.h> /* for open and close */
#include <sys/stat.h>  /* to read /dev/urandom */
#include <fcntl.h>  /* to read /dev/urandom */
#include <ctype.h>  /* to read /dev/urandom */

#include <stdlib.h>
#include <stdio.h>

uint8_t 
compute_difference (uint8_t state, uint8_t mod_state, uint8_t chunk_last_round_key)
  {
    uint8_t result = inv_sbox[state ^ chunk_last_round_key];
    result ^= inv_sbox[mod_state ^ chunk_last_round_key];
    return result;
  }

uint8_t
random_byte ()
{
  uint8_t buffer;
  int fd = open("/dev/urandom", O_RDONLY);
  read (fd, &buffer, 1);
  close (fd);
  return buffer;
}

void
read_from_file (char *input_file, uint8_t *buffer)
{
  int cpt = 0;
  FILE *fptr;
  fptr = fopen(input_file, "r");

  char tmp_char[2];
  uint8_t nb;

  if (fptr == NULL)
    {
      printf("Erreur lors de l'ouverture du fichier");
    }

  // any value different than EOF
  tmp_char[0] = 'a';
   while (tmp_char[0] != EOF)
     {
       tmp_char[0] = fgetc(fptr);
       tmp_char[1] = fgetc(fptr);
       nb =  strtol((char *)&tmp_char, NULL, 16);
       buffer[cpt] = nb;
       cpt++;

       // there has to be exactly one space between the numbers
       tmp_char[0] = fgetc(fptr);
       if ((tmp_char[0] != EOF) && (isspace(tmp_char[0]) == 0))
	 {
	   printf ("Mauvais format du fichier d'entrée");
	 }

     }
   return; 
}

void print_state(uint8_t state[4][4])
{
  for (int i = 0; i<4; i++)
    {
      for (int j = 0; j<4; j++)
	{
	  fprintf(stderr, "0x%x ", state[i][j]);
	}
      fprintf(stderr, "\n");
    }
  return;
}

void print_column(uint8_t column[4])
{
  for (int i = 0; i<4; i++)
    {
      fprintf(stderr, "0x%x ", column[i]);
      fprintf(stderr, "\n");
    }
  return;
}

void print_key(uint8_t key[16])
{
  for (int i = 0; i<16; i++)
    {
      fprintf(stderr, "0x%x ", key[i]);
    }
  fprintf(stderr, "\n");
  return;
}
