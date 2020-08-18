#include "tables.h"
#include "dtables.h"

#include "cipher.h"
#include "state.h"
#include "define.h"
#include "key.h"

#include <unistd.h> /* for open and close */
#include <sys/stat.h>  /* to read /dev/urandom */
#include <fcntl.h>  /* to read /dev/urandom */
#include <stdint.h>
#include <stdbool.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "ctype.h" // for "isspace"

#include "chunk1.h"
#include "chunk2.h"
#include "chunk3.h"
#include "chunk4.h"

/* Global variables */
uint8_t byte_error_1;
uint8_t byte_error_2;
int max_without_found = 9999999;
int max_written_element = 1000;
int max_nb_try = 1000;


bool test_key(uint8_t key[16])
{
  uint8_t input_1_square[4][4] = {{0, 1, 2, 3} ,{4, 5 ,6 ,7} , {8, 9, 10, 11}, {12, 13, 14, 15}};

  uint8_t test_state_1[4][4];
  uint8_t buffer[16];

  uint8_t key_schedule[16 * 11];
  key_expansion (key, key_schedule);

  cipher (test_state_1, input_1_square, key_schedule);

  /* WARNING: the included code have to act on "buffer" */
  /* #include "instr.c" */
  #include "clear_instr.c"

  fprintf(stderr, "print_state_1 is: \n");
  print_state(test_state_1);

  fprintf(stderr, "buffer is: \n");
  for (int i = 0; i < 4; i++)
    {
      for (int j = 0; j < 4; j++)
      {
	fprintf(stderr, "0x%x ", buffer[4*j + i]);
      }
    fprintf(stderr, "\n ");
    }



  for (int i = 0; i < 4; i++)
    for (int j = 0; j < 4; j++)
    {
      if (buffer[4*j + i] != test_state_1[i][j])
	return false;
    }

  return true;
}

int exhaustive_search(char *path_result)
{
  FILE *f_result = fopen (path_result, "w"); /* The file were we write the array */
  if (!f_result)
    {
      fprintf (stderr, "%s", "cannot the file to write the result key");
      return EXIT_FAILURE;
    }

  uint8_t possible_last_key[16];
  uint8_t possible_key[16];
  bool is_key = false;

  fprintf(stderr, "Size of chunk_1: %d \n", size_chunk_1);
  fprintf(stderr, "Size of chunk_1: %d \n", size_chunk_2);
  fprintf(stderr, "Size of chunk_1: %d \n", size_chunk_3);
  fprintf(stderr, "Size of chunk_1: %d \n", size_chunk_4);
  fprintf(stderr, "----------------------\n\n");

  for (int i = 0; i < size_chunk_1; i++)
    {
      fprintf(stderr, " i (chunk_1) = %d ", i);
      for (int j = 0; j < size_chunk_2; j++)
	{
	  fprintf(stderr, " j (chunk_2) = %d ", j);
	  for (int k = 0; k < size_chunk_3; k++)
	    {
	      for (int l = 0; l < size_chunk_3; l++)
		{
		  possible_last_key[0] = chunk_1[i][0];
		  possible_last_key[13] = chunk_1[i][1];
		  possible_last_key[10] = chunk_1[i][2];
		  possible_last_key[7] = chunk_1[i][3];

		  possible_last_key[4] = chunk_2[j][0];
		  possible_last_key[1] = chunk_2[j][1];
		  possible_last_key[14] = chunk_2[j][2];
		  possible_last_key[11] = chunk_2[j][3];

		  possible_last_key[8] = chunk_3[k][0];
		  possible_last_key[5] = chunk_3[k][1];
		  possible_last_key[2] = chunk_3[k][2];
		  possible_last_key[15] = chunk_3[k][3];

		  possible_last_key[12] = chunk_4[l][0];
		  possible_last_key[9] = chunk_4[l][1];
		  possible_last_key[6] = chunk_4[l][2];
		  possible_last_key[3] = chunk_4[l][3];

		  inv_key_expansion(possible_key, possible_last_key);
		  fprintf(stderr, "key is:\n");
		  print_key(possible_key);
		  is_key = test_key(possible_key);
		  if (is_key == true)
		    {
		      fprintf(stderr, "Key has been found!");
		      fprintf(f_result, "Key has been found!\n");
		      for (int i = 0; i < 16; i++)
			{
			  fprintf(f_result, "0x%02x ", possible_last_key[i]);
			}
		    }
		}
	    }
	}
    }
  return EXIT_SUCCESS;
}

int
main (int argc, char **argv)
{
  char *path_result = "result_key";
  /* test_inv_key_expansion(); */
  exhaustive_search(path_result);
  return EXIT_SUCCESS;
}
