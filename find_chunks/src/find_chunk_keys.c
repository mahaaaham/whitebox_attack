#include "find_chunk_keys.h"

#include "tables.h"
#include "dtables.h"
#include "tools.h"
#include "cipher.h"
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

/* Global variables */
uint8_t byte_error_1;
uint8_t byte_error_2;
int max_without_found = 9999999;
int max_written_element = 1000;
int max_nb_try = 3000;


/* buffer has to contains 16 bytes */
void
encrypt (uint8_t *buffer)
{

  /* WARNING: the included code have to act on "buffer" */
  /* #include "instr.c" */
  #include "instr.c"

  return;
}

/* buffer has to contains 16 bytes */
void
mod_encrypt (uint8_t *buffer)
{
  printf("\nErreur 1: %x \n" ,byte_error_1);
  printf("Erreur 2: %x \n" ,byte_error_2);

  /* WARNING: the included code have to act on "buffer" */
  #include "mod_instr.c"
  return;
}


int
main ()
{
  int nb_try = 0;
  bool found = false;
  int cpt_found = 0;
  int cpt_written = 0;

  uint8_t initial_state[16]; /* never change */
  uint8_t state[16]; /* will change with cipher */
  uint8_t mod_state[16]; /* will change with cipher */

  uint8_t to_find_in_dtable[4]; 
  uint32_t to_find_in_dtable_int = 0; 
  int ind_sort = 0;

  char *text = "input_file";

  /* uint8_t input[16] = {0x57, 0x68, 0x6f, 0x20, 0x49, 0x73, 0x20, 0x52, */ 
  /*                      0x69, 0x6a, 0x6e, 0x64, 0x61, 0x65, 0x6c, 0x20}; */

  read_from_file (text, &initial_state[0]);


  char path_1[80];
  char path_2[80];
  char path_3[80];
  char path_4[80];
  char error_1[10];
  char error_2[10];

  byte_error_1 = random_byte ();
  byte_error_2 = 0;

  try_again: 
  nb_try++;
  if (nb_try > 256)
    {
      goto exit_program;
    }
  if (nb_try != 1)
    {
      byte_error_2++;
    }

  /* Creation of the four files */
  strcpy(path_1, "chunk_key/chunk1_");
  strcpy(path_2, "chunk_key/chunk2_");
  strcpy(path_3, "chunk_key/chunk3_");
  strcpy(path_4, "chunk_key/chunk4_");


  sprintf(error_1, "%2x", byte_error_1);
  sprintf(error_2, "%2x", byte_error_2);

  strcat(path_1, error_1);
  strcat(path_1, error_2);

  strcat(path_2, error_1);
  strcat(path_2, error_2);

  strcat(path_3, error_1);
  strcat(path_3, error_2);

  strcat(path_4, error_1);
  strcat(path_4, error_2);

  /* File to put the candidates chunk keys in */
  FILE *fd_1 = fopen (path_1, "w"); /* The file were we write the array */
  if (!fd_1)
    {
      fprintf (stderr, "%s", "cannot open column_1_candidate");
      return EXIT_FAILURE;
    }
  FILE *fd_2 = fopen (path_2, "w"); /* The file were we write the array */
  if (!fd_2)
    {
      fprintf (stderr, "%s", "cannot open column_2_candidate");
      return EXIT_FAILURE;
    }
  FILE *fd_3 = fopen (path_3, "w"); /* The file were we write the array */
  if (!fd_3)
    {
      fprintf (stderr, "%s", "cannot open column_3_candidate");
      return EXIT_FAILURE;
    }
  FILE *fd_4 = fopen (path_4, "w"); /* The file were we write the array */
  if (!fd_4)
    {
      fprintf (stderr, "%s", "cannot open column_4_candidate");
      return EXIT_FAILURE;
    }

  printf("Essai numéro: %d\n", nb_try);

  /* mod state is the same than state, but will be utilised by mod_instr, and
     so, a difference will be put into it */
  for (int i = 0; i < 16; i++)
    {
      mod_state[i] = initial_state[i];
      state[i] = initial_state[i];
    }

  /* initialisation at 0 of temp variables */
  for (int i = 0; i < 4; i++)
    to_find_in_dtable[i] = 0;
  found = false;
  cpt_found = 0;


  /* normal encrypt and encrypt with error added */
  encrypt (state);

  mod_encrypt (mod_state);

  /* Try to find K0, K7, K10, K13 (with error in column 1) */
  cpt_found = 0;
  cpt_written = 0;


  fprintf(fd_1, "#include <stdint.h>\n#define SIZE_CHUNK TODO \nint size_chunk_1 = SIZE_CHUNK; \nuint8_t chunk_1[SIZE_CHUNK][4] = {\n");
  fprintf(fd_2, "#include <stdint.h>\n#define SIZE_CHUNK TODO \nint size_chunk_2 = SIZE_CHUNK; \nuint8_t chunk_2[SIZE_CHUNK][4] = {\n");
  fprintf(fd_3, "#include <stdint.h>\n#define SIZE_CHUNK TODO \nint size_chunk_3 = SIZE_CHUNK; \nuint8_t chunk_3[SIZE_CHUNK][4] = {\n");
  fprintf(fd_4, "#include <stdint.h>\n#define SIZE_CHUNK TODO \nint size_chunk_4 = SIZE_CHUNK; \nuint8_t chunk_4[SIZE_CHUNK][4] = {\n");


  fprintf(stderr, "----------------------- Ecriture dans Column 1 --------------------------\n");
  for (int key_i = 0; key_i < 256; key_i++)
    {
      fprintf(stderr, "Column 1, key_i = %d\n", key_i);
      for (int key_j = 0; key_j < 256; key_j++)
	{
	  for (int key_k = 0; key_k < 256; key_k++)
	    {
	      for (int key_l = 0; key_l < 256; key_l++)
		{
		  cpt_found++;
		  to_find_in_dtable[0] = compute_difference(state[0], mod_state[0],(uint8_t) key_i);
		  to_find_in_dtable[1] = compute_difference(state[13], mod_state[13],(uint8_t) key_j);
		  to_find_in_dtable[2] = compute_difference(state[10], mod_state[10],(uint8_t) key_k);
		  to_find_in_dtable[3] = compute_difference(state[7], mod_state[7],(uint8_t) key_l);

		  to_find_in_dtable_int = (((uint32_t)to_find_in_dtable[3]) << 24) + (((uint32_t)to_find_in_dtable[2]) << 16)
					 + (((uint32_t)to_find_in_dtable[1]) << 8) + (uint32_t)to_find_in_dtable[0];


		  ind_sort = 0;
		  if (to_find_in_dtable_int >= done[ind_sort+128]) ind_sort += 128;
		  if (to_find_in_dtable_int >= done[ind_sort+ 64]) ind_sort +=  64;
		  if (to_find_in_dtable_int >= done[ind_sort+ 32]) ind_sort +=  32;
		  if (to_find_in_dtable_int >= done[ind_sort+ 16]) ind_sort +=  16;
		  if (to_find_in_dtable_int >= done[ind_sort+  8]) ind_sort +=   8;
		  if (to_find_in_dtable_int >= done[ind_sort+  4]) ind_sort +=   4;
		  if (to_find_in_dtable_int >= done[ind_sort+  2]) ind_sort +=   2;
		  if (to_find_in_dtable_int >= done[ind_sort+  1]) ind_sort +=   1;
		  if (to_find_in_dtable_int == done[ind_sort])
		     {
		       fprintf (fd_1, "{0x%02hhx, ", (uint8_t)key_i);
		       fprintf (fd_1, " 0x%02hhx, ", (uint8_t)key_j);
		       fprintf (fd_1, " 0x%02hhx, ", (uint8_t)key_k);
		       fprintf (fd_1, " 0x%02hhx}\n, ", (uint8_t)key_l);
		       found = true;
		       cpt_written++;
		     }

		  if (cpt_written > max_written_element)
		    {
		      fprintf (fd_1, "};\n \n trop d'éléments écrits!\n");
		      fprintf (stderr, "};\n \n trop d'éléments écrits!\n");
		      cpt_written = 0;
		      fclose(fd_1);
		      fclose(fd_2);
		      fclose(fd_3);
		      fclose(fd_4);
		      goto try_again;
		    }
		} /* key_l */
	    } /* key_k */
	} /* key_j */
    } /* key_i */
    fprintf (fd_1, "};\n\n ");
    fclose(fd_1);


  /* /1* Try to find K4, K11, K14, K1 (with error in column 2) *1/ */

  fprintf(stderr, "----------------------- Ecriture dans Column 2 --------------------------\n");
  cpt_found = 0;
  for (int key_i = 0; key_i < 256; key_i++)
    {
      fprintf(stderr, "Column 2, key_i = %d\n", key_i);
      for (int key_j = 0; key_j < 256; key_j++)
	{
	  for (int key_k = 0; key_k < 256; key_k++)
	    {
	      for (int key_l = 0; key_l < 256; key_l++)
		{
		  cpt_found++;
		  to_find_in_dtable[0] = compute_difference(state[4], mod_state[4], (uint8_t)key_i); 
		  to_find_in_dtable[1] = compute_difference(state[1], mod_state[1], (uint8_t)key_j); 
		  to_find_in_dtable[2] = compute_difference(state[14], mod_state[14], (uint8_t)key_k);
		  to_find_in_dtable[3] = compute_difference(state[11], mod_state[11], (uint8_t)key_l);
		  to_find_in_dtable_int = (((uint32_t)to_find_in_dtable[3]) << 24) + (((uint32_t)to_find_in_dtable[2]) << 16)
					 + (((uint32_t)to_find_in_dtable[1]) << 8) + (uint32_t)to_find_in_dtable[0];

		  ind_sort = 0;
		  if (to_find_in_dtable_int >= dfour[ind_sort+128]) ind_sort += 128;
		  if (to_find_in_dtable_int >= dfour[ind_sort+ 64]) ind_sort +=  64;
		  if (to_find_in_dtable_int >= dfour[ind_sort+ 32]) ind_sort +=  32;
		  if (to_find_in_dtable_int >= dfour[ind_sort+ 16]) ind_sort +=  16;
		  if (to_find_in_dtable_int >= dfour[ind_sort+  8]) ind_sort +=   8;
		  if (to_find_in_dtable_int >= dfour[ind_sort+  4]) ind_sort +=   4;
		  if (to_find_in_dtable_int >= dfour[ind_sort+  2]) ind_sort +=   2;
		  if (to_find_in_dtable_int >= dfour[ind_sort+  1]) ind_sort +=   1;

		  if (to_find_in_dtable_int == dfour[ind_sort])
		     {
		       fprintf (fd_2, "{0x%02hhx, ", (uint8_t)key_i);
		       fprintf (fd_2, " 0x%02hhx, ", (uint8_t)key_j);
		       fprintf (fd_2, " 0x%02hhx, ", (uint8_t)key_k);
		       fprintf (fd_2, " 0x%02hhx}\n, ", (uint8_t)key_l);
		       found = true;
		       cpt_written++;
		     }

		  if (cpt_written > max_written_element)
		    {
		      fprintf (fd_2, "};\n \n trop d'éléments écrits!\n");
		      fprintf (stderr, "};\n \n trop d'éléments écrits!\n");
		      cpt_written = 0;
		      fclose(fd_2);
		      fclose(fd_3);
		      fclose(fd_4);
		      goto try_again;
		    }
		} /* key_l */
	    } /* key_k */
	} /* key_j */
    } /* key_i */
  fprintf (fd_2, "};\n\n ");
  fclose(fd_2);

  /* /1* Try to find K8, K15, K2, K5 (with error in column 3) *1/ */

  fprintf(stderr, "----------------------- Ecriture dans Column 3 --------------------------\n");
  cpt_found = 0;
  for (int key_i = 0; key_i < 256; key_i++)
    {
      fprintf(stderr, "Column 3, key_i = %d\n", key_i);
      for (int key_j = 0; key_j < 256; key_j++)
	{
	  for (int key_k = 0; key_k < 256; key_k++)
	    {
	      for (int key_l = 0; key_l < 256; key_l++)
		{
		  cpt_found++;
		  to_find_in_dtable[0] = compute_difference(state[8], mod_state[8], (uint8_t)key_i);
		  to_find_in_dtable[1] = compute_difference(state[5], mod_state[5],(uint8_t)key_j );
		  to_find_in_dtable[2] = compute_difference(state[2], mod_state[2], (uint8_t)key_k);
		  to_find_in_dtable[3] = compute_difference(state[15], mod_state[15],(uint8_t)key_l);
		  to_find_in_dtable_int = (((uint32_t)to_find_in_dtable[3]) << 24) + (((uint32_t)to_find_in_dtable[2]) << 16)
					 + (((uint32_t)to_find_in_dtable[1]) << 8) + (uint32_t)to_find_in_dtable[0];
  
		  ind_sort = 0;
		  if (to_find_in_dtable_int >= dthree[ind_sort+128]) ind_sort += 128;
		  if (to_find_in_dtable_int >= dthree[ind_sort+ 64]) ind_sort +=  64;
		  if (to_find_in_dtable_int >= dthree[ind_sort+ 32]) ind_sort +=  32;
		  if (to_find_in_dtable_int >= dthree[ind_sort+ 16]) ind_sort +=  16;
		  if (to_find_in_dtable_int >= dthree[ind_sort+  8]) ind_sort +=   8;
		  if (to_find_in_dtable_int >= dthree[ind_sort+  4]) ind_sort +=   4;
		  if (to_find_in_dtable_int >= dthree[ind_sort+  2]) ind_sort +=   2;
		  if (to_find_in_dtable_int >= dthree[ind_sort+  1]) ind_sort +=   1;

		  if (to_find_in_dtable_int == dthree[ind_sort])
		     {
		       fprintf (fd_3, "{0x%02hhx, ", (uint8_t)key_i);
		       fprintf (fd_3, " 0x%02hhx, ", (uint8_t)key_j);
		       fprintf (fd_3, " 0x%02hhx, ", (uint8_t)key_k);
		       fprintf (fd_3, " 0x%02hhx}\n, ", (uint8_t)key_l);
		       found = true;
		       cpt_written++;
		     }

		  if (cpt_written > max_written_element)
		    {
		      fprintf (fd_3, "};\n \n trop d'éléments écrits!\n");
		      fprintf (stderr, "};\n \n trop d'éléments écrits!\n");
		      cpt_written = 0;
		      fclose(fd_3);
		      fclose(fd_4);
		      goto try_again;
		    }

		} /* key_l */
	    } /* key_k */
	} /* key_j */
    } /* key_i */
  fprintf (fd_3, "};\n\n ");
  fclose(fd_3);

  /* /1* Try to find K12, K3, K6, K9 (with error in column 4) *1/ */

  fprintf(stderr, "----------------------- Ecriture dans Column 4 --------------------------\n");
  cpt_found = 0;
  for (int key_i = 0; key_i < 256; key_i++)
    {
      fprintf(stderr, "Column 4, key_i = %d\n", key_i);
      for (int key_j = 0; key_j < 256; key_j++)
	{
	  for (int key_k = 0; key_k < 256; key_k++)
	    {
	      for (int key_l = 0; key_l < 256; key_l++)
		{
		  cpt_found++;
		  to_find_in_dtable[0] = compute_difference(state[12], mod_state[12], (uint8_t)key_i);
		  to_find_in_dtable[1] = compute_difference(state[9], mod_state[9], (uint8_t)key_j);
		  to_find_in_dtable[2] = compute_difference(state[6], mod_state[6], (uint8_t)key_k);
		  to_find_in_dtable[3] = compute_difference(state[3], mod_state[3], (uint8_t)key_l);
		  to_find_in_dtable_int = (((uint32_t)to_find_in_dtable[3]) << 24) + (((uint32_t)to_find_in_dtable[2]) << 16)
					 + (((uint32_t)to_find_in_dtable[1]) << 8) + (uint32_t)to_find_in_dtable[0];

		  ind_sort = 0;
		  if (to_find_in_dtable_int >= dtwo[ind_sort+128]) ind_sort += 128;
		  if (to_find_in_dtable_int >= dtwo[ind_sort+ 64]) ind_sort +=  64;
		  if (to_find_in_dtable_int >= dtwo[ind_sort+ 32]) ind_sort +=  32;
		  if (to_find_in_dtable_int >= dtwo[ind_sort+ 16]) ind_sort +=  16;
		  if (to_find_in_dtable_int >= dtwo[ind_sort+  8]) ind_sort +=   8;
		  if (to_find_in_dtable_int >= dtwo[ind_sort+  4]) ind_sort +=   4;
		  if (to_find_in_dtable_int >= dtwo[ind_sort+  2]) ind_sort +=   2;
		  if (to_find_in_dtable_int >= dtwo[ind_sort+  1]) ind_sort +=   1;

		  if (to_find_in_dtable_int == dtwo[ind_sort])
		     {
		       fprintf (fd_4, "{0x%02hhx, ", (uint8_t)key_i);
		       fprintf (fd_4, " 0x%02hhx, ", (uint8_t)key_j);
		       fprintf (fd_4, " 0x%02hhx, ", (uint8_t)key_k);
		       fprintf (fd_4, " 0x%02hhx}\n, ", (uint8_t)key_l);
		       found = true;
		       cpt_written++;
		     }

		  if (cpt_written > max_written_element)
		    {
		      fprintf (fd_4, "};\n \n trop d'éléments écrits!\n");
		      fprintf (stderr, "};\n \n trop d'éléments écrits!\n");
		      cpt_written = 0;
		      fclose(fd_4);
		      goto try_again;
		    }
		
		} /* key_l */
	    } /* key_k */
	} /* key_j */
    } /* key_i */
  fprintf (fd_4, "};k\n\n ");
  fclose(fd_4);

  goto try_again;


exit_program:

  return EXIT_SUCCESS;
}
