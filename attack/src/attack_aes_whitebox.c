#include "attack_aes_whitebox.h"

#include "tables.h"
#include "sbox.h"
#include "dtables.h"

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
#define SIZE_BUFFER 3000
uint8_t byte_error_1;
uint8_t byte_error_2;



#define BINARY (strrchr (argv[0], '/') + 1)

#define EXIT(message, ...)						\
  do									\
    {									\
      fprintf (stderr, "%s: " message ".\n", BINARY, __VA_ARGS__);	\
      exit (EXIT_FAILURE);						\
    }									\
  while (0)

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

/* buffer has to contains 16 bytes */
void
encrypt (uint8_t *buffer)
{
  uint8_t s[42];

  memcpy(s, buffer, 16);

  #include "instr.c"

  memcpy(buffer, s, 16);
  return;
}

/* buffer has to contains 16 bytes */
void
mod_encrypt (uint8_t *buffer)
{
  byte_error_1 = random_byte ();
  byte_error_2 = random_byte ();
  /* byte_error_1 = 0x64; */ 
  /* byte_error_2 = 0xd4; */
  printf("\nErreur 1: %x \n" ,byte_error_1);
  printf("Erreur 2: %x \n" ,byte_error_2);

  uint8_t s[42];

  memcpy(s, buffer, 16);

  #include "mod_instr.c"

  memcpy(buffer, s, 16);
  printf("mod_encrypt calculé");
  return;
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
       nb =  strtol(&tmp_char, NULL, 16);
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


int
main (int argc, char **argv)
{
  int limit_found = 256*256*256;
  uint32_t buffer_fd[SIZE_BUFFER];
  for (int i = 0; i < SIZE_BUFFER; i++)
    buffer_fd[i] = 0;
  int last_ind_buffer_fd = 0;
  bool in_buffer = false;
  
  int nb_try = 0;
  bool found = false;
  int cpt_found = 0;

  uint8_t state[16]; /* will change with cipher */
  uint8_t mod_state[16]; /* will change with cipher */
  uint8_t initial_state[16]; /* never change */

  uint8_t to_find_in_dtable[4]; 
  uint32_t to_find_in_dtable_int = 0; 
  int ind_sort = 0;
  uint8_t last_round_key[16]; /* the Graal we are searching */

  /* File to put the candidates chunk keys in */
  FILE *fd_1 = fopen ("column_1_candidate", "w"); /* The file were we write the array */
  if (!fd_1)
    EXIT ("%s", "cannot open column_1_candidate");
  FILE *fd_2 = fopen ("column_2_candidate", "w"); /* The file were we write the array */
  if (!fd_2)
    EXIT ("%s", "cannot open column_2_candidate");
  FILE *fd_3 = fopen ("column_3_candidate", "w"); /* The file were we write the array */
  if (!fd_3)
    EXIT ("%s", "cannot open column_3_candidate");
  FILE *fd_4 = fopen ("column_4_candidate", "w"); /* The file were we write the array */
  if (!fd_4)
    EXIT ("%s", "cannot open column_4_candidate");
  FILE *fd_error = fopen ("error_working", "w"); /* The file were we write the array */
  if (!fd_1)
    EXIT ("%s", "cannot open error_working");



  char *text = "input_file";

  /* uint8_t input[16] = {0x57, 0x68, 0x6f, 0x20, 0x49, 0x73, 0x20, 0x52, */ 
  /*                      0x69, 0x6a, 0x6e, 0x64, 0x61, 0x65, 0x6c, 0x20}; */

  read_from_file (text, &initial_state[0]);

  try_again: 
  nb_try++;
  printf("Essai numéro: %d\n", nb_try);

  /* mod state is the same than state, but will be utilised by mod_instr, and
     so, a difference will be put into it */
  for (int i = 0; i < 16; i++)
    {
      mod_state[i] = initial_state[i];
      state[i] = initial_state[i];
    }

  /* initialisation at 0 */
  for (int i = 0; i < 4; i++)
    to_find_in_dtable[i] = 0;
  found = false;
  cpt_found = 0;


  encrypt (&state[0]);
  mod_encrypt (&mod_state[0]);

  /* Try to find K0, K7, K10, K13 (with error in column 1) */

  cpt_found = 0;
  for (int key_i = 0; key_i < 256; key_i++)
    {
      fprintf(stderr, "Change of key_i");
      for (int key_j = 0; key_j < 256; key_j++)
	{
	  for (int key_k = 0; key_k < 256; key_k++)
	    {
	      for (int key_l = 0; key_l < 256; key_l++)
		{
		  cpt_found++;
		  to_find_in_dtable[0] = compute_difference(state[0], mod_state[0],(uint8_t) key_i);
		  to_find_in_dtable[1] = compute_difference(state[7], mod_state[7],(uint8_t) key_j);
		  to_find_in_dtable[2] = compute_difference(state[10], mod_state[10],(uint8_t) key_k);
		  to_find_in_dtable[3] = compute_difference(state[13], mod_state[13],(uint8_t) key_l);
		  to_find_in_dtable_int = (((uint32_t)to_find_in_dtable[3]) << 12) + (((uint32_t)to_find_in_dtable[2]) << 8)
			   + (((uint32_t)to_find_in_dtable[1]) << 4) + (uint32_t)to_find_in_dtable[0];

		  for (int cpt = 0; cpt < 256; cpt++)
		    {
		      ind_sort = 0;
		      if (to_find_in_dtable_int >= done[ind_sort+128]) ind_sort += 128;
		      if (to_find_in_dtable_int >= done[ind_sort+ 64]) ind_sort +=  64;
		      if (to_find_in_dtable_int >= done[ind_sort+ 32]) ind_sort +=  32;
		      if (to_find_in_dtable_int >= done[ind_sort+ 16]) ind_sort +=  16;
		      if (to_find_in_dtable_int >= done[ind_sort+  8]) ind_sort +=   8;
		      if (to_find_in_dtable_int >= done[ind_sort+  4]) ind_sort +=   4;
		      if (to_find_in_dtable_int >= done[ind_sort+  2]) ind_sort +=   2;
		      if (to_find_in_dtable_int >= done[ind_sort+  1]) ind_sort +=   1;

		      /* NOT SURE OF THAT */
		      /* if (to_find_in_dtable_int == done[ind_sort]) */
			 /* { */
			   /* for (int i = 0; i < last_ind_buffer_fd; i++) */
			     /* { */
			       /* if (to_find_in_dtable_int == buffer_fd[i]) */
				 /* { */
				   /* in_buffer = true; */
				   /* break; */
				 /* } */
			     /* } */
			 /* } */

			   fprintf (fd_1, "0x%02hhx, ", (uint8_t)key_i);
			   fprintf (fd_1, "0x%02hhx, ", (uint8_t)key_j);
			   fprintf (fd_1, "0x%02hhx, ", (uint8_t)key_k);
			   fprintf (fd_1, "0x%02hhx\n ", (uint8_t)key_l);
			   if (found == false)
			     {
			       fprintf(stderr, "One element found and written.");
			       fprintf (fd_error, "Erreur: %d, %d", (int) byte_error_1, (int) byte_error_2);
			     }
			   found = true;
			 }

		    }
		  if ((cpt_found > 999999) && (found == false))
		    {
		      printf("Rien de trouvé. cpt_found vaut: ");
		      printf("%d.\n", cpt_found);
		      if (nb_try < 256)
			{
			  goto try_again;
			}
		      return EXIT_FAILURE;
		    }
		}
	    }
	}
    }


  /* /1* Try to find K4, K11, K14, K1 (with error in column 2) *1/ */

  cpt_found = 0;
  for (int key_i = 0; key_i < 256; key_i++)
    {
      for (int key_j = 0; key_j < 256; key_j++)
	{
	  for (int key_k = 0; key_k < 256; key_k++)
	    {
	      for (int key_l = 0; key_l < 256; key_l++)
		{
		  cpt_found++;
		  to_find_in_dtable[0] = compute_difference(state[4], mod_state[4], (uint8_t)key_i); 
		  to_find_in_dtable[1] = compute_difference(state[11], mod_state[11], (uint8_t)key_j);
		  to_find_in_dtable[2] = compute_difference(state[14], mod_state[14], (uint8_t)key_k);
		  to_find_in_dtable[3] = compute_difference(state[1], mod_state[1], (uint8_t)key_l); 
		  to_find_in_dtable_int = (((uint32_t)to_find_in_dtable[3]) << 12) + (((uint32_t)to_find_in_dtable[2]) << 8)
			   + (((uint32_t)to_find_in_dtable[1]) << 4) + (uint32_t)to_find_in_dtable[0];
		  /* if (cpt_found > limit_found) */
		  /*   { */
		  /*     printf("cpt_found trop grand"); */
		  /*     return EXIT_FAILURE; */
		  /*   } */

		  for (int cpt = 0; cpt < 256; cpt++)
		    {
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
			   fprintf (fd_2, "0x%02hhx, ", (uint8_t)key_i);
			   fprintf (fd_2, "0x%02hhx, ", (uint8_t)key_j);
			   fprintf (fd_2, "0x%02hhx, ", (uint8_t)key_k);
			   fprintf (fd_2, "0x%02hhx\n ", (uint8_t)key_l);
			   if (found == false)
			     printf("One element found and written.");
			   found = true;
			 }

		    }
		  if ((cpt_found > 9999999) && (found == false))
		    {
		      printf("Rien de trouvé, wierd. cpt_found vaut:\n");
		      printf("%d\n", cpt_found);
		      if (nb_try < 200)
			{
			  goto try_again;
			}
		      return EXIT_FAILURE;
		    }
		}
	    }
	}
    }

  /* /1* Try to find K8, K15, K2, K5 (with error in column 3) *1/ */

  cpt_found = 0;
  for (int key_i = 0; key_i < 256; key_i++)
    {
      for (int key_j = 0; key_j < 256; key_j++)
	{
	  for (int key_k = 0; key_k < 256; key_k++)
	    {
	      for (int key_l = 0; key_l < 256; key_l++)
		{
		  cpt_found++;
		  to_find_in_dtable[0] = compute_difference(state[8], mod_state[8], (uint8_t)key_i);
		  to_find_in_dtable[1] = compute_difference(state[15], mod_state[15],(uint8_t)key_j);
		  to_find_in_dtable[2] = compute_difference(state[2], mod_state[2], (uint8_t)key_k);
		  to_find_in_dtable[3] = compute_difference(state[5], mod_state[5],(uint8_t)key_l );
		  to_find_in_dtable_int = (((uint32_t)to_find_in_dtable[3]) << 12) + (((uint32_t)to_find_in_dtable[2]) << 8)
			   + (((uint32_t)to_find_in_dtable[1]) << 4) + (uint32_t)to_find_in_dtable[0];
  
		  /* if (cpt_found > limit_found) */
		  /*   { */
		  /*     printf("cpt_found trop grand"); */
		  /*     return EXIT_FAILURE; */
		  /*   } */

		  for (int cpt = 0; cpt < 256; cpt++)
		    {
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
			   fprintf (fd_3, "0x%02hhx, ", (uint8_t)key_i);
			   fprintf (fd_3, "0x%02hhx, ", (uint8_t)key_j);
			   fprintf (fd_3, "0x%02hhx, ", (uint8_t)key_k);
			   fprintf (fd_3, "0x%02hhx\n ", (uint8_t)key_l);
			   if (found == false)
			     printf("One element found and written.");
			   found = true;
			 }

		    }
		  if ((cpt_found > 9999999) && (found == false))
		    {
		      printf("Rien de trouvé, wierd. cpt_found vaut:\n");
		      printf("%d\n", cpt_found);
		      if (nb_try < 200)
			{
			  goto try_again;
			}
		      return EXIT_FAILURE;
		    }
		}
	    }
	}
    }

  /* /1* Try to find K12, K3, K6, K9 (with error in column 4) *1/ */

  cpt_found = 0;
  for (int key_i = 0; key_i < 256; key_i++)
    {
      for (int key_j = 0; key_j < 256; key_j++)
	{
	  for (int key_k = 0; key_k < 256; key_k++)
	    {
	      for (int key_l = 0; key_l < 256; key_l++)
		{
		  cpt_found++;
		  to_find_in_dtable[0] = compute_difference(state[12], mod_state[12], (uint8_t)key_i);
		  to_find_in_dtable[1] = compute_difference(state[3], mod_state[3], (uint8_t)key_j);
		  to_find_in_dtable[2] = compute_difference(state[6], mod_state[6], (uint8_t)key_k);
		  to_find_in_dtable[3] = compute_difference(state[9], mod_state[9], (uint8_t)key_l);
		  to_find_in_dtable_int = (((uint32_t)to_find_in_dtable[3]) << 12) + (((uint32_t)to_find_in_dtable[2]) << 8)
			   + (((uint32_t)to_find_in_dtable[1]) << 4) + (uint32_t)to_find_in_dtable[0];
  
		  /* if (cpt_found > limit_found) */
		  /*   { */
		  /*     printf("cpt_found trop grand"); */
		  /*     return EXIT_FAILURE; */
		  /*   } */

		  for (int cpt = 0; cpt < 256; cpt++)
		    {
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
			   fprintf (fd_4, "0x%02hhx, ", (uint8_t)key_i);
			   fprintf (fd_4, "0x%02hhx, ", (uint8_t)key_j);
			   fprintf (fd_4, "0x%02hhx, ", (uint8_t)key_k);
			   fprintf (fd_4, "0x%02hhx\n ", (uint8_t)key_l);
			   if (found == false)
			     {
			     printf("One element found and written.");
			     }
			   found = true;
			 }

		    }
		  if ((cpt_found > 9999999) && (found == false))
		    {
		      printf("Rien de trouvé, wierd. cpt_found vaut:\n");
		      printf("%d\n", cpt_found);
		      if (nb_try < 200)
			{
			  goto try_again;
			}
		      return EXIT_FAILURE;
		    }
		}
	    }
	}
    }


  /* /1* printf("Differences are:\n "); *1/ */
  /* /1* for (int i = 0; i<16; i++) *1/ */
  /* /1*   { *1/ */
  /* /1*     printf("%x ", compute_difference(state[i], state[i], key)); *1/ */
  /* /1*   } *1/ */

  /* /1* printf("\n State is:\n "); *1/ */
  /* /1* for (int i = 0; i<16; i++) *1/ */
  /* /1*   { *1/ */
  /* /1*     printf("%x ", state[i]); *1/ */
  /* /1*   } *1/ */

  /* printf("\n Modified State is:\n "); */
  /* for (int i = 0; i<16; i++) */
  /*   { */
  /*     printf("%x ", mod_state[i]); */
  /*   } */
  printf("done");

  fclose(fd_1);
  fclose(fd_2);
  fclose(fd_3);
  fclose(fd_4);
  fclose(fd_error);

  return EXIT_SUCCESS;
}

/*
  The example in the README is:
plaintext :   57 68 6f 20 49 73 20 52 69 6a 6e 64 61 65 6c 20
ciphertext : 4b 95 f3 2b d1 9c ca 0a 81 64 9c 13 05 5d c9 f2
*/
