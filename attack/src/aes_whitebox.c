#include "attack_aes_whitebox.h"

#include "tables.h"


#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>


#include "ctype.h" // for "isspace"

void
encrypt (uint8_t *buffer)
{
  uint8_t s[42];

  memcpy(s, buffer, 16);

  #include "instr.c"

  memcpy(buffer, s, 16);
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
  char *text = "input_file";

  /* uint8_t input[16] = {0x57, 0x68, 0x6f, 0x20, 0x49, 0x73, 0x20, 0x52, */ 
  /*                      0x69, 0x6a, 0x6e, 0x64, 0x61, 0x65, 0x6c, 0x20}; */
  uint8_t input[16];
  read_from_file (text, &input[0]);

  encrypt (&input[0]);


  for (int i = 0; i<16; i++)
    {
      printf("%x ", input[i]);
    }

  return EXIT_SUCCESS;
}

/*
  The example in the README is:
plaintext :   57 68 6f 20 49 73 20 52 69 6a 6e 64 61 65 6c 20
ciphertext : 4b 95 f3 2b d1 9c ca 0a 81 64 9c 13 05 5d c9 f2
*/
