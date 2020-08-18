/* #include "cipher.h" */
/* #include "state.h" */
#include "dcomputation.h"

// #include <fcntl.h>
//#include <getopt.h>
#include <string.h>
//#include <unistd.h>
#include <stdint.h> /* for uint8_t */
#include <inttypes.h>

#include <stdlib.h>
#include <stdio.h>

#define BINARY (strrchr (argv[0], '/') + 1)

#define EXIT(message, ...)						\
  do									\
    {									\
      fprintf (stderr, "%s: " message ".\n", BINARY, __VA_ARGS__);	\
      exit (EXIT_FAILURE);						\
    }									\
  while (0)

static int32_t compare (void const *a, void const *b)
{
   /* definir des pointeurs type's et initialise's
      avec les parametres */
   uint32_t const *pa = a;
   uint32_t const *pb = b;
 
   /* evaluer et retourner l'etat de l'evaluation (tri croissant) */
   if (*pa < *pb)
     return (-1);
   if (*pa == *pb)
     return 0;
   else
     return 1;
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


/* mix_column and not mix_columns because it is only in one column */
/* Compute mix_column on input_column and write the result on output_column */
void
mix_column (uint8_t *input_column, uint8_t *output_column)
{
  uint8_t s0 = rijndael_mult (0x02, input_column[0])
    ^ rijndael_mult (0x03, input_column[1])
    ^ input_column[2]
    ^ input_column[3];
  uint8_t s1 = input_column[0]
    ^ rijndael_mult (0x02, input_column[1])
    ^ rijndael_mult (0x03, input_column[2])
    ^ input_column[3];
  uint8_t s2 = input_column[0]
    ^ input_column[1]
    ^ rijndael_mult (0x02, input_column[2])
    ^ rijndael_mult (0x03, input_column[3]);
  uint8_t s3 = rijndael_mult (0x03, input_column[0]) 
    ^ input_column[1]
    ^ input_column[2] 
    ^ rijndael_mult (0x02, input_column[3]);

    output_column[0] = s0;
    output_column[1] = s1;
    output_column[2] = s2;
    output_column[3] = s3;
}


void 
inv_mix_columns (uint8_t **state)
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


/* Allocates memory for the state.
 * Returns a pointer to it or NULL if the allocation fails */
uint8_t *
column_alloc ()
{ 
  uint8_t *column = (uint8_t *) malloc ( 4 * sizeof (uint8_t)); 
  if (!column)
    return NULL;
  
  return column; 
}


/* Compute D_one, D_two, D_three and D_four as array in the file "dtables.h". */
int
main (int argc, char *argv[])
{
  uint32_t result[256]; /* hold the number that are written in the arrays */
  for (int i = 0; i < 256; i++)
    result[i] = 0; 


  FILE *fd = fopen ("dtables.h", "w"); /* The file were we write the array */
  if (!fd)
    EXIT ("%s", "cannot open dtables.h");

  /* We write the header of dtables.h" */
  fprintf (fd, "#ifndef DTABLES_H\n");
  fprintf (fd, "#define DTABLES_H\n\n");
  fprintf (fd, "#include <stdint.h>\n");
  fprintf (fd, "/*Contains the following lookup tables used to attack the AES Whitebox:*/\n");
  fprintf (fd, "/* done, dtwo, dthree, dfour. */\n\n");

  /* allocation of the two columns and set to 0 */
  uint8_t *input_column = column_alloc ();
  uint8_t *output_column = column_alloc ();
  if ((!input_column) || (!output_column))
    EXIT ("%s", "Problème d'allocation d'une des colonnes");
  for (int i = 0; i < 4; ++i) 
    {
      input_column[i] = 0; 
      output_column[i] = 0;
    }

  /* computation and writing of done */
  fprintf (fd, "uint32_t done[256] = { \n");
  for (int value = 0; value < 256; ++value)
    {
      input_column[0] = value;
      mix_column(input_column, output_column);

      result[value] = (((uint32_t)output_column[3]) << 24) + (((uint32_t)output_column[2]) << 16)
	       + (((uint32_t)output_column[1]) << 8) + (uint32_t)output_column[0];
    }
  /* sort of the array */
  qsort (result, 256, sizeof(uint32_t), compare);

  /* writing of the array */
  for (int value = 0; value < 128; ++value)
    {
	fprintf (fd, " 0x%"PRIx32 ",", result[2*value]);
	fprintf (fd, " 0x%"PRIx32 ",\n", result[2*value+1]);
    }
  fprintf (fd, "};\n\n");

  input_column[0] = 0;
  for (int value = 0; value < 256; ++value)
    {
      result[value] = 0;
    }


  /* computation and writing of dtwo */
  fprintf (fd, "uint32_t dtwo[256] = { \n");
  for (int value = 0; value <  256; ++value)
    {
      input_column[1] = value;
      mix_column(input_column, output_column);
      result[value] = (((uint32_t)output_column[3]) << 24) + (((uint32_t)output_column[2]) << 16)
	       + (((uint32_t)output_column[1]) << 8) + (uint32_t)output_column[0];
    }
  /* sort of the array */
  qsort (result, 256, sizeof(uint32_t), compare);

  /* writing of the array */
  for (int value = 0; value < 128; ++value)
    {
	fprintf (fd, " 0x%"PRIx32 ",", result[2*value]);
	fprintf (fd, " 0x%"PRIx32 ",\n", result[2*value + 1]);
    }
  fprintf (fd, "};\n\n");

  for (int value = 0; value < 256; ++value)
    {
      result[value] = 0;
    }

  input_column[0] = 0;
  input_column[1] = 0;
  /* computation and writing of dthree */
  fprintf (fd, "uint32_t dthree[256] = {\n");
  for (int value = 0; value < 256; ++value)
    {
      input_column[2] = value;
      mix_column(input_column, output_column);
      result[value] = (((uint32_t)output_column[3]) << 24) + (((uint32_t)output_column[2]) << 16)
	       + (((uint32_t)output_column[1]) << 8) + (uint32_t)output_column[0];
    }
  /* sort of the array */
  qsort (result, 256, sizeof(uint32_t), compare);

  /* writing of the array */
  for (int value = 0; value < 128; ++value)
    {
	fprintf (fd, " 0x%"PRIx32 ",", result[2*value]);
	fprintf (fd, " 0x%"PRIx32 ",\n", result[2*value + 1]);
    }
  fprintf (fd, "};\n\n");
  
  input_column[0] = 0;
  input_column[1] = 0;
  input_column[2] = 0;
  for (int value = 0; value < 256; ++value)
    {
      result[value] = 0;
    }



  /* computation and writing of dfour */
  fprintf (fd, "uint32_t dfour[256] = {\n");
  for (int value = 0; value < 256; ++value)
    {
      input_column[3] = value;
      mix_column(input_column, output_column);
      result[value] = (((uint32_t)output_column[3]) << 24) + (((uint32_t)output_column[2]) << 16)
	       + (((uint32_t)output_column[1]) << 8) + (uint32_t)output_column[0];
    }
  /* sort of the array */
  qsort (result, 256, sizeof(uint32_t), compare);

  /* writing of the array */
  for (int value = 0; value < 128; ++value)
    {
	fprintf (fd, " 0x%"PRIx32 ",", result[2*value]);
	fprintf (fd, " 0x%"PRIx32 ",\n", result[2*value + 1]);
    }
  fprintf (fd, "};\n\n");

  for (int value = 0; value < 256; ++value)
    {
      result[value] = 0;
    }


  /* End of dtable.h */
  fprintf (fd, "\n#endif /* DTABLES_H */");

  /* free the allocated spaces */
  free (input_column);
  free (output_column);

  return EXIT_SUCCESS;
}
