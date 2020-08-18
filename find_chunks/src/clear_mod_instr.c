uint8_t key_schedule_clear_mod_instr[16 * 11];
uint8_t key_clear_mod_instr[16] = {1,2,3,4,2,3,4,5,3,4,5,6,4,5,6,7};
uint8_t mod_state[4][4];
  for (int j = 0; j < 4; j++)
    for (int i = 0; i < 4; i++)
    {
      mod_state[i][j] = 0;
    }
  mod_state[0][0] = 1;
  mod_state[0][1] = 2;
  mod_state[2][2] = 100;
  mod_state[3][3] = 10;

key_expansion (key_clear_mod_instr, key_schedule_clear_mod_instr);

  /* Start enciphering */
  add_round_key (mod_state, key_schedule_clear_mod_instr, 0);

  for (int round = 1; round < 10; ++round)
    {

      sub_bytes (mod_state);
      shift_row (mod_state);
      if (round == 8)
	{
	  mod_state[0][0] = byte_error_1;  /* byte_error is my random value : D */
	}
      /* if (round == 9) */
	/* { */
	  /* fprintf(stderr, "The mod_mod_state just before the last mix_column\n"); */
	  /* print_state(mod_state); */
	  /* fprintf(stderr, "\n"); */
	/* } */
      mix_columns (mod_state);
      /* if (round == 8) */
	/* { */
	  /* fprintf(stderr, "The mod_mod_state just after the mix_column of round 8\n"); */
	  /* print_state(mod_state); */
	  /* fprintf(stderr, "\n"); */
	/* } */
      add_round_key (mod_state, key_schedule_clear_mod_instr, round);
    }

  sub_bytes (mod_state);
  shift_row (mod_state);
  add_round_key (mod_state, key_schedule_clear_mod_instr, 10);

  for (int j = 0; j < 4; j++)
    for (int i = 0; i < 4; i++)
    {
      buffer[4 * j + i] = mod_state[i][j];
    }

fprintf(stderr, "The mod_state at the end of clear_mod_instr\n"); // to suppress
print_state(mod_state); // to supress
