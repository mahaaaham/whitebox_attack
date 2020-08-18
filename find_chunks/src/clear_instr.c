uint8_t key_schedule_clear_instr[16 * 11];
uint8_t key_clear_instr[16] = {1,2,3,4,2,3,4,5,3,4,5,6,4,5,6,7};
uint8_t state[4][4];

  for (int j = 0; j < 4; j++)
    for (int i = 0; i < 4; i++)
    {
      state[i][j] = 0;
    }
  state[0][0] = 1;
  state[0][1] = 2;
  state[2][2] = 100;
  state[3][3] = 10;

key_expansion (key_clear_instr, key_schedule_clear_instr);

  /* Start enciphering */
  add_round_key (state, key_schedule_clear_instr, 0);

  for (int round = 1; round < 10; ++round)
    {
      sub_bytes (state);
      shift_row (state);
      /* if (round == 9) */
	/* { */
	  /* fprintf(stderr, "The state just before the last mix_column\n"); */
	  /* print_state(state); */
	  /* fprintf(stderr, "\n"); */
	/* } */
      mix_columns (state);
      /* if (round == 8) */
	/* { */
	  /* fprintf(stderr, "The mod_state just after the mix_column of round 8\n"); */
	  /* print_state(state); */
	  /* fprintf(stderr, "\n"); */
	/* } */
      add_round_key (state, key_schedule_clear_instr, round);
    }

  sub_bytes (state);
  shift_row (state);
  add_round_key (state, key_schedule_clear_instr, 10);

  for (int j = 0; j < 4; j++)
    for (int i = 0; i < 4; i++)
    {
      buffer[4 * j + i] = state[i][j];
    }

fprintf(stderr, "The end of the state\n");
print_state(state);
fprintf(stderr, "\n");
