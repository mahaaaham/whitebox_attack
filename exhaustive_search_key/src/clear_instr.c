uint8_t key_schedule_clear_instr[16 * 11];
uint8_t key_clear_instr[16] = {1,2,3,4,2,3,4,5,3,4,5,6,4,5,6,7};
uint8_t state[4][4] = {{0, 1, 2, 3} ,{4, 5 ,6 ,7} , {8, 9, 10, 11}, {12, 13, 14, 15}};

key_expansion (key_clear_instr, key_schedule_clear_instr);

  /* Start enciphering */
  add_round_key (state, key_schedule_clear_instr, 0);

  for (int round = 1; round < 10; ++round)
    {
      sub_bytes (state);
      shift_row (state);
      mix_columns (state);
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
