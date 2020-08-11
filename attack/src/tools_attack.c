#include "tools_attack.h"
#include "sbox.h"

#include <stdint.h> /* just to avoid but of linter because my plugin doesn't find the .h: line to suppress */

#include <stdlib.h>
#include <stdio.h>

uint8_t 
compute_difference (uint8_t state, uint8_t mod_state, uint8_t chunk_last_round_key)
  {
    uint8_t result = inv_sbox[state ^ chunk_last_round_key];
    result ^= inv_sbox[mod_state ^ chunk_last_round_key];
    return result;
  }
