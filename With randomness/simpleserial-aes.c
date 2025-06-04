#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define d 1

// External functions from assembly implementation
extern void AES_one_round_pre(void);
extern void AES_one_round_online(void);

// External variables from tables.c
extern unsigned int plain[16];
extern unsigned int plain_masked_1[d+1];
extern unsigned int plain_masked_2[d+1];
extern unsigned int plain_masked_3[d+1];
extern unsigned int plain_masked_4[d+1];
extern unsigned int plain_masked_5[d+1];
extern unsigned int plain_masked_6[d+1];
extern unsigned int plain_masked_7[d+1];
extern unsigned int plain_masked_8[d+1];
extern unsigned int plain_masked_9[d+1];
extern unsigned int plain_masked_10[d+1];
extern unsigned int plain_masked_11[d+1];
extern unsigned int plain_masked_12[d+1];
extern unsigned int plain_masked_13[d+1];
extern unsigned int plain_masked_14[d+1];
extern unsigned int plain_masked_15[d+1];
extern unsigned int plain_masked_16[d+1];
extern unsigned int cipher[16];

extern unsigned int random_1[16*d*2];
extern unsigned int random_2[16*d*d*d*2];
extern unsigned int random_3[16*d*d*2];

// LCG structure and state
typedef struct {
    uint32_t state;
} lcg_t;

static lcg_t global_lcg = {1}; // Default seed

// LCG function - simple and fast
static uint32_t lcg_next(lcg_t* rng) {
    rng->state = (1103515245 * rng->state + 12345);
    // Simple bit rotation for better distribution
    uint32_t result = rng->state;
    return ((result << 13) | (result >> 19)) & 0xFF;
}

// Fill random_1 array
void fill_random_1(uint32_t seed) {
    if (seed != 0) global_lcg.state = seed;
    
    for (int i = 0; i < 16*d*2; i++) {
        random_1[i] = lcg_next(&global_lcg) & 0xFF; // Keep in byte range
    }
}

// Fill random_2 array  
void fill_random_2(uint32_t seed) {
    if (seed != 0) global_lcg.state = seed;
    
    for (int i = 0; i < 16*d*d*d*2; i++) {
        random_2[i] = lcg_next(&global_lcg) & 0xFF; // Keep in byte range
    }
}

// Fill random_3 array
void fill_random_3(uint32_t seed) {
    if (seed != 0) global_lcg.state = seed;
    
    for (int i = 0; i < 16*d*d*2; i++) {
        random_3[i] = lcg_next(&global_lcg) & 0xFF; // Keep in byte range
    }
}

// Fill all arrays with same or different seeds
void fill_all_random_arrays(uint32_t seed) {
    global_lcg.state = seed ? seed : 12345; // Use provided seed or default
    
    // Fill all arrays sequentially with same LCG stream
    fill_random_1(0); // 0 means don't reset seed
    //fill_random_2(0);  
    fill_random_3(0);
}

uint8_t get_seed(uint8_t* seed_data, uint8_t len) {
    // Combine 4 bytes into uint32_t (big-endian)
    uint32_t result = (seed_data[0] << 24) | (seed_data[1] << 16) | 
                     (seed_data[2] << 8)  | seed_data[3];
    fill_all_random_arrays(result);
    return 0;  // Error: insufficient data
}

uint8_t get_pt(uint8_t* pt, uint8_t len)
{
    // Copy plaintext into buffer
    plain[0] = pt[0]; plain[1] = pt[1]; plain[2] = pt[2]; plain[3] = pt[3]; // Column 0
    plain[4] = pt[4]; plain[5] = pt[5]; plain[6] = pt[6]; plain[7] = pt[7]; // Column 1  
    plain[8] = pt[8]; plain[9] = pt[9]; plain[10] = pt[10]; plain[11] = pt[11]; // Column 2
    plain[12] = pt[12]; plain[13] = pt[13]; plain[14] = pt[14]; plain[15] = pt[15]; // Column 3


    //trigger_high();
    AES_one_round_pre(); 
    trigger_high();
    AES_one_round_online();
    //int a = 30 + 10;
    trigger_low();

    // Copy result from masked output (adjust based on your actual output location)
    // Column 0
    cipher[0] = (plain_masked_1[0] ^ plain_masked_1[1]) & 0xFF;
    cipher[1] = (plain_masked_2[0] ^ plain_masked_2[1]) & 0xFF;
    cipher[2] = (plain_masked_3[0] ^ plain_masked_3[1]) & 0xFF;
    cipher[3] = (plain_masked_4[0] ^ plain_masked_4[1]) & 0xFF;
    cipher[4] = (plain_masked_5[0] ^ plain_masked_5[1]) & 0xFF;
    cipher[5] = (plain_masked_6[0] ^ plain_masked_6[1]) & 0xFF;
    cipher[6] = (plain_masked_7[0] ^ plain_masked_7[1]) & 0xFF;
    cipher[7] = (plain_masked_8[0] ^ plain_masked_8[1]) & 0xFF;
    cipher[8] = (plain_masked_9[0] ^ plain_masked_9[1]) & 0xFF;
    cipher[9] = (plain_masked_10[0] ^ plain_masked_10[1]) & 0xFF;
    cipher[10] = (plain_masked_11[0] ^ plain_masked_11[1]) & 0xFF;
    cipher[11] = (plain_masked_12[0] ^ plain_masked_12[1]) & 0xFF;
    cipher[12] = (plain_masked_13[0] ^ plain_masked_13[1]) & 0xFF;
    cipher[13] = (plain_masked_14[0] ^ plain_masked_14[1]) & 0xFF;
    cipher[14] = (plain_masked_15[0] ^ plain_masked_15[1]) & 0xFF;
    cipher[15] = (plain_masked_16[0] ^ plain_masked_16[1]) & 0xFF;
    
    //memcpy(pt, cipher, 16);
    uint8_t output[16];
    for(int i = 0; i < 16; i++) {
        output[i] = (uint8_t)cipher[i];  // Convert each byte to a full integer
    }
    simpleserial_put('r', 16, output);

    return 0x00;
}

uint8_t reset(uint8_t* x, uint8_t len)
{
    // Reset security state if needed
    return 0x00;
}

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();

    /* Initialize masked AES state */
    // Add any required initialization code from your tables.c
    
    simpleserial_init();
    simpleserial_addcmd('s', 4, get_seed);
    simpleserial_addcmd('p', 16, get_pt);
    simpleserial_addcmd('x', 0, reset);
    /* simpleserial_addcmd_flags('m', 64, get_mask, CMD_FLAG_LEN); // Adjust mask length as needed */

    while(1)
        simpleserial_get();
}
