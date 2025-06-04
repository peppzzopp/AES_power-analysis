#include <stdint.h>
typedef uint8_t byte;

#define d 1

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
extern unsigned int MixColumns_table_2[256];
extern unsigned int MixColumns_table_3[256];

void mixcolumns_share(byte *stateshare[16],int n)
{
  byte ns[16];
  int i,j;
  for(i=0;i<n;i++)
  {
    for(j=0;j<4;j++)
    {
      ns[j*4]=multx(stateshare[j*4][i]) ^ multx(stateshare[j*4+1][i]) ^ stateshare[j*4+1][i] ^ stateshare[j*4+2][i] ^ stateshare[j*4+3][i];
      ns[j*4+1]=stateshare[j*4][i] ^ multx(stateshare[j*4+1][i]) ^ multx(stateshare[j*4+2][i]) ^ stateshare[j*4+2][i] ^ stateshare[j*4+3][i];
      ns[j*4+2]=stateshare[j*4][i] ^ stateshare[j*4+1][i] ^ multx(stateshare[j*4+2][i]) ^ multx(stateshare[j*4+3][i]) ^ stateshare[j*4+3][i];
      ns[j*4+3]=multx(stateshare[j*4][i]) ^ stateshare[j*4][i] ^ stateshare[j*4+1][i] ^ stateshare[j*4+2][i] ^ multx(stateshare[j*4+3][i]) ;
    }
    for(j=0;j<16;j++)
      stateshare[j][i]=ns[j];
  }
}

void shiftrows_share(byte *stateshare[16],int n)
{
  byte m;
  int i;
  for(i=0;i<n;i++)
  {
    m=stateshare[1][i];
    stateshare[1][i]=stateshare[5][i];
    stateshare[5][i]=stateshare[9][i];
    stateshare[9][i]=stateshare[13][i];
    stateshare[13][i]=m;

    m=stateshare[2][i];
    stateshare[2][i]=stateshare[10][i];
    stateshare[10][i]=m;
    m=stateshare[6][i];
    stateshare[6][i]=stateshare[14][i];
    stateshare[14][i]=m;

    m=stateshare[3][i];
    stateshare[3][i]=stateshare[15][i];
    stateshare[15][i]=stateshare[11][i];
    stateshare[11][i]=stateshare[7][i];
    stateshare[7][i]=m;
  }
}

void MixColumns_share_adapted() {
    uint8_t temp_state[16];
    int share_idx, col_idx;
    
    // Create array of pointers to your global arrays for easier access
    uint32_t *byte_arrays[16] = {
        plain_masked_1,  plain_masked_2,  plain_masked_3,  plain_masked_4,
        plain_masked_5,  plain_masked_6,  plain_masked_7,  plain_masked_8,
        plain_masked_9,  plain_masked_10, plain_masked_11, plain_masked_12,
        plain_masked_13, plain_masked_14, plain_masked_15, plain_masked_16
    };
    
    // Process each share (4 shares total since d=3, so d+1=4)
    for(share_idx = 0; share_idx < d+1; share_idx++) {
        // Process each column (4 columns in AES)
        for(col_idx = 0; col_idx < 4; col_idx++) {
            // Apply MixColumns matrix to each column using your lookup tables
            // Column col_idx contains bytes: col_idx*4, col_idx*4+1, col_idx*4+2, col_idx*4+3
            
            // Extract current share values for this column
            uint8_t b0 = (uint8_t)(byte_arrays[col_idx*4][share_idx] & 0xFF);
            uint8_t b1 = (uint8_t)(byte_arrays[col_idx*4+1][share_idx] & 0xFF);
            uint8_t b2 = (uint8_t)(byte_arrays[col_idx*4+2][share_idx] & 0xFF);
            uint8_t b3 = (uint8_t)(byte_arrays[col_idx*4+3][share_idx] & 0xFF);
            
            // Apply MixColumns transformation using your existing tables
            temp_state[col_idx*4]   = MixColumns_table_2[b0] ^ MixColumns_table_3[b1] ^ b2 ^ b3;
            temp_state[col_idx*4+1] = b0 ^ MixColumns_table_2[b1] ^ MixColumns_table_3[b2] ^ b3;
            temp_state[col_idx*4+2] = b0 ^ b1 ^ MixColumns_table_2[b2] ^ MixColumns_table_3[b3];
            temp_state[col_idx*4+3] = MixColumns_table_3[b0] ^ b2 ^ b1 ^ MixColumns_table_2[b3];
        }
        
        // Store results back to global arrays
        for(int byte_idx = 0; byte_idx < 16; byte_idx++) {
            // Clear the byte and store new value
            byte_arrays[byte_idx][share_idx] = (byte_arrays[byte_idx][share_idx] & 0xFFFFFF00) | temp_state[byte_idx];
        }
    }
}

void ShiftRows_share_adapted() {
    uint8_t temp;
    int share_idx;
    
    // Create array of pointers to your global arrays for easier access
    uint32_t *byte_arrays[16] = {
        plain_masked_1,  plain_masked_2,  plain_masked_3,  plain_masked_4,
        plain_masked_5,  plain_masked_6,  plain_masked_7,  plain_masked_8,
        plain_masked_9,  plain_masked_10, plain_masked_11, plain_masked_12,
        plain_masked_13, plain_masked_14, plain_masked_15, plain_masked_16
    };
    
    // Process each share (4 shares total since d=3, so d+1=4)
    for(share_idx = 0; share_idx < d+1; share_idx++) {
        // Row 1: Shift left by 1 position
        // Positions: 1->5->9->13->1
        temp = (uint8_t)(byte_arrays[1][share_idx] & 0xFF);
        byte_arrays[1][share_idx] = (byte_arrays[1][share_idx] & 0xFFFFFF00) | (byte_arrays[5][share_idx] & 0xFF);
        byte_arrays[5][share_idx] = (byte_arrays[5][share_idx] & 0xFFFFFF00) | (byte_arrays[9][share_idx] & 0xFF);
        byte_arrays[9][share_idx] = (byte_arrays[9][share_idx] & 0xFFFFFF00) | (byte_arrays[13][share_idx] & 0xFF);
        byte_arrays[13][share_idx] = (byte_arrays[13][share_idx] & 0xFFFFFF00) | temp;
        
        // Row 2: Shift left by 2 positions  
        // Positions: 2->10->2 and 6->14->6
        temp = (uint8_t)(byte_arrays[2][share_idx] & 0xFF);
        byte_arrays[2][share_idx] = (byte_arrays[2][share_idx] & 0xFFFFFF00) | (byte_arrays[10][share_idx] & 0xFF);
        byte_arrays[10][share_idx] = (byte_arrays[10][share_idx] & 0xFFFFFF00) | temp;
        
        temp = (uint8_t)(byte_arrays[6][share_idx] & 0xFF);
        byte_arrays[6][share_idx] = (byte_arrays[6][share_idx] & 0xFFFFFF00) | (byte_arrays[14][share_idx] & 0xFF);
        byte_arrays[14][share_idx] = (byte_arrays[14][share_idx] & 0xFFFFFF00) | temp;
        
        // Row 3: Shift left by 3 positions (equivalent to shift right by 1)
        // Positions: 3->15->11->7->3
        temp = (uint8_t)(byte_arrays[3][share_idx] & 0xFF);
        byte_arrays[3][share_idx] = (byte_arrays[3][share_idx] & 0xFFFFFF00) | (byte_arrays[15][share_idx] & 0xFF);
        byte_arrays[15][share_idx] = (byte_arrays[15][share_idx] & 0xFFFFFF00) | (byte_arrays[11][share_idx] & 0xFF);
        byte_arrays[11][share_idx] = (byte_arrays[11][share_idx] & 0xFFFFFF00) | (byte_arrays[7][share_idx] & 0xFF);
        byte_arrays[7][share_idx] = (byte_arrays[7][share_idx] & 0xFFFFFF00) | temp;
        
        // Row 0 (positions 0, 4, 8, 12) stays unchanged - no shift needed
    }
}