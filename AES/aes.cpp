#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <string.h>
using namespace std;

#define Nb 4
int Nr = 0;
int Nk = 0;

typedef uint8_t BYTE;
unsigned char out[32], state[4][Nb];

// Input plaintext:
unsigned char in[32] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };  

unsigned char RoundKey[240];
unsigned char Key[32];
unsigned char temp[4];

int sBoxValue(int num) {
    int sbox[256] = {   0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
                        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
                        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
                        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
                        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
                        0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 
                        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
                        0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
                        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
                        0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
                        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
                        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
                        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
                        0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
                        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
                        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
                        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
                        0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
                        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
                        0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
                        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
                        0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
                        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
                        0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
                        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
                        0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
                        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
                        0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
                        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
                        0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
                        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
                        0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16   };
    return sbox[num];
}

int Rcon[52] = { 0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
                   0x10000000, 0x20000000, 0x40000000, 0x80000000,
                   0x1B000000, 0x36000000, 0x6C000000, 0xD8000000,
                   0xAB000000, 0x4D000000, 0x9A000000, 0x2F000000,
                   0x5E000000, 0xBC000000, 0x63000000, 0xC6000000,
                   0x97000000, 0x35000000, 0x6A000000, 0xD4000000,
                   0xB3000000, 0x7D000000, 0xFA000000, 0xEF000000,
                   0xC5000000, 0x91000000, 0x39000000, 0x72000000,
                   0xE4000000, 0xD3000000, 0xBD000000, 0x61000000,
                   0xC2000000, 0x9F000000, 0x25000000, 0x4A000000,
                   0x94000000, 0x33000000, 0x66000000, 0xCC000000,
                   0x83000000, 0x1D000000, 0x3A000000, 0x74000000,
                   0xE8000000, 0xCB000000, 0x8D000000 };

int invSBoxValue(int num) {
    int invSBox[256] = {
     0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb  ,
     0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb  ,
     0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e  ,
     0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25  ,
     0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92  ,
     0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84  ,
     0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06  ,
     0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b  ,
     0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73  ,
     0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e  ,
     0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b  ,
     0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4  ,
     0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f  ,
     0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef  ,
     0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61  ,
     0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d 
    };
    return invSBox[num];
}

unsigned char ffAdd(unsigned char a, unsigned char b) {
    return a ^ b;
}

unsigned char xtime(unsigned char a) {
    if (a & 0x80) {
        a = (a << 1) ^ 0x11b;
    }
    else {
        a = a << 1;
    }
    return a;
}

unsigned char ffMultiply(unsigned char a, unsigned char b) {
    unsigned char res = 0;
    while (b != 0) {
        if (b & 1) {
            res = res ^ a;
        }
        a = xtime(a);
        b = b >> 1;
    }
    return res;
}

void rotWord() {
    unsigned char k;
    k = temp[0];
    temp[0] = temp[1];
    temp[1] = temp[2];
    temp[2] = temp[3];
    temp[3] = k;
}

void subWord() {
    temp[0] = sBoxValue(temp[0]);
    temp[1] = sBoxValue(temp[1]);
    temp[2] = sBoxValue(temp[2]);
    temp[3] = sBoxValue(temp[3]);
}

void keyExpansion() {
    int i, j;
    for (i = 0; i < Nk; i++) {
        RoundKey[i * 4] = Key[i * 4];
        RoundKey[i * 4 + 1] = Key[i * 4 + 1];
        RoundKey[i * 4 + 2] = Key[i * 4 + 2];
        RoundKey[i * 4 + 3] = Key[i * 4 + 3];
    }
    i = Nk;
    while (i < (Nb * (Nr + 1))) {
        for (j = 0; j < 4; j++) {
            temp[j] = RoundKey[(i - 1) * 4 + j];
        }
        if (i % Nk == 0) {
            rotWord();
            subWord();
             temp[0] = temp[0] ^ ((Rcon[i / Nk] >> 24) & 0xff);
             temp[1] = temp[1] ^ ((Rcon[i / Nk] >> 16) & 0xff);
             temp[2] = temp[2] ^ ((Rcon[i / Nk] >> 8) & 0xff);
             temp[3] = temp[3] ^ ((Rcon[i / Nk] >> 0) & 0xff);
        } else if (Nk > 6 && i % Nk == 4) {
            subWord();
        }
        RoundKey[i * 4 + 0] = RoundKey[(i - Nk) * 4 + 0] ^ temp[0];
        RoundKey[i * 4 + 1] = RoundKey[(i - Nk) * 4 + 1] ^ temp[1];
        RoundKey[i * 4 + 2] = RoundKey[(i - Nk) * 4 + 2] ^ temp[2];
        RoundKey[i * 4 + 3] = RoundKey[(i - Nk) * 4 + 3] ^ temp[3];
        i++;
      
    }
    /*
    cout << "---------Key expansion test---------------";
    for (int i = 0; i < 240; i++) {
        printf("%02x ", RoundKey[i]);
        if (i % 8 == 0) {
            printf("\n");
        }
    }
    cout << "------------------------------";
    */
}

void addRoundKey(int round) { 
    for (int i = 0; i < Nb; i++) {
        for (int j = 0; j < 4; j++) {
            state[j][i] ^= RoundKey[round * Nb * 4 + i * Nb + j];
        }
    }
}

void subBytes() {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < Nb; j++) {
            state[i][j] = sBoxValue(state[i][j]);
        }
    }
}

void shiftRows() {
    unsigned char temp2;

    temp2 = state[1][0]; // shifting row 1
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp2;

    temp2 = state[2][0]; //  shilfting row 2
    state[2][0] = state[2][2];
    state[2][2] = temp2;
     
    temp2 = state[2][1];  // shifting row 2
    state[2][1] = state[2][3];
    state[2][3] = temp2;

    temp2 = state[3][0];  // shifting row 3
    state[3][0] = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = temp2;
}

void mixColumns() {
    unsigned char x, y, z;
    for (int i = 0; i < Nb; i++) {
        z = state[0][i];
        x = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i];
        y = state[0][i] ^ state[1][i];
        y = xtime(y);
        state[0][i] ^= y ^ x;

        y = state[1][i] ^ state[2][i];
        y = xtime(y);
        state[1][i] ^= y ^ x;

        y = state[2][i] ^ state[3][i];
        y = xtime(y);
        state[2][i] ^= y ^ x;

        y = state[3][i] ^ z;
        y = xtime(y);
        state[3][i] ^= y ^ x;
    }
}

void cipher() {
    int i, j, round = 0;

    for (i = 0; i < Nb; i++) {
        for (j = 0; j < 4; j++) {
            state[j][i] = in[i * 4 + j];
        }
    }
    printf("round[ 0].input      ");
    for (int i = 0; i < Nb; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%02x ", state[j][i]);
        }
    }
    printf("\n");

    addRoundKey(0);
    printf("round[ 0].k_sch      ");
    for (int i = 0; i < Nb; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%02x ", RoundKey[i*4+j]);
        }
    }
    printf("\n");

    for (round = 1; round < Nr; round++) {
        printf("round[ %d].start      ", round);
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < 4; j++) {
                printf("%02x ", state[j][i]);
            }
        }
        printf("\n");

        subBytes();
        printf("round[ %d].s_box      ",round);
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < 4; j++) {
                printf("%02x ", state[j][i]);
            }
        }
        printf("\n");

        shiftRows();
        printf("round[ %d].s_row      ", round);
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < 4; j++) {
                printf("%02x ", state[j][i]);
            }
        }
        printf("\n");

        mixColumns();
        printf("round[ %d].m_col      ", round);
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < 4; j++) {
                printf("%02x ", state[j][i]);
            }
        }   
        printf("\n");

        addRoundKey(round);
        printf("round[ %d].k_sch      ", round);
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < 4; j++) {
                printf("%02x ", RoundKey[round * Nb * 4 + i * Nb + j]);
            }
        }
        printf("\n");
    }

    printf("round[ %d].start     ",Nr);
    for (int i = 0; i < Nb; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%02x ", state[j][i]);
        }
    }
    printf("\n");

    subBytes();
    printf("round[ %d].s_box     ",Nr);
    for (int i = 0; i < Nb; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%02x ", state[j][i]);
        }
    }
    printf("\n");

    shiftRows();
    printf("round[ %d].s_row     ",Nr);
    for (int i = 0; i < Nb; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%02x ", state[j][i]);
        }
    }
    printf("\n");

    addRoundKey(Nr);
    printf("round[ %d].k_sch     ",Nr);
    for (int i = 0; i < Nb; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%02x ", RoundKey[round * Nb * 4 + i * Nb + j]);
        }
    }
    printf("\n");

    for (int i = 0; i < Nb; i++) {
        for (int j = 0; j < 4; j++) {
            out[i * 4 + j] = RoundKey[round * Nb * 4 + i * Nb + j];
        }
    }

    printf("round[ %d].output    ",Nr);
    for (int i = 0; i < Nb; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%02x ", state[j][i]);
        }
    }
    printf("\n");
}

void invShiftRows() {
    unsigned char temp2;

    temp2 = state[3][0];  // shifting row 3
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp2;

    temp2 = state[2][0];  // shifting row 2
    state[2][0] = state[2][2];
    state[2][2] = temp2;

    temp2 = state[2][1];  // shiftng row 2
    state[2][1] = state[2][3];
    state[2][3] = temp2;

    temp2 = state[1][0];  //shifting row 1
    state[1][0] = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = temp2;
}

void invSubBytes() {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[j][i] = invSBoxValue(state[j][i]);
        }
    }
}

void invMixColumns() {
    
    for (int i = 0; i < 4; i++) {
       unsigned char  num = state[0][i];
       unsigned char  num1 = state[1][i];
       unsigned char  num2 = state[2][i];
       unsigned char  num3 = state[3][i];

        state[0][i] = ffMultiply(num, 0x0e) ^ ffMultiply(num1, 0x0b) ^ ffMultiply(num2, 0x0d) ^ ffMultiply(num3, 0x09);
        state[1][i] = ffMultiply(num, 0x09) ^ ffMultiply(num1, 0x0e) ^ ffMultiply(num2, 0x0b) ^ ffMultiply(num3, 0x0d);
        state[2][i] = ffMultiply(num, 0x0d) ^ ffMultiply(num1, 0x09) ^ ffMultiply(num2, 0x0e) ^ ffMultiply(num3, 0x0b);
        state[3][i] = ffMultiply(num, 0x0b) ^ ffMultiply(num1, 0x0d) ^ ffMultiply(num2, 0x09) ^ ffMultiply(num3, 0x0e);
    }

}

void invCipher() {

    printf("round[ 0].iinput      ");
    for (int i = 0; i < Nb; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%02x ", state[j][i]);
        }
    }
    printf("\n");

    printf("round[ 0].ik_sch      ");
    for (int i = 0; i < Nb; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%02x ", RoundKey[Nr * Nb * 4 + i * Nb + j]);
        }
    }
    printf("\n");

    addRoundKey(Nr);

    for (int round = Nr - 1; round > 0; --round) { // Decryption for Nr-1 rounds
        printf("round[ %d].istart      ",Nr-round);
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < 4; j++) {
                printf("%02x ", state[j][i]);
            }
        }
        printf("\n");

        invShiftRows();
        printf("round[ %d].is_row      ",Nr-round);
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < 4; j++) {
                printf("%02x ", state[j][i]);
            }
        }
        printf("\n");

        invSubBytes();
        printf("round[ %d].is_box      ",Nr-round);
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < 4; j++) {
                printf("%02x ", state[j][i]);
            }
        }
        printf("\n");

        printf("round[ %d].ik_sch      ",Nr-round);
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < 4; j++) {
                printf("%02x ", RoundKey[(round) * Nb * 4 + i * Nb + j]);
            }
        }
        printf("\n");

        addRoundKey(round);
        printf("round[ %d].ik_add      ",Nr-round);
        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < 4; j++) {
                printf("%02x ", state[j][i]);
            }
        }
        printf("\n");

        invMixColumns();
    }
    printf("round[ %d].istart     ", Nr);
    for (int i = 0; i < Nb; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%02x ", state[j][i]);
        }
    }
    printf("\n");


    invShiftRows();
    printf("round[ %d].is_row     ", Nr);
    for (int i = 0; i < Nb; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%02x ", state[j][i]);
        }
    }
    printf("\n");

    invSubBytes();
    printf("round[ %d].is_box     ", Nr);
    for (int i = 0; i < Nb; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%02x ", state[j][i]);
        }
    }
    printf("\n");

    addRoundKey(0);
    printf("round[ %d].ik_sch     ", Nr);
    for (int i = 0; i < Nb; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%02x ", RoundKey[i * Nb + j]);
        }
    }
    printf("\n");

    printf("round[ %d].output     ", Nr);
    for (int i = 0; i < Nb; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%02x ", state[j][i]);
        }
    }
    printf("\n");
}


int main(int argc, char** argv) {
    
  // UNIT TESTS
  // FINITE FIELD ARITHMETIC 
      
  //  printf("%x\n", ffAdd(0x57, 0x83));  //    ffAdd(0x57, 0x83) == 0xd4;
  //  printf("%x\n", xtime(0x57));        //    xtime(0x57) == 0xae  
  //  printf("%x\n", xtime(0xae));        //    xtime(0xae) == 0x47
  //  printf("%x\n", xtime(0x47));        //    xtime(0x47) == 0x8e
  //  printf("%02x\n", xtime(0x8e));      //    xtime(0x8e) == 0x07
    
    int i, num;
    cout << "Select : \n 1 for 128 bits\n 2 for 192 bits\n 3 for 256 bits \n";
    cin >> num;

    if (num == 1) {
        Nk = 4;
    }
    else if (num == 2) {
        Nk = 6;
    }
    else if (num == 3) {
        Nk = 8;
    }
    else {
        cout << "Invalid...";
    }
 
    Nr = Nk + 6;

    // Intializing Key Values of Nk=4, 6 and 8
    if (Nk == 4) {
        Key[0] = 0x00;  Key[1] = 0x01;  Key[2] = 0x02;  Key[3] = 0x03;
        Key[4] = 0x04;  Key[5] = 0x05;  Key[6] = 0x06;  Key[7] = 0x07;
        Key[8] = 0x08;  Key[9] = 0x09;  Key[10] = 0x0a;  Key[11] = 0x0b;
        Key[12] = 0x0c;  Key[13] = 0x0d;  Key[14] = 0x0e;  Key[15] = 0x0f;
    }
    if (Nk == 6) {
        Key[0] = 0x00;  Key[1] = 0x01;  Key[2] = 0x02;  Key[3] = 0x03;
        Key[4] = 0x04;  Key[5] = 0x05;  Key[6] = 0x06;  Key[7] = 0x07;
        Key[8] = 0x08;  Key[9] = 0x09;  Key[10] = 0x0a;  Key[11] = 0x0b;
        Key[12] = 0x0c;  Key[13] = 0x0d;  Key[14] = 0x0e;  Key[15] = 0x0f;
        Key[16] = 0x10; Key[17] = 0x11; Key[18] = 0x12; Key[19] = 0x13;
        Key[20] = 0x14; Key[21] = 0x15; Key[22] = 0x16; Key[23] = 0x17;
    }
    if (Nk == 8) {
        Key[0] = 0x00;  Key[1] = 0x01;  Key[2] = 0x02;  Key[3] = 0x03;
        Key[4] = 0x04;  Key[5] = 0x05;  Key[6] = 0x06;  Key[7] = 0x07;
        Key[8] = 0x08;  Key[9] = 0x09;  Key[10] = 0x0a; Key[11] = 0x0b;
        Key[12] = 0x0c; Key[13] = 0x0d; Key[14] = 0x0e; Key[15] = 0x0f;
        Key[16] = 0x10; Key[17] = 0x11; Key[18] = 0x12; Key[19] = 0x13;
        Key[20] = 0x14; Key[21] = 0x15; Key[22] = 0x16; Key[23] = 0x17;
        Key[24] = 0x18; Key[25] = 0x19; Key[26] = 0x1a; Key[27] = 0x1b;
        Key[28] = 0x1c; Key[29] = 0x1d; Key[30] = 0x1e; Key[31] = 0x1f;
    }
    

    keyExpansion();
        cout << "\nCIPHER (ENCRYPT) :\n";
    cipher();
        cout << "\nINVERSE CIPHER (DECRYPT) :\n";
    invCipher();
    
}
