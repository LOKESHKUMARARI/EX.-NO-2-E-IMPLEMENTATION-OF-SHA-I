# EX.-NO-2-E-IMPLEMENTATION-OF-SHA-I

## AIM:
  To implement the SHA-I hashing technique using C program.
  
## ALGORITHM:

  STEP-1: Read the 256-bit key values.
  
  STEP-2: Divide into five equal-sized blocks named A, B, C, D and E.
  
  STEP-3: The blocks B, C and D are passed to the function F.
  
  STEP-4: The resultant value is permuted with block E.
  
  STEP-5: The block A is shifted right by ‘s’ times and permuted with the result of
  
  
  STEP-6: Then it is permuted with a weight value and then with some other key pair and taken as the first block.
  
  STEP-7: Block A is taken as the second block and the block B is shifted by ‘s’ times and taken as the third block.
  
  STEP-8: The blocks C and D are taken as the block D and E for the final output.

## PROGRAM:
```
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define SHA1_BLOCK_SIZE 20 // SHA1 outputs a 20 byte digest

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
} SHA1_CTX;

void SHA1Transform(uint32_t state[5], const uint8_t buffer[64]);
void SHA1Init(SHA1_CTX *context);
void SHA1Update(SHA1_CTX *context, const uint8_t *data, uint32_t len);
void SHA1Final(uint8_t digest[SHA1_BLOCK_SIZE], SHA1_CTX *context);
void SHA1(const uint8_t *data, size_t len, uint8_t hash[SHA1_BLOCK_SIZE]);

#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))

void SHA1Transform(uint32_t state[5], const uint8_t buffer[64]) {
    uint32_t a, b, c, d, e, t, i;
    uint32_t block[80];

    for (i = 0; i < 16; ++i) {
        block[i] = (buffer[i*4] << 24) | (buffer[i*4+1] << 16) | (buffer[i*4+2] << 8) | (buffer[i*4+3]);
    }
    for (; i < 80; ++i) {
        block[i] = ROTLEFT(block[i-3] ^ block[i-8] ^ block[i-14] ^ block[i-16], 1);
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    for (i = 0; i < 80; ++i) {
        if (i < 20) {
            t = ROTLEFT(a, 5) + ((b & c) | (~b & d)) + e + block[i] + 0x5A827999;
        } else if (i < 40) {
            t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + block[i] + 0x6ED9EBA1;
        } else if (i < 60) {
            t = ROTLEFT(a, 5) + ((b & c) | (b & d) | (c & d)) + e + block[i] + 0x8F1BBCDC;
        } else {
            t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + block[i] + 0xCA62C1D6;
        }

        e = d;
        d = c;
        c = ROTLEFT(b, 30);
        b = a;
        a = t;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

void SHA1Init(SHA1_CTX *context) {
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;

    context->count[0] = 0;
    context->count[1] = 0;
}

void SHA1Update(SHA1_CTX *context, const uint8_t *data, uint32_t len) {
    uint32_t i, j;

    j = (context->count[0] >> 3) & 63;
    if ((context->count[0] += len << 3) < (len << 3)) context->count[1]++;
    context->count[1] += (len >> 29);

    if ((j + len) > 63) {
        memcpy(&context->buffer[j], data, (i = 64-j));
        SHA1Transform(context->state, context->buffer);
        for (; i + 63 < len; i += 64) {
            SHA1Transform(context->state, &data[i]);
        }
        j = 0;
    } else i = 0;

    memcpy(&context->buffer[j], &data[i], len - i);
}

void SHA1Final(uint8_t digest[SHA1_BLOCK_SIZE], SHA1_CTX *context) {
    uint8_t finalcount[8];
    uint8_t c;

    for (int i = 0; i < 8; i++) {
        finalcount[i] = (uint8_t)((context->count[(i >= 4 ? 0 : 1)]
                        >> ((3-(i & 3)) * 8) ) & 255);
    }

    c = 0x80;
    SHA1Update(context, &c, 1);
    while ((context->count[0] & 504) != 448) {
        c = 0x00;
        SHA1Update(context, &c, 1);
    }

    SHA1Update(context, finalcount, 8);
    for (int i = 0; i < SHA1_BLOCK_SIZE; i++) {
        digest[i] = (uint8_t)
            ((context->state[i>>2] >> ((3-(i & 3)) * 8)) & 255);
    }
}

void SHA1(const uint8_t *data, size_t len, uint8_t hash[SHA1_BLOCK_SIZE]) {
    SHA1_CTX context;
    SHA1Init(&context);
    SHA1Update(&context, data, len);
    SHA1Final(hash, &context);
}

int main() {
    const char *str = "Hello, SHA-1!";
    uint8_t hash[SHA1_BLOCK_SIZE];
    
    SHA1((const uint8_t*)str, strlen(str), hash);
    
    printf("SHA-1 hash: ");
    for (int i = 0; i < SHA1_BLOCK_SIZE; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
    
    return 0;
}
``` 

## OUTPUT:

![image](https://github.com/user-attachments/assets/d59d5a2b-f897-48ff-ad57-aa193c2a34fa)


## RESULT:
  Thus the SHA-1 hashing technique had been implemented successfully.
  
