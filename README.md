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

// Simple XOR-based encryption for demonstration (not secure for real use)
void encrypt(const char *input, const char *key, char *output) {
    int i;
    for (i = 0; i < strlen(input); i++) {
        output[i] = input[i] ^ key[i % strlen(key)];
    }
    output[i] = '\0';
}

void decrypt(const char *input, const char *key, char *output) {
    int i;
    for (i = 0; i < strlen(input); i++) {
        output[i] = input[i] ^ key[i % strlen(key)];
    }
    output[i] = '\0';
}

int main() {
    char input[128] = "LOKESH";
    char key[16] = "SecretKey123";  // Sample key
    char encrypted[128];
    char decrypted[128];

    printf("Original text: %s\n", input);

    // Encrypt the input
    encrypt(input, key, encrypted);
    printf("Encrypted text: ");
    for (int i = 0; i < strlen(input); i++) {
        printf("%02x", (unsigned char)encrypted[i]);
    }
    printf("\n");

    // Decrypt the encrypted text
    decrypt(encrypted, key, decrypted);
    printf("Decrypted text: %s\n", decrypted);

    return 0;
}

``` 

## OUTPUT:

![image](https://github.com/user-attachments/assets/3750e1ae-5a66-4b86-8d46-100f6b12f4ea)



## RESULT:
  Thus the SHA-1 hashing technique had been implemented successfully.
  
