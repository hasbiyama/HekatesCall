/*
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// gcc -s -static -O3 -o strXOR strXOR.c

void encrypt(char *str, char key) {
    int len = strlen(str);
    for (int i = 0; i < len; i++) {
        str[i] ^= key;
    }
}

void decrypt(char *str, char key) {
    encrypt(str, key);
}

char* travHex(char message[], int len){
    
    char key = 0x0F;

    encrypt(message, key);
    printf("\nEncrypted message: ");

    for (int i = 0; i < len; i++) {
        printf("\\x%02x", message[i]);
    }

    decrypt(message, key);
    printf("\nDecrypted message: %s\n", message);

    return message;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("\n>> Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *file;
    char *filename = argv[1];
    char buffer[100];

    file = fopen(filename, "r");
    if (file == NULL) {
        printf("\n[-] Error opening file %s\n", filename);
        exit(1);
    }

    while (fgets(buffer, 100, file) != NULL) {
        int len = strlen(buffer);
        if (buffer[len - 1] =='\n') {
            buffer[len - 1] = '\0'; // remove newline character
            len--; // reduce length by 1
        }
        travHex(buffer, len);
    }

    fclose(file);
    return 0;
}