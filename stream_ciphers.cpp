//
//  stream_ciphers.cpp
//  Stream Ciphers
//
//  Created by Nafis Abedin on 2019-11-27.
//  Copyright © 2019 Nafis Abedin. All rights reserved.
//  1A Computer Engineering
//  University of Waterloo

#include <iostream>
#include <cctype>

#ifndef MARMOSET_TESTING
int main();
#endif
char* encode(char *plaintext, unsigned long key);
char* decode(char *ciphertext, unsigned long key);
bool is_valid_ciphertext(char *str);
bool is_valid_plaintext(char *str);
int array_size(char *array);
void create_S(unsigned long key, unsigned char S[256], int &i, int &j);
void encrypt_plaintext(char *plaintext, int size_text, unsigned long key);
void ascii_armor(unsigned char temp_bytes[4], char base_85[5]);
void undo_ascii_armor(unsigned char temp_bytes[4], char base_85[5]);
int pow(int base, int exponent);

#ifndef MARMOSET_TESTING
int main() {
    // Key:    51323
    char test[] {"Hello world!"};

    unsigned long key{51323};

    std::cout << test << std::endl;

    char *ciphertext { encode(test, key) };

    std::cout << ciphertext << std::endl;

    char *plaintext { decode(ciphertext, key) };

    std::cout << plaintext << std::endl;

    // 106111101108

    delete[] ciphertext;
    ciphertext = nullptr;
    delete[] plaintext;
    plaintext = nullptr;

    return 0;
}
#endif

// ENCODE:
//     scramble the character array (S)
//     XOR plaintext with S (R is one element of S)
//     ASCII armor (converts from non-printable to printable)

char* encode(char *plaintext, unsigned long key) {
    int size_plaintext {array_size(plaintext)};
    int num_of_4_bytes { (size_plaintext - 1) / 4 };
    if ((size_plaintext - 1) % 4 != 0) {
        num_of_4_bytes++;
    }
    char* temptext = new char[num_of_4_bytes * 4] { };
    for (int i = 0; i < num_of_4_bytes * 4; i++) {
        if (i < size_plaintext) {
            temptext[i] = plaintext[i];
        } else {
            temptext[i] = '\0';
        }
    }

    encrypt_plaintext(temptext, num_of_4_bytes * 4, key);

    // ASCII Armor
    // 1. Break text into 4 byte chunks (Adding \0 to the end as needed)
    char *ciphertext = new char[(num_of_4_bytes * 5) + 1];
    unsigned char temp_bytes[4];
    char temp_base_85[5];
    for (int i = 0; i < num_of_4_bytes; i++) {
        for (int j = 0; j < 4; j++)
            temp_bytes[j] = temptext[(i * 4) + j];
        ascii_armor(temp_bytes, temp_base_85);
        for (int j = 0; j < 5; j++)
            ciphertext[(i * 5) + j] = temp_base_85[j];
    }

    ciphertext[(num_of_4_bytes * 5)] = '\0';

    if (!is_valid_ciphertext(ciphertext)) {
        std::cerr << "INVALID CIPHERTEXT: " << ciphertext << std::endl;
    }

    return ciphertext;
}

char* decode(char *ciphertext, unsigned long key) {
    int size_ciphertext {array_size(ciphertext)};
    int size_plaintext {((size_ciphertext - 1)/5)*4};
    char base_85[5] {};
    unsigned char temp_bytes[4] {};
    char *plaintext = new char[size_plaintext + 1];
    for(int i = 0; i < (size_ciphertext - 1)/5; i++) {
        for(int j = 0; j < 5; j++)
            base_85[j] = ciphertext[(i*5) + j];
        undo_ascii_armor(temp_bytes, base_85);
        for(int j = 0; j < 4; j++)
            plaintext[(i*4) + j] = temp_bytes[j];
    }

    encrypt_plaintext(plaintext, size_plaintext, key);

    plaintext[size_plaintext] = '\0';

    if (!is_valid_plaintext(ciphertext)) {
        std::cerr << "INVALID PLAINTEXT: " << ciphertext << std::endl;
    }

    return plaintext;
}

// Which checks that:
//    1.the array is of size 5m+ 1 with the last character being the null character
//    2.the first 5m characters are all between '!'and 'u', inclusive
bool is_valid_ciphertext(char *str) {
    // 1
    int size { array_size(str) };
    if (size % 5 == 1) {
        // 2
        for (int i = 0; i < size - 1; i++) {
            if (str[i] - '!' < 0 || str[i] - '!' >= 85) {
                std::cerr << "Invalid character for ciphertext ('!' to 'u' inclusively): " << str[i] << std::endl;
                return false;
            }
        }
        return true;
    }
    std::cerr << "Invalid size for ciphertext (must follow 5m + 1): " << size << std::endl;
    return false;
}

// Which checks for the decrypted message that all the characters before the first '\0'
// are either printable characters or printable whitespace
// (use std::isprint( ch ) || std::isspace( ch ) from the standard library cctype)
bool is_valid_plaintext(char *str) {
    int size { array_size(str) };
    for (int i = 0; i < size - 1; i++) {
        if (!(std::isprint(str[i]) || std::isspace(str[i]))) {
            std::cerr << "Invalid character for plaintext: " << str[i] << std::endl;
            return false;
        }
    }
    return true;
}

int array_size(char *array) {
    int size { 0 };
    while (array[size] != '\0')
        size++;
    return (size + 1);
}

void create_S(unsigned long key, unsigned char S[256], int &i, int &j) {
    for (int times = 0; times < 256; times++) {
        S[times] = times;
    }
    int k { 0 };
    unsigned char temp { };
    for (int times = 0; times < 256; times++) {
        k = i % 64;
        j = (j + S[i] + ((key >> k) & 1)) % 256;// ((1UL << k)&key)    1100100001111011
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        i = (i + 1) % 256;
    }
}

void encrypt_plaintext(char *text, int size_text, unsigned long key) {
    // Scramble char array S
    int i{0};
    int j{0};
    unsigned char S[256] {};
    create_S(key, S, i, j);

    // XOR text with S
    unsigned char temp { };
    unsigned char r { };
    unsigned char R { };
    for (int times = 0; times < size_text; times++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        r = (S[i] + S[j]) % 256;
        R = S[r];
        text[times] = (text[times]) ^ (R);
    }
}

// 1. Convert to base 85 number (5 digits)
// 2. Convert base 85 number into characters starting at '!' (ASCII: 33)
void ascii_armor(unsigned char temp_bytes[4], char base_85[5]) {
    // Combining the bytes into one number
    unsigned int temp_value { 0 };
    for (int i = 0; i < 4; i++)
        temp_value += (temp_bytes[3 - i] << (i * 8));
    // Converting the number into a base 85 number with 5 digits
    int power { 0 };
    for (int i = 4; i >= 0; i--) {
        power = pow(85, i);
        base_85[4 - i] = temp_value / power;
        temp_value -= base_85[4 - i] * power;
        // Starting at '!' (ASCII: 33)
        base_85[4 - i] += 33;
    }
}

void undo_ascii_armor(unsigned char temp_bytes[4], char base_85[5]) {
    unsigned int temp_value {0};
    for(int i = 4; i >= 0; i--)
        temp_value += (base_85[4 - i] - 33)*pow(85, i);
    for(int i = 3; i >= 0; i--)
        temp_bytes[i] = static_cast<unsigned char>(temp_value >> (24 - (i*8)));
}

int pow(int base, int exponent) {
    int answer { 1 };
    for (int i = 0; i < exponent; i++) {
        answer = answer * base;
    }
    return answer;
}
