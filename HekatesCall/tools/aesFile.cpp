/*
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

*/

#include <Windows.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <algorithm>

// g++ -s -static -O3 -o aesFile aesFile.cpp -lcrypt32

int main() {
    // Generate a random key
    HCRYPTPROV hProv;
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "\n[-] Error acquiring context: " << GetLastError() << std::endl;
        return -1;
    }
    BYTE key[32];
    if (!CryptGenRandom(hProv, sizeof(key), key)) {
        std::cerr << "\n[-] Error generating random key: " << GetLastError() << std::endl;
        CryptReleaseContext(hProv, 0);
        return -1;
    }

    // Ask the user whether they want to encrypt or decrypt
    char mode;
    std::cout << "\n>> Do you want to encrypt or decrypt? (e/d): ";
    std::cin >> mode;

    if (mode == 'e') {

        // Prompt the user for the plaintext file path
        std::string plaintext_file_path;
        std::cout << "\n>> Enter the path to the .bin file: ";
        std::cin >> plaintext_file_path;

        // Read plaintext from file
        std::ifstream plaintext_file(plaintext_file_path, std::ios::binary);
        if (!plaintext_file.is_open()) {
            std::cerr << "\n[-] Error opening binary file" << std::endl;
            CryptReleaseContext(hProv, 0);
            return -1;
        }
        std::stringstream plaintext_buffer;
        plaintext_buffer << plaintext_file.rdbuf();
        plaintext_file.close();

        std::string plaintext_str = plaintext_buffer.str();
        DWORD plaintext_len = plaintext_str.length();
        DWORD ciphertext_len = plaintext_len + 16; // The encrypted data may be slightly larger than the plaintext
        BYTE* ciphertext = new BYTE[ciphertext_len];
        memcpy(ciphertext, plaintext_str.c_str(), plaintext_len);

        HCRYPTHASH hHash;
        HCRYPTKEY hKey;

        if (!CryptCreateHash(hProv, CALG_SHA_512, 0, 0, &hHash)) {
            std::cerr << "\n[-] Error creating hash: " << GetLastError() << std::endl;
            delete[] ciphertext;
            CryptReleaseContext(hProv, 0);
            return -1;
        }
        if (!CryptHashData(hHash, key, sizeof(key), 0)) {
            std::cerr << "\n[-] Error hashing data: " << GetLastError() << std::endl;
            CryptDestroyHash(hHash);
            delete[] ciphertext;
            CryptReleaseContext(hProv, 0);
            return -1;
        }
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
            std::cerr << "\n[-] Error deriving key: " << GetLastError() << std::endl;
            CryptDestroyHash(hHash);
            delete[] ciphertext;
            CryptReleaseContext(hProv, 0);
            return -1;
        }
        if (!CryptEncrypt(hKey, (HCRYPTHASH)NULL, TRUE, 0, ciphertext, &plaintext_len, ciphertext_len)) {
            std::cerr << "\n[-] Error encrypting data: " << GetLastError() << std::endl;
            CryptDestroyKey(hKey);
            CryptDestroyHash(hHash);
            delete[] ciphertext;
            CryptReleaseContext(hProv, 0);
            return -1;
        }

        // Save the key into a file
        std::string keyPath = plaintext_file_path.substr(0, plaintext_file_path.find_last_of('.')) + ".key";
        std::ofstream keyFile(keyPath);

        // Save the key to the file
        keyFile << "{ ";
        
        for (int i = 0; i < sizeof(key); i++) {
            keyFile << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)key[i];
            if (i != sizeof(key) - 1) {
                keyFile << ", ";
            }   
        }

        keyFile << " }";

        // Close the file
        keyFile.close();
        std::cout << "\n[+] Key: " << keyPath << "\n";

        // Write the encrypted result to a file
        std::string encrypted_file_path = plaintext_file_path.substr(0, plaintext_file_path.find_last_of('.')) + ".enc";
        std::ofstream encrypted_file(encrypted_file_path, std::ios::binary);
        if (encrypted_file.is_open()) {
            encrypted_file << "{ ";
            for (int i = 0; i < plaintext_len; i++) {
                encrypted_file << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)ciphertext[i];
                if (i != plaintext_len - 1) {
                    encrypted_file << ", ";
                }
            }
            encrypted_file << " }";
            encrypted_file.close();
            std::cout << "\n[+] Encrypted data written to file: " << encrypted_file_path << std::endl;
        } else {
            std::cerr << "\n[-] Error opening encrypted file" << std::endl;
            CryptReleaseContext(hProv, 0);
            delete[] ciphertext;
            return -1;
        }

        // Clean up resources
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        delete[] ciphertext;
        CryptReleaseContext(hProv, 0);

    } else if (mode == 'd') {

        // Prompt the user for the ciphertext file path
        std::string ciphertext_file_path;
        std::cout << "\n>> Enter the path to the ciphertext file: ";
        std::cin >> ciphertext_file_path;

        // Read ciphertext from file
        std::string ciphertext_str;
        std::ifstream encrypted_file(ciphertext_file_path);
        if (encrypted_file.is_open()) {
            std::stringstream buffer;
            buffer << encrypted_file.rdbuf();
            ciphertext_str = buffer.str();
            encrypted_file.close();

            // Filter out unwanted characters
            ciphertext_str.erase(std::remove_if(ciphertext_str.begin(), ciphertext_str.end(),
                            [](char c) { return c == '{' || c == '}' || c == ',' || c == ' '; }), ciphertext_str.end());

            // Replace "0x" with "\x"
            const std::string old_str = "0x";
            const std::string new_str = "\\x";
            size_t pos = ciphertext_str.find(old_str);
            while (pos != std::string::npos) {
                ciphertext_str.replace(pos, old_str.length(), new_str);
                pos = ciphertext_str.find(old_str, pos + new_str.length());
            }

        } else {
            std::cerr << "\n[-] Error opening encrypted file" << std::endl;
            CryptReleaseContext(hProv, 0);
            return -1;
        }

        // Remove any escape characters from the string
        std::string ciphertext;
        for (int i = 0; i < ciphertext_str.length(); i++) {
            if (ciphertext_str[i] == '\\' && ciphertext_str[i+1] == 'x') {
                char c = static_cast<char>(std::stoi(ciphertext_str.substr(i+2, 2), nullptr, 16));
                ciphertext += c;
                i += 3;
            } else {
                ciphertext += ciphertext_str[i];
            }
        }

        // Prompt the user for the key file path
        std::string key_file_path;
        std::cout << "\n>> Enter the path to the key file: ";
        std::cin >> key_file_path;

        // Read key from file
        std::string key_str;
        std::ifstream key_file(key_file_path);
        if (key_file.is_open()) {
            std::stringstream buffer;
            buffer << key_file.rdbuf();
            key_str = buffer.str();
            key_file.close();

            // Filter out unwanted characters
            key_str.erase(std::remove_if(key_str.begin(), key_str.end(),
                            [](char c) { return c == '{' || c == '}' || c == ',' || c == ' '; }), key_str.end());

            // Replace "0x" with ""
            const std::string old_str = "0x";
            const std::string new_str = "";
            size_t pos = key_str.find(old_str);
            while (pos != std::string::npos) {
                key_str.replace(pos, old_str.length(), new_str);
                pos = key_str.find(old_str, pos + new_str.length());
            }

        } else {
            std::cerr << "\n[-] Error opening key file" << std::endl;
            return -1;
        }

        BYTE key[32];
        for (int i = 0; i < key_str.length(); i += 2) {
            std::stringstream ss;
            ss << std::hex << key_str.substr(i, 2);
            int byte_value;
            ss >> byte_value;
            key[i / 2] = static_cast<BYTE>(byte_value);
        }

        DWORD ciphertext_len = ciphertext.length();
        DWORD decrypted_len = ciphertext_len;
        BYTE* decrypted = new BYTE[decrypted_len];
        memcpy(decrypted, ciphertext.c_str(), ciphertext_len);

        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        HCRYPTKEY hKey;

        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
            std::cerr << "\n[-] Error acquiring context: " << GetLastError() << std::endl;
            delete[] decrypted;
            CryptReleaseContext(hProv, 0);
            return -1;
        }

        if (!CryptCreateHash(hProv, CALG_SHA_512, 0, 0, &hHash)) {
            std::cerr << "\n[-] Error creating hash: " << GetLastError() << std::endl;
            delete[] decrypted;
            CryptReleaseContext(hProv, 0);
            return -1;
        }
        if (!CryptHashData(hHash, key, sizeof(key), 0)) {
            std::cerr << "\n[-] Error hashing data: " << GetLastError() << std::endl;
            CryptDestroyHash(hHash);
            delete[] decrypted;
            CryptReleaseContext(hProv, 0);
            return -1;
        }
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
            std::cerr << "\n[-] Error deriving key: " << GetLastError() << std::endl;
            CryptDestroyHash(hHash);
            delete[] decrypted;
            CryptReleaseContext(hProv, 0);
            return -1;
        }
        if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, TRUE, 0, decrypted, &decrypted_len)) {
            std::cerr << "\n[-] Error decrypting data: " << GetLastError() << std::endl;
            CryptDestroyKey(hKey);
            CryptDestroyHash(hHash);
            delete[] decrypted;
            CryptReleaseContext(hProv, 0);
            return -1;
        }

        // Write the decrypted result to a file
        std::string decrypted_file_path = ciphertext_file_path.substr(0, ciphertext_file_path.find_last_of('.')) + ".dec";
        std::ofstream decrypted_file(decrypted_file_path, std::ios::binary);
        if (decrypted_file.is_open()) {
            decrypted_file.write(reinterpret_cast<const char*>(decrypted), decrypted_len);
            decrypted_file.close();
            std::cout << "\n[+] Decrypted data written to file: " << decrypted_file_path << std::endl;
        } else {
            std::cerr << "\n[-] Error opening decrypted file" << std::endl;
            CryptReleaseContext(hProv, 0);
            delete[] decrypted;
            return -1;
        }

        // Clean up resources
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        delete[] decrypted;
        CryptReleaseContext(hProv, 0);

    } else {
        std::cerr << "\n[-] Invalid input" << std::endl;
        CryptReleaseContext(hProv, 0);
        return -1;
    }

    return 0;
}