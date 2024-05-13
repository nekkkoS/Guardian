#include "Guardian/inc/Guardian.hpp"

#include <iostream>
#include <string>

int main() {
    LicenseKeyGen::Guardian G;
    if (std::string(FOO) == G.EncryptionGet()) {
        std::cout << "Correct";
    } else {
        std::cout << "Incorrect";
    }
    return 0;
}
