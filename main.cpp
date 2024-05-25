#include <iostream>

#include "Guardian/inc/Guardian.hpp"

int main() {

    LicenseKeyGen::Guardian G;
    if (std::string(LicenseKey) != G.EncryptionGet()) {
        std::cout << "Fatal Error" << std::endl;
        system("pause");
        return 0;
    }

    std::cout << "Success" << std::endl;
    system("pause");

    return 0;
}
