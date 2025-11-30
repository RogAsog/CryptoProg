#include <iostream>
#include <fstream>
#include <crypto++/sha.h>
#include <crypto++/hex.h>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << "Использование: " << argv[0] << " <файл>" << std::endl;
        return 1;
    }

    std::ifstream file(argv[1], std::ios::binary);
    if (!file) {
        std::cerr << "Ошибка открытия файла" << std::endl;
        return 1;
    }

    CryptoPP::SHA256 hash;
    CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
    
    // Чтение и хэширование файла
    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        hash.Update((CryptoPP::byte*)buffer, file.gcount());
    }
    hash.Update((CryptoPP::byte*)buffer, file.gcount());
    hash.Final(digest);

    // Вывод в hex
    std::string hexDigest;
    CryptoPP::HexEncoder encoder;
    encoder.Attach(new CryptoPP::StringSink(hexDigest));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();

    std::cout << hexDigest << std::endl;
    return 0;
}
