#include <iostream>
#include <crypto++/aes.h>
#include <crypto++/modes.h>
#include <crypto++/files.h>
#include <crypto++/sha.h>
#include <crypto++/pwdbased.h>
#include <boost/program_options.hpp>

namespace po = boost::program_options;
using namespace CryptoPP;

int main(int argc, char* argv[]) {
    std::string mode, input, output, password;
    
    po::options_description desc("Options");
    desc.add_options()
        ("help,h", "Show help")
        ("mode,m", po::value<std::string>(&mode)->required(), "encrypt/decrypt")
        ("input,i", po::value<std::string>(&input)->required(), "Input file")
        ("output,o", po::value<std::string>(&output)->required(), "Output file")
        ("password,p", po::value<std::string>(&password)->required(), "Password");
    
    po::positional_options_description p;
    p.add("mode", 1).add("input", 1).add("output", 1).add("password", 1);
    
    try {
        po::variables_map vm;
        po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
        
        if (vm.count("help")) {
            std::cout << "Use: cipher encrypt/decrypt input output password\n";
            return 0;
        }
        
        po::notify(vm);
        
    } catch (const po::error& e) {
        std::cerr << "Error: " << e.what() << "\nUse: cipher encrypt/decrypt input output password\n";
        return 1;
    }
    
    // Генерация ключа из пароля
    byte key[AES::DEFAULT_KEYLENGTH];
    byte iv[AES::BLOCKSIZE];
    
    byte salt[] = {1,2,3,4,5,6,7,8};
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    pbkdf.DeriveKey(key, sizeof(key), 0, 
                   (byte*)password.data(), password.size(),
                   salt, sizeof(salt), 1000);
    
    // Генерация IV
    byte salt_iv[] = {8,7,6,5,4,3,2,1};
    pbkdf.DeriveKey(iv, sizeof(iv), 0,
                   (byte*)password.data(), password.size(),
                   salt_iv, sizeof(salt_iv), 1000);
    
    try {
        if (mode == "encrypt") {
            CBC_Mode<AES>::Encryption e(key, sizeof(key), iv);
            FileSource(input.c_str(), true, 
                new StreamTransformationFilter(e, new FileSink(output.c_str())));
            std::cout << "Encrypted: " << output << std::endl;
        } 
        else if (mode == "decrypt") {
            CBC_Mode<AES>::Decryption d(key, sizeof(key), iv);
            FileSource(input.c_str(), true,
                new StreamTransformationFilter(d, new FileSink(output.c_str())));
            std::cout << "Decrypted: " << output << std::endl;
        }
        else {
            std::cerr << "Error: mode must be 'encrypt' or 'decrypt'\n";
            return 1;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
