#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <boost/program_options.hpp>
#include <crypto++/sha.h>
#include <crypto++/hex.h>

using namespace std;
namespace po = boost::program_options;

int main(int argc, char* argv[]) {
    po::options_description desc("Опции");
    desc.add_options()
        ("help", "Показать справку")
        ("output,o", po::value<string>(), "Файл для вывода результатов")
        ("files", po::value<vector<string>>(), "Файлы для хэширования");

    po::positional_options_description pos;
    pos.add("files", -1);

    po::variables_map vm;
    
    try {
  
        po::store(po::command_line_parser(argc, argv)
            .options(desc).positional(pos).run(), vm);
        po::notify(vm);

        if (vm.count("help")) {
            cout << desc << endl;
            return 0;
        }

        if (!vm.count("files")) {
            cerr << "Ошибка: укажите хотя бы один файл." << endl;
            cout << desc << endl;
            return 1;
        }

        const vector<string>& files = vm["files"].as<vector<string>>();
        bool toFile = vm.count("output");
        ofstream out;

        if (toFile) {
            out.open(vm["output"].as<string>());
            if (!out.is_open()) {
                cerr << "Ошибка: не удалось открыть файл вывода." << endl;
                return 1;
            }
        }

        ostream& output = toFile ? out : cout;

        for (const string& filename : files) {
            ifstream file(filename, ios::binary);
            if (!file) {
                cerr << "Ошибка: не найден файл '" << filename << "'" << endl;
                continue;
            }

            CryptoPP::SHA256 hash;
            CryptoPP::byte buffer[4096];

            while (file.read((char*)buffer, sizeof(buffer))) {
                hash.Update(buffer, file.gcount());
            }
            hash.Update(buffer, file.gcount());  

            CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
            hash.Final(digest);

            string hex;
            CryptoPP::HexEncoder encoder;
            encoder.Attach(new CryptoPP::StringSink(hex));
            encoder.Put(digest, sizeof(digest));
            encoder.MessageEnd();

            output << filename << " " << hex << endl;
        }

        if (toFile) out.close();

    } catch (const exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
        return 1;
    }

    return 0;
}
