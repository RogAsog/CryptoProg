CXX = g++
CXXFLAGS = -std=c++11 -O2
INCLUDES = -I/usr/include/crypto++
LIBS = -lcryptopp -lboost_program_options

hash: hash.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) hash.cpp -o hash $(LIBS)

clean:
	rm -f hash
