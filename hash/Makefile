CXX = g++
CXXFLAGS = -std=c++11 -O2 -I/usr/include/crypto++
LDFLAGS = -lcryptopp

hash: hash.cpp
	$(CXX) $(CXXFLAGS) hash.cpp -o hash $(LDFLAGS)

clean:
	rm -f hash *.o
