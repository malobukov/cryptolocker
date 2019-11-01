cryptolocker: cryptolocker.cpp
	g++ -O3 -Wall -Wextra -std=c++11 -march=native -g -o cryptolocker cryptolocker.cpp

test: cryptolocker
	cp LICENSE.encrypted LICENSE.decrypted
	./cryptolocker fourwordsalluppercase LICENSE.decrypted
	@echo Hashes of original and decrypted should match
	sha256sum LICENSE LICENSE.decrypted

clean:
	rm LICENSE.decrypted

