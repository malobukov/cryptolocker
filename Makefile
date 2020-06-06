all: cryptolocker password4

cryptolocker: cryptolocker.cpp
	g++ -O3 -Wall -Wextra -std=c++11 -march=native -g -o cryptolocker cryptolocker.cpp

password4:
	g++ -O3 -Wall -Wextra -std=c++11 -g -o password4 password4.cpp

test: cryptolocker password4
	cp LICENSE.encrypted LICENSE.decrypted
	CRYPTOLOCKER_PASSWORD=fourwordsalluppercase ./cryptolocker fourwordsalluppercase LICENSE.decrypted
	@echo Hashes of original and decrypted should match
	sha256sum LICENSE LICENSE.decrypted
	@echo The following command should produce ybSr-Bkw7-uYrt-Tnvz 
	CRYPTOLOCKER_PASSWORD=fourwordsalluppercase ./password4 john.doe@example.com

clean:
	rm LICENSE.decrypted

