all: cryptolocker password4

cryptolocker: cryptolocker.cpp
	g++ -O3 -Wall -Wextra -std=c++11 -march=native -g -o cryptolocker cryptolocker.cpp

password4: password4.cpp
	g++ -O3 -Wall -Wextra -std=c++11 -g -o password4 password4.cpp

test: cryptolocker password4
	cp LICENSE.encrypted-fa877845 LICENSE.tmp.encrypted-fa877845
	CRYPTOLOCKER_PASSWORD=fourwordsalluppercase ./cryptolocker LICENSE.tmp.encrypted-fa877845
	@echo Hashes of LICENSE and LICENSE.tmp should match
	sha256sum LICENSE LICENSE.tmp
	@echo The following command should produce wmRH-8ZTP-91YT-8xmy 
	CRYPTOLOCKER_PASSWORD=fourwordsalluppercase ./password4 john.doe@example.com

clean:
	rm LICENSE.tmp

