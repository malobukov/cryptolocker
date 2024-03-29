all: cryptolocker crptlckr.exe password4 password4.exe

cryptolocker: cryptolocker.cpp
	g++ -O3 -Wall -Wextra -std=c++17 -march=native -static -o cryptolocker cryptolocker.cpp

crptlckr.exe: cryptolocker.cpp
	/usr/bin/x86_64-w64-mingw32-g++-win32 -O3 -Wall -Wextra -std=c++17 -march=x86-64 -static -o crptlckr.exe cryptolocker.cpp

password4: password4.cpp
	g++ -O3 -Wall -Wextra -std=c++11 -o password4 password4.cpp

password4.exe:password4.cpp
	/usr/bin/x86_64-w64-mingw32-g++-win32 -O3 -Wall -Wextra -std=c++11 -march=x86-64 -static -o password4.exe password4.cpp

test: cryptolocker password4
	cp LICENSE.encrypted-fa877845 LICENSE.tmp1.encrypted-fa877845
	CRYPTOLOCKER_PASSWORD=fourwordsalluppercase ./cryptolocker LICENSE.tmp1.encrypted-fa877845
	cp LICENSE.encrypted LICENSE.tmp2.encrypted
	CRYPTOLOCKER_PASSWORD=fourwordsalluppercase ./cryptolocker LICENSE.tmp2.encrypted
	@echo Hashes of LICENSE, LICENSE.tmp1, and LICENSE.tmp2 should match
	sha256sum LICENSE LICENSE.tmp1 LICENSE.tmp2
	@echo The following command should produce checkword Tilausat and password Rich-envoy-pluck-069 
 
	CRYPTOLOCKER_PASSWORD=fourwordsalluppercase ./password4 john.doe@example.com

clean:
	rm LICENSE.tmp1 LICENSE.tmp2

