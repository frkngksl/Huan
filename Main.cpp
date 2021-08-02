#include <Windows.h>
#include <iostream>
#include <string>
#include "NewSection.h"
#include "Crypto.h"


void printBanner() {
	const char* banner =  
" .S    S.    .S       S.    .S_SSSs     .S_sSSs    \n"
".SS    SS.  .SS       SS.  .SS~SSSSS   .SS~YS%%b   \n"
"S%S    S%S  S%S       S%S  S%S   SSSS  S%S   `S%b  \n"
"S%S    S%S  S%S       S%S  S%S    S%S  S%S    S%S  \n"
"S%S SSSS%S  S&S       S&S  S%S SSSS%S  S%S    S&S  \n"
"S&S  SSS&S  S&S       S&S  S&S  SSS%S  S&S    S&S  \n"
"S&S    S&S  S&S       S&S  S&S    S&S  S&S    S&S  \n"
"S&S    S&S  S&S       S&S  S&S    S&S  S&S    S&S  \n"
"S*S    S*S  S*b       d*S  S*S    S&S  S*S    S*S  \n"
"S*S    S*S  S*S.     .S*S  S*S    S*S  S*S    S*S  \n"
"S*S    S*S   SSSbs_sdSSS   S*S    S*S  S*S    S*S  \n"
"SSS    S*S    YSSP~YSSY    SSS    S*S  S*S    SSS  \n"
"       SP                         SP   SP          \n"
"       Y                          Y    Y           \n"
"             by @R0h1rr1m                          \n";
	std::cout <<std::endl << banner << std::endl;
}


void printHelp(const char *exeName) {
	std::cout << "[+] Usage: " << exeName << " <exe path> <new exe name>" << std::endl << std::endl;
}

int main(int argc, char *argv[]) {
	printBanner();
	if (argc != 3) {
		/*
		DEBUG for Crypto
		
		unsigned char dataBuffer[17] = { '1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h'};
		size_t originalDataLength = 17;
		unsigned char keyBuffer[KEYSIZE] = { 0x00 };
		unsigned char IVBuffer[16] = { 0x00 };
		unsigned char* newBuffer = paddingForInput(dataBuffer, originalDataLength);
		size_t dataLength = (originalDataLength / 16 + 1) * 16;
		encryptData(newBuffer, dataLength, keyBuffer, IVBuffer);
		std::cout << "Data Buffer Encrypted ! " << std::endl;
		decryptData(newBuffer, dataLength, keyBuffer, IVBuffer);
		printf("%17s\n", newBuffer);
		*/
		printHelp(argv[0]);
		return 0;
	}
	size_t fileSize = 0;
	char* binaryContent = readBinary(argv[1],&fileSize);
	if (binaryContent == NULL || fileSize == 0) {
		std::cout << std::endl << "[!] Error on reading the exe file !" << std::endl << std::endl;
		return 0;
	}
	size_t newFileSize = 0;
	char* newBinary = createNewSectionHeader(binaryContent, 100,&newFileSize);
	if (newBinary == NULL) {
		std::cout << std::endl << "[!] Error on adding a new section header !" << std::endl << std::endl;
	}
	//memcpy(newBinary, binaryContent, fileSize);
	//memset(newBinary + fileSize, 0x90, 0x200);
	saveNewPE(newBinary,newFileSize,argv[2]);
	std::cout << std::endl << "[+] New file is created as " << argv[2] << std::endl << std::endl;
	delete[] binaryContent;
	return 0;
}