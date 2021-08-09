#include <Windows.h>
#include <iostream>
#include <string>
#include "NewSection.h"


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

bool compileLoader() {
	const char* vsWhere = "\"\"C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe\" -latest -products * -requires Microsoft.Component.MSBuild -property installationPath\"";
	FILE* pipe = _popen(vsWhere, "rt");
	if (pipe != NULL) {
		char compilerPath[MAX_PATH] = { 0 };
		char solutionDir[MAX_PATH] = { 0 };
		if (fgets(compilerPath, MAX_PATH, pipe) != NULL) {
			std::cout << "Compiler Path: " << compilerPath << std::endl;
			std::cout << "Solution Path: " << SOLUTIONDIR << std::endl;
		}
		else {
			std::cout << "[!] Visual Studio compiler path is not found! " << std::endl;
			return false;
		}
		_pclose(pipe);
	}
}

int main(int argc, char *argv[]) {
	compileLoader();
	printBanner();
	if (argc != 3) {
		printHelp(argv[0]);
		return 0;
	}
	size_t fileSize = 0;	
	char* binaryContent = readBinary(argv[1], &fileSize);
	if (binaryContent == NULL || fileSize == 0) {
		std::cout << std::endl << "[!] Error on reading the exe file !" << std::endl << std::endl;
		return 0;
	}
	size_t newFileSize = 0;
	unsigned char packedContent[17] = { '1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h' };
	size_t packedLength = 17;
	char* newBinary = createNewSectionHeader(binaryContent,packedContent, packedLength,&newFileSize);
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