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

bool DeleteDirectory(char *strPath)
{
	SHFILEOPSTRUCTA strOper = { 0 };
	strOper.hwnd = NULL;
	strOper.wFunc = FO_DELETE;
	strOper.pFrom = strPath;
	strOper.fFlags = FOF_SILENT | FOF_NOCONFIRMATION;

	if (0 == SHFileOperationA(&strOper)){
		std::cout << "[!] Unicode directory deletion problem" << std::endl;
	}
}

bool directoryExists(const std::string& dirName)
{
	DWORD fileType = GetFileAttributesA(dirName.c_str());
	if (fileType == INVALID_FILE_ATTRIBUTES) {
		return false;
	}
	if (fileType & FILE_ATTRIBUTE_DIRECTORY) {
		return true;
	}
	return false;
}

void clearDirectory() {
	char removedDir1[MAX_PATH] = { 0 };
	char removedDir2[MAX_PATH] = { 0 };
	sprintf(removedDir1, "%sx64\\JustLoader\\", SOLUTIONDIR);
	sprintf(removedDir2, "%sHuanLoader\\x64\\", SOLUTIONDIR);
	//std::cout << removedDir1 << " " << directoryExists(removedDir1) << std::endl;
	//std::cout << removedDir2 << " " << directoryExists(removedDir2) << std::endl;
	if (directoryExists(removedDir1)) {
		std::cout << "[+] Cleaning " << removedDir1 << std::endl;
		DeleteDirectory(removedDir1);
	}
	if (directoryExists(removedDir2)) {
		std::cout << "[+] Cleaning " << removedDir2 << std::endl;
		DeleteDirectory(removedDir2);
	}
}

bool compileLoader() {
	clearDirectory();
	const char* vsWhere = "\"\"C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe\" -latest -products * -requires Microsoft.Component.MSBuild -property installationPath\"";
	FILE* pipe = _popen(vsWhere, "rt");
	if (pipe != NULL) {
		char compilerPath[MAX_PATH] = { 0 };
		char fullCommand[MAX_PATH] = { 0 };
		if (fgets(compilerPath, MAX_PATH, pipe) != NULL) {
			//Remove new line
			compilerPath[strlen(compilerPath) - 1] = '\0';
			std::cout << "Compiler Path: " << compilerPath << std::endl;
			std::cout << "Solution Path: " << SOLUTIONDIR << std::endl;
			sprintf(fullCommand, "\"\"%s\\MSBuild\\Current\\Bin\\MSBuild.exe\" %s\\Huan.sln /t:HuanLoader /property:Configuration=JustLoader /property:RuntimeLibrary=MT\"\n", compilerPath, SOLUTIONDIR);
			FILE* pipe2 = _popen(fullCommand, "rt");
			_pclose(pipe2);
		}
		else {
			std::cout << "[!] Visual Studio compiler path is not found! " << std::endl;
			return false;
		}
		_pclose(pipe);
		return true;
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