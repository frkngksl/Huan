#include <Windows.h>
#include <iostream>
#include <string>
#include "NewSection.h"
#include <time.h>

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

void DeleteDirectory(char *strPath)
{
	SHFILEOPSTRUCTA strOper = { 0 };
	strOper.hwnd = NULL;
	strOper.wFunc = FO_DELETE;
	strOper.pFrom = strPath;
	strOper.fFlags = FOF_SILENT | FOF_NOCONFIRMATION;

	if (SHFileOperationA(&strOper)){
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
	if (directoryExists(removedDir1)) {
		DeleteDirectory(removedDir1);
	}
	if (directoryExists(removedDir2)) {
		DeleteDirectory(removedDir2);
	}
}

char *compileLoader() {
	clearDirectory();
	const char* vsWhere = "\"\"C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe\" -latest -products * -requires Microsoft.Component.MSBuild -property installationPath\"";
	FILE* pipe = _popen(vsWhere, "rt");
	if (pipe != NULL) {
		char compilerPath[MAX_PATH] = { 0 };
		char fullCommand[MAX_PATH] = { 0 };
		if (fgets(compilerPath, MAX_PATH, pipe) != NULL) {
			//Remove new line
			compilerPath[strlen(compilerPath) - 1] = '\0';
			sprintf(fullCommand, "\"\"%s\\MSBuild\\Current\\Bin\\MSBuild.exe\" %s\\Huan.sln /t:HuanLoader /property:Configuration=JustLoader /property:RuntimeLibrary=MT\"\n", compilerPath, SOLUTIONDIR);
			FILE* pipe2 = _popen(fullCommand, "rt");
			_pclose(pipe2);
			char* loaderBinaryPath = (char *) malloc(MAX_PATH);
			sprintf(loaderBinaryPath, "%sx64\\JustLoader\\HuanLoader.exe", SOLUTIONDIR);
			if (INVALID_FILE_ATTRIBUTES == GetFileAttributesA(loaderBinaryPath) && GetLastError() == ERROR_FILE_NOT_FOUND){
				std::cout << "[!] Compiled binary not found!" << std::endl;
				free(loaderBinaryPath);
				return NULL;
			}
			else {
				return loaderBinaryPath;
			}
		}
		else {
			std::cout << "[!] Visual Studio compiler path is not found! " << std::endl;
			return NULL;
		}
		_pclose(pipe);
		return NULL;
	}
	return NULL;
}



int main(int argc, char *argv[]) {
	printBanner();
	if (argc != 3) {
		printHelp(argv[0]);
		return 0;
	}
	srand(time(NULL));
	size_t fileSize = 0;
	char* binaryContent = readBinary(argv[1], &fileSize);
	if (binaryContent == NULL || fileSize == 0) {
		std::cout << "[!] Error on reading the exe file !" << std::endl;
		return 0;
	}
	std::cout << "[+] " << argv[1] << " is readed!" << std::endl;
	size_t newFileSize = 0;
	char *loaderPath = compileLoader();
	size_t loaderSize = 0;
	if (loaderPath == NULL) {
		std::cout << std::endl << "[!] Error on compiling loader !" << std::endl;
		return 0;
	}
	char* loaderContent = readBinary(loaderPath, &loaderSize);
	std::cout << "[+] Loader is compiled and readed!" << std::endl;
	char* newBinary = createNewSectionHeader(loaderContent, (unsigned char *) binaryContent, fileSize,&newFileSize);
	if (newBinary == NULL) {
		std::cout << std::endl << "[!] Error on adding a new section header !" << std::endl;
		return 0;
	}
	std::cout << "[+] New section is added!" << std::endl;
	bool returnResult = saveNewPE(newBinary,newFileSize, argv[2]);
	clearDirectory();
	if (returnResult) {
		std::cout << "[+] Loader is created as " << argv[2] << std::endl;
	}
	delete[] binaryContent;
	delete[] loaderContent;
	free(loaderPath);
	return 0;
}