#include <Windows.h>
#include <winnt.h>
#include <iostream>

int main() {
	//Get image base address from struct offsets of PEB and TEB
	char *TEBPtr = (char *) __readgsqword(0x30);
	char *PEBPtr = *((char **) (TEBPtr + 0x060));
	char* imageBaseAddress = *(char**)(PEBPtr+0x10);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBaseAddress;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)(imageBaseAddress + dosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER sectionHeadersCursor = (PIMAGE_SECTION_HEADER)(((PBYTE)imageNTHeaders) + sizeof(IMAGE_NT_HEADERS));
	for (unsigned int i = 1; i < imageNTHeaders->FileHeader.NumberOfSections; i++) {
			std::cout << sectionHeadersCursor->Name << std::endl;
			sectionHeadersCursor = (PIMAGE_SECTION_HEADER)((PBYTE)sectionHeadersCursor + 0x28);
	}
	return 0;
}