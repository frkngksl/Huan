#pragma once
#include <Windows.h>
#include <iostream>
#include <winnt.h>

//IMAGE_NT_HEADERS --> PE Signature + PE Header + PE Optional Header structure --> https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32
#define ntHeaders(imageBase) ((IMAGE_NT_HEADERS *)((size_t)imageBase + ((IMAGE_DOS_HEADER *)imageBase)->e_lfanew))
//Section headers are located sequentially right after the optional header in the PE file format. Each section header is 40 bytes with no padding between them. Section headers are defined as in the following structure
#define sectionHeaderArrays(imageBase) ((IMAGE_SECTION_HEADER *)((size_t)ntHeaders(imageBase) + sizeof(IMAGE_NT_HEADERS)))

#define P2ALIGNUP(size, align) ((((size) / (align)) + 1) * (align))



char* readBinary(char* fileName,size_t *givenFileSize) {
	FILE* fileHandler = fopen(fileName, "rb+");
	char* binaryContent = NULL;
	size_t fileSize = 0;
	if (fileHandler) {
		//Move cursor to the end of executable
		fseek(fileHandler, 0, SEEK_END);
		fileSize = ftell(fileHandler);
		binaryContent = new char[fileSize+1];
		//Move cursor to the beginning
		fseek(fileHandler, 0, SEEK_SET);
		fread(binaryContent, sizeof(char), fileSize, fileHandler);
		fclose(fileHandler);
	}
	*givenFileSize = fileSize;
	return binaryContent;
}

void saveNewPE(char* newFile, size_t lengthOfFile, const char* fileName) {
	ntHeaders(newFile)->OptionalHeader.SizeOfImage =
		sectionHeaderArrays(newFile)[ntHeaders(newFile)->FileHeader.NumberOfSections - 1].VirtualAddress +
		sectionHeaderArrays(newFile)[ntHeaders(newFile)->FileHeader.NumberOfSections - 1].Misc.VirtualSize;

	ntHeaders(newFile)->OptionalHeader.DllCharacteristics &= ~(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);
	FILE* fileHandler = fopen(fileName, "wb");
	fwrite(newFile, 1, lengthOfFile, fileHandler);
	fclose(fileHandler);
}

char * createNewSectionHeader(char* imageBase,size_t stubSize,size_t *newFileSize) {
	IMAGE_NT_HEADERS* ntHeaderOfImage = ntHeaders(imageBase);
	IMAGE_SECTION_HEADER* sectionHeaderArray = sectionHeaderArrays(imageBase);
	int numberOfSections = ntHeaderOfImage->FileHeader.NumberOfSections;
	//Area after the last section in disk
	size_t newSectionOffset = sectionHeaderArray[numberOfSections - 1].PointerToRawData + sectionHeaderArray[numberOfSections - 1].SizeOfRawData;
	//Area after the last element in the section header array
	IMAGE_SECTION_HEADER* newSectionHeader = &sectionHeaderArray[numberOfSections];
	
	//check the section header boundary with the first section --> Does new section header (get offset) overwrite the first section (.text section)?
	bool checkBoundary = ((char *) newSectionHeader + sizeof(IMAGE_SECTION_HEADER) - imageBase) < sectionHeaderArray[0].PointerToRawData;
	if (checkBoundary) {
		//We are safe
		memcpy(newSectionHeader->Name, ".huan", IMAGE_SIZEOF_SHORT_NAME);
		//In memory, sections should be multiple of page size, this alignment variable arranges this alignment.
		newSectionHeader->VirtualAddress = P2ALIGNUP(
			sectionHeaderArray[numberOfSections - 1].VirtualAddress + sectionHeaderArray[numberOfSections - 1].Misc.VirtualSize,
			ntHeaderOfImage->OptionalHeader.SectionAlignment
		);
		//File alignment for PE File, same alignment problem but this is for disk
		newSectionHeader->SizeOfRawData = P2ALIGNUP(stubSize, ntHeaderOfImage->OptionalHeader.FileAlignment);
		//Section alignment for memory
		newSectionHeader->Misc.VirtualSize = P2ALIGNUP((stubSize), ntHeaderOfImage->OptionalHeader.SectionAlignment);
		newSectionHeader->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
		//Offset for file
		newSectionHeader->PointerToRawData = newSectionOffset;
		// Section Alignment trick and put correct address wrt last section
		ntHeaderOfImage->FileHeader.NumberOfSections += 1;
		//Now it has new section size
		*newFileSize = P2ALIGNUP(stubSize, ntHeaderOfImage->OptionalHeader.FileAlignment);
		//New Section Offset is actually end of the file
		char* newExeBuffer = new char[newSectionOffset + *newFileSize];
		memcpy(newExeBuffer, imageBase, newSectionOffset);
		//New Section contains null bytes
		memset(newExeBuffer + newSectionOffset, 0x00, stubSize);
		*newFileSize += newSectionOffset;
		return newExeBuffer;
	}
	else {
		//TODO: Is there a way to fix this boundary problem?
		return NULL;
	}
}