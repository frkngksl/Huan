#include <Windows.h>
#include <winnt.h>
#include <iostream>
#include <stdio.h>
#include"../Crypto.h"

//IMAGE_NT_HEADERS --> PE Signature + PE Header + PE Optional Header structure --> https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32
#define ntHeaders(imageBase) ((IMAGE_NT_HEADERS *)((size_t)imageBase + ((IMAGE_DOS_HEADER *)imageBase)->e_lfanew))
//Section headers are located sequentially right after the optional header in the PE file format. Each section header is 40 bytes with no padding between them. Section headers are defined as in the following structure
#define sectionHeaderArrays(imageBase) ((IMAGE_SECTION_HEADER *)((size_t)ntHeaders(imageBase) + sizeof(IMAGE_NT_HEADERS)))

char* readBinary(const char* fileName, size_t* givenFileSize) {
	FILE* fileHandler = fopen(fileName, "rb+");
	char* binaryContent = NULL;
	size_t fileSize = 0;
	if (fileHandler) {
		//Move cursor to the end of executable
		fseek(fileHandler, 0, SEEK_END);
		fileSize = ftell(fileHandler);
		binaryContent = new char[fileSize + 1];
		//Move cursor to the beginning
		fseek(fileHandler, 0, SEEK_SET);
		fread(binaryContent, sizeof(char), fileSize, fileHandler);
		fclose(fileHandler);
	}
	*givenFileSize = fileSize;
	return binaryContent;
}

IMAGE_DATA_DIRECTORY* getRelocTable(IMAGE_NT_HEADERS *ntHeader) {
	/*
	The relocation table is a lookup table that lists all parts of the PE file that need patching when the file is loaded at a non-default base address.
	https://stackoverflow.com/questions/31981929/what-is-the-base-relocation-table-in-the-pe-file-format
	The base relocation table is for runtime and is built in the .obj file and merged into the final .exe and is pointed to by BaseRelocationTable in the
	PE header and is usually in .reloc. If the image is loaded at an address that isn't the ImageBase the linker selected and placed in the PE header,
	then the patches in the base relocation table need to be applied. The base relocation table is made up of base relocation blocks and each block describes 
	a 4 KiB page. The block header contains the RVA of the page and the size of the block structure. The rest of the block contains an array of 2 byte fields 
	where the first 4 bits of the 2 bytes indicates the relocation type and the latter 12 bits indicates the offset from the page RVA to which the relocation
	needs to be applied. This will be the offset to an address field in an instruction. To relocate, the loader just calculates the difference between ImageBase
	and the real base address of the process in the PEB and adds/subtracts it from the address. There won't be many base relocations because most of the symbols
	in the code use register indirect rip-relative addressing (for mov and dllimport calls) and direct relative addressing (for regular calls). In COFF objects, 
	both relative and absolute addresses need to be relocated, in the PE executable, only absolute addresses need relocations.

	One of the sections, that may exist, is the .reloc section, and within this section is a base relocation table. The base relocation table is needed to fix up 
	virtual addresses in the PE file if the PE file not was loaded at its preferred load address.
	The .reloc section contains a serie of blocks. There is one block for each 4 KB page that contains virtual addresses, which is in need for fix ups. Each block 
	contains an IMAGE_BASE_RELOCATION struct and a serie of entries.
		

typedef struct _IMAGE_BASE_RELOCATION {
	DWORD   VirtualAddress; //Page RVA
	DWORD   SizeOfBlock;
	//WORD    TypeOffset[1];
} IMAGE_BASE_RELOCATION;   //base relocation table

The VirtualAddress holds a Relative Virtual Address (RVA) of the 4 KB page, which the relocation applies to. The SizeOfBlock holds the size of the block in bytes (including the size of the IMAGE_BASE_RELOCATION struct).


http://research32.blogspot.com/2015/01/base-relocation-table.html

	*/
	IMAGE_DATA_DIRECTORY *returnTable =  &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (returnTable->VirtualAddress == NULL) {
		return NULL;
	}
	else {
		return returnTable;
	}
}

void fixImportAddressTable(BYTE* baseAddress) {
	/*
	The Import Address Table (IAT) is a call table of user-space modules. The executable modules running on Windows possess one or more IATs integrated as part of their file structures.
	For example, in case of an .exe file, an IAT stores the addresses of particular library functions imported from DLLs. That explains the name of this table.
	Generally speaking, a call table is nothing more than an array where each element contains the address of a certain routine.
	*/
	std::cout << "[+] IAT Fix starts...";
	IMAGE_NT_HEADERS* ntHeader = ntHeaders(baseAddress);
	IMAGE_DATA_DIRECTORY* iatDirectory = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (iatDirectory->VirtualAddress == NULL) {
		std::cout << "[!] Import Address Table not found" << std::endl;
	}
	else {
		/*
		Each data directory entry specifies the size and relative virtual address of the directory. To locate a particular directory, you determine the relative address from the data directory array in the optional header. Then use the virtual address to determine which section the directory is in. Once you determine which section contains the directory, the section header for that section is then used to find the exact file offset location of the data directory.
		So to get a data directory, you first need to know about sections, which are described next. An example of how to locate data directories immediately follows this discussion
		Data directories exist within the body of their corresponding data section. Typically, data directories are the first structure within the section body, but not out of necessity. For that reason, you need to retrieve information from both the section header and optional header to locate a specific data directory.

		The executable also lists all of the functions it will require from each dll. Because the function addresses are not static a mechanism had to be developed that allowed for the these variables to be changed without needing to alter all of the compiled code at runtime.

		http://sandsprite.com/CodeStuff/Understanding_imports.html
		*/
		size_t iatSize = iatDirectory->Size;
		size_t iatRVA = iatDirectory->VirtualAddress;
		IMAGE_IMPORT_DESCRIPTOR* ITEntryCursor = NULL;
		size_t parsedSize = 0;
		/*
		When dealing with reflective DLLs, we need to load all the dependent libraries of the DLL into the current process and fix up the IAT to make sure that the functions that the DLL imports point to correct function addresses in the current process memory space.
		In order to load the depending libraries, we need to parse the DLL headers and:
		Get a pointer to the first Import Descriptor
		From the descriptor, get a pointer to the imported library name
		Load the library into the current process with LoadLibrary
		Repeat process until all Import Descriptos have been walked through and all depending libraries loaded
		 The anchor of the imports data is the IMAGE_IMPORT_DESCRIPTOR structure. The DataDirectory entry for imports points to an array of these structures.
		 There's one IMAGE_IMPORT_DESCRIPTOR for each imported executable. The end of the IMAGE_IMPORT_DESCRIPTOR array is indicated by an entry with fields
		 all set to 0. Figure 5 shows the contents of an IMAGE_IMPORT_DESCRIPTOR.
		Each IMAGE_IMPORT_DESCRIPTOR typically points to two essentially identical arrays. These arrays have been called by several names, but the two most
		common names are the Import Address Table (IAT) and the Import Name Table (INT). Figure 6 shows an executable importing some APIs from USER32.DLL.
		
		Both arrays have elements of type IMAGE_THUNK_DATA, which is a pointer-sized union. Each IMAGE_THUNK_DATA element corresponds to one imported function
		from the executable. The ends of both arrays are indicated by an IMAGE_THUNK_DATA element with a value of zero. The IMAGE_THUNK_DATA union is a DWORD 
		with these interpretations:
		**https://relearex.wordpress.com/2017/12/26/hooking-series-part-i-import-address-table-hooking/
		The VirtualAddress member in this array element describes the location of the import directory. The import directory in turn is also an array. 
		The elements of this array consist of structures of type IMAGE_IMPORT_DESCRIPTOR. One structure of this type is assigned for each DLL that is imported by the module.
		Again, only the most relevant fields for us will be discussed. For that reason, the three MIMs (Most Import Members) are the following:

		a) OriginalFirstThunk
		-> RVA of the Import Lookup Table(ILT)
		b) Name	
		-> RVA of an ASCII string (null terminated) -> i.e. DLL name
		c) FirstThunk
		-> RVA of Import Address Table (IAT)
		The members OriginalFirstThunk and FirstThunk point to an array of IMAGE_THUNK_DATA structures. This structure embodies a union of several members.
		For each function used by the module in form of an import, we will encounter a IMAGE_THUNK_DATA structure (like each imported DLL is represented by a
		IMAGE_IMPORT_DESCRIPTOR structure as explained above).
		The prototype of the IMAGE_THUNK_DATA structure can be shown as follows:
		For each function used by the module in form of an import, we will encounter a IMAGE_THUNK_DATA structure (like each imported DLL is represented by a  IMAGE_IMPORT_DESCRIPTOR structure as explained above).
		The prototype of the IMAGE_THUNK_DATA structure can be shown as follows:

typedef struct _IMAGE_THUNK_DATA {
	 union {
		 ...
		 PDWORD Function;
		 DWORD Ordinal;
		 PIMAGE_IMPORT_BY_NAME AddressOfData;
	 }u1;
}IMAGE_THUNK_DATA32;
	The reason why we have two arrays is very simple:
	The purpose of the ILT array is to store names of the imported functions whereas the purpose of the IAT array is to conserve the addresses of the imports.
	Kimi function ordinal (index) ile import edilmiş olabilir, isim yerine
	OriginalFirstThunk pointed to Import Name Table which includes Names of functions that exported by the Milad.Dll. Functions in this table have a unique index which loader takes that index and go to the next step and reference to Import Ordinal Table with that index and takes the value which there is into that index of Import Ordinal Table which It’s another integer value.
FirstThunk is another important member which point to IAT. in the previous step dynamic loader takes an integer value via IOT. this value is an index number which dynamic loader refer to IAT with that value. In this table, there is an address in index value which dynamic loader gets from INT-IOT. After these steps when dynamic loader finds out the correct address of the function, it puts that address to Import Address Table for MPrint function. So the process can call that function with its address.
		*/
		for (; parsedSize < iatSize; parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
			ITEntryCursor = (IMAGE_IMPORT_DESCRIPTOR*)(iatRVA+(ULONG_PTR) baseAddress+ parsedSize);
			if (ITEntryCursor->OriginalFirstThunk == NULL && ITEntryCursor->FirstThunk == NULL) {
				break;
			}
			LPSTR dllName = (LPSTR)((ULONGLONG)baseAddress + ITEntryCursor->Name);
			std::cout << "[+] Imported DLL Name: " << dllName << std::endl;
			//Address
			size_t firstThunkRVA = ITEntryCursor->FirstThunk;
			//Name
			size_t originalFirstThunkRVA = ITEntryCursor->OriginalFirstThunk;
			if (originalFirstThunkRVA == NULL) originalFirstThunkRVA = ITEntryCursor->FirstThunk;
			size_t offsetFirstThunk = 0;
			size_t offsetOriginalFirstThunk = 0;
			while (true){
				//The WINNT.H file provides the IMAGE_SNAP_BY_ORDINAL macro to determine whether it's an import by ordinal. It also provides the IMAGE_ORDINAL macro to get the ordinal from the 32 - bit number in the ILT.The ILT is a variable - sized array.
				// The end of the ILT is marked with a 0.
				IMAGE_THUNK_DATA* firstThunkData = (IMAGE_THUNK_DATA*)(baseAddress + offsetFirstThunk + firstThunkRVA);
				IMAGE_THUNK_DATA* originalFirstThunkData = (IMAGE_THUNK_DATA*)(baseAddress + offsetOriginalFirstThunk + originalFirstThunkRVA);
				break;

			}
		}
	}
}

void peLoader(unsigned char* baseAddr) {
	IMAGE_NT_HEADERS* ntHeader = ntHeaders(baseAddr);
	IMAGE_DATA_DIRECTORY* relocTable = getRelocTable(ntHeader);
	ULONGLONG preferableAddress = ntHeader->OptionalHeader.ImageBase;
	HMODULE ntdllHandler = LoadLibraryA("ntdll.dll");
	//Unmap the preferable address
	((int(WINAPI*)(HANDLE, PVOID))GetProcAddress(ntdllHandler, "NtUnmapViewOfSection"))((HANDLE)-1, (LPVOID)ntHeader->OptionalHeader.ImageBase);
	BYTE *imageBaseForPE = (BYTE*)VirtualAlloc((LPVOID) preferableAddress, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!imageBaseForPE && !relocTable){
		std::cout << "[!] No Relocation Table and Cannot load to the preferable address" << std::endl;
		return;
	}
	if (!imageBaseForPE && relocTable){
		std::cout << "[+] Cannot load to the preferable address" << std::endl;
		imageBaseForPE = (BYTE*)VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!imageBaseForPE){
			std::cout << "[!] Cannot allocate the memory" << std::endl;
			return;
		}
	}
	ntHeader->OptionalHeader.ImageBase = (ULONGLONG) imageBaseForPE;
	// SizeOfHeaders indicates how much space in the file is used for representing all the file headers, including the MS - DOS header, PE file header, PE optional header, and PE section headers.The section bodies begin at this location in the file.
	memcpy(imageBaseForPE, baseAddr, ntHeader->OptionalHeader.SizeOfHeaders);
	std::cout << "[+] All headers are copied" << std::endl;
	IMAGE_SECTION_HEADER *sectionHeaderCursor = (IMAGE_SECTION_HEADER *)(size_t(ntHeader) + sizeof(IMAGE_NT_HEADERS));
	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++){
		memcpy(imageBaseForPE + sectionHeaderCursor[i].VirtualAddress, baseAddr + sectionHeaderCursor[i].PointerToRawData, sectionHeaderCursor[i].SizeOfRawData);
	}
	std::cout << "[+] All sections are copied" << std::endl;
	fixImportAddressTable(imageBaseForPE);
}

int main() {
	//Get image base address from struct offsets of PEB and TEB
	size_t fileSizeForDebug;
	unsigned char encryptKey[16];
	unsigned char IVKey[16];
	int* originalDataLength;
	int* encryptedDataLength;
	unsigned char* encryptedContent;
	unsigned char* originalContent;
	char *TEBPtr = (char *) __readgsqword(0x30);
	char *PEBPtr = *((char **) (TEBPtr + 0x060));
	char* imageBaseAddress = *(char**)(PEBPtr+0x10);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBaseAddress;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)(imageBaseAddress + dosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER sectionHeadersCursor = (PIMAGE_SECTION_HEADER)(((PBYTE)imageNTHeaders) + sizeof(IMAGE_NT_HEADERS));
	BYTE buf[10];
	for (unsigned int i = 1; i <= imageNTHeaders->FileHeader.NumberOfSections; i++) {
		//std::cout << sectionHeadersCursor->Name << std::endl;
		if (strncmp((const char*)sectionHeadersCursor->Name, ".huan", 5) == 0) {
			std::cout << "Bulundu" << std::endl;
			break;
		}
		sectionHeadersCursor = (PIMAGE_SECTION_HEADER)((PBYTE)sectionHeadersCursor + 0x28);
	}
	
	BYTE* binaryContent = (BYTE *) readBinary("C:\\Users\\picus\\source\\repos\\DummyFile\\x64\\Release\\DummyFile.exe",&fileSizeForDebug);
	peLoader(binaryContent);
	/*
	char* sectionValuePtr = imageBaseAddress + sectionHeadersCursor->VirtualAddress;
	printf("%p\n", sectionValuePtr);
	//New Section contains 4 byte original length + 4 byte encrypted length + 16 byte Key + 16 byte IV + encrypted data
	originalDataLength = (int *) sectionValuePtr;
	encryptedDataLength = (int*)(sectionValuePtr + 4);
	memcpy(encryptKey,sectionValuePtr + 8, 16);
	memcpy(IVKey,sectionValuePtr + 24, 16);
	encryptedContent = (unsigned char*) malloc(*encryptedDataLength);
	originalContent = (unsigned char*)malloc(*originalDataLength);
	memcpy(encryptedContent, sectionValuePtr + 40, *encryptedDataLength);
	decryptData(encryptedContent, *encryptedDataLength, encryptKey, IVKey);
	memcpy(originalContent, encryptedContent, *originalDataLength);

	printf("Original Content: ");
	free(encryptedContent);
	for (int i = 0; i < *originalDataLength; i++) {
		printf(" %c", originalContent[i]);
	}
	printf("\n");
	//Size of raw image shows the required address space (Last section Virtual Address + Last section virtual size
	*/
	return 0;
}