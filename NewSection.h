char* readBinary(char* fileName, size_t *fileSize);
char* createNewSectionHeader(char* imageBase,size_t stubLength, size_t *newFileSize);
void saveNewPE(char* newFile, size_t lengthOfFile, const char* fileName);