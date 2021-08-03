char* readBinary(char* fileName, size_t *fileSize);
char* createNewSectionHeader(char* imageBase,unsigned char* packedContent, size_t packedLength, size_t *newFileSize);
void saveNewPE(char* newFile, size_t lengthOfFile, const char* fileName);