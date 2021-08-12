char* readBinary(const char* fileName, size_t *fileSize);
char* createNewSectionHeader(char* imageBase,unsigned char* packedContent, size_t packedLength, size_t *newFileSize);
bool saveNewPE(char* newFile, size_t lengthOfFile, const char* fileName);