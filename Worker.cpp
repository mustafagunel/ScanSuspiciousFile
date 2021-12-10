#include "Worker.h"


std::string M::Worker::_execHashCmd(const char* filePath, const char* _hashType) {

    char cmd[500];
    std::string result = "";
    const char* hashType = _hashType;
    
    if (strcmp(hashType, "md5") & strcmp(hashType, "MD5") & strcmp(hashType, "sha256") & strcmp(hashType, "SHA256")) {
        std::cout << "ERROR: check hash type.";
        return "ERROR";
    }
    // concat command
    const char* c = "certutil -hashfile ";
    strcpy_s(cmd, c);
    strcat_s(cmd, "\"");
    strcat_s(cmd, filePath);
    strcat_s(cmd, "\"");
    strcat_s(cmd, " ");
    strcat_s(cmd, hashType);


    result = M::Worker::_exec(cmd);

    // parse cmd result
    result = result.substr(0, result.find("CertUtil:"));
    result = result.substr(result.find(filePath) + std::string(filePath).length() + 2);
    result = result.substr(0, result.find("\n"));

    return result;
}


std::string M::Worker::_exec(const char* cmd) { 

    char buffer[128];
    std::string result = "";

    FILE* pipe = _popen(cmd, "r");
    if (!pipe) throw std::runtime_error("popen() failed!");
    try {
        while (fgets(buffer, sizeof buffer, pipe) != NULL)
            result += buffer;
    }
    catch (...) {
        _pclose(pipe);
        throw;
    }
    _pclose(pipe);


    return result;
}

M::Sample M::Worker::setPEHeader(M::Sample sample) {

    HANDLE hFile;
    HANDLE hMap;
    HANDLE hMapView;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pImageHeader;

    PIMAGE_DATA_DIRECTORY pDataDirectory;
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;

    PIMAGE_THUNK_DATA32 pOriginalFirstThunk;
    PIMAGE_THUNK_DATA32 pFirstThunk;
    PIMAGE_THUNK_DATA64 pOriginalFirstThunk64;
    PIMAGE_THUNK_DATA64 pFirstThunk64;

    BOOL bFound = FALSE;
    PIMAGE_IMPORT_BY_NAME pNameImg;
    std::string dllName;


    hFile = CreateFile(sample.path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (checkHandle(hFile)) {
        hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        if (checkHandle(hMap)) {
            hMapView = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
            pDosHeader = (PIMAGE_DOS_HEADER)hMapView;       // get dos header of mapped file
            if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {           //check MZ
                std::cout << "\n\n[-] ERROR: Not valid PE. e_magic != MZ";
                return sample;
            }
            else {
                //printf("\n%x (MZ) found, valid PE.\nPE Header offset: 0x%x\n", pDosHeader->e_magic, pDosHeader->e_lfanew);
            }

            pImageHeader = (PIMAGE_NT_HEADERS)((char*)pDosHeader + pDosHeader->e_lfanew); //PE Header
            
            if (pImageHeader->Signature != IMAGE_NT_SIGNATURE) {
                std::cout << "[-] ERROR : PE00 couldn't found.";
                return sample;
            }
            //printf("\nImageBase: 0x%x\n\n", pImageHeader->OptionalHeader.ImageBase);
            //printf("\nAddress of Entry Point: 0x%x", pImageHeader->OptionalHeader.AddressOfEntryPoint);  //.text section

            switch (pImageHeader->OptionalHeader.Magic)
            {
                case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
                    sample.magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
                case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
                    sample.magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
                default:
                    break;
            }

            pDataDirectory = &pImageHeader->OptionalHeader.DataDirectory[1]; //.rdata section offseti sanýrým.
            pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((char*)pDosHeader + RvaToOffset(pImageHeader, pDataDirectory->VirtualAddress)); //first imported dll

            if (sample.magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
                while (pImportDescriptor->OriginalFirstThunk != 0 && !bFound)
                {
                    pOriginalFirstThunk = (PIMAGE_THUNK_DATA32)((char*)pDosHeader + RvaToOffset(pImageHeader, pImportDescriptor->OriginalFirstThunk));
                    pFirstThunk = (PIMAGE_THUNK_DATA32)((char*)pDosHeader + RvaToOffset(pImageHeader, pImportDescriptor->FirstThunk));


                    dllName = ((char*)pDosHeader + RvaToOffset(pImageHeader, pImportDescriptor->Name));
                    //std::cout << "\n\n" << dllName << std::endl << "''''''''''''''''''";

                    while (pOriginalFirstThunk->u1.AddressOfData != 0 && !bFound) {
                        pNameImg = (PIMAGE_IMPORT_BY_NAME)((char*)pDosHeader + RvaToOffset(pImageHeader, pOriginalFirstThunk->u1.AddressOfData));

                        for (int i = 0; i < sizeof(blackList) / sizeof(blackList[0]); i++) {
                            if (!strcmp((const char*)pNameImg->Name, this->blackList[i][0])) {
                                sample.blackListDlls.push_back((const char*)pNameImg->Name);
                                //std::cout << "\n[!] Found BlackList API: " << (const char*)pNameImg->Name << std::endl;
                            }
                        }

                        //printf("\n%s", (const char*)pNameImg->Name);
                        pOriginalFirstThunk++;
                        pFirstThunk++;
                    }
                    pImportDescriptor++;
                }
            }
            
        }
    }

    return sample;
}

bool M::checkHandle(HANDLE h) {
    if (h == INVALID_HANDLE_VALUE) {
        std::cout << "\n[-] ERROR: Invalid handle value! \n";
        return false;
    }
    return true;
}


DWORD M::RvaToOffset(IMAGE_NT_HEADERS32* pNtHdr, DWORD dwRVA)
{
    int i;
    WORD wSections;
    PIMAGE_SECTION_HEADER pSectionHdr;

    pSectionHdr = IMAGE_FIRST_SECTION(pNtHdr);  //gets first section (.text)
    wSections = pNtHdr->FileHeader.NumberOfSections;    

    for (i = 0; i < wSections; i++) // look for next section
    {
        if (pSectionHdr->VirtualAddress <= dwRVA)  // .txt = 1000 ? dwRVA = 8d620  (+)  - compare section VA
            if ((pSectionHdr->VirtualAddress + pSectionHdr->Misc.VirtualSize) > dwRVA)  // .txt = 1000+80017=81017 ? dwRVA = 8d620 (-)
            {
                dwRVA -= pSectionHdr->VirtualAddress; 
                dwRVA += pSectionHdr->PointerToRawData; 

                return (dwRVA);
            }

        pSectionHdr++;
    }

    return 0;
}


Json::Value M::Worker::searchMalwareBazaar(std::string fileHash, Json::Value jsonData) {

    cURLpp::Easy easyhandle;
    std::ofstream ofResult;
    std::ostringstream oss;

    try {

        easyhandle.setOpt(cURLpp::Options::Url("https://mb-api.abuse.ch/api/v1/"));
        easyhandle.setOpt(cURLpp::Options::Verbose(false));
        easyhandle.setOpt(cURLpp::Options::Timeout(500));
        {
            // Forms takes ownership of pointers!
            curlpp::Forms formParts;
            formParts.push_back(new curlpp::FormParts::Content("hash", fileHash));
            formParts.push_back(new curlpp::FormParts::Content("query", "get_info"));

            easyhandle.setOpt(new curlpp::options::HttpPost(formParts));
        }
        curlpp::options::WriteStream ws(&oss);
        easyhandle.setOpt(ws);

        easyhandle.perform();

        if (curlpp::infos::ResponseCode::get(easyhandle) == 200) {

            ofResult.open("MalwareBazaar.json");
            if (ofResult.fail()) {
                std::cout << "[!] (ofstream error) Can't read MalwareBazaar.json";
                return "";
            }
            ofResult << oss.str();
            ofResult.close();
            
            std::ifstream ifRead("MalwareBazaar.json", std::ifstream::binary);
            if (ifRead.fail()) {
                std::cout << "[!] (ifstream error) Can't read MalwareBazaar.json";
                return "";
            }
            ifRead >> jsonData;
            ifRead.close();
        }
        else {
            std::cout << "\n\n [!] Server doesn't response.";
            return "";
        }

    }
    catch (curlpp::LogicError& e) {
        std::cout << "\n\n[!] " << e.what() << std::endl;
        return "";
    }
    catch (curlpp::RuntimeError& e) {
        std::cout << "\n\n[!] " << e.what() << std::endl;
        return "";
    }

    return jsonData;
}

std::string M::Worker::jsonToStr(Json::Value jsonData) {

    Json::StreamWriterBuilder builder;
    builder["indentation"] = ""; // If you want whitespace-less output
    const std::string temp = Json::writeString(builder, jsonData);


    return temp;
}
