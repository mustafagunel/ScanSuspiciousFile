#ifndef UNICODE
#define UNICODE
#endif 
#define CURL_STATICLIB

#include <Windows.h>
#include <tchar.h>

#include "OffsetCalc.h"
#include "Sample.h"
#include "Worker.h"
#include "Sand.h"


#include <json/value.h>
#include <json/json.h>
#include <fstream>

/*
64-bit'e uyarlanacak
hata kontrolleri yapýlacak
*/

M::Sample* sample;
int main(int argc, char* argv[])
{
    int counter;
    char* szFilePath;
    M::Worker worker;
    std::string fileHash;
    Json::Value jsonData;

    if (argc == 1) {
        printf("\n-f [filepath]");

        return EXIT_FAILURE;
    }

    if (argc >= 2)
    {
        for (counter = 0;counter < argc;counter++) {
            if (!strcmp(argv[counter],"-f")) {
                szFilePath = argv[counter + 1];
                std::cout << "\nProgram Starting.. "<< std::endl;

                M::Sample* sample = new M::Sample(szFilePath);
                *sample = worker.setPEHeader(*sample);
                sample->getInfo();
                fileHash = *sample->getHashes();
            }
        }

        jsonData = worker.searchMalwareBazaar(fileHash, jsonData);

        std::string r = worker.jsonToStr(jsonData["query_status"]);

        if (r == "\"hash_not_found\"") {
            std::cout << "\n[+] Hash not found.";
        }
        else if (r != "\"ok\"") {
            std::cout << "\n[!] ERROR: Malware bazaar not respond";
        }
        else {
            std::cout << "\n[+] Query Status OK";
            M::Cert cert(jsonData["data"][0]["vendor_intel"]["CERT-PL_MWDB"]);
            M::Yoroi yoroi(jsonData["data"][0]["vendor_intel"]["YOROI_YOMI"]);
            M::AnyRun anyrun(jsonData["data"][0]["vendor_intel"]["ANY.RUN"]);
            M::VxCube vxcube(jsonData["data"][0]["vendor_intel"]["vxCube"]);
            M::VMRay vmray(jsonData["data"][0]["vendor_intel"]["VMRay"]);
            M::InQuest inquest(jsonData["data"][0]["vendor_intel"]["InQuest"]);
            M::Intezer intezer(jsonData["data"][0]["vendor_intel"]["Intezer"]);
            M::Cape cape(jsonData["data"][0]["vendor_intel"]["CAPE"]);
            M::Triage triage(jsonData["data"][0]["vendor_intel"]["Triage"]);
            M::ReversingLabs reversinglabs(jsonData["data"][0]["vendor_intel"]["ReversingLabs"]);
            M::UnpackMe unpackme(jsonData["data"][0]["vendor_intel"]["UnpacMe"]);
            M::FileScanIO filescanio(jsonData["data"][0]["vendor_intel"]["FileScanIO"]);

            try {
                std::cout << "\n ------------------------------- \n"
                    << "ANY.RUN : " << anyrun.detection << std::endl
                    << "CERT-PL_MWDB : " << cert.detection << "\n\tCer link: " << cert.link << std::endl
                    << "YOROI_YOMI : " << yoroi.detection << std::endl
                    << "vxCube : " << vxcube.detection << std::endl
                    << "VMRay : " << vmray.detection << std::endl
                    << "InQuest : " << inquest.detection << std::endl
                    << "Intezer : " << intezer.detection << std::endl
                    << "CAPE : " << cape.detection << std::endl
                    << "Triage : " << triage.detection << std::endl
                    << "ReversingLabs :" << reversinglabs.detection << std::endl
                    << "UnpacMe : " << unpackme.detection << std::endl
                    << "FileScanIO : " << filescanio.detection << std::endl
                    << "\n ------------------------------- \n";

            }
            catch (int) {
                std::cout << "Integer exception raised." << std::endl;
            }
        }

    }

    return EXIT_SUCCESS;

}
