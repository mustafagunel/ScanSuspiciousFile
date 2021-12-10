#pragma once

#include "iostream"
#include <string>
#include <mutex>
#include "Sample.h"
#include <Windows.h>



#include <curlpp/cURLpp.hpp>
#include <curlpp/Easy.hpp>
#include <curlpp/Options.hpp>
#include <curlpp/Exception.hpp>
#include <curlpp/Infos.hpp>
#include <json/value.h>
#include <json/json.h>
#include <fstream>


namespace M {
	class Worker
	{
		public:

			const char* blackList[47][2] = {
				"Accept","0",
				"AdjustTokenPrivileges","0",
				"AttachThreadInput","0",
				"Bind","0",
				"BitBlt","0",
				"CertOpenSystemStore","0",
				"Connect","0",
				"ConnectNamedPipe","0",
				"ControlService","0",
				"CreateFile","0",
				"CreateFileMapping","0",
				"CreateMutex","0",
				"CreateProcess","0",
				"CreateRemoteThread","0",
				"CreateService","0",
				"CreateToolhelp32Snapshot","0",
				"CryptAcquireContext","0",
				"DeviceIoControl","0",
				"EnableExecuteProtectionSupport","0",
				"EnumProcesses","0",
				"EnumProcessModules","0",
				"FindFirstFile","0",
				"FindNextFile","0",
				"FindResource","0",
				"FindWindow","0",
				"FtpPutFile","0",
				"GetAdaptersInfo","0",
				"GetAsyncKeyState","0",
				"GetDC","0",
				"GetForegroundWindow","0",
				"Gethostbyname","0",
				"Gethostname","0",
				"GetKeyState","0",
				"GetModuleFilename","0",
				"GetModuleHandle","0",
				"GetProcAddress","0",
				"GetStartupInfo","0",
				"GetSystemDefaultLangId","0",
				"GetTempPath","0",
				"GetThreadContext","0",
				"GetVersionEx","0",
				"GetWindowsDirectory","0",
				"inet_addr","0",
				"InternetOpen","0",
				"InternetOpenUrl","0",
				"InternetReadFile","0",
				"InternetWriteFile","0"

			};
			std::string sandBoxResults[10][2] = {};

			std::string _execHashCmd(const char* filePath, const char* _hashType); //get parsed file hash
			std::string _exec(const char* cmd); //execute on cmd
			std::string jsonToStr(Json::Value jsonData);
			Json::Value searchMalwareBazaar(std::string fileHash, Json::Value jsonData);

			M::Sample setPEHeader(M::Sample sample);


		

	};


	bool checkHandle(HANDLE h);
	DWORD RvaToOffset(IMAGE_NT_HEADERS32* pNtHdr, DWORD dwRVA);
}


