#include "Sample.h"
#include "iostream"
#include <string>

#include "Worker.h"

M::Worker worker;

void M::Sample::init() {
	M::Sample::sandBoxResults[0][0] = "A Sandbox";
	M::Sample::sandBoxResults[0][1] = "B Sandbox";
	M::Sample::sandBoxResults[0][2] = "C Sandbox";
	M::Sample::sandBoxResults[0][3] = "D Sandbox";

	M::Sample::sandBoxResults[1][0] = "0";
	M::Sample::sandBoxResults[1][1] = "1";
	M::Sample::sandBoxResults[1][2] = "1";
	M::Sample::sandBoxResults[1][3] = "0";
	printSandBoxResults();
}

M::Sample::Sample(char* szFilePath) {
	init();
	this->path = szFilePath;
	this->name = std::string(szFilePath).substr(std::string(szFilePath).find_last_of("\\/") + 1);
	this->setHash();

}

std::string* M::Sample::getHashes() {
	return this->hash;
}

void M::Sample::setHash() {
	const char* hashType[] = { "md5", "sha256" };
	for (int i = 0; i < 2;i++) {
		this->hash[i] = worker._execHashCmd(this->path, *(hashType + i));
	}
}

void M::Sample::printSandBoxResults() {
	std::cout << "\nSandbox results:\n";
	
}


void M::Sample::getInfo() {
	std::string* _h = this->getHashes();
	std::cout << "\n\nFile Name: " << this->name << "\nMD5 : " << *_h << "\nSHA256 : " << *(_h + 1);


	if (!this->blackListDlls.empty()) {
		std::cout << "\n\nBlackList APIs\n";
		std::vector<std::string>::iterator ptr;
		for (ptr = this->blackListDlls.begin(); ptr < this->blackListDlls.end() - 1; ptr++)
			std::cout << *ptr << ", ";
		std::cout << *ptr;
		std::cout << std::endl;
	}
	
}