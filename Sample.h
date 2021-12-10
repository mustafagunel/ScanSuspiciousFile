#pragma once

#include <iostream>
#include <vector>
#include <string>


namespace M {
	class Sample
	{
		private:
			void init();
		public:
			char* path;
			std::string name;
			int magic;
			std::string hash[2];
			std::vector<std::string> blackListDlls;
			std::string sandBoxResults[2][4];
			float suspectRatio = 0.0f;

			Sample(char* szFilePath);
			std::string* getHashes();
			void setHash();
			void printSandBoxResults();

			void getInfo();
	};
}
