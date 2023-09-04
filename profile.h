#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <map>
#include <list>

class ProFile
{
public:
	ProFile(std::string file);

	std::list<std::string> ReadPrivateProfileSectionNames();

	int32_t ReadProfileIntegerA(std::string section, std::string key);

	uint32_t ReadProfileStringsA(std::string section, std::string key, char* buffer, uint32_t size);

	std::map<std::string, std::string> ReadProfileSectionsA(std::string section);

	int32_t WriteProfileStringsA(std::string section, std::string key, std::string buffer);

	int32_t WriteProfileIntegerA(std::string seciton, std::string key, int32_t contect);

	int32_t WriteProfileSectonsA(std::string section, std::string buffer);

	int32_t DeleteProfileString(std::string section, std::string key);

	int32_t DeleteProfileSection(std::string section);

private:
	std::string m_file;
};
