/**
* @file config_reader.hpp
* @brief Reads configuration file (like standard Linux .conf files)
* @author philave (philave7@gmail.com)
*/

#ifndef CONFIG_READER_HPP
#define CONFIG_READER_HPP

#include <map>
#include <string>
#include <fstream>
#include <sstream>
#include <regex>

class ConfigReader
{
public:
	ConfigReader(){}
	ConfigReader(const ConfigReader& Reader) : settings(Reader.settings) { }
	void Parse(std::string FileName)
	{
		std::ifstream configFile(FileName);
		std::string line;
		while (std::getline(configFile, line))
		{
			size_t posComment = line.find('#');
			if (posComment != std::string::npos) line = line.substr(0, posComment);
			line = std::regex_replace(line, std::regex("^[ \t]*"), "");
			if (line.size() == 0) continue;
			line = std::regex_replace(line, std::regex("[ \t]+"), " ");
			std::istringstream iStringReader(line);
			std::string key, value;
			iStringReader >> key >> value;
			settings[key] = value;
		}

		// For test
		//for (const auto& item : settings) std::cout << item.first << "=" << item.second << std::endl;
	}

	bool CheckKey(const std::string& Key)
	{
		auto it = settings.find(Key);
		if (it == settings.end()) return false;
		return true;
	}

	const char* GetKeyValue(const std::string& Key)
	{
		return settings[Key].c_str();
	}
private:
	std::map<std::string, std::string> settings;

};

#endif // CONFIG_READER_HPP
