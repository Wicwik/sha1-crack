#include "sha1/sha1.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <optional>
#include <fstream>

class SHA1Bruteforcer
{
public:
	SHA1Bruteforcer(std::string hash, std::string salt = "", std::string input_file = "")
		: m_hash{hash}
		, m_salt{salt}
		, m_input_file{input_file}

	{
	}

	void crack()
	{
		if (m_input_file.empty())
		{
			m_crack_sha1();
		}
		else
		{
			std::cout << "Not yet implemeted" << std::endl;
		}
	}

private:
	std::string m_hash;
	std::string m_salt;
	std::string m_input_file;
	std::string m_result;
	bool m_found_hash = false;

	void m_make_permutations(std::string input_str, std::string permutations, unsigned int last, unsigned int current)
	{
		if (m_found_hash)
		{
			return;
		}

		for (const auto& i : input_str)
		{
			permutations[current] = i;
			if (current == last)
			{
				SHA1 checksum;
			    checksum.update(permutations);
			    const std::string hash = checksum.final();

				if (!m_hash.compare(hash))
				{
					std::cout << "The hash is: " << permutations <<  std::endl;
					m_result = permutations;
					m_found_hash = true;
				}
			}
			else
			{
				m_make_permutations(input_str, permutations, last, current+1);
			}	
		}
	}

	std::string m_make_allchar_string()
	{
		std::string allchar;
		for (unsigned char i = 32; i < 127; i++)
		{
			allchar.push_back(static_cast<char>(i));
		}

		return allchar;
	}

	std::string m_crack_sha1()
	{

		std::string allchar = m_make_allchar_string();
		// std::cout << allchar << std::endl;

		for (unsigned int i = 0; i < 32; i++)
		{
			std::string permutations;
			permutations.resize(i+1);
			m_make_permutations(allchar, permutations, i, 0);

			if (m_found_hash)
			{
				break;
			}
		}
		
		if (!m_found_hash)
		{
			std::cerr << "Could not decrypt the hash." << std::endl; 
		}

		return " ";
	}
};

std::optional<std::map<std::string, std::string>> parse_args(int argc, char** argv)
{
	std::map<std::string, std::string> args;

	if (argc < 2)
	{
		std::cerr << "At least 1 argument required" << std::endl;
		return std::nullopt;
	}

	for (int i = 1; i < argc; i++)
	{
		std::string arg = argv[i];

		if (arg == "-S" || arg == "--salt")
		{
			if (i == argc - 1 || argc < 3)
			{
				std::cerr << arg << " parameter requires a salt" << std::endl;
				return std::nullopt;
			}

			args["salt"] = argv[++i];
			continue;
		}

		if (arg == "-I" || arg == "--input")
		{
			if (i == argc - 1 || argc < 3)
			{
				std::cerr << arg << " parameter requires an input file" << std::endl;
				return std::nullopt;
			}

			args["input"] = argv[++i];
			continue;
		}

		args["hash"] = arg;
	}

	return args;

}

int main(int argc, char **argv)
{
	auto args =  parse_args(argc, argv).value_or(std::map<std::string, std::string>());
	if (args.empty())
	{
		std::cerr << "Error ocured - wrong or empty arguments." << std::endl;
		return 1;
	}

	if (args["hash"].empty() && args["input"].empty())
	{
		std::cerr << "Error ocured - no hash or input file specified." << std::endl;
		return 1;
	}

	SHA1Bruteforcer sha_bf(args["hash"], args["salt"], args["input"]);	
	sha_bf.crack();

	return 0;
}