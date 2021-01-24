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
	SHA1Bruteforcer(std::string hash, std::string salt = "", std::string dictionary = "")
		: m_hash{hash}
		, m_salt{salt}
		, m_dictionary{dictionary}
	{
	}

	std::string crack()
	{
		if (m_dictionary.empty())
		{
			m_crack_sha1();
		}
		else
		{
			m_crack_dictionary_sha1();

			if (!m_found_hash)
			{
				m_crack_sha1();
			}
		}

		if (!m_found_hash)
		{
			// TODO throw
		}

		return m_result;
	}

private:
	std::string m_hash;
	std::string m_salt;
	std::string m_dictionary;

	std::string m_result;
	bool m_found_hash = false;

	bool m_compare_hash(std::string candidate)
	{
		SHA1 checksum;
		checksum.update(candidate);
		const std::string hash = checksum.final();

		return m_hash.compare(hash);
	}

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
				if (!m_compare_hash(permutations))
				{
					std::cout << "The hash is: " << permutations <<  std::endl;
					m_result = permutations;
					m_found_hash = true;
				}
				else if (!m_compare_hash(permutations + m_salt))
				{
					std::cout << "The hash is: " << permutations <<  std::endl;
					m_result = permutations;
					m_found_hash = true;
				}
				else if (!m_compare_hash(m_salt + permutations))
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
		for (unsigned char i = 48; i < 58; i++)
		{
			allchar.push_back(static_cast<char>(i));
		}

		for (unsigned char i = 65; i < 91; i++)
		{
			allchar.push_back(static_cast<char>(i));
		}

		for (unsigned char i = 97; i < 123; i++)
		{
			allchar.push_back(static_cast<char>(i));
		}


		return allchar;
	}

	void m_crack_sha1()
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
	}

	void m_crack_dictionary_sha1()
	{
		std::ifstream dictstream(m_dictionary); //opens the file
		if (!dictstream.is_open())
		{
			std::cerr << "Error while openning input file" << std::endl;
			// TODO throw
		}

		std::string pass_row;
		while(std::getline(dictstream, pass_row))
		{
			if (!m_compare_hash(pass_row))
			{
				std::cout << "The hash is: " << pass_row <<  std::endl;
				m_result = pass_row;
				m_found_hash = true;
				break;
			}
		}
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

		if (arg == "-D" || arg == "--dictionary")
		{
			if (i == argc - 1 || argc < 3)
			{
				std::cerr << arg << " parameter requires a dictionary file" << std::endl;
				return std::nullopt;
			}

			args["dictionary"] = argv[++i];
			continue;
		}

		if (!args["hash"].empty())
		{
			return std::map<std::string, std::string>();
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

	if (!args["input"].empty())
	{
		if (!args["hash"].empty())
		{
			std::cerr << "Error - invalid argumet " << args["hash"] << std::endl;
			return 1;
		}

		std::ifstream input(args["input"]); //opens the file
		if (!input.is_open())
		{
			std::cerr << "Error while openning input file" << std::endl;
			return 1;
		}

		std::string hash_row;
		while(std::getline(input, hash_row))
		{
			std::cout << hash_row << std::endl;
			SHA1Bruteforcer sha_bf(hash_row, args["salt"], args["dictionary"]);	
			sha_bf.crack();
		}

		if (!input.eof()) //unexpected end of stream
		{
			std::cerr << "Error in input stream\n";
			return 1;
		}
	}
	else
	{
		SHA1Bruteforcer sha_bf(args["hash"], args["salt"], args["dictionary"]);	
		sha_bf.crack();
	}

	return 0;
}