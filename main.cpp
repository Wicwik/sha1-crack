#include "sha1/sha1.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <optional>
#include <fstream>
#include <exception>
#include <chrono>
#include <future>
#include <atomic>
#include <algorithm>

class SHA1Bruteforcer
{
public:
	SHA1Bruteforcer(std::vector<std::string> hashes, std::string salt = "", std::string dictionary = "")
		: m_hashes{hashes}
		, m_salt{salt}
		, m_dictionary{dictionary}
	{
	}

	void crack()
	{
		m_totalpass = m_hashes.size();

		for (const auto& hash : m_hashes)
		{
			if (m_dictionary.empty())
			{
				std::cout << "INFO: Currently found " << m_passcount << "/" << m_totalpass << " passwords." << std::endl;
				std::cout << "INFO: Going straight to permutation brute force." << std::endl;;
				m_crack_sha1(hash);
			}
			else
			{
				std::cout << "INFO: Currently found " << m_passcount << "/" << m_totalpass << " passwords." << std::endl;
				std::cout << "INFO: Trying dictionary for " << hash << " search." << std::endl;
				m_crack_dictionary_sha1(hash);

				if (!m_foundpass)
				{
					std::cout << "INFO: Dictionary search failed, switching to permutation brute force." << std::endl;
					m_crack_sha1(hash);
				}
			}

			if (!m_foundpass)
			{
				throw std::logic_error( "ERROR: Hash not found." );
			}
			else
			{
				m_foundpass = false;
			}
		}
	}

private:
	std::vector<std::string> m_hashes;
	std::string m_salt;
	std::string m_dictionary;

	bool m_foundpass = false;

	uint64_t m_hash_count = 0;
	uint64_t m_hashrate = 0;

	std::atomic<size_t> m_passcount = 0;
	size_t m_totalpass;


	void m_print_info(std::string current)
	{
		std::cout << "INFO: Currently found " << m_passcount << "/" << m_totalpass << " passwords." << std::endl;
		std::cout << "Current hashrate is around " << m_hashrate << " hash per second." << std::endl;
		std::cout << "Currently guessing word " << current << std::endl;
	}

	bool m_compare_hash(std::string candidate, std::string hash)
	{
		SHA1 checksum;
		checksum.update(candidate);
		const std::string cand_hash = checksum.final();

		m_hash_count++;

		if (m_hashrate && (m_hash_count%(m_hashrate*7) == 0))
		{
			m_print_info(candidate);
		}

		return hash.compare(cand_hash);
	}

	void compare_with_salt(std::string candidate, std::string hash)
	{
		if (!m_compare_hash(candidate, hash))
		{
			m_passcount++;
			m_foundpass = true;
			std::cout << "SUCESS: Found password number " << m_passcount << "/" << m_totalpass << " - " << hash << " => " << candidate <<  std::endl;
			
		}
		else if (!m_compare_hash(candidate + m_salt, hash))
		{
			m_passcount++;
			m_foundpass = true;
			std::cout << "SUCESS: Found password number " << m_passcount << "/" << m_totalpass << " - " << hash << " => " << candidate <<  std::endl;
		}
		else if (!m_compare_hash(m_salt + candidate, hash))
		{
			m_passcount++;
			m_foundpass = true;
			std::cout << "SUCESS: Found password number " << m_passcount << "/" << m_totalpass << " - " << hash << " => " << candidate <<  std::endl;
		}
	}

	void m_make_permutations(std::string input_str, std::string permutations, unsigned int last, unsigned int current, std::string hash)
	{
		if (m_foundpass)
		{
			return;
		}

		
		for (const auto& letter : input_str)
		{
			permutations[current] = letter;
			if (current == last)
			{
				compare_with_salt(permutations, hash);
			}
			else
			{
				m_make_permutations(input_str, permutations, last, current+1, hash);
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

	void m_crack_sha1(std::string hash)
	{

		std::string allchar = m_make_allchar_string();
		// std::cout << allchar << std::endl;

		for (unsigned int i = 0; i < 32; i++)
		{
			std::string permutations;
			permutations.resize(i+1);

			auto start = std::chrono::high_resolution_clock::now();
			m_make_permutations(allchar, permutations, i, 0, hash);
			auto finish = std::chrono::high_resolution_clock::now();

			std::chrono::duration<double> elapsed = finish - start;
			m_hashrate = m_hash_count/elapsed.count();

			if (m_foundpass)
			{
				break;
			}
		}
	}

	void m_crack_dictionary_sha1(std::string hash)
	{
		std::ifstream dictstream(m_dictionary); //opens the file
		if (!dictstream.is_open())
		{
			throw std::runtime_error( "ERROR: Something is wrong with dictionary file." );
		}

		std::string pass_row;
		while(std::getline(dictstream, pass_row))
		{
			compare_with_salt(pass_row, hash);

			if (m_foundpass)
			{
				break;
			}
		}

		if (!m_foundpass && !dictstream.eof()) //unexpected end of stream
		{
			throw std::runtime_error( "ERROR: A mistake in dictionary input stream." );
		}
	}
};

std::optional<std::map<std::string, std::string>> parse_args(int argc, char** argv)
{
	std::map<std::string, std::string> args;

	if (argc < 2)
	{
		std::cerr << "ERROR: At least 1 argument required" << std::endl;
		return std::nullopt;
	}

	for (int i = 1; i < argc; i++)
	{
		std::string arg = argv[i];

		if (arg == "-S" || arg == "--salt")
		{
			if (i == argc - 1 || argc < 3)
			{
				std::cerr << "ERROR: " << arg << " parameter requires a salt." << std::endl;
				return std::nullopt;
			}

			args["salt"] = argv[++i];
			continue;
		}

		if (arg == "-I" || arg == "--input")
		{
			if (i == argc - 1 || argc < 3)
			{
				std::cerr << "ERROR: " << arg << " parameter requires an input file." << std::endl;
				return std::nullopt;
			}

			args["input"] = argv[++i];
			continue;
		}

		if (arg == "-D" || arg == "--dictionary")
		{
			if (i == argc - 1 || argc < 3)
			{
				std::cerr << "ERROR: " << arg << " parameter requires a dictionary file." << std::endl;
				return std::nullopt;
			}

			args["dictionary"] = argv[++i];
			continue;
		}

		if (!args["hash"].empty())
		{
			return std::nullopt;
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
		std::cerr << "ERROR: Wrong or empty arguments." << std::endl;
		return 1;
	}

	if (args["hash"].empty() && args["input"].empty())
	{
		std::cerr << "ERROR: No hash or input file specified." << std::endl;
		return 1;
	}

	std::vector<std::string> hashes;
	if (!args["input"].empty())
	{
		if (!args["hash"].empty())
		{
			std::cerr << "ERROR: invalid argumet " << args["hash"] << std::endl;
			return 1;
		}

		std::ifstream input(args["input"]); //opens the file
		if (!input.is_open())
		{
			std::cerr << "ERROR: Something is wrong with input file" << std::endl;
			return 1;
		}

		std::string hash_row;
		while(std::getline(input, hash_row))
		{
			//TODO check hash format
			hashes.push_back(hash_row);
		}

		if (!input.eof()) //unexpected end of stream
		{
			std::cerr << "ERROR: A mistake in input stream." << std::endl;
			return 1;
		}
	}
	else
	{
		//TODO check hash format
		hashes.push_back(args["hash"]);
	}

	try
	{
		SHA1Bruteforcer sha_bf(hashes, args["salt"], args["dictionary"]);	
		sha_bf.crack();
	}
	catch (const std::exception& e)
	{
		std::cerr << e.what() << std::endl;
		return 1;
	}

	return 0;
}