#include "sha1/sha1.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <optional>
#include <fstream>
#include <exception>
#include <chrono>
#include <algorithm>

class SHA1Bruteforcer
{
public:
	SHA1Bruteforcer(std::string hash, std::string salt = "", std::string dictionary = "", uint64_t current_hash_number = 0, uint64_t todo_hash_count = 1)
		: m_hash{hash}
		, m_salt{salt}
		, m_dictionary{dictionary}
		, m_current_hash_number{current_hash_number}
		, m_todo_hash_count{todo_hash_count}
	{
	}

	std::string crack()
	{
		if (m_dictionary.empty())
		{
			std::cout << "INFO: Currently found " << m_current_hash_number << "/" << m_todo_hash_count << " passwords." << std::endl;
			std::cout << "INFO: Going straight to permutation brute force." << std::endl;;
			m_crack_sha1();
		}
		else
		{
			std::cout << "INFO: Currently found " << m_current_hash_number << "/" << m_todo_hash_count << " passwords." << std::endl;
			std::cout << "INFO: Trying dictionary for " << m_hash << " search." << std::endl;
			m_crack_dictionary_sha1();

			if (!m_found_hash)
			{
				std::cout << "INFO: Dictionary search failed, switching to permutation brute force." << std::endl;
				m_crack_sha1();
			}
		}

		if (!m_found_hash)
		{
			throw std::logic_error( "ERROR: Hash not found." );
		}
		else
		{
			std::cout << "SUCESS: Found password number " << m_current_hash_number+1 << "/" << m_todo_hash_count << " - " << m_hash << " => " << m_result <<  std::endl;
		}

		return m_result;
	}

private:
	std::string m_hash;
	std::string m_salt;
	std::string m_dictionary;

	std::string m_result;
	bool m_found_hash = false;

	uint64_t m_hash_comp_count = 0;
	uint64_t m_current_hash_number;
	uint64_t m_todo_hash_count;

	uint64_t m_hashrate = 0;


	void m_print_info(std::string current)
	{
		std::cout << "INFO: Currently found " << m_current_hash_number << "/" << m_todo_hash_count << " passwords." << std::endl;
		std::cout << "Current hashrate is around " << m_hashrate << " hash per second." << std::endl;
		std::cout << "Currently guessing word " << current << std::endl;
	}

	bool m_compare_hash(std::string candidate)
	{
		SHA1 checksum;
		checksum.update(candidate);
		const std::string hash = checksum.final();

		m_hash_comp_count++;

		if (m_hashrate && (m_hash_comp_count%(m_hashrate*7) == 0))
		{
			m_print_info(candidate);
		}

		return m_hash.compare(hash);
	}

	void compare_with_salt(std::string candidate)
	{
		if (!m_compare_hash(candidate))
		{
			m_result = candidate;
			m_found_hash = true;
		}
		else if (!m_compare_hash(candidate + m_salt))
		{
			m_result = candidate;
			m_found_hash = true;
		}
		else if (!m_compare_hash(m_salt + candidate))
		{
			m_result = candidate;
			m_found_hash = true;
		}
	}

	void m_make_permutations(std::string input_str, std::string permutations, unsigned int last, unsigned int current)
	{
		if (m_found_hash)
		{
			return;
		}

		
		for (const auto& letter : input_str)
		{
			permutations[current] = letter;
			if (current == last)
			{
				compare_with_salt(permutations);
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

			auto start = std::chrono::high_resolution_clock::now();
			m_make_permutations(allchar, permutations, i, 0);
			auto finish = std::chrono::high_resolution_clock::now();

			std::chrono::duration<double> elapsed = finish - start;
			m_hashrate = static_cast<unsigned int>(m_hash_comp_count/elapsed.count());

			if (m_found_hash)
			{
				break;
			}
		}
	}

	void m_crack_dictionary_sha1()
	{
		std::ifstream dictstream(m_dictionary); //opens the file
		if (!dictstream.is_open())
		{
			throw std::runtime_error( "ERROR: Something is wrong with dictionary file." );
		}

		std::string pass_row;
		while(std::getline(dictstream, pass_row))
		{
			compare_with_salt(pass_row);

			if (m_found_hash)
			{
				break;
			}
		}

		if (!m_found_hash && !dictstream.eof()) //unexpected end of stream
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

unsigned int get_hash_count(std::string input_file)
{
	std::ifstream input(input_file); //opens the file
	if (!input.is_open())
	{
		std::cerr << "ERROR: Something is wrong with input file" << std::endl;
		return 0;
	}

	unsigned int count = std::count(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>(), '\n');

	if (count == 0)
	{
		std::cerr << "ERROR: Empty input file, exiting." << std::endl;
		return 0;
	}

	return count+1; // password hashes are divided by newline so there should be no newline on the end of the file
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

	if (!args["input"].empty())
	{
		if (!args["hash"].empty())
		{
			std::cerr << "ERROR: invalid argumet " << args["hash"] << std::endl;
			return 1;
		}

		unsigned int hash_count = get_hash_count(args["input"]);

		if (!hash_count)
		{
			return 1;
		}

		std::ifstream input(args["input"]); //opens the file
		if (!input.is_open())
		{
			std::cerr << "ERROR: Something is wrong with input file" << std::endl;
			return 1;
		}

		unsigned int current_count = 0;
		std::string hash_row;
		while(std::getline(input, hash_row))
		{
			// std::cout << hash_row << std::endl;

			try
			{
				SHA1Bruteforcer sha_bf(hash_row, args["salt"], args["dictionary"], current_count, hash_count);	
				sha_bf.crack();
			}
			catch (const std::exception& e)
			{
				std::cerr << e.what() << std::endl;
				return 1;
			}

			current_count++;
		}

		if (!input.eof()) //unexpected end of stream
		{
			std::cerr << "ERROR: A mistake in input stream." << std::endl;
			return 1;
		}
	}
	else
	{
		try
		{
			SHA1Bruteforcer sha_bf(args["hash"], args["salt"], args["dictionary"]);	
			sha_bf.crack();
		}
		catch (const std::exception& e)
		{
			std::cerr << e.what() << std::endl;
			return 1;
		}
	}

	return 0;
}