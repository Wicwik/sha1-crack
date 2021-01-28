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
	SHA1Bruteforcer(const std::vector<std::string>& hashes, std::string salt = "", std::string dictionary = "", std::string parallel = "")
		: m_hashes{hashes}
		, m_salt{salt}
		, m_dictionary{dictionary}
		, m_parallel{parallel}
	{
	}

	void crack()
	{
		m_totalpass = m_hashes.size();
		m_todopass = m_totalpass;

		if (!m_parallel.empty())
		{
			if (m_dictionary.empty())
			{
				std::cout << "INFO: Currently found " << m_passcount << "/" << m_totalpass << " passwords." << std::endl;
				std::cout << "INFO: Going straight to parallel brute force." << std::endl;;
				m_crack_sha1_parallel();

				for (const auto& fut : m_futures)
				{
					fut.wait();
				}
			}
			else
			{
				for (const auto& hash : m_hashes)
				{
					std::cout << "INFO: Currently found " << m_passcount << "/" << m_totalpass << " passwords." << std::endl;
					std::cout << "INFO: Trying dictionary for " << hash << " search." << std::endl;
					m_crack_dictionary_sha1(hash);
				}

				if (m_todopass > 0)
				{
					std::cout << "INFO: Dictionary search failed, switching to parallel brute force." << std::endl;
					m_crack_sha1_parallel();

					for (const auto& fut : m_futures)
					{
						fut.wait();
					}
				}
			}

			if (m_todopass > 0)
			{
				throw std::logic_error( "ERROR: Hash not found." );
			}
		}
		else
		{
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
	}

private:
	std::vector<std::string> m_hashes;
	std::string m_salt;
	std::string m_dictionary;
	std::string m_parallel;

	bool m_foundpass = false;

	uint64_t m_hash_count = 0;
	uint64_t m_hashrate = 0;

	std::atomic<size_t> m_passcount = 0;
	std::atomic<int> m_todopass;
	size_t m_totalpass;

	std::vector<std::future<void>> m_futures;


	void m_print_info(std::string current)
	{
		std::ostringstream out;
		out << "INFO: Currently found " << m_passcount << "/" << m_totalpass << " passwords." << '\n';
		out << "Current hashrate is around " << m_hashrate << " hash per second." << '\n';
		out << "Currently guessing word " << current << '\n';
		std::cout << out.str();
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
			m_todopass--;
			m_foundpass = true;
			std::cout << "SUCESS: Found password number " << m_passcount << "/" << m_totalpass << " - " << hash << " => " << candidate <<  std::endl;
			
		}
		else if (!m_compare_hash(candidate + m_salt, hash))
		{
			m_passcount++;
			m_todopass--;
			m_foundpass = true;
			std::cout << "SUCESS: Found password number " << m_passcount << "/" << m_totalpass << " - " << hash << " => " << candidate <<  std::endl;
		}
		else if (!m_compare_hash(m_salt + candidate, hash))
		{
			m_passcount++;
			m_todopass--;
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

	bool m_next_pass_parallel(std::string& password, size_t start)
	{
		size_t len =  password.size();
		for (size_t i = len - 1; i >= start; i--)
		{
			char c = password[i];

			if (c+1 > '9' && c+1 < 'A')
			{
				password[i] = 'A';
				return true;
			}
			
			if (c+1 > 'Z' && c+1 < 'a')
			{
				password[i] = 'a';
				return true;
			}

			if (c < 'z')
			{
				password[i]++;
				return true;
			}

			password[i] = '0';
		}

		return false;
	}

	void m_crack_sha1_parallel(char c, size_t n)
	{
		std::string password(n, '0');
		password[0] = c;

		while(m_todopass > 0)
		{
			// std::ostringstream out;
			// out << "password: " << password << " " << m_todopass << '\n';
			// std::cout << out.str();

			for (const auto& hash : m_hashes)
			{
				if (!m_compare_hash(password, hash))
				{
					m_passcount++;
					m_todopass--;

					std::ostringstream out;
					out << "SUCESS: Found password number " << m_passcount << "/" << m_totalpass << " - " << hash << " => " << password << '\n';
					std::cout << out.str();
					continue;
				}

				if (!m_compare_hash(password+m_salt, hash))
				{
					m_passcount++;
					m_todopass--;

					std::ostringstream out;
					out << "SUCESS: Found password number " << m_passcount << "/" << m_totalpass << " - " << hash << " => " << password << '\n';
					std::cout << out.str();
					continue;
				}

				if (!m_compare_hash(m_salt+password, hash))
				{
					m_passcount++;
					m_todopass--;

					std::ostringstream out;
					out << "SUCESS: Found password number " << m_passcount << "/" << m_totalpass << " - " << hash << " => " << password << '\n';
					std::cout << out.str();
					continue;
				}
			}

			if (!m_next_pass_parallel(password, 1))
			{
				break;
			}
		}
	}

	void m_crack_sha1_parallel()
	{
		std::string allchar = m_make_allchar_string();

		for (size_t i = 1 ; i <= 32; i++)
		{
			auto start = std::chrono::high_resolution_clock::now();
			for (const auto& c : allchar)
			{
				m_futures.push_back(std::async(std::launch::async, [&, c, i]() { m_crack_sha1_parallel(c, i); }));
			}

			for (const auto& fut : m_futures)
			{
				fut.wait();
			}
			auto finish = std::chrono::high_resolution_clock::now();

			std::chrono::duration<double> elapsed = finish - start;
			m_hashrate = m_hash_count/elapsed.count();

			if (m_todopass <= 0)
			{
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

		if (arg == "-MT")
		{
			args["parallel"] = "parallel";
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

bool check_hash_format(std::string hash)
{
	return (hash.size() == 40) && (hash.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos);
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
			if(!check_hash_format(hash_row))
			{
				std::cerr << "ERROR: Invalid hash format." << std::endl;
				return 1;
			}
			
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
		if(!check_hash_format(args["hash"]))
		{
			std::cerr << "ERROR: Invalid hash format." << std::endl;
			return 1;
		}

		hashes.push_back(args["hash"]);
	}

	try
	{
		SHA1Bruteforcer sha_bf(hashes, args["salt"], args["dictionary"], args["parallel"]);	
		sha_bf.crack();
	}
	catch (const std::exception& e)
	{
		std::cerr << e.what() << std::endl;
		return 1;
	}

	return 0;
}