#include <cassert>
#include <string>
#include <sstream>
#include <iomanip>

std::string bin2hex(std::string const& s) {
	std::ostringstream oss;

	for (unsigned char ch : s)
		oss << std::hex << std::setw(2) << std::setfill('0') << (int)ch;

	return oss.str();
}

//convert hexstring from php to binary
std::string hex2bin(std::string const& s) {
	assert(s.length() % 2 == 0);

	std::string sOut;
	sOut.reserve(s.length() / 2);

	std::string extract;
	for (std::string::const_iterator pos = s.begin(); pos < s.end(); pos += 2)
	{
		extract.assign(pos, pos + 2);
		sOut.push_back(std::stoi(extract, nullptr, 16));
	}
	return sOut;
}

//decrypt array
std::string XOR(std::string value, std::string key)
{
	std::string retval(value);
	long unsigned int klen = key.length();
	long unsigned int vlen = value.length();
	unsigned long int k = 0;
	unsigned long int v = 0;
	for (; v < vlen; v++) {
		retval[v] = value[v] ^ key[k];
		k = (++k < klen ? k : 0);
	}
	return retval;
}