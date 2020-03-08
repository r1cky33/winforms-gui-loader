#include <Windows.h>
#include <string>
#include <cstring>
#include <stdlib.h>
#include <iostream>
#include <fstream>

#include "curl/curl.h"
#include "loader.h"

#include "md5.h"

uint8_t* image;
extern HANDLE hThread;


// kdmapper.lib -> map driver
	extern int kdmap(); 

// umclien.lib -> map image
	extern int umclient(uint8_t image[]);

//from crypt.cpp
	extern std::string hex2bin(std::string const& s);
	extern std::string bin2hex(std::string const& s);
	extern std::string XOR(std::string value, std::string key);

//curl writeFunction
size_t writeFunction(void* ptr, size_t size, size_t nmemb, std::string* data) {
	data->append((char*)ptr, size * nmemb);
	return size * nmemb;
}

size_t size;

void load_with_creds(const char* usr_name, const char* usr_password) {
	//load using usr_name / usr_passwd

	std::string usr = usr_name;
	std::string pw = usr_password;

	std::string request = "https://tarab.xyz/api/api.php?id=" + usr + "&pw=" + pw + "&type=1";

	auto curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, request.c_str());
		curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
		curl_easy_setopt(curl, CURLOPT_USERPWD, "user:pass");
		curl_easy_setopt(curl, CURLOPT_USERAGENT, "curl/7.42.0");
		curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 50L);
		curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);

		std::string response_string;
		std::string header_string;
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeFunction);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
		curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_string);

		char* url;
		long response_code;
		double elapsed;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
		curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &elapsed);
		curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &url);

		curl_easy_perform(curl);
		curl_easy_cleanup(curl);
		curl = NULL;

		if (response_string.length() < 1000) {
			MessageBoxA(NULL, "Check your credentials", "ERROR", NULL);
			exit(0);
		}

		std::string bin = hex2bin(response_string);
		std::string decbin = XOR(bin, md5(usr));
		std::string dechex = hex2bin(decbin);		//2bh... i dunno why, but it works lol

		image = new uint8_t[dechex.size()];
		memcpy(image, dechex.data(), dechex.size());
	}

	int status = kdmap();

	if (status != 0)
		return;

	if (!TerminateThread(hThread, NULL)) {
		MessageBoxA(NULL, "BE_ERROR", "ERROR", NULL);
	}

	//ummap
	MessageBoxA(NULL, "Ready to start PUBG!", "SUCCESS", NULL);

	status = umclient(image);

	if (status != 0) {
		MessageBoxA(NULL, "Something went wrong!", "Fail", NULL);
	}

	exit(NULL);
}

void load_with_key(const char* key) {
	//load using key
	AllocConsole();
	freopen("CONOUT$", "w", stdout);
	
	std::string stdkey = key;

	std::string request = "https://tarab.xyz/api/licensekey.php?key=" + stdkey;

	auto curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, request.c_str());
		curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
		curl_easy_setopt(curl, CURLOPT_USERPWD, "user:pass");
		curl_easy_setopt(curl, CURLOPT_USERAGENT, "curl/7.42.0");
		curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 50L);
		curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);

		std::string response_string;
		std::string header_string;
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeFunction);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
		curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_string);

		char* url;
		long response_code;
		double elapsed;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
		curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &elapsed);
		curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &url);

		curl_easy_perform(curl);
		curl_easy_cleanup(curl);
		curl = NULL;

		if (response_string.length() < 1000) {
			MessageBoxA(NULL, "Check your credentials", "ERROR", NULL);
			exit(0);
		}

		std::string bin = hex2bin(response_string);
		std::string decbin = XOR(bin, md5("SubSLgOT1KnfenIyWdQ9"));
		std::string dechex = hex2bin(decbin);		//2bh... i dunno why, but it works lol

		image = new uint8_t[dechex.size()];
		memcpy(image, dechex.data(), dechex.size());
	}

	int status = kdmap();

	if (status != 0)
		return;

	if (!TerminateThread(hThread, NULL)) {
		MessageBoxA(NULL, "BE_ERROR", "ERROR", NULL);
	}

	//ummap
	MessageBoxA(NULL, "Ready to start PUBG!", "SUCCESS", NULL);

	status = umclient(image);

	if (status != 0) {
		MessageBoxA(NULL, "Something went wrong!", "Fail", NULL);
	}

	exit(NULL);
}


