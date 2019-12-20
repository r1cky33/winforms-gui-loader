#include <Windows.h>

#include "curl/curl.h"
#include "loader.h"

	extern int kdmap(); // -> load driver
	//extern int ummap(); // map image (not def. yet)

byte image[] = { 0 };

bool retreiveImage() {
	//API magic

	return true;
}

void load_with_creds(const char* usr_name, const char* usr_password) {
	//load using usr_name / usr_passwd
	//receive binary -> kdmapper -> umclient

	int status = kdmap();

	if (status != 0)
		return;
}

void load_with_key(const char* key) {
	//load using key
	//receive binary -> kdmapper -> umclient

	int status = kdmap();

	if (status != 0)
		return;
}


