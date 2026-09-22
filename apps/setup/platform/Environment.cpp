#include "Ksword.h"
#include "Environment.h"
std::string authName;
std::string hostName;
std::string exePath;
int screenX;
int screenY;
bool isAuthAdmin;
void kEnviProb() {
	authName = getUserName();
	hostName = getHostName();
	isAuthAdmin = isAdmin();
	exePath = getSelfPath();
	screenX= GetSystemMetrics(SM_CXSCREEN);
	screenY = GetSystemMetrics(SM_CYSCREEN);
}
