//defines
#define _CRT_NONSTDC_NO_WARNINGS

//main
#include <iostream>
#include <sstream>

//socket
#include <winsock2.h>
#include <ws2tcpip.h>

//crypto
#include "../shared/crypto/crypto.h"

//extra
#pragma comment(lib,"WS2_32")

//namespaces
using namespace std;


//main values
/****************************************************************************/
int alfaKey = 969; // choose something random, must be same in client
int betaKey = 17098; // choose something random, must be same in client
// these two keys ensure encryption security as encryption key changes only every second (not good)
// improved stuff so its useless but whatsoever I keep it here

string version = "0.1.0"; //version of your program
int port = 1337; // port
PCWSTR ip = L"127.0.0.1"; //server ip
/****************************************************************************/

string gen_random(const int len, int pid)
{
	string temp;
	static const char chars[] = "0123456789" "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	srand((unsigned)time(NULL) * alfaKey - betaKey + pid * 2);
	for (int i = 0; i < len; ++i)
		temp += chars[rand() % (sizeof(chars) - 1)];
	return temp;
}

//hwid stuff
string m_CPU;
string m_ComputerName;
string m_Physical;
string hwid;
bool query_wmic(const string& input, string& out)
{
	auto* shell_cmd = _popen(input.c_str(), "r");
	if (!shell_cmd) {
		return false;
	}

	static char buffer[1024] = {};
	while (fgets(buffer, 1024, shell_cmd)) {
		out.append(buffer);
	}
	_pclose(shell_cmd);

	while (out.back() == '\n' ||
		out.back() == '\0' ||
		out.back() == ' ' ||
		out.back() == '\r' ||
		out.back() == '\t') {
		out.pop_back();
	}

	return !out.empty();
}
bool query()
{
	auto strip_keyword = [](string& buffer, const bool filter_digits = false)
	{
		string current, stripped;
		istringstream iss(buffer);

		buffer.clear();
		auto first_tick = false;
		while (getline(iss, current)) {
			if (!first_tick) {
				first_tick = true;
				continue;
			}
			if (filter_digits && std::isdigit(current.at(0))) {
				continue;
			}

			buffer.append(current).append("\n");
		}
		if (buffer.back() == '\n') {
			buffer.pop_back();
		}
	};

	if (!query_wmic("wmic cpu get name", m_CPU) ||
		!query_wmic("WMIC OS GET CSName", m_ComputerName) ||
		!query_wmic("WMIC diskdrive get SerialNumber", m_Physical)) {
		return false;
	}

	strip_keyword(m_CPU);
	strip_keyword(m_ComputerName);
	strip_keyword(m_Physical, true);

	return true;
}

//encryption stuff
void sendEnc(SOCKET s, string data, string akey, string aiv) //encrypt and send data
{
	string encrypted = security::encrypt(data, akey, aiv);
	send(s, encrypted.c_str(), sizeof(encrypted), 0);
	//printf("sent %s\n", encrypted.c_str()); //for debugging or idk
}
string recvDec(SOCKET s, string akey, string aiv) //receive and decrypt data
{
	char buffer[2048];
	recv(s, buffer, sizeof(buffer), 0);
	string decrypted = security::decrypt(buffer, akey, aiv);
	memset(buffer, 0, sizeof(buffer));
	//printf("received %s\n", decrypted.c_str()); //for debugging or idk
	return decrypted;
}

//main thread
int main()
{
	//networking
	WSADATA wsa_data;
	SOCKADDR_IN addr;

	int wsa = WSAStartup(MAKEWORD(2, 2), &wsa_data);
	if (wsa != 0)
	{
		WSACleanup();
		return 0;
	}

	const auto server = socket(AF_INET, SOCK_STREAM, 0);

	InetPton(AF_INET, ip, &addr.sin_addr.s_addr);

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	int con = connect(server, reinterpret_cast<SOCKADDR*>(&addr), sizeof(addr));
	if (con != 0)
	{
		closesocket(server);
		WSACleanup();
		return 0;
	}

	printf("connected\n");

	//program
	int pid = getpid();
	string license, buffer;

	//get license
	printf("enter your license: ");
	cin >> license;

	//get hwid
	query();
	hwid += m_CPU + m_ComputerName + m_Physical;
	hwid.erase(std::remove_if(hwid.begin(), hwid.end(), isspace), hwid.end());

	//prepare and send initialization data and make encryption key
	string preBuff = hwid + "__" + version + "__" + license;

	string akey = gen_random(32, pid);
	string aiv = gen_random(16, pid);

	string buff0Enc = security::encrypt(preBuff, akey, aiv);
	buffer = buff0Enc + "__" + to_string(pid * 3 - 796);

	send(server, buffer.c_str(), 2048, 0);
	buffer = "";

	//receive version check and validate
	buffer = recvDec(server, akey, aiv);
	if (buffer == "goodver") {}
	else
	{
		printf("invalid version\n");
		closesocket(server);
		WSACleanup();
		system("pause");
	}
	buffer = "";

	//receive license and ban check
	buffer = recvDec(server, akey, aiv);
	if (buffer == "hwidban")
	{
		printf("you have been banned from using our services\n");
		closesocket(server);
		WSACleanup();
		system("pause");
	}
	else if (buffer == "invalid" || buffer == "expired")
	{
		printf("your license is invalid or expired\n");
		closesocket(server);
		WSACleanup();
		system("pause");
	}
	else if (buffer == "badhwid")
	{
		printf("your license is bound to a different hwid\n");
		closesocket(server);
		WSACleanup();
		system("pause");
	}
	else
	{
		//actual program, load dll or whatever you want
		printf("sucessfully logged in\n");

		closesocket(server);
		WSACleanup();
		system("pause");
	}

	closesocket(server);
	WSACleanup();
	return 0;
}