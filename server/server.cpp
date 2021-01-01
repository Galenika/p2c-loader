//defines
#define _CRT_NONSTDC_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

//main
#include <iostream>
#include <fstream>

//socket
#include "server.h" // winsock2.h already inluded in server.h

//crypto
#include "../shared/crypto/crypto.h"

//time
#include <chrono>

//extra
#pragma comment(lib,"WS2_32")

//namespaces
//std already in server.h
using namespace chrono;


//main values
/****************************************************************************/
int alfaKey = 969; // choose something random, must be same in client
int betaKey = 17098; // choose something random, must be same in client
// these two keys ensure encryption security as encryption key changes only every second (not good)
// improved stuff so its useless but whatsoever I keep it here

string version = "0.1.0"; //version of your program
int port = 1337; // port
/****************************************************************************/

int connections = 0;

string gen_random(int len, int pid)
{
    string temp;
    static const char chars[] = "0123456789" "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    srand((unsigned)time(NULL) * alfaKey - betaKey + pid * 2);
    for (int i = 0; i < len; ++i)
        temp += chars[rand() % (sizeof(chars) - 1)];
    return temp;
}

string gen_random_ms(int len, int change)
{
    string temp;
    unsigned __int64 ms = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    static const char chars[] = "0123456789" "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    srand((unsigned)ms - change);
    for (int i = 0; i < len; ++i)
        temp += chars[rand() % (sizeof(chars) - 1)];
    return temp;
}

ofstream file; //used on many places

void commands()
{
    string cmd;
    while (1)
    {
        cin >> cmd;

        if (cmd == "test")
        {
            printf("test succeed\n");
        }
        else if (cmd == "help")
        {
            cout << "1. test - does nothing" << endl
                << "2. help - list of commands" << endl
                << "3. ban - blacklist hwid" << endl
                << "4. add - make license" << endl;
        }
        else if (cmd == "ban")
        {
            string ban;
            printf("enter hwid to ban: ");
            cin >> ban;

            file.open("bans", ios_base::app);
            file << ban << endl;
            file.close();

            printf("successfully banned %s\n", ban.c_str());
        }
        else if (cmd == "add")
        {
            //license parameters
            string length, license;
            int count, choice, custom;
            printf("how many licenses: ");
            cin >> count;
            printf("length (1=1d, 2=7d, 3=14d, 4=30d, 5=custom in hours): ");
            cin >> choice;
            if (choice == 1)
                length = "1__d";
            else if (choice == 2)
                length = "7__d";
            else if (choice == 3)
                length = "14__d";
            else if (choice == 4)
                length = "30__d";
            else if (choice == 5)
            {
                printf("time in hours (e.g. 72): ");
                cin >> custom;
                length = to_string(custom) + "__h";
            }
            else
                printf("invalid choice\n");

            for (int i = 0; i < count; i++)
            {
                //gen license
                //dont set second value in gen_random_ms() higher than 1000000000000
                license = gen_random_ms(4, 983642) + "-" + gen_random_ms(4, 1024) + "-" + gen_random_ms(4, 7890) + "-" + gen_random_ms(4, 234768596);

                //check if license already exists
            trygain:
                ifstream l(license.c_str());
                string expire;
                if (l)
                {
                    license = gen_random_ms(4, 92) + "-" + gen_random_ms(4, 14) + "-" + gen_random_ms(4, 92) + "-" + gen_random_ms(4, 348);
                    goto trygain; //need to set new value to the ifstream varialbe
                }
                file.open(license, ios_base::app);
                file << "notused " << length << endl;
                file.close();
            }

            printf("successfully generated %i licenses\n", count);
        }
        else if (cmd == "reset")
        {
            string license;
            printf("enter license which you want to reset hwid at: ");
            cin >> license;

            ifstream l(license.c_str());
            if (l)
            {
                string oldhwid, secondData;
                l >> oldhwid;
                if (oldhwid == "notused")
                    printf("the license has no hwid bound\n");
                else
                {
                    l >> secondData; //would be needed to add another read/change whole method if there were more than 2 data stored in license files

                    file.open(license);
                    file << "hwidreset " << secondData << endl;
                    file.close();

                    printf("successfully resetted hwid for %s\n", license.c_str());
                }
            }
            else
            {
                printf("license not found\n");
            }
        }
        else
        {
            printf("unknown command\n");
        }
    }
}

struct ARGS {
    SOCKET* soc;
    string* str;
};

int main()
{
    CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)commands, NULL, NULL, NULL);

    WSADATA wsa_data;
    SOCKADDR_IN server_addr, client_addr;

    int wsa = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (wsa != 0)
        return 0;

    const auto server = socket(AF_INET, SOCK_STREAM, 0);

    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    ::bind(server, reinterpret_cast<SOCKADDR*>(&server_addr), sizeof(server_addr));
    listen(server, 0);

    printf("listening for connections...\n");

    int client_addr_size = sizeof(client_addr);

    for (;;)
    {
        SOCKET client;
        if ((client = accept(server, reinterpret_cast<SOCKADDR*>(&client_addr), &client_addr_size)) != INVALID_SOCKET)
        {
            //using structure to pass multiple data via CreateThread()
            SOCKET soc = client;
            string str = inet_ntoa(client_addr.sin_addr); //client's IP
            ARGS args = { &soc, &str };

            CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)on_client_connect, &args, NULL, NULL);
        }

        const auto last_error = WSAGetLastError();

        if (last_error > 0)
        {
            printf("error: %i\n", last_error);
        }
    }
    closesocket(server);
    WSACleanup();
    return 1;
}

void sendEnc(SOCKET s, string data, string akey, string aiv)
{
    string encrypted = security::encrypt(data, akey, aiv);
    send(s, encrypted.c_str(), sizeof(encrypted), 0);
    printf("sent %s\n", encrypted.c_str());
}

string recvDec(SOCKET s, string akey, string aiv) //receive and decrypt data
{
    char buffer[2048];
    recv(s, buffer, sizeof(buffer), 0);
    string decrypted = security::decrypt(buffer, akey, aiv);
    memset(buffer, 0, sizeof(buffer));
    printf("received %s\n", decrypted.c_str());
    return decrypted;
}

void on_client_connect(LPVOID Ar)
{
    //getting data from the structure
    ARGS* Args = (ARGS*)Ar;
    SOCKET client = *Args->soc;
    string clientAddr = *Args->str;

    connections++; //just to know how many people are conencted at once
    printf("currently connected users: %i\n", connections);

    //string clientAddr = to_string(connections); //had issues when using client's IP, will fix soon, as of now using connection ID instead
    //printf("client connected from %s\n", clientAddr.c_str());

    char buffer[2048]; //main receiving buffer

    //initialization data (version, pid, hwid, license)
    recv(client, buffer, sizeof(buffer), 0);
    printf("%s says raw: %s\n", clientAddr.c_str(), buffer);

    //decrypt received data and initialize decryption key
    int pid;
    string delimiter = "__", pidRaw, buff0Enc, hwid, version1, license;

    size_t pos = 0;
    string s(buffer);

    //split data needed for decryption key and other
    pos = s.find(delimiter);
    buff0Enc = s.substr(0, pos);
    s.erase(0, pos + delimiter.length());
    pidRaw = s;
    pid = stoi(pidRaw);
    pid = (pid + 796) / 3;

    //make decryption key
    string akey = gen_random(32, pid);
    string aiv = gen_random(16, pid);
    string preBuff = security::decrypt(buff0Enc, akey, aiv);
    printf("%s says decrypted:\n", clientAddr.c_str());

    //count length of client ip address (just for cosmetic stuff)
    string blank;
    for (int blankI = 0; blankI < clientAddr.length(); blankI++)
        blank += " ";

    pos = 0;
    string p(preBuff);

    //split other received data (version, license, hwid)
    pos = p.find(delimiter);
    hwid = p.substr(0, pos);
    p.erase(0, pos + delimiter.length());

    pos = p.find(delimiter);
    version1 = p.substr(0, pos);
    p.erase(0, pos + delimiter.length());

    license = p;

    printf("%s hwid:    %s\n", blank.c_str(), hwid.c_str());
    printf("%s version: %s\n", blank.c_str(), version1.c_str());
    printf("%s license: %s\n", blank.c_str(), license.c_str());

    //version check
    if (version != version1)
        sendEnc(client, "invalidver", akey, aiv);
    else
        sendEnc(client, "goodver", akey, aiv);

    //license and ban check
    //here I Would suggest to make a website and use an actual database as file management sucks
    //only reason I use file system here is that not everyone has a website, well I may add it later anyways
    ifstream b("bans");
    string bannedHwid;
    while (getline(b, bannedHwid))
    {
        if (hwid == bannedHwid)
            sendEnc(client, "hwidban", akey, aiv);
    }

    //change to std::fs? fs::exists(fs::current_path().string() + "\\asd.txt")
    ifstream l(license.c_str());
    string usedornot;
    if (l)
    {
        l >> usedornot;
        if (usedornot == "notused") //if license not used yet (made so people can use license later after purchase without wasting license time)
        {
            l >> usedornot; //old value is skipped, so it reads length of the license (30__d etc)

            //check type of the length (days or hours) and split actual length and the type
            string length, hourorday;
            int len;

            pos = 0;
            pos = usedornot.find(delimiter);
            length = usedornot.substr(0, pos); //length lol
            usedornot.erase(0, pos + delimiter.length());
            hourorday = usedornot; //day or hour

            len = stoi(length);

            if (hourorday == "d")
                len = len * 24 * 3600;
            else if (hourorday == "h")
                len = len * 3600;
            else
                printf("invalid length type\n");

            file.open(license);
            file << hwid << " " << time(NULL) + len;
            file.close();

            sendEnc(client, "good", akey, aiv);
        }
        else
        {
            int expire;
            l >> expire;
            if (usedornot == hwid)
            {
                if (expire > time(NULL))
                    sendEnc(client, "good", akey, aiv);
                else
                    sendEnc(client, "expired", akey, aiv);

            }
            else if (usedornot == "hwidreset")
            {
                file.open(license);
                file << hwid << " " << expire << endl;
                file.close();

                if (expire > time(NULL))
                    sendEnc(client, "good", akey, aiv);
                else
                    sendEnc(client, "expired", akey, aiv);
            }
            else
                sendEnc(client, "badhwid", akey, aiv);
        }
    }
    else
        sendEnc(client, "invalid", akey, aiv);

    closesocket(client);
    printf("%s disconnected\n", clientAddr.c_str());
    connections--;
}