#include <iostream>
#include <stdio.h>     
#include <stdlib.h>     
#include <fstream>


bool execute_batch(int mode)
{
    if (mode == 1)
    {
        std::ofstream batch;
        batch.open("disable.bat", std::ios::out);
        batch << "netsh advfirewall firewall add rule name=lolchat dir=out remoteip=172.65.252.238 protocol=TCP action=block\n";
        batch.close();
        system("disable.bat");
        std::cout << "Disable Leaguechat...\n";
        return true;
    }
    else if (mode == 2)
    {
        std::ofstream batch;
        batch.open("enable.bat", std::ios::out);
        batch << "netsh advfirewall firewall delete rule name=lolchat\n";
        batch.close();
        system("enable.bat");
        std::cout << "Enable Leaguechat...\n";
        return true;
    }
    else if (mode == 3)
    {
        std::cout << "Exiting \n";
        return false;
    }
    else if (mode != (1 || 2 || 3))
    {
        std::cout << "Invalide Input \n";
        return true;
    }
    else
    {
        std::cout << "Error \n";
        return false;
    }
}

int main()
{
    int i = 0;
    bool exit;

    while (i != 404)
    {
        std::cout << "-- DeeGee's League Friendslist Offlinemode -- \n";
        std::cout << "Restart League of Legends client afterwards \n";
        std::cout << "[1] Disable Leaguechat \n";
        std::cout << "[2] Enable Leaguechat \n";
        std::cout << "[3] Exit \n";
        std::cout << "Insert Number and press Enter: ";
        std::cin >> i;
        exit = execute_batch(i);

        if (exit == false)
            i = 404;

    }

    return 0;
}