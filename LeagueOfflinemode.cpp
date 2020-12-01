#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <cstdio>
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>


#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable : 4996)

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))


bool sortbysec(const std::pair<std::string, int>& a, const std::pair<std::string, int>& b)
{
    return (a.second < b.second);
}

DWORD MyGetProcessId(LPCTSTR ProcessName)
{
    PROCESSENTRY32 pt;
    HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    pt.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hsnap, &pt))
    { 
        do
        {
            if (!lstrcmpi(pt.szExeFile, ProcessName))
            {
                CloseHandle(hsnap);
                return pt.th32ProcessID;
            }
        } while (Process32Next(hsnap, &pt));
    }

    CloseHandle(hsnap);
    return 0;
}

bool execute_batch(int mode, std::string tcpip_string)
{
    if (mode == 1)
    {
        std::ofstream batch;
        batch.open("disable.bat", std::ios::out);
        batch << "netsh advfirewall firewall add rule name=lolchat dir=out remoteip=" + tcpip_string + " protocol=TCP action=block\n";
        batch.close();
        system("disable.bat");
        std::cout << "Disable Leaguechat...\n";
        std::cout << "PLEASE RESTART THE LEAGUE OF LEGENDS CLIENT\n";
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
    std::cout << "-- DeeGee's League of Legends Friendslist Offlinemode --\n"; 
    DWORD pid = MyGetProcessId(TEXT("RiotClientServices.exe"));
    std::cout << "Waiting for League of Legends client..." << std::endl;

    while (pid == 0)
    {
        pid = MyGetProcessId(TEXT("RiotClientServices.exe"));
    }

    if (pid != 0)
    {
        std::cout << "Grabbing Process ID successful: " << pid << std::endl;
    }

    int port_test = 0;
    std::vector<std::pair<std::string, int>> remote_tcp;

    PMIB_TCPTABLE2 pTcpTable;
    ULONG ulSize = 0;
    DWORD dwRetVal = 0;

    char szLocalAddr[128];
    char szRemoteAddr[128];
    struct in_addr IpAddr;
    int i;
    char final_tcp_ip[128];

    pTcpTable = (MIB_TCPTABLE2*)MALLOC(sizeof(MIB_TCPTABLE2));
    if (pTcpTable == NULL) {
        printf("Error allocating memory\n");
        return 1;
    }

    ulSize = sizeof(MIB_TCPTABLE);
    if ((dwRetVal = GetTcpTable2(pTcpTable, &ulSize, TRUE)) ==
        ERROR_INSUFFICIENT_BUFFER) {
        FREE(pTcpTable);
        pTcpTable = (MIB_TCPTABLE2*)MALLOC(ulSize);
        if (pTcpTable == NULL) {
            printf("Error allocating memory\n");
            return 1;
        }
    }

    if ((dwRetVal = GetTcpTable2(pTcpTable, &ulSize, TRUE)) == NO_ERROR) 
    {
        printf("\tNumber of entries: %d\n", (int)pTcpTable->dwNumEntries);
        
        for (i = 0; i < (int)pTcpTable->dwNumEntries; i++) 
        {
            printf("\n\tTCP[%d] State: %ld - ", i,
                pTcpTable->table[i].dwState);

            switch (pTcpTable->table[i].dwState) 
            {
            case MIB_TCP_STATE_CLOSED:
                printf("CLOSED\n");
                break;
            case MIB_TCP_STATE_LISTEN:
                printf("LISTEN\n");
                break;
            case MIB_TCP_STATE_SYN_SENT:
                printf("SYN-SENT\n");
                break;
            case MIB_TCP_STATE_SYN_RCVD:
                printf("SYN-RECEIVED\n");
                break;
            case MIB_TCP_STATE_ESTAB:
                printf("ESTABLISHED\n");
                break;
            case MIB_TCP_STATE_FIN_WAIT1:
                printf("FIN-WAIT-1\n");
                break;
            case MIB_TCP_STATE_FIN_WAIT2:
                printf("FIN-WAIT-2 \n");
                break;
            case MIB_TCP_STATE_CLOSE_WAIT:
                printf("CLOSE-WAIT\n");
                break;
            case MIB_TCP_STATE_CLOSING:
                printf("CLOSING\n");
                break;
            case MIB_TCP_STATE_LAST_ACK:
                printf("LAST-ACK\n");
                break;
            case MIB_TCP_STATE_TIME_WAIT:
                printf("TIME-WAIT\n");
                break;
            case MIB_TCP_STATE_DELETE_TCB:
                printf("DELETE-TCB\n");
                break;
            default:
                printf("UNKNOWN dwState value\n");
                break;
            }

            IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwLocalAddr;
            strcpy_s(szLocalAddr, sizeof(szLocalAddr), inet_ntoa(IpAddr));
            printf("\tTCP[%d] Local Addr: %s\n", i, szLocalAddr);
            printf("\tTCP[%d] Local Port: %d \n", i,
            ntohs((u_short)pTcpTable->table[i].dwLocalPort));

            IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwRemoteAddr;
            strcpy_s(szRemoteAddr, sizeof(szRemoteAddr), inet_ntoa(IpAddr));
            printf("\tTCP[%d] Remote Addr: %s\n", i, szRemoteAddr);
            printf("\tTCP[%d] Remote Port: %d\n", i,
            ntohs((u_short)pTcpTable->table[i].dwRemotePort));

            printf("\tTCP[%d] Owning PID: %d\n", i, pTcpTable->table[i].dwOwningPid);
            printf("\tTCP[%d] Offload State: %ld - ", i, pTcpTable->table[i].dwOffloadState);

            int port_test = (int)ntohs((u_short)pTcpTable->table[i].dwRemotePort);
            std::cout << " 1st Port test : " << port_test << std:: endl;

            if ((int)pid == (int)pTcpTable->table[i].dwOwningPid)
            {
                if ((strcmp("0.0.0.0", szRemoteAddr) != 0) && (strcmp("127.0.0.1", szRemoteAddr) != 0))
                {
                    remote_tcp.push_back(std::make_pair(strcpy(final_tcp_ip, szRemoteAddr), port_test));
                    strcpy(final_tcp_ip, szRemoteAddr);
                    std::cout << " ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: Flagged -> Remote IP Output: " << final_tcp_ip << " Port test: " << port_test << std::endl;
                }
            }

            switch (pTcpTable->table[i].dwOffloadState)
            {
            case TcpConnectionOffloadStateInHost:
                printf("Owned by the network stack and not offloaded \n");
                break;
            case TcpConnectionOffloadStateOffloading:
                printf("In the process of being offloaded\n");
                break;
            case TcpConnectionOffloadStateOffloaded:
                printf("Offloaded to the network interface control\n");
                break;
            case TcpConnectionOffloadStateUploading:
                printf("In the process of being uploaded back to the network stack \n");
                break;
            default:
                printf("UNKNOWN Offload state value\n");
                break;
            }
        }
    }
    else 
    {
        printf("\tGetTcpTable2 failed with %d\n", dwRetVal);
        FREE(pTcpTable);
        return 1;
    }

    if (pTcpTable != NULL) {
        FREE(pTcpTable);
        pTcpTable = NULL;
    }

    int portme = 0;
    int final_port = 0;

    for (int j = 0; i < remote_tcp.size(); j++)
    {
        std::cout << "OUTPUT PAIR SECOND: " << remote_tcp[j].second << " VEL PORTME: " << portme << std::endl;
        portme = remote_tcp[j].second;
        std::sort(remote_tcp.begin(), remote_tcp.end(), sortbysec);
    }

    for (auto entrys : remote_tcp)
    {
        std::cout << "TCP IP Entries Sorted " << entrys.first << ":" << entrys.second << std::endl;
    }

    std::cout << "Final RIOT Chatserver IP: " << remote_tcp[remote_tcp.size() - 1].first << std::endl;
    std::cout << "-----------------------------------------------------------------------------------\n";
    std::cout << "[1] Disable Leaguechat \n";
    std::cout << "[2] Enable Leaguechat \n";
    std::cout << "[3] Exit \n";
    std::cout << "Insert Number and press Enter: ";

    int u = 0;
    bool exit;

    while (u != 404)
    {
        std::cin >> u;
        exit = execute_batch(u, remote_tcp[remote_tcp.size() - 1].first);

        if (exit == false)
            u = 404;

        std::cout << "Insert Number and press Enter: ";
    }

    return 0;
}