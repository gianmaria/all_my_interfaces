// This is an open source non-commercial project. Dear PVS-Studio, please check it.

// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

#include <winsock2.h>
#include <windows.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h> // for inet_ntop function
#include <iphlpapi.h>

#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "Ws2_32.lib")


#include <array>
#include <assert.h>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <map>
#include <numeric>
#include <queue>
#include <ranges>
#include <regex>
#include <set>
#include <string_view>
#include <string>
#include <vector>

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;

using i8 = int8_t;
using i16 = int16_t;
using i32 = int32_t;
using i64 = int64_t;

using std::cout;
using std::wcout;
using std::endl;
using std::string;
using std::string_view;
using std::vector;
using std::set;
using std::map;

using str = std::string;
using wstr = std::wstring;
using str_cref = std::string const&;
using wstr_cref = std::wstring const&;

template<typename T>
using vec = vector<T>;

using namespace std::string_literals;
using namespace std::string_view_literals;

namespace fs = std::filesystem;

std::wstring last_error_as_string(DWORD last_error)
{
    auto constexpr buffer_count = 1024;
    WCHAR buffer[buffer_count] {};

    DWORD size = FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS |
        FORMAT_MESSAGE_MAX_WIDTH_MASK,
        NULL,
        last_error,
        0,
        (wchar_t*)&buffer,
        buffer_count,
        NULL);

    return std::wstring(buffer, size);
}

bool is_user_admin()
{
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup {};

    BOOL success = AllocateAndInitializeSid(
        &NtAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &AdministratorsGroup);

    if (not success)
    {
        FreeSid(AdministratorsGroup);
        throw std::format(L"[ERROR] Cannot allocate SID: {}",
                          last_error_as_string(GetLastError()));
    }

    BOOL is_member = false;

    success = CheckTokenMembership(NULL, AdministratorsGroup, &is_member);

    if (not success)
    {
        FreeSid(AdministratorsGroup);
        throw std::format(L"[ERROR] CheckTokenMembership fasiled: {}",
                          last_error_as_string(GetLastError()));
    }

    FreeSid(AdministratorsGroup);

    return (is_member > 0);
}


struct Heap_Deleter
{
    void operator()(void* mem) const
    {
        if (mem)
            HeapFree(GetProcessHeap(), NULL, mem);
    }
};

struct Interface
{
    wstr name;
    wstr ip;
    u8 subnet {0};
    wstr gateway;
    wstr dns;
    wstr dns_suff;
    u32 metric {0};
    wstr description;
};

#if 1
int wmain(int argc, wchar_t* argv[])
{
    try
    {
#if 0
        if (not is_user_admin())
        {
            // Prompt the user with a UAC dialog for elevation
            SHELLEXECUTEINFO shellExecuteInfo {};
            shellExecuteInfo.cbSize = sizeof(SHELLEXECUTEINFO);
            shellExecuteInfo.lpVerb = L"runas"; // Request elevation
            shellExecuteInfo.lpFile = argv[0]; // Path to your application executable
            shellExecuteInfo.lpParameters = L""; // Optional parameters for your application
            shellExecuteInfo.nShow = SW_SHOWNORMAL;

            if (not ShellExecuteExW(&shellExecuteInfo))
            {
                wcout << L"[ERROR] cannot start app admin: "
                    << last_error_as_string(GetLastError())
                    << endl;
                return 1;
            }

            return 0;
        }
#endif // 0

        WSADATA wsa_data {};
        auto wsa_res = WSAStartup(MAKEWORD(2, 2), &wsa_data);

        if (wsa_res!= NO_ERROR)
        {
            throw std::format(L"[ERROR] WSAStartup failed: {}",
                              last_error_as_string(wsa_res));
        }

        ULONG buffer_size = 0;
        ULONG adapters_flags = GAA_FLAG_INCLUDE_WINS_INFO | GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;

        GetAdaptersAddresses(AF_INET, adapters_flags, NULL, NULL, &buffer_size);

        auto* mem_ = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buffer_size); // 21376
        std::unique_ptr<void, Heap_Deleter> mem(mem_);

        if (not mem)
        {
            throw std::format(L"[ERROR] cannot allocate memory!");
        }

        DWORD result = GetAdaptersAddresses(
            AF_INET,
            adapters_flags,
            NULL,
            (IP_ADAPTER_ADDRESSES*)mem.get(), &buffer_size);

        if (result != NO_ERROR)
        {
            throw std::format(L"[ERROR] cannot get adapters addresses: {}",
                              last_error_as_string(result));
        }

        IF_LUID target;
        target.Value = 77;

        vec<Interface> interfaces;

        IP_ADAPTER_ADDRESSES* adapter = (IP_ADAPTER_ADDRESSES*)mem.get();

        while(adapter != nullptr)
        {
            Interface itf {};

            itf.name = wstr(adapter->FriendlyName);
            
            // get all the IPs
            for (IP_ADAPTER_UNICAST_ADDRESS_LH* unicast_addr = adapter->FirstUnicastAddress;
                 unicast_addr != nullptr;
                 unicast_addr = unicast_addr->Next)
            {
                sockaddr_in* sockaddr_ipv4 = reinterpret_cast<sockaddr_in*>(unicast_addr->Address.lpSockaddr);
                wchar_t ip_str[INET_ADDRSTRLEN] {};
                InetNtopW(AF_INET, &(sockaddr_ipv4->sin_addr), ip_str, INET_ADDRSTRLEN);

                itf.ip.append(wstr(ip_str)).append(L" ");
                itf.subnet = unicast_addr->OnLinkPrefixLength;
            }

            // get all the Gateway
            for (IP_ADAPTER_GATEWAY_ADDRESS_LH* gateway_addr = adapter->FirstGatewayAddress;
                 gateway_addr != nullptr;
                 gateway_addr = gateway_addr->Next)
            {
                sockaddr_in* sockaddr_ipv4 = reinterpret_cast<sockaddr_in*>(gateway_addr->Address.lpSockaddr);
                wchar_t gateway_str[INET_ADDRSTRLEN] {};
                InetNtopW(AF_INET, &sockaddr_ipv4->sin_addr, gateway_str, INET_ADDRSTRLEN);

                itf.gateway.append(wstr(gateway_str)).append(L" ");
            }

            // get all the DNS
            for (IP_ADAPTER_DNS_SERVER_ADDRESS_XP* dns_addr = adapter->FirstDnsServerAddress;
                 dns_addr != nullptr;
                 dns_addr = dns_addr->Next)
            {
                sockaddr_in* sockaddr_ipv4 = reinterpret_cast<sockaddr_in*>(dns_addr->Address.lpSockaddr);
                wchar_t dns_str[INET_ADDRSTRLEN] {};
                InetNtopW(AF_INET, &sockaddr_ipv4->sin_addr, dns_str, INET_ADDRSTRLEN);

                itf.dns.append(wstr(dns_str)).append(L" ");
            }

            itf.dns_suff = adapter->DnsSuffix;

            itf.metric = adapter->Ipv4Metric;
            itf.description = adapter->Description;

            interfaces.push_back(std::move(itf));


            adapter = adapter->Next;
        }



        std::sort(interfaces.begin(), interfaces.end(),
                  [](const Interface& a, const Interface& b)
        {
            return a.metric < b.metric;
        });


        for (const auto& itf : interfaces)
        {
            wcout
                << L"Name: " << itf.name << L" - " << itf.description << endl
                << L"Metric: " << itf.metric << endl
                //<< L"Description: " << itf.description << endl
                << L"IPv4: " << itf.ip << L"/" << itf.subnet << endl
                << L"Gateway: " << itf.gateway << endl
                << L"DNS: " << itf.dns << L"(" << itf.dns_suff << L")" << endl
                << endl;       
        }


#if 0
        // Retrieve the IP interface table
        MIB_IPINTERFACE_ROW row {};
        row.Family = AF_INET; // IPv4
        row.InterfaceLuid = target; // You need to set the appropriate LUID of the interface you want to modify

        result = GetIpInterfaceEntry(&row);

        if (result != NO_ERROR)
        {
            wcout << L"[ERROR] cannot get interface entry: "
                << last_error_as_string(result)
                << endl;
            return 1;
        }

        // Change the metric
        row.Metric = 10; // Set the desired metric

        // Set the modified IP interface entry
        result = SetIpInterfaceEntry(&row);

        if (result != NO_ERROR)
        {
            wcout << L"[ERROR] cannot set interface entry: "
                << last_error_as_string(result)
                << endl;

            return 1;
        }

        std::cout << "Metric changed successfully." << std::endl;

#endif // 0

        return 0;

    }
    catch (const std::wstring& e)
    {
        wcout << e << endl;
    }
    catch (str_cref e)
    {
        cout << e << endl;
    }
    catch (const std::exception& e)
    {
        cout << "[EXC] " << e.what() << endl;
    }

    return 1;

}


#else

#include <iostream>
#include <iphlpapi.h>
#include <stdio.h>

#pragma comment(lib, "IPHLPAPI.lib")

int main() {
    // Define variables
    ULONG outBufLen = 0;
    DWORD dwRetVal = 0;
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;

    // Call GetAdaptersAddresses to retrieve adapter information
    dwRetVal = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &outBufLen);
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        // Allocate memory for adapter information
        pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
        if (pAddresses == NULL) {
            std::cerr << "Error allocating memory needed to call GetAdaptersAddresses\n";
            return 1;
        }
    } else {
        std::cerr << "Error calling GetAdaptersAddresses function with error code " << dwRetVal << std::endl;
        return 1;
    }

    // Call GetAdaptersAddresses again to retrieve adapter information
    dwRetVal = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &outBufLen);
    if (dwRetVal == NO_ERROR) {
        pCurrAddresses = pAddresses;
        while (pCurrAddresses) {
            // Print adapter information
            printf("Adapter Name: %s\n", pCurrAddresses->AdapterName);
            printf("Adapter Description: %ws\n", pCurrAddresses->Description);

            // Iterate through the list of unicast addresses
            PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress;
            while (pUnicast) {
                printf("\tIP Address: %s\n", pUnicast->Address.lpSockaddr->sa_data);

                // Retrieve subnet mask
                printf("\tSubnet Mask: ");
                for (int i = 0; i < pUnicast->OnLinkPrefixLength / 8; ++i) {
                    printf("%u", pUnicast->OnLinkPrefixLength > 8 * (i + 1) ? 255 : (255 - (255 >> (pUnicast->OnLinkPrefixLength % 8))));
                    if (i < 3)
                        printf(".");
                }
                printf("\n");

                pUnicast = pUnicast->Next;
            }

            printf("\n");

            pCurrAddresses = pCurrAddresses->Next;
        }
    } else {
        std::cerr << "Error calling GetAdaptersAddresses function with error code " << dwRetVal << std::endl;
    }

    // Free allocated memory
    if (pAddresses != NULL) {
        free(pAddresses);
    }

    return 0;
}

#endif

