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
    WCHAR buffer[buffer_count]{};

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
    PSID AdministratorsGroup{};

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
    wstr gateway;
    u32 metric{ 0 };
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
            SHELLEXECUTEINFO shellExecuteInfo{};
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
        if (
            auto res = WSAStartup(MAKEWORD(2, 2), &wsa_data);
            res != NO_ERROR
            )
        {
            throw std::format(L"[ERROR] WSAStartup failed: {}",
                              last_error_as_string(res));
        }
        

        ULONG buffer_size = 0;
        ULONG adapters_flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;
        
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

        for (IP_ADAPTER_ADDRESSES* adapter = (IP_ADAPTER_ADDRESSES*)mem.get();
             adapter != nullptr;
             adapter = adapter->Next)
        {
            Interface itf{};

            //wcout << L"Num: " << counter++ << endl;
            //wcout << L"AdapterName: " << adapter->AdapterName << "\n";
            //wcout << std::format(L"Luid: 0x{:X}", adapter->Luid.Value) << "\n";
            //wcout << L"FriendlyName: " << adapter->FriendlyName << "\n";

            itf.name = wstr(adapter->FriendlyName);

            // get all the IPs
            for (IP_ADAPTER_UNICAST_ADDRESS_LH* addr = adapter->FirstUnicastAddress;
                 addr != nullptr;
                 addr = addr->Next)
            {
                // Check if the address is IPv4
                if (addr->Address.lpSockaddr->sa_family == AF_INET)
                {
                    // IPv4 address
                    sockaddr_in* sockaddr_ipv4 = reinterpret_cast<sockaddr_in*>(addr->Address.lpSockaddr);
                    wchar_t ip_str[INET_ADDRSTRLEN]{};
                    InetNtopW(AF_INET, &(sockaddr_ipv4->sin_addr), ip_str, INET_ADDRSTRLEN);

                    //wcout << L"IPv4 Address: " << ip_str << "\n";
                    itf.ip.append(wstr(ip_str)).append(L" ");
                }
            }

            // get all the Gateway
            for (IP_ADAPTER_GATEWAY_ADDRESS_LH* pGatewayAddresses = adapter->FirstGatewayAddress;
                 pGatewayAddresses != nullptr;
                 pGatewayAddresses = pGatewayAddresses->Next)
            {
                // TODO: try to use InetNtopW()
                const SOCKADDR* sockaddr_ipv4 = pGatewayAddresses->Address.lpSockaddr;
                wchar_t gateway_address[NI_MAXHOST];
                GetNameInfoW(sockaddr_ipv4, sizeof(sockaddr_in), // only IPv4
                             gateway_address, NI_MAXHOST,
                             NULL, 0,
                             NI_NUMERICHOST);

                itf.gateway.append(wstr(gateway_address)).append(L" ");
            }



            //wcout << L"Ipv4Metric: " << adapter->Ipv4Metric << "\n";
            itf.metric = adapter->Ipv4Metric;

            //wcout << L"DnsSuffix: " << adapter->DnsSuffix << "\n";
            //wcout << L"Description: " << adapter->Description << "\n\n";
            itf.description = adapter->Description;

            interfaces.push_back(std::move(itf));
        }

        std::sort(interfaces.begin(),
                  interfaces.end(),
                  [](const Interface& a, const Interface& b)
        {
            return a.metric < b.metric;
        });

        for (const auto& itf : interfaces)
        {
            wcout
                << std::format(L"Name: {}\nMetric: {}\nDescription: {}\nIPv4: {}\nGateway: {}\n\n",
                               itf.name, itf.metric, itf.description, itf.ip, itf.gateway);
        }

#if 0
        // Retrieve the IP interface table
        MIB_IPINTERFACE_ROW row{};
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

int main() 
{
    ULONG outBufLen = 0;
    DWORD dwRetVal = 0;

    // Call GetAdaptersAddresses with a NULL pointer for the adapters parameter to get the buffer size needed.
    dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &outBufLen);
    if (dwRetVal != ERROR_BUFFER_OVERFLOW) {
        std::cerr << "GetAdaptersAddresses call failed with error code " << dwRetVal << std::endl;
        return 1;
    }

    // Allocate memory for the adapter addresses
    IP_ADAPTER_ADDRESSES* pAddresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(malloc(outBufLen));
    if (pAddresses == nullptr) {
        std::cerr << "Memory allocation failed." << std::endl;
        return 1;
    }

    // Call GetAdaptersAddresses again to retrieve the adapter addresses
    dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
    if (dwRetVal != NO_ERROR) {
        std::cerr << "GetAdaptersAddresses call failed with error code " << dwRetVal << std::endl;
        free(pAddresses);
        return 1;
    }

    // Iterate through the adapter addresses to find the subnet mask for each adapter
    for (IP_ADAPTER_ADDRESSES* pCurrAddresses = pAddresses; 
         pCurrAddresses != nullptr; 
         pCurrAddresses = pCurrAddresses->Next) 
    {
        IP_ADAPTER_PREFIX* pPrefix = pCurrAddresses->FirstPrefix;

        if (pPrefix != nullptr) 
        {
            std::wcout << "Adapter Name: " << pCurrAddresses->FriendlyName << std::endl;

            for (ULONG i = 1; 
                 pPrefix != nullptr; 
                 i++, pPrefix = pPrefix->Next) 
            {
                sockaddr* sa = pPrefix->Address.lpSockaddr;

                if (sa->sa_family == AF_INET) 
                {
                    sockaddr_in* sa_in = reinterpret_cast<sockaddr_in*>(sa);
                    
                    char subnetString[INET_ADDRSTRLEN];
                    InetNtopA(AF_INET, &(sa_in->sin_addr), subnetString, INET_ADDRSTRLEN);

                    std::cout << "    Subnet Mask " << i << ": " << subnetString << std::endl;
                }
            }
        }
    }

    free(pAddresses);
    return 0;
}

#endif

