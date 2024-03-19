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
    str ip;
    u32 metric{ 0 };
    wstr description;
};

int wmain(int argc, wchar_t* argv[])
{
    try
    {
        //if (not is_user_admin())
        //{
        //    // Prompt the user with a UAC dialog for elevation
        //    SHELLEXECUTEINFO shellExecuteInfo {};
        //    shellExecuteInfo.cbSize = sizeof(SHELLEXECUTEINFO);
        //    shellExecuteInfo.lpVerb = L"runas"; // Request elevation
        //    shellExecuteInfo.lpFile = argv[0]; // Path to your application executable
        //    shellExecuteInfo.lpParameters = L""; // Optional parameters for your application
        //    shellExecuteInfo.nShow = SW_SHOWNORMAL;

        //    if (not ShellExecuteExW(&shellExecuteInfo))
        //    {
        //        wcout << L"[ERROR] cannot start app admin: " 
        //            << last_error_as_string(GetLastError())
        //            << endl;
        //        return 1;
        //    }

        //    return 0;
        //}

        ULONG buffer_size = 0;
        GetAdaptersAddresses(AF_INET, NULL, NULL, NULL, &buffer_size);

        auto* mem_ = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buffer_size);
        std::unique_ptr<void, Heap_Deleter> mem(mem_);

        if (not mem)
        {
            throw std::format(L"[ERROR] cannot allocate memory!");
        }

        DWORD result = GetAdaptersAddresses(
            AF_INET,
            NULL,
            NULL,
            (IP_ADAPTER_ADDRESSES*)mem.get(),
            &buffer_size);

        if (result != NO_ERROR)
        {
            throw std::format(L"[ERROR] cannot get adapters addresses: {}",
                              last_error_as_string(result));
        }

        IF_LUID target;
        target.Value = 77;

        int counter = 1;

        vec<Interface> interfaces;

        for (auto* adapter = (IP_ADAPTER_ADDRESSES*)mem.get();
             adapter != nullptr;
             adapter = adapter->Next)
        {
            Interface itf{};

            //wcout << L"Num: " << counter++ << endl;
            //wcout << L"AdapterName: " << adapter->AdapterName << "\n";
            //wcout << std::format(L"Luid: 0x{:X}", adapter->Luid.Value) << "\n";
            //wcout << L"FriendlyName: " << adapter->FriendlyName << "\n";

            itf.name = wstr(adapter->FriendlyName);

            for (auto* addr = adapter->FirstUnicastAddress;
                 addr != nullptr;
                 addr = addr->Next)
            {
                // Check if the address is IPv4
                if (addr->Address.lpSockaddr->sa_family == AF_INET)
                {
                    // IPv4 address
                    auto* sockaddr_ipv4 = reinterpret_cast<sockaddr_in*>(addr->Address.lpSockaddr);
                    char ip_str[INET_ADDRSTRLEN]{};
                    inet_ntop(AF_INET, &(sockaddr_ipv4->sin_addr), ip_str, INET_ADDRSTRLEN);

                    //wcout << L"IPv4 Address: " << ip_str << "\n";
                    itf.ip = str(ip_str);
                }
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
                << std::format(L"{}\n{}\n{}\n{}\n", itf.name, itf.metric, itf.description, itf.ip)
                << endl;
        }

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

