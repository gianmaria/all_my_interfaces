// This is an open source non-commercial project. Dear PVS-Studio, please check it.

// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winsock2.h>
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
#include <print>
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
#include <locale>
#include <cwchar>

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/error/en.h"
using namespace rapidjson;

#include "utf8.h"

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
using std::println;

using str = std::string; // NOTE: all std::string are utf-8 encoded
using wstr = std::wstring;
using str_cref = std::string const&;
using wstr_cref = std::wstring const&;

template<typename T>
using vec = vector<T>;

using namespace std::string_literals;
using namespace std::string_view_literals;

namespace fs = std::filesystem;


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
    str name;
    str description;
    str ip;
    u32 subnet{ 0 };
    str gateway;
    str dns;
    str dns_suff;
    u32 metric{ 0 };
    bool automatic_metric{ false };
    bool connected{ false };
    IF_LUID luid{};
    IF_INDEX index{};
};

struct WSA_Startup
{

    WSA_Startup(WORD version)
    {
        res = WSAStartup(version, &wsa_data);
    }

    ~WSA_Startup()
    {
        // we ignore return code here
        WSACleanup();
    }

    WSADATA wsa_data{};
    int res{};
};


str to_UTF8(wstr_cref wide_str)
{
    int size = WideCharToMultiByte(
        CP_UTF8, 0, wide_str.c_str(), -1,
        nullptr, 0, nullptr, nullptr);

    if (size == 0)
        return "";

    auto utf8_str = std::string(size, '\0');

    WideCharToMultiByte(
        CP_UTF8, 0, wide_str.c_str(), -1,
        &utf8_str[0], size, nullptr, nullptr);

    return utf8_str;
}

wstr to_wide(str_cref utf8_str)
{
    int size = MultiByteToWideChar(
        CP_UTF8, 0, utf8_str.data(),
        -1, nullptr, 0);

    if (size == 0)
        return L"";

    wstr wide_str(size, L'\0');

    MultiByteToWideChar(
        CP_UTF8, 0, utf8_str.data(),
        -1, &wide_str[0], size);

    return wide_str;
}


str last_error_as_string(DWORD last_error)
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

    return to_UTF8(wstr(buffer, size));
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
        throw std::format("[ERROR] Cannot allocate SID: {}",
                          last_error_as_string(GetLastError()));
    }

    BOOL is_member = false;

    success = CheckTokenMembership(NULL, AdministratorsGroup, &is_member);

    if (not success)
    {
        FreeSid(AdministratorsGroup);
        throw std::format("[ERROR] CheckTokenMembership fasiled: {}",
                          last_error_as_string(GetLastError()));
    }

    FreeSid(AdministratorsGroup);

    return (is_member > 0);
}

#if 0 // not used
void run_as_administrator(wchar_t* argv[])
{
    std::wstringstream ss;

    for (wchar_t** args = argv + 1;
         *args != nullptr;
         ++args)
    {
        ss << *args << " ";
    }

    auto s_argv = ss.str();

    // Prompt the user with a UAC dialog for elevation
    SHELLEXECUTEINFO shell_execute_info{};
    shell_execute_info.cbSize = sizeof(SHELLEXECUTEINFO);
    shell_execute_info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_UNICODE | SEE_MASK_NO_CONSOLE;
    shell_execute_info.lpVerb = L"runas"; // Request elevation
    shell_execute_info.lpFile = argv[0]; // Path to your application executable
    shell_execute_info.lpParameters = s_argv.c_str(); // Optional parameters for your application
    shell_execute_info.nShow = SW_SHOWNORMAL;

    if (BOOL res = ShellExecuteExW(&shell_execute_info);
        not res)
    {
        throw std::format("[ERROR] cannot start app as Administrator: {}",
                          last_error_as_string(GetLastError()));
    }

    if (DWORD res = WaitForSingleObject(shell_execute_info.hProcess, INFINITE);
        res == WAIT_FAILED)
    {
        throw std::format("[ERROR] WaitForSingleObject failed: {}",
                          last_error_as_string(GetLastError()));
    }

    if (BOOL res = CloseHandle(shell_execute_info.hProcess);
        res == 0)
    {
        throw std::format("[ERROR] CloseHandle failed: {}",
                          last_error_as_string(GetLastError()));
    }
}
#endif

void print_nic_info(const vec<Interface>& interfaces)
{
    for (const auto& itf : interfaces)
    {
        cout
            << "Name: " << itf.name << " - " << itf.description << endl
            << "Status: " << (itf.connected ? "Connected" : "Disconnected") << endl
            << "IPv4: " << itf.ip << "/" << itf.subnet << endl
            << "Gateway: " << itf.gateway << endl
            << "DNS: " << itf.dns << "(" << itf.dns_suff << ")" << endl
            << "Metric: " << itf.metric << " auto: " << (itf.automatic_metric ? "Yes" : "No") << endl
            << "Index: " << itf.index << endl
            //<< "Description: " << itf.description << endl
            << endl;
    }
}

void dump_nic_info(const vec<Interface>& interfaces,
                   str_cref filename)
{
    StringBuffer sb;
    PrettyWriter writer(sb);

    writer.StartArray();

    for (const auto& itf : interfaces)
    {
        writer.String(itf.name.data());
    }

    writer.String("dummy, leave it last");

    writer.EndArray();

    std::ofstream ofs(filename,
                      std::ios::out |
                      std::ios::trunc |
                      std::ios::binary);

    if (not ofs.is_open())
    {
        throw std::format("[ERROR] Cannot open file '{}' for writing", filename);
    }

    ofs << sb.GetString();
}

void update_nic_metric_for_luid(str_cref interface_name,
                                IF_LUID luid,
                                ULONG new_metric)
{
    // Retrieve the IP interface table
    MIB_IPINTERFACE_ROW row{};
    row.Family = AF_INET; // IPv4
    row.InterfaceLuid = luid;

    DWORD result = GetIpInterfaceEntry(&row);
    row.SitePrefixLength = 32; // For an IPv4 address, any value greater than 32 is an illegal value.

    if (result != NO_ERROR)
    {
        throw std::format("[ERROR] cannot get interface entry: {}",
                          last_error_as_string(result));
    }

    // Change the metric
    row.Metric = new_metric; // Set the desired metric

    // Set the modified IP interface entry
    result = SetIpInterfaceEntry(&row);

    if (result != NO_ERROR)
    {
        throw std::format("[ERROR] Cannot update metric for interface '{}': {}",
                          interface_name, last_error_as_string(result));
    }

}

void update_nic_metric(const vec<Interface>& interfaces,
                       str_cref filename)
{
    std::ifstream ifs(filename,
                      std::ios::in |
                      std::ios::binary);

    if (not ifs.is_open())
    {
        throw std::format("[ERROR] Cannot open file '{}' for reading", filename);
    }

    str json_content(std::istreambuf_iterator<char>{ifs},
                     std::istreambuf_iterator<char>{});

    Document document;

    if (document.Parse(json_content.data()).HasParseError())
    {
        auto why = GetParseError_En(document.GetParseError());
        throw std::format("[ERROR] Cannot parse JSON '{}': {}", filename, why);
    }

    if (not document.IsArray())
    {
        throw std::format("[ERROR] Root value in json file '{}' is not an array.",
                          filename);
    }

    // Iterate over the array elements
    for (SizeType i = 0;
         i < document.Size();
         ++i)
    {
        // Check if the array element is a string
        if (not document[i].IsString())
        {
            continue;
        }

        auto target_name = document[i].GetString();

        auto it = std::find_if(interfaces.begin(), interfaces.end(),
                               [&target_name](const Interface& itf)
        {
            return utf8cmp(itf.name.c_str(), target_name) == 0;
        });

        if (it == interfaces.end())
        {
            cout << std::format("[WARN] Cannot find interface '{}', maybe has been disabled? skipping...", target_name)
                << endl;
            continue;
        }

        if (it->automatic_metric)
        {
            MIB_IPINTERFACE_ROW row{};
            row.Family = AF_INET;
            row.InterfaceLuid = it->luid;

            DWORD res = GetIpInterfaceEntry(&row);

            if (res != NO_ERROR)
            {
                throw std::format("[ERROR] Cannot get info on interface '{}' : {}",
                                  target_name, last_error_as_string(res));
            }

            row.UseAutomaticMetric = 0;
            row.SitePrefixLength = 32; // For an IPv4 address, any value greater than 32 is an illegal value.

            res = SetIpInterfaceEntry(&row);

            if (res != NO_ERROR)
            {
                cout << std::format("[WARN] Cannot disable automatic metric for interface '{}' : {}",
                                    target_name, last_error_as_string(res));

                continue;
            }
        }

        ULONG new_metric = (i + 1) * 10;
        update_nic_metric_for_luid(target_name,
                                   it->luid,
                                   new_metric);

        cout << std::format("[INFO] interface '{}' updated succesfully, new metric: {}",
                            target_name, new_metric) << endl;
    }
}


vec<Interface> collect_nic_info()
{
    ULONG buffer_size = 0;
    ULONG adapters_flags =
        GAA_FLAG_INCLUDE_WINS_INFO |
        GAA_FLAG_INCLUDE_PREFIX |
        GAA_FLAG_INCLUDE_GATEWAYS;

    GetAdaptersAddresses(AF_INET, adapters_flags, NULL, NULL, &buffer_size);

    auto* mem_ = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buffer_size);
    std::unique_ptr<void, Heap_Deleter> mem(mem_);

    if (not mem)
    {
        throw std::format("[ERROR] cannot allocate memory!");
    }

    DWORD result = GetAdaptersAddresses(
        AF_INET,
        adapters_flags,
        NULL,
        (IP_ADAPTER_ADDRESSES*)mem.get(), &buffer_size);

    if (result != NO_ERROR)
    {
        throw std::format("[ERROR] cannot get adapters addresses: {}",
                          last_error_as_string(result));
    }

    vec<Interface> interfaces;

    IP_ADAPTER_ADDRESSES* adapter = (IP_ADAPTER_ADDRESSES*)mem.get();

    while (adapter != nullptr)
    {
        Interface itf{};

        itf.name = to_UTF8(adapter->FriendlyName);
        itf.description = to_UTF8(adapter->Description);
        itf.connected = adapter->OperStatus == IfOperStatusUp;
        itf.dns_suff = to_UTF8(adapter->DnsSuffix);
        itf.metric = adapter->Ipv4Metric;
        itf.index = adapter->IfIndex;
        itf.luid = adapter->Luid;

        MIB_IPINTERFACE_ROW interface_row{};
        interface_row.Family = AF_INET;
        interface_row.InterfaceLuid = adapter->Luid;

        result = GetIpInterfaceEntry(&interface_row);

        if (result != NO_ERROR)
        {
            throw std::format("[ERROR] GetIpInterfaceEntry failed: {}",
                              last_error_as_string(result));
        }

        itf.automatic_metric = interface_row.UseAutomaticMetric;

        // get all the IPs
        for (IP_ADAPTER_UNICAST_ADDRESS_LH* unicast_addr = adapter->FirstUnicastAddress;
             unicast_addr != nullptr;
             unicast_addr = unicast_addr->Next)
        {
            sockaddr_in* sockaddr_ipv4 = reinterpret_cast<sockaddr_in*>(unicast_addr->Address.lpSockaddr);
            wchar_t ip_str[INET_ADDRSTRLEN]{};
            InetNtopW(AF_INET, &(sockaddr_ipv4->sin_addr), ip_str, INET_ADDRSTRLEN);

            itf.ip.append(to_UTF8(ip_str)).append(" ");
            itf.subnet = unicast_addr->OnLinkPrefixLength;
        }

        // get all the Gateway
        for (IP_ADAPTER_GATEWAY_ADDRESS_LH* gateway_addr = adapter->FirstGatewayAddress;
             gateway_addr != nullptr;
             gateway_addr = gateway_addr->Next)
        {
            sockaddr_in* sockaddr_ipv4 = reinterpret_cast<sockaddr_in*>(gateway_addr->Address.lpSockaddr);
            wchar_t gateway_str[INET_ADDRSTRLEN]{};
            InetNtopW(AF_INET, &sockaddr_ipv4->sin_addr, gateway_str, INET_ADDRSTRLEN);

            itf.gateway.append(to_UTF8(gateway_str)).append(" ");
        }

        // get all the DNS
        for (IP_ADAPTER_DNS_SERVER_ADDRESS_XP* dns_addr = adapter->FirstDnsServerAddress;
             dns_addr != nullptr;
             dns_addr = dns_addr->Next)
        {
            sockaddr_in* sockaddr_ipv4 = reinterpret_cast<sockaddr_in*>(dns_addr->Address.lpSockaddr);
            wchar_t dns_str[INET_ADDRSTRLEN]{};
            InetNtopW(AF_INET, &sockaddr_ipv4->sin_addr, dns_str, INET_ADDRSTRLEN);

            itf.dns.append(to_UTF8(dns_str)).append(" ");
        }

        interfaces.push_back(std::move(itf));

        adapter = adapter->Next;
    }

    return interfaces;
}

void print_help(const char* program_)
{
    fs::path program_path = program_;
    string program = program_path.filename().string();

    cout << "Usage: " << program << " [<empty> | dump | load | help]" << endl << endl

        << program << endl
        << "   print info on installed nic" << endl << endl

        << program << " dump file.json " << endl
        << "   produce a json file that allows you to reorder the nic priority" << endl << endl

        << program << " load file.json (requires elevation)" << endl
        << "   reorder the nic priority based on the order in the json file" << endl << endl

        << program << " help" << endl
        << "   show this help" << endl;
}

int main(int argc, const char* argv[])
{
    try
    {

#if DEV_BUILD == 1

        const char* fake_argv[] =
        {
            "nic",
            "dump",
            "nic⚙️⚙️.json",
            NULL,
        };

        argv = (const char**)fake_argv;
        argc = sizeof(fake_argv) / sizeof(fake_argv[0]);
        argc -= 1;

#endif // DEV_BUILD

#if 0
        for (int i = 0;
             i < argc;
             ++i)
        {
            println("[{}] '{}'", i + 1, argv[i]);
        }
        println("");
        return 0;
#endif // 0


        auto wsa = WSA_Startup(MAKEWORD(2, 2));

        if (wsa.res != NO_ERROR)
        {
            throw std::format("[ERROR] WSAStartup failed with code: {}", wsa.res);
        }

        vec<Interface> interfaces = collect_nic_info();

        std::sort(interfaces.begin(), interfaces.end(),
                  [](const Interface& a, const Interface& b)
        {
            return a.metric < b.metric;
        });

        if (argc == 1)
        {
            print_nic_info(interfaces);
        }
        else if (argc == 2)
        {
            if (utf8cmp(argv[1], "help") == 0)
            {
                print_help(argv[0]);
            }
            else
            {
                print_help(argv[0]);
                return 1;
            }
        }
        else if (argc == 3)
        {
            if (utf8cmp(argv[1], "dump") == 0)
            {
                dump_nic_info(interfaces, argv[2]);
            }
            else if (utf8cmp(argv[1], "load") == 0)
            {
                update_nic_metric(interfaces, argv[2]);
            }
            else
            {
                print_help(argv[0]);
                return 1;
            }
        }
        else
        {
            print_nic_info(interfaces);
            return 1;
        }

        return 0;
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
