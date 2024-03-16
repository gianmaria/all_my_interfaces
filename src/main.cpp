// This is an open source non-commercial project. Dear PVS-Studio, please check it.

// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

#include <winsock2.h>
#include <iphlpapi.h>
#include <iostream>

#pragma comment(lib, "IPHLPAPI.lib")

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
using std::endl;
using std::string;
using std::string_view;
using std::vector;
using std::set;
using std::map;

using str = std::string;
using str_cref = std::string const&;

template<typename T>
using vec = vector<T>;

using namespace std::string_literals;
using namespace std::string_view_literals;

namespace fs = std::filesystem;

std::wstring last_error_as_string(DWORD last_error);

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
        throw std::format(L"ERROR: Cannot allocate SID: {}", 
                          last_error_as_string(GetLastError()));
    }

    BOOL is_member = false;

    success = CheckTokenMembership(NULL, AdministratorsGroup, &is_member);

    if (not success)
    {
        FreeSid(AdministratorsGroup);
        throw std::format(L"ERROR: CheckTokenMembership fasiled: {}", 
                          last_error_as_string(GetLastError()));
    }

    FreeSid(AdministratorsGroup);

    return (is_member > 0);
}


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

int main()
{
    try
    {
        cout << "IsUserAdmin: " << is_user_admin() << endl;

        throw std::wstring(L"yoooooooooooooo");

        auto constexpr adapter_count = 128;
        IP_ADAPTER_ADDRESSES adapters[adapter_count] {};
        ULONG outBufLen = sizeof(IP_ADAPTER_ADDRESSES) * adapter_count;

        auto res = GetAdaptersAddresses(
            AF_INET,
            GAA_FLAG_INCLUDE_PREFIX |
            GAA_FLAG_INCLUDE_WINS_INFO |
            GAA_FLAG_INCLUDE_GATEWAYS |
            GAA_FLAG_INCLUDE_ALL_INTERFACES,
            NULL,
            adapters,
            &outBufLen);

        if (res != NO_ERROR)
        {
            //std::string message = GetLastErrorAsString(res);
            int s = 0;
        }

        IP_ADAPTER_ADDRESSES* pAddresses = adapters;

        if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &outBufLen) == NO_ERROR)
        {
            while (pAddresses)
            {
                std::wcout << L"AdapterName: " << pAddresses->AdapterName << "\n";
                std::wcout << L"FriendlyName: " << pAddresses->FriendlyName << "\n";
                std::wcout << L"Ipv4Metric: " << pAddresses->Ipv4Metric << "\n";

                std::wcout << L"DnsSuffix: " << pAddresses->DnsSuffix << "\n";
                std::wcout << L"Description: " << pAddresses->Description << "\n\n";

                pAddresses = pAddresses->Next;
            }
        }
        return 0;
    }
    catch (const std::wstring& e)
    {
        std::wcout << e << endl;
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

