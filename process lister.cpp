#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

int main()
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "err creating snapshot: " << GetLastError() << std::endl;
        return 1;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &pe32)) {
        std::cerr << "err process32: " << GetLastError() << std::endl;
        CloseHandle(snapshot);
        return 1;
    }

    std::cout << "process list:\n";
    std::cout << "------------------------------------------------\n";
    std::cout << "PID\tprocess name\n";
    std::cout << "------------------------------------------------\n";

    do {
        std::wcout << pe32.th32ProcessID << L"\t" << pe32.szExeFile << L"\n";
        
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
        if (process) {
            WCHAR fullPath[MAX_PATH];
            DWORD size = MAX_PATH;
            if (QueryFullProcessImageName(process, 0, fullPath, &size)) {
                std::wcout << L"\t" << fullPath << "\n";
            }
            else {
                std::wcout << L"\terr handling process: " << GetLastError() << std::endl;
            }
        }

        else {
            std::cerr << "\terr getting full path: " << GetLastError() << std::endl;
        }
    } while (Process32Next(snapshot, &pe32));

    CloseHandle(snapshot);

    std::cout << "its all for now..";
    std::cin.get();

    return 0;
}
