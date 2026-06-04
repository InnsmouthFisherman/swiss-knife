#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "psapi.lib")

void memory_snap(){
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "err creating snapshot: " << GetLastError() << std::endl;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &pe32)) {
        std::cerr << "err process32: " << GetLastError() << std::endl;
        CloseHandle(snapshot);
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
            if (QueryFullProcessImageNameW(process, 0, fullPath, &size)) {
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
}

void dump_memory() {
    DWORD process_id;
    std::cout << "Enter process id: ";
    std::cin >> process_id;

    HANDLE process = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        process_id
    );

    if (process == NULL) {
        std::cerr << "Failed to open process. Error: " << GetLastError() << std::endl;
        return;
    }

    HMODULE mods[1024];
    DWORD cb_needed;

    if (!EnumProcessModules(process, mods, sizeof(mods), &cb_needed)) {
        std::cerr << "EnumProcessModules failed. Error: " << GetLastError() << std::endl;
        CloseHandle(process);
        return;
    }

    HMODULE hModule = mods[0];
    MODULEINFO mod_info;

    if (!GetModuleInformation(process, hModule, &mod_info, sizeof(mod_info))) {
        std::cerr << "GetModuleInformation failed. Error: " << GetLastError() << std::endl;
        CloseHandle(process);
        return;
    }

    LPCVOID base_address = mod_info.lpBaseOfDll;
    SIZE_T module_size = mod_info.SizeOfImage;

    std::cout << "Base address: " << base_address << std::endl;
    std::cout << "Module size: " << module_size << " bytes" << std::endl;

    std::vector<BYTE> buffer(module_size);
    SIZE_T bytes_read;

    if (ReadProcessMemory(process, base_address, buffer.data(), module_size, &bytes_read)) {
        std::cout << "Successfully read " << bytes_read << " bytes" << std::endl;
    } else {
        std::cerr << "ReadProcessMemory failed. Error: " << GetLastError() << std::endl;
    }

    CloseHandle(process);
}

void inject_dll(int argc, char* argv[]) {
    DWORD pid = 0;
    std::wstring dllPath;

    if (argc == 3) {
        pid = std::stoul(argv[1]);
        int len = MultiByteToWideChar(CP_ACP, 0, argv[2], -1, nullptr, 0);
        wchar_t* widePath = new wchar_t[len];
        MultiByteToWideChar(CP_ACP, 0, argv[2], -1, widePath, len);
        dllPath = widePath;
        delete[] widePath;
    } else {
        std::cout << "Enter target PID: ";
        std::cin >> pid;
        std::cout << "Enter full DLL path: ";
        std::string path;
        std::cin >> path;
        int len = MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, nullptr, 0);
        wchar_t* widePath = new wchar_t[len];
        MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, widePath, len);
        dllPath = widePath;
        delete[] widePath;
    }

    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProcess) {
        std::cerr << "OpenProcess failed. Error: " << GetLastError() << std::endl;
    }

    size_t size = (dllPath.length() + 1) * sizeof(wchar_t);
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        std::cerr << "VirtualAllocEx failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
    }

    if (!WriteProcessMemory(hProcess, remoteMem, dllPath.c_str(), size, NULL)) {
        std::cerr << "WriteProcessMemory failed. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
    }

    LPVOID loadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    if (!loadLibAddr) {
        std::cerr << "GetProcAddress failed. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibAddr, remoteMem, 0, NULL);
    if (!hThread) {
        std::cerr << "CreateRemoteThread failed. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
    }

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "DLL injected successfully." << std::endl;
}

int main()
{
    int option = 1;

    while (option) {
        std::cout << "\n1) List processes \n2) Process memory dump\n3)Inject DLL\n";
        std::cin >> option;

        switch (option){
            case 1: 
                memory_snap();
                break;
            case 2: 
                dump_memory();
                break;
            case 3:
                //inject_dll();
                break;
            case 0: break;
        } 
    }    

    return 0;
}
