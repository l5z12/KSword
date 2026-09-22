/*
 * hvm_probe_dll.dll: Evidence of R-1 DLL injection.
 *
 * It does one thing: when loaded, it writes a file containing the PID of the process that loaded it.
 *
 * Why write to disk instead of a popup or shared memory: Injection is triggered by the hypervisor on
 * a borrowed thread on **another machine**; the verifier cannot obtain any handles to that process.
 * A file is the only evidence that can be verified externally afterward and proves authorship—if the
 * PID matches, it rules out the possibility that the file was left by something else.
 *
 * Performing file I/O in DllMain is avoided in production code due to the loader lock. This is acceptable here:
 * it is a one-time lab probe; CreateFile/WriteFile do not recurse into the loader, whereas switching to 'set an
 * event and wait for external consumption' would require more operations that should not be done under the lock.
 */

#include <windows.h>
#include <stdio.h>

static void writeProof(void)
{
    char text[128];
    DWORD written = 0UL;
    HANDLE file = CreateFileA(
        "C:\\ksword\\dll-inject-proof.txt",
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (file == INVALID_HANDLE_VALUE) {
        return;
    }
    /* PID is the credential of 'who loaded me'; the verifier reconciles it with the target process. */
    (void)sprintf_s(
        text,
        sizeof(text),
        "loaded-by-pid %lu\r\n",
        GetCurrentProcessId());
    (void)WriteFile(
        file,
        text,
        (DWORD)strlen(text),
        &written,
        NULL);
    CloseHandle(file);
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
    UNREFERENCED_PARAMETER(reserved);

    if (reason == DLL_PROCESS_ATTACH) {
        /* Thread attachment notifications are unnecessary, eliminating one callback under the loader lock. */
        (void)DisableThreadLibraryCalls(module);
        writeProof();
    }
    return TRUE;
}
