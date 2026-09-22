/* User-visible scheduling gaps around an existing HVM CLI operation.
 * This is NOT an internal VMX stage timer or an exact pause measurement.
 * QPC samples include Windows scheduling, Hyper-V scheduling and observer cost.
 * No driver IOCTLs, VMware APIs, process injection or hooks are used here. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MAX_CPUS 32
#define TOP_GAPS 16
typedef struct { LONGLONG start,end; } Gap;
typedef struct {
    DWORD cpu,affinityError;
    uint64_t samples;
    Gap top[TOP_GAPS];
    LONGLONG first,last;
} CpuResult;
static volatile LONG running=1,ready=0;
static HANDLE goEvent;
static CpuResult results[MAX_CPUS];
static DWORD WINAPI observe(void *arg) {
    CpuResult *r=(CpuResult*)arg;
    LARGE_INTEGER previous,current;
    int i,minI;
    if(!SetThreadAffinityMask(GetCurrentThread(),(DWORD_PTR)1<<r->cpu))
        r->affinityError=GetLastError();
    InterlockedIncrement(&ready);
    WaitForSingleObject(goEvent,INFINITE);
    QueryPerformanceCounter(&previous);r->first=previous.QuadPart;
    while(InterlockedCompareExchange(&running,1,1)) {
        QueryPerformanceCounter(&current);r->samples++;
        if(current.QuadPart-previous.QuadPart>1000) {
            minI=0;
            for(i=1;i<TOP_GAPS;i++)
                if(r->top[i].end-r->top[i].start<r->top[minI].end-r->top[minI].start) minI=i;
            if(current.QuadPart-previous.QuadPart>r->top[minI].end-r->top[minI].start) {
                r->top[minI].start=previous.QuadPart;r->top[minI].end=current.QuadPart;
            }
        }
        previous=current;
    }
    r->last=previous.QuadPart;return 0;
}
int main(int argc,char **argv) {
    DWORD count=GetActiveProcessorCount(ALL_PROCESSOR_GROUPS),i,code=1,launchError=0;
    HANDLE threads[MAX_CPUS]={0};
    STARTUPINFOA si={0};PROCESS_INFORMATION pi={0};
    LARGE_INTEGER frequency,commandStart,commandEnd;
    char command[256];
    if(argc!=2 || (strcmp(argv[1],"resident-nested-hidehv") && strcmp(argv[1],"stop"))) return 2;
    if(count>MAX_CPUS || GetActiveProcessorGroupCount()!=1) return 3;
    QueryPerformanceFrequency(&frequency);
    goEvent=CreateEventW(NULL,TRUE,FALSE,NULL);if(!goEvent)return 4;
    for(i=0;i<count;i++) {
        results[i].cpu=i;threads[i]=CreateThread(NULL,0,observe,&results[i],0,NULL);
        if(!threads[i]) {InterlockedExchange(&running,0);SetEvent(goEvent);return 5;}
    }
    while((DWORD)InterlockedCompareExchange(&ready,0,0)<count) Sleep(1);
    SetEvent(goEvent);Sleep(1000);
    snprintf(command,sizeof(command),"C:\\ksword\\hvm_ctl.exe --json %s",argv[1]);
    si.cb=sizeof(si);
    QueryPerformanceCounter(&commandStart);
    if(CreateProcessA(NULL,command,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi)) {
        if(WaitForSingleObject(pi.hProcess,30000)==WAIT_OBJECT_0) GetExitCodeProcess(pi.hProcess,&code);
        else code=258; /* Never kill an in-flight HVM transition. */
        CloseHandle(pi.hThread);CloseHandle(pi.hProcess);
    }else launchError=GetLastError();
    QueryPerformanceCounter(&commandEnd);Sleep(1000);
    InterlockedExchange(&running,0);WaitForMultipleObjects(count,threads,TRUE,INFINITE);
    printf("{\"schemaVersion\":1,\"kind\":\"execution-gap-observer\",\"command\":\"%s\",\"commandExitCode\":%lu,\"launchError\":%lu,\"qpcFrequency\":%lld,\"commandStartQpc\":%lld,\"commandEndQpc\":%lld,\"processors\":[",argv[1],(unsigned long)code,(unsigned long)launchError,(long long)frequency.QuadPart,(long long)commandStart.QuadPart,(long long)commandEnd.QuadPart);
    for(i=0;i<count;i++) {
        int j;CpuResult *r=&results[i];
        printf("%s{\"group\":0,\"number\":%lu,\"affinityError\":%lu,\"samples\":%llu,\"firstQpc\":%lld,\"lastQpc\":%lld,\"largestGaps\":[",i?",":"",(unsigned long)i,(unsigned long)r->affinityError,(unsigned long long)r->samples,(long long)r->first,(long long)r->last);
        for(j=0;j<TOP_GAPS;j++) printf("%s{\"startQpc\":%lld,\"endQpc\":%lld}",j?",":"",(long long)r->top[j].start,(long long)r->top[j].end);
        printf("]}");CloseHandle(threads[i]);
    }
    printf("]}\n");CloseHandle(goEvent);return code?1:0;
}
