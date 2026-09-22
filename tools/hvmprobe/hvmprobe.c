/*
 * hvmprobe: User-mode hardware virtualization environment detector.
 *
 * Rationale: The HVM backend of KswordARK checks a series of CPUID/MSR conditions before starting the resident component. Among
 * them, CPUID.1:ECX[31] (hypervisor present) is always 1 in a virtual machine, causing the resident component to be rejected.
 * To determine whether a VM can test resident operation, first establish which CPUID values its guest actually sees.
 *
 * This program does not load a driver, requires no signature, and needs no administrator privileges. It prints the CPUID values that the
 * driver would read exactly as-is, so it can be copied directly into a virtual machine to verify whether .vmx modifications have taken effect.
 *
 * Compile (on host, statically linked to avoid missing runtime libraries in the VM):
 *   cl /nologo /O2 /MT /W4 hvmprobe.c /Fe:hvmprobe.exe
 */

#include <windows.h>
#include <intrin.h>
#include <stdio.h>

/* Reconstruct the 12-byte vendor string from the three CPUID registers. */
static void
copyVendor(char* out, int b, int d, int c)
{
    memcpy(out + 0, &b, 4);
    memcpy(out + 4, &d, 4);
    memcpy(out + 8, &c, 4);
    out[12] = '\0';
}

/* Hyper-V vendor string is in leaf 0x40000000 in EBX/ECX/EDX order, unlike leaf 0. */
static void
copyHvVendor(char* out, int b, int c, int d)
{
    memcpy(out + 0, &b, 4);
    memcpy(out + 4, &c, 4);
    memcpy(out + 8, &d, 4);
    out[12] = '\0';
}

static void
printBit(const char* name, int value, const char* meaning)
{
    printf("  %-34s %s   %s\n", name, value ? "yes" : "no ", meaning);
}

/* Read a DWORD registry value; return fallback if not found. */
static DWORD
readDword(const char* subKey, const char* valueName, DWORD fallback)
{
    HKEY key = NULL;
    DWORD value = fallback;
    DWORD size = sizeof(value);
    DWORD type = 0;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &key) !=
        ERROR_SUCCESS) {
        return fallback;
    }
    if (RegQueryValueExA(key, valueName, NULL, &type,
                         (LPBYTE)&value, &size) != ERROR_SUCCESS ||
        type != REG_DWORD) {
        value = fallback;
    }
    RegCloseKey(key);
    return value;
}

int
main(void)
{
    int regs[4] = { 0 };
    char vendor[13] = { 0 };
    char hvVendor[13] = { 0 };
    int hypervisorPresent = 0;
    int vmxSupported = 0;
    int svmSupported = 0;
    DWORD vbsEnabled = 0;
    DWORD hvciRunning = 0;

    printf("hvmprobe - KswordARK HVM 环境探测\n");
    printf("================================================================\n\n");

    /* Leaf 0: Vendor ID, determines whether to take the VMX or SVM branch. */
    __cpuid(regs, 0);
    copyVendor(vendor, regs[1], regs[3], regs[2]);
    printf("CPU 厂商: %s\n", vendor);

    /* leaf 1: The two decisive bits for VMX and hypervisor-present. */
    __cpuid(regs, 1);
    vmxSupported = (regs[2] >> 5) & 1;
    hypervisorPresent = (regs[2] >> 31) & 1;
    printf("\nCPUID.1:ECX 关键位\n");
    printBit("[5]  VMX", vmxSupported, "Intel 硬件虚拟化");
    printBit("[31] hypervisor present", hypervisorPresent,
             "驱动据此判定已有 hypervisor 占用");

    /* Corresponding bit on the AMD side, allowing the same output to cover both platforms. */
    __cpuid(regs, (int)0x80000000);
    if ((unsigned)regs[0] >= 0x80000001u) {
        __cpuid(regs, (int)0x80000001);
        svmSupported = (regs[2] >> 2) & 1;
        printf("\nCPUID.80000001:ECX 关键位\n");
        printBit("[2]  SVM", svmSupported, "AMD 硬件虚拟化");
    }

    /* The hypervisor vendor string is defined only when the present bit is set to 1. */
    if (hypervisorPresent) {
        __cpuid(regs, (int)0x40000000);
        copyHvVendor(hvVendor, regs[1], regs[2], regs[3]);
        printf("\nhypervisor 厂商串: \"%s\"  (CPUID.40000000)\n", hvVendor);
        printf("  最大 hypervisor leaf: 0x%08X\n", (unsigned)regs[0]);
    }

    /*
     * VBS and HVCI keep Windows' own hypervisor resident, making the environment behave like a VM. These
     * settings are readable from user mode without admin privileges, so they must be checked even on bare metal.
     */
    vbsEnabled = readDword(
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
        "EnableVirtualizationBasedSecurity", 0);
    hvciRunning = readDword(
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios"
        "\\HypervisorEnforcedCodeIntegrity",
        "Enabled", 0);
    printf("\nWindows 虚拟化安全\n");
    printf("  %-34s %lu\n", "EnableVirtualizationBasedSecurity",
           (unsigned long)vbsEnabled);
    printf("  %-34s %lu\n", "HVCI Enabled", (unsigned long)hvciRunning);

    /* Translate the facts above into "how the driver behaves"; this is the true purpose of running this program. */
    printf("\n----------------------------------------------------------------\n");
    printf("对 KswordARK 常驻的判定\n\n");
    if (!vmxSupported && !svmSupported && hypervisorPresent) {
        /*
         * This is the most easily misjudged case: the CPU supports virtualization, but the underlying hypervisor
         * does not expose it, so VMX/SVM capabilities are not visible during the capability detection phase.
         * On bare metal, HVCI/Memory Integrity typically launches Hyper-V; in a VM, the
         * host either lacks nested virtualization or runs under another hypervisor.
         */
        printf("  拒绝：底层 hypervisor \"%s\" 没有把硬件虚拟化暴露上来，\n",
               hvVendor);
        printf("  连 VMX/SVM 能力位都看不到，PREPARE 阶段即失败。\n\n");
        if (vbsEnabled != 0 || hvciRunning != 0) {
            printf("  本机原因很可能是 VBS/HVCI：它会拉起 Hyper-V 并接管 VT-x。\n");
            printf("  需要关闭内存完整性并设置 hypervisorlaunchtype off 后重启。\n");
        } else {
            printf("  若这是虚拟机，宿主需要开启嵌套虚拟化\n");
            printf("  （VMware 为 vhv.enable = \"TRUE\"），\n");
            printf("  且宿主自身不能运行在别的 hypervisor 之下。\n");
        }
    } else if (!vmxSupported && !svmSupported) {
        printf("  拒绝：没有硬件虚拟化能力，也没有检测到 hypervisor。\n");
        printf("  通常是固件里关闭了虚拟化，需要在 BIOS/UEFI 中开启。\n");
    } else if (hypervisorPresent) {
        printf("  拒绝：hvm_resident.c 对 HYPERVISOR_PRESENT 是无条件拒绝，\n");
        printf("  常驻与 SOAK 都会返回 HYPERVISOR_CONFLICT。\n\n");
        printf("  可测的部分：驱动加载卸载、能力探测、R-1 内存通道、\n");
        printf("  控制寄存器策略配置、事件流面板、全部错误路径。\n");
    } else if (vmxSupported) {
        printf("  可以尝试：VMX 可用且 CPUID 未报告 hypervisor，\n");
        printf("  常驻的硬件门可以通过。\n");
    } else {
        printf("  硬件支持 SVM，但当前版本没有 SVM 后端，\n");
        printf("  驱动会返回 BACKEND_NOT_IMPLEMENTED。\n");
    }
    printf("\n");
    return 0;
}
