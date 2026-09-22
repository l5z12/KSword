; tickprobe: A 512-byte boot sector that answers only one question: Did the clock interrupt enter the guest? If not, where did it stop?
;
;   Whether the clock interrupt entered the guest; if not, where it stopped.
;
; Why it is needed: The target under test, TinyCore, has too many components tightly coupled — real mode and protected mode.
; 12,000 round trips per second, BIOS calls, optical drives, and isolinux's own menu logic. Any single point of failure.
; The display appears static, and since the background VMware process is disabled, the application fails to start, leaving no baseline for comparison.
;
; This program runs in reverse: executes in real mode to completion without switching modes, calling BIOS, or touching the disk; writes directly to the screen.
; 0B800h text video memory. Except for the **intentionally added** sampling ports below, no other exits are generated in the guest.
;
; The readings on the screen are divided into two groups.
;
; The first group checks 'whether the interrupt arrived':
;   SPIN: increments by +1 per loop iteration; pure CPU execution, independent of any interrupts — positive control.
;   TICK reads 0040:006C; it changes only when IRQ0 arrives and BIOS's ISR #8 executes.
;   OWN: count of handlers we installed in IVT[8], incremented before the BIOS section.
;
; The second group is "where the break occurs". Driver-side measurements show: in the guest's steady state, every exit from RFLAGS.IF has it set to 1.
; VMware gains control tens of thousands of times per second, yet **never requests a single injection**. The remaining two possibilities are,
; Their boundary lies exactly at VMware's own virtual chipset registers, which the guest can read via ports:
;
;   PIT channel 0 latched count value. It decrements every 838ns; **moving = VMware's virtual timer is advancing.
;         Has a time base; if it remains constant, VMware's time is not advancing.
;   IRR: Interrupt Request Register of the master PIC (read 20h after OCW3=0Ah). bit 0 = IRQ0 is pending.
;   ISR: The In-Service Register of the main PIC (OCW3=0Bh). A set bit 0 without clearing indicates an EOI was not sent.
;         That would block all subsequent interrupts, causing a completely different type of failure.
;   SIRR: sticky or value of IRR; SISR is similar. IRQ0 goes high for only a few microseconds.
;         Sampling 110 times per second may miss every assertion; **an instantaneous zero does not prove the interrupt was never asserted,
;         Sticky value only.
;   Note: The issue occurs only on the 8254 device, not the VMware time master clock. ; Interpretation table: RTC CMOS second register (BCD). The second independent virtual clock: it runs while the PIT does not.
;         Indicates the issue is isolated to the 8254 device only, not a VMware time accounting problem.
;
; Interpretation table:
;   PIT active + SIRR bit0 = 1 + OWN = 0 -> VMware raised IRQ0 but did not deliver it; the issue lies in the delivery path.
;   PIT moves + SIRR bit0 = 0 -> Virtual PIT is running but interrupt not raised
;   PIT unchanged -> VMware virtual time has not advanced; investigate upstream.
;   SISR bit0 is always 1 -> EOI not sent, interrupt masked by self
;
; The same nine readings are written to COM1 at approximately 110 times per second, with each line containing 38 hexadecimal characters plus CRLF,
; Field widths are 8/8/8/4/2/2/2/2/2 in order. The screen version is for human viewing; the serial port version is the criterion.
; See the note at serout regarding why relying solely on the screen is not possible.
;
; ORG 7C00h is used because the BIOS loads the boot sector at 0000:7C00; code internally uses only relative jumps and
; Absolute low memory address, so no relocation is needed.

; --- Why use base-register addressing throughout instead of absolute addresses ---
;
; This MASM version only recognizes .386 (both .286 and .8086 report `error A2008: syntax error : .`),
; Under .386, it treats each absolute memory operand as a 32-bit offset and encodes it as
;
;   67& A1 00000500        mov ax, ds:[SPIN_LO]      ; 6 bytes
;
; 6 bytes doing the work of 3. After adding the sampling and display lines, the entire code block is 615 bytes and cannot fit into the boot sector.
; Switch to 16-bit base register (there is no form using BX/BP as base in 32-bit addressing mode, so the assembler)
; Must revert to 16-bit encoding, causing the prefix to naturally disappear):
;
;   8B 07                  mov ax, [bx]              ; 2 bytes
;
; Thus, BX always points to the 0500h note area, BP always points to the BDA tick counter, and the main loop no longer contains
; No absolute addresses. This is not a style choice; it is the only way to fit within these 512 bytes.
.386
_TEXT SEGMENT USE16 'CODE'
    ASSUME CS:_TEXT, DS:NOTHING, ES:NOTHING
    ORG 7C00h

VIDEO_SEG EQU 0B800h
BDA_TICK  EQU 046Ch            ; BIOS timer count (32-bit); the IRQ0 ISR increments by 1 per tick.
SCRATCH   EQU 0500h            ; Scratch area: The gap after the BIOS data area and before the boot sector.
IVT_V8    EQU 0020h            ; Real-mode Interrupt Vector Table entry 8.
ATTR      EQU 0Fh              ; Bright White

; Offsets of items in the note area relative to BX.
O_SPIN    EQU 000h             ; Spin count
O_OWN     EQU 004h             ; dd: our own IRQ0 counter
O_SAVED   EQU 008h             ; dd original interrupt vector 8 (seg:off)
O_SIRR    EQU 00Ch             ; db: sticky OR value of IRR
O_SISR    EQU 00Dh             ; db: sticky OR value of ISR
O_PIT     EQU 010h             ; dw: PIT channel 0 count read in this round.
O_IRR     EQU 012h             ; db: IRR for this round
O_ISR     EQU 013h             ; db: ISR for this round
O_RTC     EQU 014h             ; db: current round CMOS seconds
O_TSC     EQU 016h             ; Lower 16 bits of EDX for the current RDTSC cycle.

; Note: Absolute addresses usable in the interrupt handler (BX cannot be borrowed from the interrupted code there).
OWN_ABS   EQU SCRATCH + O_OWN
SAVED_ABS EQU SCRATCH + O_SAVED

; --- BIOS Parameter Block ---
;
; Having just the 55AA signature is not enough. VMware's floppy library treats the boot sector as a FAT boot sector with a BPB.
; Validation: The first version lacked a BPB, causing it to misinterpret code bytes as fields and reject the boot.
;
;   FLOPPYLIB-IMAGE: Invalid boot sector: signature aa55, sector size 952, sectors 49294
;   FLOPPYLIB-IMAGE: Expected:            signature aa55, sector size 512, sectors 2880
;
; Then it silently skipped the floppy and booted from the CD-ROM—the screen shows the TinyCore menu, appearing as
; "My program ran but showed nothing." **The rejected fixture and the observed behavior look identical**; the criterion exists only in the logs.
;
; The values here represent a 1.44MB floppy disk: 2880 512-byte sectors, 80 tracks, 2 sides, 18 sectors per track.
; File system fields are for validation purposes; we do not write FAT, and no one reads it.
entry:
    jmp SHORT start
    nop
    db 'KSWTICK '              ; OEM name, 8 bytes
    dw 512                     ; Bytes per sector
    db 1                       ; Sectors per cluster.
    dw 1                       ; Reserved sector
    db 2                       ; Number of FATs
    dw 224                     ; Root directory entry
    dw 2880                    ; Total sector count
    db 0F0h                    ; Media descriptor: 1.44MB floppy disk.
    dw 9                       ; Number of sectors per FAT.
    dw 18                      ; Sectors per track
    dw 2                       ; Number of heads
    dd 0                       ; Hidden sector
    dd 0                       ; Large capacity total sector count.
    db 0                       ; Drive letter
    db 0                       ; Reserved
    db 29h                     ; Extended boot signature
    dd 4B535754h               ; Volume serial number
    db 'KSWORDTICK'            ; Label, 11 bytes
    db ' '
    db 'FAT12   '              ; File system type, 8 bytes.

start:
    cli
    xor ax, ax
    mov ds, ax
    mov ss, ax
    mov sp, 7C00h              ; Stack grows downward, so it will not collide with code starting at 7C00h.
    cld

    ; Switch display to 80x25 text mode first.
    ;
    ; The first version omitted this step, resulting in a pure black screen: the BIOS boot screen uses **graphics mode**.
    ; At that time, 0B800h was not a visible text buffer; writing to it produced nothing visible — and 'invisible'
    ; Exactly the same as 'program did not start' in the screenshot.
    ;
    ; This is the only BIOS call in the entire program, occurring before STI and outside the loop.
    mov ax, 0003h
    int 10h

    mov ax, VIDEO_SEG
    mov es, ax

    ; Clear screen to prevent leftover characters from BIOS from interfering with parsing.
    xor di, di
    mov cx, 80*25
    mov ax, (ATTR SHL 8) OR 20h
    rep stosw

    ; Nine labels, four characters per line, with a line spacing of 160 bytes.
    ; Using a loop instead of nine calls: nine `mov di / mov si / call` instructions plus nine null-terminated strings
    ; Requires 126 bytes; this way only 58 bytes are needed, and the boot sector is short by exactly these few dozen bytes.
    mov si, OFFSET labels
    xor di, di
    mov dx, 10
lab_row:
    push di
    mov cx, 4
lab_ch:
    lodsb
    mov ah, ATTR
    stosw
    loop lab_ch
    pop di
    add di, 160
    dec dx
    jnz lab_row

    mov bx, SCRATCH            ; All subsequent scratch area accesses use [bx+offset].
    mov bp, BDA_TICK           ; [bp] The default segment is SS; here SS=0, which is exactly the segment where the BDA resides.

    ; Configure the serial port for 8-bit word length, no parity, and 1 stop bit.
    ;
    ; Without this line, every byte in the log will **retain only its lower 5 bits**: the BIOS sets the Line Control Register
    ; Leaving it at 0 (5-bit word length) causes the UART to transmit only the lower 5 bits. The previous 989 KB log exhibited exactly this behavior —
    ; No data was lost ('0'-'9' masked to 10h-19h, 'A'-'F' masked to 01h-06h, with no overlap between the two ranges),
    ; Can be unambiguously restored, but appears to be a full screen of control characters.
    ; Writing 3 also clears DLAB, so 3F8h becomes the Transmit Holding Register thereafter.
    mov dx, 3FBh
    mov al, 3
    out dx, al

    ; Only allow IRQ0; mask all others.
    ;
    ; This is not throttling, but **converting the reading to a single variable**: the BIOS default mask 0B8h still leaves IRQ1 and IRQ6 enabled,
    ; The floppy drive of that guest VM is disconnected, and IRR bit6 remains stuck. After masking it, the interrupt is now active.
    ; This implies only IRQ0 is active.
    mov al, 0FEh
    out 21h, al                ; Master mask: retain only IRQ0
    mov al, 0FFh
    out 0A1h, al               ; From mask: full mask

    ; EOI is intentionally not sent here.
    ;
    ; In the previous version, eight non-specific EOIs were issued here to verify a specific condition: the main PIC's ISR was constantly 03h,
    ; IRR remains 41h; after clearing the service bit, TICK and OWN immediately start (85 ticks match).
    ; 5s RTC, 16.8Hz). This proves the delivery link itself is functional; the deadlock stems from two historically dropped packets.
    ; Caused by interrupts — they are acknowledged and removed from the virtual controller by L1, yet no handler ever runs,
    ; Thus, EOI is never sent.
    ;
    ; The root cause has already been fixed in L0 (event delivery was aborted, and missing events were re-injected based on IDT-vectoring information).
    ; Keeping these EOI instructions would merge the readings for "the fix worked" and "the guest untangled the deadlock itself" into a single value —
    ; **Verify that the patched probe cannot bypass the defect**.

    xor ax, ax
    mov [bx+O_SPIN], ax
    mov [bx+O_SPIN+2], ax
    mov [bx+O_SIRR], ax        ; Write to both SIRR and SISR sticky bytes in one operation.

    ; Install a custom interrupt handler for interrupt 8 and chain it to the original BIOS handler.
    ;
    ; Why it's needed: The TICK not incrementing alone cannot distinguish between 'interrupt never arrived' and 'interrupt arrived but BIOS failed'
    ; ISR not finished. The own counter increments before the BIOS section, so OWN moves while TICK does not.
    ; This indicates the interrupt occurred but the BIOS handler failed; if neither moves, the interrupt truly never arrived.
    ; After incrementing, **chain to** the original handler instead of using iret directly, so EOI and tick handling remain with the BIOS.
    ; Do not alter the behavior under test.
    mov di, IVT_V8
    mov ax, [di]
    mov [bx+O_SAVED], ax
    mov ax, [di+2]
    mov [bx+O_SAVED+2], ax
    mov word ptr [di], OFFSET irq0
    mov word ptr [di+2], 0
    xor ax, ax
    mov [bx+O_OWN], ax
    mov [bx+O_OWN+2], ax

    sti                        ; Interrupts are enabled only from this point; IRQ0 can only arrive after this.

; The main loop is now **wait-for-interrupt**, no longer spinning.
;
; Reason for change: The spinning version has already proven that interrupts can enter the guest (18.1 Hz, OWN and TICK synchronized). However, the spinning...
; Guests never need to be woken up, so they cannot ask the remaining question — in practice, both L1 virtual processors remain halted.
; With HLT set, RFLAGS.IF = 1, and zero increment in entry/injection counts within 30 seconds, it means "after being halted"
; Nothing to wake them up.
;
; Adding hlt makes this fixture test exactly whether **VMware can wake a halted vCPU**.
; Each round equals one wake-up, so the SPIN growth rate directly represents the wake-up rate and should be approximately 18.2.
; SPIN not moving means the system stopped and never woke up again, whereas the previous version ran at 7 million iterations per second on the same machine.
;
; Throttling was also removed: with one interrupt per cycle and a base rate of only 18 Hz, there is nothing to throttle.
main:
    add word ptr [bx+O_SPIN], 1
    adc word ptr [bx+O_SPIN+2], 0

    ; --- Sample the VMware virtual chipset.

    ; PIT Channel 0: Issue the latch command (control word 00h) first, then read the low and high bytes.
    ; Latching ensures obtaining a consistent 16-bit value; reading without latching may capture a counter that is currently changing.
    mov al, 0
    out 43h, al
    in  al, 40h
    mov dl, al
    in  al, 40h
    mov dh, al
    mov [bx+O_PIT], dx

    ; Main PIC: Select IRR via OCW3 then read; select ISR via OCW3 then read. Leave it in IRR mode after reading.
    ; Prevent others (BIOS ISR) from reading the ISR with default semantics.
    mov al, 0Ah
    out 20h, al
    in  al, 20h
    mov [bx+O_IRR], al
    or  [bx+O_SIRR], al
    mov al, 0Bh
    out 20h, al
    in  al, 20h
    mov [bx+O_ISR], al
    or  [bx+O_SISR], al
    mov al, 0Ah
    out 20h, al

    ; CMOS seconds. Writing bit 7 of 70h simultaneously controls NMI masking; writing 0 enables it, consistent with power-on state.
    mov al, 0
    out 70h, al
    in  al, 71h
    mov [bx+O_RTC], al

    ; Guest's own timestamp counter.
    ;
    ; PIT and CMOS second prove that the **VMware device time** is running; TSC is the **guest processor's own**.
    ; Counter, offset by the TSC offset in vmcs. These are two different things, whereas Linux's
    ; TSC-deadline timers, udelay, and clock sources are all built on the latter; if TSC does not run,
    ; The timer will never expire, and the outside world only sees it as 'stopped'.
    ;
    ; Only take the lower 16 bits of EDX: at 2.1GHz it increments approximately once every 2 seconds, rising by 30 per minute.
    ; Detects whether the instruction was modified without being so fast that it cannot be read.
    ; rdtsc. Written byte-by-byte instead of using .586: changing the CPU instruction affects encoding elsewhere.
    ; And this entire code block fits into 512 bytes thanks to the current 16-bit encoding scheme.
    db 0Fh, 31h
    mov [bx+O_TSC], dx

    ; --- Display, column 6 of each line ---
    mov di, 12
    mov ax, [bx+O_SPIN+2]
    call hex16
    mov ax, [bx+O_SPIN]
    call hex16

    mov di, 172
    mov ax, [bp+2]
    call hex16
    mov ax, [bp]
    call hex16

    mov di, 332
    mov ax, [bx+O_OWN+2]
    call hex16
    mov ax, [bx+O_OWN]
    call hex16

    mov di, 492
    mov ax, [bx+O_PIT]
    call hex16

    mov di, 652
    mov al, [bx+O_IRR]
    call hex8

    mov di, 812
    mov al, [bx+O_ISR]
    call hex8

    mov di, 972
    mov al, [bx+O_SIRR]
    call hex8

    mov di, 1132
    mov al, [bx+O_SISR]
    call hex8

    mov di, 1292
    mov al, [bx+O_RTC]
    call hex8

    mov di, 1452
    mov ax, [bx+O_TSC]
    call hex16

    ; End of line. Each line on the serial port is a fixed width of 38 hex characters; they can be split by offset.
    ; Therefore, only this single delimiter is needed.
    mov al, 13
    call serout
    mov al, 10
    call serout

    ; Halt and wait for the next interrupt to wake us up.
    ; sti is redundant (interrupts already enabled outside the loop); kept because the instruction shadow between sti and hlt is
    ; This is the standard pattern: interrupts arriving exactly here will not be missed.
    sti
    hlt
    jmp main

; --- Our own IRQ0 handler: counts and chains to the original BIOS handler ---
;
; Do not send EOI or iret yourself: EOI and tick are left to the original handler, so besides an extra counter, nothing else changes.
; Nothing else changes. Using a far indirect jump chain to reach it, the return address remains the instruction that was interrupted.
;
; Use absolute addresses instead of [bx]: interrupts can occur at any instruction, so borrowing registers from the interrupted code is unsafe.
; An assumption that holds only when 'it happens to be our main loop'. CS must be 0 here (we wrote it ourselves).
; The segment part of IVT[8] is written as 0), so the absolute address under the cs: prefix is unconditionally correct.
irq0:
    push ax
    add word ptr cs:[OWN_ABS], 1
    adc word ptr cs:[OWN_ABS+2], 0
    pop ax
    jmp dword ptr cs:[SAVED_ABS]

; --- Write AX as a four-digit hexadecimal value to ES:DI, then increment DI by 8 ---
hex16:
    mov cx, 4
hx_next:
    rol ax, 4
    push ax
    and al, 0Fh
    call nibble
    pop ax
    loop hx_next
    ret

; --- Write the lower two nibbles of AL to ES:DI, then increment DI by 4 ---
; The low nibble must be used only after the high nibble is written, and `nibble` modifies AH to the attribute byte.
; So the original value is pushed to the stack for preservation; registers cannot be relied upon.
hex8:
    push ax
    shr al, 4
    call nibble
    pop ax
    and al, 0Fh
    call nibble
    ret

; --- Write the lower nibble of AL as a character; send a copy to both the screen and the serial port.
nibble:
    add al, '0'
    cmp al, '9'
    jbe nb_ok
    add al, 7
nb_ok:
    mov ah, ATTR
    stosw
    ; It falls to serout. All characters passing through the nibble appear simultaneously on the serial port.
    ; The label is written directly via stosw, so it won't mix with the serial port path.

; --- AL sends to COM1
;
; Why this path is essential: **The screen path relies on VMware having a visible window**, and from
; Starting the VM through PowerShell Direct opens its UI on a non-visible desktop in session 0; the host-side
; The thumbnail is empty. The serial backend is a file, unrelated to sessions, windows, or focus.
; And it provides a time series rather than two snapshots — whether TICK is "stuck" or "running slow",
; Only the time series can distinguish them.
;
; Waiting for the transmit holding register to be empty must have an upper bound. Unbounded polling when the serial port is not connected will hang the program.
; It always stops here, and 'the program hangs' and 'the guest does not receive a clock' look identical on any observation surface —
; **A fixture failure must not resemble the condition being tested.** On timeout, drop the byte; one character will be missing from the log
; The missing character is obvious at a glance (mismatched line widths); a hang cannot be distinguished from the condition being tested.
serout:
    mov ah, al                 ; Temporarily store the byte to be sent; AL is about to be used to read the status.
    mov si, 40h                ; Poll upper bound; the first entry in the file backend should be empty.
    mov dx, 3FDh               ; Line status register
so_wait:
    in  al, dx
    test al, 20h               ; bit 5: Transmit hold register empty.
    jnz so_ok
    dec si
    jnz so_wait
    ret                        ; Timeout, drop bytes.
so_ok:
    mov dx, 3F8h               ; Transmit hold register
    mov al, ah
    out dx, al
    ret

labels db 'SPINTICKOWN PIT IRR ISR SIRRSISRRTC TSC '

_TEXT ENDS
END
