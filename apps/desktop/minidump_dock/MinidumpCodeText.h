#pragma once

// ============================================================
// MinidumpCodeText.h
// Purpose:
// - Centralizes the 'numeric value → human-readable text' mapping tables required for dump parsing.
// - Overrides NTSTATUS exception codes, kernel BugCheck (BSOD) codes, CPU
//   architecture, memory state/protection bits, and MDMP stream type names;
// - Returns standardized Chinese text (or original English constant names); the rendering layer handles translation via language packs.
// Call method:
// - Called by MinidumpParser/KernelDumpParser when assembling the model;
// - Return an empty string or "Unknown" for any value not found; the caller decides the fallback format.
// ============================================================

#include <QString>

#include <cstdint>

namespace ks::minidump
{
    // exceptionCodeName purpose: Returns the constant name for an NTSTATUS exception code (e.g., EXCEPTION_ACCESS_VIOLATION).
    // Accepts exception code; returns the constant name, or an empty string if unknown.
    QString exceptionCodeName(std::uint32_t code);

    // exceptionCodeMeaning purpose: returns the Chinese meaning description of the exception code.
    // Input: exception code; Output: Chinese description, or empty string if unknown.
    QString exceptionCodeMeaning(std::uint32_t code);

    // accessViolationDetailText purpose: Translate the two parameters of an access violation/page fault into a
    // Chinese description of 'read/write/execute address' (parameter meanings see EXCEPTION_RECORD documentation).
    // Accepts operationType (0 for read, 1 for write, 8 for DEP execution) and faultAddress; returns a Chinese description.
    QString accessViolationDetailText(std::uint64_t operationType, std::uint64_t faultAddress);

    // fastFailCodeText: Translates __fastfail subcodes into Chinese descriptions.
    // Parameter 1 of STATUS_STACK_BUFFER_OVERRUN (0xC0000409) is this sub-code, which is the actual information
    // indicating 'which security check was triggered'; the exception code itself has little differentiation.
    // Input code: sub-code; returns an empty string if not recorded.
    QString fastFailCodeText(std::uint64_t code);

    // cppExceptionMagicText: Identifies the magic number version for MSVC C++ exceptions (0xE06D7363).
    // Input: magic parameter value 1; returns an empty string if the magic number is not recognized.
    QString cppExceptionMagicText(std::uint64_t magic);

    // isCppException: Determines if the exception code is an MSVC C++ exception ('msc' + 0xE0000000).
    bool isCppException(std::uint32_t code);

    // isManagedException: determines whether the exception code originates from the .NET runtime.
    bool isManagedException(std::uint32_t code);



    // processorArchitectureText: Converts SYSTEM_INFO architecture ID to human-readable text.
    // Takes a PROCESSOR_ARCHITECTURE_* ID as input; returns text like x86/x64/ARM64, or the numeric ID text if unknown.
    QString processorArchitectureText(std::uint16_t architecture);

    // streamTypeName purpose: Returns the official enum name corresponding to the MDMP stream type number.
    // Input: stream type number streamType; Output: enum name, or empty string if unknown.
    QString streamTypeName(std::uint32_t streamType);

    // streamTypeNote: returns a Chinese description of the content carried by the stream.
    // Accepts stream type ID streamType; returns a Chinese description, or an empty string if unknown.
    QString streamTypeNote(std::uint32_t streamType);

    // memoryStateText: Converts state flags like MEM_COMMIT to constant name strings.
    // Input state value; returns the constant name, or hexadecimal text if unknown.
    QString memoryStateText(std::uint32_t state);

    // memoryProtectText purpose: Convert PAGE_* protection bit combinations into constant name text (including modifier bits).
    // Accepts the protect value as input; returns a combined text string, or an empty string if the value is 0.
    QString memoryProtectText(std::uint32_t protect);

    // memoryTypeText purpose: Convert MEM_IMAGE/MAPPED/PRIVATE type bits to constant name strings.
    // Accepts a type value; returns the constant name, or hexadecimal text if unknown.
    QString memoryTypeText(std::uint32_t type);
}
