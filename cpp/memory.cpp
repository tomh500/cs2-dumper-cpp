#include "memory.hpp"
#include <TlHelp32.h>
#include <algorithm>
#include <sstream>
#include <limits>

namespace dumper {
namespace {
std::wstring wide(const std::string& s) {
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (!n) throw std::runtime_error("Invalid UTF-8 process name");
    std::wstring out(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}
std::string narrow(const wchar_t* s) {
    int n = WideCharToMultiByte(CP_UTF8, 0, s, -1, nullptr, 0, nullptr, nullptr);
    std::string out(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, s, -1, out.data(), n, nullptr, nullptr);
    out.pop_back(); return out;
}
DWORD pid(const std::string& name) {
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (snapshot.get() == INVALID_HANDLE_VALUE) throw std::runtime_error("Cannot enumerate processes");
    PROCESSENTRY32W entry{}; entry.dwSize = sizeof entry;
    auto target = wide(name);
    if (Process32FirstW(snapshot.get(), &entry)) do {
        if (_wcsicmp(entry.szExeFile, target.c_str()) == 0) return entry.th32ProcessID;
    } while (Process32NextW(snapshot.get(), &entry));
    throw std::runtime_error("Process not found: " + name + ". Start the game first.");
}
}
std::string hex(Address value) { std::ostringstream s; s << "0x" << std::hex << std::uppercase << value; return s.str(); }
std::string Memory::string(Address address, std::size_t limit) const {
    if (!address) return {};
    std::string out;
    for (std::size_t i=0; i<limit; ++i) {
        char c = read<char>(address+i); if (!c) return out; out += c;
    }
    throw std::runtime_error("Unterminated string at " + hex(address));
}
Address Memory::rip(Address instruction, unsigned displacement) const {
    return instruction + displacement + 4 + static_cast<std::int64_t>(read<std::int32_t>(instruction+displacement));
}
Process::Process(const std::string& name) : process_(OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid(name))) {
    if (!process_.get()) throw std::runtime_error("Cannot open process; Windows error " + std::to_string(GetLastError()));
    BOOL wow = FALSE;
    if (!IsWow64Process(process_.get(), &wow) || wow) throw std::runtime_error("Target must be a 64-bit process");
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(process_.get())));
    if (snapshot.get() == INVALID_HANDLE_VALUE) throw std::runtime_error("Cannot enumerate modules");
    MODULEENTRY32W entry{}; entry.dwSize = sizeof entry;
    if (Module32FirstW(snapshot.get(), &entry)) do {
        modules.push_back({narrow(entry.szModule), reinterpret_cast<Address>(entry.modBaseAddr), entry.modBaseSize});
    } while (Module32NextW(snapshot.get(), &entry));
}
void Process::read_bytes(Address address, void* buffer, std::size_t size) const {
    SIZE_T done = 0;
    if (!ReadProcessMemory(process_.get(), reinterpret_cast<LPCVOID>(address), buffer, size, &done) || done != size)
        throw std::runtime_error("Cannot read " + hex(address) + "; Windows error " + std::to_string(GetLastError()));
}
const Module& Process::module(const std::string& name) const {
    for (const auto& m : modules) if (_stricmp(name.c_str(), m.name.c_str()) == 0) return m;
    throw std::runtime_error("Module not found: " + name);
}
Image Process::image(const Module& m) const {
    if (!m.size || m.size > 1024u*1024u*1024u) throw std::runtime_error("Invalid image size");
    Image img{m, std::vector<std::uint8_t>(m.size), {}};
    // Read committed readable regions only; PE images can contain inaccessible gaps.
    Address cursor = m.base, end = m.base+m.size;
    while (cursor < end) {
        MEMORY_BASIC_INFORMATION region{};
        if (!VirtualQueryEx(process_.get(), reinterpret_cast<LPCVOID>(cursor), &region, sizeof region))
            throw std::runtime_error("Cannot query module memory");
        Address next = std::min(end, reinterpret_cast<Address>(region.BaseAddress)+region.RegionSize);
        if (next <= cursor) throw std::runtime_error("Invalid memory region");
        if (region.State == MEM_COMMIT && !(region.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
            read_bytes(cursor, img.bytes.data()+(cursor-m.base), static_cast<std::size_t>(next-cursor));
        cursor = next;
    }
    auto dos = img.at<IMAGE_DOS_HEADER>(0);
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0) throw std::runtime_error("Invalid DOS header");
    auto nt = img.at<IMAGE_NT_HEADERS64>(dos.e_lfanew);
    if (nt.Signature != IMAGE_NT_SIGNATURE || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        throw std::runtime_error("Invalid PE64 header");
    auto table = static_cast<std::size_t>(dos.e_lfanew)+4+sizeof(IMAGE_FILE_HEADER)+nt.FileHeader.SizeOfOptionalHeader;
    for (unsigned i=0; i<nt.FileHeader.NumberOfSections; ++i) {
        auto section = img.at<IMAGE_SECTION_HEADER>(table+i*sizeof(IMAGE_SECTION_HEADER));
        if (!(section.Characteristics & IMAGE_SCN_CNT_CODE)) continue;
        auto begin = static_cast<std::size_t>(section.VirtualAddress);
        if (begin >= img.bytes.size()) continue;
        img.code.emplace_back(begin, std::min(img.bytes.size()-begin, static_cast<std::size_t>(section.Misc.VirtualSize)));
    }
    return img;
}
std::uint32_t Image::exported(const std::string& name) const {
    auto dos = at<IMAGE_DOS_HEADER>(0);
    auto nt = at<IMAGE_NT_HEADERS64>(dos.e_lfanew);
    auto dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress) throw std::runtime_error("No exports");
    auto exports = at<IMAGE_EXPORT_DIRECTORY>(dir.VirtualAddress);
    if (exports.NumberOfNames > bytes.size()/4) throw std::runtime_error("Invalid exports");
    for (std::size_t i=0; i<exports.NumberOfNames; ++i) {
        auto str = at<std::uint32_t>(exports.AddressOfNames+i*4);
        if (str >= bytes.size() || name.size() >= bytes.size()-str) continue;
        if (std::memcmp(bytes.data()+str, name.c_str(), name.size()+1)) continue;
        auto ordinal = at<std::uint16_t>(exports.AddressOfNameOrdinals+i*2);
        if (ordinal >= exports.NumberOfFunctions) throw std::runtime_error("Invalid export ordinal");
        auto target = at<std::uint32_t>(exports.AddressOfFunctions+ordinal*4);
        if (target >= dir.VirtualAddress && target-dir.VirtualAddress < dir.Size) throw std::runtime_error("Forwarded export");
        return target;
    }
    throw std::runtime_error("Export not found: " + name);
}
}
