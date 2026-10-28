#pragma once
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <stdexcept>
#include <type_traits>

namespace dumper {
using Address = std::uint64_t;
class Memory {
public:
    virtual ~Memory() = default;
    virtual void read_bytes(Address address, void* buffer, std::size_t size) const = 0;
    template<class T> T read(Address address) const {
        static_assert(std::is_trivially_copyable_v<T>);
        T value{}; read_bytes(address, &value, sizeof value); return value;
    }
    std::string string(Address address, std::size_t limit = 256) const;
    Address rip(Address instruction, unsigned displacement = 3) const;
};
class Handle {
    HANDLE value_ = nullptr;
public:
    explicit Handle(HANDLE value = nullptr) : value_(value) {}
    ~Handle() { if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE get() const { return value_; }
};
struct Module { std::string name; Address base; std::uint32_t size; };
struct Image {
    Module module;
    std::vector<std::uint8_t> bytes;
    std::vector<std::pair<std::size_t, std::size_t>> code;
    template<class T> T at(std::size_t rva) const {
        if (rva > bytes.size() || sizeof(T) > bytes.size() - rva)
            throw std::runtime_error("PE read outside image");
        T value{}; std::memcpy(&value, bytes.data()+rva, sizeof value); return value;
    }
    std::uint32_t exported(const std::string& name) const;
};
class Process final : public Memory {
    Handle process_;
public:
    std::vector<Module> modules;
    explicit Process(const std::string& name);
    void read_bytes(Address address, void* buffer, std::size_t size) const override;
    const Module& module(const std::string& name) const;
    Image image(const Module& module) const;
};
std::string hex(Address value);
}
