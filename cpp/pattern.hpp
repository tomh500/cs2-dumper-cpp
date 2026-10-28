#pragma once
#include "memory.hpp"
#include <optional>
namespace dumper {
struct Pattern {
    std::vector<int> bytes; // -1 is a wildcard.
    std::size_t capture = 0;
    unsigned width = 0;
    bool relative = false;
    unsigned add = 0;
    static Pattern parse(const std::string& text);
    std::optional<std::uint32_t> find(const Image& image) const;
};
}
