#pragma once
#include "pattern.hpp"
#include <nlohmann/json.hpp>
#include <functional>
namespace dumper {
using Json = nlohmann::json;
struct Result {
    Json buttons=Json::object(), interfaces=Json::object(), offsets=Json::object(), schemas=Json::object();
    Json info=Json::object();
    std::vector<std::string> errors;
};
using Log = std::function<void(const std::string&)>;
Result analyze(const Process& process, const Log& log);
std::vector<Address> hash_elements(const Memory& memory, Address hash);
Json read_class(const Memory& memory, Address binding);
Json read_enum(const Memory& memory, Address binding);
}
