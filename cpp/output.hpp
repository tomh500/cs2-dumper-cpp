#pragma once
#include "analysis.hpp"
#include <filesystem>
namespace dumper {
std::string identifier(const std::string& name);
std::string render(const Json& data, const std::string& category, const std::string& format, unsigned indent, bool schema=false);
void write_output(const Result& result, const std::filesystem::path& directory, const std::vector<std::string>& formats, unsigned indent);
}
