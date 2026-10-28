#include "pattern.hpp"
#include <cctype>
#include <limits>
namespace dumper {
Pattern Pattern::parse(const std::string& text) {
    Pattern p;
    for (std::size_t i=0; i<text.size();) {
        char c=text[i];
        if (std::isspace(static_cast<unsigned char>(c))) { ++i; continue; }
        if (c=='?') { p.bytes.push_back(-1); ++i; continue; }
        if (c=='[') {
            auto end=text.find(']',i); if(end==std::string::npos) throw std::runtime_error("Invalid pattern skip");
            unsigned n=static_cast<unsigned>(std::stoul(text.substr(i+1,end-i-1)));
            if(n>4096) throw std::runtime_error("Pattern skip too large");
            p.bytes.insert(p.bytes.end(),n,-1); i=end+1; continue;
        }
        if (c=='$') {
            if (i+1>=text.size() || text[i+1]!='{') throw std::runtime_error("Invalid relative pattern");
            auto end=text.find('}',i+2); if(end==std::string::npos) throw std::runtime_error("Invalid relative pattern");
            auto inner=text.substr(i+2,end-i-2);
            if(inner.find('\'')!=std::string::npos) {
                p.capture=p.bytes.size(); p.width=4; p.relative=true;
                if(inner.front()=='[') p.add=static_cast<unsigned>(std::stoul(inner.substr(1)));
            }
            p.bytes.insert(p.bytes.end(),4,-1); i=end+1; continue;
        }
        if(c=='u' && i+1<text.size() && (text[i+1]=='1' || text[i+1]=='4')) {
            p.capture=p.bytes.size(); p.width=static_cast<unsigned>(text[i+1]-'0'); p.relative=false;
            p.bytes.insert(p.bytes.end(),p.width,-1); i+=2; continue;
        }
        if(i+1>=text.size() || !std::isxdigit(static_cast<unsigned char>(c)) || !std::isxdigit(static_cast<unsigned char>(text[i+1])))
            throw std::runtime_error("Invalid pattern byte");
        p.bytes.push_back(std::stoi(text.substr(i,2),nullptr,16)); i+=2;
    }
    if(p.bytes.empty() || !p.width) throw std::runtime_error("Pattern has no capture");
    return p;
}
std::optional<std::uint32_t> Pattern::find(const Image& image) const {
    std::optional<std::uint32_t> result;
    for(auto [begin,size] : image.code) {
        if(begin>image.bytes.size() || size>image.bytes.size()-begin || size<bytes.size()) continue;
        for(std::size_t pos=begin; pos<=begin+size-bytes.size(); ++pos) {
            std::size_t i=0;
            for(;i<bytes.size();++i) if(bytes[i]>=0 && bytes[i]!=image.bytes[pos+i]) break;
            if(i!=bytes.size()) continue;
            std::int64_t value = width==1 ? image.at<std::uint8_t>(pos+capture) : image.at<std::uint32_t>(pos+capture);
            if(relative) value=static_cast<std::int64_t>(pos+capture+4)+image.at<std::int32_t>(pos+capture)+add;
            if(value<0 || value>UINT32_MAX) throw std::runtime_error("Pattern capture out of range");
            if(result) throw std::runtime_error("Ambiguous pattern (multiple matches)");
            result=static_cast<std::uint32_t>(value);
        }
    }
    return result;
}
}
