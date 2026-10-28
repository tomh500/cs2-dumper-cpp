#include "analysis.hpp"
#include <unordered_set>
#include <algorithm>
#include <map>
namespace dumper {
namespace {
constexpr std::size_t max_nodes=100000;
Address find(const Image& img, const char* pattern) {
    auto r=Pattern::parse(pattern).find(img);
    if(!r) throw std::runtime_error("Outdated pattern in " + img.module.name + ": " + pattern);
    return img.module.base+*r;
}
std::string type_name(const Memory& m, Address p) {
    auto s=m.string(m.read<Address>(p+8));
    s.erase(std::remove(s.begin(),s.end(),' '),s.end()); return s;
}
template<class F> void chain(Address node, F visit) {
    std::unordered_set<Address> seen;
    while(node) {
        if(seen.size()>=max_nodes || !seen.insert(node).second) throw std::runtime_error("Invalid/cyclic remote list");
        node=visit(node);
    }
}
struct Signature { const char* module; const char* name; const char* pattern; };
#include "signatures.inc"
}
std::vector<Address> hash_elements(const Memory& m, Address hash) {
    std::unordered_set<Address> unique;
    auto allocated=m.read<std::int32_t>(hash+0xc), peak=m.read<std::int32_t>(hash+0x10);
    if(allocated<0 || peak<0 || allocated>max_nodes || peak>max_nodes) throw std::runtime_error("Invalid schema hash count");
    std::size_t count=0;
    for(unsigned i=0;i<256 && count<static_cast<std::size_t>(allocated);++i) {
        auto node=m.read<Address>(hash+0x60+i*0x18+0x10);
        chain(node,[&](Address p) {
            auto data=m.read<Address>(p+0x10);
            if(data) {unique.insert(data);++count;}
            return count>=static_cast<std::size_t>(allocated) ? Address(0) : m.read<Address>(p+8);
        });
    }
    count=0;
    if(peak) chain(m.read<Address>(hash+0x20),[&](Address p) {
        auto data=m.read<Address>(p+0x10);
        if(data) {unique.insert(data);++count;}
        return count>=static_cast<std::size_t>(peak) ? Address(0) : m.read<Address>(p);
    });
    std::vector<Address> out(unique.begin(),unique.end()); std::sort(out.begin(),out.end()); return out;
}
Json read_class(const Memory& m, Address b) {
    Json result={{"name",m.string(m.read<Address>(b+8))},{"parent",nullptr},{"fields",Json::object()},{"metadata",Json::array()}};
    if(result["name"].get<std::string>().empty()) throw std::runtime_error("Empty class name");
    auto count=m.read<std::int16_t>(b+0x24), metadata_count=m.read<std::int16_t>(b+0x26);
    if(count<0 || metadata_count<0) throw std::runtime_error("Invalid class counts");
    auto parent=m.read<Address>(b+0x40);
    if(parent) result["parent"]=m.string(m.read<Address>(m.read<Address>(parent+0x18)+0x10));
    auto fields=m.read<Address>(b+0x30);
    if(count && !fields) throw std::runtime_error("Null class fields");
    for(int i=0;i<count;++i) {
        auto f=fields+i*0x20;
        if(!m.read<Address>(f+8)) continue;
        auto name=m.string(m.read<Address>(f));
        // Read type too, so stale field layouts fail rather than emit plausible offsets.
        type_name(m,m.read<Address>(f+8));
        result["fields"][name]=m.read<std::int32_t>(f+0x10);
    }
    auto metadata=m.read<Address>(b+0x48);
    if(metadata_count && !metadata) throw std::runtime_error("Null metadata");
    for(int i=0;i<metadata_count;++i) {
        auto p=metadata+i*0x10, value=m.read<Address>(p+8);
        if(!value) continue;
        auto name=m.string(m.read<Address>(p));
        Json item={{"type","Unknown"},{"name",name}};
        if(name=="MNetworkChangeCallback") item={{"type","NetworkChangeCallback"},{"name",m.string(m.read<Address>(value))}};
        else if(name=="MNetworkVarNames") {
            auto type=m.string(m.read<Address>(value+8)); type.erase(std::remove(type.begin(),type.end(),' '),type.end());
            item={{"type","NetworkVarNames"},{"name",m.string(m.read<Address>(value))},{"type_name",type}};
        }
        result["metadata"].push_back(item);
    }
    return result;
}
Json read_enum(const Memory& m, Address b) {
    auto alignment=m.read<std::uint8_t>(b+0x19);
    auto count=m.read<std::uint16_t>(b+0x1c);
    Json result={{"name",m.string(m.read<Address>(b+8))},{"alignment",alignment},
        {"type","uint"+std::to_string(alignment*8)},{"members",Json::object()}};
    if(result["name"].get<std::string>().empty()) throw std::runtime_error("Empty enum name");
    auto members=m.read<Address>(b+0x20);
    if(count && !members) throw std::runtime_error("Null enum members");
    for(unsigned i=0;i<count;++i) {
        auto p=members+i*0x20;
        result["members"][m.string(m.read<Address>(p))]=m.read<std::int64_t>(p+8);
    }
    return result;
}
Result analyze(const Process& p, const Log& log) {
    Result out;
    auto attempt=[&](const std::string& label, auto action) {
        try { action(); log("Completed " + label); }
        catch(const std::exception& e) { auto msg=label+": "+e.what(); out.errors.push_back(msg); log(msg); }
    };
    attempt("buttons",[&] {
        auto img=p.image(p.module("client.dll"));
        Json buttons=Json::object();
        chain(p.read<Address>(find(img,"488b15${'} 4885d2 74? 488b02 4885c0")),[&](Address b) {
            auto name=p.string(p.read<Address>(b+8),32);
            if(b+0x30>=img.module.base) buttons[name]=b+0x30-img.module.base;
            return p.read<Address>(b+0x88);
        });
        if(buttons.empty()) throw std::runtime_error("No buttons found");
        out.buttons["client.dll"]=buttons;
    });
    for(const auto& mod:p.modules) {
        // A module without CreateInterface is normal.
        Image img; std::uint32_t exported=0;
        try { img=p.image(mod); exported=img.exported("CreateInterface"); } catch(const std::exception&) {continue;}
        attempt("interfaces/"+mod.name,[&] {
            Json interfaces=Json::object();
            chain(p.read<Address>(p.rip(mod.base+exported)),[&](Address reg) {
                auto instance=p.rip(p.read<Address>(reg));
                if(instance>=mod.base) interfaces[p.string(p.read<Address>(reg+8),128)]=instance-mod.base;
                return p.read<Address>(reg+0x10);
            });
            if(!interfaces.empty()) out.interfaces[mod.name]=interfaces;
        });
    }
    std::map<std::string,Image> images;
    for(const auto& sig:signatures) attempt(std::string("offset/")+sig.name,[&] {
        auto it=images.find(sig.module);
        if(it==images.end()) it=images.emplace(sig.module,p.image(p.module(sig.module))).first;
        const auto& img=it->second;
        auto value=find(img,sig.pattern)-img.module.base;
        out.offsets[sig.module][sig.name]=value;
        std::string name=sig.name;
        if(name=="dwCSGOInput") out.offsets[sig.module]["dwViewAngles"]=value+find(img,"f2420f108428u4")-img.module.base;
        if(name=="dwPrediction") out.offsets[sig.module]["dwLocalPlayerPawn"]=value+find(img,"4c39b6u4 74? 4488be")-img.module.base;
        if(name=="dwSensitivity") out.offsets[sig.module]["dwSensitivity_sensitivity"]=0x58;
    });
    attempt("schemas",[&] {
        auto img=p.image(p.module("schemasystem.dll"));
        auto system=find(img,"4c8d35${'} 0f2845");
        if(!p.read<std::int32_t>(system+0x280)) throw std::runtime_error("No schema registrations");
        auto count=p.read<std::int32_t>(system+0x190);
        if(count<=0 || count>4096) throw std::runtime_error("Invalid scope count");
        auto scopes=p.read<Address>(system+0x198);
        for(int i=0;i<count;++i) {
            auto scope=p.read<Address>(scopes+i*8); auto module=p.string(scope+8);
            Json classes=Json::object(), enums=Json::object();
            for(auto binding:hash_elements(p,scope+0x560)) attempt("class/"+hex(binding),[&] {
                auto c=read_class(p,binding); auto name=c["name"].get<std::string>(); c.erase("name"); classes[name]=c;
            });
            for(auto binding:hash_elements(p,scope+0x1dd0)) attempt("enum/"+hex(binding),[&] {
                auto e=read_enum(p,binding); auto name=e["name"].get<std::string>(); e.erase("name"); enums[name]=e;
            });
            if(!classes.empty() || !enums.empty()) out.schemas[module]={{"classes",classes},{"enums",enums}};
        }
        if(out.schemas.empty()) throw std::runtime_error("No schema bindings found");
    });
    attempt("build number",[&] {
        auto rva=out.offsets.at("engine2.dll").at("dwBuildNumber").get<Address>();
        out.info["build_number"]=p.read<std::uint32_t>(p.module("engine2.dll").base+rva);
    });
    if(out.interfaces.empty()) out.errors.push_back("No interfaces found");
    return out;
}
}
