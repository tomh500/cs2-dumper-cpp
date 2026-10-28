#include "output.hpp"
#include <iostream>
#include <cstring>
#include <functional>
#include <fstream>
using namespace dumper;
namespace {
void check(bool condition,const char* message) {if(!condition) throw std::runtime_error(message);}
void fails(const std::function<void()>& f) {bool threw=false;try{f();}catch(const std::exception&){threw=true;}check(threw,"Expected an exception");}
struct Mock final:Memory {
    std::vector<std::uint8_t> bytes=std::vector<std::uint8_t>(0x10000);
    void read_bytes(Address a,void* out,std::size_t n) const override {
        if(a>bytes.size() || n>bytes.size()-static_cast<std::size_t>(a)) throw std::runtime_error("Unmapped memory");
        std::memcpy(out,bytes.data()+a,n);
    }
    template<class T> void put(Address a,T value) {std::memcpy(bytes.data()+a,&value,sizeof value);}
    void text(Address a,const char* value) {std::memcpy(bytes.data()+a,value,std::strlen(value)+1);}
};
}
int main() {
    try {
        Process self("dumper_tests.exe");
        const std::uint64_t sentinel=0x123456789ABCDEF0;
        check(self.read<std::uint64_t>(reinterpret_cast<Address>(&sentinel))==sentinel,"Native ReadProcessMemory");
        auto native_image=self.image(self.module("dumper_tests.exe"));
        check(native_image.at<std::uint16_t>(0)==IMAGE_DOS_SIGNATURE && !native_image.code.empty(),"Native PE code sections");
        Image img{{"test.dll",0x100000,64},std::vector<std::uint8_t>(64,0xcc),{{0,64}}};
        img.bytes[16]=0x48; img.bytes[17]=0x8b;img.bytes[18]=0x05;
        std::int32_t disp=-15;std::memcpy(img.bytes.data()+19,&disp,4);img.bytes[23]=0xc3;
        auto p=Pattern::parse("488b05${'} c3");
        check(p.find(img)==8u,"Signed RIP displacement");
        check(Pattern::parse("488b05${[8]'} c3").find(img)==16u,"Nested capture skip");
        check(!Pattern::parse("4c8b05${'} c3").find(img),"Missing pattern");
        img.bytes[30]=0xaa; img.bytes[31]=0xff;
        check(Pattern::parse("aau1").find(img)==255u,"u1 capture");
        img.bytes[32]=0xaa;img.bytes[33]=0xfe;
        fails([&]{Pattern::parse("aau1").find(img);});
        fails([]{Pattern::parse("48zz");});
        img.code={{16,6}};check(!p.find(img),"Pattern cannot cross code-section boundary");
        Mock mem;mem.put<std::int32_t>(0x103,-11);check(mem.rip(0x100)==0xfc,"Remote RIP");
        mem.text(0x200,"hello");check(mem.string(0x200)=="hello","String read");
        fails([&]{mem.string(0x200,3);});
        mem.put<Address>(0x1008,0x2000);mem.text(0x2000,"TestClass");
        mem.put<std::int16_t>(0x1024,1);mem.put<Address>(0x1030,0x3000);
        mem.put<Address>(0x3000,0x2100);mem.text(0x2100,"m_value");
        mem.put<Address>(0x3008,0x3100);mem.put<Address>(0x3108,0x2200);mem.text(0x2200,"unsigned int");
        mem.put<std::int32_t>(0x3010,0x28);
        auto cls=read_class(mem,0x1000);check(cls["fields"]["m_value"]==0x28,"Schema field offset");
        check(cls["parent"].is_null(),"Null parent");
        mem.put<std::int16_t>(0x1024,-1);fails([&]{read_class(mem,0x1000);});
        mem.put<std::int32_t>(0x400c,2);mem.put<std::int32_t>(0x4010,1);
        mem.put<Address>(0x4070,0x6000);mem.put<Address>(0x6010,0x1000);
        mem.put<Address>(0x6008,0x6030);mem.put<Address>(0x6040,0x1100);
        mem.put<Address>(0x4020,0x6060);mem.put<Address>(0x6070,0x1000);
        auto elements=hash_elements(mem,0x4000);check(elements.size()==2,"Schema hash deduplicates allocated/free entries");
        mem.put<std::int32_t>(0x400c,3);mem.put<Address>(0x6038,0x6000);
        fails([&]{hash_elements(mem,0x4000);});
        Json fields={{"dwExample",0x1234},{"use",5}};
        Json data={{"client.dll",fields}};
        check(Json::parse(render(data,"offsets","json",2))==data,"JSON preserves structure and values");
        for(const auto& format:{"hpp","cs","rs","zig"}) {
            auto text=render(data,"offsets",format,4);
            check(text.find("dwExample")!=std::string::npos && text.find("0x1234")!=std::string::npos,"Code export");
            check(text.find("id_use")!=std::string::npos,"Keyword escaping");
        }
        Json schema={{"client.dll",{{"classes",{{"TestClass",{{"parent",nullptr},{"fields",fields},{"metadata",Json::array()}}}}},
            {"enums",{{"TestEnum",{{"alignment",1},{"type","uint8"},{"members",{{"One",1},{"Alias",1},{"Max",-1}}}}}}}}}};
        for(const auto& format:{"hpp","cs","rs","zig"}) {
            auto code=render(schema,"schemas",format,4,true);
            check(code.find("0xFF")!=std::string::npos,"Negative enum values wrap to underlying width");
            if(std::string(format)=="rs" || std::string(format)=="zig") check(code.find("One =")==std::string::npos,"Duplicate enum values removed deterministically");
        }
        fails([&]{render(Json{{"client.dll",{{"a-b",1},{"a_b",2}}}},"offsets","hpp",4);});
        check(identifier("123abc")=="id_123abc","Leading digit identifier");
        Result exported;
        exported.offsets=data;
        exported.errors.push_back("Synthetic partial analysis");
        write_output(exported,"test_export",{"json","hpp"},2);
        std::ifstream info_file("test_export/info.json");Json info;info_file>>info;
        check(info["status"]=="partial" && info["errors"].size()==1 && info.contains("timestamp"),"Partial output status");
        std::ifstream offsets_file("test_export/offsets.json");Json offsets;offsets_file>>offsets;
        check(offsets==data,"Exported file data");
        // Optional regression over checked-in upstream JSON, no running game needed.
        char path[32768]{};
        if(GetEnvironmentVariableA("DUMPER_FIXTURES",path,sizeof path)) {
            std::size_t count=0;
            for(const auto& file:std::filesystem::directory_iterator(path)) {
                if(file.path().extension()!=".json" || file.path().stem()=="info") continue;
                std::ifstream input(file.path());Json value;input>>value;
                auto name=file.path().stem().string();bool is_schema=name!="buttons" && name!="interfaces" && name!="offsets";
                for(const auto& format:{"json","hpp","cs","rs","zig"}) {
                    auto generated=render(value,is_schema?"schemas":name,format,4,is_schema);
                    if(std::string(format)=="json") check(Json::parse(generated)==value,"Upstream JSON round trip");
                    if(std::string(format)=="hpp") {
                        std::filesystem::create_directories("fixture_headers");
                        std::ofstream("fixture_headers/"+name+".hpp")<<generated;
                    }
                }
                ++count;
            }
            check(count>=3,"No upstream fixtures found");std::cout<<"Validated "<<count<<" upstream JSON files across five formats\n";
        }
        std::cout<<"All core tests passed\n";return 0;
    } catch(const std::exception& e) {std::cerr<<e.what()<<'\n';return 1;}
}
