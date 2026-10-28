#include "output.hpp"
#include <iostream>
#include <fstream>
#include <algorithm>
#include <set>
namespace {
struct Args {
    std::string process="cs2.exe";
    std::filesystem::path output="output";
    std::vector<std::string> formats={"cs","hpp","json","rs","zig"};
    unsigned indent=4,verbose=0; bool no_log=false;
};
void help() {
    std::cout<<"cs2-dumper 0.2.0 (C++17, Windows x64)\n"
        "Usage: cs2-dumper [options]\n"
        "  -p, --process-name NAME   Process to read (default: cs2.exe)\n"
        "  -o, --output DIRECTORY    Output directory (default: output)\n"
        "  -f, --file-types LIST     Comma-separated cs,hpp,json,rs,zig\n"
        "  -i, --indent-size N       Spaces per level, 0..16 (default: 4)\n"
        "  -v, -vv, -vvv            Increase console logging\n"
        "  -n, --no-log-file         Disable cs2-dumper.log\n"
        "  -h, --help                Print help\n"
        "  -V, --version             Print version\n"
        "Exit codes: 0 complete, 1 fatal error, 2 partial analysis.\n"
        "Uses native read-only Windows memory access. Memflow connectors are unsupported.\n";
}
Args parse(int argc,char** argv) {
    Args args;
    for(int i=1;i<argc;++i) {
        std::string arg=argv[i],value;
        auto equal=arg.find('='); if(equal!=std::string::npos) {value=arg.substr(equal+1);arg.resize(equal);}
        auto next=[&] {
            if(equal!=std::string::npos) return value;
            if(i+1>=argc) throw std::runtime_error("Missing value for "+arg);
            return std::string(argv[++i]);
        };
        if(arg=="-p" || arg=="--process-name") args.process=next();
        else if(arg=="-o" || arg=="--output") args.output=std::filesystem::u8path(next());
        else if(arg=="-i" || arg=="--indent-size") {
            auto s=next();
            if(s.empty() || s.find_first_not_of("0123456789")!=std::string::npos || s.size()>2 || std::stoul(s)>16) throw std::runtime_error("Indent must be 0..16");
            args.indent=static_cast<unsigned>(std::stoul(s));
        } else if(arg=="-f" || arg=="--file-types") {
            auto list=next(); args.formats.clear(); std::set<std::string> seen;
            for(std::size_t pos=0;;) {
                auto end=list.find(',',pos); auto f=list.substr(pos,end==std::string::npos?end:end-pos);
                if(f!="cs" && f!="hpp" && f!="json" && f!="rs" && f!="zig") throw std::runtime_error("Unsupported file type: "+f);
                if(seen.insert(f).second) args.formats.push_back(f);
                if(end==std::string::npos) break; pos=end+1;
            }
        } else if(arg=="-c" || arg=="--connector" || arg=="-a" || arg=="--connector-args") throw std::runtime_error("Memflow connectors are unsupported in the native C++ build");
        else if(arg=="-n" || arg=="--no-log-file") args.no_log=true;
        else if(arg.size()>1 && arg[0]=='-' && arg.find_first_not_of('v',1)==std::string::npos) args.verbose+=static_cast<unsigned>(arg.size()-1);
        else throw std::runtime_error("Unknown argument: "+arg);
    }
    if(args.process.empty() || args.output.empty()) throw std::runtime_error("Process and output path must not be empty");
    return args;
}
}
int main(int argc,char** argv) {
    try {
        for(int i=1;i<argc;++i) {
            std::string a=argv[i];
            if(a=="--help" || a=="-h") {help();return 0;}
            if(a=="--version" || a=="-V") {std::cout<<"cs2-dumper 0.2.0 C++17\n";return 0;}
        }
        auto args=parse(argc,argv);
        std::ofstream logfile;
        if(!args.no_log) {logfile.open("cs2-dumper.log",std::ios::trunc);if(!logfile) throw std::runtime_error("Cannot create log file; use --no-log-file or a writable working directory");}
        auto log=[&](const std::string& message) {if(args.verbose>=2) std::cout<<message<<'\n'; if(logfile) logfile<<message<<'\n';};
        dumper::Process process(args.process);
        auto result=dumper::analyze(process,log);
        if(result.buttons.empty() && result.interfaces.empty() && result.offsets.empty() && result.schemas.empty()) throw std::runtime_error("All analysis stages failed; see log for outdated patterns or unreadable memory");
        dumper::write_output(result,args.output,args.formats,args.indent);
        if(!result.errors.empty()) {
            std::cerr<<"Partial analysis: "<<result.errors.size()<<" errors. See info.json in "<<args.output.u8string()<<"\n";
            for(const auto& error:result.errors) std::cerr<<"  "<<error<<'\n';
            return 2;
        }
        std::cout<<"Analysis complete: "<<args.output.u8string()<<'\n'; return 0;
    } catch(const std::exception& e) {std::cerr<<"Error: "<<e.what()<<'\n';return 1;}
}
