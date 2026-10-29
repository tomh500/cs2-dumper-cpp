# cs2-dumper — C++17 / MSVC

Windows x64 原生 C++17 版本，使用本机 MSVC 构建，无需安装 Rust、Cargo 或 memflow。

本项目是原项目 [a2x/cs2-dumper](https://github.com/a2x/cs2-dumper) 的 Windows C++17 移植版，基于 fork [tomh500/cs2-dumper-cpp](https://github.com/tomh500/cs2-dumper-cpp) 开发，保留原作者 a2x 的 MIT 许可证及版权声明。程序源码在 `cpp/`，旧 Rust 实现可从 Git 历史查看。

## 构建

需要 Visual Studio 的“使用 C++ 的桌面开发”组件（MSVC x64、Windows SDK）和 CMake 3.20 或更新版本。在仓库目录执行：

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

脚本构建 Release、运行测试，将可执行文件复制到 `bin/cs2-dumper.exe`。也可手动执行：

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
```

手动构建产物为 `build/Release/cs2-dumper.exe`。也可在 Visual Studio 中打开项目文件夹或生成的解决方案。Release 使用静态 MSVC 运行库。JSON 库 nlohmann/json 3.11.3 已随源码附带，构建过程不下载依赖。

## 使用

启动 CS2，进入主菜单后执行：

```powershell
.\bin\cs2-dumper.exe -vv -o .\dump
```

使用 OpenProcess / ReadProcessMemory，只申请读取和查询权限，不写入游戏内存。如果 Windows 拒绝读取，请检查程序与目标进程权限。

```text
-p, --process-name NAME   目标进程，默认 cs2.exe
-o, --output DIRECTORY    输出目录，默认 output
-f, --file-types LIST     逗号分隔的 cs,hpp,json,rs,zig，默认全部
-i, --indent-size N       缩进空格数，0..16，默认 4
-v, -vv, -vvv             控制台日志详细程度（-vv 显示分析进度）
-n, --no-log-file         不创建 cs2-dumper.log
-h, --help                帮助
-V, --version             版本
```

导出按钮、CreateInterface 接口、29 条基础偏移及 3 条派生偏移、Schema 类字段/父类/元数据和枚举，以及 info.json 中的构建号和时间。偏移以模块基址为参照。代码输出保留 cs2_dumper / CS2Dumper 分组结构，JSON 保留原有数据结构。

退出码：0 表示完整分析；1 表示致命错误；2 表示部分分析失败。部分结果仍会导出，info.json 的 status 为 partial，errors 列出失败项。请使用新的输出目录，避免混入以往的 Schema 文件。运行输出、日志及构建产物已加入 `.gitignore`。

## 与 Rust 版本的差异

- 仅支持 Windows x64 原生读取；不提供 Linux、DMA 或 memflow 外部连接器。-c / -a 会明确报错。
- 签名和 Source 2 数据结构沿用本次克隆的上游版本。游戏更新后可能需要更新 cpp/signatures.inc 或 Schema 布局；编译成功不代表适用于所有游戏版本。
- 代码中的非法标识符转换为下划线，语言关键字加 id_ 前缀（例如 use → id_use）。名称冲突会报错，JSON 保留字段名。
- Rust/Zig 枚举去除重复值，负值按枚举宽度转换。注释和大小写格式与原版可能不同。字段类型用于验证读取，但不在代码注释中输出；完整类元数据保留在 JSON。
- 增加链表循环检测、边界检查和部分失败状态，避免静默返回空结果。

## 验证

ctest 不依赖游戏：覆盖 RIP 位移、通配符和捕获、无匹配/多匹配、Schema 字段读取、哈希表去重和循环检测、五种格式输出、关键字及名称冲突。还读取 `tests/fixtures/` 历史 JSON 作为回归输入，验证五种格式可生成且 JSON 数据不变。这些数据仅供测试，不代表当前游戏版本。

2026-10-28 已在本机运行中的 CS2 build 14192 验证：五种格式全部生成，32 个偏移、137 个接口、16 个按钮、3300 个类、569 个枚举、17073 个字段，分析状态 complete、错误数 0。游戏后续更新仍需重新验证。单元测试不注入、不启动游戏。

Schema 池按 `peak_allocated - blocks_allocated` 限定空闲链表读取数量，避免读取回收区域。父类解析同时检查 has_base_class 和内部指针。接口支持 Source 2 及 Steam 旧式注册表入口；不暴露标准注册表的自定义工厂（例如 crashhandler64.dll）会记录跳过，不会把任意指令当作 RIP 位移解析。

## 许可

原项目：[a2x/cs2-dumper](https://github.com/a2x/cs2-dumper)，原作者 a2x，许可证：[MIT](LICENSE)。本仓库为其 fork 的 C++17 移植版。

随附依赖：[nlohmann/json 3.11.3](https://github.com/nlohmann/json/tree/v3.11.3)，许可证见 third_party/nlohmann/LICENSE.MIT。
