---
layout: news_item
title: 'Frida 5.0 发布'
date: 2015-09-17 19:00:00 +0100
author: oleavr
version: 5.0
categories: [release]
---

哇，又一个主要版本！我们决定更改 Device API 以为您提供持久 ID，以便您可以轻松区分热插拔时的不同设备。

但这仅仅是开始，这次我们还带来了大量其他改进：

5.0.0:

- core: 更改 Device.id 以表示跨重新连接的单个设备
- core: 添加新的 Droidy 后端用于与连接的 Android 设备接口
- core: 调整 Darwin 上令人困惑的 iPhone 5+ 设备名称
- core: 规范化回退 iOS 设备名称以与 Android 保持一致
- core: 将 V8 升级到 4.5.103.30
- objc: 在 *$methods* 和 *$ownMethods* 中包含类和实例方法
- python: 添加 -D 开关用于指定要连接的设备 ID
- python: 添加 frida-ls-devices CLI 工具用于列出设备
- python: 更新到新的 Device.id API
- python: 添加 *get_local_device()* 并提高与 frida-node 的 API 一致性
- node: 更新到新的 Device.id API
- node: 改进顶级外观 API
- qml: 更新到新的 Device.id API
- clr: 更新到新的 Device.id API
- frida-ps: 改进输出格式

5.0.1:

- core: 添加对源映射的支持
- node: 添加 frida.load() 用于将 CommonJS 模块转换为脚本
- node: 升级 Nan

5.0.2:

- core: 添加 *console.warn()* 和 *console.error()*
- core: 添加 *Module.enumerateImports()* 并在 Darwin、Linux 和 Windows 上实现
- core: 调用 *Module.findExportByName()* 时允许 *null* 模块名称
- core: 将 *Darwin.Module* 和 *Darwin.Mapper* 从 frida-core 移动到 frida-gum，允许轻松的 Mach-O 解析和进程外动态链接
- core: 更好地处理临时文件
- frida-trace: 添加对方便跟踪导入函数的支持
- frida-trace: 将 dyld_stub_binder 列入黑名单以防止被跟踪
- python: 避免日志被状态消息更改覆盖

5.0.3:

- core: 改进 arm64 hook，包括对 hook 短函数的支持

5.0.4:

- core: 改进 arm64 hook，还要注意避免重定位其他指令依赖的指令，包括 BL/BLR/SVC 指令之后的下一条指令
- core: 将 *Arm64Writer* 和 *Arm64Relocator* 移植到 Capstone

5.0.5:

- core: 通过使用我们的 GLib 补丁提供的新 API 修复拆卸时的崩溃
- core: 修复 Linux 上的模块名称解析
- core: 改进 ELF 处理以也将 *ET_EXEC* 映像视为有效模块
- core: 改进 arm64 hook
- core: 将 *{Arm,Thumb}Writer* 和 *{Arm,Thumb}Relocator* 移植到 Capstone
- python: 修复 OS X 10.11 上的测试
- node: 修复 OS X 10.11 上的测试

5.0.6:

- core: 尽可能将 NativeFunction 调用崩溃转换为 JS 异常
- core: 添加 *Process.setExceptionHandler()* 用于处理来自 JS 的本机异常
- core: 安装一个发出错误消息的默认异常处理程序
- core: 如果我们在进程生命周期的早期安装我们的异常处理程序，则防止应用程序覆盖我们的异常处理程序
- core: 如果我们无法替换本机函数，则优雅地处理它
- core: 允许 RPC 导出返回 ArrayBuffer 值
- python: 添加对返回 ArrayBuffer 对象的 rpc 方法的支持
- node: 添加对返回 ArrayBuffer 对象的 rpc 方法的支持

5.0.7:

- core: 暂时不安装默认异常处理程序

5.0.8:

- 由于构建机器问题，重新发布 5.0.7。

5.0.9:

- python: 更新 setup.py 以匹配新的构建服务器配置

5.0.10:

- core: 修复早期使用 IP 寄存器的 arm64 函数的检测

享受吧！
