---
layout: news_item
title: 'Frida 4.2 发布'
date: 2015-06-18 19:00:00 +0100
author: oleavr
version: 4.2
categories: [release]
---

Frida 的同谋者们最近一直在几条战线上努力工作，以至于我觉得值得记下来把消息传出去。

在 Dalvik 领域，[@marc1006](https://github.com/marc1006) 贡献了一个非常整洁的新功能 —— 对象雕刻的能力，本质上是扫描堆中特定类型的对象。看看这个：

{% highlight js %}
const strings = [];
Dalvik.choose('java.lang.String', {
  onMatch(str) {
    strings.push(str);
  },
  onComplete() {
    console.log('Found ' + strings.length + ' strings!');
  }
});
{% endhighlight %}

与此同时，[@Tyilo](https://github.com/Tyilo) 一直在为 Objective-C 添加相同的功能：

{% highlight js %}
const strings = [];
ObjC.choose(ObjC.classes.NSString, {
  onMatch(str) {
    strings.push(str);
  },
  onComplete() {
    console.log('Found ' + strings.length + ' strings!');
  }
});
{% endhighlight %}

在其他移动新闻中，[@pancake](https://github.com/trufae) 添加了对枚举 Firefox OS 上的应用程序的支持。太棒了！

在所有这些进行的同时，[@s1341](https://github.com/s1341) 一直在努力稳定 QNX 端口，据报道它现在运行得非常好。

在我这边，我一直在 [NowSecure](https://www.nowsecure.com/) 将 Frida 应用于有趣的挑战，并在 Objective-C 集成中遇到了一些错误和限制。现在支持覆盖处理按值传递的结构类型的方法，例如 `-[UIView drawRect:]`，这意味着 `NativeFunction` 和 `NativeCallback` 也支持这些；因此，要声明结构，只需启动一个数组，其中按顺序指定字段的类型。您甚至可以嵌套它们。因此，对于按值传递结构且该结构由另外两个结构组成的 `- drawRect:` 案例，您可以像这样声明它：
- core: 添加 *NativePointer.toMatchPattern()* 以与 *Memory.scan()* 一起使用
- core: 修复 QNX 注入器竞争条件
- objc: 大幅改进类型的处理
- objc: 修复从 JS 字符串到 NSString 的隐式转换
- objc: 修复注册第二个代理或未命名类时的崩溃
- objc: 新的 *ObjC.Object* 属性: *$className* 和 *$super*
- dalvik: 添加 *Dalvik.choose()* 用于对象雕刻

4.1.9:

- core: *NativeFunction* 和 *NativeCallback* 现在支持按值传递结构类型的函数
- core: 修复 *Process.getModuleByName()* 中的意外大小写敏感性
- dalvik: 新的对象属性: *$className*

4.2.0:

- core: 向 *Interceptor* 的 *onEnter* 和 *onLeave* 回调添加 *this.returnAddress*
- objc: 添加 *ObjC.choose()* 用于对象雕刻

4.2.1:

- core: 修复 QNX 上剥离库的导出枚举
- objc: 新的 *ObjC.Object* 属性: *$kind*，一个字符串，是 *instance*、*class* 或 *meta-class*
- objc: 修复 *$class* 属性，使其对类也做正确的事情
- objc: 修复查找不存在的方法时的崩溃
- python: 确保反应器线程的优雅拆卸
- frida-discover: 修复回归
- frida-repl: 修复目标在评估表达式期间崩溃时的挂起

4.2.2:

- core: 修复异常处理的怪异现象；在 ios-arm 上非常明显
- core: QNX 稳定性改进
- objc: 添加 *ObjC.api* 以直接访问 Objective-C 运行时的 API
- objc: 新的 *ObjC.Object* 属性: *equals*、*$superClass* 和 *$methods*
- objc: 修复 iOS 7 兼容性
- objc: 修复 *ObjC.classes* 和 *ObjC.protocols* 的 *toJSON()*
- dalvik: 修复 *java.lang.CharSequence* 的处理
- frida-repl: 添加 *%time* 命令以便于分析

4.2.3:

- core: 修复处理没有消息对象的异常时的崩溃
- core: 修复 CpuContext JS 包装器的生命周期
- core: 向 *Process.enumerateRanges()* 公开文件映射信息
- core: 使枚举时合并相邻范围成为可能
- core: 添加用于查找模块和范围的便捷 API
- core: 使 QNX mprotect 在循环中读取而不是只读取一次
- dalvik: 如果类型转换失败，避免使进程崩溃
- dalvik: 允许 *null* 作为调用参数
- objc: 修复具有简单字段类型的结构的转换
- objc: 通过缓存包装对象加速隐式字符串转换

4.2.4:

- objc: 修复与尚未实现的类交互时的崩溃

4.2.5:

- core: 优化 Interceptor 回调逻辑，当未同时指定 *onEnter* 和 *onLeave* 时使其快两倍
- core: 修复 arm64 上调用上下文看到的返回地址
- core: 为 arm64 添加模糊回溯器

4.2.6:

- core: 修复 arm64 上对参数 4 到 7 的访问
- core: 添加 *Memory.readFloat()*、*Memory.writeFloat()*、*Memory.readDouble()* 和 *Memory.writeDouble()*
- dalvik: 改进类型检查
- qnx: 实现侧堆栈，用于使用消耗堆栈的 V8 引擎调用 *onEnter()*/*onLeave()*

4.2.7:

- core: Darwin 后端错误修复
- core: 优化 *send()* 数据有效载荷的处理
- core: 添加通过 *task_for_pid(0)* 与 iOS 内核交互的 API，仅在 *attach(pid=0)* 会话中可用
- core: QNX 上替换函数的侧堆栈支持
- objc: 向 ObjC.classes 添加 *getOwnPropertyNames()*
- frida-repl: 改进完成

4.2.8:

- python: 修复 Py3k 回归

4.2.9:

- objc: 向 *ObjC.Object* 添加 *$ownMethods*
- dalvik: 添加对原始数组和对象数组的支持
- python: 改进 Python 2 和 3 之间的兼容性
- frida-repl: 更好的魔术命令

4.2.10:

- core: 修复 arm64 上 Interceptor 向量寄存器破坏问题
- core: 改进 Android 上的临时目录处理

4.2.11:

- dalvik: 添加对访问实例和静态字段的支持
- dalvik: 类型转换改进
- python: 在 Mac 上延迟解析 python 运行时，以允许我们的二进制文件与多个 Python 发行版一起工作
- python: pip 支持

4.2.12:

- python: 修复 Py3k 回归

目前就这些。请通过在网络上传播这篇文章来帮助宣传。作为一个开源项目，我们还很小，所以口碑营销对我们来说意义重大。

享受吧！
