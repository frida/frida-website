## 入门指南

为了提高效率，我们强烈建议使用我们的 **[TypeScript](https://www.typescriptlang.org/)**
绑定。这意味着你可以获得代码补全、类型检查、内联文档、重构工具等功能。

这里有一个简短的预告视频展示了编辑体验：

[![Frida TypeScript demo](https://i.ytimg.com/vi/9cr4gOPFN4o/sddefault.jpg)](https://youtu.be/9cr4gOPFN4o)

克隆 **[这个仓库](https://github.com/oleavr/frida-agent-example)** 即可开始。

## 目录

1. **运行时信息**
    1. [Frida](#frida)
    1. [Script](#script)
1. **进程、线程、模块和内存**
    1. [Thread](#thread)
    1. [Process](#process)
    1. [Module](#module)
    1. [ModuleMap](#modulemap)
    1. [Memory](#memory)
    1. [MemoryAccessMonitor](#memoryaccessmonitor)
    1. [CModule](#cmodule)
    1. [RustModule](#rustmodule)
    1. [ApiResolver](#apiresolver)
    1. [DebugSymbol](#debugsymbol)
    1. [Kernel](#kernel)
1. **数据类型、函数和回调**
    1. [Int64](#int64)
    1. [UInt64](#uint64)
    1. [NativePointer](#nativepointer)
    1. [ArrayBuffer](#arraybuffer)
    1. [NativeFunction](#nativefunction)
    1. [NativeCallback](#nativecallback)
    1. [SystemFunction](#systemfunction)
1. **网络**
    1. [Socket](#socket)
    1. [SocketListener](#socketlistener)
    1. [SocketConnection](#socketconnection)
1. **文件和流**
    1. [File](#file)
    1. [IOStream](#iostream)
    1. [InputStream](#inputstream)
    1. [OutputStream](#outputstream)
    1. [UnixInputStream](#unixinputstream)
    1. [UnixOutputStream](#unixoutputstream)
    1. [Win32InputStream](#win32inputstream)
    1. [Win32OutputStream](#win32outputstream)
1. **数据库**
    1. [SqliteDatabase](#sqlitedatabase)
    1. [SqliteStatement](#sqlitestatement)
1. **插桩**
    1. [Interceptor](#interceptor)
    1. [Stalker](#stalker)
    1. [ObjC](#objc)
    1. [Java](#java)
1. **CPU 指令**
    1. [Instruction](#instruction)
    1. [X86Writer](#x86writer)
    1. [X86Relocator](#x86relocator)
    1. [x86 enum types](#x86-enum-types)
    1. [ArmWriter](#armwriter)
    1. [ArmRelocator](#armrelocator)
    1. [ThumbWriter](#thumbwriter)
    1. [ThumbRelocator](#thumbrelocator)
    1. [ARM enum types](#arm-enum-types)
    1. [Arm64Writer](#arm64writer)
    1. [Arm64Relocator](#arm64relocator)
    1. [AArch64 enum types](#aarch64-enum-types)
    1. [MipsWriter](#mipswriter)
    1. [MipsRelocator](#mipsrelocator)
    1. [MIPS enum types](#mips-enum-types)
1. **其他**
    1. [Console](#console)
    1. [Hexdump](#hexdump)
    1. [Shorthand](#shorthand)
    1. [Communication between host and injected process](#communication-between-host-and-injected-process)
    1. [Timing events](#timing-events)
    1. [Garbage collection](#garbage-collection)
    1. [Worker](#worker)
    1. [Cloak](#cloak)
    1. [Profiler](#profiler)
    1. [Sampler](#sampler)
    1. [CycleSampler](#cycle-sampler)
    1. [BusyCycleSampler](#busy-cycle-sampler)
    1. [WallClockSampler](#wall-clock-sampler)
    1. [UserTimeSampler](#user-time-sampler)
    1. [MallocCountSampler](#malloc-count-sampler)
    1. [CallCountSampler](#call-count-sampler)

---

## 运行时信息

### Frida

+   `Frida.version`: 包含当前 Frida 版本的字符串属性。

+   `Frida.heapSize`: 包含 Frida 私有堆当前大小的动态属性，该堆由所有脚本和 Frida 自身的运行时共享。
    这对于监视你的插桩代码在宿主进程消耗的总内存中使用了多少内存非常有用。

### Script

+   `Script.runtime`: 包含正在使用的运行时的字符串属性。
    要么是 `QJS`，要么是 `V8`。

+   `Script.evaluate(name, source)`: 在全局作用域中评估给定的 JavaScript 字符串 `source`，
    其中 `name` 是指定脚本名称的字符串，例如 `/plugins/tty.js`。提供的名称是用于未来堆栈跟踪的 UNIX 风格虚拟文件系统路径。
    {: #script-evaluate}

    对于想要在自己的脚本中支持加载用户提供的脚本的代理非常有用。相比简单地使用 `eval()`，它的两个好处是
    可以提供脚本文件名，并且支持源映射——包括内联的和通过 [`Script.registerSourceMap()`](#script-registersourcemap) 提供的。

    返回评估代码的结果值。

+   `Script.load(name, source)`: 将给定的 JavaScript 字符串 `source` 编译并评估为 ES 模块，
    其中 `name` 是指定模块名称的字符串，例如 `/plugins/screenshot.js`。提供的名称是用于未来堆栈跟踪的 UNIX 风格虚拟文件系统路径，
    并且对其他模块可见，这些模块可以静态或动态地导入它。

    对于想要在自己的脚本中支持加载用户提供的脚本的代理非常有用。此 API 提供了与 [`Script.evaluate()`](#script-evaluate)
    相比 `eval()` 相同的好处，此外还将用户提供的代码封装在其自己的 ES 模块中。这意味着可以导出值，
    随后由其他模块导入。父脚本也可以导出可以从加载的子脚本导入的值。
    这要求父脚本使用较新版本的 frida-compile 使用的新 ES 模块捆绑格式。

    返回一个解析为模块命名空间对象的 *Promise*。

+   `Script.registerSourceMap(name, json)`: 为指定的脚本 `name` 注册源映射，
    `name` 是一个 UNIX 风格的虚拟文件系统路径字符串，例如 `/plugins/screenshot.js`。
    源映射 `json` 是包含源映射的原始 JSON 表示的字符串。
    {: #script-registersourcemap}

    理想情况下应在加载给定脚本之前调用，以便加载期间创建的堆栈跟踪可以使用源映射。

+   `Script.nextTick(func[, ...params])`: 在下一个 tick 运行 `func`，即
    当当前本机线程退出 JavaScript 运行时时。任何额外的 `params` 都会传递给它。

+   `Script.pin()`: 暂时阻止当前脚本被卸载。
    这是引用计数的，因此必须在稍后有一个匹配的 *unpin()*。通常在 *bindWeak()* 的回调中使用，
    当你需要在另一个线程上安排清理时。

+   `Script.unpin()`: 撤销之前的 *pin()*，以便可以卸载当前脚本。

+   `Script.bindWeak(value, fn)`: 监视 `value`，并在 `value` 被垃圾回收或脚本即将被卸载时
    立即调用 `fn` 回调。返回一个 ID，你可以将其传递给 [`Script.unbindWeak()`](#unbindweak) 进行显式清理。
    {: #bindweak}

    如果你正在构建语言绑定，并且需要在不再需要 JS 值时释放本机资源，则此 API 非常有用。

+   `Script.unbindWeak(id)`: 停止监视传递给 `Script.bindWeak(value, fn)` 的值，
    并立即调用 `fn` 回调。
    {: #unbindweak}

+   `Script.setGlobalAccessHandler(handler | null)`: 安装或卸载用于解决访问不存在的全局变量的尝试的处理程序。
    对于实现 REPL 非常有用，其中未知的标识符可以从数据库中延迟获取。

    `handler` 是一个包含两个属性的对象：

    -   `enumerate()`: 查询存在哪些额外的全局变量。必须返回一个字符串数组。
    -   `get(property)`: 检索给定属性的值。

---

## 进程、线程、模块和内存

### Process

+   `Process.id`: 包含 PID 的数字属性

+   `Process.arch`: 包含字符串 `ia32`、`x64`、`arm` 或 `arm64` 的属性
    {: #process-arch}

+   `Process.platform`: 包含字符串 `windows`、`darwin`、`linux`、`freebsd`、`qnx` 或 `barebone` 的属性

+   `Process.pageSize`: 包含虚拟内存页面大小（以字节为单位）的数字属性。
    这用于使你的脚本更具可移植性。
    {: #process-pagesize}

+   `Process.pointerSize`: 包含指针大小（以字节为单位）的数字属性。
    这用于使你的脚本更具可移植性。
    {: #process-pointersize}

+   `Process.codeSigningPolicy`: 包含字符串 `optional` 或 `required` 的属性，
    后者意味着 Frida 将避免修改内存中的现有代码，并且不会尝试运行未签名的代码。
    目前，除非你使用 **[Gadget](/docs/gadget)** 并将其配置为假设需要代码签名，否则此属性将始终设置为 `optional`。
    此属性允许你确定 **[Interceptor](#interceptor)** API 是否受限，以及修改代码或运行未签名代码是否安全。

+   `Process.mainModule`: 包含表示进程主可执行文件的 [`Module`](#module) 的属性

+   `Process.getCurrentDir()`: 返回指定当前工作目录的文件系统路径的字符串

+   `Process.getHomeDir()`: 返回指定当前用户主目录的文件系统路径的字符串

+   `Process.getTmpDir()`: 返回指定用于临时文件的目录的文件系统路径的字符串

+   `Process.isDebuggerAttached()`: 返回一个布尔值，指示当前是否附加了调试器

+   `Process.getCurrentThreadId()`: 获取此线程的操作系统特定 ID（数字）

+   `Process.enumerateThreads()`: 枚举正在运行的线程，返回 **[Thread](#thread)** 对象的数组。
    {: #process-enumeratethreads}

+   `Process.attachThreadObserver(callbacks)`: 开始观察线程，在添加、移除和重命名线程时调用提供的 `callbacks`。

    `callbacks` 参数是一个包含以下一个或多个属性的对象：

    -   `onAdded(thread)`: 给定刚刚添加的 [`Thread`](#thread) 的回调函数。
        立即使用所有现有线程调用，因此可以轻松管理初始状态与更新，而无需担心竞争条件。
        当使用全新的线程调用时，调用从该新线程同步发生。

    -   `onRemoved(thread)`: 给定刚刚移除（即即将终止）的 [`Thread`](#thread) 的回调函数。
        调用从即将终止的线程同步发生。

    -   `onRenamed(thread, previousName)`: 给定刚刚重命名的 [`Thread`](#thread) 的回调函数，
        带有其新的 `name` 属性，以及第二个参数 `previousName` 指定其先前的名称。
        先前的名称是字符串，如果线程以前未命名，则为 `null`。

    请注意，[`Thread`](#thread) 对象缺少 `state` 和 `context` 属性，因为这些属性本质上是高度易变的，
    并且不会观察到它们的变化。请注意，你可以将此 API 与 [`Stalker`](#stalker) 结合使用以跟踪单个线程的执行。

    返回一个你可以调用 `detach()` 的观察者对象。

+   `Process.runOnThread(id, callback)`: 在由 `id` 指定的线程上运行 JavaScript 函数 `callback`，
    不带任何参数。返回一个 *Promise*，该 Promise 接收你的回调返回的值。

    由于线程可能会在不可重入代码中被中断，因此必须非常谨慎地使用。例如，你可能会在它处于某些微妙代码中间、
    持有特定的非递归锁时中断它，然后当你调用某些函数时尝试再次隐式获取该锁。

+   `Process.findModuleByAddress(address)`,
    `Process.getModuleByAddress(address)`,
    `Process.findModuleByName(name)`,
    `Process.getModuleByName(name)`:
    返回一个 **[Module](#module)**，其 *address* 或 *name* 与指定的匹配。
    如果找不到此类模块，*find*-前缀函数返回 *null*，而 *get*-前缀函数抛出异常。
    {: #process-getmodulebyname}

+   `Process.enumerateModules()`: 枚举当前加载的模块，返回 **[Module](#module)** 对象的数组。
    {: #process-enumeratemodules}

+   `Process.attachModuleObserver(callbacks)`: 开始观察模块，在添加和移除模块时调用提供的 `callbacks`。

    `callbacks` 参数是一个包含以下一个或多个属性的对象：

    -   `onAdded(module)`: 给定刚刚添加的 [`Module`](#module) 的回调函数。
        立即使用所有现有模块调用，因此可以轻松管理初始状态与更新，而无需担心竞争条件。
        当使用全新模块调用时，调用在该模块加载后立即同步发生，但在应用程序有机会使用它之前。
        这意味着这是应用插桩的好时机，例如使用 [`Interceptor`](#interceptor)。

    -   `onRemoved(module)`: 给定刚刚移除（即卸载）的 [`Module`](#module) 的回调函数。

    返回一个你可以调用 `detach()` 的观察者对象。

+   `Process.findRangeByAddress(address)`, `getRangeByAddress(address)`:
    返回一个包含有关包含 *address* 的范围的详细信息的对象。
    如果找不到此类范围，*findRangeByAddress()* 返回 *null*，而 *getRangeByAddress()* 抛出异常。
    有关包含哪些字段的详细信息，请参阅 [`Process.enumerateRanges()`](#process-enumerateranges)。

+   `Process.enumerateRanges(protection|specifier)`: 枚举满足给定 `protection` 字符串（形式为 `rwx`，
    其中 `rw-` 表示“必须至少可读且可写”）的内存范围。或者，你可以提供一个 `specifier` 对象，
    其中包含一个 `protection` 键（其值如前所述）和一个 `coalesce` 键（设置为 `true`，
    如果你希望合并具有相同保护的相邻范围（默认为 `false`；即保持范围分开））。
    返回包含以下属性的对象数组：
    {: #process-enumerateranges}

    -   `base`: [`NativePointer`](#nativepointer) 形式的基地址
    -   `size`: 字节大小
    -   `protection`: 保护字符串（见上文）
    -   `file`: （如果可用）文件映射详细信息对象，包含：

        -   `path`: 完整文件系统路径字符串
        -   `offset`: 磁盘上映射文件的偏移量（以字节为单位）
        -   `size`: 磁盘上映射文件的大小（以字节为单位）

+   `Process.enumerateMallocRanges()`: 就像 [`enumerateRanges()`](#process-enumerateranges)，
    但针对系统堆已知的单个内存分配。

+   `Process.setExceptionHandler(callback)`: 安装进程范围的异常处理程序回调，
    该回调有机会在宿主进程本身处理之前处理本机异常。使用单个参数 `details` 调用，该对象包含：
    {: #process-setexceptionhandler}

    -   `type`: 指定以下之一的字符串：
        * abort
        * access-violation
        * guard-page
        * illegal-instruction
        * stack-overflow
        * arithmetic
        * breakpoint
        * single-step
        * system
    -   `address`: 发生异常的地址，作为 **[NativePointer](#nativepointer)**
    -   `memory`: 如果存在，是一个包含以下内容的对象：
        -   `operation`: 触发异常的操作类型，指定为 `read`、`write` 或 `execute` 的字符串
        -   `address`: 发生异常时访问的地址，作为 **[NativePointer](#nativepointer)**
    -   `context`: 具有键 `pc` and `sp` 的对象，它们是指定 EIP/RIP/PC 和 ESP/RSP/SP 的
        **[NativePointer](#nativepointer)** 对象，分别用于 ia32/x64/arm。
        其他特定于处理器的键也可用，例如 `eax`, `rax`, `r0`, `x0` 等。
        你也可以通过分配给这些键来更新寄存器值。
    -   `nativeContext`: 操作系统和架构特定的 CPU 上下文结构的地址，作为 **[NativePointer](#nativepointer)**。
        这仅作为最后的手段暴露，用于 `context` 无法提供足够细节的边缘情况。
        但是，我们要劝阻使用此方法，而是提交拉取请求以添加你的用例所需的缺失位。

    由你的回调决定如何处理异常。它可以记录问题，通过 **[send()](#communication-send)** 通知你的应用程序，
    然后进行阻塞 recv() 以确认发送的数据已被接收，或者它可以修改寄存器和内存以从异常中恢复。
    如果你确实处理了异常，则应返回 `true`，在这种情况下，Frida 将立即恢复线程。
    如果你不返回 `true`，Frida 将把异常转发给宿主进程的异常处理程序（如果有），或者让操作系统终止进程。


### Thread

由例如 [`Process.enumerateThreads()`](#process-enumeratethreads) 返回的对象。<br/><br/>

-   `id`: 操作系统特定的 ID，作为数字

-   `name`: 指定线程名称的字符串（如果可用）

-   `state`: 线程状态的快照，作为指定 `running`、`stopped`、`waiting`、`uninterruptible` 或 `halted` 的字符串

-   `context`: CPU 寄存器的快照，作为一个具有键 `pc` 和 `sp` 的对象，它们是指定 EIP/RIP/PC 和 ESP/RSP/SP 的
    **[NativePointer](#nativepointer)** 对象，分别用于 ia32/x64/arm。
    其他特定于处理器的键也可用，例如 `eax`, `rax`, `r0`, `x0` 等。
    {: #thread-context}

-   `entrypoint`: 线程开始执行的位置（如果适用且可用）。如果存在，它是一个包含以下内容的对象：

    -   `routine`: 线程的启动例程，作为 [`NativePointer`](#nativepointer)

    -   `parameter`: 传递给 `routine` 的参数（如果可用），作为 [`NativePointer`](#nativepointer)

-   `setHardwareBreakpoint(id, address)`: 设置硬件断点，其中 `id` 是指定断点 ID 的数字，
    `address` 是指定断点地址的 [`NativePointer`](#nativepointer)。
    通常与 [`Process.setExceptionHandler()`](#process-setexceptionhandler) 结合使用以处理引发的异常。
    {: #thread-sethardwarebreakpoint}

-   `unsetHardwareBreakpoint(id)`: 取消设置硬件断点，其中 `id` 是指定先前通过调用
    [`setHardwareBreakpoint()`](#thread-sethardwarebreakpoint) 设置的断点 ID 的数字。

-   `setHardwareWatchpoint(id, address, size, conditions)`: 设置硬件观察点，
    其中 `id` 是指定观察点 ID 的数字，`address` 是指定要监视的区域地址的 [`NativePointer`](#nativepointer)，
    `size` 是指定该区域大小的数字，`conditions` 是指定 `r`、`w` 或 `rw` 的字符串。
    在这里，`r` 表示监视读取，`w` 表示监视写入，`rw` 表示监视读取和写入。
    通常与 [`Process.setExceptionHandler()`](#process-setexceptionhandler) 结合使用以处理引发的异常。
    {: #thread-sethardwarewatchpoint}

-   `unsetHardwareWatchpoint(id)`: 取消设置硬件观察点，其中 `id` 是指定先前通过调用
    [`setHardwareWatchpoint()`](#thread-sethardwarewatchpoint) 设置的观察点 ID 的数字。

+   `Thread.backtrace([context, backtracer])`: 生成当前线程的回溯，作为 [`NativePointer`](#nativepointer) 对象数组返回。
    {: #thread-backtrace}

    如果你从 Interceptor 的 [`onEnter`](#interceptor-onenter) 或 [`onLeave`](#interceptor-onleave) 回调中调用此函数，
    你应该为可选的 `context` 参数提供 `this.context`，因为它将为你提供更准确的回溯。
    省略 `context` 意味着回溯将从当前堆栈位置生成，由于 JavaScript VM 的堆栈帧，这可能无法为你提供非常好的回溯。
    可选的 `backtracer` 参数指定要使用的回溯器类型，必须是 `Backtracer.FUZZY` 或 `Backtracer.ACCURATE`，
    如果未指定，则后者为默认值。准确的回溯器类型依赖于调试器友好的二进制文件或调试信息的存​​在才能做好工作，
    而模糊回溯器对堆栈执行取证以猜测返回地址，这意味着你会得到误报，但它适用于任何二进制文件。
    生成的回溯目前限制为 16 帧，并且在不重新编译 Frida 的情况下无法调整。

{% highlight js %}
const commonCrypto = Process.getModuleByName('libcommonCrypto.dylib');
const f = commonCrypto.getExportByName('CCCryptorCreate');
Interceptor.attach(f, {
  onEnter(args) {
    console.log('CCCryptorCreate called from:\n' +
        Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress).join('\n') + '\n');
  }
});
{% endhighlight %}

+   `Thread.sleep(delay)`: 将当前线程的执行挂起 `delay` 秒（指定为数字）。例如 0.05 表示睡眠 50 毫秒。


### Module

由例如 [`Module.load()`](#module-load) 和 [`Process.enumerateModules()`](#process-enumeratemodules) 返回的对象。<br/><br/>

-   `name`: 规范模块名称字符串

-   `base`: [`NativePointer`](#nativepointer) 形式的基地址

-   `size`: 字节大小

-   `path`: 完整文件系统路径字符串

-   `ensureInitialized()`: 确保已运行模块初始化程序。
    这在早期插桩期间（即在进程生命周期的早期运行）非常重要，以便能够安全地与 API 交互。
    一个这样的用例是与给定模块提供的 **[ObjC](#objc)** 类进行交互。

-   `enumerateImports()`: 枚举模块的导入，返回包含以下属性的对象数组：

    -   `type`: 指定 `function` 或 `variable` 的字符串
    -   `name`: 导入名称字符串
    -   `module`: 模块名称字符串
    -   `address`: [`NativePointer`](#nativepointer) 形式的绝对地址
    -   `slot`: 存储导入的内存位置，作为 [`NativePointer`](#nativepointer)

    只有 `name` 字段保证存在于所有导入中。平台特定的后端将尽最大努力解析其他字段，
    甚至超出本机元数据提供的范围，但不能保证它会成功。

-   `enumerateExports()`: 枚举模块的导出，返回包含以下属性的对象数组：

    -   `type`: 指定 `function` 或 `variable` 的字符串
    -   `name`: 导出名称字符串
    -   `address`: [`NativePointer`](#nativepointer) 形式的绝对地址

-   `enumerateSymbols()`: 枚举模块的符号，返回包含以下属性的对象数组：

    -   `isGlobal`: 指定符号是否全局可见的布尔值
    -   `type`: 指定以下之一的字符串：
        -   unknown
        -   section
        -   undefined (Mach-O)
        -   absolute (Mach-O)
        -   prebound-undefined (Mach-O)
        -   indirect (Mach-O)
        -   object (ELF)
        -   function (ELF)
        -   file (ELF)
        -   common (ELF)
        -   tls (ELF)
    -   `section`: 如果存在，是一个包含以下内容的对象：
        -   `id`: 包含部分索引、段名称（如果适用）和部分名称的字符串——格式与 [r2][] 的部分 ID 相同
        -   `protection`: 类似于 [`Process.enumerateRanges()`](#process-enumerateranges) 中的保护
    -   `name`: 符号名称字符串
    -   `address`: [`NativePointer`](#nativepointer) 形式的绝对地址
    -   `size`: 如果存在，指定符号大小（以字节为单位）的数字

<div class="note info">
  <h5>enumerateSymbols() 仅在 i/macOS 和基于 Linux 的操作系统上可用</h5>
  <p markdown="1">
    我们也希望在其他平台上支持这一点，所以如果你觉得这很有用并想提供帮助，请联系我们。
    根据你的用例，你可能也会发现 **[DebugSymbol](#debugsymbol)** API 就足够了。
  </p>
</div>

-   `enumerateRanges(protection)`: 就像 [`Process.enumerateRanges`](#process-enumerateranges)，
    除了它的范围限定于模块。

-   `enumerateSections()`: 枚举模块的部分，返回包含以下属性的对象数组：

    -   `id`: 包含部分索引、段名称（如果适用）和部分名称的字符串——格式与 [r2][] 的部分 ID 相同
    -   `name`: 部分名称字符串
    -   `address`: [`NativePointer`](#nativepointer) 形式的绝对地址
    -   `size`: 字节大小

-   `enumerateDependencies()`: 枚举模块的依赖项，返回包含以下属性的对象数组：

    -   `name`: 模块名称字符串
    -   `type`: 指定以下之一的字符串：
        -   regular
        -   weak
        -   reexport
        -   upward

-   `findExportByName(name)`,
    `getExportByName(name)`: 返回名为 `name` 的导出的绝对地址。
    如果找不到此类导出，*find*-前缀函数返回 *null*，而 *get*-前缀函数抛出异常。
    {: #module-getexportbyname}

-   `findSymbolByName(name)`,
    `getSymbolByName(name)`: 返回名为 `name` 的符号的绝对地址。
    如果找不到此类符号，*find*-前缀函数返回 *null*，而 *get*-前缀函数抛出异常。

+   `Module.load(path)`: 从文件系统路径加载指定的模块并返回一个 [`Module`](#module) 对象。
    如果无法加载指定的模块，则抛出异常。
    {: #module-load}

+   `Module.findGlobalExportByName(name)`,
    `Module.getGlobalExportByName(name)`: 返回名为 `name` 的全局导出的绝对地址。
    这可能是一个昂贵的搜索，应避免使用。如果找不到此类导出，
    *find*-前缀函数返回 *null*，而 *get*-前缀函数抛出异常。


### ModuleMap

+   `new ModuleMap([filter])`: 创建一个新的模块映射，该映射针对确定给定内存地址属于哪个模块（如果有）进行了优化。
    创建时获取当前加载模块的快照，可以通过调用 [`update()`](#modulemap-update) 进行刷新。
    `filter` 参数是可选的，允许你传递一个用于过滤模块列表的函数。
    例如，如果你只关心应用程序本身拥有的模块，这很有用，并允许你快速检查地址是否属于其模块之一。
    `filter` 函数被传递一个 **[Module](#module)** 对象，并且必须为应保留在映射中的每个模块返回 `true`。
    每次更新映射时，都会为每个加载的模块调用它。

-   `has(address)`: 检查 `address` 是否属于任何包含的模块，并返回结果作为布尔值

-   `find(address)`, `get(address)`: 返回一个 **[Module](#module)**，其中包含有关 `address` 所属模块的详细信息。
    如果找不到此类模块，`find()` 返回 `null`，而 `get()` 抛出异常。
    {: #modulemap-find}

-   `findName(address)`,
    `getName(address)`,
    `findPath(address)`,
    `getPath(address)`:
    就像 [`find()`](#modulemap-find) 和 [`get()`](#modulemap-find)，但只返回 `name` 或 `path` 字段，
    这意味着当你不需要其他细节时开销更小。

-   `update()`: 更新映射。你应该在加载或卸载模块后调用此函数，以避免对过时数据进行操作。
    {: #modulemap-update}

-   `values()`: 返回当前在映射中的 **[Module](#module)** 对象的数组。
    返回的数组是深层副本，并且在调用 [`update()`](#modulemap-update) 后不会发生变异。


### Memory

+   `Memory.scan(address, size, pattern, callbacks)`: 在由 `address` 和 `size` 给定的内存范围内扫描 `pattern` 的出现。
    {: #memory-scan}

    -   `pattern` 必须是 "13 37 ?? ff" 的形式，以匹配 0x13 后跟 0x37 后跟任意字节后跟 0xff。
        对于更高级的匹配，也可以指定 [r2][]-风格的掩码。掩码与 needle 和 haystack 进行按位与运算。
        要指定掩码，请在 needle 后附加 `:` 字符，后跟使用相同语法的掩码。
        例如："13 37 13 37 : 1f ff ff f1"。
        为了方便起见，也可以指定半字节级别的通配符，如 "?3 37 13 ?7"，这在幕后被转换为掩码。

    -   `callbacks` 是一个对象，具有：

        -   `onMatch(address, size)`: 使用包含出现地址的 `address`（作为 [`NativePointer`](#nativepointer)）
            和指定大小的 `size`（作为数字）调用。

            此函数可以返回字符串 `stop` 以提前取消内存扫描。

        -   `onError(reason)`: 当扫描时发生内存访问错误时使用 `reason` 调用

        -   `onComplete()`: 当内存范围已被完全扫描时调用

-   `Memory.scanSync(address, size, pattern)`: [`scan()`](#memory-scan) 的同步版本，
    返回包含以下属性的对象数组：

    -   `address`: [`NativePointer`](#nativepointer) 形式的绝对地址。
    -   `size`: 字节大小

    例如：

{% highlight js %}
// Find the module for the program itself, always at index 0:
const m = Process.enumerateModules()[0];

// Or load a module by name:
//const m = Module.load('win32u.dll');

// Print its properties:
console.log(JSON.stringify(m));

// Dump it from its base address:
console.log(hexdump(m.base));

// The pattern that you are interested in:
const pattern = '00 00 00 00 ?? 13 37 ?? 42';

Memory.scan(m.base, m.size, pattern, {
  onMatch(address, size) {
    console.log('Memory.scan() found match at', address,
        'with size', size);

    // Optionally stop scanning early:
    return 'stop';
  },
  onComplete() {
    console.log('Memory.scan() complete');
  }
});

const results = Memory.scanSync(m.base, m.size, pattern);
console.log('Memory.scanSync() result:\n' +
    JSON.stringify(results));
{% endhighlight %}

+   `Memory.alloc(size[, options])`: 在堆上分配 `size` 字节的内存，或者，如果 `size` 是
    [`Process.pageSize`](#process-pagesize) 的倍数，则分配由操作系统管理的一个或多个原始内存页面。
    当使用页面粒度时，如果你需要分配的内存靠近给定地址，你也可以指定一个 `options` 对象，
    通过指定 `{ near: address, maxDistance: distanceInBytes }`。
    返回的值是一个 [`NativePointer`](#nativepointer)，并且当所有对它的 JavaScript 句柄都消失时，
    底层内存将被释放。这意味着当指针被 JavaScript 运行时之外的代码使用时，你需要保留对它的引用。
    {: #memory-alloc}

+   `Memory.copy(dst, src, n)`: 就像 memcpy()。不返回任何内容。
    {: #memory-copy}

    - dst: 指定目标基地址的 [`NativePointer`](#nativepointer)。
    - src: 指定源基地址的 [`NativePointer`](#nativepointer)。
    - n: 要复制的字节大小。

+   `Memory.dup(address, size)`: [`Memory.alloc()`](#memory-alloc) 后跟 [`Memory.copy()`](#memory-copy) 的简写。
    返回包含新分配内存基地址的 [`NativePointer`](#nativepointer)。
    有关内存分配的生命周期的详细信息，请参阅 [`Memory.copy()`](#memory-copy)。

+   `Memory.protect(address, size, protection)`: 更新内存区域的保护，其中 `protection` 是与
    [`Process.enumerateRanges()`](#process-enumerateranges) 格式相同的字符串。

    返回一个布尔值，指示操作是否成功完成。

    例如：

{% highlight js %}
Memory.protect(ptr('0x1234'), 4096, 'rw-');
{% endhighlight %}

+   `Memory.queryProtection(address)`: 确定 `address` 处内存的当前保护，指定为 **[NativePointer](#nativepointer)**。
    返回与 [`Process.enumerateRanges()`](#process-enumerateranges) 格式相同的页面保护字符串。

+   `Memory.patchCode(address, size, apply)`: 安全地修改 `address` 处的 `size` 字节，
    指定为 **[NativePointer](#nativepointer)**。提供的 JavaScript 函数 `apply` 会被调用，
    带有一个可写指针，你必须在返回之前在该指针处写入所需的修改。不要假设这与 `address` 是同一个位置，
    因为某些系统要求将修改写入临时位置，然后再映射到原始内存页面之上的内存中（例如在 iOS 上，
    直接修改内存中的代码可能会导致进程丢失其 CS_VALID 状态）。
    {: #memory-patchcode}

    例如：

{% highlight js %}
const gameEngine = Process.getModuleByName('game-engine.so');
const getLivesLeft = gameEngine.getExportByName('get_lives_left');
const maxPatchSize = 64; // Do not write out of bounds, may be a temporary buffer!
Memory.patchCode(getLivesLeft, maxPatchSize, code => {
  const cw = new X86Writer(code, { pc: getLivesLeft });
  cw.putMovRegU32('eax', 9000);
  cw.putRet();
  cw.flush();
});
{% endhighlight %}

+   `Memory.allocUtf8String(str)`,
    `Memory.allocUtf16String(str)`,
    `Memory.allocAnsiString(str)`:
    在堆上分配、编码并写出 `str` 作为 UTF-8/UTF-16/ANSI 字符串。
    返回的对象是一个 [`NativePointer`](#nativepointer)。
    有关其生命周期的详细信息，请参阅 [`Memory.alloc()`](#memory-alloc)。


### MemoryAccessMonitor

+   `MemoryAccessMonitor.enable(ranges, callbacks)`: 监视一个或多个内存范围的访问，
    并在每次包含的内存页面首次访问时发出通知。`ranges` 是单个范围对象或此类对象的数组，
    每个对象包含：
    {: #memoryaccessmonitor-enable}

    -   `base`: [`NativePointer`](#nativepointer) 形式的基地址
    -   `size`: 字节大小

    `callbacks` 是一个对象，指定：

    -   `onAccess(details)`: 使用 `details` 对象同步调用，包含：
        -   `threadId`: 执行访问的线程 ID，作为数字。
        -   `operation`: 触发访问的操作类型，指定为 `read`、`write` 或 `execute` 的字符串
        -   `from`: 执行访问的指令地址，作为 [`NativePointer`](#nativepointer)
        -   `address`: 正在访问的地址，作为 [`NativePointer`](#nativepointer)
        -   `rangeIndex`: 访问范围在提供给 `MemoryAccessMonitor.enable()` 的范围中的索引
        -   `pageIndex`: 访问的内存页面在指定范围内的索引
        -   `pagesCompleted`: 到目前为止已访问（且不再受监控）的页面总数
        -   `pagesTotal`: 最初受监控的页面总数
        -   `context`: CPU 寄存器，就像 [`Thread#context`](#thread-context)。
            你也可以通过分配给这些键来更新寄存器值。

+   `MemoryAccessMonitor.disable()`: 停止监视传递给 [`MemoryAccessMonitor.enable()`](#memoryaccessmonitor-enable)
    的剩余内存范围。


### CModule

+   `new CModule(code[, symbols, options])`: 从提供的 `code` 创建一个新的 C 模块，
    `code` 可以是包含要编译的 C 源代码的字符串，也可以是包含预编译共享库的 ArrayBuffer。
    C 模块被映射到内存中，并且可以完全被 JavaScript 访问。

    对于实现热回调非常有用，例如用于 **[Interceptor](#interceptor)** 和 **[Stalker](#stalker)**，
    但在需要启动新线程以紧密循环调用函数时也很有用，例如用于模糊测试目的。

    全局函数自动导出为 **[NativePointer](#nativepointer)** 属性，名称与 C 源代码中的完全相同。
    这意味着你可以将它们传递给 **[Interceptor](#interceptor)** 和 **[Stalker](#stalker)**，
    或者使用 **[NativePointer](#nativepointer)** 调用它们。

    除了访问 Gum、GLib 和标准 C API 的精选子集外，映射进来的代码还可以通过暴露给它的 `symbols` 与 JavaScript 通信。
    这是可选的第二个参数，一个指定附加符号名称及其 **[NativePointer](#nativepointer)** 值的对象，
    每个值都将在创建时插入。例如，这可以是使用 **[Memory.alloc()](#memory-alloc)** 分配的一个或多个内存块，
    和/或用于从 C 模块接收回调的 **[NativeCallback](#nativecallback)** 值。

    要执行初始化和清理，你可以定义具有以下名称和签名的函数：

    -   `void init (void)`
    -   `void finalize (void)`

    请注意，所有数据都是只读的，因此可写全局变量应声明为 *extern*，使用例如 **[Memory.alloc()](#memory-alloc)** 分配，
    并通过构造函数的第二个参数作为符号传入。

    可选的第三个参数 `options` 是一个对象，可用于指定要使用的工具链，例如：`{ toolchain: 'external' }`。
    支持的值为：

    -   `internal`: 使用 TinyCC，它静态链接到运行时中。从不接触文件系统，甚至在沙盒进程中也能工作。
        但是生成的代码没有优化，因为 TinyCC 针对小编译器占用空间和短编译时间进行了优化。
    -   `external`: 使用目标系统提供的工具链，假设我们在其中执行的进程可以访问它。
    -   `any`: 如果 TinyCC 支持 [`Process.arch`](#process-arch)，则与 `internal` 相同，否则为 `external`。
        如果未指定，这是默认行为。

-   `dispose()`: 立即从内存中取消映射模块。当不希望等待未来的垃圾回收时，这对于短寿命模块很有用。

+   `builtins`: 一个指定从 C 源代码构造 CModule 时存在的内置函数的对象。
    这通常由诸如 `frida-create` 之类的脚手架工具使用，以便设置与 CModule 使用的相匹配的构建环境。
    确切的内容取决于 [`Process.arch`](#process-arch) 和 Frida 版本，但可能看起来像下面这样：

        {
          defines: {
            'GLIB_SIZEOF_VOID_P': '8',
            'G_GINT16_MODIFIER': '"h"',
            'G_GINT32_MODIFIER': '""',
            'G_GINT64_MODIFIER': '"ll"',
            'G_GSIZE_MODIFIER': '"l"',
            'G_GSSIZE_MODIFIER': '"l"',
            'HAVE_I386': true
          },
          headers: {
            'gum/arch-x86/gumx86writer.h': '…',
            'gum/gumdefs.h': '…',
            'gum/guminterceptor.h': '…',
            'gum/gummemory.h': '…',
            'gum/gummetalarray.h': '…',
            'gum/gummetalhash.h': '…',
            'gum/gummodulemap.h': '…',
            'gum/gumprocess.h': '…',
            'gum/gumspinlock.h': '…',
            'gum/gumstalker.h': '…',
            'glib.h': '…',
            'json-glib/json-glib.h': '…',
            'capstone.h': '…'
          }
        }

#### 示例

{% highlight js %}
const cm = new CModule(`
#include <stdio.h>

void hello(void) {
  printf("Hello World from CModule\\n");
}
`);

console.log(JSON.stringify(cm));

const hello = new NativeFunction(cm.hello, 'void', []);
hello();
{% endhighlight %}

你可以使用 Frida 的 REPL 加载它：

{% highlight sh %}
$ frida -p 0 -l example.js
{% endhighlight %}

（REPL 监视磁盘上的文件并在更改时重新加载脚本。）

然后你可以在 REPL 中输入 `hello()` 来调用 C 函数。

对于原型设计，我们建议使用 Frida REPL 的内置 CModule 支持：

{% highlight sh %}
$ frida -p 0 -C example.c
{% endhighlight %}

你也可以添加 `-l example.js` 来在其旁边加载一些 JavaScript。
JavaScript 代码可以使用名为 `cm` 的全局变量来访问 CModule 对象，
但仅在调用 [`rpc.exports.init()`](#rpc-exports) 之后，因此请在那里执行任何依赖于 CModule 的初始化。
你也可以通过分配给名为 `cs` 的全局对象来注入符号，但这必须在调用 [`rpc.exports.init()`](#rpc-exports) *之前*完成。

这是一个例子：

![CModule REPL example](https://pbs.twimg.com/media/EEyxQzwXoAAqoAw?format=jpg&name=small)

有关 CModule 的更多详细信息，请参阅 **[Frida 12.7 发行说明]({{
site.baseurl_root }}/news/2019/09/18/frida-12-7-released/)**。


### RustModule

将 Rust 源代码编译为机器代码，直接存入内存。

+   `new RustModule(code[, symbols, options])`: 从提供的 `code` 创建一个新的 Rust 模块，
    `code` 是包含要编译的 Rust 源代码的字符串。Rust 模块被映射到内存中，并且可以完全被 JavaScript 访问。

    对于实现热回调非常有用，例如用于 [Interceptor](#interceptor) 和 [Stalker](#stalker)，
    但在需要启动新线程以紧密循环调用函数时也很有用，例如用于模糊测试目的。

    公共函数自动导出为 [`NativePointer`](#nativepointer) 属性。这意味着你可以将它们传递给
    Interceptor 和 Stalker，或者使用 [`NativeFunction`](#nativefunction) 调用它们。
    在这种情况下，你通常希望确保它们被标记为 `#[no_mangle]` 和 `extern "C"`。

    除了 Rust 库之外，映射进来的代码还可以通过暴露给它的 `symbols` 与 JavaScript 通信。
    此对象将符号名称映射到 [`NativePointer`](#nativepointer) 值。在你的 Rust 源代码中将它们声明为 `extern "C"`。
    例如，这可以是使用 `Memory.alloc()` 分配的一个或多个内存块，和/或用于从 Rust 模块接收回调的
    [`NativeCallback`](#nativecallback) 值。

    可选的第三个参数 `options` 是一个对象，可用于指定要使用的 Cargo 依赖项，例如：
    `{ dependencies: ['base64 = "0.22.1"', 'anyhow = "1.0.97"'] }`。


### ApiResolver

+   `new ApiResolver(type)`: 创建给定 `type` 的新解析器，允许你按名称快速查找 API，允许使用 glob。
    确切可用的解析器取决于当前平台和当前进程中加载的运行时。截至撰写本文时，可用的解析器有：

    -   `module`: 解析模块导出、导入和部分。始终可用。
    -   `swift`: 解析 Swift 函数。
                 在加载了 Swift 运行时的进程中可用。使用 `Swift.available` 在运行时检查，
                 或者将你的 `new ApiResolver('swift')` 调用包装在 *try-catch* 中。
    -   `objc`: 解析 Objective-C 方法。
                在 macOS 和 iOS 上，在加载了 Objective-C 运行时的进程中可用。
                使用 [`ObjC.available`](#objc-available) 在运行时检查，
                或者将你的 `new ApiResolver('objc')` 调用包装在 *try-catch* 中。

    解析器将在创建时加载所需的最小数据量，并根据收到的查询延迟加载其余数据。
    因此，建议对一批查询使用相同的实例，但为将来的批次重新创建它以避免查看过时的数据。

-   `enumerateMatches(query)`: 执行解析器特定的 `query` 字符串，可选地后缀 `/i` 以执行不区分大小写的匹配，
    返回包含以下属性的对象数组：

    -   `name`: 找到的 API 的名称
    -   `address`: [`NativePointer`](#nativepointer) 形式的地址
    -   `size`: 如果存在，指定字节大小的数字

{% highlight js %}
const resolver = new ApiResolver('module');
const matches = resolver.enumerateMatches('exports:*!open*');
const first = matches[0];
/*
 * Where `first` is an object similar to:
 *
 * {
 *   name: '/usr/lib/libSystem.B.dylib!opendir$INODE64',
 *   address: ptr('0x7fff870135c9')
 * }
 */
{% endhighlight %}

{% highlight js %}
const resolver = new ApiResolver('module');
const matches = resolver.enumerateMatches('sections:*!*text*');
const first = matches[0];
/*
 * Where `first` is an object similar to:
 *
 * {
 *   name: '/usr/lib/libSystem.B.dylib!0.__TEXT.__text',
 *   address: ptr('0x191c1e504'),
 *   size: 1528
 * }
 */
{% endhighlight %}

{% highlight js %}
const resolver = new ApiResolver('swift');
const matches = resolver.enumerateMatches('functions:*CoreDevice!*RemoteDevice*');
const first = matches[0];
/*
 * Where `first` is an object similar to:
 *
 * {
 *   name: '/Library/Developer/PrivateFrameworks/CoreDevice.framework/Versions/A/CoreDevice!dispatch thunk of CoreDevice.RemoteDevice.addDeviceInfoChanged(on: __C.OS_dispatch_queue?, handler: (Foundation.UUID, CoreDeviceProtocols.DeviceInfo) -> ()) -> CoreDevice.Invalidatable',
 *   address: ptr('0x1078c3570')
 * }
 */
{% endhighlight %}

{% highlight js %}
const resolver = new ApiResolver('objc');
const matches = resolver.enumerateMatches('-[NSURL* *HTTP*]');
const first = matches[0];
/*
 * Where `first` is an object similar to:
 *
 * {
 *   name: '-[NSURLRequest valueForHTTPHeaderField:]',
 *   address: ptr('0x7fff94183e22')
 * }
 */
{% endhighlight %}


### DebugSymbol

+   `DebugSymbol.fromAddress(address)`, `DebugSymbol.fromName(name)`:
    查找 `address`/`name` 的调试信息并将其作为包含以下内容的对象返回：

    -   `address`: 此符号的地址，作为 [`NativePointer`](#nativepointer)。
    -   `name`: 符号名称，作为字符串，如果未知则为 null。
    -   `moduleName`: 拥有此符号的模块名称，作为字符串，如果未知则为 null。
    -   `fileName`: 拥有此符号的文件名，作为字符串，如果未知则为 null。
    -   `lineNumber`: `fileName` 中的行号，作为数字，如果未知则为 null。

    你也可以对其调用 `toString()`，当与 [`Thread.backtrace()`](#thread-backtrace) 结合使用时非常有用：

{% highlight js %}
const commonCrypto = Process.getModuleByName('libcommonCrypto.dylib');
const f = commonCrypto.getExportByName('CCCryptorCreate');
Interceptor.attach(f, {
  onEnter(args) {
    console.log('CCCryptorCreate called from:\n' +
        Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress).join('\n') + '\n');
  }
});
{% endhighlight %}

+   `DebugSymbol.getFunctionByName(name)`: 解析函数名称并将其地址作为 [`NativePointer`](#nativepointer) 返回。
    如果找到多个函数，则返回第一个。如果无法解析名称，则抛出异常。

+   `DebugSymbol.findFunctionsNamed(name)`: 解析函数名称并将其地址作为 [`NativePointer`](#nativepointer) 对象数组返回。

+   `DebugSymbol.findFunctionsMatching(glob)`: 解析匹配 `glob` 的函数名称并将其地址作为
    [`NativePointer`](#nativepointer) 对象数组返回。

+   `DebugSymbol.load(path)`: 加载特定模块的调试符号。


### Kernel

+   `Kernel.available`: 指定 Kernel API 是否可用的布尔值。除非如此，否则不要调用任何其他 `Kernel` 属性或方法。

+   `Kernel.base`: 内核的基地址，作为 **[UInt64](#uint64)**。

+   `Kernel.pageSize`: 内核页面大小（以字节为单位），作为数字。

+   `Kernel.enumerateModules()`: 枚举当前加载的内核模块，返回包含以下属性的对象数组：

    -   `name`: 规范模块名称字符串
    -   `base`: [`NativePointer`](#nativepointer) 形式的基地址
    -   `size`: 字节大小

+   `Kernel.enumerateRanges(protection|specifier)`: 枚举满足给定 `protection` 字符串（形式为 `rwx`，
    其中 `rw-` 表示“必须至少可读且可写”）的内核内存范围。或者，你可以提供一个 `specifier` 对象，
    其中包含一个 `protection` 键（其值如前所述）和一个 `coalesce` 键（设置为 `true`，
    如果你希望合并具有相同保护的相邻范围（默认为 `false`；即保持范围分开））。
    返回包含以下属性的对象数组：
    {: #kernel-enumerateranges}

    -   `base`: [`NativePointer`](#nativepointer) 形式的基地址
    -   `size`: 字节大小
    -   `protection`: 保护字符串（见上文）

+   `Kernel.enumerateModuleRanges(name, protection)`: 就像 [`Kernel.enumerateRanges`](#kernel-enumerateranges)，
    除了它的范围限定于指定的模块 `name`——对于内核本身的模块，它可以是 `null`。
    每个范围还有一个 `name` 字段，包含作为字符串的唯一标识符。

+   `Kernel.alloc(size)`: 分配 `size` 字节的内核内存，向上取整为内核页面大小的倍数。
    返回的值是指定分配基地址的 [`UInt64`](#uint64)。

+   `Kernel.protect(address, size, protection)`: 更新内核内存区域的保护，其中 `protection` 是与
    [`Kernel.enumerateRanges()`](#kernel-enumerateranges) 格式相同的字符串。

    例如：

{% highlight js %}
Kernel.protect(UInt64('0x1234'), 4096, 'rw-');
{% endhighlight %}

+   `Kernel.readByteArray(address, length)`: 就像
    [`NativePointer#readByteArray`](#nativepointer-readbytearray)，但从内核内存读取。

+   `Kernel.writeByteArray(address, bytes)`: 就像
    [`NativePointer#writeByteArray`](#nativepointer-writebytearray)，但写入内核内存。

+   `Kernel.scan(address, size, pattern, callbacks)`: 就像 [`Memory.scan`](#memory-scan)，
    但扫描内核内存。
    {: #kernel-scan}

-   `Kernel.scanSync(address, size, pattern)`: [`scan()`](#kernel-scan) 的同步版本，
    返回数组中的匹配项。

---

## 数据类型、函数和回调


### Int64

+   `new Int64(v)`: 从 `v` 创建一个新的 Int64，`v` 可以是数字或包含十进制值的字符串，
    如果以 "0x" 为前缀，则为十六进制。为了简洁起见，你可以使用 `int64(v)` 简写。

-   `add(rhs)`, `sub(rhs)`,
    `and(rhs)`, `or(rhs)`,
    `xor(rhs)`:
    创建一个新的 Int64，其值为此 Int64 加/减/与/或/异或 `rhs`，`rhs` 可以是数字或另一个 Int64

-   `shr(n)`, `shl(n)`:
    创建一个新的 Int64，其值为此 Int64 右移/左移 `n` 位

-   `compare(rhs)`: 返回整数比较结果，就像
    **[String#localeCompare()](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/localeCompare)**

-   `toNumber()`: 将此 Int64 转换为数字

-   `toString([radix = 10])`: 转换为可选基数的字符串（默认为 10）


### UInt64

+   `new UInt64(v)`: 从 `v` 创建一个新的 UInt64，`v` 可以是数字或包含十进制值的字符串，
    如果以 "0x" 为前缀，则为十六进制。为了简洁起见，你可以使用 `uint64(v)` 简写。

-   `add(rhs)`, `sub(rhs)`,
    `and(rhs)`, `or(rhs)`,
    `xor(rhs)`:
    创建一个新的 UInt64，其值为此 UInt64 加/减/与/或/异或 `rhs`，`rhs` 可以是数字或另一个 UInt64

-   `shr(n)`, `shl(n)`:
    创建一个新的 UInt64，其值为此 UInt64 右移/左移 `n` 位

-   `compare(rhs)`: 返回整数比较结果，就像
    **[String#localeCompare()](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/localeCompare)**

-   `toNumber()`: 将此 UInt64 转换为数字

-   `toString([radix = 10])`: 转换为可选基数的字符串（默认为 10）


### NativePointer

+   `new NativePointer(s)`: 从字符串 `s` 创建一个新的 **[NativePointer](#nativepointer)**，
    该字符串包含十进制内存地址，如果以 '0x' 为前缀，则为十六进制。
    为了简洁起见，你可以使用 `ptr(s)` 简写。

-   `isNull()`: 返回一个布尔值，允许你方便地检查指针是否为 NULL

-   `add(rhs)`, `sub(rhs)`,
    `and(rhs)`, `or(rhs)`,
    `xor(rhs)`:
    创建一个新的 **[NativePointer](#nativepointer)**，其值为此 **[NativePointer](#nativepointer)**
    加/减/与/或/异或 `rhs`，`rhs` 可以是数字或另一个 **[NativePointer](#nativepointer)**

-   `shr(n)`, `shl(n)`:
    创建一个新的 **[NativePointer](#nativepointer)**，其值为此 **[NativePointer](#nativepointer)**
    右移/左移 `n` 位

-   `not()`: 创建一个新的 **[NativePointer](#nativepointer)**，其值为此 **[NativePointer](#nativepointer)** 的位取反

-   `sign([key, data])`: 通过获取此 **[NativePointer](#nativepointer)** 的位并添加指针身份验证位来创建新的
    **[NativePointer](#nativepointer)**，从而创建签名指针。如果当前进程不支持指针身份验证，则这是一个无操作，
    返回此 **[NativePointer](#nativepointer)** 而不是新值。
    {: #nativepointer-sign}

    可选地，可以将 `key` 指定为字符串。支持的值为：
    -   ia: IA 密钥，用于签署代码指针。这是默认值。
    -   ib: IB 密钥，用于签署代码指针。
    -   da: DA 密钥，用于签署数据指针。
    -   db: DB 密钥，用于签署数据指针。

    `data` 参数也可以指定为 **[NativePointer](#nativepointer)**/类数字值，
    以提供用于签名的额外数据，默认为 `0`。

-   `strip([key])`: 通过获取此 **[NativePointer](#nativepointer)** 的位并移除其指针身份验证位来创建新的
    **[NativePointer](#nativepointer)**，从而创建原始指针。
    如果当前进程不支持指针身份验证，则这是一个无操作，返回此 **[NativePointer](#nativepointer)** 而不是新值。

    可选地，可以传递 `key` 以指定用于签署被剥离指针的密钥。默认为 `ia`。
    （有关支持的值，请参阅 [`sign()`](#nativepointer-sign)。）

-   `blend(smallInteger)`: 通过获取此 **[NativePointer](#nativepointer)** 的位并将它们与常量混合来创建新的
    **[NativePointer](#nativepointer)**，该常量又可以作为 `data` 传递给 [`sign()`](#nativepointer-sign)。

-   `equals(rhs)`: 返回一个布尔值，指示 `rhs` 是否等于此指针；即它具有相同的指针值

-   `compare(rhs)`: 返回整数比较结果，就像
    **[String#localeCompare()](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/localeCompare)**

-   `toInt32()`: 将此 **[NativePointer](#nativepointer)** 转换为有符号 32 位整数

-   `toString([radix = 16])`: 转换为可选基数的字符串（默认为 16）

-   `toMatchPattern()`: 返回一个包含此指针原始值的 [`Memory.scan()`](#memory-scan) 兼容匹配模式的字符串

-   `readPointer()`: 从此内存位置读取 [`NativePointer`](#nativepointer)。

    如果地址不可读，将抛出 JavaScript 异常。

-   `writePointer(ptr)`: 将 `ptr` 写入此内存位置。

    如果地址不可写，将抛出 JavaScript 异常。

-   `readS8()`, `readU8()`,
    `readS16()`, `readU16()`,
    `readS32()`, `readU32()`,
    `readShort()`, `readUShort()`,
    `readInt()`, `readUInt()`,
    `readFloat()`, `readDouble()`:
    从此内存位置读取有符号或无符号 8/16/32/等或浮点/双精度值，并将其作为数字返回。

    如果地址不可读，将抛出 JavaScript 异常。

-   `writeS8(value)`, `writeU8(value)`,
    `writeS16(value)`, `writeU16(value)`,
    `writeS32(value)`, `writeU32(value)`,
    `writeShort(value)`, `writeUShort(value)`,
    `writeInt(value)`, `writeUInt(value)`,
    `writeFloat(value)`, `writeDouble(value)`:
    将有符号或无符号 8/16/32/等或浮点/双精度 `value` 写入此内存位置。

    如果地址不可写，将抛出 JavaScript 异常。

-   `readS64()`, `readU64()`,
    `readLong()`, `readULong()`:
    从此内存位置读取有符号或无符号 64 位或长整型值，并将其作为 **[Int64](#int64)**/**[UInt64](#uint64)** 值返回。

    如果地址不可读，将抛出 JavaScript 异常。

-   `writeS64(value)`, `writeU64(value)`,
    `writeLong(value)`, `writeULong(value)`:
    将 **[Int64](#int64)**/**[UInt64](#uint64)** `value` 写入此内存位置。

    如果地址不可写，将抛出 JavaScript 异常。

-   `readByteArray(length)`: 从此内存位置读取 `length` 字节，并将其作为 **[ArrayBuffer](#arraybuffer)** 返回。
    通过将其作为第二个参数传递给 [`send()`](#communication-send)，可以将此缓冲区有效地传输到基于 Frida 的应用程序。
    {: #nativepointer-readbytearray}

    如果从地址读取的 `length` 字节中的任何一个不可读，将抛出 JavaScript 异常。

-   `writeByteArray(bytes)`: 将 `bytes` 写入此内存位置，其中 `bytes` 要么是 **[ArrayBuffer](#arraybuffer)**
    （通常从 `readByteArray()` 返回），要么是 0 到 255 之间的整数数组。例如：`[ 0x13, 0x37, 0x42 ]`。
    {: #nativepointer-writebytearray}

    如果写入地址的任何字节不可写，将抛出 JavaScript 异常。

-   `readVolatile(length)`, `writeVolatile(bytes)`: 就像
    [`NativePointer#readByteArray`](#nativepointer-readbytearray) 和
    [`NativePointer#writeByteArray`](#nativepointer-writebytearray)，但在内存不可访问的情况下避免生成本机异常。
    这意味着内存访问速度较慢，因为涉及一个或多个系统调用，但在我们的本机异常处理失败或不可用且错误访问会导致进程崩溃的情况下可以安全使用。
    如果你在应用程序线程可能正在运行时转储内存，或者指针引用的内存可能不再可访问，请使用此 API。

-   `readCString([size = -1])`,
    `readUtf8String([size = -1])`,
    `readUtf16String([length = -1])`,
    `readAnsiString([size = -1])`:
    将此内存位置的字节读取为 ASCII、UTF-8、UTF-16 或 ANSI 字符串。
    如果你知道字符串的字节大小，请提供可选的 `size` 参数，或者如果字符串以 NUL 结尾，则省略它或指定 *-1*。
    同样，如果你知道字符串的字符长度，你可以提供可选的 `length` 参数。

    如果从地址读取的 `size` / `length` 字节中的任何一个不可读，将抛出 JavaScript 异常。

    请注意，`readAnsiString()` 仅在 Windows 上可用（且相关）。

-   `writeUtf8String(str)`,
    `writeUtf16String(str)`,
    `writeAnsiString(str)`:
    将 JavaScript 字符串编码并写入此内存位置（带有 NUL 终止符）。

    如果写入地址的任何字节不可写，将抛出 JavaScript 异常。

    请注意，`writeAnsiString()` 仅在 Windows 上可用（且相关）。


### ArrayBuffer

+   `wrap(address, size)`: 创建一个由现有内存区域支持的 ArrayBuffer，其中 `address` 是指定区域基地址的
    [`NativePointer`](#nativepointer)，`size` 是指定其大小的数字。
    与 [`NativePointer`](#nativepointer) 读/写 API 不同，访问时不执行验证，这意味着错误的指针会导致进程崩溃。

-   `unwrap()`: 返回指定 ArrayBuffer 后备存储基地址的 [`NativePointer`](#nativepointer)。
    调用者有责任在后备存储仍在使用时保持缓冲区处于活动状态。


### NativeFunction

+   `new NativeFunction(address, returnType, argTypes[, abi])`: 创建一个新的 NativeFunction 来调用 `address`
    （用 [`NativePointer`](#nativepointer) 指定）处的函数，其中 `returnType` 指定返回类型，
    `argTypes` 数组指定参数类型。如果不是系统默认值，你还可以选择指定 `abi`。
    对于可变参数函数，在固定参数和可变参数之间向 `argTypes` 添加一个 `'...'` 条目。

    - #### 按值传递的结构体和类

        对于按值传递的结构体或类，提供一个包含结构体字段类型的数组，而不是字符串。
        你可以根据需要嵌套这些数组以表示结构体内的结构体。
        请注意，返回的对象也是一个 [`NativePointer`](#nativepointer)，因此可以传递给 [`Interceptor#attach`](#interceptor-attach)。

        这必须与结构体/类完全匹配，因此如果你有一个包含三个 int 的结构体，你必须传递 `['int', 'int', 'int']`。

        对于具有虚方法的类，第一个字段将是指向 **[vtable](https://en.wikipedia.org/wiki/Virtual_method_table)** 的指针。

        对于涉及返回值大于 [`Process.pointerSize`](#process-pointersize) 的 C++ 场景，
        典型的 ABI 可能期望必须将指向预分配空间的 [`NativePointer`](#nativepointer) 作为第一个参数传入。
        （例如，这种情况在 WebKit 中很常见。）

    - #### 支持的类型
        -   void
        -   pointer
        -   int
        -   uint
        -   long
        -   ulong
        -   char
        -   uchar
        -   size_t
        -   ssize_t
        -   float
        -   double
        -   int8
        -   uint8
        -   int16
        -   uint16
        -   int32
        -   uint32
        -   int64
        -   uint64
        -   bool

    - #### 支持的 ABI
        -   default
        -   Windows 32-bit:
            -   sysv
            -   stdcall
            -   thiscall
            -   fastcall
            -   mscdecl
        - Windows 64-bit:
            -   win64
        - UNIX x86:
            -   sysv
            -   unix64
        - UNIX ARM:
            -   sysv
            -   vfp

+   `new NativeFunction(address, returnType, argTypes[, options])`: 就像前一个构造函数，
    但第四个参数 `options` 是一个对象，可能包含以下一个或多个键：

    -   `abi`: 与上面的枚举相同。
    -   `scheduling`: 调度行为作为字符串。支持的值为：
        -   cooperative: 允许其他线程在调用本机函数时执行 JavaScript 代码，即在调用之前释放锁，并在之后重新获取它。
                         这是默认行为。
        -   exclusive: 不允许其他线程在调用本机函数时执行 JavaScript 代码，即保持持有 JavaScript 锁。
                       这更快，但可能导致死锁。
    -   `exceptions`: 异常行为作为字符串。支持的值为：
        -   steal: 如果调用的函数生成本机异常，例如通过解引用无效指针，Frida 将展开堆栈并窃取异常，
                   将其转换为可以处理的 JavaScript 异常。这可能会使应用程序处于未定义状态，
                   但在实验时避免进程崩溃很有用。
                   这是默认行为。
        -   propagate: 让应用程序处理函数调用期间发生的任何本机异常。（或者，通过
                       [`Process.setExceptionHandler()`](#process-setexceptionhandler) 安装的处理程序。）
    -   `traps`: 要启用的代码陷阱，作为字符串。支持的值为：
        -   default: 如果函数调用触发了任何钩子，则将调用 **[Interceptor.attach()](#interceptor-attach)** 回调。
        -   none: 防止 **[Interceptor](#interceptor)** 和 **[Stalker](#stalker)** 触发。
        -   all: 除了 **[Interceptor](#interceptor)** 回调之外，**[Stalker](#stalker)**
                 也可能在每个函数调用期间暂时重新激活。这对于例如在引导模糊器时测量代码覆盖率、
                 在调试器中实现“步入”等非常有用。
                 请注意，在使用 **[Java](#java)** 和 **[ObjC](#objc)** API 时这也是可能的，
                 因为方法包装器也提供了一个 `clone(options)` API 来创建具有自定义 NativeFunction 选项的新方法包装器。


### NativeCallback

+   `new NativeCallback(func, returnType, argTypes[, abi])`: 创建一个由 JavaScript 函数 `func` 实现的新 NativeCallback，
    其中 `returnType` 指定返回类型，`argTypes` 数组指定参数类型。如果不是系统默认值，你也可以指定 abi。
    有关支持的类型和 abi 的详细信息，请参阅 [`NativeFunction`](#nativefunction)。
    请注意，返回的对象也是一个 [`NativePointer`](#nativepointer)，因此可以传递给 [`Interceptor#replace`](#interceptor-replace)。
    当将结果回调与 **[Interceptor.replace()](#interceptor-replace)** 一起使用时，
    `func` 将被调用，`this` 绑定到一个具有一些有用属性的对象，就像 **[Interceptor.attach()](#interceptor-attach)** 中的那个一样。


### SystemFunction

+   `new SystemFunction(address, returnType, argTypes[, abi])`: 就像 [`NativeFunction`](#nativefunction)，
    但也提供线程最后错误状态的快照。返回值是一个将实际返回值包装为 `value` 的对象，
    带有一个名为 `errno` (UNIX) 或 `lastError` (Windows) 的附加平台特定字段。

+   `new SystemFunction(address, returnType, argTypes[, options])`: 与上面相同，
    但接受像 [`NativeFunction`](#nativefunction) 的相应构造函数一样的 `options` 对象。

---

## 网络


### Socket

+   `Socket.listen([options])`: 打开一个 TCP 或 UNIX 监听套接字。返回一个接收 **[SocketListener](#socketlistener)** 的 *Promise*。

    默认情况下，如果支持，则监听 IPv4 和 IPv6，并在随机选择的 TCP 端口上绑定所有接口。

    可选的 `options` 参数是一个对象，可能包含以下一些键：

    -   `family`: 地址族作为字符串。支持的值为：
        -   unix
        -   ipv4
        -   ipv6
        如果支持，默认为监听 `ipv4` 和 `ipv6`。
    -   `host`: (IP family) IP 地址作为字符串。默认为所有接口。
    -   `port`: (IP family) IP 端口作为数字。默认为任何可用端口。
    -   `type`: (UNIX family) UNIX 套接字类型作为字符串。支持的类型为：
        -   anonymous
        -   path
        -   abstract
        -   abstract-padded
        默认为 `path`。
    -   `path`: (UNIX family) UNIX 套接字路径作为字符串。
    -   `backlog`: 监听积压作为数字。默认为 `10`。

+   `Socket.connect(options)`: 连接到 TCP 或 UNIX 服务器。返回一个接收 **[SocketConnection](#socketconnection)** 的 *Promise*。

    `options` 参数是一个对象，应包含以下一些键：

    -   `family`: 地址族作为字符串。支持的值为：
        -   unix
        -   ipv4
        -   ipv6
        默认为取决于指定的 `host` 的 IP 族。
    -   `host`: (IP family) IP 地址作为字符串。默认为 `localhost`。
    -   `port`: (IP family) IP 端口作为数字。
    -   `type`: (UNIX family) UNIX 套接字类型作为字符串。支持的类型为：
        -   anonymous
        -   path
        -   abstract
        -   abstract-padded
        默认为 `path`。
    -   `path`: (UNIX family) UNIX 套接字路径作为字符串。

+   `Socket.type(handle)`: 检查 OS 套接字 `handle` 并将其类型作为字符串返回，
    该字符串为 `tcp`、`udp`、`tcp6`、`udp6`、`unix:stream`、`unix:dgram`，
    如果无效或未知，则为 `null`。

+   `Socket.localAddress(handle)`,
    `Socket.peerAddress(handle)`:
    检查 OS 套接字 `handle` 并返回其本地或对等地址，如果无效或未知，则返回 `null`。

    返回的对象具有以下字段：

    -   `ip`: (IP sockets) IP 地址作为字符串。
    -   `port`: (IP sockets) IP 端口作为数字。
    -   `path`: (UNIX sockets) UNIX 路径作为字符串。


### SocketListener

所有方法都是完全异步的并返回 Promise 对象。<br/><br/>

-   `path`: (UNIX family) 正在监听的路径。

-   `port`: (IP family) 正在监听的 IP 端口。

-   `close()`: 关闭监听器，释放与其相关的资源。一旦监听器关闭，所有其他操作都将失败。
    允许多次关闭监听器，并且不会导致错误。

-   `accept()`: 等待下一个客户端连接。返回的 *Promise* 接收一个 **[SocketConnection](#socketconnection)**。


### SocketConnection

继承自 **[IOStream](#iostream)**。
所有方法都是完全异步的并返回 Promise 对象。<br/><br/>

-   `setNoDelay(noDelay)`: 如果 `noDelay` 为 `true`，则禁用 Nagle 算法，否则启用它。
    Nagle 算法默认启用，因此仅当你希望优化低延迟而不是高吞吐量时才需要调用此方法。

---

## 文件和流


### File

+   `File.readAllBytes(path)`: 同步读取 `path` 指定的文件中的所有字节，并将其作为 `ArrayBuffer` 返回。

+   `File.readAllText(path)`: 同步读取 `path` 指定的文件中的所有文本，并将其作为字符串返回。
    文件必须是 UTF-8 编码的，如果不是这种情况，将抛出异常。

+   `File.writeAllBytes(path, data)`: 同步将 `data` 写入 `path` 指定的文件，其中 `data` 是一个 `ArrayBuffer`。

+   `File.writeAllText(path, text)`: 同步将 `text` 写入 `path` 指定的文件，其中 `text` 是一个字符串。
    文件将是 UTF-8 编码的。

+   `new File(filePath, mode)`: 打开或创建 `filePath` 处的文件，`mode` 字符串指定应如何打开它。
    例如 `"wb"` 以二进制模式打开文件进行写入（这与 C 标准库中的 `fopen()` 格式相同）。

-   `tell()`: 返回文件指针在文件中的当前位置。

-   `seek(offset[, whence])`: 将文件指针移动到新位置。`offset` 是要移动到的位置，
    `whence` 是偏移量的起始点（`File.SEEK_SET` 表示文件开头，`File.SEEK_CUR` 表示当前文件位置，
    或 `File.SEEK_END` 表示文件末尾）。

-   `readBytes([size])`: 从当前文件指针位置开始从文件中读取并返回 `size` 字节作为 `ArrayBuffer`。
    如果未指定 `size`，则从当前位置读取直到文件末尾。

-   `readText([size])`: 从当前文件指针位置开始从文件中读取并返回 `size` 个字符作为字符串。
    如果未指定 `size`，则从当前位置读取文本直到文件末尾。
    正在读取的字节必须是 UTF-8 编码的，如果不是这种情况，将抛出异常。

-   `readLine()`: 读取并返回下一行作为字符串。从当前文件指针位置开始读取。返回的行不包括换行符。

-   `write(data)`: 同步将 `data` 写入文件，其中 `data` 是字符串或由
    [`NativePointer#readByteArray`](#nativepointer-readbytearray) 返回的缓冲区。

-   `flush()`: 将任何缓冲数据刷新到底层文件。

-   `close()`: 关闭文件。你应该在完成文件操作后调用此函数，除非你不介意在对象被垃圾回收或脚本卸载时发生这种情况。


### IOStream

所有方法都是完全异步的并返回 Promise 对象。<br/><br/>

-   `input`: 要从中读取的 **[InputStream](#inputstream)**。

-   `output`: 要写入的 **[OutputStream](#outputstream)**。

-   `close()`: 关闭流，释放与其相关的资源。这也将关闭单独的输入和输出流。
    一旦流关闭，所有其他操作都将失败。允许多次关闭流，并且不会导致错误。


### InputStream

所有方法都是完全异步的并返回 Promise 对象。<br/><br/>

-   `close()`: 关闭流，释放与其相关的资源。一旦流关闭，所有其他操作都将失败。
    允许多次关闭流，并且不会导致错误。

-   `read(size)`: 从流中读取最多 `size` 字节。返回的 **Promise** 接收一个最长为 `size` 字节的
    **[ArrayBuffer](#arraybuffer)**。流的结束通过空缓冲区发出信号。

-   `readAll(size)`: 继续从流中读取，直到正好消耗了 `size` 字节。返回的 *Promise* 接收一个正好
    `size` 字节长的 **[ArrayBuffer](#arraybuffer)**。过早错误或流结束会导致 *Promise* 被拒绝并显示错误，
    其中 `Error` 对象具有包含不完整数据的 `partialData` 属性。


### OutputStream

所有方法都是完全异步的并返回 Promise 对象。<br/><br/>

-   `close()`: 关闭流，释放与其相关的资源。一旦流关闭，所有其他操作都将失败。
    允许多次关闭流，并且不会导致错误。

-   `write(data)`: 尝试将 `data` 写入流。`data` 值要么是 **[ArrayBuffer](#arraybuffer)**，
    要么是 0 到 255 之间的整数数组。返回的 *Promise* 接收一个 *Number*，指定有多少字节的 `data` 已写入流。

-   `writeAll(data)`: 继续写入流，直到所有 `data` 都已写入。`data` 值要么是 **[ArrayBuffer](#arraybuffer)**，
    要么是 0 到 255 之间的整数数组。过早错误或流结束会导致错误，其中 `Error` 对象具有 `partialSize` 属性，
    指定在发生错误之前有多少字节的 `data` 已写入流。

-   `writeMemoryRegion(address, size)`: 尝试将 `size` 字节写入流，从 `address` 读取它们，
    `address` 是一个 [`NativePointer`](#nativepointer)。返回的 *Promise* 接收一个 *Number*，
    指定有多少字节的 `data` 已写入流。


### UnixInputStream

(仅在类 UNIX 操作系统上可用。)<br/><br/>

+   `new UnixInputStream(fd[, options])`: 从指定的文件描述符 `fd` 创建一个新的 **[InputStream](#inputstream)**。

    你也可以提供一个 `options` 对象，其中 `autoClose` 设置为 `true`，以使流在释放时（通过 `close()` 或未来的垃圾回收）
    关闭底层文件描述符。


### UnixOutputStream

(仅在类 UNIX 操作系统上可用。)<br/><br/>

+   `new UnixOutputStream(fd[, options])`: 从指定的文件描述符 `fd` 创建一个新的 **[OutputStream](#outputstream)**。

    你也可以提供一个 `options` 对象，其中 `autoClose` 设置为 `true`，以使流在释放时（通过 `close()` 或未来的垃圾回收）
    关闭底层文件描述符。


### Win32InputStream

(仅在 Windows 上可用。)<br/><br/>

+   `new Win32InputStream(handle[, options])`: 从指定的 `handle` 创建一个新的 **[InputStream](#inputstream)**，
    `handle` 是一个 Windows *HANDLE* 值。

    你也可以提供一个 `options` 对象，其中 `autoClose` 设置为 `true`，以使流在释放时（通过 `close()` 或未来的垃圾回收）
    关闭底层句柄。


### Win32OutputStream

(仅在 Windows 上可用。)<br/><br/>

+   `new Win32OutputStream(handle[, options])`: 从指定的 `handle` 创建一个新的 **[OutputStream](#outputstream)**，
    `handle` 是一个 Windows *HANDLE* 值。

    你也可以提供一个 `options` 对象，其中 `autoClose` 设置为 `true`，以使流在释放时（通过 `close()` 或未来的垃圾回收）
    关闭底层句柄。


## 数据库


### SqliteDatabase

+   `SqliteDatabase.open(path[, options])`: 打开由 `path` 指定的 SQLite v3 数据库，
    `path` 是包含数据库文件系统路径的字符串。默认情况下，数据库将以读写方式打开，
    但你可以通过提供一个 `options` 对象来自定义此行为，该对象具有名为 `flags` 的属性，
    指定包含以下一个或多个值的字符串数组：`readonly`、`readwrite`、`create`。
    返回的 SqliteDatabase 对象将允许你对数据库执行查询。

+   `SqliteDatabase.openInline(encodedContents)`: 就像 `open()`，但数据库的内容作为包含其数据的字符串提供，
    Base64 编码。我们建议在 Base64 编码之前对数据库进行 gzip 压缩，但这是可选的，通过查找 gzip 魔术标记来检测。
    数据库以读写方式打开，但是 100% 在内存中，从不接触文件系统。这对于需要捆绑预计算数据缓存的代理非常有用，
    例如用于指导动态分析的静态分析数据。
    {: #sqlitedatabase-openinline}

-   `close()`: 关闭数据库。你应该在完成数据库操作后调用此函数，除非你不介意在对象被垃圾回收或脚本卸载时发生这种情况。

-   `exec(sql)`: 执行原始 SQL 查询，其中 `sql` 是包含查询文本表示的字符串。
    查询的结果被忽略，因此这应该仅用于设置数据库的查询，例如表创建。

-   `prepare(sql)`: 将提供的 SQL 编译为 **[SqliteStatement](#sqlitestatement)** 对象，
    其中 `sql` 是包含查询文本表示的字符串。

    例如：

{% highlight js %}
const db = SqliteDatabase.open('/path/to/people.db');

const smt = db.prepare('SELECT name, bio FROM people WHERE age = ?');

console.log('People whose age is 42:');
smt.bindInteger(1, 42);
let row;
while ((row = smt.step()) !== null) {
  const [name, bio] = row;
  console.log('Name:', name);
  console.log('Bio:', bio);
}
smt.reset();
{% endhighlight %}

-   `dump()`: 将数据库转储为 Base64 编码的 gzip 压缩 blob，结果作为字符串返回。
    这对于在代理代码中内联缓存非常有用，通过调用 [`SqliteDatabase.openInline()`](#sqlitedatabase-openinline) 加载。


### SqliteStatement

-   `bindInteger(index, value)`: 将整数 `value` 绑定到 `index`
-   `bindFloat(index, value)`: 将浮点数 `value` 绑定到 `index`
-   `bindText(index, value)`: 将文本 `value` 绑定到 `index`
-   `bindBlob(index, bytes)`: 将 blob `bytes` 绑定到 `index`，其中 `bytes` 是
    **[ArrayBuffer](#arraybuffer)**、字节值数组或字符串
-   `bindNull(index)`: 将空值绑定到 `index`
-   `step()`: 要么开始新查询并获取第一个结果，要么移动到下一个结果。
    返回一个包含按查询指定顺序排列的值的数组，或者当达到最后一个结果时返回 `null`。
    如果你打算再次使用此对象，则应在那时调用 `reset()`。
-   `reset()`: 重置内部状态以允许后续查询

---

## 插桩


### Interceptor

+   `Interceptor.attach(target, callbacks[, data])`: 拦截对 `target` 处函数的调用。
    这是一个 [`NativePointer`](#nativepointer)，指定你想要拦截调用的函数的地址。
    请注意，在 32 位 ARM 上，对于 ARM 函数，此地址的最低有效位必须设置为 0，对于 Thumb 函数，必须设置为 1。
    如果你从 Frida API（例如 [`Module#getExportByName()`](#module-getexportbyname)）获取地址，Frida 会为你处理此细节。
    {: #interceptor-attach}

    `callbacks` 参数是一个包含以下一个或多个属性的对象：

    -   `onEnter(args)`: 给定一个参数 `args` 的回调函数，该参数可用于读取或写入参数，
        作为 [`NativePointer`](#nativepointer) 对象数组。 {: #interceptor-onenter}

    -   `onLeave(retval)`: 给定一个参数 `retval` 的回调函数，该参数是包含原始返回值的
        [`NativePointer`](#nativepointer) 派生对象。
        你可以调用 `retval.replace(1337)` 将返回值替换为整数 `1337`，
        或者调用 `retval.replace(ptr("0x1234"))` 将其替换为指针。
        请注意，此对象在 *onLeave* 调用之间被回收，因此不要在回调之外存储和使用它。
        如果你需要存储包含的值，请进行深层复制，例如：`ptr(retval.toString())`。
        {: #interceptor-onleave}

    如果被钩住的函数非常热，`onEnter` 和 `onLeave` 可以是指向使用 **[CModule](#cmodule)** 编译的
    本机 C 函数的 [`NativePointer`](#nativepointer) 值。它们的签名是：

    -   `void onEnter (GumInvocationContext * ic)`

    -   `void onLeave (GumInvocationContext * ic)`

    在这种情况下，第三个可选参数 `data` 可以是一个 [`NativePointer`](#nativepointer)，
    可以通过 `gum_invocation_context_get_listener_function_data()` 访问。

    你也可以通过传递一个函数而不是 `callbacks` 对象来拦截任意指令。此函数具有与 `onEnter` 相同的签名，
    但传递给它的 `args` 参数只有在被拦截的指令位于函数开头或寄存器/堆栈尚未偏离该点的位置时才会给你合理的值。

    就像上面一样，此函数也可以通过指定 [`NativePointer`](#nativepointer) 而不是函数来用 C 实现。

    返回一个你可以调用 `detach()` 的监听器对象。

    请注意，这些函数在调用时，`this` 会绑定到一个每次调用（线程本地）的对象，你可以在其中存储任意数据，
    如果你想在 `onEnter` 中读取参数并在 `onLeave` 中对其采取行动，这很有用。

    例如：

{% highlight js %}
const libc = Process.getModuleByName('libc.so');
Interceptor.attach(libc.getExportByName('read'), {
  onEnter(args) {
    this.fileDescriptor = args[0].toInt32();
  },
  onLeave(retval) {
    if (retval.toInt32() > 0) {
      /* do something with this.fileDescriptor */
    }
  }
});
{% endhighlight %}

+   此外，该对象包含一些有用的属性：

    -   `returnAddress`: 返回地址作为 **[NativePointer](#nativepointer)**

    -   `context`: 具有键 `pc` 和 `sp` 的对象，它们是指定 EIP/RIP/PC 和 ESP/RSP/SP 的
        **[NativePointer](#nativepointer)** 对象，分别用于 ia32/x64/arm。
        其他特定于处理器的键也可用，例如 `eax`, `rax`, `r0`, `x0` 等。
        你也可以通过分配给这些键来更新寄存器值。

    -   `errno`: (UNIX) 当前 errno 值（你可以替换它）

    -   `lastError`: (Windows) 当前操作系统错误值（你可以替换它）

    -   `threadId`: 操作系统线程 ID

    -   `depth`: 相对于其他调用的调用深度

    例如：

{% highlight js %}
Interceptor.attach(Module.getGlobalExportByName('read'), {
  onEnter(args) {
    console.log('Context information:');
    console.log('Context  : ' + JSON.stringify(this.context));
    console.log('Return   : ' + this.returnAddress);
    console.log('ThreadId : ' + this.threadId);
    console.log('Depth    : ' + this.depth);
    console.log('Errornr  : ' + this.err);

    // Save arguments for processing in onLeave.
    this.fd = args[0].toInt32();
    this.buf = args[1];
    this.count = args[2].toInt32();
  },
  onLeave(result) {
    console.log('----------')
    // Show argument 1 (buf), saved during onEnter.
    const numBytes = result.toInt32();
    if (numBytes > 0) {
      console.log(hexdump(this.buf, { length: numBytes, ansi: true }));
    }
    console.log('Result   : ' + numBytes);
  }
})
{% endhighlight %}

<div class="note">
  <h5>性能注意事项</h5>
  <p>
    提供的回调对性能有重大影响。如果你只需要检查参数但不关心返回值，或者反过来，
    请确保省略你不需要的回调；即避免将你的逻辑放在 <i>onEnter</i> 中并将 <i>onLeave</i> 留在那儿作为一个空回调。
  </p>
  <p>
    在 iPhone 5S 上，仅提供 <i>onEnter</i> 时的基本开销可能约为 6 微秒，
    而同时提供 <i>onEnter</i> 和 <i>onLeave</i> 时约为 11 微秒。
  </p>
  <p markdown="1">
    还要注意拦截对每秒调用无数次的函数的调用；虽然 **[send()](#communication-send)** 是异步的，
    但发送单个消息的总开销并未针对高频进行优化，因此这意味着 Frida 让你根据需要低延迟还是高吞吐量，
    自行决定将多个值批处理到单个 **[send()](#communication-send)** 调用中。
  </p>
  <p markdown="1">
    但是，当钩住热函数时，你可以将 Interceptor 与 **[CModule](#cmodule)** 结合使用以在 C 中实现回调。
  </p>
</div>

+   `Interceptor.detachAll()`: 分离所有先前附加的回调。

+   `Interceptor.replace(target, replacement[, data])`: 用 `replacement` 处的实现替换 `target` 处的函数。
    如果你想完全或部分替换现有函数的实现，通常使用此方法。
    {: #interceptor-replace}

    使用 [`NativeCallback`](#nativecallback) 在 JavaScript 中实现 `replacement`。

    如果被替换的函数非常热，你可以使用 **[CModule](#cmodule)** 在 C 中实现 `replacement`。
    然后你也可以指定第三个可选参数 `data`，这是一个可以通过 `gum_invocation_context_get_listener_function_data()`
    访问的 [`NativePointer`](#nativepointer)。使用 `gum_interceptor_get_current_invocation()` 获取 `GumInvocationContext *`。

    请注意，`replacement` 将保持活动状态，直到调用 [`Interceptor#revert`](#interceptor-revert)。

    如果你想链接到原始实现，你可以在你的实现中通过 [`NativeFunction`](#nativefunction) 同步调用 `target`，
    这将绕过并直接转到原始实现。

    这是一个例子：

{% highlight js %}
const libc = Process.getModuleByName('libc.so');
const openPtr = libc.getExportByName('open');
const open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);
Interceptor.replace(openPtr, new NativeCallback((pathPtr, flags) => {
  const path = pathPtr.readUtf8String();
  log('Opening "' + path + '"');
  const fd = open(pathPtr, flags);
  log('Got fd: ' + fd);
  return fd;
}, 'int', ['pointer', 'int']));
{% endhighlight %}

+   `Interceptor.replaceFast(target, replacement)`: 就像 [`replace()`](#interceptor-replace)，
    除了 `target` 被修改为直接跳转到你的替换，这意味着与 replace() 相比开销更小。
    这也意味着如果你想调用原始实现，你需要使用返回的指针。

+   `Interceptor.revert(target)`: 将 `target` 处的函数恢复为先前的实现。
    {: #interceptor-revert}

+   `Interceptor.flush()`: 确保任何挂起的更改已提交到内存。这应该仅在极少数必要的情况下完成，
    例如，如果你刚刚 **[attach()](#interceptor-attach)** 或 **[replace()](#interceptor-replace)** 了一个
    你即将使用 **[NativeFunction](#nativefunction)** 调用的函数。
    每当当前线程即将离开 JavaScript 运行时或调用 **[send()](#communication-send)** 时，挂起的更改都会自动刷新。
    这包括构建在 **[send()](#communication-send)** 之上的任何 API，例如从 **[RPC](#rpc-exports)** 方法返回时，
    以及调用 **[console](#console)** API 上的任何方法。

+   `Interceptor.breakpointKind`: 指定用于非内联钩子的断点类型的字符串。仅在 Barebone 后端可用。

    默认为 'soft'，即软件断点。将其设置为 'hard' 以使用硬件断点。


### Stalker

+   `Stalker.exclude(range)`: 将指定的内存 `range` 标记为排除，该对象具有 `base` 和 `size` 属性——
    就像例如 [`Process.getModuleByName()`](#process-getmodulebyname) 返回的对象中的属性一样。

    这意味着当遇到对该范围内指令的调用时，Stalker 将不会跟踪执行。
    因此，你将能够观察/修改进入的参数和返回的返回值，但不会看到其间发生的指令。

    对于提高性能和减少噪音很有用。

+   `Stalker.follow([threadId, options])`: 开始跟踪 `threadId`（如果省略，则为当前线程），
    可选地使用 `options` 启用事件。
    {: #stalker-follow}

    例如：

{% highlight js %}
const mainThread = Process.enumerateThreads()[0];

Stalker.follow(mainThread.id, {
  events: {
    call: true, // CALL instructions: yes please

    // Other events:
    ret: false, // RET instructions
    exec: false, // all instructions: not recommended as it's
                 //                   a lot of data
    block: false, // block executed: coarse execution trace
    compile: false // block compiled: useful for coverage
  },

  //
  // Only specify one of the two following callbacks.
  // (See note below.)
  //

  //
  // onReceive: Called with `events` containing a binary blob
  //            comprised of one or more GumEvent structs.
  //            See `gumevent.h` for details about the
  //            format. Use `Stalker.parse()` to examine the
  //            data.
  //
  //onReceive(events) {
  //},
  //

  //
  // onCallSummary: Called with `summary` being a key-value
  //                mapping of call target to number of
  //                calls, in the current time window. You
  //                would typically implement this instead of
  //                `onReceive()` for efficiency, i.e. when
  //                you only want to know which targets were
  //                called and how many times, but don't care
  //                about the order that the calls happened
  //                in.
  //
  //onCallSummary(summary) {
  //},

  //
  // Advanced users: This is how you can plug in your own
  //                 StalkerTransformer, where the provided
  //                 function is called synchronously
  //                 whenever Stalker wants to recompile
  //                 a basic block of the code that's about
  //                 to be executed by the stalked thread.
  //
  //transform(iterator) {
  //  let instruction = iterator.next();
  //
  //  const startAddress = instruction.address;
  //  const isAppCode = startAddress.compare(appStart) >= 0 &&
  //      startAddress.compare(appEnd) === -1;
  //
  //  /*
  //   * Need to be careful on ARM/ARM64 as we may disturb instruction sequences
  //   * that deal with exclusive stores.
  //   */
  //  const canEmitNoisyCode = iterator.memoryAccess === 'open';
  //
  //  do {
  //    if (isAppCode && canEmitNoisyCode && instruction.mnemonic === 'ret') {
  //      iterator.putCmpRegI32('eax', 60);
  //      iterator.putJccShortLabel('jb', 'nope', 'no-hint');
  //
  //      iterator.putCmpRegI32('eax', 90);
  //      iterator.putJccShortLabel('ja', 'nope', 'no-hint');
  //
  //      iterator.putCallout(onMatch);
  //
  //      iterator.putLabel('nope');
  //
  //      /* You may also use putChainingReturn() to insert an early return. */
  //    }
  //
  //    iterator.keep();
  //  } while ((instruction = iterator.next()) !== null);
  //},
  //
  // The default implementation is just:
  //
  //   while (iterator.next() !== null)
  //     iterator.keep();
  //
  // The example above shows how you can insert your own code
  // just before every `ret` instruction across any code
  // executed by the stalked thread inside the app's own
  // memory range. It inserts code that checks if the `eax`
  // register contains a value between 60 and 90, and inserts
  // a synchronous callout back into JavaScript whenever that
  // is the case. The callback receives a single argument
  // that gives it access to the CPU registers, and it is
  // also able to modify them.
  //
  // function onMatch (context) {
  //   console.log('Match! pc=' + context.pc +
  //       ' rax=' + context.rax.toInt32());
  // }
  //
  // Note that not calling keep() will result in the
  // instruction getting dropped, which makes it possible
  // for your transform to fully replace certain instructions
  // when this is desirable.
  //

  //
  // Want better performance? Write the callbacks in C:
  //
  // /*
  //  * const cm = new CModule(\`
  //  *
  //  * #include <gum/gumstalker.h>
  //  *
  //  * static void on_ret (GumCpuContext * cpu_context,
  //  *     gpointer user_data);
  //  *
  //  * void
  //  * transform (GumStalkerIterator * iterator,
  //  *            GumStalkerOutput * output,
  //  *            gpointer user_data)
  //  * {
  //  *   cs_insn * insn;
  //  *
  //  *   while (gum_stalker_iterator_next (iterator, &insn))
  //  *   {
  //  *     if (insn->id == X86_INS_RET)
  //  *     {
  //  *       gum_x86_writer_put_nop (output->writer.x86);
  //  *       gum_stalker_iterator_put_callout (iterator,
  //  *           on_ret, NULL, NULL);
  //  *     }
  //  *
  //  *     gum_stalker_iterator_keep (iterator);
  //  *   }
  //  * }
  //  *
  //  * static void
  //  * on_ret (GumCpuContext * cpu_context,
  //  *         gpointer user_data)
  //  * {
  //  *   printf ("on_ret!\n");
  //  * }
  //  *
  //  * void
  //  * process (const GumEvent * event,
  //  *          GumCpuContext * cpu_context,
  //  *          gpointer user_data)
  //  * {
  //  *   switch (event->type)
  //  *   {
  //  *     case GUM_CALL:
  //  *       break;
  //  *     case GUM_RET:
  //  *       break;
  //  *     case GUM_EXEC:
  //  *       break;
  //  *     case GUM_BLOCK:
  //  *       break;
  //  *     case GUM_COMPILE:
  //  *       break;
  //  *     default:
  //  *       break;
  //  *   }
  //  * }
  //  * `);
  //  */
  //
  //transform: cm.transform,
  //onEvent: cm.process,
  //data: ptr(1337) /* user_data */
  //
  // You may also use a hybrid approach and only write
  // some of the callouts in C.
  //
});
{% endhighlight %}

<div class="note">
  <h5>性能注意事项</h5>
  <p>
    提供的回调对性能有重大影响。如果你只需要定期调用摘要但不关心原始事件，或者反过来，
    请确保省略你不需要的回调；即避免将你的逻辑放在 <i>onCallSummary</i> 中并将
    <i>onReceive</i> 留在那儿作为一个空回调。
  </p>
  <p markdown="1">
    另请注意，Stalker 可以与 **[CModule](#cmodule)** 结合使用，这意味着回调可以用 C 实现。
  </p>
</div>

+   `Stalker.unfollow([threadId])`: 停止跟踪 `threadId`（如果省略，则为当前线程）。
    {: #stalker-unfollow}

+   `Stalker.parse(events[, options])`: 解析 GumEvent 二进制 blob，可选地使用 `options` 自定义输出。

    例如：

{% highlight js %}
  onReceive(events) {
    console.log(Stalker.parse(events, {
      annotate: true, // to display the type of event
      stringify: true
        // to format pointer values as strings instead of `NativePointer`
        // values, i.e. less overhead if you're just going to `send()` the
        // thing not actually parse the data agent-side
    }));
  },
{% endhighlight %}

+   `Stalker.flush()`: 刷新任何缓冲的事件。当你不想等到下一个 [`Stalker.queueDrainInterval`](#stalker-queuedraininterval) tick 时很有用。
    {: #stalker-flush}

+   `Stalker.garbageCollect()`: 在 [`Stalker#unfollow`](#stalker-unfollow) 之后的安全点释放累积的内存。
    这是为了避免刚刚取消跟踪的线程正在执行其最后指令的竞争条件所必需的。

+   `Stalker.invalidate(address)`: 使当前线程针对给定基本块的翻译代码无效。
    当提供转换回调并希望动态调整给定基本块的插桩时很有用。
    这比取消跟踪并重新跟踪线程要有效得多，后者会丢弃所有缓存的翻译并要求从头开始编译所有遇到的基本块。

+   `Stalker.invalidate(threadId, address)`: 使特定线程针对给定基本块的翻译代码无效。
    当提供转换回调并希望动态调整给定基本块的插桩时很有用。
    这比取消跟踪并重新跟踪线程要有效得多，后者会丢弃所有缓存的翻译并要求从头开始编译所有遇到的基本块。

+   `Stalker.addCallProbe(address, callback[, data])`: 当调用 `address` 时同步调用 `callback`
    （签名见 [`Interceptor#attach#onEnter`](#interceptor-attach)）。
    返回一个 id，稍后可以将其传递给 [`Stalker#removeCallProbe`](#stalker-removecallprobe)。
    {: #stalker-addcallprobe}

    也可以使用 **[CModule](#cmodule)** 在 C 中实现 `callback`，方法是指定 [`NativePointer`](#nativepointer) 而不是函数。签名：

    -   `void onCall (GumCallSite * site, gpointer user_data)`

    In such cases, the third optional argument `data` may be a [`NativePointer`](#nativepointer)
    whose value is passed to the callback as `user_data`.

+   `Stalker.removeCallProbe`: 移除由 [`Stalker#addCallProbe`](#stalker-addcallprobe) 添加的调用探测。
    {: #stalker-removecallprobe}

+   `Stalker.trustThreshold`: 一个整数，指定一段代码在被假定可以信任不会发生变异之前需要执行多少次。
    指定 -1 表示不信任（慢），0 表示从一开始就信任代码，N 表示在执行 N 次后信任代码。默认为 1。

+   `Stalker.queueCapacity`: 一个整数，指定事件队列的容量（以事件数为单位）。默认为 16384 个事件。

+   `Stalker.queueDrainInterval`: 一个整数，指定每次耗尽事件队列之间的时间（以毫秒为单位）。
    默认为 250 毫秒，这意味着事件队列每秒耗尽四次。你也可以将此属性设置为零以禁用定期耗尽，
    而是当你希望耗尽队列时调用 [`Stalker.flush()`](#stalker-flush)。
    {: #stalker-queuedraininterval}


### ObjC

<div class="note">
<h5>Moved</h5>
<p markdown="1">
    从 Frida 17 开始，此runtime bridge不再包含在 Frida 的 GumJS 运行时中，可以通过运行以下命令获取：`npm install frida-objc-bridge`。
    <br/>
    像这样将其导入到你的代理中：<br/>
    `import ObjC from 'frida-objc-bridge';`<br/>

    目前，在 Frida REPL 加载的脚本以及 frida-trace 中不需要这样做。
</p>
</div>

+   `ObjC.available`: 一个布尔值，指定当前进程是否加载了 Objective-C 运行时。
    除非是这种情况，否则不要调用任何其他 `ObjC` 属性或方法。
    {: #objc-available}

+   `ObjC.api`: 一个将函数名称映射到 [`NativeFunction`](#nativefunction) 实例的对象，
    用于直接访问大部分 Objective-C 运行时 API。

+   `ObjC.classes`: 一个将类名映射到每个当前注册类的 [`ObjC.Object`](#objc-object) JavaScript 绑定的对象。
    你可以通过使用点符号并将冒号替换为下划线来与对象交互，即：
    `[NSString stringWithString:@"Hello World"]`
    变成
    `const { NSString } = ObjC.classes; NSString.stringWithString_("Hello World");`。
    注意方法名后面的下划线。有关更多详细信息，请参阅 iOS 示例部分。
    {: #objc-classes}

+   `ObjC.protocols`: 一个将协议名称映射到每个当前注册协议的 [`ObjC.Protocol`](#objc-protocol) JavaScript 绑定的对象。

+   `ObjC.mainQueue`: 主线程的 GCD 队列

+   `ObjC.schedule(queue, work)`: 在 `queue` 指定的 GCD 队列上调度 JavaScript 函数 `work`。
    在调用 `work` 之前创建一个 `NSAutoreleasePool`，并在返回时清理。

{% highlight js %}
const { NSSound } = ObjC.classes; /* macOS */
ObjC.schedule(ObjC.mainQueue, () => {
    const sound = NSSound.alloc().initWithContentsOfFile_byReference_("/Users/oleavr/.Trash/test.mp3", true);
    sound.play();
});
{% endhighlight %}

+   <code id="objc-object">new ObjC.Object(handle[, protocol])</code>: 给定 `handle` 处的现有对象（一个 **[NativePointer](#nativepointer)**），
    创建一个 JavaScript 绑定。如果你想将 `handle` 视为仅实现特定协议的对象，你也可以指定 `protocol` 参数。

{% highlight js %}
Interceptor.attach(myFunction.implementation, {
  onEnter(args) {
    // ObjC: args[0] = self, args[1] = selector, args[2-n] = arguments
    const myString = new ObjC.Object(args[2]);
    console.log("String argument: " + myString.toString());
  }
});
{% endhighlight %}

>   此对象具有一些特殊属性：
>
>   -   `$kind`: 指定 `instance`、`class` 或 `meta-class` 的字符串
>   -   `$super`: 一个 **[ObjC.Object](#objc-object)** 实例，用于链接到超类方法实现
>   -   `$superClass`: 作为 **[ObjC.Object](#objc-object)** 实例的超类
>   -   `$class`: 此对象的类作为 **[ObjC.Object](#objc-object)** 实例
>   -   `$className`: 包含此对象类名的字符串
>   -   `$moduleName`: 包含此对象模块路径的字符串
>   -   `$protocols`: 将协议名称映射到此对象符合的每个协议的 [`ObjC.Protocol`](#objc-protocol) 实例的对象
>   -   `$methods`: 包含此对象类和父类公开的本机方法名称的数组
>   -   `$ownMethods`: 包含此对象类公开的本机方法名称的数组，不包括父类
>   -   `$ivars`: 将每个实例变量名称映射到其当前值的对象，允许你通过访问和赋值来读取和写入每个变量
>
>   还有一个 `equals(other)` 方法，用于检查两个实例是否引用同一个底层对象。
>
>   请注意，所有方法包装器都提供了一个 `clone(options)` API，用于创建具有自定义 **[NativeFunction](#nativefunction)** 选项的新方法包装器。

+   `new ObjC.Protocol(handle)`: 给定 `handle` 处的现有协议（一个 **[NativePointer](#nativepointer)**），
    创建一个 JavaScript 绑定。
    {: #objc-protocol}

+   `new ObjC.Block(target[, options])`: 给定 `target` 处的现有块（一个 **[NativePointer](#nativepointer)**）创建一个 JavaScript 绑定，
    或者，要定义一个新块，`target` 应该是一个指定类型签名和每当块被调用时要调用的 JavaScript 函数的对象。
    函数使用 `implementation` 键指定，签名通过 `types` 键或 `retType` 和 `argTypes` 键指定。
    有关详细信息，请参阅 [`ObjC.registerClass()`](#objc-registerclass)。

    请注意，如果现有块缺少签名元数据，你可以调用 `declare(signature)`，其中 `signature` 是一个具有 `types` 键
    或 `retType` 和 `argTypes` 键的对象，如上所述。

    你也可以提供一个 `options` 对象，其中包含 **[NativeFunction](#nativefunction)** 支持的相同选项，
    例如传递 `traps: 'all'` 以便在调用块时 [`Stalker.follow()`](#stalker-follow) 执行。

    最常见的用例是钩住现有块，对于期望两个参数的块，它看起来像这样：

{% highlight js %}
const pendingBlocks = new Set();

Interceptor.attach(..., {
  onEnter(args) {
    const block = new ObjC.Block(args[4]);
    pendingBlocks.add(block); // Keep it alive
    const appCallback = block.implementation;
    block.implementation = (error, value) => {
      // Do your logging here
      const result = appCallback(error, value);
      pendingBlocks.delete(block);
      return result;
    };
  }
});
{% endhighlight %}

+   `ObjC.implement(method, fn)`: 创建一个与 `method` 签名兼容的 JavaScript 实现，
    其中 JavaScript 函数 `fn` 用作实现。返回一个 [`NativeCallback`](#nativecallback)，
    你可以将其分配给 ObjC 方法的 `implementation` 属性。

{% highlight js %}
const NSSound = ObjC.classes.NSSound; /* macOS */
const oldImpl = NSSound.play.implementation;
NSSound.play.implementation = ObjC.implement(NSSound.play, (handle, selector) => {
  return oldImpl(handle, selector);
});

const NSView = ObjC.classes.NSView; /* macOS */
const drawRect = NSView['- drawRect:'];
const oldImpl = drawRect.implementation;
drawRect.implementation = ObjC.implement(drawRect, (handle, selector) => {
  oldImpl(handle, selector);
});
{% endhighlight %}

>   由于 `implementation` 属性是一个 [`NativeFunction`](#nativefunction)，因此也是一个 [`NativePointer`](#nativepointer)，
>   你也可以使用 [`Interceptor`](#interceptor) 来钩住函数：

{% highlight js %}
const { NSSound } = ObjC.classes; /* macOS */
Interceptor.attach(NSSound.play.implementation, {
  onEnter() {
    send("[NSSound play]");
  }
});
{% endhighlight %}

+   `ObjC.registerProxy(properties)`: 创建一个旨在充当目标对象代理的新类，其中 `properties` 是一个指定以下内容的对象：

    -   `protocols`: (可选) 此类符合的协议数组。
    -   `methods`: (可选) 指定要实现的方法的对象。
    -   `events`: (可选) 指定用于获取有关事件通知的回调的对象：
        -   `dealloc()`: 在对象被释放后立即调用。这是你可以清理任何关联状态的地方。
        -   `forward(name)`: 使用 `name` 调用，指定我们要将调用转发到的方法名称。
            这可能是你开始使用仅记录名称的临时回调的地方，以帮助你决定要覆盖哪些方法。

{% highlight js %}
const MyConnectionDelegateProxy = ObjC.registerProxy({
  protocols: [ObjC.protocols.NSURLConnectionDataDelegate],
  methods: {
    '- connection:didReceiveResponse:': function (conn, resp) {
      /* fancy logging code here */
      /* this.data.foo === 1234 */
      this.data.target
          .connection_didReceiveResponse_(conn, resp);
    },
    '- connection:didReceiveData:': function (conn, data) {
      /* other logging code here */
      this.data.target
          .connection_didReceiveData_(conn, data);
    }
  },
  events: {
    forward(name) {
      console.log('*** forwarding: ' + name);
    }
  }
});

const method = ObjC.classes.NSURLConnection[
    '- initWithRequest:delegate:startImmediately:'];
Interceptor.attach(method.implementation, {
  onEnter(args) {
    args[3] = new MyConnectionDelegateProxy(args[3], {
      foo: 1234
    });
  }
});
{% endhighlight %}

+   `ObjC.registerClass(properties)`: 创建一个新的 Objective-C 类，其中 `properties` 是一个指定以下内容的对象：
    {: #objc-registerclass}

    -   `name`: (可选) 指定类名的字符串；如果你不关心全局可见的名称并希望运行时为你自动生成一个，请省略此项。
    -   `super`: (可选) 超类，或 *null* 以创建新的根类；省略以继承自 *NSObject*。
    -   `protocols`: (可选) 此类符合的协议数组。
    -   `methods`: (可选) 指定要实现的方法的对象。

{% highlight js %}
const MyConnectionDelegateProxy = ObjC.registerClass({
  name: 'MyConnectionDelegateProxy',
  super: ObjC.classes.NSObject,
  protocols: [ObjC.protocols.NSURLConnectionDataDelegate],
  methods: {
    '- init': function () {
      const self = this.super.init();
      if (self !== null) {
        ObjC.bind(self, {
          foo: 1234
        });
      }
      return self;
    },
    '- dealloc': function () {
      ObjC.unbind(this.self);
      this.super.dealloc();
    },
    '- connection:didReceiveResponse:': function (conn, resp) {
      /* this.data.foo === 1234 */
    },
    /*
     * But those previous methods are declared assuming that
     * either the super-class or a protocol we conform to has
     * the same method so we can grab its type information.
     * However, if that's not the case, you would write it
     * like this:
     */
    '- connection:didReceiveResponse:': {
      retType: 'void',
      argTypes: ['object', 'object'],
      implementation(conn, resp) {
      }
    },
    /* Or grab it from an existing class: */
    '- connection:didReceiveResponse:': {
      types: ObjC.classes
          .Foo['- connection:didReceiveResponse:'].types,
      implementation(conn, resp) {
      }
    },
    /* Or from an existing protocol: */
    '- connection:didReceiveResponse:': {
      types: ObjC.protocols.NSURLConnectionDataDelegate
          .methods['- connection:didReceiveResponse:'].types,
      implementation(conn, resp) {
      }
    },
    /* Or write the signature by hand if you really want to: */
    '- connection:didReceiveResponse:': {
      types: 'v32@0:8@16@24',
      implementation(conn, resp) {
      }
    }
  }
});

const proxy = MyConnectionDelegateProxy.alloc().init();
/* use `proxy`, and later: */
proxy.release();
{% endhighlight %}

+   `ObjC.registerProtocol(properties)`: 创建一个新的 Objective-C 协议，其中 `properties` 是一个指定以下内容的对象：

    -   `name`: (可选) 指定协议名称的字符串；如果你不关心全局可见的名称并希望运行时为你自动生成一个，请省略此项。
    -   `protocols`: (可选) 此协议包含的协议数组。
    -   `methods`: (可选) 指定要声明的方法的对象。

{% highlight js %}
const MyDataDelegate = ObjC.registerProtocol({
  name: 'MyDataDelegate',
  protocols: [ObjC.protocols.NSURLConnectionDataDelegate],
  methods: {
    /* You must specify the signature: */
    '- connection:didStuff:': {
      retType: 'void',
      argTypes: ['object', 'object']
    },
    /* Or grab it from a method of an existing class: */
    '- connection:didStuff:': {
      types: ObjC.classes
          .Foo['- connection:didReceiveResponse:'].types
    },
    /* Or from an existing protocol method: */
    '- connection:didStuff:': {
      types: ObjC.protocols.NSURLConnectionDataDelegate
          .methods['- connection:didReceiveResponse:'].types
    },
    /* Or write the signature by hand if you really want to: */
    '- connection:didStuff:': {
      types: 'v32@0:8@16@24'
    },
    /* You can also make a method optional (default is required): */
    '- connection:didStuff:': {
      retType: 'void',
      argTypes: ['object', 'object'],
      optional: true
    }
  }
});
{% endhighlight %}

+   `ObjC.bind(obj, data)`: 将一些 JavaScript 数据绑定到 Objective-C 实例；
    有关示例，请参阅 [`ObjC.registerClass()`](#objc-registerclass)。

+   `ObjC.unbind(obj)`: 从 Objective-C 实例解绑先前关联的 JavaScript 数据；
    有关示例，请参阅 [`ObjC.registerClass()`](#objc-registerclass)。

+   `ObjC.getBoundData(obj)`: 从 Objective-C 对象中查找先前绑定的数据。

+   `ObjC.enumerateLoadedClasses([options, ]callbacks)`: 枚举当前已加载的类，其中 `callbacks` 是一个指定以下内容的对象：
    {: #objc-enumerateloadedclasses}

    -   `onMatch(name, owner)`: 为每个已加载的类调用，`name` 为类名字符串，`owner` 指定加载类的模块路径。
        要获取给定类的 JavaScript 包装器，请执行：[`ObjC.classes[name]`](#objc-classes)。

    -   `onComplete()`: 当所有类都已枚举时调用。

    例如：

{% highlight js %}
ObjC.enumerateLoadedClasses({
  onMatch(name, owner) {
    console.log('onMatch:', name, owner);
  },
  onComplete() {
  }
});
{% endhighlight %}

可选的 `options` 参数是一个对象，你可以在其中指定 `ownedBy` 属性以将枚举限制为给定 [`ModuleMap`](#modulemap) 中的模块。

例如：

{% highlight js %}
const appModules = new ModuleMap(isAppModule);
ObjC.enumerateLoadedClasses({ ownedBy: appModules }, {
  onMatch(name, owner) {
    console.log('onMatch:', name, owner);
  },
  onComplete() {
  }
});

function isAppModule(m) {
  return !/^\/(usr\/lib|System|Developer)\//.test(m.path);
}
{% endhighlight %}

+   `ObjC.enumerateLoadedClassesSync([options])`: [`enumerateLoadedClasses()`](#objc-enumerateloadedclasses) 的同步版本，
    返回一个将所有者模块映射到类名数组的对象。

    例如：

{% highlight js %}
const appModules = new ModuleMap(isAppModule);
const appClasses = ObjC.enumerateLoadedClassesSync({ ownedBy: appModules });
console.log('appClasses:', JSON.stringify(appClasses));

function isAppModule(m) {
  return !/^\/(usr\/lib|System|Developer)\//.test(m.path);
}
{% endhighlight %}

+   `ObjC.choose(specifier, callbacks)`: 通过扫描堆来枚举与 `specifier` 匹配的类的活动实例。
    `specifier` 是类选择器或指定类选择器和所需选项的对象。
    类选择器是类的 **[ObjC.Object](#objc-object)**，例如 *ObjC.classes.UIButton*。
    当传递一个对象作为说明符时，你应该提供带有类选择器的 `class` 字段，以及一个布尔值 `subclasses` 字段，
    指示你是否也对匹配给定类选择器的子类感兴趣。默认值是也包括子类。
    `callbacks` 参数是一个指定以下内容的对象：
    {: #objc-choose}

    -   `onMatch(instance)`: 为找到的每个活动实例调用一次，带有一个即用型 `instance`，
        就像你调用了 [`new ObjC.Object(ptr("0x1234"))`](#objc-object) 一样，
        知道这个特定的 Objective-C 实例位于 *0x1234*。

        此函数可能会返回字符串 `stop` 以提前取消枚举。

    -   `onComplete()`: 当所有实例都已枚举时调用

+   `ObjC.chooseSync(specifier)`: [`choose()`](#objc-choose) 的同步版本，它将实例作为数组返回。

+   `ObjC.selector(name)`: 将 JavaScript 字符串 `name` 转换为选择器

+   `ObjC.selectorAsString(sel)`: 将选择器 `sel` 转换为 JavaScript 字符串


### Java

<div class="note">
<h5>Moved</h5>
<p markdown="1">
    从 Frida 17 开始，此runtime bridge不再包含在 Frida 的 GumJS 运行时中，可以通过运行以下命令获取：`npm install frida-java-bridge`。
    <br/>

    像这样将其导入到你的代理中：<br/>
    `import Java from 'frida-java-bridge';`<br/>

    目前，在 Frida REPL 加载的脚本以及 frida-trace 中不需要这样做。
</p>
</div>

+   `Java.available`: 一个布尔值，指定当前进程是否加载了 Java VM，即 Dalvik 或 ART。
    除非是这种情况，否则不要调用任何其他 `Java` 属性或方法。

+   `Java.androidVersion`: 一个字符串，指定我们正在运行的 Android 版本。

+   `ACC_PUBLIC`,
    `ACC_PRIVATE`,
    `ACC_PROTECTED`,
    `ACC_STATIC`,
    `ACC_FINAL`,
    `ACC_SYNCHRONIZED`,
    `ACC_BRIDGE`,
    `ACC_VARARGS`,
    `ACC_NATIVE`,
    `ACC_ABSTRACT`,
    `ACC_STRICT`,
    `ACC_SYNTHETIC`: 方法标志常量，每个都是一个数字，用于例如 [`Java.backtrace()`](#java-backtrace)。

+   `Java.enumerateLoadedClasses(callbacks)`: 枚举当前已加载的类，其中 `callbacks` 是一个指定以下内容的对象：
    {: #java-enumerateloadedclasses}

    -   `onMatch(name, handle)`: 为每个已加载的类调用，带有 `name`，可以传递给 [`use()`](#java-use) 以获取 JavaScript 包装器。
        你也可以将 `handle` [`Java.cast()`](#java-cast) 为 `java.lang.Class`。

    -   `onComplete()`: 当所有类都已枚举时调用。

+   `Java.enumerateLoadedClassesSync()`: [`enumerateLoadedClasses()`](#java-enumerateloadedclasses) 的同步版本，
    它将类名作为数组返回。

+   `Java.enumerateClassLoaders(callbacks)`: 枚举 Java VM 中存在的类加载器，其中 `callbacks` 是一个指定以下内容的对象：
    {: #java-enumerateclassloaders}

    -   `onMatch(loader)`: 为每个类加载器调用，带有 `loader`，它是特定 `java.lang.ClassLoader` 的包装器。

    -   `onComplete()`: 当所有类加载器都已枚举时调用。

    你可以将此类加载器传递给 `Java.ClassFactory.get()` 以便能够在指定的类加载器上 [`.use()`](#java-use) 类。

+   `Java.enumerateClassLoadersSync()`: [`enumerateClassLoaders()`](#java-enumerateclassloaders) 的同步版本，
    它将类加载器作为数组返回。

+   `Java.enumerateMethods(query)`: 枚举与 `query` 匹配的方法，指定为 `"class!method"`，允许使用 glob。
    也可以后缀 `/` 和一个或多个修饰符：

    -   `i`: 不区分大小写的匹配。
    -   `s`: 包括方法签名，例如 `"putInt"` 变成 `"putInt(java.lang.String, int): void"`。
    -   `u`: 仅限用户定义的类，忽略系统类。

{% highlight js %}
Java.perform(() => {
  const groups = Java.enumerateMethods('*youtube*!on*')
  console.log(JSON.stringify(groups, null, 2));
});
{% endhighlight %}

{% highlight json %}
[
  {
    "loader": "<instance: java.lang.ClassLoader, $className: dalvik.system.PathClassLoader>",
    "classes": [
      {
        "name": "com.google.android.apps.youtube.app.watch.nextgenwatch.ui.NextGenWatchLayout",
        "methods": [
          "onAttachedToWindow",
          "onDetachedFromWindow",
          "onFinishInflate",
          "onInterceptTouchEvent",
          "onLayout",
          "onMeasure",
          "onSizeChanged",
          "onTouchEvent",
          "onViewRemoved"
        ]
      },
      {
        "name": "com.google.android.apps.youtube.app.search.suggest.YouTubeSuggestionProvider",
        "methods": [
          "onCreate"
        ]
      },
      {
        "name": "com.google.android.libraries.youtube.common.ui.YouTubeButton",
        "methods": [
          "onInitializeAccessibilityNodeInfo"
        ]
      },
      …
    ]
  }
]
{% endhighlight %}

+   `Java.scheduleOnMainThread(fn)`: 在 VM 的主线程上运行 `fn`。

+   `Java.perform(fn)`: 确保当前线程已附加到 VM 并调用 `fn`。（这在来自 Java 的回调中不是必需的。）
    如果应用程序的类加载器尚不可用，将推迟调用 `fn`。
    如果不需要访问应用程序的类，请使用 [`Java.performNow()`](#java-performnow)。
    {: #java-perform}

{% highlight js %}
Java.perform(() => {
  const Activity = Java.use('android.app.Activity');
  Activity.onResume.implementation = function () {
    send('onResume() got called! Let\'s call the original implementation');
    this.onResume();
  };
});
{% endhighlight %}

+   `Java.performNow(fn)`: 确保当前线程已附加到 VM 并调用 `fn`。（这在来自 Java 的回调中不是必需的。）
    {: #java-performnow}

+   `Java.use(className)`: 动态获取 `className` 的 JavaScript 包装器，你可以通过对其调用 `$new()` 来实例化对象以调用构造函数。
    在实例上调用 `$dispose()` 以显式清理它（或等待 JavaScript 对象被垃圾回收，或脚本被卸载）。
    静态和非静态方法均可用，你甚至可以替换方法实现并从中抛出异常：
    {: #java-use}

{% highlight js %}
Java.perform(() => {
  const Activity = Java.use('android.app.Activity');
  const Exception = Java.use('java.lang.Exception');
  Activity.onResume.implementation = function () {
    throw Exception.$new('Oh noes!');
  };
});
{% endhighlight %}

>   默认情况下使用应用程序的类加载器，但你可以通过将不同的加载器实例分配给 `Java.classFactory.loader` 来对此进行自定义。
>
>   请注意，所有方法包装器都提供了一个 `clone(options)` API，用于创建具有自定义 **[NativeFunction](#nativefunction)** 选项的新方法包装器。

+   `Java.openClassFile(filePath)`: 打开 `filePath` 处的 .dex 文件，返回具有以下方法的对象：
    {: #java-openclassfile}

    -   `load()`: 将包含的类加载到 VM 中。

    -   `getClassNames()`: 获取可用类名的数组。

+   `Java.choose(className, callbacks)`: 通过扫描 Java 堆来枚举 `className` 类的活动实例，其中 `callbacks` 是一个指定以下内容的对象：
    {: #java-choose}

    -   `onMatch(instance)`: 为找到的每个活动实例调用，带有一个即用型 `instance`，
        就像你用这个特定实例的原始句柄调用了 [`Java.cast()`](#java-cast) 一样。

        此函数可能会返回字符串 `stop` 以提前取消枚举。

    -   `onComplete()`: 当所有实例都已枚举时调用

+   `Java.retain(obj)`: 复制 JavaScript 包装器 `obj` 以便在替换方法之外稍后使用。
    {: #java-retain}

{% highlight js %}
Java.perform(() => {
  const Activity = Java.use('android.app.Activity');
  let lastActivity = null;
  Activity.onResume.implementation = function () {
    lastActivity = Java.retain(this);
    this.onResume();
  };
});
{% endhighlight %}

+   <code id="java-cast">Java.cast(handle, klass)</code>: 给定 [`Java.use()`](#java-use) 返回的给定类 `klass` 的 `handle` 处的现有实例，
    创建一个 JavaScript 包装器。
    这样的包装器也有一个 `class` 属性用于获取其类的包装器，以及一个 `$className` 属性用于获取其类名的字符串表示形式。

{% highlight js %}
const Activity = Java.use('android.app.Activity');
const activity = Java.cast(ptr('0x1234'), Activity);
{% endhighlight %}

+   <code id="java-array">Java.array(type, elements)</code>: 从 JavaScript 数组 `elements` 创建一个具有指定 `type` 元素的 Java 数组。
    生成的 Java 数组的行为类似于 JS 数组，但可以通过引用传递给 Java API，以允许它们修改其内容。

{% highlight js %}
const values = Java.array('int', [ 1003, 1005, 1007 ]);

const JString = Java.use('java.lang.String');
const str = JString.$new(Java.array('byte', [ 0x48, 0x65, 0x69 ]));
{% endhighlight %}

+   `Java.backtrace([options])`: 为当前线程生成回溯。
    {: #java-backtrace}

    可选的 `options` 参数是一个对象，可能包含以下一些键：

    -   `limit`: 向上遍历堆栈的帧数，作为一个数字。
        默认为 16。

    返回一个具有以下属性的对象：

    -   `id`: 可用于对相同回溯进行重复数据删除的 ID，作为字符串。
    -   `frames`: 堆栈帧。包含以下属性的对象数组：

        -   `signature`: 堆栈帧签名作为字符串，例如
            `Landroid/os/Looper;,loopOnce,(Landroid/os/Looper;JI)Z`
        -   `origin`: 代码来源，即指定文件系统路径的字符串。在 Android 上，这是 `.dex` 的路径。
        -   `className`: 方法所属的类名，作为字符串，例如
            `android.os.Looper`
        -   `methodName`: 方法名作为字符串，例如 `loopOnce`
        -   `methodFlags`: 方法标志作为数字，例如
            `Java.ACC_PUBLIC | Java.ACC_STATIC`
        -   `fileName`: 源文件名作为字符串，例如 `Looper.java`
        -   `lineNumber`: 源行号作为数字，例如 `201`

+   `Java.isMainThread()`: 确定调用者是否在主线程上运行。

+   `Java.registerClass(spec)`: 创建一个新的 Java 类并返回它的包装器，其中 `spec` 是一个包含以下内容的对象：
    {: #java-registerclass}

    -   `name`: 指定类名的字符串。
    -   `superClass`: (可选) 超类。省略以继承自 `java.lang.Object`。
    -   `implements`: (可选) 此类实现的接口数组。
    -   `fields`: (可选) 指定要公开的每个字段的名称和类型的对象。
    -   `methods`: (可选) 指定要实现的方法的对象。

{% highlight js %}
const SomeBaseClass = Java.use('com.example.SomeBaseClass');
const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');

const MyTrustManager = Java.registerClass({
  name: 'com.example.MyTrustManager',
  implements: [X509TrustManager],
  methods: {
    checkClientTrusted(chain, authType) {
    },
    checkServerTrusted(chain, authType) {
    },
    getAcceptedIssuers() {
      return [];
    },
  }
});

const MyWeirdTrustManager = Java.registerClass({
  name: 'com.example.MyWeirdTrustManager',
  superClass: SomeBaseClass,
  implements: [X509TrustManager],
  fields: {
    description: 'java.lang.String',
    limit: 'int',
  },
  methods: {
    $init() {
      console.log('Constructor called');
    },
    checkClientTrusted(chain, authType) {
      console.log('checkClientTrusted');
    },
    checkServerTrusted: [{
      returnType: 'void',
      argumentTypes: ['[Ljava.security.cert.X509Certificate;', 'java.lang.String'],
      implementation(chain, authType) {
        console.log('checkServerTrusted A');
      }
    }, {
      returnType: 'java.util.List',
      argumentTypes: ['[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.lang.String'],
      implementation(chain, authType, host) {
        console.log('checkServerTrusted B');
        return null;
      }
    }],
    getAcceptedIssuers() {
      console.log('getAcceptedIssuers');
      return [];
    },
  }
});
{% endhighlight %}

+   `Java.deoptimizeEverything()`: 强制 VM 使用其解释器执行所有操作。
    这对于防止优化在某些情况下绕过方法钩子是必要的，并允许使用 ART 的 Instrumentation API 来跟踪运行时。

+   `Java.deoptimizeBootImage()`: 类似于 Java.deoptimizeEverything()，但仅取消优化引导映像代码。
    与 `dalvik.vm.dex2oat-flags --inline-max-code-units=0` 一起使用以获得最佳效果。

+   `Java.vm`: 具有以下方法的对象：

    -   `perform(fn)`: 确保当前线程已附加到 VM 并调用 `fn`。（这在来自 Java 的回调中不是必需的。）

    -   `getEnv()`: 获取当前线程的 `JNIEnv` 的包装器。如果当前线程未附加到 VM，则抛出异常。

    -   `tryGetEnv()`: 尝试获取当前线程的 `JNIEnv` 的包装器。如果当前线程未附加到 VM，则返回 `null`。

+   `Java.classFactory`: 用于实现例如 [`Java.use()`](#java-use) 的默认类工厂。使用应用程序的主类加载器。

+   `Java.ClassFactory`: 具有以下属性的类：

    +   `get(classLoader)`: 获取给定类加载器的类工厂实例。
        在幕后使用的默认类工厂仅与应用程序的主类加载器交互。
        其他类加载器可以通过 `Java.enumerateClassLoaders()` 发现并通过此 API 进行交互。

    -   `loader`: 只读属性，提供当前正在使用的类加载器的包装器。
        对于默认类工厂，这是由第一次调用 [`Java.perform()`](#java-perform) 更新的。

    -   `cacheDir`: 包含当前正在使用的缓存目录路径的字符串。
        对于默认类工厂，这是由第一次调用 [`Java.perform()`](#java-perform) 更新的。

    -   `tempFileNaming`: 指定用于临时文件的命名约定的对象。默认为 `{ prefix: 'frida', suffix: 'dat' }`。

    -   `use(className)`: 像 [`Java.use()`](#java-use) 但用于特定的类加载器。

    -   `openClassFile(filePath)`: 像 [`Java.openClassFile()`](#java-openclassfile) 但用于特定的类加载器。

    -   `choose(className, callbacks)`: 像 [`Java.choose()`](#java-choose) 但用于特定的类加载器。

    -   `retain(obj)`: 像 [`Java.retain()`](#java-retain) 但用于特定的类加载器。

    -   `cast(handle, klass)`: 像 [`Java.cast()`](#java-cast) 但用于特定的类
        loader.

    -   `array(type, elements)`: 像 [`Java.array()`](#java-array) 但用于特定的类加载器。

    -   `registerClass(spec)`: 像 [`Java.registerClass()`](#java-registerclass) 但用于特定的类加载器。

---

## CPU 指令


### Instruction

+   `Instruction.parse(target)`: 解析内存中 `target` 地址处的指令，由 [`NativePointer`](#nativepointer) 表示。
    请注意，在 32 位 ARM 上，对于 ARM 函数，此地址的最低有效位必须设置为 0，对于 Thumb 函数，必须设置为 1。
    如果你从 Frida API（例如 [`Module#getExportByName()`](#module-getexportbyname)）获取地址，Frida 会为你处理此细节。

    返回的对象具有以下字段：

    -   `address`: 此指令的地址 (EIP)，作为 [`NativePointer`](#nativepointer)
    -   `next`: 指向下一条指令的指针，因此你可以 `parse()` 它
    -   `size`: 此指令的大小
    -   `mnemonic`: 指令助记符的字符串表示形式
    -   `opStr`: 指令操作数的字符串表示形式
    -   `operands`: 描述每个操作数的对象数组，每个对象至少指定 `type` 和 `value`，
                    但也可能根据体系结构指定其他属性
    -   `regsRead`: 此指令隐式读取的寄存器名称数组
    -   `regsWritten`: 此指令隐式写入的寄存器名称数组
    -   `groups`: 此指令所属的组名数组
    -   `toString()`: 转换为人类可读的字符串

    有关 `operands` 和 `groups` 的详细信息，请查阅你的体系结构的 **[Capstone](http://www.capstone-engine.org/)** 文档。


### X86Writer

+   `new X86Writer(codeAddress[, { pc: ptr('0x1234') }])`: 创建一个新的代码编写器，
    用于生成直接写入 `codeAddress` 处内存的 x86 机器代码，`codeAddress` 指定为 **[NativePointer](#nativepointer)**。
    第二个参数是一个可选的选项对象，可以在其中指定初始程序计数器，这在生成代码到暂存缓冲区时很有用。
    这在 iOS 上使用 [`Memory.patchCode()`](#memory-patchcode) 时至关重要，因为它可能会为你提供一个临时位置，
    稍后会将其映射到预期内存位置的内存中。

-   `reset(codeAddress[, { pc: ptr('0x1234') }])`: 回收实例

-   `dispose()`: 立即清理内存

-   `flush()`: 解析标签引用并将挂起的数据写入内存。完成代码生成后，你应该始终调用一次。
    通常也希望在不相关的代码片段之间执行此操作，例如一次生成多个函数时。

-   `base`: 输出的第一个字节的内存位置，作为 **[NativePointer](#nativepointer)**

-   `code`: 输出的下一个字节的内存位置，作为 **[NativePointer](#nativepointer)**

-   `pc`: 输出的下一个字节处的程序计数器，作为 **[NativePointer](#nativepointer)**

-   `offset`: 当前偏移量作为 JavaScript 数字

-   `putLabel(id)`: 在当前位置放置一个标签，其中 `id` 是一个可以在过去和将来的 `put*Label()` 调用中引用的字符串
    {: #x86writer-putlabel}

-   `putCallAddressWithArguments(func, args)`: 放置调用具有指定 `args` 的 C 函数所需的代码，
    `args` 指定为 JavaScript 数组，其中每个元素要么是指定寄存器的字符串，要么是指定立即值的数字或
    **[NativePointer](#nativepointer)**。

-   `putCallAddressWithAlignedArguments(func, args)`: 与上面类似，但也确保参数列表在 16 字节边界上对齐

-   `putCallRegWithArguments(reg, args)`: 放置调用具有指定 `args` 的 C 函数所需的代码，
    `args` 指定为 JavaScript 数组，其中每个元素要么是指定寄存器的字符串，要么是指定立即值的数字或
    **[NativePointer](#nativepointer)**。

-   `putCallRegWithAlignedArguments(reg, args)`: 与上面类似，但也确保参数列表在 16 字节边界上对齐

-   `putCallRegOffsetPtrWithArguments(reg, offset, args)`: 放置调用具有指定 `args` 的 C 函数所需的代码，
    `args` 指定为 JavaScript 数组，其中每个元素要么是指定寄存器的字符串，要么是指定立即值的数字或
    **[NativePointer](#nativepointer)**。

-   `putCallAddress(address)`: 放置一个 CALL 指令

-   `putCallReg(reg)`: 放置一个 CALL 指令

-   `putCallRegOffsetPtr(reg, offset)`: 放置一个 CALL 指令

-   `putCallIndirect(addr)`: 放置一个 CALL 指令

-   `putCallIndirectLabel(labelId)`: 放置一个引用 `labelId` 的 CALL 指令，
    `labelId` 由过去或将来的 [`putLabel()`](#x86writer-putlabel) 定义

-   `putCallNearLabel(labelId)`: 放置一个引用 `labelId` 的 CALL 指令，
    `labelId` 由过去或将来的 [`putLabel()`](#x86writer-putlabel) 定义

-   `putLeave()`: 放置一个 LEAVE 指令

-   `putRet()`: 放置一个 RET 指令

-   `putRetImm(immValue)`: 放置一个 RET 指令

-   `putJmpAddress(address)`: 放置一个 JMP 指令

-   `putJmpShortLabel(labelId)`: 放置一个引用 `labelId` 的 JMP 指令，
    `labelId` 由过去或将来的 [`putLabel()`](#x86writer-putlabel) 定义

-   `putJmpNearLabel(labelId)`: 放置一个引用 `labelId` 的 JMP 指令，
    `labelId` 由过去或将来的 [`putLabel()`](#x86writer-putlabel) 定义

-   `putJmpReg(reg)`: 放置一个 JMP 指令

-   `putJmpRegPtr(reg)`: 放置一个 JMP 指令

-   `putJmpRegOffsetPtr(reg, offset)`: 放置一个 JMP 指令

-   `putJmpNearPtr(address)`: 放置一个 JMP 指令

-   `putJccShort(instructionId, target, hint)`: 放置一个 JCC 指令

-   `putJccNear(instructionId, target, hint)`: 放置一个 JCC 指令

-   `putJccShortLabel(instructionId, labelId, hint)`: 放置一个引用 `labelId` 的 JCC 指令，
    `labelId` 由过去或将来的 [`putLabel()`](#x86writer-putlabel) 定义

-   `putJccNearLabel(instructionId, labelId, hint)`: 放置一个引用 `labelId` 的 JCC 指令，
    `labelId` 由过去或将来的 [`putLabel()`](#x86writer-putlabel) 定义

-   `putAddRegImm(reg, immValue)`: 放置一个 ADD 指令

-   `putAddRegReg(dstReg, srcReg)`: 放置一个 ADD 指令

-   `putAddRegNearPtr(dstReg, srcAddress)`: 放置一个 ADD 指令

-   `putSubRegImm(reg, immValue)`: 放置一个 SUB 指令

-   `putSubRegReg(dstReg, srcReg)`: 放置一个 SUB 指令

-   `putSubRegNearPtr(dstReg, srcAddress)`: 放置一个 SUB 指令

-   `putIncReg(reg)`: 放置一个 INC 指令

-   `putDecReg(reg)`: 放置一个 DEC 指令

-   `putIncRegPtr(target, reg)`: 放置一个 INC 指令

-   `putDecRegPtr(target, reg)`: 放置一个 DEC 指令

-   `putLockXaddRegPtrReg(dstReg, srcReg)`: 放置一个 LOCK XADD 指令

-   `putLockCmpxchgRegPtrReg(dstReg, srcReg)`: 放置一个 LOCK CMPXCHG 指令

-   `putLockIncImm32Ptr(target)`: 放置一个 LOCK INC IMM32 指令

-   `putLockDecImm32Ptr(target)`: 放置一个 LOCK DEC IMM32 指令

-   `putAndRegReg(dstReg, srcReg)`: 放置一个 AND 指令

-   `putAndRegU32(reg, immValue)`: 放置一个 AND 指令

-   `putShlRegU8(reg, immValue)`: 放置一个 SHL 指令

-   `putShrRegU8(reg, immValue)`: 放置一个 SHR 指令

-   `putXorRegReg(dstReg, srcReg)`: 放置一个 XOR 指令

-   `putMovRegReg(dstReg, srcReg)`: 放置一个 MOV 指令

-   `putMovRegU32(dstReg, immValue)`: 放置一个 MOV 指令

-   `putMovRegU64(dstReg, immValue)`: 放置一个 MOV 指令

-   `putMovRegAddress(dstReg, address)`: 放置一个 MOV 指令

-   `putMovRegPtrU32(dstReg, immValue)`: 放置一个 MOV 指令

-   `putMovRegOffsetPtrU32(dstReg, dstOffset, immValue)`: 放置一个 MOV 指令

-   `putMovRegPtrReg(dstReg, srcReg)`: 放置一个 MOV 指令

-   `putMovRegOffsetPtrReg(dstReg, dstOffset, srcReg)`: 放置一个 MOV 指令

-   `putMovRegRegPtr(dstReg, srcReg)`: 放置一个 MOV 指令

-   `putMovRegRegOffsetPtr(dstReg, srcReg, srcOffset)`: 放置一个 MOV 指令

-   `putMovRegBaseIndexScaleOffsetPtr(dstReg, baseReg, indexReg, scale, offset)`: 放置一个 MOV 指令

-   `putMovRegNearPtr(dstReg, srcAddress)`: 放置一个 MOV 指令

-   `putMovNearPtrReg(dstAddress, srcReg)`: 放置一个 MOV 指令

-   `putMovFsU32PtrReg(fsOffset, srcReg)`: 放置一个 MOV FS 指令

-   `putMovRegFsU32Ptr(dstReg, fsOffset)`: 放置一个 MOV FS 指令

-   `putMovFsRegPtrReg(fsOffset, srcReg)`: 放置一个 MOV FS 指令

-   `putMovRegFsRegPtr(dstReg, fsOffset)`: 放置一个 MOV FS 指令

-   `putMovGsU32PtrReg(fsOffset, srcReg)`: 放置一个 MOV GS 指令

-   `putMovRegGsU32Ptr(dstReg, fsOffset)`: 放置一个 MOV GS 指令

-   `putMovGsRegPtrReg(gsOffset, srcReg)`: 放置一个 MOV GS 指令

-   `putMovRegGsRegPtr(dstReg, gsOffset)`: 放置一个 MOV GS 指令

-   `putMovqXmm0EspOffsetPtr(offset)`: 放置一个 MOVQ XMM0 ESP 指令

-   `putMovqEaxOffsetPtrXmm0(offset)`: 放置一个 MOVQ EAX XMM0 指令

-   `putMovdquXmm0EspOffsetPtr(offset)`: 放置一个 MOVDQU XMM0 ESP 指令

-   `putMovdquEaxOffsetPtrXmm0(offset)`: 放置一个 MOVDQU EAX XMM0 指令

-   `putLeaRegRegOffset(dstReg, srcReg, srcOffset)`: 放置一个 LEA 指令

-   `putXchgRegRegPtr(leftReg, rightReg)`: 放置一个 XCHG 指令

-   `putPushU32(immValue)`: 放置一个 PUSH 指令

-   `putPushNearPtr(address)`: 放置一个 PUSH 指令

-   `putPushReg(reg)`: 放置一个 PUSH 指令

-   `putPopReg(reg)`: 放置一个 POP 指令

-   `putPushImmPtr(immPtr)`: 放置一个 PUSH 指令

-   `putPushax()`: 放置一个 PUSHAX 指令

-   `putPopax()`: 放置一个 POPAX 指令

-   `putPushfx()`: 放置一个 PUSHFX 指令

-   `putPopfx()`: 放置一个 POPFX 指令

-   `putSahf()`: 放置一个 SAHF 指令

-   `putLahf()`: 放置一个 LAHF 指令

-   `putTestRegReg(regA, regB)`: 放置一个 TEST 指令

-   `putTestRegU32(reg, immValue)`: 放置一个 TEST 指令

-   `putCmpRegI32(reg, immValue)`: 放置一个 CMP 指令

-   `putCmpRegOffsetPtrReg(regA, offset, regB)`: 放置一个 CMP 指令

-   `putCmpImmPtrImmU32(immPtr, immValue)`: 放置一个 CMP 指令

-   `putCmpRegReg(regA, regB)`: 放置一个 CMP 指令

-   `putClc()`: 放置一个 CLC 指令

-   `putStc()`: 放置一个 STC 指令

-   `putCld()`: 放置一个 CLD 指令

-   `putStd()`: 放置一个 STD 指令

-   `putCpuid()`: 放置一个 CPUID 指令

-   `putLfence()`: 放置一个 LFENCE 指令

-   `putRdtsc()`: 放置一个 RDTSC 指令

-   `putPause()`: 放置一个 PAUSE 指令

-   `putNop()`: 放置一个 NOP 指令

-   `putBreakpoint()`: 放置一个特定于操作系统/体系结构的断点指令

-   `putPadding(n)`: 放置 `n` 个保护指令

-   `putNopPadding(n)`: 放置 `n` 个 NOP 指令

-   `putFxsaveRegPtr(reg)`: 放置一个 FXSAVE 指令

-   `putFxrstorRegPtr(reg)`: 放置一个 FXRSTOR 指令

-   `putU8(value)`: 放置一个 uint8

-   `putS8(value)`: 放置一个 int8

-   `putBytes(data)`: 放置来自提供的 **[ArrayBuffer](#arraybuffer)** 的原始数据


### X86Relocator

+   `new X86Relocator(inputCode, output)`: 创建一个新的代码重定位器，用于将 x86 指令从一个内存位置复制到另一个内存位置，
    并注意相应地调整位置相关指令。
    源地址由 `inputCode` 指定，这是一个 **[NativePointer](#nativepointer)**。
    目的地由 `output` 给出，这是一个指向所需目标内存地址的 **[X86Writer](#x86writer)**。

-   `reset(inputCode, output)`: 回收实例

-   `dispose()`: 立即清理内存

-   `input`: 到目前为止读取的最新 **[Instruction](#instruction)**。开始时为 `null`，
    并在每次调用 [`readOne()`](#x86relocator-readone) 时更改。

-   `eob`: 布尔值，指示是否已到达块的末尾，即我们已到达任何类型的分支，如 CALL、JMP、BL、RET。

-   `eoi`: 布尔值，指示是否已到达输入的末尾，例如我们已到达 JMP/B/RET，这是一条指令，其后可能有也可能没有有效代码。

-   `readOne()`: 将下一条指令读入重定位器的内部缓冲区，并返回到目前为止读取的字节数，包括以前的调用。
    你可以继续调用此方法以继续缓冲，或者立即调用 [`writeOne()`](#x86relocator-writeone) 或 [`skipOne()`](#x86relocator-skipone)。
    或者，你可以缓冲直到所需的点，然后调用 [`writeAll()`](#x86relocator-writeall)。
    当到达输入末尾时返回零，这意味着 `eoi` 属性现在为 `true`。
    {: #x86relocator-readone}

-   `peekNextWriteInsn()`: 查看要写入或跳过的下一条 **[Instruction](#instruction)**

-   `peekNextWriteSource()`: 查看要写入或跳过的下一条指令的地址

-   `skipOne()`: 跳过本来要写入的下一条指令
    {: #x86relocator-skipone}

-   `skipOneNoLabel()`: 跳过本来要写入的下一条指令，但不使用标签供内部使用。
    这破坏了分支到重定位范围内的位置的重定位，并且是针对所有分支都被重写（例如 Frida 的 **[Stalker](#stalker)**）的用例的优化。

-   `writeOne()`: 写入下一条缓冲的指令
    {: #x86relocator-writeone}

-   `writeOneNoLabel()`: 写入下一条缓冲的指令，但不使用标签供内部使用。
    这破坏了分支到重定位范围内的位置的重定位，并且是针对所有分支都被重写（例如 Frida 的 **[Stalker](#stalker)**）的用例的优化。

-   `writeAll()`: 写入所有缓冲的指令
    {: #x86relocator-writeall}


### x86 enum types

-   Register: `xax` `xcx` `xdx` `xbx` `xsp` `xbp` `xsi` `xdi` `eax` `ecx` `edx`
    `ebx` `esp` `ebp` `esi` `edi` `rax` `rcx` `rdx` `rbx` `rsp` `rbp` `rsi`
    `rdi` `r8` `r9` `r10` `r11` `r12` `r13` `r14` `r15` `r8d` `r9d` `r10d`
    `r11d` `r12d` `r13d` `r14d` `r15d` `xip` `eip` `rip`
-   InstructionId: `jo` `jno` `jb` `jae` `je` `jne` `jbe` `ja` `js` `jns` `jp`
    `jnp` `jl` `jge` `jle` `jg` `jcxz` `jecxz` `jrcxz`
-   BranchHint: `no-hint` `likely` `unlikely`
-   PointerTarget: `byte` `dword` `qword`


### ArmWriter

+   `new ArmWriter(codeAddress[, { pc: ptr('0x1234') }])`: 创建一个新的代码编写器，
    用于生成直接写入 `codeAddress` 处内存的 ARM 机器代码，`codeAddress` 指定为 **[NativePointer](#nativepointer)**。
    第二个参数是一个可选的选项对象，可以在其中指定初始程序计数器，这在生成代码到暂存缓冲区时很有用。
    这在 iOS 上使用 [`Memory.patchCode()`](#memory-patchcode) 时至关重要，因为它可能会为你提供一个临时位置，
    稍后会将其映射到预期内存位置的内存中。

-   `reset(codeAddress[, { pc: ptr('0x1234') }])`: 回收实例

-   `dispose()`: 立即清理内存

-   `flush()`: 解析标签引用并将挂起的数据写入内存。完成代码生成后，你应该始终调用一次。
    通常也希望在不相关的代码片段之间执行此操作，例如一次生成多个函数时。

-   `base`: 输出的第一个字节的内存位置，作为 **[NativePointer](#nativepointer)**

-   `code`: 输出的下一个字节的内存位置，作为 **[NativePointer](#nativepointer)**

-   `pc`: 输出的下一个字节处的程序计数器，作为 **[NativePointer](#nativepointer)**

-   `offset`: 当前偏移量作为 JavaScript 数字

-   `skip(nBytes)`: 跳过 `nBytes`

-   `putLabel(id)`: 在当前位置放置一个标签，其中 `id` 是一个可以在过去和将来的 `put*Label()` 调用中引用的字符串
    {: #armwriter-putlabel}

-   `putCallAddressWithArguments(func, args)`: 放置调用具有指定 `args` 的 C 函数所需的代码，
    `args` 指定为 JavaScript 数组，其中每个元素要么是指定寄存器的字符串，要么是指定立即值的数字或
    **[NativePointer](#nativepointer)**。

-   `putCallReg(reg)`: 放置一个 CALL 指令

-   `putCallRegWithArguments(reg, args)`: 放置调用具有指定 `args` 的 C 函数所需的代码，
    `args` 指定为 JavaScript 数组，其中每个元素要么是指定寄存器的字符串，要么是指定立即值的数字或
    NativePointer 指定的立即值。

-   `putBranchAddress(address)`: 放置分支/跳转到给定地址所需的代码

-   `canBranchDirectlyBetween(from, to)`: 确定两个给定内存位置之间是否可以直接分支

-   `putBImm(target)`: 放置一个 B 指令

-   `putBCondImm(cc, target)`: 放置一个 B COND 指令

-   `putBLabel(labelId)`: 放置一个引用 `labelId` 的 B 指令，
    `labelId` 由过去或将来的 [`putLabel()`](#armwriter-putlabel) 定义

-   `putBCondLabel(cc, labelId)`: 放置一个引用 `labelId` 的 B COND 指令，
    `labelId` 由过去或将来的 [`putLabel()`](#armwriter-putlabel) 定义

-   `putBlImm(target)`: 放置一个 BL 指令

-   `putBlxImm(target)`: 放置一个 BLX 指令

-   `putBlLabel(labelId)`: 放置一个引用 `labelId` 的 BL 指令，
    `labelId` 由过去或将来的 [`putLabel()`](#armwriter-putlabel) 定义

-   `putBxReg(reg)`: 放置一个 BX 指令

-   `putBlReg(reg)`: 放置一个 BL 指令

-   `putBlxReg(reg)`: 放置一个 BLX 指令

-   `putRet()`: 放置一个 RET 指令

-   `putVpushRange(firstReg, lastReg)`: 放置一个 VPUSH RANGE 指令

-   `putVpopRange(firstReg, lastReg)`: 放置一个 VPOP RANGE 指令

-   `putLdrRegAddress(reg, address)`: 放置一个 LDR 指令

-   `putLdrRegU32(reg, val)`: 放置一个 LDR 指令

-   `putLdrRegReg(dstReg, srcReg)`: 放置一个 LDR 指令

-   `putLdrRegRegOffset(dstReg, srcReg, srcOffset)`: 放置一个 LDR 指令

-   `putLdrCondRegRegOffset(cc, dstReg, srcReg, srcOffset)`: 放置一个 LDR COND 指令

-   `putLdmiaRegMask(reg, mask)`: 放置一个 LDMIA MASK 指令

-   `putLdmiaRegMaskWb(reg, mask)`: 放置一个 LDMIA MASK WB 指令

-   `putStrRegReg(srcReg, dstReg)`: 放置一个 STR 指令

-   `putStrRegRegOffset(srcReg, dstReg, dstOffset)`: 放置一个 STR 指令

-   `putStrCondRegRegOffset(cc, srcReg, dstReg, dstOffset)`: 放置一个 STR COND 指令

-   `putMovRegReg(dstReg, srcReg)`: 放置一个 MOV 指令

-   `putMovRegRegShift(dstReg, srcReg, shift, shiftValue)`: 放置一个 MOV SHIFT 指令

-   `putMovRegCpsr(reg)`: 放置一个 MOV CPSR 指令

-   `putMovCpsrReg(reg)`: 放置一个 MOV CPSR 指令

-   `putAddRegU16(dstReg, val)`: 放置一个 ADD U16 指令

-   `putAddRegU32(dstReg, val)`: 放置一个 ADD 指令

-   `putAddRegRegImm(dstReg, srcReg, immVal)`: 放置一个 ADD 指令

-   `putAddRegRegReg(dstReg, srcReg1, srcReg2)`: 放置一个 ADD 指令

-   `putAddRegRegRegShift(dstReg, srcReg1, srcReg2, shift, shiftValue)`: 放置一个 ADD SHIFT 指令

-   `putSubRegU16(dstReg, val)`: 放置一个 SUB U16 指令

-   `putSubRegU32(dstReg, val)`: 放置一个 SUB 指令

-   `putSubRegRegImm(dstReg, srcReg, immVal)`: 放置一个 SUB 指令

-   `putSubRegRegReg(dstReg, srcReg1, srcReg2)`: 放置一个 SUB 指令

-   `putRsbRegRegImm(dstReg, srcReg, immVal)`: 放置一个 RSB 指令

-   `putAndsRegRegImm(dstReg, srcReg, immVal)`: 放置一个 ANDS 指令

-   `putCmpRegImm(dstReg, immVal)`: 放置一个 CMP 指令

-   `putNop()`: 放置一个 NOP 指令

-   `putBreakpoint()`: 放置一个特定于操作系统/体系结构的断点指令

-   `putBrkImm(imm)`: 放置一个 BRK 指令

-   `putInstruction(insn)`: 将原始指令作为 JavaScript 数字放置

-   `putBytes(data)`: 放置来自提供的 **[ArrayBuffer](#arraybuffer)** 的原始数据


### ArmRelocator

+   `new ArmRelocator(inputCode, output)`: 创建一个新的代码重定位器，用于将 ARM 指令从一个内存位置复制到另一个内存位置，
    并注意相应地调整位置相关指令。
    源地址由 `inputCode` 指定，这是一个 **[NativePointer](#nativepointer)**。
    目的地由 `output` 给出，这是一个指向所需目标内存地址的 **[ArmWriter](#armwriter)**。

-   `reset(inputCode, output)`: 回收实例

-   `dispose()`: 立即清理内存

-   `input`: 到目前为止读取的最新 **[Instruction](#instruction)**。开始时为 `null`，
    并在每次调用 [`readOne()`](#armrelocator-readone) 时更改。

-   `eob`: 布尔值，指示是否已到达块的末尾，即我们已到达任何类型的分支，如 CALL、JMP、BL、RET。

-   `eoi`: 布尔值，指示是否已到达输入的末尾，例如我们已到达 JMP/B/RET，这是一条指令，其后可能有也可能没有有效代码。

-   `readOne()`: 将下一条指令读入重定位器的内部缓冲区，并返回到目前为止读取的字节数，包括以前的调用。
    你可以继续调用此方法以继续缓冲，或者立即调用 [`writeOne()`](#armrelocator-writeone) 或 [`skipOne()`](#armrelocator-skipone)。
    或者，你可以缓冲直到所需的点，然后调用 [`writeAll()`](#armrelocator-writeall)。
    当到达输入末尾时返回零，这意味着 `eoi` 属性现在为 `true`。
    {: #armrelocator-readone}

-   `peekNextWriteInsn()`: 查看要写入或跳过的下一条 **[Instruction](#instruction)**

-   `peekNextWriteSource()`: 查看要写入或跳过的下一条指令的地址

-   `skipOne()`: 跳过本来要写入的下一条指令
    {: #armrelocator-skipone}

-   `writeOne()`: 写入下一条缓冲的指令
    {: #armrelocator-writeone}

-   `writeAll()`: 写入所有缓冲的指令
    {: #armrelocator-writeall}


### ThumbWriter

+   `new ThumbWriter(codeAddress[, { pc: ptr('0x1234') }])`: 创建一个新的代码编写器，
    用于生成直接写入 `codeAddress` 处内存的 ARM 机器代码，`codeAddress` 指定为 **[NativePointer](#nativepointer)**。
    第二个参数是一个可选的选项对象，可以在其中指定初始程序计数器，这在生成代码到暂存缓冲区时很有用。
    这在 iOS 上使用 [`Memory.patchCode()`](#memory-patchcode) 时至关重要，因为它可能会为你提供一个临时位置，
    稍后会将其映射到预期内存位置的内存中。

-   `reset(codeAddress[, { pc: ptr('0x1234') }])`: 回收实例

-   `dispose()`: 立即清理内存

-   `flush()`: 解析标签引用并将挂起的数据写入内存。完成代码生成后，你应该始终调用一次。
    通常也希望在不相关的代码片段之间执行此操作，例如一次生成多个函数时。

-   `base`: 输出的第一个字节的内存位置，作为 **[NativePointer](#nativepointer)**

-   `code`: 输出的下一个字节的内存位置，作为 **[NativePointer](#nativepointer)**

-   `pc`: 输出的下一个字节处的程序计数器，作为 **[NativePointer](#nativepointer)**

-   `offset`: 当前偏移量作为 JavaScript 数字

-   `skip(nBytes)`: 跳过 `nBytes`

-   `putLabel(id)`: 在当前位置放置一个标签，其中 `id` 是一个可以在过去和将来的 `put*Label()` 调用中引用的字符串
    {: #thumbwriter-putlabel}

-   `commitLabel(id)`: 提交对给定标签的第一个挂起引用，成功时返回 `true`。
    如果尚未定义给定标签，或者没有更多对它的挂起引用，则返回 `false`。

-   `putCallAddressWithArguments(func, args)`: 放置调用具有指定 `args` 的 C 函数所需的代码，
    `args` 指定为 JavaScript 数组，其中每个元素要么是指定寄存器的字符串，要么是指定立即值的数字或
    **[NativePointer](#nativepointer)**。

-   `putCallRegWithArguments(reg, args)`: 放置调用具有指定 `args` 的 C 函数所需的代码，
    `args` 指定为 JavaScript 数组，其中每个元素要么是指定寄存器的字符串，要么是指定立即值的数字或
    **[NativePointer](#nativepointer)**。

-   `putBranchAddress(address)`: 放置分支/跳转到给定地址所需的代码

-   `canBranchDirectlyBetween(from, to)`: 确定两个给定内存位置之间是否可以直接分支

-   `putBImm(target)`: 放置一个 B 指令

-   `putBLabel(labelId)`: 放置一个引用 `labelId` 的 B 指令，
    `labelId` 由过去或将来的 [`putLabel()`](#thumbwriter-putlabel) 定义

-   `putBLabelWide(labelId)`: 放置一个 B WIDE 指令

-   `putBxReg(reg)`: 放置一个 BX 指令

-   `putBlImm(target)`: 放置一个 BL 指令

-   `putBlLabel(labelId)`: 放置一个引用 `labelId` 的 BL 指令，
    `labelId` 由过去或将来的 [`putLabel()`](#thumbwriter-putlabel) 定义

-   `putBlxImm(target)`: 放置一个 BLX 指令

-   `putBlxReg(reg)`: 放置一个 BLX 指令

-   `putCmpRegImm(reg, immValue)`: 放置一个 CMP 指令

-   `putBeqLabel(labelId)`: 放置一个引用 `labelId` 的 BEQ 指令，
    `labelId` 由过去或将来的 [`putLabel()`](#thumbwriter-putlabel) 定义

-   `putBneLabel(labelId)`: 放置一个引用 `labelId` 的 BNE 指令，
    `labelId` 由过去或将来的 [`putLabel()`](#thumbwriter-putlabel) 定义

-   `putBCondLabel(cc, labelId)`: 放置一个引用 `labelId` 的 B COND 指令，
    `labelId` 由过去或将来的 [`putLabel()`](#thumbwriter-putlabel) 定义

-   `putBCondLabelWide(cc, labelId)`: 放置一个 B COND WIDE 指令

-   `putCbzRegLabel(reg, labelId)`: 放置一个引用 `labelId` 的 CBZ 指令，
    `labelId` 由过去或将来的 [`putLabel()`](#thumbwriter-putlabel) 定义

-   `putCbnzRegLabel(reg, labelId)`: 放置一个引用 `labelId` 的 CBNZ 指令，
    `labelId` 由过去或将来的 [`putLabel()`](#thumbwriter-putlabel) 定义

-   `putPushRegs(regs)`: 放置一个具有指定寄存器的 PUSH 指令，
    指定为 JavaScript 数组，其中每个元素是指定寄存器名称的字符串。

-   `putPopRegs(regs)`: 放置一个具有指定寄存器的 POP 指令，
    指定为 JavaScript 数组，其中每个元素是指定寄存器名称的字符串。

-   `putVpushRange(firstReg, lastReg)`: 放置一个 VPUSH RANGE 指令

-   `putVpopRange(firstReg, lastReg)`: 放置一个 VPOP RANGE 指令

-   `putLdrRegAddress(reg, address)`: 放置一个 LDR 指令

-   `putLdrRegU32(reg, val)`: 放置一个 LDR 指令

-   `putLdrRegReg(dstReg, srcReg)`: 放置一个 LDR 指令

-   `putLdrRegRegOffset(dstReg, srcReg, srcOffset)`: 放置一个 LDR 指令

-   `putLdrbRegReg(dstReg, srcReg)`: 放置一个 LDRB 指令

-   `putVldrRegRegOffset(dstReg, srcReg, srcOffset)`: 放置一个 VLDR 指令

-   `putLdmiaRegMask(reg, mask)`: 放置一个 LDMIA MASK 指令

-   `putStrRegReg(srcReg, dstReg)`: 放置一个 STR 指令

-   `putStrRegRegOffset(srcReg, dstReg, dstOffset)`: 放置一个 STR 指令

-   `putMovRegReg(dstReg, srcReg)`: 放置一个 MOV 指令

-   `putMovRegU8(dstReg, immValue)`: 放置一个 MOV 指令

-   `putMovRegCpsr(reg)`: 放置一个 MOV CPSR 指令

-   `putMovCpsrReg(reg)`: 放置一个 MOV CPSR 指令

-   `putAddRegImm(dstReg, immValue)`: 放置一个 ADD 指令

-   `putAddRegReg(dstReg, srcReg)`: 放置一个 ADD 指令

-   `putAddRegRegReg(dstReg, leftReg, rightReg)`: 放置一个 ADD 指令

-   `putAddRegRegImm(dstReg, leftReg, rightValue)`: 放置一个 ADD 指令

-   `putSubRegImm(dstReg, immValue)`: 放置一个 SUB 指令

-   `putSubRegReg(dstReg, srcReg)`: 放置一个 SUB 指令

-   `putSubRegRegReg(dstReg, leftReg, rightReg)`: 放置一个 SUB 指令

-   `putSubRegRegImm(dstReg, leftReg, rightValue)`: 放置一个 SUB 指令

-   `putAndRegRegImm(dstReg, leftReg, rightValue)`: 放置一个 AND 指令

-   `putOrRegRegImm(dstReg, leftReg, rightValue)`: 放置一个 OR 指令

-   `putLslRegRegImm(dstReg, leftReg, rightValue)`: 放置一个 LSL 指令

-   `putLslsRegRegImm(dstReg, leftReg, rightValue)`: 放置一个 LSLS 指令

-   `putLsrsRegRegImm(dstReg, leftReg, rightValue)`: 放置一个 LSRS 指令

-   `putMrsRegReg(dstReg, srcReg)`: 放置一个 MRS 指令

-   `putMsrRegReg(dstReg, srcReg)`: 放置一个 MSR 指令

-   `putNop()`: 放置一个 NOP 指令

-   `putBkptImm(imm)`: 放置一个 BKPT 指令

-   `putBreakpoint()`: 放置一个特定于操作系统/体系结构的断点指令

-   `putInstruction(insn)`: 将原始指令作为 JavaScript 数字放置

-   `putInstructionWide(upper, lower)`: 从两个 JavaScript 数字值放置一个原始 Thumb-2 指令

-   `putBytes(data)`: 放置来自提供的 **[ArrayBuffer](#arraybuffer)** 的原始数据


### ThumbRelocator

+   `new ThumbRelocator(inputCode, output)`: 创建一个新的代码重定位器，用于将 ARM 指令从一个内存位置复制到另一个内存位置，
    并注意相应地调整位置相关指令。
    源地址由 `inputCode` 指定，这是一个 **[NativePointer](#nativepointer)**。
    目的地由 `output` 给出，这是一个指向所需目标内存地址的 **[ThumbWriter](#thumbwriter)**。

-   `reset(inputCode, output)`: 回收实例

-   `dispose()`: 立即清理内存

-   `input`: 到目前为止读取的最新 **[Instruction](#instruction)**。开始时为 `null`，
    并在每次调用 [`readOne()`](#thumbrelocator-readone) 时更改。

-   `eob`: 布尔值，指示是否已到达块的末尾，即我们已到达任何类型的分支，如 CALL、JMP、BL、RET。

-   `eoi`: 布尔值，指示是否已到达输入的末尾，例如我们已到达 JMP/B/RET，这是一条指令，其后可能有也可能没有有效代码。

-   `readOne()`: 将下一条指令读入重定位器的内部缓冲区，并返回到目前为止读取的字节数，包括以前的调用。
    你可以继续调用此方法以继续缓冲，或者立即调用 [`writeOne()`](#thumbrelocator-writeone) 或 [`skipOne()`](#thumbrelocator-skipone)。
    或者，你可以缓冲直到所需的点，然后调用 [`writeAll()`](#thumbrelocator-writeall)。
    当到达输入末尾时返回零，这意味着 `eoi` 属性现在为 `true`。
    {: #thumbrelocator-readone}

-   `peekNextWriteInsn()`: 查看要写入或跳过的下一条 **[Instruction](#instruction)**

-   `peekNextWriteSource()`: 查看要写入或跳过的下一条指令的地址

-   `skipOne()`: 跳过本来要写入的下一条指令
    {: #thumbrelocator-skipone}

-   `writeOne()`: 写入下一条缓冲的指令
    {: #thumbrelocator-writeone}

-   `copyOne()`: 复制下一条缓冲的指令而不推进输出光标，允许将同一条指令写出多次

-   `writeAll()`: 写入所有缓冲的指令
    {: #thumbrelocator-writeall}


### ARM enum types

-   Register: `r0` `r1` `r2` `r3` `r4` `r5` `r6` `r7` `r8` `r9` `r10` `r11`
    `r12` `r13` `r14` `r15` `sp` `lr` `sb` `sl` `fp` `ip` `pc` `s0` `s1` `s2`
    `s3` `s4` `s5` `s6` `s7` `s8` `s9` `s10` `s11` `s12` `s13` `s14` `s15`
    `s16` `s17` `s18` `s19` `s20` `s21` `s22` `s23` `s24` `s25` `s26` `s27`
    `s28` `s29` `s30` `s31` `d0` `d1` `d2` `d3` `d4` `d5` `d6` `d7` `d8` `d9`
    `d10` `d11` `d12` `d13` `d14` `d15` `d16` `d17` `d18` `d19` `d20` `d21`
    `d22` `d23` `d24` `d25` `d26` `d27` `d28` `d29` `d30` `d31` `q0` `q1` `q2`
    `q3` `q4` `q5` `q6` `q7` `q8` `q9` `q10` `q11` `q12` `q13` `q14` `q15`
-   SystemRegister: `apsr-nzcvq`
-   ConditionCode: `eq` `ne` `hs` `lo` `mi` `pl` `vs` `vc` `hi` `ls` `ge` `lt`
    `gt` `le` `al`
-   Shifter: `asr` `lsl` `lsr` `ror` `rrx` `asr-reg` `lsl-reg` `lsr-reg`
    `ror-reg` `rrx-reg`


### Arm64Writer

+   `new Arm64Writer(codeAddress[, { pc: ptr('0x1234') }])`: 创建一个新的代码编写器，
    用于生成直接写入 `codeAddress` 处内存的 AArch64 机器代码，`codeAddress` 指定为 **[NativePointer](#nativepointer)**。
    第二个参数是一个可选的选项对象，可以在其中指定初始程序计数器，这在生成代码到暂存缓冲区时很有用。
    这在 iOS 上使用 [`Memory.patchCode()`](#memory-patchcode) 时至关重要，因为它可能会为你提供一个临时位置，
    稍后会将其映射到预期内存位置的内存中。

-   `reset(codeAddress[, { pc: ptr('0x1234') }])`: 回收实例

-   `dispose()`: 立即清理内存

-   `flush()`: 解析标签引用并将挂起的数据写入内存。完成代码生成后，你应该始终调用一次。
    通常也希望在不相关的代码片段之间执行此操作，例如一次生成多个函数时。

-   `base`: 输出的第一个字节的内存位置，作为 NativePointer

-   `code`: 输出的下一个字节的内存位置，作为 NativePointer

-   `pc`: 输出的下一个字节处的程序计数器，作为 NativePointer

-   `offset`: 当前偏移量作为 JavaScript 数字

-   `skip(nBytes)`: 跳过 `nBytes`

-   `putLabel(id)`: 在当前位置放置一个标签，其中 `id` 是一个可以在过去和将来的 `put*Label()` 调用中引用的字符串
    {: #arm64writer-putlabel}

-   `putCallAddressWithArguments(func, args)`: 放置调用具有指定 `args` 的 C 函数所需的代码，
    `args` 指定为 JavaScript 数组，其中每个元素要么是指定寄存器的字符串，要么是指定立即值的数字或
    **[NativePointer](#nativepointer)**。

-   `putCallRegWithArguments(reg, args)`: 放置调用具有指定 `args` 的 C 函数所需的代码，
    `args` 指定为 JavaScript 数组，其中每个元素要么是指定寄存器的字符串，要么是指定立即值的数字或
    **[NativePointer](#nativepointer)**。

-   `putBranchAddress(address)`: 放置分支/跳转到给定地址所需的代码

-   `canBranchDirectlyBetween(from, to)`: 确定两个给定内存位置之间是否可以直接分支

-   `putBImm(address)`: 放置一个 B 指令

-   `putBLabel(labelId)`: 放置一个引用 `labelId` 的 B 指令，
    `labelId` 由过去或将来的 [`putLabel()`](#arm64writer-putlabel) 定义

-   `putBCondLabel(cc, labelId)`: 放置一个引用 `labelId` 的 B COND 指令，
    `labelId` 由过去或将来的 [`putLabel()`](#arm64writer-putlabel) 定义

-   `putBlImm(address)`: 放置一个 BL 指令

-   `putBlLabel(labelId)`: 放置一个引用 `labelId` 的 BL 指令，
    `labelId` 由过去或将来的 [`putLabel()`](#arm64writer-putlabel) 定义

-   `putBrReg(reg)`: 放置一个 BR 指令

-   `putBrRegNoAuth(reg)`: 放置一个 BR 指令，期望一个没有任何认证位的原始指针

-   `putBlrReg(reg)`: 放置一个 BLR 指令

-   `putBlrRegNoAuth(reg)`: 放置一个 BLR 指令，期望一个没有任何认证位的原始指针

-   `putRet()`: 放置一个 RET 指令

-   `putRetReg(reg)`: 放置一个 RET 指令

-   `putCbzRegImm(reg, target)`: 放置一个 CBZ 指令

-   `putCbnzRegImm(reg, target)`: 放置一个 CBNZ 指令

-   `putCbzRegLabel(reg, labelId)`: 放置一个引用 `labelId` 的 CBZ 指令，
    `labelId` 由过去或将来的 [`putLabel()`](#arm64writer-putlabel) 定义

-   `putCbnzRegLabel(reg, labelId)`: 放置一个引用 `labelId` 的 CBNZ 指令，
    `labelId` 由过去或将来的 [`putLabel()`](#arm64writer-putlabel) 定义

-   `putTbzRegImmImm(reg, bit, target)`: 放置一个 TBZ 指令

-   `putTbnzRegImmImm(reg, bit, target)`: 放置一个 TBNZ 指令

-   `putTbzRegImmLabel(reg, bit, labelId)`: 放置一个引用 `labelId` 的 TBZ 指令，
    `labelId` 由过去或将来的 [`putLabel()`](#arm64writer-putlabel) 定义

-   `putTbnzRegImmLabel(reg, bit, labelId)`: 放置一个引用 `labelId` 的 TBNZ 指令，
    `labelId` 由过去或将来的 [`putLabel()`](#arm64writer-putlabel) 定义

-   `putPushRegReg(regA, regB)`: 放置一个 PUSH 指令

-   `putPopRegReg(regA, regB)`: 放置一个 POP 指令

-   `putPushAllXRegisters()`: 放置将所有 X 寄存器推入堆栈所需的代码

-   `putPopAllXRegisters()`: 放置将所有 X 寄存器从堆栈弹出所需的代码

-   `putPushAllQRegisters()`: 放置将所有 Q 寄存器推入堆栈所需的代码

-   `putPopAllQRegisters()`: 放置将所有 Q 寄存器从堆栈弹出所需的代码

-   `putLdrRegAddress(reg, address)`: 放置一个 LDR 指令

-   `putLdrRegU32(reg, val)`: 放置一个 LDR 指令

-   `putLdrRegU64(reg, val)`: 放置一个 LDR 指令

-   `putLdrRegU32Ptr(reg, srcAddress)`: 放置一个 LDR 指令

-   `putLdrRegU64Ptr(reg, srcAddress)`: 放置一个 LDR 指令

-   `putLdrRegRef(reg)`: 放置一个带有悬空数据引用的 LDR 指令，
    返回一个不透明的 ref 值，该值应传递给所需位置的 [`putLdrRegValue()`](#arm64writer-putldrregvalue)
    {: #arm64writer-putldrregref}

-   `putLdrRegValue(ref, value)`: 从先前的 [`putLdrRegRef()`](#arm64writer-putldrregref) 放置值并更新 LDR 指令
    {: #arm64writer-putldrregvalue}

-   `putLdrRegReg(dstReg, srcReg)`: 放置一个 LDR 指令

-   `putLdrRegRegOffset(dstReg, srcReg, srcOffset)`: 放置一个 LDR 指令

-   `putLdrRegRegOffsetMode(dstReg, srcReg, srcOffset, mode)`: 放置一个 LDR MODE 指令

-   `putLdrswRegRegOffset(dstReg, srcReg, srcOffset)`: 放置一个 LDRSW 指令

-   `putAdrpRegAddress(reg, address)`: 放置一个 ADRP 指令

-   `putStrRegReg(srcReg, dstReg)`: 放置一个 STR 指令

-   `putStrRegRegOffset(srcReg, dstReg, dstOffset)`: 放置一个 STR 指令

-   `putStrRegRegOffsetMode(srcReg, dstReg, dstOffset, mode)`: 放置一个 STR MODE 指令

-   `putLdpRegRegRegOffset(regA, regB, regSrc, srcOffset, mode)`: 放置一个 LDP 指令

-   `putStpRegRegRegOffset(regA, regB, regDst, dstOffset, mode)`: 放置一个 STP 指令

-   `putMovRegReg(dstReg, srcReg)`: 放置一个 MOV 指令

-   `putMovRegNzcv(reg)`: 放置一个 MOV NZCV 指令

-   `putMovNzcvReg(reg)`: 放置一个 MOV NZCV 指令

-   `putUxtwRegReg(dstReg, srcReg)`: 放置一个 UXTW 指令

-   `putAddRegRegImm(dstReg, leftReg, rightValue)`: 放置一个 ADD 指令

-   `putAddRegRegReg(dstReg, leftReg, rightReg)`: 放置一个 ADD 指令

-   `putSubRegRegImm(dstReg, leftReg, rightValue)`: 放置一个 SUB 指令

-   `putSubRegRegReg(dstReg, leftReg, rightReg)`: 放置一个 SUB 指令

-   `putAndRegRegImm(dstReg, leftReg, rightValue)`: 放置一个 AND 指令

-   `putEorRegRegReg(dstReg, leftReg, rightReg)`: 放置一个 EOR 指令

-   `putUbfm(dstReg, srcReg, imms, immr)`: 放置一个 UBFM 指令

-   `putLslRegImm(dstReg, srcReg, shift)`: 放置一个 LSL 指令

-   `putLsrRegImm(dstReg, srcReg, shift)`: 放置一个 LSR 指令

-   `putTstRegImm(reg, immValue)`: 放置一个 TST 指令

-   `putCmpRegReg(regA, regB)`: 放置一个 CMP 指令

-   `putXpaciReg(reg)`: 放置一个 XPACI 指令

-   `putNop()`: 放置一个 NOP 指令

-   `putBrkImm(imm)`: 放置一个 BRK 指令

-   `putMrs(dstReg, systemReg)`: 放置一个 MRS 指令

-   `putInstruction(insn)`: 将原始指令作为 JavaScript 数字放置

-   `putBytes(data)`: 放置来自提供的 **[ArrayBuffer](#arraybuffer)** 的原始数据

-   `sign(value)`: 对给定的指针值进行签名


### Arm64Relocator

+   `new Arm64Relocator(inputCode, output)`: 创建一个新的代码重定位器，用于将 AArch64 指令从一个内存位置复制到另一个内存位置，
    并注意相应地调整位置相关指令。
    源地址由 `inputCode` 指定，这是一个 **[NativePointer](#nativepointer)**。
    目的地由 `output` 给出，这是一个指向所需目标内存地址的 **[Arm64Writer](#arm64writer)**。

-   `reset(inputCode, output)`: 回收实例

-   `dispose()`: 立即清理内存

-   `input`: 到目前为止读取的最新 **[Instruction](#instruction)**。开始时为 `null`，
    并在每次调用 [`readOne()`](#arm64relocator-readone) 时更改。

-   `eob`: 布尔值，指示是否已到达块的末尾，即我们已到达任何类型的分支，如 CALL、JMP、BL、RET。

-   `eoi`: 布尔值，指示是否已到达输入的末尾，例如我们已到达 JMP/B/RET，这是一条指令，其后可能有也可能没有有效代码。

-   `readOne()`: 将下一条指令读入重定位器的内部缓冲区，并返回到目前为止读取的字节数，包括以前的调用。
    你可以继续调用此方法以继续缓冲，或者立即调用 [`writeOne()`](#arm64relocator-writeone) 或 [`skipOne()`](#arm64relocator-skipone)。
    或者，你可以缓冲直到所需的点，然后调用 [`writeAll()`](#arm64relocator-writeall)。
    当到达输入末尾时返回零，这意味着 `eoi` 属性现在为 `true`。
    {: #arm64relocator-readone}

-   `peekNextWriteInsn()`: 查看要写入或跳过的下一条 **[Instruction](#instruction)**

-   `peekNextWriteSource()`: 查看要写入或跳过的下一条指令的地址

-   `skipOne()`: 跳过本来要写入的下一条指令
    {: #arm64relocator-skipone}

-   `writeOne()`: 写入下一条缓冲的指令
    {: #arm64relocator-writeone}

-   `writeAll()`: 写入所有缓冲的指令
    {: #arm64relocator-writeall}


### AArch64 enum types

-   Register: `x0` `x1` `x2` `x3` `x4` `x5` `x6` `x7` `x8` `x9` `x10` `x11`
    `x12` `x13` `x14` `x15` `x16` `x17` `x18` `x19` `x20` `x21` `x22` `x23`
    `x24` `x25` `x26` `x27` `x28` `x29` `x30` `w0` `w1` `w2` `w3` `w4` `w5`
    `w6` `w7` `w8` `w9` `w10` `w11` `w12` `w13` `w14` `w15` `w16` `w17` `w18`
    `w19` `w20` `w21` `w22` `w23` `w24` `w25` `w26` `w27` `w28` `w29` `w30`
    `sp` `lr` `fp` `wsp` `wzr` `xzr` `nzcv` `ip0` `ip1` `s0` `s1` `s2` `s3`
    `s4` `s5` `s6` `s7` `s8` `s9` `s10` `s11` `s12` `s13` `s14` `s15` `s16`
    `s17` `s18` `s19` `s20` `s21` `s22` `s23` `s24` `s25` `s26` `s27` `s28`
    `s29` `s30` `s31` `d0` `d1` `d2` `d3` `d4` `d5` `d6` `d7` `d8` `d9` `d10`
    `d11` `d12` `d13` `d14` `d15` `d16` `d17` `d18` `d19` `d20` `d21` `d22`
    `d23` `d24` `d25` `d26` `d27` `d28` `d29` `d30` `d31` `q0` `q1` `q2` `q3`
    `q4` `q5` `q6` `q7` `q8` `q9` `q10` `q11` `q12` `q13` `q14` `q15` `q16`
    `q17` `q18` `q19` `q20` `q21` `q22` `q23` `q24` `q25` `q26` `q27` `q28`
    `q29` `q30` `q31`
-   ConditionCode: `eq` `ne` `hs` `lo` `mi` `pl` `vs` `vc` `hi` `ls` `ge` `lt`
    `gt` `le` `al` `nv`
-   IndexMode: `post-adjust` `signed-offset` `pre-adjust`


### MipsWriter

+   `new MipsWriter(codeAddress[, { pc: ptr('0x1234') }])`: 创建一个新的代码编写器，
    用于生成直接写入 `codeAddress` 处内存的 MIPS 机器代码，`codeAddress` 指定为 **[NativePointer](#nativepointer)**。
    第二个参数是一个可选的选项对象，可以在其中指定初始程序计数器，这在生成代码到暂存缓冲区时很有用。
    这在 iOS 上使用 [`Memory.patchCode()`](#memory-patchcode) 时至关重要，因为它可能会为你提供一个临时位置，
    稍后会将其映射到预期内存位置的内存中。

-   `reset(codeAddress[, { pc: ptr('0x1234') }])`: 回收实例

-   `dispose()`: 立即清理内存

-   `flush()`: 解析标签引用并将挂起的数据写入内存。完成代码生成后，你应该始终调用一次。
    通常也希望在不相关的代码片段之间执行此操作，例如一次生成多个函数时。

-   `base`: 输出的第一个字节的内存位置，作为 **[NativePointer](#nativepointer)**

-   `code`: 输出的下一个字节的内存位置，作为 **[NativePointer](#nativepointer)**

-   `pc`: 输出的下一个字节处的程序计数器，作为 **[NativePointer](#nativepointer)**

-   `offset`: 当前偏移量作为 JavaScript 数字

-   `skip(nBytes)`: 跳过 `nBytes`

-   `putLabel(id)`: 在当前位置放置一个标签，其中 `id` 是一个可以在过去和将来的 `put*Label()` 调用中引用的字符串
    {: #mipswriter-putlabel}

-   `putCallAddressWithArguments(func, args)`: 放置调用具有指定 `args` 的 C 函数所需的代码，
    `args` 指定为 JavaScript 数组，其中每个元素要么是指定寄存器的字符串，要么是指定立即值的数字或
    **[NativePointer](#nativepointer)**。

-   `putCallRegWithArguments(reg, args)`: 放置调用具有指定 `args` 的 C 函数所需的代码，
    `args` 指定为 JavaScript 数组，其中每个元素要么是指定寄存器的字符串，要么是指定立即值的数字或
    **[NativePointer](#nativepointer)**。

-   `putJAddress(address)`: 放置一个 J 指令

-   `putJAddressWithoutNop(address)`: 放置一个 J WITHOUT NOP 指令

-   `putJLabel(labelId)`: 放置一个引用 `labelId` 的 J 指令，
    `labelId` 由过去或将来的 [`putLabel()`](#mipswriter-putlabel) 定义

-   `putJrReg(reg)`: 放置一个 JR 指令

-   `putJalAddress(address)`: 放置一个 JAL 指令

-   `putJalrReg(reg)`: 放置一个 JALR 指令

-   `putBOffset(offset)`: 放置一个 B 指令

-   `putBeqRegRegLabel(rightReg, leftReg, labelId)`: 放置一个引用 `labelId` 的 BEQ 指令，
    `labelId` 由过去或将来的 [`putLabel()`](#mipswriter-putlabel) 定义

-   `putRet()`: 放置一个 RET 指令

-   `putLaRegAddress(reg, address)`: 放置一个 LA 指令

-   `putLuiRegImm(reg, imm)`: 放置一个 LUI 指令

-   `putDsllRegReg(dstReg, srcReg, amount)`: 放置一个 DSLL 指令

-   `putOriRegRegImm(rt, rs, imm)`: 放置一个 ORI 指令

-   `putLdRegRegOffset(dstReg, srcReg, srcOffset)`: 放置一个 LD 指令

-   `putLwRegRegOffset(dstReg, srcReg, srcOffset)`: 放置一个 LW 指令

-   `putSwRegRegOffset(srcReg, dstReg, dstOffset)`: 放置一个 SW 指令

-   `putMoveRegReg(dstReg, srcReg)`: 放置一个 MOVE 指令

-   `putAdduRegRegReg(dstReg, leftReg, rightReg)`: 放置一个 ADDU 指令

-   `putAddiRegRegImm(dstReg, leftReg, imm)`: 放置一个 ADDI 指令

-   `putAddiRegImm(dstReg, imm)`: 放置一个 ADDI 指令

-   `putSubRegRegImm(dstReg, leftReg, imm)`: 放置一个 SUB 指令

-   `putPushReg(reg)`: 放置一个 PUSH 指令

-   `putPopReg(reg)`: 放置一个 POP 指令

-   `putMfhiReg(reg)`: 放置一个 MFHI 指令

-   `putMfloReg(reg)`: 放置一个 MFLO 指令

-   `putMthiReg(reg)`: 放置一个 MTHI 指令

-   `putMtloReg(reg)`: 放置一个 MTLO 指令

-   `putNop()`: 放置一个 NOP 指令

-   `putBreak()`: 放置一个 BREAK 指令

-   `putPrologueTrampoline(reg, address)`: 放置一个最小尺寸的 trampoline 用于跳转到给定地址

-   `putInstruction(insn)`: 将原始指令作为 JavaScript 数字放置

-   `putBytes(data)`: 放置来自提供的 **[ArrayBuffer](#arraybuffer)** 的原始数据


### MipsRelocator

+   `new MipsRelocator(inputCode, output)`: 创建一个新的代码重定位器，用于将 MIPS 指令从一个内存位置复制到另一个内存位置，
    并注意相应地调整位置相关指令。
    源地址由 `inputCode` 指定，这是一个 **[NativePointer](#nativepointer)**。
    目的地由 `output` 给出，这是一个指向所需目标内存地址的 **[MipsWriter](#mipswriter)**。

-   `reset(inputCode, output)`: 回收实例

-   `dispose()`: 立即清理内存

-   `input`: 到目前为止读取的最新 **[Instruction](#instruction)**。开始时为 `null`，
    并在每次调用 [`readOne()`](#mipsrelocator-readone) 时更改。

-   `eob`: 布尔值，指示是否已到达块的末尾，即我们已到达任何类型的分支，如 CALL、JMP、BL、RET。

-   `eoi`: 布尔值，指示是否已到达输入的末尾，例如我们已到达 JMP/B/RET，这是一条指令，其后可能有也可能没有有效代码。

-   `readOne()`: 将下一条指令读入重定位器的内部缓冲区，并返回到目前为止读取的字节数，包括以前的调用。
    你可以继续调用此方法以继续缓冲，或者立即调用 [`writeOne()`](#mipsrelocator-writeone) 或 [`skipOne()`](#mipsrelocator-skipone)。
    或者，你可以缓冲直到所需的点，然后调用 [`writeAll()`](#mipsrelocator-writeall)。
    当到达输入末尾时返回零，这意味着 `eoi` 属性现在为 `true`。
    {: #mipsrelocator-readone}

-   `peekNextWriteInsn()`: 查看要写入或跳过的下一条 **[Instruction](#instruction)**

-   `peekNextWriteSource()`: 查看要写入或跳过的下一条指令的地址

-   `skipOne()`: 跳过本来要写入的下一条指令
    {: #mipsrelocator-skipone}

-   `writeOne()`: 写入下一条缓冲的指令
    {: #mipsrelocator-writeone}

-   `writeAll()`: 写入所有缓冲的指令
    {: #mipsrelocator-writeall}


### MIPS enum types

-   Register: `v0` `v1` `a0` `a1` `a2` `a3` `t0` `t1` `t2` `t3` `t4` `t5` `t6`
    `t7` `s0` `s1` `s2` `s3` `s4` `s5` `s6` `s7` `t8` `t9` `k0` `k1` `gp` `sp`
    `fp` `s8` `ra` `hi` `lo` `zero` `at` `0` `1` `2` `3` `4` `5` `6` `7` `8`
    `9` `10` `11` `12` `13` `14` `15` `16` `17` `18` `19` `20` `21` `22` `23`
    `24` `25` `26` `27` `28` `29` `30` `31`

---

## 其他


### Console

+   `console.log(line)`, `console.warn(line)`, `console.error(line)`:
    将 `line` 写入基于 Frida 的应用程序的控制台。确切的行为取决于 [frida-core](https://github.com/frida/frida-core)
    集成的位置。
    例如，当通过 [frida-python](https://github.com/frida/frida-python) 使用 Frida 时，
    此输出将转到 *stdout* 或 *stderr*，当使用 **[frida-qml](https://github.com/frida/frida-qml)** 时，
    转到 **[qDebug](https://doc.qt.io/qt-5/qdebug.html)** 等。

    作为 **[ArrayBuffer](#arraybuffer)** 对象的参数将被替换为具有默认选项的 [`hexdump()`](#hexdump) 的结果。


### Hexdump

+   `hexdump(target[, options])`: 从提供的 **[ArrayBuffer](#arraybuffer)** 或 [NativePointer](#nativepointer) `target` 生成十六进制转储，
    可选地使用 `options` 自定义输出。

    例如：

{% highlight js %}
const libc = Process.getModuleByName('libc.so').base;
console.log(hexdump(libc, {
  /* address: ptr('0x1000'), -- to override the base address */
  offset: 0,
  length: 64,
  header: true,
  ansi: true
}));
{% endhighlight %}

{% highlight sh %}
           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00  .ELF............
00000010  03 00 28 00 01 00 00 00 00 00 00 00 34 00 00 00  ..(.........4...
00000020  34 a8 04 00 00 00 00 05 34 00 20 00 08 00 28 00  4.......4. ...(.
00000030  1e 00 1d 00 06 00 00 00 34 00 00 00 34 00 00 00  ........4...4...
{% endhighlight %}


### Shorthand

+   `int64(v)`: [`new Int64(v)`](#int64) 的简写

+   `uint64(v)`: [`new UInt64(v)`](#uint64) 的简写

+   `ptr(s)`: [`new NativePointer(s)`](#nativepointer) 的简写

+   `NULL`: `ptr("0")` 的简写


### 主机和注入进程之间的通信

+   `recv([type, ]callback)`: 请求在从基于 Frida 的应用程序收到下一条消息时调用 `callback`。
    可选地，可以指定 `type` 以仅接收 `type` 字段设置为 `type` 的消息。
    {: #communication-recv}

    消息作为第一个参数传递，如果随消息传递了二进制数据，则第二个参数是 **[ArrayBuffer](#arraybuffer)**，否则为 *null*。

    这只会给你一条消息，所以你需要再次调用 `recv()` 来接收下一条消息。

+   `send(message[, data])`: 将 JavaScript 对象 `message` 发送到基于 Frida 的应用程序（它必须可序列化为 JSON）。
    如果你还有一些原始二进制数据想随之发送，例如你使用 [`NativePointer#readByteArray`](#nativepointer-readbytearray)
    转储了一些内存，那么你可以通过可选的 `data` 参数传递它。这要求它要么是 **[ArrayBuffer](#arraybuffer)**，
    要么是 0 到 255 之间的整数数组。
    {: #communication-send}

    <div class="note">
    <h5>性能注意事项</h5>
    <p>
        虽然 <i>send()</i> 是异步的，但发送单个消息的总开销并未针对高频进行优化，
        因此这意味着 Frida 让你根据需要低延迟还是高吞吐量，自行决定将多个值批处理到单个 <i>send()</i> 调用中。
    </p>
    </div>

+   `rpc.exports`: 空对象，你可以替换或插入该对象以向应用程序公开 RPC 风格的 API。
    键指定方法名称，值是你的导出函数。此函数可以返回一个普通值以立即将其返回给调用者，
    或者返回一个 Promise 以异步返回。
    {: #rpc-exports}

>   例如：

{% highlight js %}
rpc.exports = {
  add(a, b) {
    return a + b;
  },
  sub(a, b) {
    return new Promise(resolve => {
      setTimeout(() => {
        resolve(a - b);
      }, 100);
    });
  }
};
{% endhighlight %}

>   从使用 Node.js 绑定的应用程序来看，此 API 将像这样使用：

{% highlight js %}
const frida = require('frida');
const fs = require('fs');
const path = require('path');
const util = require('util');

const readFile = util.promisify(fs.readFile);

let session, script;
async function run() {
  const source = await readFile(path.join(__dirname, '_agent.js'), 'utf8');
  session = await frida.attach('iTunes');
  script = await session.createScript(source);
  script.message.connect(onMessage);
  await script.load();
  console.log(await script.exports.add(2, 3));
  console.log(await script.exports.sub(5, 3));
}

run().catch(onError);

function onError(error) {
  console.error(error.stack);
}

function onMessage(message, data) {
  if (message.type === 'send') {
    console.log(message.payload);
  } else if (message.type === 'error') {
    console.error(message.stack);
  }
}
{% endhighlight %}

>   Python 版本将非常相似：

{% highlight py %}
import codecs
import frida

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(message['stack'])

session = frida.attach('iTunes')
with codecs.open('./agent.js', 'r', 'utf-8') as f:
    source = f.read()
script = session.create_script(source)
script.on('message', on_message)
script.load()
print(script.exports.add(2, 3))
print(script.exports.sub(5, 3))
session.detach()
{% endhighlight %}

在上面的示例中，我们使用 `script.on('message', on_message)` 来监视来自注入进程（JavaScript 端）的任何消息。
你也可以在 `script` 和 `session` 上监视其他通知。
如果你想在目标进程退出时收到通知，请使用 `session.on('detached', your_function)`。


### 定时事件

+   `setTimeout(func, delay[, ...parameters])`: 在 `delay` 毫秒后调用 `func`，
    可选地传递一个或多个 `parameters`。
    返回一个 id，可以传递给 `clearTimeout` 以取消它。

+   `clearTimeout(id)`: 取消由调用 `setTimeout` 返回的 id。

+   `setInterval(func, delay[, ...parameters])`: 每 `delay` 毫秒调用 `func`，
    可选地传递一个或多个 `parameters`。
    返回一个 id，可以传递给 `clearInterval` 以取消它。

+   `clearInterval(id)`: 取消由调用 `setInterval` 返回的 id。

+   `setImmediate(func[, ...parameters])`: 安排在 Frida 的 JavaScript 线程上尽快调用 `func`，
    可选地传递一个或多个 `parameters`。
    返回一个 id，可以传递给 `clearImmediate` 以取消它。

+   `clearImmediate(id)`: 取消由调用 `setImmediate` 返回的 id。


### 垃圾回收

+   `gc()`: 强制垃圾回收。对于测试很有用，尤其是涉及 [`Script.bindWeak()`](#bindweak) 的逻辑。


### Worker

具有自己的 JavaScript 堆、锁等的 Worker 脚本。

这对于将繁重的处理移动到后台线程很有用，从而允许及时处理钩子。

+   `new Worker(url[, options])`: 创建一个新的 worker，执行指定 `url` 处的脚本。

    URL 通常通过让模块导出其 `import.meta.url` 并从创建 worker 的模块导入该 URL 来检索。

    如果指定，`options` 是一个可能包含以下一个或多个键的对象：

    -   `onMessage`: 当 worker 使用 **[send()](#communication-send)** 发出消息时调用的函数。
        回调签名与 **[recv()](#communication-recv)** 相同。

-   `terminate()`: 终止 worker。

-   `post(message[, data])`: 向 worker 发布消息。签名与 **[send()](#communication-send)** 相同。
    在 worker 内部使用 **[recv()](#communication-recv)** 接收它。

-   `exports`: 用于调用 worker 定义的 **[rpc.exports](#rpc-exports)** 的魔术代理对象。
    每个函数返回一个 *Promise*，你可以在 *async* 函数内部 *await* 它。


### Cloak

让你在进程内省期间看不到自己。

诸如 [`Process.enumerateThreads()`](#process-enumeratethreads) 之类的内省 API 确保跳过隐形资源，
并且事情看起来就像你不在被检测的进程中一样。

Frida 运行时创建的任何资源都将自动隐形。这意味着你通常只需要在使用特定于操作系统的 API 创建给定资源时管理隐形资源。

+   `Cloak.addThread(id)`: 更新隐形资源注册表，使给定的线程 `id` 对隐形感知 API 不可见，
    例如 [`Process.enumerateThreads()`](#process-enumeratethreads)。

+   `Cloak.removeThread(id)`: 更新隐形资源注册表，使给定的线程 `id` 对隐形感知 API 可见，
    例如 [`Process.enumerateThreads()`](#process-enumeratethreads)。

+   `Cloak.hasCurrentThread()`: 返回一个布尔值，指示当前线程当前是否被隐形。

+   `Cloak.hasThread(id)`: 返回一个布尔值，指示给定的线程 `id` 当前是否被隐形。

+   `Cloak.addRange(range)`: 更新隐形资源注册表，使给定的内存 `range` 对隐形感知 API 不可见，
    例如 [`Process.enumerateRanges()`](#process-enumerateranges)。
    提供的 `range` 是一个具有 `base` 和 `size` 属性的对象——就像例如
    [`Process.getModuleByName()`](#process-getmodulebyname) 返回的对象中的属性一样。
    {: #cloak-addrange}

+   `Cloak.removeRange(range)`: 更新隐形资源注册表，使给定的内存 `range` 对隐形感知 API 可见，
    例如 [`Process.enumerateRanges()`](#process-enumerateranges)。
    提供的 `range` 是一个具有 `base` 和 `size` 属性的对象——就像例如
    [`Process.getModuleByName()`](#process-getmodulebyname) 返回的对象中的属性一样。

+   `Cloak.hasRangeContaining(address)`: 返回一个布尔值，指示包含 `address` 的内存范围当前是否被隐形，
    指定为 [NativePointer](#nativepointer)。

+   `Cloak.clipRange(range)`: 确定给定的内存 `range` 当前有多少是可见的。
    提供的 `range` 是一个具有 `base` 和 `size` 属性的对象——就像例如
    [`Process.getModuleByName()`](#process-getmodulebyname) 返回的对象中的属性一样。
    返回此类对象的数组，指示 `range` 的可见部分。如果整个范围被隐形，将返回一个空数组，
    如果它完全可见，则返回 `null`。

+   `Cloak.addFileDescriptor(fd)`: 更新隐形资源注册表，使给定的文件描述符 `fd` 对隐形感知 API 不可见。

+   `Cloak.removeFileDescriptor(fd)`: 更新隐形资源注册表，使给定的文件描述符 `fd` 对隐形感知 API 可见。

+   `Cloak.hasFileDescriptor(fd)`: 返回一个布尔值，指示给定的文件描述符 `fd` 当前是否被隐形。


### Profiler

建立在 `Interceptor` 之上的简单最坏情况分析器。

与以特定频率对调用堆栈进行采样的传统分析器不同，你决定你感兴趣的分析的确切函数。

当任何这些函数被调用时，分析器会在进入时获取一个样本，并在返回时获取另一个样本。
然后它减去这两个样本，以计算调用的昂贵程度。如果结果值大于它之前为特定函数看到的值，
则该值将成为其新的最坏情况。

每当发现新的最坏情况时，知道大部分时间/周期/等都花在特定函数上并不一定足够。
例如，该函数可能仅在某些输入参数下很慢。

这是你可以为特定函数传递 [`describe`](#profiler-describe) 回调的情况。
你的回调应该从参数列表和/或其他相关状态捕获相关上下文，并返回一个描述刚刚发现的新最坏情况的字符串。

当你稍后决定调用 `generateReport()` 时，你会发现你计算的描述嵌入在每个最坏情况条目中。

+   `new Profiler()`: 创建一个 Profiler。

-   `instrument(functionAddress, sampler[, callbacks])`: 开始使用 [`sampler`](#sampler)
    检测由 `functionAddress` [`NativePointer`](#nativepointer) 指定的指定函数。

    可选的 `callbacks` 参数是一个可能包含以下内容的对象：

    -   `describe(args)`: 当发现新的最坏情况并且应该从参数列表和/或其他相关状态捕获描述时同步调用。
        实现必须返回描述参数列表的字符串。有关 `args` 以及 `this` 如何绑定的更多详细信息，
        请参阅 Interceptor [`onEnter`](#interceptor-onenter)。
        {: #profiler-describe}

-   `generateReport()`: 从实时分析器状态生成 XML 报告，作为字符串返回。可以在任何时候调用，次数不限。


### Sampler

-   `sample()`: 检索一个新样本，作为 bigint 返回。它表示什么取决于特定的采样器。


### CycleSampler

测量 CPU 周期的采样器，例如在 x86 上使用 RDTSC 指令。

+   `new CycleSampler()`: 创建一个 CycleSampler。

### BusyCycleSampler

仅测量当前线程花费的 CPU 周期的采样器，例如在 Windows 上使用
QueryThreadCycleTime()。

+   `new BusyCycleSampler()`: 创建一个 BusyCycleSampler。


### WallClockSampler

测量时间流逝的采样器。

+   `new WallClockSampler()`: 创建一个 WallClockSampler。


### UserTimeSampler

测量在用户空间花费的时间的采样器。

+   `new UserTimeSampler([threadId])`: 创建一个 UserTimeSampler，对 `threadId` 指定的线程进行采样（作为数字），
    如果省略，则对当前线程进行采样。


### MallocCountSampler

计算 malloc()、calloc() 和 realloc() 调用次数的采样器。

+   `new MallocCountSampler()`: 创建一个 MallocCountSampler。


### CallCountSampler

计算对你选择的函数的调用次数的采样器。

+   `new CallCountSampler(functions)`: 创建一个 CallCountSampler，
    对 `functions` 的调用次数进行采样，`functions` 是一个 [`NativePointer`](#nativepointer) 值数组，
    指定要计算调用次数的函数。


[r2]: https://radare.org/r/
