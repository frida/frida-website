---
layout: news_item
title: 'Frida 1.6.0 发布'
date: 2014-05-29 23:00:00 +0100
author: oleavr
version: 1.6.0
categories: [release]
---

正如你们中的一些人可能已经注意到的那样，Frida 最近获得了全新的 Android 支持，允许您像在 Windows、Mac、Linux 和 iOS 上一样轻松地检测代码。这听起来可能很酷，但 Android 确实运行大量 Java 代码，这意味着您只能观察该代码正在做的任何事情的本机副作用。您当然可以使用 Frida 的 FFI API 闯入 VM，但是嘿，Frida 不应该只为您做那个肮脏的管道吗？当然应该！

这是它在行动中的样子：

{% highlight js %}
Dalvik.perform(() => {
    const Activity = Dalvik.use('android.app.Activity');
    Activity.onResume.implementation = function () {
        send('onResume() got called! Let's call the original implementation');
        this.onResume();
    };
});
{% endhighlight %}

`Dalvik.perform()` 调用负责将您的线程附加到 VM，并且在来自 Java 的回调中不是必需的。此外，第一次使用给定的类名调用 `Dalvik.use()` 时，Frida 将询问 VM 并即时构建 JavaScript 包装器。上面我们请求 [Activity](https://developer.android.com/reference/android/app/Activity.html) 类并用我们自己的版本替换其 `onResume` 的实现，并在向调试器（在您的 Windows、Mac 或 Linux 机器上运行）发送消息后继续调用原始实现。您当然可以选择根本不调用原始实现，并模拟其行为。或者，也许您想模拟错误场景：

{% highlight js %}
Dalvik.perform(() => {
    const Activity = Dalvik.use('android.app.Activity');
    const Exception = Dalvik.use('java.lang.Exception');
    Activity.onResume.implementation = function () {
        throw Exception.$new('Oh noes!');
    };
});
{% endhighlight %}

所以您刚刚实例化了一个 Java 异常，并直接从您的 `Activity.onResume` 的 JavaScript 实现中抛出它。

此版本还附带了一些其他运行时好东西：

- `Memory.copy(dst, src, n)`: 就像 memcpy
- `Memory.dup(mem, size)`: `Memory.alloc()` 后跟 `Memory.copy()` 的简写
- `Memory.writeXXX()`: 缺少的 `Memory.read()` 对应物：S8, S16, U16, S32, U32, S64, U64, ByteArray, Utf16String 和 AnsiString
- `Process.pointerSize` 使您的脚本更便携
- `NativePointer` 实例现在有一个方便的 `isNull()` 方法
- `NULL` 常量，所以您不必到处做 `ptr("0")`
- `WeakRef.bind(value, fn)` 和 `WeakRef.unbind(id)` 给铁杆玩家：前者监视 `value`，以便一旦 `value` 被垃圾收集，或者脚本即将被卸载，`fn` 就会被调用。它返回一个 id，您可以将其传递给 `unbind()` 以进行显式清理。如果您正在构建语言绑定，其中需要在不再需要 JS 值时释放本机资源，则此 API 很有用。

享受吧！
