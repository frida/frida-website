---
layout: news_item
title: 'Frida 1.0.10 发布'
date: 2014-02-16 01:51:00 +0100
author: oleavr
version: 1.0.10
categories: [release]
---

此版本带来了一些改进：

-   `Interceptor` 现在与 iOS/ARM 上更多的函数兼容。
-   一个名为 `frida-repl` 的新 CLI 工具为您提供了一个基本的 REPL，以便从目标进程内部试验 JavaScript API。
-   传递给 `Interceptor.attach()` 的 `onLeave` 回调现在可以通过调用 `retval.replace()` 来替换返回值。
-   传递给 `Interceptor.attach()` 的 `onEnter` 和 `onLeave` 回调都可以访问 `this.errno` (UNIX) 或 `this.lastError` (Windows) 以检查或操作当前线程的最后一个系统错误。

以下是如何结合后三个来模拟 Mac 上运行的特定进程的网络条件：

{% highlight bash %}
~ $ frida-repl TargetApp
{% endhighlight %}

然后粘贴：

{% highlight js %}
callbacks = { \
    onEnter(args) { \
        args[0] = ptr(-1); // Avoid side-effects on socket \
    }, \
    onLeave(retval) { \
        const ECONNREFUSED = 61; \
        this.errno = ECONNREFUSED; \
        retval.replace(-1); \
    } \
}; \
Module.enumerateExports("libsystem_kernel.dylib", { \
    onMatch(exp) { \
        if (exp.name.indexOf("connect") === 0 && exp.name.indexOf("connectx") !== 0) { \
            Interceptor.attach(exp.address, callbacks); \
        } \
    }, \
    onComplete() {} \
});
{% endhighlight %}

享受吧！
