---
layout: news_item
title: 'Frida 1.0.10 Released'
date: 2014-02-16 01:51:00 +0100
author: oleavr
version: 1.0.10
categories: [release]
---

This release brings a few improvements:

-   `Interceptor` is now compatible with a lot more functions on iOS/ARM.
-   A new CLI tool called `frida-repl` provides you with a basic REPL to
    experiment with the JavaScript API from inside a target process.
-   `onLeave` callback passed to `Interceptor.attach()` is now able to replace
    the return value by calling `retval.replace()`.
-   Both `onEnter` and `onLeave` callbacks passed to `Interceptor.attach()` can
    access `this.errno` (UNIX) or `this.lastError` (Windows) to inspect or
    manipulate the current thread's last system error.

Here's how you can combine the latter three to simulate network conditions for
a specific process running on your Mac:

{% highlight bash %}
~ $ frida-repl TargetApp
{% endhighlight %}

Then paste in:

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

Enjoy!
