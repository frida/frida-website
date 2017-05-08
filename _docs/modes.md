---
layout: docs
title: Modes of Operation
permalink: /docs/modes/
---

Frida provides dynamic instrumentation through its powerful instrumentation core
Gum, which is written in C. Because such instrumentation logic is prone to
change, you usually want to write it in a scripting language so you get a short
feedback loop while developing and maintaining it. This is where GumJS comes
into play. With just a few lines of C you can run a piece of JavaScript inside a
runtime that has full access to Gum's APIs, allowing you to hook functions,
enumerate loaded libraries, their imported and exported functions, read and
write memory, scan memory for patterns, etc.

## Table of contents
  1. [Injected](#injected)
  1. [Embedded](#embedded)
  1. [Preloaded](#preloaded)

## Injected

Most of the time, however, you want to spawn an existing program, attach to a
running program, or hijack one as it's being spawned, and then run your
instrumentation logic inside of it. As this is such a common way to use Frida,
it is what most of our documentation focuses on. This functionality is provided
by frida-core, which acts as a logistics layer that packages up GumJS into a
shared library that it injects into existing software, and provides a two-way
communication channel for talking to your scripts, if needed, and later unload
them. Beside this core functionality, frida-core also lets you enumerate
installed apps, running processes, and connected devices. The connected devices
are typically iOS and Android devices where frida-server is running. That
component is essentially just a daemon that exposes frida-core over TCP, on
*localhost:27042*.

## Embedded

It is sometimes not possible to use Frida in [Injected](#injected) mode, for
example on jailed iOS and Android systems. For such cases we provide you with
*frida-gadget*, a shared library that you're supposed to embed inside the app
that you want to instrument. This library starts running as soon as the dynamic
linker executes its constructor function, and exposes the same interface as
*frida-server* does, listening on *localhost:27042*. The only difference is
that the lists of running processes and installed apps only contain a single
entry, which is for the app itself. The process name is always just *Gadget*,
and the installed app's identifier is always *re.frida.Gadget*. In order to
achieve early instrumentation we let the aforementioned constructor function
block until you either *attach()* to the process, or call *resume()* after
going through the usual *spawn()* -> *attach()* -> *…apply instrumentation…*
steps. This means that existing CLI tools like [frida-trace](/docs/frida-trace/)
work the same ways you're already using them.

## Preloaded

Perhaps you're familiar with *LD_PRELOAD*, or *DYLD_INSERT_LIBRARIES*? Wouldn't
it be cool if there was *JS_PRELOAD*? This is where *frida-gadget*, the shared
library discussed in the [Embedded](#embedded) section, also provides a second
mode of operation which doesn't involve any TCP or outside communication. All
you need to do is to set the `FRIDA_GADGET_SCRIPT` environment variable to the
path to the file containing your JavaScript.

For example on Linux, just create the file `hook.js` with the contents:

{% highlight js %}
'use strict';

rpc.exports = {
  init: function () {
    Interceptor.attach(Module.findExportByName(null, 'open'), {
      onEnter: function (args) {
        var path = Memory.readUtf8String(args[0]);
        console.log('open("' + path + '")');
      }
    });
  }
};
{% endhighlight %}

The latest *frida-gadget* for your OS can be found on github::

[GitHub Releases](https://github.com/frida/frida/releases/latest)


Now just set two environment variables and launch your target process:

{% highlight bash %}
LD_PRELOAD=/path/to/frida-gadget.so \
FRIDA_GADGET_SCRIPT=/path/to/hook.js \
cat /etc/hosts
{% endhighlight %}

Use *DYLD_INSERT_LIBRARIES* on Mac and iOS. Note that */bin/cat* won't work
on El Capitan, as it ignores such attempts for system binaries.

You may also add `FRIDA_GADGET_ENV=development` while developing your
instrumentation logic, which will make *frida-gadget* watch your file for
changes and automatically reload the script whenever it changes on disk. This
will even work if your script hooks functions, like in this example above, as
all hooks are reverted automatically when the old version of the script is
unloaded.

The reason we expose an `init()` method using [Frida's RPC feature](/docs/javascript-api/#rpc)
is because *frida-gadget* will call it and wait for it to return until it lets
the program continue executing its entrypoint. This means you can return a
*Promise* if you need to do something asynchronous, e.g. *Memory.scan()* to
locate a function you want to instrument, and guarantees that you won't miss any
early calls. You may also expose a `dispose()` method if you need to perform
some explicit cleanup when the process exits or your script get unloaded before
the new version is loaded from disk (which happens with
*FRIDA_GADGET_ENV=development*).

For debugging you can use *console.log()*, *console.warn()*, and
*console.error()*, which will print to *stdout*/*stderr*.
