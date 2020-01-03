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
are typically iOS and Android devices where *frida-server* is running. That
component is essentially just a daemon that exposes frida-core over TCP,
listening on *localhost:27042* by default.

## Embedded

It is sometimes not possible to use Frida in [Injected](#injected) mode, for
example on jailed iOS and Android systems. For such cases we provide you with
*frida-gadget*, a shared library that you're supposed to embed inside the
program that you want to instrument. By simply loading the library it will allow
you to interact with it remotely, using existing Frida-based tools like
[frida-trace][]. It also supports a fully autonomous approach where it can run
scripts off the filesystem without any outside communication.

Read more about Gadget [here](/docs/gadget/).

## Preloaded

Perhaps you're familiar with *LD_PRELOAD*, or *DYLD_INSERT_LIBRARIES*? Wouldn't
it be cool if there was *JS_PRELOAD*? This is where *frida-gadget*, the shared
library discussed in the previous section, is really useful when configured to
run autonomously by loading a script from the filesystem.

Read more about Gadget [here](/docs/gadget/).


[frida-trace]: /docs/frida-trace/
