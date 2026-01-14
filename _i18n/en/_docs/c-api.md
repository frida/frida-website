## Getting Started

The functionality that provides you the JavaScript API for injection, function
manipulation, memory reading, and more is also available from C.

Frida is broken down into several modules, which we will discuss below.

These can each be compiled individually and are also available on
[the releases page](https://github.com/frida/frida/releases).

The devkit downloads come with an example on how to use each module.
Using the devkits is the best way to learn how to utilize each module.

## core

frida-core contains the main injection code.  From frida-core, you can inject
into a process, create a thread running QuickJS, and run your JavaScript.

See the [frida-core](https://github.com/frida/frida-core) repository for the source.

## gum

frida-gum allows you to augment and replace functions using C.

[This project](https://github.com/0xXA/snapchat-emulator-bypass) shows you how to augment `open`, `execve`, `__system_property_find`, and `__system_property_get` as well as how a patch can be applied from c only.

The example in the devkit shows you how to augment `open` and `close` from C only.

See the [frida-gum](https://github.com/frida/frida-gum) repository for the source.

## gumjs

frida-gumjs contains the JavaScript bindings.

## gadget

Similar to frida-agent except to either DYLD_INSERT_LIBRARIES, bundle with an
app, etc. and it can run either in a remote mode where it listens and looks just
like frida-server.

_Please click "Improve this page" above and add an example. Thanks!_
