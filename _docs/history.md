---
layout: docs
title: History
permalink: "/docs/history/"
---

Frida was born after [@oleavr][] and [@hsorbo][] had been casually
brainstorming about how they wish they could turn tedious manual reverse-
engineering into something much more fun, productive, and interactive.

Having built [oSpy][] and other custom tools to scratch reverse-engineering
itches, [@oleavr][] started piecing together [frida-gum][], a generic cross-
platform code-instrumentation library for C. At the time it was limited to
hooking functions and providing some tools to help developers write unit-
tests for memory leaks and profiling on an extremely granular level. Later it
was further improved and used to create Frida. The component [frida-core][]
would take care of all the nitty gritty details of injecting shared libraries
into arbitrary processes, and maintaining a live two-way channel with the
injected code running inside those processes. Inside that payload, [frida-gum][]
would take care of hooking functions and providing a scripting runtime using
Google's excellent [V8][] engine.

Later, in their not-so-ample spare time, [@oleavr][] and [@karltk][] did some
recreational pair-programming-hackathons that resulted in [huge improvements][]
to [frida-gum][]'s code tracing engine, the so-called [Stalker][]. There were
also Python bindings created. They started realizing that it was about time
that people out there knew about the project, so further hackathons were devoted
to piecing together a website and some much needed documentation.

Today, Frida should be a very helpful toolbox for anyone interested in dynamic
instrumentation and/or reverse-engineering. There are now language bindings
for [python][], [.NET][], and even a [browser plugin][].


[@oleavr]: https://twitter.com/oleavr
[@hsorbo]: https://twitter.com/hsorbo
[@karltk]: https://twitter.com/karltk
[frida-core]: https://github.com/frida/frida-core/
[frida-gum]: https://github.com/frida/frida-gum/
[Stalker]: https://github.com/frida/frida-gum/blob/master/gum/backend-x86/gumstalker-x86.c
[huge improvements]: http://blog.kalleberg.org/post/833101026/live-x86-code-instrumentation-with-frida
[python]: https://pypi.python.org/pypi/frida
[.NET]: http://build.frida.re/frida/windows/x64-Release/bin/Frida.dll
[browser plugin]: http://build.frida.re/frida/mac/lib/browser/plugins/libnpfrida.dylib
[oSpy]: https://code.google.com/p/ospy/
[V8]: https://code.google.com/p/v8/
