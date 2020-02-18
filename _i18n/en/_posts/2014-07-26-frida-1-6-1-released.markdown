---
layout: news_item
title: 'Frida 1.6.1 Released'
date: 2014-07-26 19:00:00 +0100
author: oleavr
version: 1.6.1
categories: [release]
---

It's time for a bugfix release. Highlights:

- Compatibility with the Pangu iOS jailbreak on ARM64. The issue is that RWX
  pages are not available like they used to be with the evad3rs jailbreak.
- Fix occasional target process crash when detaching.
- Fix crash when trying to attach to a process the second time after failing
  to establish the first time. This primarily affected Android users, but could
  happen on any OS when using `frida-server`.
- Faster and more reliable injection on Linux/x86-64 and Android/ARM.
- Fix issues preventing hooking of HeapFree and friends on Windows.
- Upgraded GLib, libgee, json-glib and Vala dependencies for improved
  performance and bugfixes.
- No more resource leaks. Please report if you find any.

Also new since 1.6.0, as covered in my [blog post][], there is now a full-
featured [binding for Qml][]. This should be of interest to those of you
building graphical cross-platform tools.

[blog post]: https://medium.com/@oleavr/build-a-debugger-in-5-minutes-1-5-51dce98c3544
[binding for Qml]: https://github.com/frida/frida-qml
