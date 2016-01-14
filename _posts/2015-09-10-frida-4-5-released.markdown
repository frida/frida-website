---
layout: news_item
title: 'Frida 4.5 Released'
date: 2015-09-10 19:00:00 +0100
author: oleavr
version: 4.5
categories: [release]
---

Time for another packed release. This time we're bringing a brand new spawn
gating API that lets you catch processes spawned by the system, and tons of
Android improvements and improvements all over the place.

So without further ado, the list of changes:

4.5.0:

- core: add *Process.pageSize* constant
- core: let *Memory.alloc()* allocate raw pages when size >= page size
- core: fix NativeFunction's handling of small return types
- core: fix PC alignment when rewriting BLX instructions
- core: add spawn gating API
- core: implement *get_frontmost_application()* on Android
- core: implement *enumerate_applications()* on Android
- core: add support for spawning Android apps
- core: add support for injecting into arm64 processes on Android
- core: add support for Android M
- core: patch the kernel's live SELinux policy
- core: integrate with SuperSU to work around restrictions on Samsung kernels
- core: work around broken sigsetjmp on Android, and many other Android fixes
- core: fix crash when enumerating modules on Linux
- core: optimize exports enumeration for remote processes on Darwin
- dalvik: port to ART and deprecate *Dalvik* name, now known as *Java*
- java: add *Java.openClassFile()* to allow loading classes at runtime
- java: fixes for array conversions and field setters
- python: add support for the new spawn gating API
- python: allow script source and name to be unicode on Python 2.x also
- python: fix error-propagation in Python 3.x
- python: fix the Linux download URL computation
- node: add support for the new spawn gating API
- node: port to Nan 2.x

4.5.1:

- core: fix `ensure_host_session()` error propagation

Enjoy!
