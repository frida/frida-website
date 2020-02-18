---
layout: news_item
title: 'Frida 4.3 Released'
date: 2015-07-15 19:00:00 +0100
author: oleavr
version: 4.3
categories: [release]
---

It's release o'clock, and this time we have a slew of improvements all over
the place. In brief:

4.3.0:

- core: add support for getting details about the frontmost application,
        initially only for iOS
- python: add *Device.get_frontmost_application()*
- node: add *Device.getFrontmostApplication()*

4.3.1:

- core: add support for relocating PC-relative *CBZ* on arm64
- frida-repl: fix crash and loading of script on Py3k

4.3.2:

- core: add support for launching an iOS app with a URL
- dalvik: fix bug in field caching
- frida-trace: color and indent events based on thread ID and depth
- frida-ps: fix application listing on Py3k

4.3.3:

- core: re-enable the Darwin mapper after accidentally disabling it

4.3.4:

- core: gracefully handle attempts to replace functions
- core: throw an exception when Interceptor's *attach()* and *replace()* fail
- core: fix clean-up of agent sessions
- core: fix assertion logging and log to CFLog on Darwin
- dalvik: add *Dalvik.synchronized()*, *Dalvik.scheduleOnMainThread()* and
          *Dalvik.isMainThread()*
- dalvik: port *Dalvik.androidVersion* and *Dalvik.choose()* to Android 4.2.2
- python: fix the PyPI download URL for windows-i386
- frida-trace: handle *attach()* failures gracefully

4.3.5:

- frida-server: better resource tracking

4.3.6:

- core: fix for arm64 function hooking
- dalvik: fix for *Dalvik.enumerateLoadedClasses()*

4.3.7:

- objc: add *ObjC.Block* for implementing and interacting with blocks

Enjoy!
