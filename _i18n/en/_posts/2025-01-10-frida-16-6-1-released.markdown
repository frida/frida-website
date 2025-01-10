---
layout: news_item
title: 'Frida 16.6.1 Released'
date: 2025-01-10 02:04:19 +0100
author: oleavr
version: 16.6.1
categories: [release]
---

A fresh release with some important fixes and improvements:

- **gumjs**: Relinquish JS lock while unreffing modules. To avoid deadlocking in
  case `dispose()` releases a cached handle. Such an operation typically requires
  acquiring a runtime linker lock. Another thread might already be holding that
  lock while waiting for the JS lock. A common scenario for that to happen is that
  the agent registers a callback with the runtime linker, called whenever a module
  is loaded or unloaded.

  Kudos to [@mrmacete][] for reporting.

- **agent**: Exclude OS/arch symbols in version script. Newer toolchains, such as
  the default toolchain on FreeBSD 14.2, don't like references to symbols that
  don't exist. Instead of listing `JNI_OnLoad`, which is only defined for Android
  builds, we use a separate version script for Android instead.

- **ci**: Move CI to FreeBSD 14.2, up from 14.0 which has gone EOL. Our FreeBSD
  CI broke at some point during the last few weeks, and this went unnoticed
  until it caused the previous release to not make it out. Oops!

[@mrmacete]: https://github.com/mrmacete
