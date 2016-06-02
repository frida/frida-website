---
layout: news_item
title: 'Frida 7.1 Released'
date: 2016-04-04 02:00:00 +0100
author: oleavr
version: 7.1
categories: [release]
---

If you've ever used Frida to spawn programs making use of stdio you might have
been frustrated by how the spawned process' stdio state was rather undefined and
left you with very little control. Starting with this release we have started
addressing this, and programs are now always spawned with *stdin*, *stdout* and
*stderr* redirected, and you can even input your own data to *stdin* and get
the data being written to *stdout* and *stderr*. Frida's CLI tools get this
for free as this is [wired up](https://github.com/frida/frida-python/blob/4afd9debd489e3920b85cb6c542de10aabb0dcce/src/frida/application.py#L212)
in the *ConsoleApplication* base-class. If you're not using *ConsoleApplication*
or you're using a different language-binding, simply connect to the *output*
signal of the *Device* object and your handler will get three arguments each
time this signal is emitted: *pid*, *fd*, and *data*, in that order. Hit the
*input()* method on the same class to write to *stdin*. That's all there is to
it.

Now that we have normalized the stdio behavior across platforms, we will
later be able to add API to disable stdio redirection.

Beside this and lots of bug-fixes we have also massively improved the support
for spawning plain programs on Darwin, on both Mac and iOS, where *spawn()* is
now lightning fast on both and no longer messes up the code-signing status on
iOS.

So in closing, here's a summary of the changes:

7.1.0:

- core: add *Device.input()* API for writing to *stdin* of spawned processes
- core: add *Device.output* signal for propagating output from spawned processes
- core: implement the new *spawn()* stdio behavior in the Windows, Darwin, and
        Linux backends
- core: downgrade to Capstone 3.x for now due to non-trivial regressions in 4.x
- node: add support for the new stdio API
- node: add missing return to error-path
- python: add support for the new stdio API

7.1.1:

- core: fix intermittent crash in *spawn()*

7.1.2:

- core: rework the *spawn()* implementation on Darwin, now much faster and
        reliable
- core: add support for enumerating and looking up dynamic symbols on Darwin
- core: fix page size computation in the Darwin Mach-O parser

7.1.3:

- core: revert temporary hack

7.1.4:

- python: fix *ConsoleApplication* crash on EOF
- frida-trace: flush queued events before exiting

7.1.5:

- frida-repl: improve REPL autocompletion
- objc: add *ObjC.registerProtocol()* for dynamic protocol creation
- objc: fix handling of class name conflicts
- objc: allow proxies to be named

7.1.6:

- python: fix setup.py download fallback

7.1.7:

- python: improve the setup.py download fallback

7.1.8:

- python: fix the setup.py local fallback and look in home directory instead

7.1.9:

- core: fix handling of overlapping requests to attach to the same pid
- core: (Darwin) fix *spawn()* without *attach()*
- core: (Darwin) fix crash when shutdown requests overlap
- frida-server: always recycle the same temporary directory

7.1.10:

- core: (Windows) upgrade from VS2013 to VS2015
- node: add prebuild for Node.js 6.x
- python: fix handling of unicode command-line arguments on Python 2.x
- qml: use libc++ instead of libstdc++ on Mac

7.1.11:

- core: provide a proper error message when the remote Frida is incompatible
- core: ignore attempts to detach from the system session
- core: guard against *create_script()* and *detach()* overlapping
- core: fix *setTimeout()* so the delay is optional and defaults to 0
- core: (V8 runtime) fix crash when closed *File* object gets GCed
- core: (Darwin) fix intermittent crash on teardown
- core: (QNX) fix implementation of *gum_module_find_export_by_name()*
- core: (QNX) implement temporary TLS storage
- frida-repl: monitor the loaded script and auto-reload on change
- node: take *level* into account when handling log messages so *console.warn()*
        and *console.error()* go to *stderr* instead of *stdout*
- node: do not let sessions keep the runtime alive

7.1.12:

- core: fix the return value of *Memory.readByteArray()* for size = 0

7.1.13:

- core: (Linux/Android) fix export address calculation for libraries with a
        preferred base
- core: fix *Java API not available* error on Android 6.0
- java: improve ART support by taking OS version and arch into account
- frida-repl: add *--no-pause* to not pause spawned process at startup

Enjoy!
