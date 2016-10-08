---
layout: news_item
title: 'Frida 8.0 Released'
date: 2016-10-04 23:00:00 +0200
author: oleavr
version: 8.0
categories: [release]
---

It is time to level up to the next major version.

First off is the long-standing issue where multiple Frida clients attached to
the same process were forced to coordinate so none of them would call *detach()*
while one of the others was still using the session.

This was probably not a big deal for most users of Frida. However, we also had
the same issue if one running *frida-server* was shared by multiple clients.
You might have *frida-trace* running in one terminal while using the REPL in
another, both attached to the same process, and you wouldn't then expect one of
them calling *detach()* to result in the other one getting kicked out.

Some of you may have tried this and observed that it works as expected, but this
was due to some crazy logic in frida-server that would keep track of how many
clients were interested in the same process, so it could ignore a *detach()*
call if other clients were still subscribed to the same session. It also had
some logic to clean up a certain client's resources, e.g. scripts, if it
suddenly disconnected.

Starting with 8.0 we have moved the session awareness into the agent, and kept
the client-facing API the same, but with one little detail changed. Each call to
*attach()* will now get its own Session, and the injected agent is aware of it.
This means you can call *detach()* at any time, and only the scripts created in
your session will be destroyed. Also, if your session is the last one alive,
Frida will unload its agent from the target process.

That was the big change of this release, but we didn't stop there.

One important feature of Frida's scripts is that you can exchange messages with
them. A script may call *send(message[, data])* to send a JSON-serializable
*message*, and optionally a binary blob of *data* next to it. The latter is so
you don't have to spend CPU-cycles turning your binary data into text that you
include in the *message*.

It is also possible to communicate in the other direction, where the script
would call *recv(callback)* to get a *callback* when you *post_message()* to
it from your application. This allowed you to post a JSON-serializable *message*
to your script, but there was no support for sending a binary blob of *data*
next to it.

To address this shortcoming we renamed *post_message()* to *post()*, and gave it
an optional second argument allowing you to send a binary blob of *data* next to
it.

We also improved the C API by migrating from plain C arrays to [GBytes](https://developer.gnome.org/glib/stable/glib-Byte-Arrays.html#GBytes),
which means we are able to minimize how many times we copy the data as it flows
through our APIs.

So in closing, let's summarize the changes:

8.0.0:

- core: add support for multiple parallel sessions
- core: rename Script's *post_message()* to *post()* and add support for passing
        out-of-band binary data to the script
- core: replace C arrays with *GBytes* to improve performance
- core: fix heap corruption caused by use-after-free in libgee
- core: fix multiple crashes
- core: fix exports enumeration crash on macOS Sierra
- core: add basic support for running on Valgrind
- core: bump the macOS requirement to 10.9 so we can rely on libc++
- node: update to the new 8.x API
- python: update to the new 8.x API
- swift: update to the new 8.x API
- swift: upgrade to Swift 3
- qml: update to the new 8.x API
- clr: update to the new 8.x API
- clr: plug leaks

8.0.1:

- node: fix *Script#post()*

8.0.2:

- core: fix deadlock when calling *recv().wait()* from our JS thread

8.0.3:

- core: reduce Interceptor base overhead by up to 65%
- core: minimize Interceptor GC churn in our V8 runtime, using the same
        recycling and copy-on-write tricks as our Duktape runtime
- core: speed up *gum_process_get_current_thread_id()* on macOS and iOS

Enjoy!
