---
layout: news_item
title: 'Frida 8.1 Released'
date: 2016-10-25 20:00:00 +0200
author: oleavr
version: 8.1
categories: [release]
---

It's time for a release, and this time we have some big new things for those of
you building Frida-based tools, plus a few additional goodies. Let's start with
the first part.

There's no doubt that Frida's [JavaScript API][] is fairly low-level and only
meant to provide low-level building blocks that don't pertain to just one
specific use-case. If your use-case involves grabbing screenshots on iOS, for
example, this is not functionality one would expect to find in Frida itself.

You may then wonder how different tools with common features are supposed to
share agent code with each other, and luckily the answer is not “copy paste”.
We have a growing [ecosystem][] of Frida-specific libraries, like
[frida-screenshot][], [frida-uikit][], [frida-trace][], etc.

Perhaps some of you would be interested in APIs for instrumenting backend
software written in Java, .NET, Python, Ruby, or Perl, or perhaps you would want
to trace crypto APIs across different OSes and libraries, or some other cool
idea. I would then highly recommend that you publish your module to npm, perhaps
naming your module *frida-$name* to make it easy to discover.

Now you might be asking "but Frida does not support *require()*, how can I even
split my agent code into multiple files in the first place?". I'm glad you
asked! This is where a handy little CLI tool called [frida-compile][] enters
the picture.

You give it a *.js* file as input and it will take care of bundling up any other
files it depends on into just one file. But unlike a homegrown concatenation
solution using *cat*, the final result also gets an embedded source map, which
means filenames and line numbers in stack traces are meaningful. Modules are
also separated into separate closures so variables are contained and never
collide. You can also use the latest JavaScript syntax, like
[arrow functions][], [destructuring][], and [generator functions][], as it
compiles the code down to ES5 syntax for you. This means that your code also
runs on our Duktape-based runtime, which you are forced to use if you use Frida
on a jailed iOS device, or on a jailbroken iOS device running iOS >= 9.

In order to give you a short feedback loop while developing, frida-compile also
provides a watch mode through *-w*, so you get instant incremental builds as you
develop your agent.

Anyway, enough theory. Let's look at how we can use an off-the-shelf web
application framework from npm, and inject that into any process.

First, make sure you have the latest version of Node.js installed. Next, create
an empty directory and paste this into a file named “package.json”:

{% highlight json %}
{
  "name": "hello-frida",
  "version": "1.0.0",
  "scripts": {
    "prepublish": "npm run build",
    "build": "frida-compile agent -o _agent.js",
    "watch": "frida-compile agent -o _agent.js -w"
  },
  "devDependencies": {
    "express": "^4.14.0",
    "frida-compile": "^2.0.6"
  }
}
{% endhighlight %}

Then in agent.js, paste the following code:

{% highlight js %}
'use strict';

const express = require('express');

const app = express();

app
  .get('/ranges', (req, res) => {
    res.json(Process.enumerateRangesSync({
      protection: '---',
      coalesce: true
    }));
  })
  .get('/modules', (req, res) => {
    res.json(Process.enumerateModulesSync());
  })
  .get('/modules/:name', (req, res) => {
    try {
      res.json(Process.getModuleByName(req.params.name));
    } catch (e) {
      res.status(404).send(e.message);
    }
  })
  .get('/modules/:name/exports', (req, res) => {
    res.json(Module.enumerateExportsSync(req.params.name));
  })
  .get('/modules/:name/imports', (req, res) => {
    res.json(Module.enumerateImportsSync(req.params.name));
  })
  .get('/objc/classes', (req, res) => {
    if (ObjC.available) {
      res.json(Object.keys(ObjC.classes));
    } else {
      res.status(404).send('Objective-C runtime not available in this process');
    }
  })
  .get('/threads', (req, res) => {
    res.json(Process.enumerateThreadsSync());
  });

app.listen(1337);
{% endhighlight %}

Install frida-compile and build your agent in one step:

{% highlight bash %}
$ npm install
{% endhighlight %}

Then load the generated *_agent.js* into a running process:

{% highlight bash %}
$ frida Spotify -l _agent.js
{% endhighlight %}

You can now hit it with HTTP requests:

{% highlight bash %}
$ curl http://127.0.0.1:1337/ranges
$ curl http://127.0.0.1:1337/modules
$ curl http://127.0.0.1:1337/modules/libSystem.B.dylib
$ curl http://127.0.0.1:1337/modules/libSystem.B.dylib/exports
$ curl http://127.0.0.1:1337/modules/libSystem.B.dylib/imports
$ curl http://127.0.0.1:1337/objc/classes
$ curl http://127.0.0.1:1337/threads
{% endhighlight %}

Sweet. We just built a process inspection REST API with 7 different endpoints in
fewer than 50 lines of code. What's pretty cool about this is that we used an
off-the-shelf web application framework written for Node.js. You can actually
use any existing modules that rely on Node.js' built-in [net][] and [http][]
modules. Like an [FTP server][], [IRC client][], or [NSQ client][].

So up until this release you could use Frida-specific modules like those
mentioned earlier. You could also use thousands of other modules from npm, as
most of them don't do any I/O. Now with this release you also get access to
all *net* and *http* based modules, which opens up Frida for even more cool
use-cases.

In case you are curious how this was implemented, I added *Socket.listen()*
and *Socket.connect()* to Frida. These are minimal wrappers on top of [GIO][]'s
[SocketListener][] and [SocketClient][], which are already part of Frida's
technology stack and used by Frida for its own needs. So that means our
footprint stays the same with no dependencies added. Because frida-compile
uses [browserify][] behind the scenes, all we had to do was [plug in] our own
builtins for *net* and *http*. I simply ported the original *net* and *http*
modules from Node.js itself.

This release also brings some other goodies. One long-standing limitation with
*NativeFunction* is that calling a system API that requires you to read *errno*
(UNIX) or call *GetLastError()* (Windows) would be tricky to deal with. The
challenge is that Frida's own code might clobber the current thread's error
state between your *NativeFunction* call and when you try to read out the
error state.

Enter *SystemFunction*. It is exactly like *NativeFunction*, except that the
call returns an object wrapping the returned value and the error state right
afterwards. Here's an example:

{% highlight js %}
const open = new SystemFunction(
    Module.findExportByName(null, 'open'),
    'int',
    ['pointer', 'int']);
const O_RDONLY = 0;

const path = Memory.allocUtf8String('/inexistent');
const result = open(path, O_RDONLY);
console.log(JSON.stringify(result, null, 2));
/*
 * Which on Darwin typically results in the following output:
 *
 * {
 *   "value": -1,
 *   "errno": 2
 * }
 *
 * Where 2 is ENOENT.
 */
{% endhighlight %}

This release also lets you read and modify this system error value from your
*NativeCallback* passed to *Interceptor.replace()*, which might come handy if
you are replacing system APIs. Note that you could already do this with
*Interceptor.attach()*, but that's not an option in cases where you don't want
the original function to get called.

Another big change worth mentioning is that our V8 runtime has been heavily
refactored. The code is now easier to understand and it is way less work to add
new features. Not just that, but our argument parsing is also handled by a
single code-path. This means that all of our APIs are much more resilient to bad
or missing arguments, so you get a JavaScript exception instead of having some
APIs do fewer checks and happily crash the target process in case you forgot an
argument.

Anyway, those are the highlights. Here's a full summary of the changes:

8.1.0:

- core: add *Socket.listen()* and *Socket.connect()*
- core: add *setImmediate()* and *clearImmediate()*
- core: improve *set{Timeout,Interval}()* to support passing arguments
- core: fix performance-related bug in Interceptor's dirty state logic

8.1.1:

- core: add *Script.nextTick()*

8.1.2:

- core: teach *Socket.listen()* and *Socket.connect()* about UNIX sockets
- core: fix handling of *this.errno* / *this.lastError* replacement functions
- core: add *SystemFunction* API to get *errno* / *lastError* on return
- core: fix crash on *close()* during I/O with the Stream APIs
- core: fix and consolidate argument handling in the V8 runtime

8.1.3:

- core: temporarily disable Mapper on macOS in order to confirm whether this was
        the root cause of reported stability issues
- core: add *.call()* and *.apply()* to NativeFunction
- objc: fix parsing of opaque struct types

8.1.4:

- core: fix crash in the V8 runtime caused by invalid use of *v8::Eternal*
- frida-repl: add batch mode support through *-e* and *-q*

8.1.5:

- node: generate prebuilds for 6.0 (LTS) and 7.0 only

8.1.6:

- node: generate prebuilds for 4.0 and 5.0 in addition to 6.0 and 7.0

8.1.7:

- objc: fix infinite recursion when proxying some proxies
- objc: add support for proxying non-NSObject instances
- python: fix removal of signal callbacks that are member functions

8.1.8:

- core: implement hooking of single-instruction ARM functions
- core: plug leak in the handling of unhookable functions on some architectures
- core: fix *setImmediate()* callback processing behavior
- core: plug leak in *setTimeout()*
- core: fix race condition in the handling of *setTimeout(0)* and
        *setImmediate()* in the Duktape runtime
- core: fix crash when processing tick callbacks in the Duktape runtime
- core: fix lifetime issue in the Duktape runtime
- core: fix the reported module sizes on Linux
- core: fix crash when launching apps on newer versions of Android
- core: fix handling of attempts to launch Android apps not installed
- core: improve compatibility with different versions and flavors of Android by
        detecting Dalvik and ART field offsets dynamically
- core: fix unload issue on newer versions of Android, which resulted in only
        the first *attach()* succeeding and subsequent attempts all timing out
- core: move *ObjC* and *Java* into their own modules published to npm, and use
        *frida-compile* to keep baking them into Frida's built-in JS runtime
- java: improve ART compatibility by detecting ArtMethod field offsets
        dynamically
- node: update dependencies
- node: fix unhandled Promise rejection issues

8.1.9:

- core: fix use-after-free caused by race condition on script unload

8.1.10:

- core: make *ApiResolver* and *DebugSymbol* APIs preemptible to avoid deadlocks

8.1.11:

- core: use a Mach exception handler on macOS and iOS, allowing us to reliably
        catch exceptions in apps that already have a Mach exception handler of
        their own
- core: fix leak in *InvocationContext* copy-on-write logic in the Duktape
        runtime, used when storing data on *this* across *onEnter* and *onLeave*

8.1.12:

- core: fix *Interceptor* argument replacement issue in the V8 runtime,
        resulting in the argument only being replaced the first time

Enjoy!


[JavaScript API]: http://www.frida.re/docs/javascript-api/
[ecosystem]: https://www.npmjs.com/search?q=frida
[frida-screenshot]: https://www.npmjs.com/package/frida-screenshot
[frida-uikit]: https://www.npmjs.com/package/frida-uikit
[frida-trace]: https://www.npmjs.com/package/frida-trace
[frida-compile]: https://www.npmjs.com/package/frida-compile
[arrow functions]: https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Functions/Arrow_functions
[destructuring]: https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Operators/Destructuring_assignment
[generator functions]: https://github.com/tj/co
[net]: https://nodejs.org/api/net.html
[http]: https://nodejs.org/api/http.html
[FTP server]: https://github.com/frida/frida-net/tree/master/examples/ftp-server
[IRC client]: https://github.com/frida/frida-net/tree/master/examples/irc-client
[NSQ client]: https://github.com/frida/frida-net/tree/master/examples/nsq-client
[GIO]: https://developer.gnome.org/gio/stable/
[SocketListener]: https://developer.gnome.org/gio/stable/GSocketListener.html
[SocketClient]: https://developer.gnome.org/gio/stable/GSocketClient.html
[browserify]: http://browserify.org/
[plug in]: https://github.com/frida/frida-compile/blob/1eeb38d9453f812e7b404e83cb9b5d0e5dc26241/index.js#L22-L23
