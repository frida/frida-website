---
layout: news_item
title: 'Frida 16.0.0 Released'
date: 2022-10-08 02:00:19 +0200
author: oleavr
version: 16.0.0
categories: [release]
---

Hope some of you are enjoying frida.Compiler! In case you have no idea what that
is, check out the [15.2.0 release notes][].

## Performance

Back in 15.2.0 there was something that bothered me about frida.Compiler: it
would take a few seconds just to compile a tiny "Hello World", even on my
i9-12900K Linux workstation:

{% highlight bash %}
$ time frida-compile explore.ts -o _agent.js

real	0m1.491s
user	0m3.016s
sys	0m0.115s
{% endhighlight %}

After a lot of [profiling][] and insane amounts of yak shaving, I finally
arrived at this:

{% highlight bash %}
$ time frida-compile explore.ts -o _agent.js

real	0m0.325s
user	0m0.244s
sys	0m0.109s
{% endhighlight %}

That's quite a difference! This means on-the-fly compilation use-cases such as
`frida -l explore.ts` are now a lot smoother. More importantly though, it means
Frida-based tools can load user scripts this way without making their users
suffer through seconds of startup delay.

## Snapshots

You might be wondering how we made our compiler so quick to start. If you take
a peek under the hood, you'll see that it uses the TypeScript compiler. This is
quite a bit of code to parse and run at startup. Also, loading and processing
the .d.ts files that define all of the types involved is actually even more
expensive.

The first optimization that we implemented back in 15.2 was to simply use our
V8 runtime if it's available. That alone gave us a nice speed boost. However,
after a bit of profiling it was clear that V8 realized that it's dealing with
a heavy workload once we start processing the .d.ts files, and that resulted in
it spending a big chunk of time just optimizing the TypeScript compiler's code.

This reminded me of a really cool V8 feature that I'd noticed a long time ago:
[custom startup snapshots][]. Basically if we could warm up the TypeScript
compiler ahead of time and also pre-create all of the .d.ts source files when
building Frida, we could snapshot the VM's state at that point and embed the
resulting startup snapshot. Then at runtime we can boot from the snapshot and
hit the ground running.

As part of implementing this, I extended GumJS so a snapshot can be passed to
create_script(), together with the source code of the agent. There is also
snapshot_script(), used to create the snapshot in the first place.

For example:

{% highlight python %}
import frida

session = frida.attach(0)

snapshot = session.snapshot_script("const example = { magic: 42 };",
                                   warmup_script="true",
                                   runtime="v8")
print("Snapshot created! Size:", len(snapshot))
{% endhighlight %}

This snapshot could then be saved to a file and later loaded like this:

{% highlight python %}
script = session.create_script("console.log(JSON.stringify(example));",
                               snapshot=snapshot,
                               runtime="v8")
script.load()
{% endhighlight %}

Note that snapshots need to be created on the same OS/architecture/V8 version
as they're later going to be loaded on.

## V8 10.x

Another exciting bit of news is that we've upgraded V8 to 10.x, which means we
get to enjoy the latest VM refinements and JavaScript language features.
Considering that our last upgrade was more than two years ago, it's definitely a
solid upgrade this time around.

## The curse of multiple build systems, part two

As you may recall from the [15.1.15 release notes][], we were closer than ever
to reaching the milestone where all of Frida can be built with a single build
system. The only component left at that point was V8, which we used to build
using Google's GN build system. I'm happy to report that we have finally reached
that milestone. We now have a brand new Meson build system for V8. Yay!

## EOF

There's also a bunch of other exciting changes, so definitely check out the
changelog below.

Enjoy!

### Changelog

- compiler: Use snapshot to reduce startup time.
- compiler: Bump frida-compile and other dependencies.
- Add support for JavaScript VM snapshots. This is only implemented by the V8
  backend, as QuickJS does not currently support this.
- Move debugger API from Session to Script. This is necessary since V8's
  debugger works on a per-Isolate basis, and we now need one Isolate per Script
  in order to support snapshots.
- server+portal: Fix daemon parent ready fail exit. Thanks [@pachoo][]!
- resource-compiler: Add support for compression. We make use of this for
  frida.Compiler's heap snapshot.
- ipc: Bump UNIX socket buffer sizes for improved throughput.
- meson: Promote frida-payload to public API. This allows implementing custom
  payloads for use-cases where frida-agent and frida-gadget aren't suitable.
- windows: Move to Visual Studio 2022.
- windows: Move toolchain/SDK logic to use granular SDKs.
- windows: Do not rely on .py file association.
- darwin: Fix compatibility with macOS 13 and iOS >= 15.6.1.
- darwin: Use Apple's libffi-trampolines.dylib if present, so we can support
  iOS 15 and beyond. Thanks for the fun pair-programming sessions, [@hsorbo][]!
- fruity: Fix handling of USBMUXD_SOCKET_ADDRESS. Thanks [@0x3c3e][]!
- fruity: Drop support for USBMUXD_SERVER_\* envvars. Thanks [@as0ler][]!
- droidy: Improve handling of ADB envvars. Thanks [@0x3c3e][]!
- java: (android) Fix ClassLinker offset detection on Android 11 & 12 (#264).
  Thanks [@sh4dowb][]!
- java: (android) Fix early instrumentation on Android 13.
- java: Handle methods and fields prefixed with *$*. Thanks [@eybisi][]!
- android: Move to NDK r25.
- arm64: Optimize memory copy implementation.
- stalker: Ensure EventSink gets stopped on teardown.
- stalker: Fix ARM stack clobbering when branch involves a shift.
- stalker: Handle ARM PC load involving shifted register.
- stalker: Notify ARM observer when backpatches are applied.
- stalker: Apply ARM backpatches when notified.
- stalker: Add ARM support for switch block callback.
- arm-reader: Expose disassemble_instruction_at().
- thumb-reader: Expose disassemble_instruction_at().
- memory: Realign API with current V8 semantics.
- gumjs: Move V8 backend to one Isolate per script.
- gumjs: Support passing V8 flags using an env var: FRIDA_V8_EXTRA_FLAGS.
- gumjs: Use V8 write protection on Darwin/arm\*.
- gumjs: Add support for dynamically defined scripts.
- prof: Support old system headers on Linux/MIPS.
- devkit: Improve examples' compilation docs on UNIX.
- ci: Migrate remainder of the legacy CI to GitHub Actions.
- quickjs: Fix use-after-free on error during module evaluation.
- v8: Upgrade to latest V8 10.x.
- v8: Add Meson build system.
- usrsctp: Lower Windows requirement to XP, like the rest of our components.
- xz: Avoid ANSI-era Windows API.
- libc-shim: Support old system headers on Linux/MIPS.
- glib: Add Linux libc fallbacks for MIPS.
- Add config.mk option to be able to disable emulated agents on Android, to
  allow building smaller binaries. Thanks [@muhzii][]!
- python: Drop Python 2 support, modernize code, add docstrings, typings, add CI
  with modern tooling, and many other goodies. Thanks [@yotamN][]!
- python: Build Python wheels instead of eggs. Thanks [@oriori1703][]!
- python: Fix Device.get_bus(). The previous implementation called
  \_Device.get_bus(), which doesn't exist. Thanks [@oriori1703][]!
- python: Move to the stable Python C API.
- python: Add support for building from source, using a frida-core devkit.
- python: Add support for the new snapshot APIs.
- node: Add support for the new snapshot APIs.
- node: Fix Electron v20 compatibility.


[15.2.0 release notes]: {% post_url _i18n/en/2022-07-21-frida-15-2-0-released %}
[profiling]: https://github.com/frida/frida-core/blob/155328df3420ead34e485f1c4fb7e5b3fe7d71a6/tests/profile-compiler.sh
[custom startup snapshots]: https://v8.dev/blog/custom-startup-snapshots
[15.1.15 release notes]: {% post_url _i18n/en/2022-02-01-frida-15-1-15-released %}
[@pachoo]: https://github.com/pachoo
[@hsorbo]: https://twitter.com/hsorbo
[@0x3c3e]: https://github.com/0x3c3e
[@as0ler]: https://twitter.com/as0ler
[@sh4dowb]: https://github.com/sh4dowb
[@eybisi]: https://github.com/eybisi
[@muhzii]: https://github.com/muhzii
[@yotamN]: https://github.com/yotamN
[@oriori1703]: https://github.com/oriori1703
