---
layout: news_item
title: 'Frida 14.2 Released'
date: 2021-02-10 10:00:00 +0200
author: oleavr
version: 14.2
categories: [release]
---

So much to talk about. Let's kick things off with a big new feature:

## Realms

Frida has supported Android for quite a while, but one particular feature has
kept getting requested (mostly) by users who thought they were looking at a bug.
The conversation usually started something like: “I'm using Frida inside the
hardware-accelerated Android emulator X, and when I attach to this process Y,
Process.enumerateModules() is missing JNI library Z. But I can see it in
Process.enumerateRanges() and /proc/$pid/maps. How come?”

As you may have guessed, we're talking about Android's NativeBridge, typically
used on Intel-powered Android devices to enable them to run apps that only
support ARM – i.e. apps with one or more JNI components only built for ARM.

In a Frida context, however, we're usually talking about a VirtualBox-based
emulator that runs an Android system built for x86. This system then ships with
NativeBridge support powered by libhoudini, a proprietary ARM translator.

There's quite a few of these emulators, e.g. BlueStacks, LDPlayer, NoxPlayer,
etc. While the ones mentioned are optimized for running games, there's now also
Google's official Android 11 AVDs which ship with NativeBridge support out of
the gate.

Through the years I've been thinking about how we could support such scenarios
in Frida, but thinking about it always made my head hurt a little. It did feel
like something we should support at some point, though, I just had a hard time
figuring out what the API would look like.

Then along came 2020 and Apple announced their transition to ARM, and suddenly
Rosetta became relevant once again. “Alright”, I thought, “now we have two
platforms where it would be useful to support processes containing an emulated
realm that's running legacy code.”

And yeah there's also Windows, but we don't yet support Windows on ARM. We
totally should though, so if somebody's interested in taking a stab at this
then please *do* get in touch.

Anyway, I'm exited to announce that our Android binaries for x86 and x86_64
now support such processes out of the box. You may already be familiar with
the following frida-core API, where the Python flavor looks like this:

{% highlight python %}
session = device.attach(target)
{% endhighlight %}

(Or *frida.attach()* if your code only deals with the local system.)

If *target* has an emulated realm, you can now do:

{% highlight python %}
session = device.attach(target, realm='emulated')
{% endhighlight %}

The default is `realm='native'`, and you can actually use both realms at the
same time. And when using our CLI tools, pass `--realm=emulated` to act on the
emulated realm.

One important caveat when using this on Android is that you will need to apply
your Java-level instrumentation in the *native* realm.

Lastly it's worth noting that this new feature is only supported on Android for
now, but it shouldn't be hard to support Rosetta on macOS down the road.
Definitely get in touch if you want to help out with this.

## Taking Android Java Hooking Inline

The way Frida's [Java bridge][] replaces Java methods on Android has up until
now been accomplished by mutating the in-memory method metadata so that the
target method becomes native – if it wasn't already. This allows us to install
a NativeCallback that matches the given method's JNI signature.

This has presented some challenges, as the ART runtime does have other internal
state that depends on the given method's personality. We have devised a few
hacks to dance around some of these issues, but some particularly gnarly
edge-cases remained unsolved. One such example is JIT profiling data maintained
by the ART VM.

An idea I had been thinking about for a while was to stop mutating the method
metadata, and instead perform inline hooking of the AOT-generated machine code –
for non-native methods that is. That still leaves methods run on the VM's
interpreter, but the assumption was that we could deal with those by hooking
VM internals.

I took a stab at an early prototype to explore this approach further. It seemed
like it could work, but there were still many challenges to work through. After
some brainstorming with [@muhzii][], he kept working on evolving this rough PoC
further in his spare time. Then one day I almost fell off my chair out of pure
excitement when I saw the amazing pull-request he had just opened.

Thanks to Muhammed's amazing work, you can now all enjoy a much improved Java
instrumentation experience on Android. This means improved stability and also
that direct calls won't bypass your replacement method. Yay!

## Deoptimization

For those of you using Java.deoptimizeEverything() on Android to ensure that
your hooks aren't skipped due to optimizations, there's now a more granular
alternative. Thanks to [@alkalinesec][]'s neat contribution to our Java bridge,
you can now use Java.deoptimizeBootImage(). It ensures only code in the boot
image OAT files gets deoptimized. This is a serious performance gain in some
situations where the app code itself is slow when deoptimized, and it is not
necessary to deoptimize it in order for hooks to be hit reliably.

## CModule

Another really exciting update here. The next hero in our story is [@mephi42][],
who started porting Frida to S390x. Our CModule implementation relies on TinyCC
behind the scenes, and it doesn't yet support this architecture. The system
might have a C compiler though, so @mephi42 proposed that we add support for
using GCC on systems where TinyCC cannot help us out.

I really liked this idea. Not only from the perspective of architecture support,
but also because of the potential for much faster code – TinyCC optimizes for
small compiler footprint and fast compilation, not fast code.

So needless to say I got more and more excited with each pull-request towards
GCC support. Once the last one landed it inspired me to add support for using
Apple's clang on i/macOS.

In the end we arrived at this:

{% highlight js %}
const cm = new CModule(`…`, {}, { toolchain: 'external' });
{% endhighlight %}

Where `toolchain` is either `any`, `internal`, or `external`. The default is
`any`, which means we will use TinyCC if it supports your `Process.arch`, and
fall back to `external` otherwise.

The story doesn't end here, though. While implementing support for i/macOS,
it wasn't really clear to me how we could fuse in symbols provided by the
JavaScript side. (The second argument to CModule's constructor.)

The GCC implementation uses a linker script, which is a really elegant solution
that Apple's linker doesn't support. But then it hit me: we already have our own
dynamic linker that we use for our injector.

Once I had wired that up, it seemed really obvious that we could also trivially
support skipping Clang entirely, and allow the user to pass in a precompiled
shared library.

The thinking there was that it would enable cross-compilation, but also make it
possible to implement a CModule in languages such as Swift and Rust: basically
anything that can interop with C.

So this means we now also support the following:

{% highlight js %}
const cm = new CModule(blob);
{% endhighlight %}

Where `blob` is an ArrayBuffer containing the shared library to construct it
from. For now this part is only implemented on i/macOS, but the goal is to
support this on all platforms. (Contributions welcome!)

Also, as of frida-tools 9.2, the REPL's `-C` switch also supports this, making
it easy to use an external toolchain without missing out on live-reload – which
makes for a much shorter feedback loop during development.

Taking that one step further, the CModule API now also provides a the property
`CModule.builtins`, which scaffolding tools can use to obtain the built-in
headers and preprocessor defines.

And on that note we now have such a tool in frida-tools:

{% highlight sh %}
$ mkdir pewpew
$ cd pewpew
$ frida-create cmodule
Created ./meson.build
Created ./pewpew.c
Created ./.gitignore
Created ./include/glib.h
Created ./include/gum/gumstalker.h
Created ./include/gum/gumprocess.h
Created ./include/gum/gummetalarray.h
Created ./include/gum/guminterceptor.h
Created ./include/gum/gumspinlock.h
Created ./include/gum/gummetalhash.h
Created ./include/gum/gummemory.h
Created ./include/gum/gumdefs.h
Created ./include/gum/gummodulemap.h
Created ./include/json-glib/json-glib.h
Created ./include/gum/arch-x86/gumx86writer.h
Created ./include/capstone.h
Created ./include/x86.h
Created ./include/platform.h

Run `meson build && ninja -C build` to build, then:
- Inject CModule using the REPL: frida Calculator -C ./build/pewpew.dylib
- Edit *.c, and build incrementally through `ninja -C build`
- REPL will live-reload whenever ./build/pewpew.dylib changes on disk

$ meson build && ninja -C build
…
[2/2] Linking target pewpew.dylib
$ frida Calculator -C ./build/pewpew.dylib
…
init()
[Local::Calculator]->
{% endhighlight %}

And yes, it live-reloads! Taken to the extreme you could use a file-watcher tool
and make it run `ninja -C build` whenever `pewpew.c` changes – then just save
and instantly see the instrumentation go live in the target process.

It's worth noting that you can also use the above when using the internal
CModule toolchain, as having the headers available on disk is handy for editor
features such as code completion.

## EOF

There's also a bunch of other exciting changes, so definitely check out the
changelog below.

Enjoy!


### Changes in 14.2.0

- Brand new realms API for instrumenting emulated realms inside native
  processes. Only implemented on Android for now.
- Add Java.deoptimizeBootImage(). Thanks [@alkalinesec][]!
- Add --disable-preload/-P to frida-server. Useful in case of OS compatibility
  issues where Frida crashes certain OS processes when attaching to them.
- Fix libc detection on older versions of Android.
- Fix crash when resolving export of the vDSO on Android. Thanks [@ant9000][]!
- Restore support for libhoudini on Android.
- Fix ARM cache flushing on Android 11's translator.
- Fix linker offsets for Android 5.x. Thanks [@muhzii][]!
- Start refactoring CModule's internals to prepare for multiple backends. Thanks
  [@mephi42][]!
- Fix CModule aggregate initializations on ARM.
- Fix ModuleApiResolver fast-path emitting bad matches.

### Changes in 14.2.1

- Fix CModule constructor error-path in the V8 runtime.
- Use V8 runtime for the “system_server” agent on Android.

### Changes in 14.2.2

- Fix Darwin.Mapper arm64e handling of pages without fixups. This went unnoticed
  out of pure “luck”, until our binaries eventually mutated sufficiently to
  expose this bug.

### Changes in 14.2.3

- Upgrade to using inline hooking for the ART runtime. Thanks [@muhzii][]!
- Fix direct transport regression on i/macOS, introduced by GLib upgrade where
  GLib.Socket gained GLib.Credentials support on Apple OSes. A typical symptom
  of this regression is that frida-server gets killed by Jetsam.
- Fix libffi support for stdcall, thiscall, and fastcall on 32-bit Windows.
- Extend Memory.alloc() to support allocating near a given address. Thanks
  [@muhzii][]!
- Fix relocation of RIP-relative indirect branches on x86_64. Thanks
  [@dkw72n][]!
- Improve the JVM C++ allocator API probing logic by consulting debug symbols
  before giving up. Thanks [@Happyholic1203][]!
- Upgrade SELinux libraries to support bleeding edge Android systems.
- Add gum-linux-x86_64-gir target for GIR generation. Thanks [@meme][]!

### Changes in 14.2.4

- Fix Android performance regression when ART's interpreter is used, such as
  when using deoptimizeEverything() or deoptimizeBootImage(), which results in
  our JS callbacks becoming extremely hot. Move the hot callbacks to CModule to
  speed things up.
- Fix V8 debugger support in Node.js bindings on Linux.
- Fix crash on ELF init error in the libdwarf backend.

### Changes in 14.2.5

- Fix regression on older Android systems, introduced in 14.2.4.

### Changes in 14.2.6

- Fix compatibility with legacy NativeBridge v3 and newer, where a namespace
  needs to be specified.

### Changes in 14.2.7

- Fix frida-java-bridge crash on systems where printf() renders %p without
  “0x” prefix.
- Fix jni_ids_indirection_ offset parsing on ARM64. Thanks [@muhzii][]!

### Changes in 14.2.8

- Fix GLib SO_NOSIGPIPE regression on i/macOS. This would typically result in
  frida-server dying due to SIGPIPE. Thanks [@mrmacete][]!
- Refactor CModule internals and lay foundations for GCC backend. Thanks
  [@mephi42][]!
- Add EventSink.make_from_callback() for Stalker C API consumers that only care
  about events, and don't need lifecycle hooks or code transformations.
- Emit Stalker BLOCK event at the start of the block, as this is what's the most
  intuitive, as one would expect at least as many BLOCK events as COMPILE
  events. This behavior is also the most suitable for measuring coverage.
- Add Stalker prefetch support, useful for optimizing “AFL fork server”-like
  use-cases.

### Changes in 14.2.9

- Handle permanent entries in Darwin CodeSegment backend. Starting from iOS 14.3
  on A12+ devices, mach_vm_remap() can return KERN_NO_SPACE when the target VM
  map entries are marked as “permanent”. Thanks [@mrmacete][]!
- Wire up GCC support in CModule. Thanks [@mephi42][]!
- Add CModule backend for Clang on Apple OSes.
- Add support for linking in a prebuilt CModule. (Only on i/macOS for now.)
- Finalize the CModule toolchain selection API.
- Add CModule.builtins property for tooling support.
- Generate frida-core GIR by default. Thanks [@meme][]!
- Fix regressions on Linux/MIPS.

### Changes in 14.2.10

- Improve frida-inject to support bidirectional stdio.
- Add support for Termux in frida-python: `pip install frida-tools` now works.

### Changes in 14.2.11

- Improve frida-inject to support raw terminal mode.
- Add internal policy daemon for Darwin.
- Improve Gum.Darwin.Mapper to support strict kernels.

### Changes in 14.2.12

- Fix ART method hooking reliability after GC. Thanks [@muhzii][]!

### Changes in 14.2.13

- Fix Instruction operands parsing on x86, ensuring the immediate value is
  always represented by an Int64 and never a number. Thanks [@muhzii][]!
- Fix frida-inject when process is not attached to a terminal. Thanks
  [@muhzii][]!
- Expose Base64 and Checksum GLib primitives to CModule. Thanks [@mrmacete][]!

### Changes in 14.2.14

- Fix Gadget crash on i/macOS when loaded early.
- Make frida-inject stdin communication optional. Thanks [@muhzii][]!
- Support iOS app spawn on unc0ver 6.x. Thanks [@mrmacete][]!
- Work around single-step delay when spawning iOS apps, to avoid failing
  randomly. Thanks [@mrmacete][]!
- Fix read() signature mismatch in the libc shim, which would result in a
  compilation error on newer Apple toolchains. Thanks [@Manouchehri][]!
- Fix Android enumerate_applications() name truncation on newer versions of
  Android. Kudos to [@pancake][] for reporting and helping figure this one out!
- Fix hang when target is unable to load frida-agent.
- Fix support for attaching to Windows services.
- Clean up stale Windows services before registering new ones.
- Add build option to support using installed assets instead of embedding them.
- Update iOS packaging to use installed assets.
- Add basic support for jailed Android. Thanks [@enovella_][] for all the fun
  and productive pair-programming on this one!
- Extend Arm64Writer API to support more immediates.
- Improve Stalker to support temporarily misaligned stack on arm64.
- Fix crash in Stalker follow() without a sink.
- Implement Stalker invalidation support. This allows updating the
  instrumentation without throwing away all of the translated code. Thanks
  for the assist on this one, [@p1onk][]!
- Add Gum.DarwinModule.enumerate_function_starts().
- Add Gum.DarwinGrafter for AOT grafting to be able to prepare binaries so they
  can be instrumented when runtime code modification isn't possible. Thanks for
  the assist, [@mrmacete][]!
- Add Memory.allocate_near().
- Improve Stalker performance and robustness on all supported architectures:
    - Improve call probes to probe at the target instead of at the call
      site, and take advantage of the new invalidation infrastructure.
    - Handle adding/removing call probes from within call probes.
    - Refactor callout-handling so user data can be destroyed on invalidate.
      This also eliminates the callout lock.
    - In case of self-modifying code, recompile instead of allocating a new
      block.
    - Use separate slabs for code and data, to avoid cases where we only
      use part of the slab because we run out of metadata storage.
    - Inline the first code/data slab in ExecCtx, so we use a lot less
      memory when following threads that either don't touch much code, or
      none at all in case they don't wake up.
    - Don't bother storing original code when trust_threshold is 0.
    - Simplify Stalker block metadata to reduce the per-block memory
      consumption.
- Fix result of Java.enumerateMethods() on ART. This was a bug where static
  initializer methods were being included in the enumerated set as '$init' when
  they should be skipped altogether. Thanks [@muhzii][]!
- Fix the Android/ART near memory allocation code path used during Java method
  hooking. Thanks [@muhzii][]!
- Fix handling of generic Java array types. This allows array objects obtained
  from the runtime to be reused later when marshalling array types, which is
  necessary to preserve type information particularly in cases where the type
  is dynamic. Thanks [@muhzii][]!
- Port Android/ART StackVisitor to x86, x64, and ARM32. Thanks [@P-Sc][]!
- Fix ARM cache flushing on Android. Turns out cacheflush() expects a range on
  Linux/ARM. This 32-bit Android/ARM regression was introduced in 14.2.0.
- Add a few missing TinyCC builtins for 32-bit ARM.  Kudos to [@giantpune][] for
  reporting and helping figure this one out!
- Fix wrap-around in Stalker block recycling logic.
- Fix V8 NativePointer construction from large numbers.
- Fix Stalker local thread actions on Windows.
- Fix the CModule temporary directory cleanup logic.
- Remove forgotten InspectorServer debug code.
- Fix the V8 debugger integration. Kudos to [@taviso][] for reporting!

### Changes in 14.2.15

- Fix compatibility with latest unc0ver iOS jailbreak. Thanks [@mrmacete][]!
- Add support for Anbox. Thanks [@asabil][]!
- Add Java.deoptimizeMethod(). Thanks [@liuyufei][]!
- Handle replacing ART methods that may be devirtualized. Thanks [@liuyufei][]!

### Changes in 14.2.16

- Add many missing TinyCC builtins for 32-bit ARM. Kudos to [@giantpune][] for
  reporting and helping figure this one out!
- Fix Android ART trampoline alignment when using ADRP on arm64, previously
  resulting in `Error: invalid argument` exception being thrown when attempting
  to replace some methods. Kudos to [@pandasauce][] for reporting and helping
  figure this one out!

### Changes in 14.2.17

- Enumerate Darwin imports from chained fixups, to support the latest arm64e
  binaries. Thanks [@mrmacete][]!
- Fix chained fixups handling in the jailed iOS injector. Thanks [@mrmacete][]!
- qml: Compile with *no_keywords* for GLib compatibility. Thanks [@suy][]!


[@alkalinesec]: https://twitter.com/alkalinesec
[Java bridge]: https://github.com/frida/frida-java-bridge
[@muhzii]: https://github.com/muhzii
[@mephi42]: https://github.com/mephi42
[dynamic linker]: https://github.com/frida/frida-gum/blob/master/gum/backend-darwin/gumdarwinmapper.h
[@ant9000]: https://github.com/ant9000
[@dkw72n]: https://github.com/dkw72n
[@Happyholic1203]: https://github.com/Happyholic1203
[@meme]: https://github.com/meme
[@mrmacete]: https://twitter.com/bezjaje
[@Manouchehri]: https://github.com/Manouchehri
[@pancake]: https://twitter.com/trufae
[@enovella_]: https://twitter.com/enovella_
[@p1onk]: https://twitter.com/p1onk
[@P-Sc]: https://github.com/P-Sc
[@giantpune]: https://twitter.com/giantpune
[@taviso]: https://twitter.com/taviso
[@asabil]: https://twitter.com/asabil
[@liuyufei]: https://github.com/liuyufei
[@pandasauce]: https://github.com/pandasauce
[@suy]: https://github.com/suy
