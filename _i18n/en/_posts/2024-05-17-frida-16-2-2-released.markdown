---
layout: news_item
title: 'Frida 16.2.2 Released'
date: 2024-05-17 18:26:11 +0200
author: oleavr
version: 16.2.2
categories: [release]
---

It's release o'clock, and this one comes jam-packed with improvements! 🎉

## Build System

After years of being dissatisfied with our build system situation, I have
finally worked up the courage to restructure it — in a big way.

### User Experience

One of the things that bothered me was that our build system felt very eccentric
and complex. You would invoke *make* and see a menu of things you could build.
But that menu would be different depending on the OS you're running this on.
Changing build options meant either editing config.mk or overriding them on the
command-line. And if you were on Windows you'd have to use Visual Studio (MSVS).

The MSVS build system is now gone, and you can build Frida the same way you'd
build many other OSS projects:

{% highlight bash %}
$ ./configure
$ make
{% endhighlight %}

The *configure* step can be skipped if you don't need to pass any options, such
as --prefix. This script is really just a thin wrapper around Meson's setup
command, and you can pass options straight to Meson by adding `--` followed by
the options. You can also run *make install* to install things, which supports
the DESTDIR environment variable to change where the output goes.

Cross-compilation is easy too; for example if you want to build for iOS/arm64,
invoke configure with --host=ios-arm64. If you have a toolchain for an embedded
system, pass --host=$triplet, which will look for $triplet-gcc, $triplet-g++,
etc. on your PATH. You can also add CFLAGS, LDFLAGS, etc. to the environment to
pass in extra flags, just like you'd expect from other build systems.

What's cool is that our different repos can now be built standalone. You can
clone the frida-gum repo and build it, just like you can do with frida-python,
frida-tools, etc. The frida repo is no longer as important, it's only kept
around to be able to version a collection of repos, and host the CI used for
rolling new releases.

Each repo contains any needed subprojects/*.wrap files that tell Meson where it
can find the dependencies. This means if you grab frida-core and try to build it
without already having frida-gum on your PKG_CONFIG_PATH, it will grab and build
that for you automatically. What's also neat is that our Python and Node.js
bindings now make use of this to build from source if a .whl or prebuild can't
be found or downloaded.

So now that our different components work well as subprojects, this also means
anyone can integrate Frida components into their own projects just as easily.
All you need to do is add a .wrap-file to subprojects/ in your project's top
source dir, and call dependency() from your meson.build. Meson then looks on
your system first, and if it fails to find the dependency it will clone the git
repo in subprojects/ and build it as part of your project. It is also possible
to tell Meson to force such a fallback without looking on your system.

Here's what such a .wrap-file could look like for Gum:

{% highlight ini %}
[wrap-git]
url = https://github.com/frida/frida-gum.git
revision = 16.2.4
depth = 1

[provide]
dependency_names = frida-gum-1.0, frida-gum-heap-1.0, frida-gum-prof-1.0, frida-gumjs-1.0, frida-gumjs-inspector-1.0
{% endhighlight %}

And for frida-core:

{% highlight ini %}
[wrap-git]
url = https://github.com/frida/frida-core.git
revision = 16.2.4
depth = 1

[provide]
dependency_names = frida-core-1.0
{% endhighlight %}

Our thin Meson wrapper is also easy to get started with, and you can read more
about it [here][].

### A bit of history

The reason I chose to maintain a separate build system for Windows was that I
previously worked with quite a few experienced Windows developers, and noticed
they'd be a lot more excited about an OSS project if they could work on it using
their favorite IDE. It was important to them that they could look at a crash in
the debugger, jump to a frame belonging to an OSS library, and be able to add
some temporary logging code. And then hit the "Run" hotkey to have the IDE
incrementally compile and relink everything, for a short and sweet feedback
loop.

At the time, Frida's non-Windows build system was autotools. We later moved to
Meson. Although Meson has a backend for MSVS, meaning we could have it generate
MSVS project files for us, there was one issue blocking us from doing that.
Unlike MSVS, where you can mix projects targeting different machines in the same
"solution" (workspace), Meson only supports compiling for one machine at a time,
in addition to the build machine. Due to how Frida supports injecting code into
e.g. both 32- and 64-bit targets on Windows, we would introduce a usability
regression if we were to remove our MSVS build system. So because of this I
hesitated to drop the MSVS build system.

We also had the same challenge on non-Windows. I ended up solving it by writing
a Makefile that invokes Meson for each architecture, to glue it all together.
While this did work, I never got it to the point where incremental builds would
also work reliably. However, late March this year I finally settled on a way to
solve this locally in frida-core -- the only component where we need this kind
of multi-arch madness. By recursively invoking Meson from a custom_target() we
can build the needed components for the other architectures.

This took a lot of work to get working right, but once there it made things so
much more pleasant to work with in the rest of the stack. The *frida* repo's
Makefiles and shell-scripts could be dropped and replaced with Meson. The CI
became simpler and more uniform. Anyone can just clone the frida-core repo and
run *make*, and the resulting binaries would support cross-arch. (Unless
explicitly disabled through --disable-compat / -Dfrida-core:compat=disabled.)

Now you might be wondering why we're still running *make*, if we're now only
using Meson. I ended up writing a thin wrapper around Meson that automates the
downloading of prebuilt dependencies, choosing sensible linker flags for smaller
binaries, etc. The new *configure* and *Makefile* files in each repo take care
of invoking releng/meson_configure.py and releng/meson_make.py, which constitute
the thin wrapper around Meson. The *releng* directory is a submodule, shared by
Frida's repos. The other thing done before invoking the wrapper, is to also make
sure the releng submodule has been initialized and updated.

### Maintenance

Before this release we were maintaining seven different build systems:

1. Meson (main components, on non-Windows)
2. Visual Studio (main components, on Windows)
3. GNU Make (main components meta build system, on non-Windows)
4. setuptools (Python bindings)
5. GYP (Node.js bindings)
6. Xcode (Swift bindings)
7. QMake (QML bindings)

As of this release, I am excited to announce that we are down to just one build
system: Meson.

The main pain point with the previous situation was having to deal with both 1)
and 2), since they were involved in all of the main components. This meant that
something as simple as adding a source file would require knowledge of two
different build systems. Not only that, but contributors on Linux for example,
would typically have a hard time testing their Visual Studio build system
changes.

Another aspect was that developers would be less inclined to refactor their code
if something as simple as adding a new file involves dealing with two build
systems. The long-term consequence of this was that it fostered bad habits.
“Hmm, I should split this out into a separate file, but uhh… no, that's too
painful, I'm gonna add that code here for now.”

As for the remaining build systems, only used in bindings, it may not seem that
bad to maintain those -- they're typically familiar to the folks touching that
code anyway. The challenge there was the lack of pkg-config integration in all
but one of them (QMake). This meant that include paths, library paths, and
libraries to link with would end up being duplicated in multiple places. This is
particularly gnarly when linking with a static library that uses other libraries
internally, which is how our language bindings typically consume frida-core.

## New Features

Quite a few new things to be excited about in this release:

- gumjs: Add Process.runOnThread(), to make it easy to run arbitrary code on a
  specific thread. Must be used with care to avoid deadlocks/reentrancy issues.
- gumjs: Add *limit* option to Thread.backtrace(). Thanks [@davinci-tech][]!
- gumjs: Expand CModule glib.h with alternatives to deprecated APIs.
- stalker: Add StalkerIterator.put_chaining_return(). Thanks [@s1341][]!
- stalker: Add run_on_thread() and run_on_thread_sync().
- interceptor: Add support for shadow stacks on x86. Thanks [@yjugl][]!
- cpu-features: Add CET_SS flag and detection logic. Thanks [@yjugl][]!
- x86-writer: Add cpu_features field. Thanks [@yjugl][]!
- spinlock: Add try_acquire(). Thanks [@mrmacete][]!
- cloak: Add with_lock_held() and is_locked(). Thanks [@mrmacete][]!
- interceptor: Add with_lock_held() and is_locked(). Thanks [@mrmacete][]!
- darwin: Hint at macOS boot arguments when helper crashes.
- java: Support instantiating classes without constructors. Thanks
  [@AeonLucid][]!
- java: Add support for arrays of array. Thanks [@histausse][]!
- python: Make the source distribution buildable fully from source, instead of
  only supporting building using a devkit.
- python: Drop the MSVS build system.
- node: Add Meson build system, drop prebuild and node-gyp bits.
- node: Support building fully from source when a prebuilt can't be found.
- clr: Add Meson build system, drop the MSVS build system.
- qml: Add Meson build system, drop the qmake build system.
- qml: Add support for Qt 6. Thanks [@zaxo7][]!
- qml: Drop support for Qt 5.

## Bugfixes

Last but not least, we're also bringing you a long list of quality improvements:

- gumjs: Preserve thread's system error over NativeCallback invocations. Thanks
  [@HexKitchen][]!
- gumjs: Always expose thread's system error to NativeCallback.
- gumjs: Plug leak of Stalker instance.
- stalker: Fix block events disrupting exclusive access on arm64. Thanks
  [@saicao][]!
- memory: Fix patch_code() protection flipping on RWX systems.
- swift-api-resolver: Fix handling of indirect type entries.
- swift: Work around Module.load() issue on iOS Simulator. Thanks [@zydeco][]!
- base: Fix racy crash in custom GSource implementations.
- base: Fix the p2p AgentSession registration logic.
- buffer: Fix the read_string() size logic. Thanks [@hsorbo][]!
- linux: Fix early instrumentation on certain 32-bit systems.
- linux: Fix inject_library_blob() on modern Android.
- linux: Fix unreliable exec transition logic.
- linux: Fix unreliable injection when libc is absent.
- agent: Fix hang in child-gating fork() scenarios. Reproducible in situations
  where pidfd_getfd() is available but not permitted, such as inside Docker
  containers.
- windows: Use RW/RX permissions for injection. This makes Frida injection
  compatible with more software. In particular, Mozilla Firefox rejects thread
  startup if the start address is RWX. Thanks [@yjugl][]!
- darwin: Massage libunwind around Frida hooks, to avoid breaking code making
  use of exceptions, such as through @try/@catch in Objective-C. Thanks
  [@mrmacete][]!
- darwin: Take Interceptor and Cloak locks in ThreadSuspendMonitor, to extend
  its scope to prevent deadlock scenarios where threads holding the Cloak or
  Interceptor lock get suspended. Thanks [@mrmacete][]!
- darwin: Fix racy teardown of InjectInstance dispatch source.
- darwin: Fix racy teardown of SpawnInstance dispatch source.
- android: Fix child-gating of execl() and friends.
- compiler: Bump @types/frida-gum. Thanks [@s1341][]!
- modulate: Gracefully handle missing symbols. Thanks [@hsorbo][]!
- python: Move _frida package inside the frida package.

## EOF

And that pretty much sums it up. Enjoy!


[here]: https://github.com/frida/releng?tab=readme-ov-file#setting-up-a-new-project
[@davinci-tech]: https://github.com/davinci-tech
[@s1341]: https://github.com/s1341
[@yjugl]: https://github.com/yjugl
[@mrmacete]: https://twitter.com/bezjaje
[@AeonLucid]: https://twitter.com/AeonLucid
[@histausse]: https://github.com/histausse
[@zaxo7]: https://github.com/zaxo7
[@HexKitchen]: https://github.com/HexKitchen
[@saicao]: https://github.com/saicao
[@zydeco]: https://github.com/zydeco
[@hsorbo]: https://twitter.com/hsorbo
