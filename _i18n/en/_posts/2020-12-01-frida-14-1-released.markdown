---
layout: news_item
title: 'Frida 14.1 Released'
date: 2020-12-01 12:00:00 +0200
author: oleavr
version: 14.1
categories: [release]
---

Lots of goodies this time! 🎉 Let's dive in.

## Dependencies

We've just upgraded all of our dependencies to the latest and greatest. Part of
this work included refurbishing the build system bits used for building them.

With these improvements we will finally support building past versions of Frida
fully from source, which has been a long-standing issue that's caused a lot of
frustration.

It is now also a whole lot easier to tweak our dependencies, e.g. while
debugging an issue. Say you're troubleshooting why *Thread.backtrace()* isn't
working well on Android, you might want to play around with libunwind's
internals. It is now really easy to build one specific dependency:

{% highlight bash %}
$ make -f Makefile.sdk.mk FRIDA_HOST=android-arm64 libunwind
{% endhighlight %}

Or if you're building it for the local system:

{% highlight bash %}
$ make -f Makefile.sdk.mk libunwind
{% endhighlight %}

But you might already have built Frida, and want to switch out libunwind in the
prebuilt SDK that it is using. To do that you can now do:

{% highlight bash %}
$ make -f Makefile.sdk.mk symlinks-libunwind
{% endhighlight %}

You can then keep making changes to “deps/libunwind”, and perform an incremental
compilation by re-running:

{% highlight bash %}
$ make -f Makefile.sdk.mk libunwind
{% endhighlight %}

## iOS

We now support iOS 14.2. It was kinda already working, but our crash reporter
integration would deadlock Apple's crash reporter, and this isn't great for
system stability overall.

## GumJS support for size_t and ssize_t

Thanks to [@mame82][] we finally support “size_t” and “ssize_t” in APIs
such as *NativeFunction*. This means that your cross-platform agents no longer
need to maintain mappings to the native types that these correspond to. Yay!

## System GLib support

[Gum][] can finally be built with the upstream version of GLib, and we now
support generating [GObject introspection][] definitions. This paves the way for
future language bindings that are fully auto-generated.

Kudos to [@meme][] for these awesome improvements!

## Windows inprocess injection

Our Windows backend finally supports inprocess injection. By this I mean that in
the most common cases where the target process' architecture is the same – and
no elevation is needed – we can now avoid writing out “frida-helper-{32,64}.exe”
to a temporary directory and launching it before we're able to *attach()* to a
given target. As an added bonus this also reduces our startup time.

The motivation behind this improvement was to fix a long-standing issue where
some endpoint security products would prevent our injector from working, as our
logic was prone to trigger false positives in such software. We will still
obviously run into such issues when we *do* need to spawn our helpers, but
there's now a good chance that the most common use-cases will actually work.

## Stalker ARM improvements

For those of you using Stalker on 32-bit ARM, it should now be working a whole
lot better than ever before. A whole slew of fixes landed in this release.

## Bytecode and frida-tools

One of the realizations since 14.0 was released is that QuickJS' bytecode format
is a lot more volatile than expected. Because of this I would caution against
using “frida-compile -b” unless your application is designed to only be used
with one exact version of Frida.

As I wasn't aware of this pitfall when cutting the previous release of
frida-tools, I opted to precompile the frida-trace agent to bytecode. Upon
realizing my mistake while working on releasing 14.1, I reverted this mistake
and released a new version of frida-tools.

So make sure you also grab its latest release while upgrading:

{% highlight bash %}
$ pip3 install -U frida-tools
{% endhighlight %}

## EOF

There's also a bunch of other exciting changes, so definitely check out the
changelog below.

Enjoy!


### Changes in 14.1.0

- All dependencies upgraded to the latest and greatest.
- Heavily refurbished build system for dependencies. Going forward we will
  finally support building past versions of Frida fully from source.
- Port iOS crash reporter integration to iOS 14.2.
- Fix error propagation when talking to iOS devices.
- Add support for “size_t” and “ssize_t” in GumJS. Thanks [@mame82][]!
- Support linking against system GLib and libffi. Thanks [@meme][]!
- Support GObject Introspection. Thanks [@meme][]!
- Improve Windows backend to support inprocess injection. This means we can
  dodge common AV heuristics and speed things up in the most common cases where
  the target process' architecture is the same, and no elevation is needed.
- Fix Stalker ARM handling of “ldr pc, [sp], #4”.
- Fix Stalker ARM clobbering of flags in IT blocks.
- Fix Stalker ARM handling of CMN/CMP/TST in IT blocks.
- Fix suppression flags for ThumbWriter instruction.
- Fix Stalker ARM exclusion logic reliability.
- Fix ARM Stalker follow() of thread in Thumb mode.
- Fix ARM Stalker SVC handling in Thumb mode.
- Fix ThumbRelocator handling of unaligned ADR.
- Move Stalker ARM to runtime VFP feature detection.
- Refuse to Interceptor.attach() without any callbacks.
- Improve GumJS error message formatting.
- Fix starvation in the V8 debugger integration.
- Keep NativeCallback alive during calls on V8 also.

### Changes in 14.1.1

- Fix CModule regression where Capstone went missing.
- Add missing CModule builtins for 32-bit ARM.
- Fix Thread.backtrace() on Android/ARM64.

### Changes in 14.1.2

- Fix Thread.backtrace() on Android/ARM.


[@mame82]: https://twitter.com/mame82
[Gum]: https://github.com/frida/frida-gum
[GObject introspection]: https://gi.readthedocs.io/en/latest/
[@meme]: https://github.com/meme
