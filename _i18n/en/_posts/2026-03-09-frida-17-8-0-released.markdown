---
layout: news_item
title: 'Frida 17.8.0 Released'
date: 2026-03-09 11:45:38 +0100
author: oleavr
version: 17.8.0
categories: [release]
---

This release brings some big improvements across the board.

## Syscall Tracer

Sometimes it's useful to observe the system calls happening inside a given
target process. Especially if the target includes some kind of Frida detection,
root detection, or any other kind of Runtime Application Self-Protection (RASP).
In such cases, spotting syscalls that check for artifacts means you can quickly
determine what kind of instrumentation/patches you need to apply to beat those
checks.

That's why, as of Frida 17.8.0, and frida-tools 14.6.1, you can now do:

{% highlight sh %}
$ frida-strace -U -f com.dexprotector.detector.envchecks
{% endhighlight %}

![frida-strace-android](/img/frida-strace-android.jpg "frida-strace vs. Android app")

Or, with an attached iPhone running the latest iOS (jailbreak not needed):

{% highlight sh %}
$ frida-strace -U -f com.toyopagroup.picaboo
{% endhighlight %}

![frida-strace-ios](/img/frida-strace-ios.jpg "frida-strace vs. iOS app")

You may also repeat `-f` any number of times to spawn multiple programs/apps, or
combine that with `-p $pid` and `-u $username` switches. Targeting by user is
not supported for iOS, though. That is a feature particularly useful on Android,
where each app has its own user account: in this way you can observe syscalls
across all processes owned by a specific app.

## EOF

This release also includes a slew of other goodies. Be sure to check out the
changelog below for the full details.

Enjoy!

### Changelog

- fruity: Implement syscall tracing on top of CoreProfile ktrace/kdebug,
  with syscall decoding, path reconstruction for filesystem-related calls,
  stitched-in callstacks, and symbolication support.
- Support spawning non-debuggable apps by falling back to ProcessControlService
  and suspending them with signals when LLDB-based launching is not an option.
- dtx: Add CoreProfileService, extend ProcessControlService, upgrade
  protocol handling, lift buffering restrictions, and improve handling of
  nil arguments and bulk data.
- linux: Make the Linux syscall-tracer eBPF backend more verifier-friendly, bump
  the BPF log buffer size, and align the Linux syscall-trace protocol with
  the latest cross-platform format.
- android: Load the ART/Dalvik VM and run frida-helper.dex in-process. This
  eliminates a whole host of edge-cases, including ROM compatibility cases.
- android-helper: Fix initialization crash on some Transsion-based ROMs by
  using Looper.prepareMainLooper(). Thanks [@depreciating][]!
- android: Fix linker detection and export resolution on newer Android versions.
- libc-shim: Improve stdio coverage, add versioned fopen/fopen64 support
  for libstdc++, and avoid teardown-time undefined behavior by skipping
  deinit unless explicitly requested.
- elf-module: Improve symbol enumeration by falling back to .dynsym when
  needed, and tighten symbol name bounds checks. Thanks [@danielbaier][]!
- gumjs: Add column metadata to the SQLite API. Thanks [@codecolorist][]!
- objc-api-resolver: Realize collected classes before copying methods to
  avoid crashes and undefined behavior. Thanks [@mrmacete][]!
- websocket/network-stack: Improve fairness under load by pausing libsoup
  input to avoid starvation and handling incoming datagrams asynchronously.
  Thanks [@mrmacete][] and [@hsorbo][]!
- atomics: Fix `-Watomic-alignment` warnings on ABIs where `guint64` is not
  naturally 8-byte aligned.
- gum: Add Gum.Android vapi bindings.

Also, kudos to [@hsorbo][] for the fun pair-programming on the Fruity bits!


[@hsorbo]: https://x.com/hsorbo
[@depreciating]: https://github.com/depreciating
[@danielbaier]: https://x.com/danielbaier
[@codecolorist]: https://infosec.exchange/@codecolorist
[@mrmacete]: https://x.com/bezjaje
