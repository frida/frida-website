---
layout: news_item
title: 'Frida 17.6.0 Released'
date: 2026-01-18 16:51:48 +0100
author: oleavr
version: 17.6.0
categories: [release]
---

Quite excited about this one. On Android, we’ve eliminated our two biggest
sources of system instability: our historically intrusive instrumentation of
Zygote and system_server. Thanks to [@mrmacete][], we also now have significantly
improved DebugSymbol performance on Apple platforms, along with several
stability fixes. And beyond that, there’s been a broad sweep of robustness
improvements across the board.

## Android

Let’s take a closer look at the Android-side stability work.

Before diving into Zygote and system_server, it’s worth calling out an important
piece of groundwork: our SELinux userspace library has been rebased onto a much
newer upstream to support modern binary policy formats, while retaining Android
M–specific behavior, thanks to [@AeonLucid][].

Historically, our Zygote handling relied on injecting frida-agent in order to
observe fork() transitions via our child gating feature. We had to inject code
there because the system does not allow spawning an app in a suspended state
unless it is marked debuggable.

This injection was expensive: it required stopping and restarting threads,
left artifacts behind in all future child processes, and was brittle in a number
of ways.

For example, we had to carefully hide our file descriptors to prevent Zygote
from abort()ing. And if frida-core—typically as part of frida-server—performed
the injection at an unfortunate moment, such as during an app or service launch,
it could crash that process and bring down most of user space.

We mitigated this by ptrace()ing Zygote until it reached a syscall we deemed
indicative of idleness. I never got around to implementing the same logic for
teardown, though, so that part was always risky.

Worse still, the syscall-tracing machinery itself had bugs and would fail
randomly. I initially set out to fix those, but before shipping this release I
had a different idea: what if we could replace all of this complexity with
something lightweight and purpose-built?

I paired up with [@hsorbo][] and got to work. The solution we landed on performs
all instrumentation from the outside and avoids ptrace() entirely, relying
instead on `/proc/$pid/mem`:

1. We open `/proc/$pid/mem` and scan relevant memory ranges to locate the
   ArtMethod (or Dalvik equivalent) for
   `android.os.Process.setArgV0Native()`. Since this is a native method
   implemented in `libandroid_runtime.so`, we first identify the module’s base
   address and then use Gum’s ELF parser (`Gum.ElfModule`) to compute the exact
   function pointer. This method is also ideal for child gating: by the time it
   runs, the SELinux transition has completed and the package name is known,
   conveniently passed in as the new argv0.
2. Instead of inline hooking (as we did previously, and technically still
   could), we simply swap out the function pointer inside the method struct.
3. We select a memory range containing executable code that has either already
   run and will not run again, or will only run after the fork(), such as code
   reached when the child uses certain multimedia APIs.
4. We write our “zymbiote” payload into that region. It’s small—currently
   920 bytes on arm64—so we don’t need to clobber much.
5. The method struct’s function pointer is updated to point at the payload.
6. The payload restores the original function pointer, calls the real
   implementation, and then connects to an abstract UNIX socket. It transmits
   its PID, PPID, and package name, then waits for an ACK.
7. If there’s a pending spawn() request for that package, or spawn gating is
   enabled, frida-core withholds the ACK until the application calls resume()
   with the given PID. This gives the client a chance to attach() and apply
   early instrumentation.
8. If connect() fails or a socket error occurs, the payload simply returns—so a
   frida-core crash won’t take down user space.
9. If communication succeeds and an ACK is received, the payload tail-calls
   `raise(SIGSTOP)`. The tail-call is important to make the next step safe.
10. Once frida-core observes the process in a stopped state—meaning it is no
    longer executing inside the payload—it rolls back all changes and sends
    SIGCONT. Any children not instrumented by Frida are left completely
    pristine. Previously, this was not the case, and some apps would crash due
    to RASP systems detecting lingering (albeit inert) artifacts from a prior
    frida-agent load.

That’s the approach we ended up with. Fairly straightforward in the end. The
entire payload is just 295 lines of C (including a small amount of inline
assembly for the tail-call). And since ptrace() is no longer involved at all,
interop with other tools is significantly improved.

The system_server side was a much smaller effort. We already had a tiny helper,
`frida-helper.dex`, used on non-rooted Android. We’d write it to a temporary
file, point `app_process` at it, and communicate with it to enumerate installed
apps, running processes, and so on.

This release generalizes that approach: the helper is now shared between the
Linux and Droidy backends and expanded to support additional request types,
such as launching activities and sending broadcasts.

Beyond the obvious stability benefits, this also means frida-core no longer
depends on frida-java-bridge. As a result, libart.so compatibility issues
introduced by future OS versions or Play Store updates won’t compromise
Frida’s core functionality.

The one downside of no longer injecting an internal agent into system_server is
that we lose the ability to disable the system’s default app launch timeout.
I consider this acceptable, as the same effect can still be achieved by
injecting a tiny script into system_server if needed.

## EOF

This release also includes a slew of other goodies. Be sure to check out the
changelog below for the full details.

Enjoy!

### Changelog

- android: Rebase SELinux userspace library onto a newer upstream to support
  modern binary policy formats while preserving Android M quirks.
  (Thanks to [@AeonLucid][])
- android: Move to lightweight Zygote hooking by patching
  `android.os.Process.setArgV0Native()` to trampoline through a tiny payload and
  connect back to frida-core for instrumentation. This replaces the previous
  internal-agent-in-Zygote approach and removes the dependency on
  frida-java-bridge. (Co-authored-by: [@hsorbo][])
- android: Migrate to frida-helper.dex universally, eliminating code injection
  into system_server.
- libc-shim: Fix a long-standing Android SELinux getline() allocator mismatch
  leading to heap corruption and undefined behavior.
- darwin: Speed up Objective-C method lookup by address via a rewritten
  resolver, and replace the symbolutil cache invalidator with
  GumModuleRegistry signals. The latter fixes a SIGBUS in a swizzled dyld
  notification scenario. (Thanks to [@mrmacete][])
- fruity: Throw CLOSED on TCP writes performed in a closed state to avoid an
  infinite polling loop. (Thanks to [@mrmacete][])
- fruity: Fix a USB startup/shutdown race that could deadlock the USB worker,
  making enumeration and shutdown deterministic.
- linux: Fix ptrace signal waiter forwarding and syscall tracing desync, making
  spawn/attach flows more robust in the presence of ptrace-internal stops and
  real signals.
- linux: Fix arm64 ucontext record parsing. (Thanks to [@MarlinDiary][])
- android: Handle `__pthread_start` symbol suffixes on newer Android releases so
  thread enumeration no longer spuriously treats the system as unsupported.
  (Thanks to [@MarlinDiary][])
- android: Handle APK libs in enumerateRanges(). (Thanks to [@monkeywave][])
- arm64: Avoid attempting fast Interceptor patching when it is not feasible.
  (Thanks to [@Jiay1C][])
- interceptor: Add a FORCE attach flag to allow inline hooking even when the
  function is too small to safely patch. This may overwrite bytes past the end
  and should be used with care.
- elf: Forcibly hook the RTLD notifier when needed, and improve ELF module hash
  parsing and validation (including correct GNU hash parsing for ELF32).
- frida-node: Use Symbol descriptions instead of coercion, avoiding
  “Cannot convert a Symbol value to a string” errors in XPC-related usage.
  (Thanks to [@mrmacete][])

[@AeonLucid]: https://x.com/AeonLucid
[@hsorbo]: https://x.com/hsorbo
[@mrmacete]: https://x.com/bezjaje
[@MarlinDiary]: https://github.com/MarlinDiary
[@monkeywave]: https://github.com/monkeywave
[@Jiay1C]: https://github.com/Jiay1C
