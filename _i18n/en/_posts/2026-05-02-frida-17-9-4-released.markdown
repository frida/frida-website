---
layout: news_item
title: 'Frida 17.9.4 Released'
date: 2026-05-02 15:48:49 +0200
author: oleavr
version: 17.9.4
categories: [release]
---

Frida 17.9.4 is out, with fixes and improvements focused on Darwin,
Apple TLS compatibility, and a couple of gnarly correctness bugs:

- darwin: Store helper tempfiles in the container's Caches directory instead
  of ~/.Trash. xctest sandboxes deny exec from .Trash, while Caches is
  writable and executable everywhere we need it.
- darwin: Replace the helper handshake's filesystem socket with a socketpair.
  This avoids macOS' 104-byte sun_path limit when HOME is deeply nested,
  such as inside a sandbox container. Helper crashes during dyld startup now
  surface as PROCESS_NOT_FOUND more reliably.
- darwin: Thin the helper to arm64 in installed mode too, using the same
  universal-binary fallback without shipping two artifacts.
- darwin: Skip no-op stdio dup2() actions. posix_spawn rejects dup2(fd, fd)
  with EBADF when the source fd is a FIFO inherited from a parent like Node.
- darwin: Fix posix_spawn error reporting by using its return value, as it may
  not update errno. Failures no longer show up as "Undefined error: 0".
- macos: Implement the applications API using NSWorkspace and LaunchServices
  metadata, and support spawning applications by bundle identifier.
- build: Install frida-agent correctly in shared+installed mode by ensuring
  the lipo target exists and the universal frida-agent.dylib gets installed.
- base: Add a flat-layout fallback in AssetLocation, allowing uninstalled
  builds to resolve assets placed next to the library.
- compat: Build frida-agent with OpenSSL TLS on Apple when the parent build
  uses gioapple. This avoids injecting Security, Network, and CoreFoundation
  into targets, which the injector cannot do safely.
- agent: Avoid building a duplicate host-arch agent when compat already owns
  it, fixing a Darwin universal lipo failure.
- value: Fix Json.Reader root-node ownership so we keep the original
  parser-owned node alive. This avoids json-glib's buggy node-copy behavior,
  where child parent pointers can keep pointing at freed nodes.
- interceptor: Fix the shared deflector on arm64e by signing the dispatcher
  thunk pointer.
- tests: Add Darwin spawn-application coverage, and tolerate empty nvram
  boot-args output when the setting is unset.
