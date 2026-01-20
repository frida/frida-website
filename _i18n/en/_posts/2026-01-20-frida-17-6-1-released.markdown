---
layout: news_item
title: 'Frida 17.6.1 Released'
date: 2026-01-20 23:12:57 +0100
author: oleavr
version: 17.6.1
categories: [release]
---

Small but important maintenance release fixing crashes in the recently
re-engineered Android Zygote instrumentation on BTI-enabled arm64 systems,
broadening compatibility across devices, alongside a GumJS crash fix and
improved out-of-the-box support for Termux environments.

- android: Place the zymbiote payload in a safer address range, avoiding
  conflicts with memory ranges used by Zygote (reverted before the forked
  app/service gets a chance to care).
- android: Fix crash in the new, minimally intrusive Zygote instrumentation on
  BTI-enabled arm64 systems by ensuring the injected payload is built with BTI
  enabled, so indirect branches into it do not fault.
- android: Tweak the statically linked OpenSSL to automatically use Termux’s
  ca-certificates, allowing Frida.PackageManager (frida-pm) to work
  out-of-the-box on Termux without requiring SSL_CERT_FILE to be set.
- compiler: Fix loading of the backend on Android by avoiding the memfd path,
  which could fail due to reopening the same underlying file with more
  restrictive permissions. We now use a temporary file even where memfd is
  supported.
- gumjs: Avoid freeing a NULL ffi_closure when NativeCallback construction fails
  (e.g. invalid argument types), preventing libffi from crashing and allowing
  the JavaScript exception to propagate instead.

Thanks to [@leg1tsoul][] for the GumJS fix, and to [@as0ler][] and
[@ApkUnpacker][] for their help tracking down the Android Zygote instrumentation
issues.

[@leg1tsoul]: https://github.com/leg1tsoul
[@as0ler]: https://x.com/as0ler
[@ApkUnpacker]: https://x.com/ApkUnpacker
