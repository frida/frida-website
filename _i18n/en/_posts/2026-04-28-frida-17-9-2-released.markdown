---
layout: news_item
title: 'Frida 17.9.2 Released'
date: 2026-04-28 12:23:22 +0200
author: oleavr
version: 17.9.2
categories: [release]
---

Frida 17.9.2 is out. This release is heavy on build-system polish and
packaging infrastructure, while also bringing new APIs, Swift binding
improvements, and a healthy batch of bug-fixes.

Highlights:

- fruity: Keep shared LLDB sessions alive until the last Gadget using them
  detaches. Thanks to [@mrmacete][].
- elf: Handle missing ELF backing files more gracefully.
- exceptor: Strip PAC bits from arm64e PCs in exception details.
- module-registry: Use r_debug for Linux RTLD notification synchronization to
  avoid reentering the dynamic linker.
- fruity-syscall-trace: Keep tracing when symbolicator signature lookup fails
  for one PID by falling back to a minimal signature. Thanks to joe.
- syscall-trace: Add include-syscall support. Thanks to [@IPMegladon][].
- stalker-x86: Free slow slabs on destroy and add the matching helper. Thanks to
  [@buherator][].
- compat/build: Fix source builds with an empty allowed-prebuild set, helping
  platforms such as FreeBSD. Thanks to [@cl45h][].
- build: Add first-class distro-packaging support. Frida Core can now be built
  as a shared library against upstream GLib and system dependencies, with
  installed assets under lib/frida-1.0, relocatable asset discovery, cleaner
  .pc/GIR/typelib output, and fewer internal subproject artifacts leaking into
  the install prefix.
- apple: Move away from OpenSSL on Darwin. TLS now uses gioapple, certificate
  generation uses SecKey, libnice uses CommonCrypto and arc4random_buf, XPC
  UUID generation uses GLib.Uuid, and macOS builds skip Fruity code that needs
  OpenSSL. There is also a new --with-apple-min-os configure flag for raising
  the Apple deployment-target floor.
- fruity: Split the portable pairing/tunnel code into its own files, drive
  TLS-PSK directly through OpenSSL on non-macOS, and fix the binary plist
  serializer's hashing/equality for Bytes values.
- core: Work around JSON-GLib's Json.Reader lifetime trap by pinning parsed root
  nodes, fixing aborts on GLib builds with runtime checks enabled.
- core: Fix frida_init_with_runtime() being overwritten by later frida_init()
  calls.
- api: Add WebRequestHandler, WebRequest, WebResponse, and endpoint
  request-handler support; expose PortalService extra-endpoint registration.
- host-session: Replace the old hardcoded provider icon blobs with bundled PNG
  resources, and add icons for the local and simulator providers.
- compiler: Keep the dynamically loaded backend resident.
- swift: Add Linux support through pkg-config, a USE_SYSTEM_FRIDA escape hatch
  on Apple platforms, WebRequestHandler bindings, PortalService endpoint
  bindings, DeviceChange async streams, broader Variant unmarshalling, and
  Swift 6 Sendable polish.
- swift: Fix NSNumber JSON classification on Apple platforms, Linux build
  breakage from CoreFoundation-only helpers, and Int32/UInt32 enum raw-value
  mismatches on MSVC.
- build: Isolate pkg-config per machine; preserve the caller's PKG_CONFIG_PATH;
  avoid Strawberry Perl's broken pkg-config.


[@mrmacete]: https://x.com/bezjaje
[@IPMegladon]: https://x.com/IPMegladon
[@buherator]: https://infosec.place/buherator
[@cl45h]: https://github.com/cl45h
