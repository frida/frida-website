---
layout: news_item
title: 'Frida 17.5.2 Released'
date: 2025-12-15 21:28:46 +0100
author: oleavr
version: 17.5.2
categories: [release]
---

This release improves module export accuracy on Windows, makes helper spawning
more robust on Darwin, and delivers major enhancements for Swift users via
SwiftPM and the new FridaCore xcframework:

- windows: Fix Module export metadata so the `type` property accurately reflects
  the real export type instead of always reporting functions. Thanks
  [@Ninja3047][]!
- darwin: Use DO_NOT_REAP_CHILD when spawning helper, making helper launch more
  robust on systems booted without -arm64e_preview_abi by insulating the host
  process from signal-related side effects.
- python: Improve typings. Thanks [@EtienneMaheux][]!
- swift: Add SwiftPM package manifest and support; rename Frida_Private module
  to FridaCore; implement LocalizedError (when Foundation is available) and add
  error description; refine the RPC API and allow discarding call results;
  deduplicate Device instances and fix a yield/finish race in AsyncEventSource.
- swift: Add bindings for AuthenticationService, PortalService,
  EndpointParameters, PackageManager, and Compiler; add minimal GLib bindings
  (MainLoop, File, Uuid, TlsCertificate, DateTime/TimeZone) and move GLib and
  JSONGLib into a sub-namespace.
- ci: Publish frida-core releases with .xcframework.


[@Ninja3047]: https://github.com/Ninja3047
[@EtienneMaheux]: https://github.com/EtienneMaheux
