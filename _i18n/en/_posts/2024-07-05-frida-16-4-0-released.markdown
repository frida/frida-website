---
layout: news_item
title: 'Frida 16.4.0 Released'
date: 2024-07-05 15:32:58 +0200
author: oleavr
version: 16.4.0
categories: [release]
---

This release is packing some exciting new things. Let's dive right in.

## CoreDevice

As mentioned in the 16.3.0 release notes, [@hsorbo][] and I were working on
submitting a patch for the Linux kernel's CDC-NCM driver to make it compatible
with Apple's private network interface. This has since gone [upstream][], and
will be part of Linux 6.11.

In the meantime, and for those of you using Frida on Windows, we have just
implemented a [minimal user-mode driver][] that Frida now uses when it detects
that the kernel doesn't provide one. We leveraged [lwIP][] to also do Ethernet
and IPv6 entirely in user space. The result is that Frida can support CoreDevice
on any platform supported by libusb.

## EOF

There's also a bunch of other exciting changes, so definitely check out the
changelog below.

Enjoy!

### Changelog

- fruity: Rework to support userspace CDC-NCM.
- fruity: Add support for dyld restart on iOS >= 18.
- fruity: Await ObjC runtime initialization on iOS >= 18.
- fruity: Fix gadget upload when no usbmux connection is available.
- fruity: Improve open_channel() to support tcp:service-name.
- fruity: Retry RSD port lookup on failure.
- fruity: Revive HostChannelProvider implementation.
- fruity: Skip fetching dyld symbols if libSystem is initialized.
- fruity: Wire up MacOSCoreDeviceTransport event handling.
- fruity: Fix the macOS CoreDevice connection type logic.
- fruity: Add `os.build` and `hardware` to the exposed system parameters. Thanks
  [@as0ler][]!
- server and gadget: Listen on Apple's CoreDevice tunnel network interfaces on
  iOS and tvOS.
- xpc-service: Fix handling of request() with arrays. Thanks [@hsorbo][]!
- xpc-service: Support type-annotating request parameters.
- python: Support unmarshaling tuples to GVariant.
- python: Fix unmarshaling of bool to GVariant.
- node: Support type-annotations when marshaling to GVariant.
- node: Bump Node.js requirement to `>=16 || 14 >=14.17`, to match minimatch.
- java: Fix registerClass() field item ordering on Android. Thanks [@eybisi][]!


[@hsorbo]: https://twitter.com/hsorbo
[upstream]: https://github.com/torvalds/linux/commit/3ec8d7572a69d142d49f52b28ce8d84e5fef9131
[minimal user-mode driver]: https://github.com/frida/frida-core/blob/31188db39a7c9ae24f640a34b3fdf701f4a93bb3/src/fruity/ncm.vala
[lwIP]: https://savannah.nongnu.org/projects/lwip/
[@as0ler]: https://twitter.com/as0ler
[@eybisi]: https://github.com/eybisi
