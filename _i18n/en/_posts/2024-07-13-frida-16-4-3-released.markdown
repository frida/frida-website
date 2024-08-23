---
layout: news_item
title: 'Frida 16.4.3 Released'
date: 2024-07-13 00:34:16 +0200
author: oleavr
version: 16.4.3
categories: [release]
---

This release is packing a whole slew of improvements:

- fruity: Add support for networked devices on Windows and Linux.
- ncm: Switch USB device configuration if needed.
- network-stack: Fix TcpConnection use-after-free.
- fruity: Fix the LWIP.NetworkInterface bindings.
- fruity: Remove forgotten .pcap debug output.
- dtx: Fix teardown of DTXConnection vs. DTXChannel.
- buffer: Add content validation to read_string().
- buffer: Add content validation to read_fixed_string().
- java: Fix Java.choose() on Android >= 14. Thanks [@mbricchi][]!
- java: Handle the CMC GC strategy. Thanks [@mbricchi][]!


[@mbricchi]: https://github.com/mbricchi
