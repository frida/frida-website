---
layout: news_item
title: 'Frida 12.2 Released'
date: 2018-09-11 22:00:00 +0200
author: mrmacete
version: 12.2
categories: [release]
---

Let's talk about iOS kernel introspection. It's been a while since Frida got
basic support for introspection of the iOS kernel, but in the last months we
kept improving on that. Today's release includes significant additions to our
Kernel API to work with recent 64-bit kernels.

## Kernel base

You can get the kernel's base address by reading the `Kernel.base` property.
Having the base allows for example to calculate the slid virtual address of
any symbol you already know from static analysis of the kernel cache.

## Kernel memory search

The memory search API has been ported to the Kernel, so you can use
`Kernel.scan()` (or `Kernel.scanSync()`) in the same way you use `Memory.scan()`
(or `Memory.scanSync()`) in userland. This is a powerful primitive which,
combined with the recent bit mask feature, allows you to create your own symbol
finding code by searching for arm64 patterns.

## KEXTs and memory ranges

With `Kernel.enumerateModules()` (or `Kernel.enumerateModulesSync()`) it's now
possible to get the names and the offsets of all the KEXTs.

`Kernel.enumerateModuleRanges()` (or `Kernel.enumerateModuleRangesSync()`) is
the way to enumerate all the memory ranges defined by the Mach-O sections
belonging to a module (by name) filtering by protection. The result is similar
to what you can get in userland when calling `Module.enumerateRanges()` but it
also includes the section names.

## Final notes

All Kernel APIs don't rely on `NativePointer` because its size depends on the
user-space which doesn't necessarily match the kernel space one. Instead all
addresses are represented as `UInt64` objects.

All of this, plus the existing JavaScript interfaces for reading, writing, and
allocating kernel memory can provide a powerful starting point to build your own
kernel analysis or vulnerability research tools.

Note that this is to be considered experimental and messing with the kernel in
random ways can wildly damage your devices, so be careful, and happy hacking!

## Troubleshooting

### Problem: Kernel.available is false

The Kernel API is available if both of these conditions are met:

- Your device is jailbroken
- Frida is able to get a send right to the kernel task, either by traditional
  `task_for_pid (0)` or by accessing the host special port 4 (which is what
  modern jailbreaks are doing)

The recommended way to accomplish the latter is to attach to the system session,
i.e. PID 0, and load your scripts there.

### Problem: can't do much with my 32-bit kernel

Yes, that could improve in the future but 32-bit iOS is quite far down on the
list of priorities nowadays, but you're very welcome to contribute and send PRs.

### Problem: I was trying to do X and the kernel panicked

Don't worry that's normal. You can go to the
`/private/var/mobile/Library/Logs/CrashReporter` directory on your device, or
navigate to Settings -> Privacy -> Analytics -> Analytics Data, find your panic
log and figure out what you (or Frida) did wrong. Remember: the Kernel is always
right!

### Problem: I unrecoverably damaged my device using Frida Kernel APIs

Sorry to hear, if the damage is at the hardware level and you can dedicate
enough time and money you can probably repair it yourself by following tutorials
at [https://ifixit.com](https://ifixit.com).
