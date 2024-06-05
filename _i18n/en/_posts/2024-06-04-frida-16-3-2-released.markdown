---
layout: news_item
title: 'Frida 16.3.2 Released'
date: 2024-06-04 13:41:24 +0200
author: oleavr
version: 16.3.2
categories: [release]
---

It's time for another bug-fix release. Quite a few goodies in this one:

- darwin: Avoid thread_set_state() during injection, so we don't get killed by
  the system on e.g. macOS >= 14.5. Thanks [@\_saagarjha][] for contributing the
  first draft of the fix!
- fruity: Perform RSDCheckin on services that need it. In this way we retain
  backwards-compatibility for open_channel() of lockdown services when a
  CoreDevice tunnel is available.
- fruity: Stop caching the LockdownClient, to avoid issues with multiple
  consumers. Reproducible using frida-ps with a jailed iOS device connected.
- python: Fix the open_service() plist example.
- node: Fix spawn() options logic for undefined values. Kudos to [@as0ler][] for
  reporting and helping track this one down!
- node: Skip undefined when marshaling aux options to GVariant.
- node: Skip undefined when marshaling object to GVariant.
- node: Handle errors when marshaling to GVariant.
- node: Fix the openService() plist example.

Kudos to [@hsorbo][] for the fun and productive pair-programming on all of the
above! 🙌

Note: This release never made it out due to a CI issue, addressed in 16.3.3.


[@_saagarjha]: https://twitter.com/_saagarjha
[@as0ler]: https://twitter.com/as0ler
[@hsorbo]: https://twitter.com/hsorbo
