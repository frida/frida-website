---
layout: news_item
title: 'Frida 17.3.0 Released'
date: 2025-09-15 22:57:13 +0200
author: oleavr
version: 17.3.0
categories: [release]
---

Fresh beans, new features! This release brings exciting capabilities to our
Barebone and Fruity back-ends, and smooths out a few rough edges:

- barebone: Add basic support for XNU injection, successfully tested on iOS
  14.0 in QEMU. Co-authored with [@hsorbo][].
- barebone: Expose underscore-prefixed CModule symbols so they are usable from
  Frida scripts.
- fruity: Fall back to usbmux whenever a tunnel times out or hits other
  transport errors. Thanks to [@Xplo8E][] for the nudge.
- fruity: Handle CoreDevice pairing events, and match pairing requests and
  responses using a FIFO instead of the sequence number. Huge thanks to
  [@hsorbo][].
- fruity: Deal with a handful of edge-cases during teardown. Kudos to
  [@mrmacete][].

Enjoy!


[@hsorbo]: https://x.com/hsorbo
[@Xplo8E]: https://github.com/Xplo8E
[@mrmacete]: https://github.com/mrmacete
