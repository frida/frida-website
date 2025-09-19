---
layout: news_item
title: 'Frida 17.3.2 Released'
date: 2025-09-19 17:16:32 +0200
author: oleavr
version: 17.3.2
categories: [release]
---

Fresh bits are ready! This release focuses on squeezing even more performance
out of our Fruity backend:

- fruity: Batch datagram delivery to make cross-thread hand-off more
  deterministic and reduce context-switch overhead.
- ncm: Rework host→device scheduling. We now keep a rolling window of OUT
  transfers and refill as soon as any URB completes, keeping the bulk pipe
  busy and bumping HS throughput from ~29 MB/s to ~34 MB/s in our tests.
- ncm: Switch to a fixed-slot NDP layout, turning the O(k²) “shrink until it
  fits” packer into an O(k) one. On a 256 MiB transfer this drops layout time
  from ~1.1 s to the noise floor.

Enjoy, and let us know how it works for you!
