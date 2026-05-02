---
layout: news_item
title: 'Frida 17.9.5 Released'
date: 2026-05-02 21:13:40 +0200
author: oleavr
version: 17.9.5
categories: [release]
---

Turns out software is hard, so here's another same-day bug-fix release. This
one improves our Darwin backend:

- darwin: Reap helper on handshake error. GDBus may report EOF before
  ChildExitMonitor has observed the child exiting, leaving `child_exited` false
  and causing `obtain()` to skip its arm64e-fallback retry.
