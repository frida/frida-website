---
layout: news_item
title: 'Frida 17.4.4 Released'
date: 2025-11-01 00:38:24 +0100
author: oleavr
version: 17.4.4
categories: [release]
---

Small but important update for our Darwin users:

- darwin: Revive app listing/launching on iOS ≥ 16 when running on rootful
  systems. This brings frida-core commit dccb612 back to life after 8108d4d
  broke it while fixing two Interceptor singleton leaks. It turns out the
  leak in springboard.m was intentional, acting as init-once logic with no
  teardown expected; without it, the instrumentation we apply gets reverted
  right away. Kudos to [@alexhude][] for the heads-up.


[@alexhude]: https://github.com/alexhude
