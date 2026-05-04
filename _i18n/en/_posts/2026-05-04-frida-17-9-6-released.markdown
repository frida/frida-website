---
layout: news_item
title: 'Frida 17.9.6 Released'
date: 2026-05-04 15:25:41 +0200
author: oleavr
version: 17.9.6
categories: [release]
---

Quick bug-fix release fixing a regression on rootless iOS, where our Darwin
backend was getting a little too enthusiastic with path prefixes:

- darwin: Fix agent path on rootless iOS. `Frida.agent_path` is now absolute and
  resolved, so prepending the sysroot or `CRYPTEX_MOUNT_PATH` duplicated the
  rootless prefix and produced a non-existent path. The server now routes the
  detected prefix straight to `TemporaryDirectory.use_sysroot`, fixing
  [#1232][].


[#1232]: https://github.com/frida/frida-core/issues/1232
