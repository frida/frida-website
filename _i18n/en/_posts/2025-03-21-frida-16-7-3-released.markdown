---
layout: news_item
title: 'Frida 16.7.3 Released'
date: 2025-03-21 15:43:12 +0100
author: oleavr
version: 16.7.3
categories: [release]
---

Well, sometimes software is hard. Here's a quick update to fix our CI:

- ci: Temporarily drop arm64beilp32 from the package-linux job. Since some
  components haven't been ported to this architecture yet, we are suspending its
  inclusion in our Linux packages until the porting work is complete.

- ci: Bump pypa/gh-action-pypi-publish to latest v1.
