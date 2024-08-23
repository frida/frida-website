---
layout: news_item
title: 'Frida 16.4.7 Released'
date: 2024-07-23 10:15:09 +0200
author: oleavr
version: 16.4.7
categories: [release]
---

Quick bug-fix release to address a crash on Windows:

- fruity: Fix crash when enumerating network interfaces on Windows. Some don't
  have a unicast address, and need to be ignored. Thanks [@xiofee][]!


[@xiofee]: https://github.com/xiofee
