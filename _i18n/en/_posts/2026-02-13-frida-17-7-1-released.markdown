---
layout: news_item
title: 'Frida 17.7.1 Released'
date: 2026-02-13 22:48:44 +0100
author: oleavr
version: 17.7.1
categories: [release]
---

Quick bug-fix release, because software is hard and apparently also enjoys
same-day encores:

- android: Defer spawn completion until setArgV0(), by only recording the
  package name in selinux_android_setcontext() and delaying contact with
  RoboLauncher until setArgV0(). This ensures ART is ready so frida-java-bridge
  can attach to the VM.

- android: Refactor Zymbiote code and improve naming.
