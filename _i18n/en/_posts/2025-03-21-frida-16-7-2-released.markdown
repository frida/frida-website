---
layout: news_item
title: 'Frida 16.7.2 Released'
date: 2025-03-21 14:21:02 +0100
author: oleavr
version: 16.7.2
categories: [release]
---

Another quick bug-fix release on the same day—it turns out software is hard!

I rolled up my sleeves and fixed the following issue:

- droidy: Fix the `MAX_MESSAGE_LENGTH` declaration. The new maximum exceeds the
  range of a `uint16`.
