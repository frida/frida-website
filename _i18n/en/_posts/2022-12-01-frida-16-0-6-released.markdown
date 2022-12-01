---
layout: news_item
title: 'Frida 16.0.6 Released'
date: 2022-12-01 01:23:12 +0100
author: oleavr
version: 16.0.6
categories: [release]
---

Turns out a serious stability regression made it into Frida 16.0.3, where our
out-of-process dynamic linker for Apple OSes could end up crashing the target
process. This is especially disastrous when the target process is launchd, as it
results in a kernel panic. Thanks to the amazing work of [@mrmacete][], this
embarrassing regression is now fixed. 🎉 Enjoy!


[@mrmacete]: https://twitter.com/bezjaje
