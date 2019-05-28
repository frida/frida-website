---
layout: news_item
title: 'Frida 12.6 Released'
date: 2019-05-28 02:00:00 +0200
author: oleavr
version: 12.6
categories: [release]
---

After a flurry of fixes across all platforms over the last few weeks,
I figured it was time to do another minor bump to call attention to
this release.

One particular fix is worth mentioning specifically. There was a long-
standing bug in our Android Java integration, where exception delivery
would intermittently result in the process crashing with
*GetOatQuickMethodHeader()* typically in the stack-trace. Shout-out to
[Jake Van Dyke][] and [Giovanni Rocca][] for helping track this one
down. This bug has been around for as long as ART has been supported,
so this fix is worth celebrating. 🎉

Our V8 runtime is also a lot more stable, child-gating works better
than ever before, Android device compatibility is much improved, etc.

So bottom line is that this is the most stable version of Frida ever
released – and now is the time to make sure you're running Frida 12.6.

Enjoy!


[Jake Van Dyke]: https://twitter.com/giantpune
[Giovanni Rocca]: https://twitter.com/iGio90
