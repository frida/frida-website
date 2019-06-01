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

### Changes in 12.6.1

- The exception delivery fix in the Android Java integration introduced
  a performance bottleneck when running the VM in interpreter mode, e.g.
  through *Java.deoptimizeEverything()*. For example when running the
  Dropbox app from start to login screen, this would take ~94 seconds
  on a Pixel 3 running Android 9, and now takes ~6 seconds.

### Changes in 12.6.2

- Android Java integration now supports more arm64 systems thanks to a
  fix contributed by [Giovanni Rocca][].
- Android Java integration once again supports being used by more than
  one script at a time.


[Jake Van Dyke]: https://twitter.com/giantpune
[Giovanni Rocca]: https://twitter.com/iGio90
