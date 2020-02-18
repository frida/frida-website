---
layout: news_item
title: 'Frida 10.6 Released'
date: 2017-09-29 19:00:00 +0200
author: oleavr
version: 10.6
categories: [release]
---

It's time for some big updates to Frida's [Gadget](/docs/gadget/).

This component is really useful when dealing with jailed iOS and Android
devices, but is now also able to cover a lot of other scenarios.

Its environment variables are now gone, and have been replaced by an optional
configuration file. Because some apps may look for loaded libraries with "Frida"
in their name as part of their "anti-debug" defenses, we now allow you to rename
Gadget's binary however you like. Along with this it now also supports three
different interaction types.

It can listen on a TCP port, like before, and it can also load scripts from the
filesystem and run fully autonomously. The latter part used to be really limited
but is now really flexible, as you can even tell it to load scripts from a
directory, where each script may have filters. This is pretty useful for
system-wide tampering, and should allow for even more interesting use-cases.

So without further ado, I would urge you all to check out the brand new docs
available [here](/docs/gadget/).

Enjoy!
