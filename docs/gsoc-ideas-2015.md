---
layout: docs
title: GSoC Ideas 2015
prev_section: contributing
next_section: history
permalink: /docs/gsoc-ideas-2015/
---

## Make Android a first-class Frida citizen

**Brief explanation:** While Frida does currently support Android, there
are two missing pieces that result in a lot of friction when instrumenting
Android apps, and we need to improve on those:

- Packaging: Package up frida-server and either run it as a system
daemon or bundle a launcher app.

- Integration: Add an Android backend for automating USB device discovery
and port forwarding. This is similar to Frida's iOS «Fruity» backend that
integrates with iTunes' usbmuxd, effectively automating device discovery
and TCP port forwarding so the user just plugs in the device and starts
instrumenting mobile apps in a matter of seconds.
Implementation-wise this should be about either integrating with adb, or
embedding adb's core, which will:
  - Enumerate connected Android devices and notify the application
  whenever a hotplug event occurs.
  - Automatically forward ports as they're needed; no more error-prone
  `adb forward` every time the user attaches to a new process.

**Expected results:** Android package. Device discovery and automatic port
forwarding.

**Knowledge Prerequisite:** Vala, C

**Possible Mentors:** Ole André Vadla Ravnås &lt;[oleavr@gmail.com](mailto:oleavr@gmail.com)&gt;, Karl Trygve Kalleberg &lt;[karltk@gmail.com](mailto:karltk@gmail.com)&gt;


## Add support for Android apps running in the ART VM

**Brief explanation:** Frida currently supports Dalvik, and while most of
that code is just interacting with the JNI APIs implemented by the VM, there
are some bits that are VM-specific. The current code can be found [here](https://github.com/frida/frida-gum/blob/42b69917976f43ba3ec4297046b319970dc037dd/gum/gumscript-runtime-dalvik.js).
Adding support for the ART VM should only be a matter of improving
that implementation to add the ART-specific bits, and then expose one
unified API. The current `Dalvik` module would then just be a
deprecated alias kept around until the next major Frida release.

**Expected results:** ART VM support.

**Knowledge Prerequisite:** JavaScript, C

**Possible Mentors:** Ole André Vadla Ravnås &lt;[oleavr@gmail.com](mailto:oleavr@gmail.com)&gt;, Karl Trygve Kalleberg &lt;[karltk@gmail.com](mailto:karltk@gmail.com)&gt;


## Port Stalker to ARM

**Brief explanation:** Frida's Stalker is a very powerful code tracing engine
based on dynamic recompilation. It is currently only available for x86. Porting
it to ARM would allow [CryptoShark](https://github.com/frida/cryptoshark) to be
used on mobile apps.

Want to know more about how it's implemented for x86? Read more [here](https://medium.com/@oleavr/anatomy-of-a-code-tracer-b081aadb0df8).

**Expected results:** Stalker being able to trace code on ARM.

**Knowledge Prerequisite:** C, Assembly

**Possible Mentors:** Ole André Vadla Ravnås &lt;[oleavr@gmail.com](mailto:oleavr@gmail.com)&gt;, Karl Trygve Kalleberg &lt;[karltk@gmail.com](mailto:karltk@gmail.com)&gt;


## Port Stalker to ARM64

**Brief explanation:** Frida's Stalker is a very powerful code tracing engine
based on dynamic recompilation. It is currently only available for x86. Porting
it to ARM64 would allow [CryptoShark](https://github.com/frida/cryptoshark) to
be used on mobile apps.

Want to know more about how it's implemented for x86? Read more [here](https://medium.com/@oleavr/anatomy-of-a-code-tracer-b081aadb0df8).

**Expected results:** Stalker being able to trace code on ARM64.

**Knowledge Prerequisite:** C, Assembly

**Possible Mentors:** Ole André Vadla Ravnås &lt;[oleavr@gmail.com](mailto:oleavr@gmail.com)&gt;, Karl Trygve Kalleberg &lt;[karltk@gmail.com](mailto:karltk@gmail.com)&gt;


## Add JS API for installing a global exception handler

**Brief explanation:** Being able to install a global exception handler from
JavaScript would be very helpful for building fuzzer tools on top of Frida.

**Expected results:** Global exception handler API available in the JavaScript runtime.

**Knowledge Prerequisite:** C, JavaScript

**Possible Mentors:** Ole André Vadla Ravnås &lt;[oleavr@gmail.com](mailto:oleavr@gmail.com)&gt;, Karl Trygve Kalleberg &lt;[karltk@gmail.com](mailto:karltk@gmail.com)&gt;


## Add support for spawning apps on Android: instrument from the first instruction

**Brief explanation:** Not to be confused with support for spawning processes,
which is already present in Frida, this is about adding support for
instrumenting an Android app from the first instruction executed after Zygote
forks itself to run an app.

**Expected results:** API for spawning an Android app.

**Knowledge Prerequisite:** Vala, C

**Possible Mentors:** Ole André Vadla Ravnås &lt;[oleavr@gmail.com](mailto:oleavr@gmail.com)&gt;, Karl Trygve Kalleberg &lt;[karltk@gmail.com](mailto:karltk@gmail.com)&gt;


## Package for major distributions

**Brief explanation:** We should make it easier for Linux users to get started,
and also improve the visibility of Frida by being present in as many ecosystems
as possible.

**Expected results:** Packages for major distributions automatically published
by Frida's buildbot.

**Knowledge Prerequisite:** python

**Possible Mentors:** Ole André Vadla Ravnås &lt;[oleavr@gmail.com](mailto:oleavr@gmail.com)&gt;, Karl Trygve Kalleberg &lt;[karltk@gmail.com](mailto:karltk@gmail.com)&gt;


## Port Frida to Windows Phone

**Brief explanation:** Frida currently supports Windows, Mac, Linux, iOS, and
Android, but sadly not yet Windows Phone. Adding support for WP would require:

- An injector to get Frida's shared library injected into the target process

- Process spawn support

- JavaScript runtime that interacts with the CLR runtime
dynamically, similar to the [Dalvik JS runtime](https://github.com/frida/frida-gum/blob/42b69917976f43ba3ec4297046b319970dc037dd/gum/gumscript-runtime-dalvik.js)
that's built into Frida's JS environment.

The first two items would likely be similar to the current Windows backend,
although presumably much much simpler.

**Expected results:** Support for instrumenting Windows Phone apps.

**Knowledge Prerequisite:** JavaScript, C, CLR

**Possible Mentors:** Ole André Vadla Ravnås &lt;[oleavr@gmail.com](mailto:oleavr@gmail.com)&gt;, Karl Trygve Kalleberg &lt;[karltk@gmail.com](mailto:karltk@gmail.com)&gt;


## Expose backtracer and symbol resolving API to JavaScript

**Brief explanation:** There's currently a [Backtracer](https://github.com/frida/frida-gum/blob/42b69917976f43ba3ec4297046b319970dc037dd/gum/gumbacktracer.h)
and a [symbol resolving](https://github.com/frida/frida-gum/blob/42b69917976f43ba3ec4297046b319970dc037dd/gum/gumsymbolutil.h)
API in frida-gum that are not yet exposed to the JS runtime.

The symbol resolving API is however not just a matter of exposing this API,
as the underlying implementations will need some adjustments to work well
when injected into another process. The Windows implementation currently
relies on DbgHelp.dll being loaded, which might not be an acceptable constraint.

**Expected results:** Backtracer and symbol resolving API available in the JavaScript runtime.

**Knowledge Prerequisite:** JavaScript, C

**Possible Mentors:** Ole André Vadla Ravnås &lt;[oleavr@gmail.com](mailto:oleavr@gmail.com)&gt;, Karl Trygve Kalleberg &lt;[karltk@gmail.com](mailto:karltk@gmail.com)&gt;
