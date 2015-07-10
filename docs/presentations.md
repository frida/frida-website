---
layout: docs
title: Presentations
next_section: functions
prev_section: hacking
permalink: /docs/presentations/
---

## Presentations of Frida

We have presented Frida at various conferences around the world. As presentation
material becomes available, we will try to put it here.

- <a href="http://act.osdc.no/osdc2015no/">OSDC 2015</a>:
  <a href="http://act.osdc.no/osdc2015no/talk/6165">Putting the open back into
  closed software</a>
  (<a href="osdc-2015-putting-the-open-back-into-closed-software.pdf">PDF</a>)
  <br>
  Have this black box process that you’re just dying to peek inside of? Is
  this process perhaps running on your cell phone, or on a closed-source OS,
  and you just got to interoperate with it? Is the company behind this
  proprietary software being less than forthcoming with APIs and docs?
  Well, if you know a little JavaScript and have a little persistence,
  perhaps we can help…

  In this talk, we show what you can do with Frida, a scriptable dynamic
  binary instrumentation toolkit for Windows, Mac, Linux, iOS, Android,
  and QNX. We show by example how to write snippets of custom debugging
  code in JavaScript, and then dynamically insert these scripts into running
  processes. Hook any function, spy on crypto APIs or trace private application
  code. No source code, no permission needed!

- <a href="http://act.osdc.no/osdc2015no/">OSDC 2015</a>:
  <a href="http://act.osdc.no/osdc2015no/talk/6195">The engineering behind
  the reverse engineering<a/>
  (<a href="osdc-2015-the-engineering-behind-the-reverse-engineering.pdf">PDF</a>)
  <br>
  Ever wondered how to build your own debugger? Did you complete that assembly
  tutorial as a teenager, but never found any real life use for low-level
  programming? Need to learn more scary-sounding technical jargon to crank
  up your pay grade? If you answered “yes” to zero or more of the above,
  you might be interested in what we have to offer.

  In this talk, we dive into the engineering principles behind Frida, a
  multi-platform scriptable dynamic binary instrumentation toolkit. We
  explain the basics of operating system processes, together with the
  relevant native OS APIs. We show how to use these APIs to probe state (memory,
  registers, threads) of a target process, and how to inject your own code
  into the process. If time allows, we’ll show how Frida performs its dynamic
  instrumentation by rewriting binary code, in memory, while the target process
  is running.

