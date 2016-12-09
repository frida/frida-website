---
layout: docs
title: Presentations
permalink: /docs/presentations/
---

## Presentations of Frida

We have presented Frida at various conferences around the world. As presentation
material becomes available, we will try to put it here.

- [OSDC 2015](https://act.osdc.no/osdc2015no/):
  [Putting the open back into closed software](https://act.osdc.no/osdc2015no/talk/6165)
  ([PDF](osdc-2015-putting-the-open-back-into-closed-software.pdf) · [Recording](https://youtu.be/tmpjftTHzH8))

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

- [OSDC 2015](https://act.osdc.no/osdc2015no/):
  [The engineering behind the reverse engineering](https://act.osdc.no/osdc2015no/talk/6195)
  ([PDF](osdc-2015-the-engineering-behind-the-reverse-engineering.pdf) · [Recording](https://youtu.be/uc1mbN9EJKQ))

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

- [NLUUG 2015](https://www.nluug.nl/activiteiten/events/nj15/index.html):
  [Frida: Putting the open back into closed software](https://www.nluug.nl/activiteiten/events/nj15/abstracts/ab08.html)
  ([Slides](https://slides.com/oleavr/nluug-2015-frida-putting-the-open-back-into-closed-software)
  · [Demos](https://github.com/frida/frida-presentations/tree/master/NLUUG2015)
  · [Recording](https://youtu.be/3lo1Y2oKkE4))

  Have this black box process that you're just dying to peek inside of? Is
  this process perhaps running on your cell phone, or on a closed-source OS,
  and you just got to interoperate with it? Is the company behind this
  proprietary software being less than forthcoming with APIs and docs?
  Well, if you know a little JavaScript and have a little persistence,
  perhaps we can help...

  In this talk, we show what you can do with Frida, a scriptable dynamic
  binary instrumentation toolkit for Windows, Mac, Linux, iOS, Android,
  and QNX. We show by example how to write snippets of custom debugging
  code in JavaScript, and then dynamically insert these scripts into running
  processes. Hook any function, spy on crypto APIs or trace private application
  code. No source code, no permission needed!

- [ZeroNights 2015](http://2015.zeronights.org/):
  [Cross-platform reversing with Frida](http://2015.zeronights.org/workshops.html)
  ([PDF](zeronights-2015-cross-platform-reversing-with-frida.pdf)
  · [Demos](https://github.com/frida/frida-presentations/tree/master/ZeroNights2015))

  Frida is a scriptable dynamic binary instrumentation toolkit aiming to
  dramatically shorten the development cycle of dynamic analysis and
  reverse-engineering tools. It also comes with some CLI tools built on top of
  its APIs. Written in portable C, released under a commercially friendly OSS
  license, with language bindings for Python, Node.js, and more, it's a tool of
  trade to deal with dynamic instrumentation of binaries on all current
  platforms (Windows, Mac, Linux, iOS, Android, and QNX).

  This workshop is for attendees who would like to get up to speed on the
  state-of-the-art in dynamic instrumentation on both desktop and mobile.
  We will start out with an intro to Frida's APIs and CLI tools, and then walk
  you through how to build a reversing tool from scratch.

  Requirements for the workshop participants:

  - 2-3 hours
  - Knowledge of the English language
  - It's great if you bring a laptop running Windows, Mac or Linux, and
    optionally also a jailbroken/rooted iOS or Android device

- [No cON Name 2015](https://www.noconname.org/):
  [Cross-platform reversing with Frida](https://www.noconname.org/)
  ([PDF](ncn-2015-cross-platform-reversing-with-frida.pdf)
  · [Demos](https://github.com/frida/frida-presentations/tree/master/NcN2015))

  Frida is a scriptable dynamic binary instrumentation toolkit aiming to
  dramatically shorten the development cycle of dynamic analysis and
  reverse-engineering tools. It also comes with some CLI tools built on top of
  its APIs. Written in portable C, released under a commercially friendly OSS
  license, with language bindings for Python, Node.js, and more, it's a tool of
  trade to deal with dynamic instrumentation of binaries on all current
  platforms (Windows, Mac, Linux, iOS, Android, and QNX).

  This workshop is for attendees who would like to get up to speed on the
  state-of-the-art in dynamic instrumentation on both desktop and mobile.
  We will start out with an intro to Frida's APIs and CLI tools, and then walk
  you through how to build a reversing tool from scratch.

  Requirements for the workshop participants:

  - 2 hours
  - Knowledge of the English language
  - It's great if you bring a laptop running Windows, Mac or Linux, and
    optionally also a jailbroken/rooted iOS or Android device

- [FOSDEM 2016](https://fosdem.org/2016/schedule/track/testing_and_automation/):
  [Testing interoperability with closed-source software through scriptable diplomacy](https://fosdem.org/2016/schedule/event/closed_source_interop/)
  ([PDF](fosdem-2016-testing-interoperability-with-closed-source-software-through-scriptable-diplomacy.pdf))

  You, of course, write open-source software. They didn’t. And for the sake of
  your mobile users, you both need to be friends. Enter Frida, the diplomat
  (she’s really only a library, but don’t tell anyone). She has coaxing
  superpowers that allow you to expose the innards of binary-only software,
  be it other libraries, operating systems, or other OS processes you must deal
  with. You can program Frida to infiltrate closed-source software, and expose
  their internals into abstractions you can use for testing the interoperability
  of your software. Want to lift some of their logic into your mock? Or replace
  a few functions in their binary code with your mocks? Hopefully, you want to
  do that using high-level languages such as JavaScript and/or Python, because
  those are the ones Frida likes the most.

  In this talk, we use Frida, the scriptable, dynamic instrumentation toolkit,
  to expose internal functionality from binary-only software. By exposing
  internal functions and data structures, tightly integrating software often
  becomes easier to test at fine granularity. What previously had to be larger
  integration tests dependent upon several running subsystems, may, with a
  little effort, become isolated test fixtures that are easier to reason about.
  We show you unfortunate souls who have to deal with this level of
  interoperability how to program Frida to identify and expose functions in
  remote processes, and how to combine these exposed functions into small test
  fixtures in a unit-testing style.

- [BSides Knoxville](https://bsidesknoxville.com/):
  [Peeking under the hood with Frida](https://bsidesknoxville2016.sched.org/event/6tCd/peeking-under-the-hood-with-frida)
  ([Recording](https://youtu.be/RINNW4xOWL8))

  Ever wanted to peek beneath the hood of an application running on your desktop
  or smart-phone? Want to know what data is passed to a particular crypto
  function? Frida is for you!

  Frida is a powerful and modern binary instrumentation framework which makes it
  simple to hook and trace arbitrary functions within target executables, and
  otherwise explore their functionality, using easy-to-write javascript. It's
  like greasemonkey for binary applications! It supports Windows, Linux, OSX,
  iOS, Android and QNX.

  This talk will introduce Frida and show how it can be used to aid in analysis
  of binary applications. It will be packed with demos.

  Time permitting, we will also discuss some of the effort that was required to
  port Frida to QNX.

- [Ekoparty 2016](https://www.ekoparty.org/):
  [Getting fun with Frida](https://www.coresecurity.com/publication/getting-fun-frida)
  
  Do you know what's Frida? Do you know what's about? What's useful for?. No, I'm not talking about the famous painter. I'm talking about a new hooking and dynamic binary instrumentation framework. 
  
  In this turbo talk, I pretend to show you this newly available framework to facilitate some daily reverse engineering tasks. I'm going to teach you which are it basic parts, why it could be useful for you, which are the advantages and disadvantages over other similar frameworks and how to use it trough some demos and code snippets.
