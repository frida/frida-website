---
layout: news_item
title: 'Frida 16.1.5 Released'
date: 2023-11-04 21:11:20 +0100
author: oleavr
version: 16.1.5
categories: [release]
---

Since our last release, [@hsorbo][] and I had a lot of fun pair-programming on a
wide range of exciting tech. Let's dive right in.

## Swift

We've introduced a brand new ApiResolver for Swift, which you can use like this:

{% highlight js %}
const r = new ApiResolver('swift');
r.enumerateMatches('functions:*CoreDevice!*RemoteDevice*')
.forEach(({ name, address }) => {
  console.log('Found:', name, 'at:', address);
});
{% endhighlight %}

There's also a new and exciting frida-tools release, 12.3.0, which upgrades
frida-trace with Swift tracing support, using the new ApiResolver:

{% highlight bash %}
$ frida-trace Xcode -y '*CoreDevice!*RemoteDevice*'
{% endhighlight %}

## Module

Our Module API now also provides *enumerateSections()* and
*enumerateDependencies()*. And for when you want to scan loaded modules for
specific section names, our existing *module* ApiResolver now lets you do
this with ease:

{% highlight js %}
const r = new ApiResolver('module');
r.enumerateMatches('sections:*!*text*/i')
.forEach(({ name, address }) => {
  console.log('Found:', name, 'at:', address);
});
{% endhighlight %}

## EOF

There's also a bunch of other exciting changes, so definitely check out the
changelog below.

Enjoy!

### Changelog

- swift-api-resolver: Add a brand new Swift API Resolver.
- module-api-resolver: Support resolving sections.
- api-resolver: Add optional *size* field to matches.
- module: Add enumerate_sections().
- module: Add enumerate_dependencies().
- device: Add unpair(). Only implemented for iOS-devices for now.
- compiler: Bump frida-compile to 16.4.1, and @types/frida-gum to 18.4.5.
- gdb: Handle empty response packets.
- gdb: Handle error reply to feature document request.
- darwin-mapper: Initialize TLV descriptors on load. Thanks [@fabianfreyer][]!
- darwin-module: Add Thread Local Variable APIs. Thanks [@fabianfreyer][]!
- darwin-module: Optimize exports enumeration slightly.
- elf-module: Improve the section ID generation.
- x86-writer: Add reg-reg {fs,gs}-based MOV insns. Thanks [@fabianfreyer][]!
- arm64-writer: Add MRS instruction. Thanks [@fabianfreyer][]!
- arm64-writer: Add UBFM, LSL, and LSR instructions. Thanks [@fabianfreyer][]!
- relocator: Improve scratch register strategy on arm64.
- interceptor: Branch to trampoline using computed scratch register.
- interceptor: Relocate tiny targets on arm64.
- linux: Handle disabled process_vm_{read,write}v(). Thanks [@Pyraun][]!
- server: Use sysroot for temporary files on rootless iOS. Thanks
  [@fabianfreyer][]!
- gumjs: Fix crash in File and Database when Interceptor is absent. Thanks
  [@mrmacete][]!
- gumjs: Fix NativePointer from number for 32-bit BE (#752). Thanks [@forky2][]!
- gumjs: Bump frida-swift-bridge to 2.0.7.
- ci: Publish prebuilds for Node.js 20 & 21, and Electron 27.
- ci: Do not publish Swift bindings for now. There's a long-standing heisenbug
  that causes the x86_64 slice to randomly end up corrupted, in turn resulting
  in CI release jobs failing. As I'm not too keen on sinking time into this
  anytime soon, considering how easy it is to build these bindings locally using
  a downloaded core devkit, simply dropping the release asset seems like the
  best solution.


[@hsorbo]: https://x.com/hsorbo
[@fabianfreyer]: https://github.com/fabianfreyer
[@Pyraun]: https://github.com/Pyraun
[@mrmacete]: https://x.com/bezjaje
[@forky2]: https://github.com/forky2
