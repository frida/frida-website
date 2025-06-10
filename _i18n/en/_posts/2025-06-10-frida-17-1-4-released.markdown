---
layout: news_item
title: 'Frida 17.1.4 Released'
date: 2025-06-10 22:10:02 +0200
author: oleavr
version: 17.1.4
categories: [release]
---

Excited to announce Frida 17.1.4, which brings several important fixes and
improvements — most notably Android 16 support. Here’s what’s new:

- **Compiler**: Switched esbuild’s `platform` to `node`, so `package.json`
  `main` and `exports` are resolved the Node.js way, restoring compatibility for
  packages that rely on it. Kudos to [@hsorbo][] for helping track this down.
- **Plist**: Fixed `offsetIntSize` for binary property lists, ensuring
  compatibility with Core Foundation. Thanks to [@mrmacete][] for helping track
  this down.
- **Plist**: Empty dicts and arrays in XML output now use self-closing tags
  (e.g. `<dict/>`), matching Apple’s encoder.
- **Android**: Bumped `frida-java-bridge` to 7.0.3 in the `system_server`
  agent, adding Android 16 support. Thanks to [@tbodt][] — and shout-out to
  [@thinhbuzz][] for contributing an error-handling patch that resolves
  inoperability on some Android 12 devices.
- **Darwin**: Bumped `frida-objc-bridge` to 8.0.5 in internal agents.
- **GumJS**: Fixed big-endian handling of FFI arguments.

We recommend all users upgrade at their earliest convenience. Make sure you also
upgrade to frida-tools 14.1.2, also just released.

[@hsorbo]: https://twitter.com/hsorbo
[@mrmacete]: https://twitter.com/bezjaje
[@tbodt]: https://mastodon.social/@tbodt
[@thinhbuzz]: https://github.com/thinhbuzz
