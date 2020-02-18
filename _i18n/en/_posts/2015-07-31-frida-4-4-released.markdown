---
layout: news_item
title: 'Frida 4.4 Released'
date: 2015-07-31 19:00:00 +0100
author: oleavr
version: 4.4
categories: [release]
---

With 4.4 out the door, we can now offer you a brand new [RPC API](/docs/javascript-api/#rpc)
that makes it super-easy to communicate with your scripts and have them expose
services to your application. We also got some amazing contributions from
[Adam Brady](https://github.com/SomeoneWeird), who just ported frida-node to
[Nan](https://github.com/nodejs/nan), making it easy to build it for multiple
versions of Node.js.

So to summarize this release:

- core: add new RPC API
- python: add support for calling RPC exports
- node: add support for calling RPC exports
- node: allow posted message value to be anything serializable to JSON
- node: port to Nan

Enjoy!
