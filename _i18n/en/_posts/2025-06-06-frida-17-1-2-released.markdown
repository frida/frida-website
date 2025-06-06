---
layout: news_item
title: 'Frida 17.1.2 Released'
date: 2025-06-06 22:11:49 +0200
author: oleavr
version: 17.1.2
categories: [release]
---

Apparently, software *is* hard! Just hours after shipping 17.1.1 we’re back
with a follow-up that polishes both **frida-core** and **frida-node**.

### frida-core
- **Compiler** – The `DeviceManager` constructor parameter is now optional.
  It remains in the signature for ABI compatibility but is no longer used.

### frida-node (Node.js / N-API bindings)
- **Signal handling**
  - Handlers now receive `GVariant` parameters correctly.
  - Exceptions thrown inside handlers propagate instead of being swallowed.
- **Compiler** – Keeps the runtime alive while any `output` signal handler is
  connected, preventing premature exit.

Happy hacking!
