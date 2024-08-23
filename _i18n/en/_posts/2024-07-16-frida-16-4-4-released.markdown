---
layout: news_item
title: 'Frida 16.4.4 Released'
date: 2024-07-16 15:25:08 +0200
author: oleavr
version: 16.4.4
categories: [release]
---

This release is packing a whole slew of improvements:

- darwin: Handle dyld restart on macOS Sequoia and iOS 18.
- darwin: Await ObjC init on macOS Sequoia and iOS 18, by making use of
  notifyObjCInit() if available.
- fruity: Improve CoreDevice pairing support:
  - Fix support for multiple pairing relationships.
  - Keep the in-memory peer store up-to-date, so new pairing relationships
    don't require a process restart to be able to match them up with pairing
    services on the network.
- ncm: Detach all drivers before changing configuration.
- ncm: Avoid using a broken kernel NCM driver.
- darwin: Fix sysroot on simulator. Thanks [@CodeColorist][]!
- darwin-mapper: Locally resolve shared cache symbols, to avoid resolver
  functions when possible, side-stepping our existing issue where the generated
  constructor function tries to write the result to a read-only page.
- gumjs: Fix race in recv().wait() on application thread. Thanks
  [@HexKitchen][]!
- python: Eliminate usage of unstable ref-counting APIs, so extensions built
  with newer Python headers still work on older Python runtimes.


[@CodeColorist]: https://twitter.com/CodeColorist
[@HexKitchen]: https://github.com/HexKitchen
