---
layout: news_item
title: 'Frida 17.1.1 Released'
date: 2025-06-06 14:11:29 +0200
author: oleavr
version: 17.1.1
categories: [release]
---

With a fresh cup of coffee, I've hammered out the following improvements:

- **Build System Improvements**:
  - Switched bundling to ESBuild for:
    - `reportcrash.js` on Darwin.
    - `osanalytics.js` on Darwin.
    - `system-server.js` on Linux.
    - The runtime in the Barebone backend.

- **Barebone Backend Fixes**:
  - Fixed ESM-handling where failing to await the returned Promise caused errors
    to be swallowed. Now, any errors will be properly reported.
  - Removed stale bridge globals.
