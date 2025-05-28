---
layout: news_item
title: 'Frida 17.0.6 Released'
date: 2025-05-28 23:17:13 +0200
author: oleavr
version: 17.0.6
categories: [release]
---

Quick bug-fix release with an important contribution from [@londek][]. In this
release, we've addressed the following issue:

- **darwin**: Fixed the launchd agent, which was still using an old GumJS API
  that has since been removed. This prevented the agent from functioning on
  jailbroken iOS/iPadOS/tvOS systems.

[@londek]: https://github.com/londek
