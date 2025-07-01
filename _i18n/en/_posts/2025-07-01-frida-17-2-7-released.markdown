---
layout: news_item
title: 'Frida 17.2.7 Released'
date: 2025-07-01 23:40:14 +0200
author: oleavr
version: 17.2.7
categories: [release]
---

We're excited to announce the release of Frida 17.2.7, featuring significant
improvements to our Package Manager.

- **package-manager**: Improve resolution and hoisting to mimic npm's behavior
  more closely. Co-authored with [@hsorbo][]. Thanks for your help!
- **package-manager**: Add `install()` option for `role`, achieving the
  equivalent of npm install's `--save-*` switches.
- **package-manager**: Add `install()` option for `omits`, to achieve the
  equivalent of npm install's `--omit=x` switch.
- **package-manager**: Improve handling of optional packages.
- **package-manager**: Handle file modes when extracting on non-Windows systems.
- **package-manager**: Fix the `has_install_script` logic to also take
  `preinstall` and `postinstall` scripts into account.
- **meson**: Clarify Vala build system instructions. The Vala README only
  mentioned autotools instructions, and when Vala is compiled that way the
  `-frida` suffix is not added to the version string, causing the frida-core
  check for Vala to fail. We now clarify that Vala needs to be built from source
  with Meson. Thanks to [@grimler][] for pointing this out!


[@hsorbo]: https://twitter.com/hsorbo
[@grimler]: https://mastodon.social/@grimler
