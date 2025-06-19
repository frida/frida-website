---
layout: news_item
title: 'Frida 17.2.3 Released'
date: 2025-06-20 01:14:05 +0200
author: oleavr
version: 17.2.3
categories: [release]
---

Quick bug-fix release focusing on improvements to our package manager:

- package-manager: Fixed handling of scoped specs.

- package-manager: Handle tarballs with root entries.

  This fix ensures that tarballs containing a directory entry for "package/",
  or any files at the root level, are correctly processed.
