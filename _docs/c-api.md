---
layout: docs
title: C API
permalink: /docs/c-api/
---

## Getting Started

The functionality that provides you the JavaScript API for injection, function manipulation, memory reading, and more is also available from C.

Frida is broken down into several modules:

| Project Name | Description | Repository |
|---|---|---|
|core|process injection|https://github.com/frida/frida-core|
|gum|augment or replace functions|https://github.com/frida/frida-gum|
|gumjs|JavaScript bindings|
|gadget|similar to frida-agent except to either DYLD_INSERT_LIBRARIES, bundle with an app, etc. and it can run either in a remote mode where it listens and looks just like frida-server|

These can each be compiled individually and are also available on [the releases page](https://github.com/frida/frida/releases).

The devkit downloads come with an example on how to use each module.

_Please click "Improve this page" above and add an example. Thanks!_
