---
layout: docs
title: macOS
permalink: /docs/examples/macos/
---

To setup Frida for macOS, you need to authorize Frida to use task_for_pid to access your target process.

If you run your Frida tool via the GUI with your local user (e.g. from Terminal.app), you will be prompted via taskgate to authorize the process.

If you run via ssh, you can authorize use of task_for_pid globally with `sudo security authorizationdb write system.privilege.taskport allow`.  Warning that this is a global change and should be used with cautious or reverted back after your script runs.

You may also need to disable [System Integrity Protection](https://support.apple.com/en-us/HT204899).

_Please click "Improve this page" above and add an example. Thanks!_
