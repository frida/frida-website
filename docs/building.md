---
layout: docs
title: Building
prev_section: troubleshooting
next_section: contributing
permalink: /docs/building/
---

## Building Frida

Frida has a rather complicated build system due to some design constraints:

- **Short build time for new contributors.** frida-build-env downloads a
prebuilt toolchain and SDK to save time. This requires a bit more fiddling to
get the build environment just right, but it has the added benefit of providing
a coherent build environment. For example we know we're being built with just
one version of autotools whether we're on Mac or Linux.

- **No moving parts.** The final binary must be self-contained/portable. Some of
Frida's run-time components, like frida-fruitjector-helper, frida-agent, etc.
will at some point need to be present on the filesystem. These binaries are
serialized and linked into the Frida library (for example `_frida.so` in the
case of frida-python), which means it's portable without relying on external
moving parts. At runtime these are written out to a temporary directory and
later cleaned up.

- **No runtime conflicts.** frida-agent, the shared library injected into target
processes, must have all of its dependencies (GLib, Gee, etc.) linked in to
avoid runtime conflicts with target applications that happen to use the same
libraries. Because of this, these libraries are compiled as static libraries.

- **No resource leaks.** frida-agent, the shared library injected into target
processes, should not allocate any OS resources without releasing them when it
is unloaded to avoid accumulating leaks in long-lived processes. Because Frida
is mostly written in C and makes use of the excellent GLib library, which
unfortunately doesn't provide any way to clean up statically allocated
resources, we had to patch that library to add support for this. Upstream
doesn't consider this a valid use-case, so unfortunately we need to maintain our
fork of this library. This means we can't make use of a system-wide GLib on
Linux systems, which consequently makes the prebuilt SDK much larger.

Frida's build system tries to keep you sane by making use of a prebuilt
toolchain and SDK for each platform. This is what's used in the steps outlined
below.

### Linux

- Make sure you have a:
  - Modern x86 64-bit system (Frida's Linux backend is not yet ported to 32-bit).
  - Compiler:
```bash
    $ sudo apt-get install build-essential
```
- Clone `frida-build-env` and build it:
```bash
    $ git clone git://github.com/frida/frida-build-env.git
    $ cd frida-build-env
    $ make
```

### Mac

- Make sure you have the latest Xcode with command-line tools installed.
- Clone `frida-build-env` and build it:
```bash
    $ git clone git://github.com/frida/frida-build-env.git
    $ cd frida-build-env
    $ make
```

### Windows

- Make sure you have:
  - 64-bit version of Windows (32-bit will work but may require some fiddling)
  - Visual Studio 2010
  - [Git](http://msysgit.github.com/)
  - [Python 2.7 and 3.3](http://python.org/). You want both the 32- and the
  64-bit version of each, with the 32-bit versions installed in
  `C:\Program Files (x86)` and 64-bit ones installed in `C:\Program Files`.
  - Clone `frida-build-env`:
```bash
    $ git clone git://github.com/frida/frida-build-env.git
    $ cd frida-build-env
    $ git submodule init
    $ git submodule update
```
- Open `frida.sln` and build it.


## Building the toolchain and SDK

This should not be necessary unless you're porting Frida to a new platform. The
following steps assume you have the OS-specific prerequisites mentioned above.

### UNIX

- Make sure your system has the following goodies:
```bash
    $ sudo apt-get install build-essential gcc git sudo flex \
      bison libglib2.0-dev
```
- Clone the `frida-ci` repository and build away:
```bash
    $ git clone git@github.com:frida/frida-ci.git
    $ mkdir tmp
    $ cd tmp
    $ ../frida-ci/create-toolchain-and-sdk.sh
```
- Transfer the resulting toolchain and SDK to a web server somewhere:
```bash
    $ scp build/toolchain-*.tar.bz2 your@own.server:
    $ scp build/sdk-*.tar.bz2 your@own.server:
```
- Now you can clone `frida-build-env` like above and adjust the URLs in
`setup-env.sh` (look for `download_command`) before running `make`.

### Windows

- Prepare your system
  - Make sure that Visual Studio 2010 is installed.
  - Install
  [hsbuild-0.2.msi](http://launchpad.net/hsbuild/trunk/0.2/+download/hsbuild-0.2.msi).
  You need [Git](http://msysgit.github.com/) and
  [Perl](http://www.activestate.com/activeperl/) installed, and `perl` should be
  in your PATH. For packaging you will also need [7-Zip](http://www.7-zip.org/)
  to be in your PATH.
  - Ensure that your Git configuration at
  `C:\Program Files (x86)\Git\etc\gitconfig` (or similar) has the following in
   its `core` section:
```
autoCRLF = false
```
  - Also ensure that your environment does not have a `CC` environment variable
  defined (might have happened if you installed `msys` or `cygwin`).
  - Use [bazaar](http://bazaar.canonical.com/) to check out our slightly
  modified HSBuild:
```bash
    $ bzr branch lp:~oleavr/hsbuild/tweaks hsbuild
```
  - Open `msbuild\tasks\HSBuildTasks.sln` and build it in `Release` configuration.
  - Open `hsbuild\hsbuild.sln` and build it in `Release` configuration (with
  Platform set to `x86`).
  - As Administrator, run `deploy.bat`, which will update the system-wide
  HSBuild installation.
  - Download [Frida.props](http://dl.dropbox.com/u/169648/frida/Frida.props) and
  put it alongside HSBuild's .targets/.props files, typically something like
  `C:\Program Files (x86)\MSBuild\HSBuild`.
- Build it
  - Download [frida.modules](http://dl.dropbox.com/u/169648/frida/frida.modules)
  and put it in a (preferably empty) directory somewhere.
  - Open `cmd.exe` and navigate to that directory.
  - Start the build process:
```bash
    $ set FRIDAMODULES=glib libgee json-glib vala
    $ hsbuild build -p x86_64 -c Debug -v %FRIDAMODULES%
    $ hsbuild build -p x86_64 -c Release -v %FRIDAMODULES%
    $ hsbuild build -p x86 -c Debug -v %FRIDAMODULES%
    $ hsbuild build -p x86 -c Release -v %FRIDAMODULES%
```
- Package it
  - Download
  [makedist.py](https://dl.dropboxusercontent.com/u/169648/frida/makedist.py)
  and put it next to `frida.modules`.
  - Run makedist.py:
```bash
    $ makedist.py
```
- Transfer the resulting toolchain and SDK to a web server somewhere:
```bash
    $ scp toolchain-windows-*.exe your@own.server:
    $ scp sdk-windows-*.exe your@own.server:
```
- Now you can clone `frida-build-env` like above and adjust the URLs in
`windows-toolchain.txt` and `windows-sdk.txt` before opening `frida.sln`.
