---
layout: docs
title: Building
permalink: /docs/building/
---


## Table of contents

1. Building Frida
 - [Design Constraints](#design-constraints)
 - [Linux](#linux)
 - [macOS](#macOS)
 - [Windows](#windows)
2. Building the toolchain and SDK
 - [Unix](#unix-toolchain-and-sdk)
 - [Windows](#windows-toolchain-and-sdk)

## Building Frida

### Design Constraints

Frida has a rather complicated build system due to some design constraints:

- **Short build time for new contributors.** Frida downloads a prebuilt
toolchain and SDK to save time. This requires a bit more fiddling to get the
build environment just right, but it has the added benefit of providing a
coherent build environment. For example we know we're being built with just
one version of autotools whether we're on macOS or Linux.

- **No moving parts.** The final binary must be self-contained/portable. Some of
Frida's run-time components, like frida-helper, frida-agent, etc. will at some
point need to be present on the filesystem. These binaries are serialized and
linked into the Frida library (for example `_frida.so` in the case of
frida-python), which means it's portable without relying on external moving
parts. At runtime these are written out to a temporary directory and later
cleaned up.

- **No runtime conflicts.** frida-agent, the shared library injected into target
processes, must have all of its dependencies (GLib, Gee, etc.) linked in to
avoid runtime conflicts with target applications that happen to use the same
libraries. Because of this, these libraries are compiled as static libraries.

- **No resource leaks.** frida-agent, the shared library injected into target
processes, should not allocate any OS resources without releasing them when it
is unloaded to avoid accumulating leaks in long-lived processes. Because Frida
is mostly written in C and makes use of the excellent GLib library, which
unfortunately doesn't provide any way to fully clean up statically allocated
resources, we had to patch that library to add support for this. Upstream
doesn't consider this a valid use-case, so unfortunately we need to maintain our
fork of this library. This means we can't make use of a system-wide GLib on
Linux systems, which consequently makes the prebuilt SDK much larger.

Frida's build system tries to keep you sane by making use of a prebuilt
toolchain and SDK for each platform. This is what's used in the steps outlined
below.

### Linux

- Make sure you have a:
  - Modern x86 system
  - Development toolchain:
{% highlight bash %}
$ sudo apt-get install build-essential gcc-multilib git lib32stdc++-4.9-dev \
    lib32z1-dev python-dev python3-dev zlib1g-dev
{% endhighlight %}

  - Development toolchain Ubuntu 14.04 (Trusty Jahr) with Node 7.x
  See [Installing Node.js via package manager](https://nodejs.org/en/download/package-manager/) for more installation options
{% highlight bash %}
$ curl -sL https://deb.nodesource.com/setup_7.x | sudo -E bash -
$ sudo apt-get install -y nodejs
$ sudo apt-get install build-essential gcc-multilib git lib32stdc++-4.8-dev \
    lib32z1-dev python-dev python3-dev zlib1g-dev
{% endhighlight %}

- Clone `frida` and build it:
{% highlight bash %}
$ git clone git://github.com/frida/frida.git
$ cd frida
$ make
{% endhighlight %}

`make` will provide you a list of modules to build.  See [the hacking page](https://www.frida.re/docs/hacking/) for more information.

### macOS

- Make sure you have the latest Xcode with command-line tools installed.
- Clone `frida` and build it:
{% highlight bash %}
$ git clone git://github.com/frida/frida.git
$ cd frida
$ make
{% endhighlight %}

`make` will provide you a list of modules to build.  See [the hacking page](https://www.frida.re/docs/hacking/) for more information.

### Windows

- Make sure you have:
  - 64-bit version of Windows
  - Visual Studio 2017
  - [Git](https://git-scm.com/downloads) on your PATH
  - [Node.js](https://nodejs.org/) on your PATH
  - [Python 2.7](https://www.python.org/downloads/windows/) on your PATH and associated to .py files
  - [PowerShell](https://msdn.microsoft.com/en-us/powershell/scripting/setup/installing-windows-powershell)

- Clone the `frida` repository:
{% highlight bash %}
$ git clone https://github.com/frida/frida
$ cd frida
$ git submodule init
$ git submodule update
{% endhighlight %}

- Enter the `frida` folder and execute the Python staging script
{% highlight bash %}
$ powershell
PS> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted
PS> .\releng\stage-python.ps1
{% endhighlight %}

- Open `frida.sln` and build it.

## Building the toolchain and SDK

This should not be necessary unless you're porting Frida to a new platform. The
following steps assume you have the OS-specific prerequisites mentioned above.

### UNIX Toolchain and SDK

- Make sure your system has the following goodies:
{% highlight bash %}
$ sudo apt-get install bison build-essential flex gcc-multilib git \
    lib32stdc++-4.9-dev lib32z1-dev libglib2.0-dev python-dev python3-dev \
    zlib1g-dev
{% endhighlight %}
  Note that you may run into [this bug](https://bugs.launchpad.net/ubuntu/+source/zlib/+bug/1155307)
  when building a 32-bit SDK on recent Ubuntu releases. The workaround is:
{% highlight bash %}
  $ sudo ln -s /usr/include/x86_64-linux-gnu/zconf.h /usr/include
{% endhighlight %}
- Clone the `frida-ci` repository and build away:
{% highlight bash %}
$ git clone git://github.com/frida/frida-ci.git
$ mkdir tmp
$ cd tmp
$ ../frida-ci/create-toolchain-and-sdk.sh
{% endhighlight %}
- Transfer the resulting toolchain and SDK to a web server somewhere:
{% highlight bash %}
$ scp build/toolchain-*.tar.bz2 your@own.server:
$ scp build/sdk-*.tar.bz2 your@own.server:
{% endhighlight %}
- Now you can clone `frida` like above and adjust the URLs in
`releng/setup-env.sh` (look for `download_command`) before running `make`.

(Note: the `frida` module now has integrated support for building the SDK.
For example: `make -f Makefile.sdk.mk FRIDA_HOST=android-arm`)

### Windows Toolchain and SDK

- Prepare your system
  - Make sure that Visual Studio 2015 is installed.
  - Install
  [hsbuild-0.2.msi](https://launchpad.net/hsbuild/trunk/0.2/+download/hsbuild-0.2.msi).
  You need [Git](https://msysgit.github.com/) and
  [Perl](https://www.activestate.com/activeperl/) installed, and `perl` should be
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
  - Use [bazaar](https://bazaar.canonical.com/) to check out our slightly
  modified HSBuild:
{% highlight bash %}
$ bzr branch lp:~oleavr/hsbuild/tweaks hsbuild
{% endhighlight %}
  - Open `msbuild\tasks\HSBuildTasks.sln` and build it in `Release` configuration.
  - Open `hsbuild\hsbuild.sln` and build it in `Release` configuration (with
  Platform set to `x86`).
  - As Administrator, run `deploy.bat`, which will update the system-wide
  HSBuild installation.
  - Clone the `frida-ci` repository:
{% highlight bash %}
$ git clone git://github.com/frida/frida-ci.git
{% endhighlight %}
  - Copy `frida-ci\Frida.props` next to HSBuild's .targets/.props
  files, typically at `C:\Program Files (x86)\MSBuild\HSBuild`.
- Build it
  - Open `cmd.exe` and navigate to `frida-ci`.
  - Start the build process:
{% highlight bash %}
$ build-deps-windows.py
{% endhighlight %}
- Transfer the resulting toolchain and SDK to a web server somewhere:
{% highlight bash %}
$ scp toolchain-windows-*.exe your@own.server:
$ scp sdk-windows-*.exe your@own.server:
{% endhighlight %}
- Now you can clone `frida` like above and adjust the URLs in
`releng\windows-toolchain.txt` and `releng\windows-sdk.txt` before opening
`frida.sln`.
