## Table of contents

1. Building Frida
 - [Design Constraints](#design-constraints)
 - [GNU/Linux](#gnulinux)
 - [macOS](#macos)
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
coherent build environment.

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
GNU/Linux systems, which consequently makes the prebuilt SDK much larger.

Frida's build system tries to keep you sane by making use of a prebuilt
toolchain and SDK for each platform. This is what's used in the steps outlined
below.

### GNU/Linux

- Make sure you have a:
  - Modern x86 system with GCC 7.5 or newer
  - Development toolchain, and Node.js on your PATH. E.g. on Ubuntu 20.04:
{% highlight bash %}
$ sudo apt-get install build-essential curl git lib32stdc++-9-dev \
    libc6-dev-i386 nodejs npm python3-dev python3-pip
{% endhighlight %}

- Clone `frida` and build it:
{% highlight bash %}
$ git clone --recurse-submodules https://github.com/frida/frida.git
$ cd frida
$ make
{% endhighlight %}

Running `make` will provide you a list of modules to build. See
[the hacking page](https://www.frida.re/docs/hacking/) for more information.

### macOS

- Make sure you have:
  - Xcode with command-line tools
  - [Python 3.8](https://www.python.org/downloads/mac-osx/) on your PATH
  - [Node.js](https://nodejs.org/) on your PATH
- Clone `frida` and build it:
{% highlight bash %}
$ git clone --recurse-submodules https://github.com/frida/frida.git
$ cd frida
$ make
{% endhighlight %}

Running `make` will provide you a list of modules to build. See
[the hacking page](https://www.frida.re/docs/hacking/) for more information.

### Windows

- Make sure you have:
  - Visual Studio 2019 w/XP support installed
  - [Git](https://git-scm.com/downloads) on your PATH
  - [Python 3.8](https://www.python.org/downloads/windows/) on your PATH
  - [Node.js](https://nodejs.org/) on your PATH
    `py` launcher installed, and associated to .py files
  - [PowerShell](https://msdn.microsoft.com/en-us/powershell/scripting/setup/installing-windows-powershell)

- Clone the `frida` repository:
{% highlight bash %}
$ git clone --recurse-submodules https://github.com/frida/frida
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
$ sudo apt-get install flex bison
{% endhighlight %}
- Clone the `frida` repository and build away:
{% highlight bash %}
$ git clone --recurse-submodules https://github.com/frida/frida
$ cd frida
$ make -f Makefile.toolchain.mk
$ make -f Makefile.sdk.mk FRIDA_HOST=linux-x86_64
{% endhighlight %}
- Transfer the resulting toolchain and SDK to a web server somewhere:
{% highlight bash %}
$ scp build/toolchain-*.tar.bz2 your@own.server:
$ scp build/sdk-*.tar.bz2 your@own.server:
{% endhighlight %}
- Now you can clone `frida` like above and adjust the URLs in
`releng/setup-env.sh` (look for `download_command`) before running `make`.

### Windows Toolchain and SDK

- Clone the `frida` repository and build away:
{% highlight bash %}
$ git clone --recurse-submodules https://github.com/frida/frida
$ cd frida
$ py -3 releng\build-deps-windows.py
{% endhighlight %}
- Transfer the resulting toolchain and SDK to a web server somewhere:
{% highlight bash %}
$ scp toolchain-windows-*.exe your@own.server:
$ scp sdk-windows-*.exe your@own.server:
{% endhighlight %}
- Now you can clone `frida` like above and adjust the URLs in
  `releng\windows-toolchain.txt` and `releng\windows-sdk.txt` before opening
  `frida.sln`.
