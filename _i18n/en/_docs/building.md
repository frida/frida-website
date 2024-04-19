## Table of contents

1. Building Frida
 - [Prerequisites](#prerequisites)
 - [Getting the code](#clone)
 - [Building for the native machine](#native)
 - [Building for a different machine](#cross)
 - [Building out-of-tree](#oot)

## Building Frida

### Prerequisites

You need:

- C/C++ toolchain
- Node.js >= 18
- Git

For example on an Ubuntu system:

{% highlight bash %}
$ sudo apt-get install build-essential git lib32stdc++-9-dev \
    libc6-dev-i386 nodejs npm
{% endhighlight %}

### Getting the code

{% highlight bash %}
$ git clone https://github.com/frida/frida.git
{% endhighlight %}

### Building for the native machine

To build, run:

{% highlight bash %}
$ make
{% endhighlight %}

Which will use `./build` as the build directory. Run `make install` to install.

You may also do `./configure` first to specify a `--prefix`, or any other
options. Use `--help` to list the top-level options.

For setting lower level options, do:

{% highlight bash %}
$ ./configure -- first-option second-option …
{% endhighlight %}

The options after `--` are passed directly to Meson's `setup` command. This
means you can also pass project options to subprojects, e.g.:

{% highlight bash %}
$ ./configure -- \
    -Dfrida-gum:devkits=gum,gumjs \
    -Dfrida-core:devkits=core
{% endhighlight %}

Consult `meson.options` in subprojects/* for available options. You may also
clone the different repos standalone and build the same way as described here.

### Building for a different machine

#### iOS/watchOS/tvOS

{% highlight bash %}
$ ./configure --host=ios-arm64
# or: ./configure --host=watchos-arm64
# or: ./configure --host=tvos-arm64
# optionally suffixed by `-simulator`
$ make
{% endhighlight %}

#### Android

{% highlight bash %}
$ ./configure --host=android-arm64
$ make
{% endhighlight %}

#### Raspberry Pi

{% highlight bash %}
$ sudo apt-get install g++-arm-linux-gnueabihf
$ ./configure --host=arm-linux-gnueabihf
$ make
{% endhighlight %}

### Building out-of-tree

Sometimes you may want to use a single source tree to build for multiple
systems or configurations. To do this, invoke `configure` from an empty
directory outside the source tree:

{% highlight bash %}
$ mkdir build-ios
$ ../frida/configure --host=ios-arm64
$ make
$ cd ..
$ mkdir build-android
$ ../frida/configure --host=android-arm64
$ make
{% endhighlight %}
