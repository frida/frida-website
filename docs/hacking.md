---
layout: docs
title: Hacking
prev_section: modes
next_section: presentations
permalink: /docs/hacking/
---

## Architecture

<div class="mxgraph" style="position:relative;overflow:auto;width:100%;">
<div style="width:1px;height:1px;overflow:hidden;">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</div>
</div>
<script type="text/javascript" src="https://www.draw.io/embed.js?s=arrows"></script>

## Porting

The first step is setting up the build system. Let's assume you're about
to port Frida to run on Linux/MIPS. As Frida already supports Linux, all
we need to do is add the architecture-specific bits.

### Porting the build system

- releng/setup-env.sh

This is the script that generates an .rc file that you can source to enter
the build environment. The top-level *Makefile.$build_os.mk* uses this to
generate the environment before proceeding to build modules inside of it.
Fill in the blanks [here](https://github.com/frida/frida/blob/e23516d9d027c35cedc9c3497dde774f0acfce1a/releng/setup-env.sh#L105-L128).
We use the same terminology as autotools, so *build* means the build machine
while *host* refers to the machine that will be executing the binaries.

- releng/config.site.in

Instead of passing lots of switches and environment variables to *configure*
we generate a *config.site* file that we point the `CONFIG_SITE` environment
variable to. Go fill in the blanks [here](https://github.com/frida/frida/blob/e23516d9d027c35cedc9c3497dde774f0acfce1a/releng/config.site.in#L26-L33).
*setup-env.sh* will take care of generating the final *config.site* based on
this template.

- Makefile.sdk.mk

Frida's build system automatically downloads a tarball with all dependencies
prebuilt for the host OS and architecture. As we're porting to a new
architecture we will have to build these dependencies by hand. But first,
we need to update the build recipe to support this new architecture.
Because most of the dependencies make use of autotools this requires almost
no changes at all; we just need to add the V8-specific bits as it uses a
custom build system. Go update them [here](https://github.com/frida/frida/blob/e23516d9d027c35cedc9c3497dde774f0acfce1a/Makefile.sdk.mk#L271-L286).

- frida-gum/configure.ac

Add `HAVE_MIPS` and `ARCH_MIPS` [here](https://github.com/frida/frida-gum/blob/2471ca17df1babd60269a60aab4705737c5485dd/configure.ac#L30-L55)
by just following the existing patterns.

- frida-core/configure.ac

Repeat the procedure from the previous point [here](https://github.com/frida/frida-core/blob/50408c69968321f653030f5b3fb515f66b846a93/configure.ac#L24-L56).

### Building the SDK

{% highlight bash %}
$ make -f Makefile.sdk.mk FRIDA_HOST=linux-mips
{% endhighlight %}

### Building frida-gum

A user would normally not build a component by hand and instead just invoke the
toplevel Makefile. However, when porting we recommend focusing on just one
module at a time and get its tests passing before moving on to the next one.
We'll start with *frida-gum*, which is the low-level foundation of *frida-core*.

Let's first use the top-level Makefile to just bootstrap the basics:

{% highlight bash %}
$ make build/frida-linux-mips/lib/pkgconfig/frida-gum-1.0.pc
{% endhighlight %}

That may not actually succeed in building *frida-gum*, but should at least get
the environment set up, configure script generated, etc.

Now let's change the working directory to *frida-gum* and rinse and repeat this
until all is well:

{% highlight bash %}
$ (. ../build/frida-env-linux-mips.rc && make -C ../build/tmp-linux-mips/frida-gum)
$ scp ../build/tmp-linux-mips/frida-gum/tests/gum-tests target:/tmp/
$ ssh target "/tmp/gum-tests"
{% endhighlight %}

You can add `-p` to limit which tests are run, e.g. `-p /Core/Interceptor/attach_one`.

### Porting frida-gum

Add the directory *gum/backend-mips* by duplicating for example
[gum/backend-arm64](https://github.com/frida/frida-gum/tree/master/gum/backend-arm64),
and just search-replace everything. The important part to port here is
*guminterceptor-mips.c* and *gumspinlock-mips.c*. You should leave
*gumstalker-mips.c* as a stub, as it's an advanced feature that takes a lot
of effort to port.

### Building frida-core

Let's first use the top-level Makefile to just bootstrap the basics:

{% highlight bash %}
$ make build/frida-linux-mips/lib/pkgconfig/frida-core-1.0.pc
{% endhighlight %}

That may not actually succeed in building *frida-core*, but should at least get
the environment set up, configure script generated, etc.

Now let's change the working directory to *frida-core* and rinse and repeat this
until all is well:

{% highlight bash %}
$ (. ../build/frida-env-linux-mips.rc && make -C ../build/tmp-linux-mips/frida-core)
$ scp ../build/tmp-linux-mips/frida-core/tests/frida-tests target:/tmp/
$ ssh target "/tmp/frida-tests"
{% endhighlight %}

You can add `-p` to limit which tests are run, e.g. `-p /Linjector/inject`.

### Porting frida-core

This should only be a matter of porting the injector. The implementation is [here](https://github.com/frida/frida-core/blob/master/src/linux/frida-helper-glue.c)
and it is basically just a matter of following the `HAVE_ARM64` breadcrumbs
to port the architecture-specific bits. For a walkthrough of the Linux injector,
check out our presentation [here](https://www.youtube.com/watch?v=uc1mbN9EJKQ).
