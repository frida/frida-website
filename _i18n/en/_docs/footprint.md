We put a lot of effort into making sure that Frida can scale from desktops all
the way down to embedded systems.

While our prebuilt binaries ship with all features enabled, building Frida
yourself means you can tailor it to your needs and build significantly smaller
binaries. The way this is done is by tweaking the available options in
`config.mk`:

{% highlight make %}
# Features ordered by binary footprint, from largest to smallest
FRIDA_V8 ?= enabled
FRIDA_CONNECTIVITY ?= enabled
FRIDA_DATABASE ?= enabled
FRIDA_JAVA_BRIDGE ?= auto
FRIDA_OBJC_BRIDGE ?= auto
FRIDA_SWIFT_BRIDGE ?= auto
{% endhighlight %}

Let's run through these and look at how the different options impact footprint
size on Linux/armhf (32-bit ARM).

To make the following a bit clearer, we have added `-Dassets=installed` to the
frida-core Meson options. This means that frida-agent.so is not embedded into
the frida-server/frida-inject binary, but is instead loaded from the filesystem.

This is also what you typically want on embedded systems, as writing out the
agent to /tmp is somewhat wasteful, whether it's backed by flash or tmpfs.

## All config.mk features enabled on linux-armhf

{% highlight bash %}
3.8M frida-inject
3.2M frida-server
 15M frida-agent.so
 15M frida-gadget.so
{% endhighlight %}

## Step 1: Disable V8

{% highlight bash %}
3.8M frida-inject
3.2M frida-server
5.2M frida-agent.so
5.3M frida-gadget.so
{% endhighlight %}

Agent reduced by 9.8M.

## Step 2: Disable connectivity features (TLS and ICE), eliminating OpenSSL

{% highlight bash %}
2.6M frida-inject
2.0M frida-server
3.6M frida-agent.so
3.7M frida-gadget.so
{% endhighlight %}

Agent reduced by 1.6M.

## Step 3: Disable the GumJS Database API, eliminating SQLite

{% highlight bash %}
2.6M frida-inject
2.0M frida-server
3.2M frida-agent.so
3.3M frida-gadget.so
{% endhighlight %}

Agent reduced by 0.4M.

## Step 4: Disable the GumJS bridges: ObjC, Swift, Java

{% highlight bash %}
2.6M frida-inject
2.0M frida-server
2.8M frida-agent.so
2.9M frida-gadget.so
{% endhighlight %}

Agent reduced by 0.4M.

Let's look at what we're left with:

![frida-agent.so footprint](/img/frida-agent-footprint.png "frida-agent.so footprint")

And to sate our curiosity, let's have a closer look at three of the components
that stand out:

![libcapstone.a footprint](/img/capstone-breakdown.png "libcapstone.a footprint")

![libglib-2.0.a footprint](/img/glib-breakdown.png "libglib-2.0.a footprint")

![libgio-2.0.a footprint](/img/gio-breakdown.png "libgio-2.0.a footprint")

