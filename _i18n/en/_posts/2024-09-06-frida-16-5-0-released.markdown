---
layout: news_item
title: 'Frida 16.5.0 Released'
date: 2024-09-06 21:57:17 +0200
author: oleavr
version: 16.5.0
categories: [release]
---

Some of you may have found yourself in a situation where a piece of data in
memory looks interesting, and you want to locate the code responsible for it.
You may have tried Frida's MemoryAccessMonitor API, but found the page
granularity hard to work with. That is, you might have to collect many samples
until you get lucky and catch the code that accesses those specific bytes on
the page that they're on. This might be hard enough on systems with 4K pages,
and even worse on modern Apple systems with 16K pages.

To address this, [@hsorbo][] and I filled up our coffee cups and got to work,
implementing support for hardware breakpoints and watchpoints. The long story
short is that thread objects returned by Process.enumerateThreads() now have
setHardwareBreakpoint(), setHardwareWatchpoint(), and corresponding methods
to unset them at a later point. These are then combined with
Process.setExceptionHandler() where you call the unset method and return true
to signal that the exception was handled, and execution should be resumed.

## Demo time

Let's take these new APIs for a spin. As our target we'll pick id Software's
brand new 2024 re-release of DOOM + DOOM II.

![DOOM](/img/doom-e1m1.jpg "DOOM E1M1")

The first thing we might want to do is figure out where in memory the number of
bullets is stored. Let's cook up a tiny agent to help us achieve this:

{% highlight js %}
let matches = [];

function scan(pattern) {
  const locations = new Set();
  for (const r of Process.enumerateMallocRanges()) {
    for (const match of Memory.scanSync(r.base, r.size, pattern)) {
      locations.add(match.address.toString());
    }
  }
  matches = Array.from(locations).map(ptr);
  console.log('Found', matches.length, 'matches');
}

function reduce(val) {
  matches = matches.filter(location => location.readU32() === val);
  console.log('Filtered down to:');
  console.log(JSON.stringify(matches));
}

function patternFromU32(val) {
  return new MatchPattern(ptr(val).toMatchPattern().substr(0, 11));
}
{% endhighlight %}

And load it into the game:

{% highlight sh %}
$ frida -n doom.exe -l demo.js
…
[Local::doom.exe ]->
{% endhighlight %}

We know that we have 50 bullets currently, so let's find all heap allocations
containing the value 50, encoded as a native uint32:

{% highlight sh %}
[Local::doom.exe ]-> scan(patternFromU32(50))
Found 6947 matches
{% endhighlight %}

That's quite a few. Let's narrow it down by firing one bullet, and checking
which of those locations now contain the value 49:

{% highlight sh %}
[Local::doom.exe ]-> reduce(49)
Filtered down to:
["0x1fbf5191884"]
{% endhighlight %}

Bingo! Now that we know where in memory the number of bullets is stored, our
next step is to find the code that updates the number of bullets when one is
fired. Let's add another helper function to our agent:

{% highlight js %}
function installWatchpoint(address, size, conditions) {
  const thread = Process.enumerateThreads()[0];

  Process.setExceptionHandler(e => {
    console.log(`\n=== Handler got ${e.type} exception at ${e.context.pc}`);

    if (Process.getCurrentThreadId() === thread.id &&
        ['breakpoint', 'single-step'].includes(e.type)) {
      thread.unsetHardwareWatchpoint(0);
      console.log('\tDisabled hardware watchpoint');
      return true;
    }

    console.log('\tPassing to application');
    return false;
  });

  thread.setHardwareWatchpoint(0, address, size, conditions);

  console.log('Ready');
}
{% endhighlight %}

And call it:

{% highlight sh %}
[Local::doom.exe ]-> installWatchpoint(ptr('0x1fbf5191884'), 4, 'w')
Ready
{% endhighlight %}

Next we'll flip back to the game and fire another bullet:

{% highlight sh %}
[Local::doom.exe ]->
=== Handler got system exception at 0x7ffc2bc2fabc
        Passing to application

=== Handler got single-step exception at 0x7ff6f0a21010
        Disabled hardware watchpoint
{% endhighlight %}

Yay, that looks promising. Let's symbolicate that address:

{% highlight sh %}
[Local::doom.exe ]-> ammoCode = ptr('0x7ff6f0a21010')
"0x7ff6f0a21010"
[Local::doom.exe ]-> ammoModule = Process.getModuleByAddress(ammoCode)
{
    "base": "0x7ff6f0730000",
    "name": "DOOM.exe",
    "path": "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Ultimate Doom\\rerelease\\DOOM.exe",
    "size": 15495168
}
[Local::doom.exe ]-> offset = ammoCode.sub(ammoModule.base)
"0x2f1010"
{% endhighlight %}

Let's take a closer look using r2:

![DOOM](/img/doom-r2.png "DOOM static analysis")

We can see that the program counter that we observed in our exception handler is
on the instruction right after the `sub` that triggered our watchpoint.

So from here we can set up an inline hook that gets fired whenever a bullet is
fired:

{% highlight js %}
Interceptor.attach(Module.getBaseAddress('doom.exe').add(0x2f1010), function () {
  const ammoLeft = this.context.rax.add(4).readU32();
  console.log(`Shots fired! Ammo left: ${ammoLeft}`);
});
{% endhighlight %}

{% highlight sh %}
[Local::doom.exe ]-> Shots fired! Ammo left: 42
Shots fired! Ammo left: 41
Shots fired! Ammo left: 40
Shots fired! Ammo left: 39
Shots fired! Ammo left: 38
{% endhighlight %}

We can just as easily make ourselves a cheat for infinite ammo:

{% highlight js %}
Interceptor.attach(Module.getBaseAddress('doom.exe').add(0x2f100d), function () {
  this.context.rbx = ptr(0);
  console.log(`Shots fired! Pretending no ammo was actually used`);
});
{% endhighlight %}

{% highlight sh %}
[Local::doom.exe ]-> Shots fired! Pretending no ammo was actually used
Shots fired! Pretending no ammo was actually used
Shots fired! Pretending no ammo was actually used
Shots fired! Pretending no ammo was actually used
Shots fired! Pretending no ammo was actually used
{% endhighlight %}

Look ma, infinite ammo!

Note that we could also have achieved this by using Memory.patchCode() to
replace the `sub` with a 3-byte `nop`, which X86Writer can do for us through
putNopPadding(3). The Interceptor hook has the advantage of automatically
being rolled back when our script is unloaded, and makes it easy to execute
arbitrary code.

## Windows on ARM

Another highlight of this release is that we now support Windows on ARM. This
means that an arm64 version of Frida can inject into native arm64 processes, as
well as emulated x86_64 and x86 processes.

We don't yet provide binaries however, as we're waiting for GitHub to provide
arm64 runners to OSS projects, which for now is limited to their Team and
Enterprise Cloud customers. While it is technically feasible to cross-compile
from an x86_64 build machine, we decided to punt on this as we quickly ran into
issues with Meson's MSVC support.

## EOF

There's also a slew of other exciting changes, so definitely check out the
changelog below.

Enjoy!

## Changelog

- thread: Support hardware breakpoints and watchpoints.
- fruity: Fix deadlock in perform_on_lwip_thread().
- windows: Add support for arm64.
- windows: Migrate Exceptor to Microsoft's VEH API.
- linux: Handle process gone when detaching. Thanks [@ajwerner][]!
- linux: Fix the clone() wrapper on MIPS.
- java: Handle Android GC cycle handlers not being exported. Thanks
  [@thinhbuzz][]!
- java: Add preliminary support for OpenJDK 17 on Windows. Thanks
  [@FrankSpierings][]!
- meson: Add frida-netif to the public frida-core, so frida-core devkits include
  all needed symbols.
- node: Add Cancellable.withTimeout() convenience factory function. Thanks [@hsorbo][]!
- node: Add Cancellable.combine() convenience method. Thanks [@hsorbo][]!


[@hsorbo]: https://twitter.com/hsorbo
[@ajwerner]: https://github.com/ajwerner
[@thinhbuzz]: https://github.com/thinhbuzz
[@FrankSpierings]: https://github.com/FrankSpierings
