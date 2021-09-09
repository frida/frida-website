---
layout: news_item
title: 'Frida 15.1 Released'
date: 2021-09-03 12:00:00 +0200
author: hot3eed
version: 15.1
categories: [release]
---

Introducing the _brand new_ Swift bridge! Now that Swift has been
ABI-stable since version 5, this long-awaited bridge allows Frida to play nicely
with binaries written in Swift. Whether you [consider][] Swift a static or a
dynamic language, one thing is for sure, it just got a lot more dynamic with
this Frida release.

## Metadata

Probably the first thing a reverser does when they start reversing a binary is
getting to know the different data structures that the binary defines. So it
made most since to start by building the Swift equivalent of the `ObjC.classes`
and `ObjC.protocols` APIs. But since Swift has other first-class types,
i.e. structs and enums, and since the Swift runtime doesn't offer reflection
primitives, at least not in the sense that Objective-C does, it meant we had to
dig a little deeper.

Luckily for us, the Swift compiler emits metadata for each type
defined by the binary. This metadata is bundled in a
`TargetTypeContextDescriptor` C++ struct, defined in
[include/swift/ABI/Metadata.h][] at the time of writing. This data structure
includes the type name, its fields, its methods (if applicable,) and other useful
data depending on the type at hand. These data structures are pointed to by
relative pointers (defined in [include/swift/Basic/RelativePointer.h][].) In
Mach-O binaries, these are stored in the `__swift5_types` section.

So to dump types, Frida basically iterates over these data structures and
parses them along the way, very similar to what [dsdump][] does, except that you
don't have to build the Swift compiler to in order to tinker with it.

Frida also has the advantage of being able to probe into
internal Apple dylibs written in Swift, and that's because we don't need to
parse the `dyld_shared_cache` thanks to the private `getsectiondata` API, whch
gives us section offsets hassle-free.

Once we have the metadata, we're able to easily create JavaScript wrappers for
object instances and values of different types.

## Conventions

To be on par with the Objective-C bridge, the Swift bridge has to support
calling Swift functions, which also proved to be not as straight forward.

Swift defines its own calling convention, `swiftcall`, which, to put it
succinctly, tries to be as efficient as possible. That means, not wasting load
and store instructions on structs that are smaller than 4 registers-worth of
size. That is, to pass those kinds of structs directly in registers. And since
that could quickly over-book our precious 8 argument registers
(on AARCH64 `x0`-`x7`), it doesn't use the first register for the `self`
argument. It also defines an `error` register where callees can store errors
which they throw.

What we just described above is termed "physical lowering" in the Swift compiler
docs, and it's implemented by the back-end, LLVM.

The process that precedes physical lowering is termed "semantic lowering," which
is the compiler front-end figuring out who "owns" a value and whether
it's direct or indirect. Some structs, even though they might be smaller than
4 registers, have to be passed indirectly, because, for example, they are
generic and thus their exact memory layout is not known at compile time, or
because they include a weak reference that has to be in-memory at all times.

Frida had to implement both semantic and physical lowering in order to be able
to call Swift functions. Physical lowering is implemented using JIT-compiled
adapter functions (thanks to the `Arm64Writer` API) that does the necessary
`SystemV`-`swiftcall` translation. Semantic lowering is implemented by utilizing
the type's metadata to figure out whether we should pass a value directly or
not.

The compiler [docs][] are a great resource to learn more about the calling
convention.

## Interception

Because Swift passes structs directly in registers, there isn't a 1-to-1 mapping
between registers and actual arguments, as is the case for SystemV.

And now that we have JavaScript wrappers for types, and are able to call Swift
functions from the JS runtime, a good next step would be extending `Interceptor`
to support Swift functions.

For functions that are not stripped, we use a simple regex to parse argment
types and names, same for return values. After parsing them we retrieve the
type metadata, figure the type's layout, then simply construct JS wrappers
for each argument, which we pass the Swift argument value, however many
registers it occupies.

## EOF

Note that the bridge is still very early in development, and so:
  - Currently supports Darwin arm64(e) only.
  - Performance is not yet in tip-top shape, some edge case might not be handled
    properly and some bugs are to be expected.
  - There's a chance the API might change in breaking ways in the
    short-to-medium term.
  - PRs and issues are very welcome!


Refer to the [documentation][] for an up-to-date resource on the current API.

Enjoy!

### Changes in 15.1.0

Implement the Swift bridge, which allows Frida to:
  - Explore Swift modules along with types implemented in them, i.e. classes,
    structs, enums and protocols.
  - Create JavaScript wrappers for object instances and values.
  - Invoke functions that use the `swiftcall` calling convention from the
    JavaScript runtime.
  - Intercept Swift functions and automatically parse their arguments and return
    values.


[consider]: https://youtu.be/0rHG_Pa86oA?t=36
[include/swift/ABI/Metadata.h]: https://github.com/apple/swift/blob/52e852a7a9758e6edcb872761ab997b552eec565/include/swift/ABI/Metadata.h
[dsdump]: https://github.com/DerekSelander/dsdump
[include/swift/Basic/RelativePointer.h]: https://github.com/apple/swift/blob/52e852a7a9758e6edcb872761ab997b552eec565/include/swift/Basic/RelativePointer.h
[docs]: https://github.com/apple/swift/blob/52e852a7a9758e6edcb872761ab997b552eec565/docs/ABI/CallingConvention.rst
[documentation]: https://github.com/frida/frida-swift-bridge/blob/master/docs/api.md