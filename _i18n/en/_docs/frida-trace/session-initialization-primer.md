This page describes uses for the frida-trace `--init-session` / `-S` command
line option, and how to utilize it in your work.

## What is the --init-session option?

The `--init-session` option executes any number of user-written JavaScript code
files during the frida-trace engine initialization stage.  These files are
executed before the first function handler is called.

Its power comes from the ability to create and save code and data objects in the
global "state" object, which is passed as a parameter to every handler called.
The "state" object allows you to maintain information across function calls.
Code and data objects stored in "state" are accessible to all called handlers.

## Uses for the --init-session option

The `--init-session` / `-S` option guarantees that JavaScript source code of
your choice is executed before the frida-trace engine begins its tracing.
Possible applications of this feature include:

1. Executing custom code that creates both code and data objects of your choice,
   doing this before the first function handler is invoked.
2. Creating a library of shared code, allowing the sharing of fine-tuned and
   debugged JavaScript code that can be called globally by any handler, at any
   time.

The frida-trace JavaScript code is often written as one-time "throw-away" code.
If, however, you find yourself frequently copying and pasting code between
handlers and projects, consider saving the code in a shared library.  Once
written and debugged, you can reuse the functions and data in future projects.

## Detailed Example: Creating a shared-code library

In this example, we demonstrate using the `--init-session` / `-S` option to
enhance tracing of the Microsoft Windows `ExtTextOutW()` function.  We describe
the components in a top-down fashion, beginning with the ExtTextOutW.js
JavaScript handler function, working our way down to the shared code files.

### ExtTextOutW: Function Signature

In my Windows system, the [ExtTextOutW][] function to monitor resides in
*gdi32full.dll*. Here is the C syntax of the function:

{% highlight c %}
BOOL ExtTextOutA(
  HDC        hdc,
  int        x,
  int        y,
  UINT       options,
  const RECT *lprect,
  LPCSTR     lpString,
  UINT       c,
  const INT  *lpDx
);
{% endhighlight %}

Leveraging JavaScript code in our shared code libraries, we produce an enhanced
tracing output.

### The enhanced trace output

Before showing the handler code and the shared code libraries, here is the
enhanced tracing output itself:

{% highlight console %}
c:\project> frida-trace -p 6980 --decorate -i "gdi32full.dll!ExtTextOutW" -S core.js -S ms-windows.js
Instrumenting...
ExtTextOutW: Loaded handler at "c:\\project\\__handlers__\\gdi32full.dll\\ExtTextOutW.js"
Started tracing 1 function. Press Ctrl+C to stop.
           /* TID 0x3ab8 */
  2695 ms  ---------------------------------------------
  2695 ms  ExtTextOutW() [gdi32full.dll]
  2695 ms  x: 0
  2695 ms  y: 0
  2695 ms  options: ETO_OPAQUE
  2695 ms  lprect [20 bytes]
                           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
                00b9c81c  00 00 00 00 01 00 00 00 01 00 00 00 98 02 00 00  ................
                00b9c82c  26 90 b2 b3                                      &...
  2695 ms  lprect: (left, top, right, bottom) = (0, 1, 1, 664)
  2695 ms  c: 0
  2696 ms  x (exit): 0
  2696 ms  y (exit): 0
  . . .
  2788 ms  ---------------------------------------------
  2788 ms  ExtTextOutW() [gdi32full.dll]
  2788 ms  x: 1
  2788 ms  y: 0
  2788 ms  options: ETO_CLIPPED | ETO_IGNORELANGUAGE
  2788 ms  lprect [20 bytes]
                      0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
           00b9eaac  00 00 00 00 00 00 00 00 4d 00 00 00 0f 00 00 00  ........M.......
           00b9eabc  0a 78 7e c1                                      .x~.
  2788 ms  lprect: (left, top, right, bottom) = (0, 0, 77, 15)
  2788 ms  lpString [50 bytes]
                      0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
           1aa90148  43 00 61 00 6c 00 69 00 62 00 72 00 69 00 20 00  C.a.l.i.b.r.i. .
           1aa90158  28 00 42 00 6f 00 64 00 79 00 29 00 29 00 75 00  (.B.o.d.y.).).u.
           1aa90168  20 00 77 00 61 00 6e 00 20 00 20 00 74 00 6f 00   .w.a.n. . .t.o.
           1aa90178  20 00                                             .
  2788 ms  *lpString: "Calibri (Body))u wan  to do"
  2788 ms  c: 14
  2788 ms  lpDx [4 bytes]
                      0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
           09e71208  08 00 00 00                                      ....
  2788 ms  *lpDx: 8
  2789 ms  x (exit): 0
  2789 ms  y (exit): 0
{% endhighlight %}

Notice the following tracing enhancements:

- The `options` field is converted to textual form
- The `lprect` memory pointer is displayed as both a hex memory dump and a
  textual string
- The `lpString` memory pointer is displayed as both a hex memory dump and a
  textual string
- The `lpDx` integer pointer is displayed as both a hex memory dump and an
  integer

The textual conversions and hex memory dumps are functions within our shared code
libraries.  Let's see our `ExtTextOutW()` handler JavaScript code, which will
make use of the shared code.

### Handler: ExtTextOutW.js

Here is our ExeTextOutW() handler code.  We enhance it by invoking shared code
functions.  These functions exist in the outer scope, as any top-level functions
defined in session scripts become visible to all handlers.  The functions are
defined when the shared code JavaScript files are executed by frida-trace via
the `--init-session` / `-S` command line option.

{% highlight js %}
/*
 * Auto-generated by Frida. Please modify to match the signature of ExtTextOutW.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

{
  onEnter(log, args, state) {
    /*
     * C syntax:
     *
     * BOOL ExtTextOutW(
     *   HDC        hdc,
     *   int        x,
     *   int        y,
     *   UINT       options,
     *   const RECT *lprect,
     *   LPCWSTR    lpString,
     *   UINT       c,
     *   const INT  *lpDx
     * );
    */

    log('---------------------------------------------');
    log('ExtTextOutW() [gdi32full.dll]');

    cloneArgs(args, 8, this);
    const [, x, y, options, lprect, lpString, c, lpDx] = this.args;

    log(`x: ${x.toInt32()}`);
    log(`y: ${y.toInt32()}`);

    log(`options: ${decodeExttextoutOptions(options)}`);

    if (!lprect.isNull()) {
      generalHexdump(log, 'lprect', lprect, 20);
      log(`lprect: ${rectStructToString(lprect)}`);
    }

    if (!lpString.isNull()) {
      state.generalHexdump(log, 'lpString', lpString, 50);
      log(`*lpString: "${lpString.readUtf16String()}"`);
    }

    log(`c: ${c.toUInt32()}`);

    if (!lpDx.isNull()) {
      state.generalHexdump(log, 'lpDx', lpDx, 4);
      log(`*lpDx: ${lpDx.readU32()}`);
    }
  },

  onLeave(log, retval, state) {
    /*
     * We can access the onEnter arguments using `this.args`,
     * as cloneArgs() copied them there.
     */
    const [, x, y] = this.args;
    log(`x (exit): ${x.toInt32()}`);
    log(`y (exit): ${y.toInt32()}`);
  }
}
{% endhighlight %}

Note that, besides calling standard Frida functions (e.g., `toInt32()`,
`isNull()`, `readUtf16String()`), there are calls to our shared code functions
(e.g., `cloneArgs()`, `decodeExttextoutOptions()`, `generalHexdump()`,
`rectStructToString()`).  The shared code functions have been debugged and
refined, and are ready to be called by any handler, at any time.

### Shared Code: core.js

The 'core.js' shared code library contains core, or basic, functions that are
meant to be reused by frida-trace handlers and shared code libraries.

Writing a shared code library is simple: your shared library source files define
functions and data objects, storing the latter in the global `state` object.
Once stored there, any handler can access them through "state.propertyName".

{% highlight js %}
/*
 * Collection of useful general-purpose Frida handler functions.
 */

/**
 * Creates a true JavaScript array as `invCtx.args`.  This array can be accessed
 * in the handler's onLeave().
 *
 * @param {NativePointer[]} args - The `args` array as passed to onEnter().
 * @param {number} numArgs - The number of meaningful arguments in `args`. This
 *     function has no way of determining the number of actual arguments because
 *     `args` is a virtual array.
 * @param {InvocationContext} invCtx - The `this` object of the calling onEnter().
 * @returns {NativePointer[]} Copy of `args`.
 */
function cloneArgs(args, numArgs, invCtx) {
  const items = [];
  for (let i = 0; i !== numArgs; i++)
    items.push(args[i]);
  invCtx.args = items;
}

/**
 * Returns a string describing the bitflags set in `value`.
 *
 * @param {number} value - A value consisting of zero or more bitflags.
 * @param {Map<number, string>} spec - A Map between:
 *     [hex value] -> [flag descriptive string]
 *     For example:
 *       new Map([
 *          [0x0004: 'ETO_CLIPPED'],
 *          [0x0010: 'ETO_GLYPH_INDEX'],
 *          ...
 *       ])
 * @returns {string} Flag names delimited by '|', or '0' if none are set.
 */
function decodeBitflags(value, spec) {
  const flags = [];

  for (const [flagValue, flagName] of spec.entries()) {
    if ((value & flagValue) !== 0)
      flags.push(flagName);
  }

  if (flags.length === 0)
    return '0';

  return flags.join(' | ');
}

/**
 * Produces a somewhat more elegant hex dump, based on Frida's own hexdump().
 * It does not output the hex dump to any stream, but rather returns the hex
 * dump lines in an array.  It is up to the caller to decide where to, and how,
 * to output the dump lines.
 *
 * @param {string[]} lines - Caller-provided array that will return the hex dump
 *     lines.
 * @param {string} desc - Descriptive text, printed together with the hex dump.
 * @param {NativePointer} address - Memory location to dump.
 * @param {number} length - Number of bytes to dump.
 * @param {string} [indent='\t\t'] - String to prepend to each dump line.
 */
function prettyHexdumpLines(lines, desc, address, length, indent = '\t\t') {
  lines.push(`${desc} [${len} bytes]`);

  try {
      const s = hexdump(address, { length });
      for (const line of s.split('\n')) {
        lines.push(`${indent}${line}`);
      }
  } catch (e) {
    lines.push(`${indent}WARNING: address is NOT VALID (${address})`);
  }
}

/**
 * Outputs the hex dump results to the log stream.  If you only want the dump
 * lines without outputing them to the log stream, use prettyHexdumpLines().
 *
 * @param {function} log - The log function to output to.
 * @param {string} desc - Descriptive text, printed together with the hex dump.
 * @param {NativePointer} address - Memory location to dump.
 * @param {number} length - Number of bytes to dump.
 */
function prettyHexdump(log, desc, address, length) {
  const lines = [];
  prettyHexdumpLines(lines, desc, address, length);
  log(lines.join('\n'));
}
{% endhighlight %}

### Shared Code: ms-windows.js

The `ms-windows.js` shared code library consists of MS Windows-related utility
functions, and is built on top of the `core.js` library.

{% highlight js %}
/*
 * Collection of useful Frida handler functions for MS Windows.
 */

const extTextOptionsSpec = new Map([
  [0x00004, 'ETO_CLIPPED'],
  [0x00010, 'ETO_GLYPH_INDEX'],
  [0x01000, 'ETO_IGNORELANGUAGE'],
  [0x00800, 'ETO_NUMERICSLATIN'],
  [0x00400, 'ETO_NUMERICSLOCAL'],
  [0x00002, 'ETO_OPAQUE'],
  [0x02000, 'ETO_PDY'],
  [0x00080, 'ETO_RTLREADING'],
  [0x10000, 'ETO_REVERSE_INDEX_MAP'],
]);

/**
 * Decodes ExtTextOutW() `options` bit flags.
 *
 * @param {number} flags - A DWORD consisting of the `options` bit flags used
 *     by ExtTextOutW().
 * @returns {string} Options delimited by '|', or '0' if none are set.
 */
function decodeExttextoutOptions(flags) {
  return decodeBitflags(flags, extTextOptionsSpec);
}

/**
 * Returns the four RECT values as a string of the form:
 *     (left, top, right, bottom) = (0, 0, 77, 15)
 *
 * @param {NativePointer} lprect - Pointer to a Windows RECT object.  The memory
 *     consists of four (4) contiguous LONG values, corresponding to the left,
 *     top, right, and bottom values, respectively.
 * @returns {string} Description of the RECT.
 */
function rectStructToString(lprect) {
  if (lprect.isNull()) {
    return 'LPRECT is null';
  }

  const left   = lprect.readU32();
  const top    = lprect.add(4).readU32();
  const right  = lprect.add(8).readU32();
  const bottom = lprect.add(12).readU32();

  return `(left, top, right, bottom) = (${left}, ${top}, ${right}, ${bottom})`;
}
{% endhighlight %}

The two `-S` command line options provide the paths to the “core.js” and
“ms-windows.js” shared library source files.

Touching just about anything in the Word application with the cursor will
generate ExtTextOutW() traces.

## Points to Consider

Here are some points to consider when using the `-S` option.

### Use different code source files to group your shared functions

For clarity sake, you can have several shared code files for different groups of
functions.  In the above example, the common and basic functions reside in
“core.js”, while MS Windows specific function are found in “ms-windows.js”.
In other projects of mine I have files for Android-related functions, for Linux
functions, etc.

### Implementing namespaces

As the number of shared library code files you use grows, you may experience
name clashes due to “namespace pollution”.  This can occur if two different
shared code files implement a function with the same name.  If within your own
organization, you can modify the name.  If, however, you are using third-party
shared code libraries, this might be more difficult.

A possible solution is for a shared library to store its functions on a global
object named descriptively, and correspondingly for data stored on “state”.

Here is how you might implement it:

{% highlight js %}
const MyLibrary = {
  doX() {
  },
  doY() {
  }
};
{% endhighlight %}


[ExtTextOutW]: https://web.archive.org/web/20191222090821/https://docs.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-exttextoutw
