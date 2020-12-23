This page describes uses for the frida-trace `--init-session` / `-S` command line option, and how to 
utilize it in your work.

## What is the --init-session option?

The `--init-session` option executes any number of user-written JavaScript 
code files during the frida-trace engine initialization stage.  These files 
are executed before the first function handler is called.

Its power comes from the ability to create and save code and data objects in the global "state"
object, which is passed as a parameter to every handler called.  The "state" object allows you 
to maintain information across function calls.  Code and data objects stored in "state"
are accessible to all called handlers.

## Uses for the --init-session option

The `--init-session` / `-S` option guarantees that JavaScript source code
of your choice is executed before the frida-trace engine begins its tracing.  Possible
applications of this feature include:

<ol>
<li>Executing custom code that creates both code and data objects of your choice, doing
this before the first function handler is invoked.</li>
<li>Creating a library of shared code, allowing the sharing of fine-tuned and debugged
JavaScript code that can be called globally by any handler, at any time.</li>
</ol>

Frida-trace JavaScript code is often written as one-time "throw-away" code.  If, however, 
you find yourself frequently copying and pasting code between handlers and projects, 
consider saving the code in a shared library.  Once written and debugged, you can reuse 
the functions and data in future projects.

## Detailed Example: Creating a shared-code library

In this example, we demonstrate using the `--init-session` / `-S` option to enhance
tracing of the Microsoft Windows `ExtTextOutW` function.  We describe the components
in a top-down fashion, beginning with the ExtTextOutW.js JavaScript handler function, working 
our way down to the shared code files.

### ExtTextOutW: Function Signature

In my Windows system, the <a href="https://web.archive.org/web/20191222090821/https://docs.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-exttextoutw">ExtTextOutW</a> function 
to monitor resides in <i>gdi32full.dll</i>. Here is the C++ syntax of the function:

<pre style="font-size: medium; background-color:powderblue; line-height: normal; margin-left: 50px;">
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
</pre>

Leveraging JavaScript code in our shared code libraries, we produce an enhanced tracing output.

### The enhanced trace output

Before showing the handler code and the shared code libraries, here is the enhanced tracing output itself:

<pre style="font-size: medium; background-color:powderblue; line-height: normal; margin-left: 50px;">
c:\project>frida-trace -p 6980 --decorate -i "gdi32full.dll!ExtTextOutW" -S core.js -S ms-windows.js
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
</pre>

Notice the following tracing enhancements:

<ul>
<li>The 'options' field is converted to textual form</li>
<li>The 'lprect' memory pointer is displayed as both a hex memory dump and a textual string</li>
<li>The 'lpString' memory pointer is displayed as both a hex memory dump and a textual string</li>
<li>The 'lpDx' integer pointer is displayed as both a hex memory dump and an integer</li>
</ul>

The textual conversions and hex memory dumps are functions within our shared code libraries.  Let's see
our `ExtTextOutW` handler JavaScript code, which will make use of the shared code.

### Handler: ExtTextOutW.js

Here is our 'ExeTextOutW' handler code.  We enhance it by invoking shared code functions.  You can 
identify these shared code function calls as those that begin "state.".  These functions exist as
JavaScript function objects stored in the 'state' global object.  The function objects are created
when the shared code Javascript files are executed by frida-trace via the `--init-session` / `-S` command 
line option.

<pre style="font-size: medium; background-color:powderblue; line-height: normal; margin-left: 50px;">
/*
 * Auto-generated by Frida. Please modify to match the signature of ExtTextOutW.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

{
  onEnter(log, args, state) {
    /*
        C++ Syntax:

        BOOL ExtTextOutW(
          HDC        hdc,
          int        x,
          int        y,
          UINT       options,
          const RECT *lprect,
          LPCWSTR    lpString,
          UINT       c,
          const INT  *lpDx
        );
    */

    log('---------------------------------------------');
    log('ExtTextOutW() [gdi32full.dll]');
    state.generalCloneArgs(args, 8, this);
    log('x: ' + args[1].toString(10));
    log('y: ' + args[2].toString(10));
    log('options: ' + state.decodeExttextoutOptions(args[3]));
    if (!args[4].isNull()) {
        state.generalHexdump(log, 'lprect', args[4], 20);
        log('lprect: ' + state.rectStructToString(args[4]));
    }
    if (!args[5].isNull()) {
        state.generalHexdump(log, 'lpString', args[5], 50);
        log('*lpString: "' + args[5].readUtf16String() + '"');
    }
    log('c: ' + args[6].toString(10));
    if (!args[7].isNull()) {
        state.generalHexdump(log, 'lpDx', args[7], 4);
        log('*lpDx: ' + args[7].readU32().toString(10));
    }
  },

  onLeave(log, retval, state) {
    // We can access the onEnter arguments using "this.args"
    log('x (exit): ' + this.args[1].toString(10));
    log('y (exit): ' + this.args[2].toString(10));
  }
}
</pre>

Note that, besides calling standard frida-trace functions (e.g., `toString`,
`isNull`, `readUtf16String`), there are calls to our shared code functions (e.g., 
`state.general_clone_args`, `state.decode_exttextout_options`, `state.general_hexdump`,
`state.rect_struct_tostring`).  The shared code functions have been debugged and refined,
and are ready for calling by any handler, at any time.
<p/>
### Shared Code: core.js

The 'core.js' shared code library contains core, or basic, functions that are meant to be reused by
frida-trace handlers and shared code libraries.

Writing a shared code library is simple: your shared library source files create 
function and data objects, storing them in the global "state" object.  Once stored there, any 
handler can access or invoke the objects by referring to them as "state.&lt;function-name&gt;".

<pre style="font-size: medium; background-color:powderblue; line-height: normal; margin-left: 50px;">
// Define useful general-purpose Frida handler functions

//--------------------------------------------------------------------
// state.generalCloneArgs()
//
// args (array):     [in] The "args" array as passed to the onEnter() function.
// numArgs (int32):  [in] The number of meaningful arguments in "args". This
//                        function has no way of determining the number of
//                        actual arguments because "args" is a virtual array.
// myThis (object):  [in] The "this" object of the calling onEnter() function.
//
// This function creates a true JavaScript array as [myThis].args.  This
// array can be accessed in the handler's onLeave() function.
//--------------------------------------------------------------------
state.generalCloneArgs = function(args, numArgs, myThis)
{
    if (myThis.args === undefined) {
        myThis.args = []

        for (let i=0; i<numArgs; ++i) {
            myThis.args.push (args[i].add(0));
        }
    }
};

//--------------------------------------------------------------------
// state.generalDecodeBitflags()
//
// value (int32):     [in] A value consisting of optional bitflags
// dict (dictionary): [in] A JavaScript array whose elements are
//                         key/value pairs, where each pair has the
//                         form:
//                            [hex value] : [flag descriptive string]
//                         For example:
//                            {
//                               0x0004 : 'ETO_CLIPPED',
//                               0x0010 : 'ETO_GLYPH_INDEX',
//                               ...
//                            }
//
// Returns a string consisting of one or more flag strings delimited
// by the OR ('|') symbol.
//--------------------------------------------------------------------
state.generalDecodeBitflags = function(value, dict)
{
    let s = '';

    for (const key in dict) {
        if (value & key) {
            if (s.length > 0)
            {
                s = s + ' | ';
            }

            s = s + dict[key];
        }
    }

    return s;
};

//--------------------------------------------------------------------
// state.generalHexdumpLines()
//
// outlines:      [out] Caller-provided array that will return the hex dump lines
// desc:          [in]  Descriptive text, printed together with the hex dump
// pMem:          [in]  Frida NativePointer pointing to a memory location to dump
// len:           [in]  Number of bytes to dump
// indentString:  [in]  Optional string to prepend to each dump line
//
// This function produces a somewhat more elegant hex dump, based on frida-trace's
// own "hexdump".  It does not output the hex dump to any stream, but rather
// returns the hex dump lines in an array.  It is up to the caller to decide
// where to, and how, to output the dump lines.
//--------------------------------------------------------------------
state.generalHexdumpLines = function(outlines, desc, pMem, len, indentString)
{
    outlines.push(desc + ' [' + len + ' bytes]');

    const actualIndentString = (typeof indentString === 'undefined') ? '\t\t' : indentString;

    if (pMem === undefined) {
        outlines.push(actualIndentString + 'WARNING: pMem is UNDEFINED');
    } else if (pMem === null) {
        outlines.push(actualIndentString + 'WARNING: pMem is NULL');
    } else {
        try {
            const s = hexdump(pMem, {length: len});
            const splitLines = s.split('\n');
            for (let j=0; j<splitLines.length; ++j) {
                outlines.push(actualIndentString + splitLines [j]);
            }
        }
        catch (err) {
            outlines.push(actualIndentString + 'WARNING: pMem is NOT VALID (' + pMem.toString() + ')');
        }
    }
};

//--------------------------------------------------------------------
// state.generalHexdump()
//
// log (function): [in] The log object to output to
// desc (string):  [in] Descriptive string, printed with the hex dump
// pMem (pointer): [in] NativePointer pointing to a memory location to dump
// len (int):      [in] Number of bytes to dump
//
// Outputs the hex dump results to the log stream.  If you only want
// the dump lines without outputing them to the log stream, call
// the state.generalHexdumpLines() function directly.
//--------------------------------------------------------------------
state.generalHexdump = function(log, desc, pMem, len)
{
    let outlines = [];

    state.generalHexdumpLines(outlines, desc, pMem, len, '\t\t');
    log(outlines.join('\n'));
};
</pre>
<p/>
### Shared Code: ms-windows.js

The `ms-windows.js` shared code library consists of MS Windows-related utility functions, and is
built on top of the `core.js` library.

<p/>
<pre style="font-size: medium; background-color:powderblue; line-height: normal; margin-left: 50px;">
// Define useful Frida handler functions for MS Windows

//--------------------------------------------------------------------
// state.decodeExttextoutOptions()
//
// flags (int32): [in] A DWORD consisting of the "options" bit flags
//                     used in the ExtTextOutW function.
//
// This function decodes ExtTextOutW "options" bit flags, returning a
// string consisting of one or more bit flags strings delimited by
// the OR ('|') symbol.
//--------------------------------------------------------------------
state.decodeExttextoutOptions = function(/*DWORD*/ flags)
{
    const dict = {
                    0x0004 : 'ETO_CLIPPED',
                    0x0010 : 'ETO_GLYPH_INDEX',
                    0x1000 : 'ETO_IGNORELANGUAGE',
                    0x0800 : 'ETO_NUMERICSLATIN',
                    0x0400 : 'ETO_NUMERICSLOCAL',
                    0x0002 : 'ETO_OPAQUE',
                    0x2000 : 'ETO_PDY',
                    0x0080 : 'ETO_RTLREADING',
                    0x10000 : 'ETO_REVERSE_INDEX_MAP'
                 };

    return state.generalDecodeBitflags(flags, dict);
}

//--------------------------------------------------------------------
// state.rectStructToString()
//
// lprect (pointer): [in] A NativePointer object pointing to a Windows
//                        RECT object.  The memory consists of four (4)
//                        contiguous LONG values, corresponding to the
//                        left, top, right, and bottom values, respectively.
//
// This function returns the four RECT values as a string of the form:
//
//    (left, top ,right, bottom) = (0, 0, 77, 15)
//--------------------------------------------------------------------
state.rectStructToString = function(/*LPRECT*/ lprect)
{
    if (lprect.isNull()) {
        return 'LPRECT is null';
    }

    const left   = lprect.add(0).readU32();
    const top    = lprect.add(4).readU32();
    const right  = lprect.add(8).readU32();
    const bottom = lprect.add(12).readU32();

    return '(left, top, right, bottom) = (' + left + ', ' + top + ', ' + right + ', ' + bottom + ')';
}
</pre>

The two `-S` command line options provide the paths to the "core.js" and "ms-windows.js" shared library source files.

Touching just about anything in the Word application with the cursor will generate ExtTextOutW traces.
<p/>
## Points to Consider

Here are some points to consider when using the `-S` option.

### Use different code source files to group your shared functions

For clarity sake, you can have several shared code files for different groups of functions.  In 
the above example, the common and basic functions reside in 'core.js', while MS Windows specific
function are found in 'ms-windows.js'.  In other projects of mine I have files for Android-related
functions, for Linux functions, etc.

### Implementing namespaces

As the number of shared library code files you use grows, you may experience name clashes due to 'namespace
pollution'.  This can occur if two different shared code files implement a function with the same name.  If 
within your own organization, you can modify the name.  If, however, you are using third-party shared code libraries,
this might be more difficult.

A possible solution is for a shared library to store its function and data objects in a namespaced object
beneath "state".  For example, an organization called PQRS could store all its objects under "state.pqrs". 
Here is how you might implement it:

<pre style="font-size: medium; background-color:powderblue; line-height: normal; margin-left: 50px;">
// Define useful Frida handler functions for MS Windows

// Initialization code to guarantee the existence of a namespace
if (typeof state.pqrs === 'undefined') {
    state.pqrs = {}
}

state.pqrs.decodeExttextoutOptions = function(/*DWORD*/ flags)
{
    ...
}

state.pqrs.rectStructToString = function(/*LPRECT*/ lprect)
{
    ...
}
</pre>
