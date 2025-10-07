---
layout: docs
title: Windows
permalink: /docs/examples/windows/
---

## Example tool for directly monitoring a jvm.dll

Shows how to monitor a jvm.dll which is being executed by a process called
*fledge.exe* (BB Simulator) using Frida.

Save this code as *bb.py*, run BB Simulator (fledge.exe), then run
`python.exe bb.py fledge.exe` for monitoring
[AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) usage of
*jvm.dll*.

{% highlight py %}
import frida
import sys

def on_message(message, data):
    print("[%s] => %s" % (message, data))

def main(target_process):
    session = frida.attach(target_process)

    script = session.create_script("""

    // Find base address of current imported jvm.dll by main process fledge.exe
    const baseAddr = Process.getModuleByName('Jvm.dll').base;
    console.log('Jvm.dll baseAddr: ' + baseAddr);

    const setAesDecrypt0 = resolveAddress('0x1FF44870'); // Here we use the function address as seen in our disassembler

    Interceptor.attach(setAesDecrypt0, { // Intercept calls to our SetAesDecrypt function

        // When function is called, print out its parameters
        onEnter(args) {
            console.log('');
            console.log('[+] Called SetAesDeCrypt0' + setAesDecrypt0);
            console.log('[+] Ctx: ' + args[0]);
            console.log('[+] Input: ' + args[1]); // Plaintext
            console.log('[+] Output: ' + args[2]); // This pointer will store the de/encrypted data
            console.log('[+] Len: ' + args[3]); // Length of data to en/decrypt
            dumpAddr('Input', args[1], args[3].toInt32());
            this.outptr = args[2]; // Store arg2 and arg3 in order to see when we leave the function
            this.outsize = args[3].toInt32();
        },

        // When function is finished
        onLeave(retval) {
            dumpAddr('Output', this.outptr, this.outsize); // Print out data array, which will contain de/encrypted data as output
            console.log('[+] Returned from setAesDecrypt0: ' + retval);
        }
    });

    function dumpAddr(info, addr, size) {
        if (addr.isNull())
            return;

        console.log('Data dump ' + info + ' :');
        const buf = addr.readByteArray(size);

        // If you want color magic, set ansi to true
        console.log(hexdump(buf, { offset: 0, length: size, header: true, ansi: false }));
    }

    function resolveAddress(addr) {
        const idaBase = ptr('0x1FEE0000'); // Enter the base address of jvm.dll as seen in your favorite disassembler (here IDA)
        const offset = ptr(addr).sub(idaBase); // Calculate offset in memory from base address in IDA database
        const result = baseAddr.add(offset); // Add current memory base address to offset of function to monitor
        console.log('[+] New addr=' + result); // Write location of function in memory to console
        return result;
    }
""")
    script.on('message', on_message)
    script.load()
    print("[!] Ctrl+D on UNIX, Ctrl+Z on Windows/cmd.exe to detach from instrumented program.\n\n")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: %s <process name or PID>" % __file__)
        sys.exit(1)

    try:
        target_process = int(sys.argv[1])
    except ValueError:
        target_process = sys.argv[1]
    main(target_process)
{% endhighlight %}
