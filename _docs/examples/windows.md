---
layout: docs
title: Windows
permalink: /docs/examples/windows/
---
***
Python Example Module for directly monitoring a jvm.dll under Windows which is being executed by a main process called fledge.exe (BB Simulator) using Frida.

*Usage:*
Save this code as bb.py, run BB Simulator (fledge.exe), then run "Python.exe bb.py fledge.exe" for monitoring aes
usage of jvm.dll
***

```
import sys
import frida
 
def on_message(message, data):
    print "[%s] => %s" % (message, data)
 
def main(target_process):
    session = frida.attach(target_process)
    # Here we start with Javascript
    script = session.create_script("""
    
	var BaseAddr = Module.findBaseAddress('Jvm.dll'); // Find base address of current imported jvm.dll by main process fledge.exe
    console.log("Jvm.dll BaseAddr: " + BaseAddr.toString());

	function parseaddr (info,addr,size) { // Small function to dump data as a beautiful hex
		if (addr.toString()!="0x0")
		{
			console.log("Data dump "+info+" "+":");
			var buf = Memory.readByteArray(addr, size);
			console.log(hexdump(buf, {offset: 0,length: size,header: true,ansi: false})); // If you need color magic, set ansi to true
		}
	}
	
	function getbase(addr) { // function calculates current offset the function we try to monitor when loaded into memory
		var IDABase=ptr("0x1FEE0000"); // Enter here base address of jvm.dll as seen in your favorite disassembler (here IDA)
		var Offset=parseInt(ptr(addr), 16) - parseInt(IDABase, 16); // Calculate current address in memory from base address in IDA database
		var Addr=+BaseAddr + +Offset; // Add current memory base address with offset of function to monitor
		console.log('[+] New addr= ' + ptr(Addr).toString()); // Write location of function in memory to console
		return ptr(Addr);
	}
	
	var SetAesDeCrypt0=getbase("0x1FF44870"); //Here we use the function address as seen in our disassembler
	
	Interceptor.attach(SetAesDeCrypt0, { //Intercept our SetAesDecrypt function on call
    outptr:0, outsize:0,
	
	onEnter: function (args){ //When function is called, print out its parameters
		console.log('');
		console.log('[+] Called SetAesDeCrypt0' + SetAesDeCrypt0.toString());
		console.log('[+] Ctx: ' + args[0].toString());
		console.log('[+] Input: ' + args[1].toString()); //Plaintext
		console.log('[+] Output: ' + args[2].toString()); //This pointer will store the de/encrypted data
		console.log('[+] Len: ' + args[3].toString()); //Length of data to en/decrypt
		parseaddr('Input',args[1],args[3].toInt32());
		this.outptr=args[2]; //Store arg2 and arg3 in order to see when we leave the function
		this.outsize=args[3].toInt32();
        },
    
onLeave: function (retval){ //When function is finished
		parseaddr('Ret_Output',this.outptr,this.outsize); // Print out data array, which will contain de/encrypted data as output
		console.log('[+] Returned from SetAesDeCrypt0: '+ retval.toString());
        }

    });
	
""")
 # Javascript done
 
    script.on('message', on_message)
    script.load()
    raw_input('[!] Press Enter at any time to detach from instrumented program.\n\n')
    session.detach()
 
if __name__ == '__main__':
    if len(sys.argv)!=2:
        print 'Usage: %s process name or PID' % __file__ # You can use both process id or process name (fledge.exe)
        sys.exit(1)
 
    try:
        target_process = int(sys.argv[1])
    except ValueError:
        target_process = sys.argv[1]
    main(target_process)
```
