---
layout: docs
title: Android
permalink: /docs/examples/android/
---
# Example module for using Frida with Android #

Using Android 4.4 Emulator x86 is strongly recommended, here is an example how to
ctf the SECCON Quals CTF 2015 APK1 example, download the APK over here:
[Link to APK](https://github.com/ctfs/write-ups-2015/tree/master/seccon-quals-ctf-2015/binary/reverse-engineering-android-apk-1)

##Usage:##
Save code as ctf.py and run as "python ctf.py"

```
# SECCTF2015 APK1

import frida,sys
 
def on_message(message, data):
    try:
        if message:
            print("[*] {0}".format(message["payload"]))
    except Exception as e:
        print(message)
        print(e)
 
jscode = """
 
Dalvik.perform(function () {
var MainActivity = Dalvik.use("com.example.seccon2015.rock_paper_scissors.MainActivity"); //define function to hook over here
MainActivity.onClick.implementation = function (v) { // if button gets clicked
send("Run."); //Show a message, that function got called
this.onClick(v); //Send original onClick event
this.m['value']=0; //Set our values after running original onClick event, here value of variable m=0
this.n['value']=1; //Set our values after running original onClick event, here value of variable n=1
this.cnt['value']=999; //Set our values after running original onClick event, here value of cnt=999
console.log("Done:"+JSON.stringify(this.cnt)); //Send info to console that its done, and we should have ctf !
};
});
"""
 
process = frida.get_device_manager().enumerate_devices()[-1].attach("com.example.seccon2015.rock_paper_scissors") #Enumerate attached adb devices and attach to process "com.example.seccon2015.rock_paper_scissors"
script = process.create_script(jscode) #Process Javascript part
script.on('message', on_message)
 
print "[*] Running CTF"
 
script.load()
sys.stdin.read()
```
