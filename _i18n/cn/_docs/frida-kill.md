这是一个用于杀死进程的命令行工具。

您可以从 [frida-ps](/docs/frida-ps/) 工具获取 PID。
{% highlight bash %}
$ frida-kill -D <DEVICE-ID> <PID>
# 列出活动应用程序
$ frida-ps -D 1d07b5f6a7a72552aca8ab0e6b706f3f3958f63e  -a

PID  Name                Identifier
----  ------------------  -----------------------------------------------------
4433  Camera              com.apple.camera
4001  Cydia               com.saurik.Cydia
4997  Filza               com.tigisoftware.Filza
4130  IPA Installer       com.slugrail.ipainstaller
3992  Mail                com.apple.mobilemail
4888  Maps                com.apple.Maps
6494  Messages            com.apple.MobileSMS
5029 Safari              com.apple.mobilesafari
4121  Settings            com.apple.Preferences

# 将 Frida 连接到设备并杀死正在运行的进程
$ frida-kill -D 1d07b5f6a7a72552aca8ab0e6b706f3f3958f63e 5029

# 检查进程是否已被杀死
$ frida-ps -D 1d07b5f6a7a72552aca8ab0e6b706f3f3958f63e  -a

PID  Name                Identifier
----  ------------------  -----------------------------------------------------
4433  Camera              com.apple.camera
4001  Cydia               com.saurik.Cydia
4997  Filza               com.tigisoftware.Filza
4130  IPA Installer       com.slugrail.ipainstaller
3992  Mail                com.apple.mobilemail
4888  Maps                com.apple.Maps
6494  Messages            com.apple.MobileSMS
4121  Settings            com.apple.Preferences

{% endhighlight %}
