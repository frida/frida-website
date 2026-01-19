我们展示了如何使用 Frida 在函数被调用时检查它们，修改它们的参数，以及对目标进程内的函数进行自定义调用。

## 设置实验

创建一个文件 `hello.c`：

{% highlight c %}
#include <stdio.h>
#include <unistd.h>

void
f (int n)
{
  printf ("Number: %d\n", n);
}

int
main (int argc,
      char * argv[])
{
  int i = 0;

  printf ("f() is at %p\n", f);

  while (1)
  {
    f (i++);
    sleep (1);
  }
}
{% endhighlight %}

使用以下命令编译：

{% highlight bash %}
$ gcc -Wall hello.c -o hello
{% endhighlight %}

启动程序并记下 `f()` 的地址（在以下示例中为 `0x400544`）：

{% highlight bash %}
f() is at 0x400544
Number: 0
Number: 1
Number: 2
…
{% endhighlight %}

## Hook 函数

以下脚本展示了如何 hook 目标进程内的函数调用并将函数参数报告给您。创建一个包含以下内容的文件 `hook.py`：

{% highlight py %}
import frida
import sys

session = frida.attach("hello")
script = session.create_script("""
Interceptor.attach(ptr("%s"), {
    onEnter(args) {
        send(args[0].toInt32());
    }
});
""" % int(sys.argv[1], 16))
def on_message(message, data):
    print(message)
script.on('message', on_message)
script.load()
sys.stdin.read()
{% endhighlight %}

使用您从上面挑选出的地址运行此脚本（在我们的示例中为 `0x400544`）：

{% highlight bash %}
$ python hook.py 0x400544
{% endhighlight %}

这应该每秒给您一条如下形式的新消息：

{% highlight py %}
{'type': 'send', 'payload': 531}
{'type': 'send', 'payload': 532}
…
{% endhighlight %}

## 修改函数参数

接下来：我们想要修改传递给目标进程内函数的参数。创建具有以下内容的 `modify.py` 文件：

{% highlight py %}
import frida
import sys

session = frida.attach("hello")
script = session.create_script("""
Interceptor.attach(ptr("%s"), {
    onEnter(args) {
        args[0] = ptr("1337");
    }
});
""" % int(sys.argv[1], 16))
script.load()
sys.stdin.read()
{% endhighlight %}

针对 `hello` 进程运行此脚本（它应该仍在运行）：

{% highlight bash %}
$ python modify.py 0x400544
{% endhighlight %}

此时，运行 `hello` 进程的终端应该停止计数并始终报告 `1337`，直到您按 `Ctrl-D` 从中分离。

{% highlight bash %}
Number: 1281
Number: 1282
Number: 1337
Number: 1337
Number: 1337
Number: 1337
Number: 1287
Number: 1288
Number: 1289
…
{% endhighlight %}

## 调用函数

我们可以使用 Frida 调用目标进程内的函数。创建具有以下内容的 `call.py` 文件：

{% highlight py %}
import frida
import sys

session = frida.attach("hello")
script = session.create_script("""
const f = new NativeFunction(ptr("%s"), 'void', ['int']);
f(1911);
f(1911);
f(1911);
""" % int(sys.argv[1], 16))
script.load()
{% endhighlight %}

运行脚本：

{% highlight bash %}
$ python call.py 0x400544
{% endhighlight %}

并密切关注（仍在）运行 `hello` 的终端：

{% highlight bash %}
Number: 1879
Number: 1911
Number: 1911
Number: 1911
Number: 1880
…
{% endhighlight %}

## 实验 2 - 注入字符串并调用函数

注入整数非常有用，但我们也可以注入字符串，实际上，还可以注入您进行模糊测试/测试所需的任何其他类型的对象。

创建一个新文件 `hi.c`：

{% highlight c %}
#include <stdio.h>
#include <unistd.h>

int
f (const char * s)
{
  printf ("String: %s\n", s);
  return 0;
}

int
main (int argc,
      char * argv[])
{
  const char * s = "Testing!";

  printf ("f() is at %p\n", f);
  printf ("s is at %p\n", s);

  while (1)
  {
    f (s);
    sleep (1);
  }
}
{% endhighlight %}

与之前类似，我们可以创建一个脚本 `stringhook.py`，使用 Frida 将字符串注入内存，然后以以下方式调用函数 f()：

{% highlight py %}
import frida
import sys

session = frida.attach("hi")
script = session.create_script("""
const st = Memory.allocUtf8String("TESTMEPLZ!");
const f = new NativeFunction(ptr("%s"), 'int', ['pointer']);
    // In NativeFunction param 2 is the return value type,
    // and param 3 is an array of input types
f(st);
""" % int(sys.argv[1], 16))
def on_message(message, data):
    print(message)
script.on('message', on_message)
script.load()
{% endhighlight %}

密切关注 `hi` 的输出，您应该看到类似以下的内容：

{% highlight bash %}
...
String: Testing!
String: Testing!
String: TESTMEPLZ!
String: Testing!
String: Testing!
...
{% endhighlight %}

使用类似的方法，如 `Memory.alloc()` 和 `Memory.protect()` 来轻松操作进程内存。将其与 python `ctypes` 库结合使用，可以创建其他内存对象（如 `structs`），将其作为字节数组加载，然后作为指针参数传递给函数。

## 注入恶意内存对象 - 示例：sockaddr_in 结构体

任何做过网络编程的人都知道，C 语言中最常用的数据类型之一是 `struct`。这是一个简单的程序示例，它创建一个网络套接字，并通过端口 5000 连接到服务器，并通过连接发送字符串 `"Hello there!"` 来宣布自己。

{% highlight c %}
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int
main (int argc,
      char * argv[])
{
  int sock_fd, i, n;
  struct sockaddr_in serv_addr;
  unsigned char * b;
  const char * message;
  char recv_buf[1024];

  if (argc != 2)
  {
    fprintf (stderr, "Usage: %s <ip of server>\n", argv[0]);
    return 1;
  }

  printf ("connect() is at: %p\n", connect);

  if ((sock_fd = socket (AF_INET, SOCK_STREAM, 0)) < 0)
  {
    perror ("Unable to create socket");
    return 1;
  }

  bzero (&serv_addr, sizeof (serv_addr));

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons (5000);

  if (inet_pton (AF_INET, argv[1], &serv_addr.sin_addr) <= 0)
  {
    fprintf (stderr, "Unable to parse IP address\n");
    return 1;
  }
  printf ("\nHere's the serv_addr buffer:\n");
  b = (unsigned char *) &serv_addr;
  for (i = 0; i != sizeof (serv_addr); i++)
    printf ("%s%02x", (i != 0) ? " " : "", b[i]);

  printf ("\n\nPress ENTER key to Continue\n");
  while (getchar () == EOF && ferror (stdin) && errno == EINTR)
    ;

  if (connect (sock_fd, (struct sockaddr *) &serv_addr, sizeof (serv_addr)) < 0)
  {
    perror ("Unable to connect");
    return 1;
  }

  message = "Hello there!";
  if (send (sock_fd, message, strlen (message), 0) < 0)
  {
    perror ("Unable to send");
    return 1;
  }

  while (1)
  {
    n = recv (sock_fd, recv_buf, sizeof (recv_buf) - 1, 0);
    if (n == -1 && errno == EINTR)
      continue;
    else if (n <= 0)
      break;
    recv_buf[n] = 0;

    fputs (recv_buf, stdout);
  }

  if (n < 0)
  {
    perror ("Unable to read");
  }

  return 0;
}
{% endhighlight %}

这是相当标准的代码，并调用作为第一个参数给出的任何 IP 地址。如果您运行 `nc -lp 5000` 并在另一个终端窗口中运行 `./client 127.0.0.1`，您应该看到消息出现在 netcat 中，并且还能够发回消息给 `client`。

现在，我们可以开始找点乐子了 - 正如我们在上面看到的，我们可以将字符串和指针注入到进程中。我们可以通过操作程序作为其操作的一部分吐出的结构体 `sockaddr_in` 来做同样的事情：

{% highlight bash %}
$ ./client 127.0.0.1
connect() is at: 0x400780

Here's the serv_addr buffer:
02 00 13 88 7f 00 00 01 30 30 30 30 30 30 30 30
Press ENTER key to Continue
{% endhighlight %}

如果您不完全熟悉 struct 的结构，网上有很多资源会告诉您这是什么。这里重要的部分是字节 `0x1388`，即十进制的 5000。这是我们的端口号（后面的 4 个字节是十六进制的 IP 地址）。如果我们将其更改为 `0x1389`，那么我们可以将客户端重定向到不同的端口。如果我们更改接下来的 4 个字节，我们可以完全更改客户端指向的 IP 地址！

这是一个将恶意结构体注入内存，然后劫持 `libc.so` 中的 `connect()` 函数以将我们的新结构体作为其参数的脚本。

创建如下文件 `struct_mod.py`：

{% highlight py %}
import frida
import sys

session = frida.attach("client")
script = session.create_script("""
// First, let's give ourselves a bit of memory to put our struct in:
send('Allocating memory and writing bytes...');
const st = Memory.alloc(16);
// Now we need to fill it - this is a bit blunt, but works...
st.writeByteArray([0x02, 0x00, 0x13, 0x89, 0x7F, 0x00, 0x00, 0x01, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30]);
// Module.getGlobalExportByName() can find functions without knowing the source
// module, but it's slower, especially over large binaries! YMMV...
Interceptor.attach(Module.getGlobalExportByName('connect'), {
    onEnter(args) {
        send('Injecting malicious byte array:');
        args[1] = st;
    }
    //, onLeave(retval) {
    //   retval.replace(0); // Use this to manipulate the return value
    //}
});
""")

# Here's some message handling..
# [ It's a little bit more meaningful to read as output :-D
#   Errors get [!] and messages get [i] prefixes. ]
def on_message(message, data):
    if message['type'] == 'error':
        print("[!] " + message['stack'])
    elif message['type'] == 'send':
        print("[i] " + message['payload'])
    else:
        print(message)
script.on('message', on_message)
script.load()
sys.stdin.read()
{% endhighlight %}

请注意，此脚本演示了如何使用 `Module.getGlobalExportByName()` API 在我们的目标中按名称查找任何导出的函数。如果我们可以提供模块，那么在较大的二进制文件上会更快，但这在这里不太重要。

现在，运行 `./client 127.0.0.1`，在另一个终端运行 `nc -lp 5001`，在第三个终端运行 `./struct_mod.py`。一旦我们的脚本运行，在 `client` 终端窗口中按 ENTER，netcat 现在应该显示客户端发送的字符串。

我们已经成功劫持了原始网络，方法是将我们自己的数据对象注入内存并使用 Frida hook 我们的进程，并使用 `Interceptor` 来完成我们在操作函数方面的肮脏工作。

这展示了 Frida 的真正力量 - 无需修补、复杂的逆向工程，也无需花费数小时盯着反汇编代码。

这是一个演示上述内容的快速视频：

https://www.youtube.com/watch?v=cTcM7R872Ls
