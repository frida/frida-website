Go 绑定使您可以轻松地从 [Go][] 使用 Frida 的 API。

提供的一些功能包括：

* 列出设备/应用程序/进程
* 附加到应用程序/进程
* 获取有关设备/应用程序/进程的信息

有关完整文档，请访问 [pkg.go.dev][]。

## 示例

{% highlight golang %}
package main

import (
	"fmt"

	"github.com/frida/frida-go/frida"
)

func main() {
	manager := frida.NewDeviceManager()
	devices, err := manager.EnumerateDevices()
	if err != nil {
		panic(err)
	}

	fmt.Printf("[*] Frida version: %s\n", frida.Version())
	fmt.Println("[*] Devices: ")
	for _, device := range devices {
		fmt.Printf("[*] %s => %s\n", device.Name(), device.ID())
	}
}
{% endhighlight %}

上面的示例应该输出类似以下内容：

{% highlight bash %}
$ go build main.go && ./main
[*] Frida version: 16.0.3
[*] Devices:
[*] Local System => local
[*] Local Socket => socket
{% endhighlight %}


[Go]: https://go.dev/
[pkg.go.dev]: https://pkg.go.dev/github.com/frida/frida-go/frida
