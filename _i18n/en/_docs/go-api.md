Go bindings enables usage of frida using Go language.

Some of the functionalities provided are:
* Listing devices/applications/processes
* Attaching to applications/processes
* Fetching informations about devices/applications/processes

For the full documentation please visit [pkg.go.dev][].

## Example

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

Example above should produce:

{% highlight bash %}
$ go build main.go && ./main
[*] Frida version: 16.0.3
[*] Devices:
[*] Local System => local
[*] Local Socket => socket
{% endhighlight %}

[pkg.go.dev]: https://pkg.go.dev/github.com/frida/frida-go/frida
