# Linux on Docker
In order to run Frida using Linux in Docker, you will need to start the container without seccomp, e.g:
```
docker run --security-opt seccomp:unconfined -it <image name> /bin/bash
```
The above will create a container based off of the image you specified, disable seccomp, and run an interactive shell. You can then use `frida-trace` to test out Frida.
