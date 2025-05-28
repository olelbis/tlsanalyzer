# sslscango

 [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
 [![OS - Linux](https://img.shields.io/badge/OS-Linux-blue?logo=linux&logoColor=white)](https://www.linux.org/ "Go to Linux homepage")
 [![OS - FreeBSD](https://img.shields.io/badge/OS-FreeBSD-blue)](https://www.freebsd.org/ "Go to FreeBSD homepage")
 [![OS - MacOS](https://img.shields.io/badge/OS-macOS-blue?logo=Apple&logoColor=white)](https://apple.com/ "Go to Apple homepage")
 [![contributions - welcome](https://img.shields.io/badge/contributions-welcome-blue)](/CONTRIBUTING.md "Go to contributions doc")

 ## Building from source

If you want to build `sslscango` from source, please verify to have already installed **go1.23.4** or higher.

Then run this command:

```bash
go build -v -ldflags="-X 'github.com/olelbis/sslscango/build.Version=$(cat VERSION)' -X 'github.com/olelbis/sslscango/build.BuildUser=Team chref' -X 'github.com/olelbis/sslscango/build.BuildTime=$(date)'"
```