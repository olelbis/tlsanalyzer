# sslscango

 [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
 [![OS - Linux](https://img.shields.io/badge/OS-Linux-blue?logo=linux&logoColor=white)](https://www.linux.org/ "Go to Linux homepage")
 [![OS - MacOS](https://img.shields.io/badge/OS-macOS-blue?logo=Apple&logoColor=white)](https://apple.com/ "Go to Apple homepage")
 

`sslscango` It is a utility that takes inspiration from the original `sslscan`, with fewer features, but with the aim of being used in those work contexts where it is not permitted to install anything on your machines, or where you are not allowed access to the internet network.

This is early development version.
## Roadmap:

- [x] Timeout flag
- [x] Print certificate chain
- [ ] Save certificate chain on file
- [ ] Generate report
- [ ] TBD

 ## Building from source

If you want to build `sslscango` from source, please verify to have already installed **go1.23.4** or higher.

Then run this command:

```bash
go build -v -ldflags="-X 'github.com/olelbis/sslscango/build.Version=$(cat VERSION)' -X 'github.com/olelbis/sslscango/build.BuildUser=Team sslscango' -X 'github.com/olelbis/sslscango/build.BuildTime=$(date)'"
```