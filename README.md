# AbandonedIcebox
The dream of an intelligent and multi-purpose reverse engineering tool.

## DebugEngine (C++)
Contains the main functionality, the heart of the project.

Command line flags:
* `--lazy` resolve DLL imports once they are needed, not during load time
* `--ugly` ignore any invalid/flawed instruction
* `--nofat` simply do not throw any assertion-exceptions
