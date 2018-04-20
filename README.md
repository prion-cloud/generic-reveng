# AbandonedIcebox
_Just because the acronym is 'AI'._

## DebugEngine (C++)
Contains the main functionality, the heart of the project.

Planned CLI commands:
* `debug` debugs a specified PE file
  * `--lazy` resolve external references (imports, etc.) once they are needed, not during load time
  * `--nofail` simply do not throw any exceptions
* `break` sets an executino breakpoint at a specified position

## SharpReverse (C#/.NET)
Adapter to managed code with reduced features (e.g. for GUIs).
