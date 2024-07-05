# Binary Ninja Interactive Functions List (IFL) Plugin

License: CC-BY (https://creativecommons.org/licenses/by/3.0/)

This is a Binary Ninja version of the [IDA IFL](https://github.com/hasherezade/ida_ifl) plugin written by hasherezade.

ILF is a small plugin with the goal to provide user-friendly way to navigate between functions and their references.<br/>
Additionally, it allows to import reports generated by i.e. [PE-sieve](https://github.com/hasherezade/pe-sieve/wiki/1.-FAQ) into Binary Ninja. Supports:
+ [`.tag` format](https://github.com/hasherezade/tiny_tracer/wiki/Using-the-TAGs-with-disassemblers-and-debuggers) (generated by [PE-sieve](https://github.com/hasherezade/pe-sieve), [Tiny Tracer](https://github.com/hasherezade/tiny_tracer), [PE-bear](https://github.com/hasherezade/pe-bear-releases))
+ [`.imports.txt` format](https://github.com/hasherezade/pe-sieve/wiki/4.3.-Import-table-reconstruction-(imp)) (generated by [PE-sieve](https://github.com/hasherezade/pe-sieve))

Examples
==

![](https://github.com/leandrofroes/bn_ifl/blob/master/img/example1.png)

![](https://github.com/leandrofroes/bn_ifl/blob/master/img/example2.png)