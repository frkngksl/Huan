# Huan

Huan is an encrypted PE Loader Generator that I developed for learning PE file structure and PE loading processes. It encrypts the PE file to be run with different keys each time and embeds it in a new section of the loader binary. Currently, it works on 64 bit PE files.

# How It Works?

First, Huan reads the given PE file and encrypts it with CBC mode AES-128 encryption algorithm. For the encryption, I used `Tiny AES in C` and prepared a padding code for the requirement of this library. When the encryption is complete, it compiles the loader using the Visual Studio compiler (`MsBuild.exe`) and creates an executable. After that, it creates a section (called `.huan`) on that executable, and embed the encrypted content, size information, IV and symmetric key. Both keys are created randomly for each copy of the loader. The layout of this section can be seen below.
<p align="center">
  <img src="https://user-images.githubusercontent.com/26549173/129253846-f29fd325-d0ef-4b80-af92-d415bfa33ff4.png">
</p>

When the loader is executed, it first takes the image base of itself by reading the `Process Environment Block`. After learning the image base, it parses the loaded copy of itself to find `.huan`section. Then, it decrypts the whole content, buffers it, and loads the binary which relies on the memory.
# Quick Demo
<p align="center">
  <img src="https://user-images.githubusercontent.com/26549173/129263548-76647e8c-35b7-48a0-8c7a-603f41cb82a3.gif">
</p>

# TO-DO List
- 32 Bit support
- Improvements on PE loader
- Blog post about PE loading process
- Reducing the detection rate of the loader

# References

- https://github.com/kokke/tiny-AES-c
- https://relearex.wordpress.com/2017/12/26/hooking-series-part-i-import-address-table-hooking/
- http://research32.blogspot.com/2015/01/base-relocation-table.html
- https://blog.kowalczyk.info/articles/pefileformat.html
- http://sandsprite.com/CodeStuff/Understanding_imports.html

# Disclaimer
I shared this tool only for showing the code snippets of well known TTPs. I'm not responsible for the use of this tool for malicious activities.
