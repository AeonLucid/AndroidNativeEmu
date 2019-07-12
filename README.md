# AndroidNativeEmu
[ 中文README & 教程？ ](README_cn.md)

Allows you to partly emulate an Android native library.

This is an educational project to learn more about the ELF file format and [Unicorn](https://github.com/unicorn-engine/unicorn).

## Features

- Emulation of the [JNI Invocation API](https://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/invocation.html) so `JNI_OnLoad` can be called properly.
- Emulation of native memory for malloc / memcpy.
- Emulation of syscalls (SVC #0) instruction.
- Hooking through the symbol table.
- All JavaVM, JNIEnv and hooked functions are handled by python.
- Enable VFP support.

## My Changes
- Add init_array support depends on Relocation information.
- Add support of modify object value by reference id.
- Implement getcpu() syscall
- Implement set_byte_array_region
- Register Function failed would't raise an error(beacuse most jni functions are not used.)
- samples:添加抖音 X-Gorgen 调用实例
- [ 中文README ](README_cn.md)

## Usage

> In the future this will be possible through pypi.

Make sure you are using python 3.7.

1. Clone the repository
2. Run `pip install -r requirements.txt`
3. Run `python example.py`

> If you have trouble getting the `keystone-engine` dependency on Windows (as I did):
> 1. Clone their [repository](https://github.com/keystone-engine/keystone)
> 2. Open a terminal in `bindings/python`
> 3. Run `python setup.py install` (Make sure you are using python 3.7)
> 4. Download their `Windows - Core engine` package [here](http://www.keystone-engine.org/download/) for your python arch.
> 5. Put the `keystone.dll` in `C:\location_to_python\Lib\site-packages\keystone\`.

## TODO

- Improve file descriptors in `vfs/file_system.py` so they are re-useable.
- Add a way for the VirtualFileSystem to give back dynamic files, such as `/proc/self/status`, `/proc/self/status` but also `/dev/urandom`.
- Library consumers must be able to easily rebuild the needed Java classes for a native library, which are used by the native library through the JNIEnv.
  - ~~Classes~~
  - ~~Objects~~
  - ~~Methods~~
  - ~~Native methods~~
  - Fields
  - Types
  - Reflection

## Dependencies

- [Unicorn CPU emulator framework](https://github.com/unicorn-engine/unicorn)
- [Keystone assembler framework](https://github.com/keystone-engine/keystone)

## Resources

All resources used while developing AndroidNativeEmu.

### Text sources
- https://greek0.net/elf.html
- https://stackoverflow.com/questions/13908276/loading-elf-file-in-c-in-user-space
- https://programtalk.com/python-examples/pyelftools.elftools.elf.relocation.Relocation/
- http://infocenter.arm.com/help/topic/com.arm.doc.ihi0044f/IHI0044F_aaelf.pdf
- https://wiki.osdev.org/ELF_Tutorial
- https://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/functions.html
- https://android.googlesource.com/platform/dalvik/+/donut-release/vm/Jni.c

### Code sources
- https://github.com/lunixbochs/usercorn
- https://github.com/slick1015/pad_unpacker (SVC 0 instruction)
