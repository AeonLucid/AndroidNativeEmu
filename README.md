# AndroidNativeEmu

Allows you to partly emulate an Android native library.

This is an educational project to learn more about the ELF file format and [Unicorn](https://github.com/unicorn-engine/unicorn).

## Features

- Emulation of the [JNI Invocation API](https://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/invocation.html) so `JNI_OnLoad` can be called properly.
- Emulation of native memory for malloc / memcpy.
- Emulation of syscalls (SVC #0) instruction.
- Hooking through the symbol table.
- All JavaVM, JNIEnv and hooked functions are handled by python.
- Enable VFP support.

## TODO

- Improve file descriptors in `vfs/file_system.py` so they are re-useable.
- Add a way for the VirtualFileSystem to give back dynamic files, such as `/proc/self/status`, `/proc/self/status` but also `/dev/urandom`.
- Library consumers must be able to easily rebuild the needed Java classes for a native library, which are used by the native library through the JNIEnv.
  - Classes
  - Objects
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

### Code sources
- https://github.com/lunixbochs/usercorn
- https://github.com/slick1015/pad_unpacker (SVC 0 instruction)
