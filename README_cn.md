# AndroidNativeEmu
AndroidNativeEmu 让你能够跨平台模拟Android Native库函数，比如JNI_OnLoad、Java_XXX_XX等函数。
fork from  : https://github.com/AeonLucid/AndroidNativeEmu

## 特性
- 模拟 [JNI Invocation API](https://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/invocation.html) so `JNI_OnLoad` can be called properly.
- 模拟 memory、malloc、memcpy
- 支持拦截系统调用(SVC #0)
- 通过符号Hook
- 所有 JavaVM, JNIEnv 和 hooked functions 都可以用python来处理
- 支持 VFP
- 支持文件系统（也就是说你可以模拟maps、status等文件）

## 本人瞎改
小弟不才，修改了一些代码，使其能够运行libcms的leviathan.
- 添加 自动调用InitArray初始化代码，基于重定位表解析。
- 添加 修改对象引用的值
- 实现 getcpu() 系统调用
- 实现  setByteArrayRegion
- JNI中动态注册Native函数失败将不再报错(libcms中注册了大量不需要的函数)

## 使用方法
运行环境：python 3.7 必须！
1. Clone the repository
2. Run `pip install -r requirements.txt`
3. Run `python example.py`

Windows上可以跑，自行尝试。


## 依赖库
- [Unicorn CPU emulator framework](https://github.com/unicorn-engine/unicorn)
- [Keystone assembler framework](https://github.com/keystone-engine/keystone)


## 初始化模拟器
```python
# Initialize emulator
emulator = Emulator(
    vfp_inst_set=True,
    vfs_root=posixpath.join(posixpath.dirname(__file__), "vfs")
)
```

## 如何定义Java类呢？

### Jni 中会调用到的类
注意看看各项参数的定义
```python
class java_lang_System(metaclass=JavaClassDef, jvm_name='java/lang/System'):
        def __init__(self):
            pass

        @java_method_def(name='getProperty', args_list=["jstring"] ,signature='(Ljava/lang/String;)Ljava/lang/String;', native=False)
        def getProperty(self, *args, **kwargs):
            print (args[0].value)
            return "2.1.0"
```
### 我们的目标类
```python
class XGorgen(metaclass=JavaClassDef, jvm_name='com/ss/sys/ces/a'):
    def __init__(self):
        pass

    @java_method_def(name='leviathan', signature='(I[B)[B', native=True)
    def leviathan(self, mu):
        pass

    def test(self):
        pass
```

### 模拟stacktrace的类
```python
class java_lang_Thread(metaclass=JavaClassDef, jvm_name='java/lang/Thread'):
    def __init__(self):
        pass

    @java_method_def(name="currentThread", signature='()Ljava/lang/Thread;', native=False)
    def currentThread(self, *args, **kwargs):
        return java_lang_Thread()

    @java_method_def(name="getStackTrace", signature='()[Ljava/lang/StackTraceElement;', native=False)
    def getStackTrace(self, *args, **kwargs):
        return  [java_lang_StackTraceElement("dalvik.system.VMStack"),
                 java_lang_StackTraceElement("java.lang.Thread"),
                 java_lang_StackTraceElement("com.ss.sys.ces.a"),
                 java_lang_StackTraceElement("com.yf.douyintool.MainActivity"),
                 java_lang_StackTraceElement("java.lang.reflect.Method"),
                 java_lang_StackTraceElement("java.lang.reflect.Method"),
                 java_lang_StackTraceElement("android.support.v7.app.AppCompatViewInflater$DeclaredOnClickListener"),
                 java_lang_StackTraceElement("android.view.View"),
                 java_lang_StackTraceElement("android.os.Handler"),
                 java_lang_StackTraceElement("android.os.Handler"),
                 java_lang_StackTraceElement("android.os.Looper"),
                 java_lang_StackTraceElement("android.app.ActivityThread"),
                 java_lang_StackTraceElement("java.lang.reflect.Method"),
                 java_lang_StackTraceElement("java.lang.reflect.Method"),
                 java_lang_StackTraceElement("com.android.internal.os.ZygoteInit$MethodAndArgsCaller"),
                 java_lang_StackTraceElement("com.android.internal.os.ZygoteInit"),
                 java_lang_StackTraceElement("dalvik.system.NativeStart")
                 ]
```
更多的类请见example

## 注册类
```python
emulator.java_classloader.add_class(XGorgen)
emulator.java_classloader.add_class(java_lang_System)
emulator.java_classloader.add_class(java_lang_Thread)
emulator.java_classloader.add_class(java_lang_StackTraceElement)
```

## 调用JNI_OnLoad
init array 已经自动调用了，SO如果有加密也没关系。
```python
# 添加依赖库
emulator.load_library("samples/example_binaries/libdl.so")
emulator.load_library("samples/example_binaries/libc.so")
emulator.load_library("samples/example_binaries/libstdc++.so")
emulator.load_library("samples/example_binaries/libm.so")

lib_module = emulator.load_library("samples/example_binaries/libcms.so")

#   JNI_OnLoad will call 'RegisterNatives'.
emulator.call_symbol(lib_module, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0x00)

```

## 调用native 方法
```python
x = XGorgen()
data = 'acde74a94e6b493a3399fac83c7c08b35D58B21D9582AF77647FC9902E36AE70f9c001e9334e6e94916682224fbe4e5f00000000000000000000000000000000'
data = bytearray(bytes.fromhex(data))
result = x.leviathan(emulator, 1562848170, data)
```