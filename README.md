
# iOS App的安全防范

- [1.防止抓包篡改数据](#1)
- [2.防止反编译（防止class-dump、hopper反编）](#2)
- [3.阻止动态调试](#3)
- [4.防止二次打包](#4)
- [5、开发中代码注意点](#5)


## [1.防止抓包篡改数据](id:1)
### 1、判断是否设置了代理
对于抓包，现在的手段基本是设置代理，所以我们可以通过判断是否设置了代理的方式来进行下一步的防范。

代码

```object-c
#在网络请求前插入这个方法，再根据需求做相应的防范
+ (BOOL)getDelegateStatus
{
    NSDictionary *proxySettings = CFBridgingRelease((__bridge CFTypeRef _Nullable)((__bridge NSDictionary *)CFNetworkCopySystemProxySettings()));
    NSArray *proxies = CFBridgingRelease((__bridge CFTypeRef _Nullable)((__bridge NSArray *)CFNetworkCopyProxiesForURL((__bridge CFURLRef)[NSURL URLWithString:@"http://www.google.com"], (__bridge CFDictionaryRef)proxySettings)));
    NSDictionary *settings = [proxies objectAtIndex:0];
    NSLog(@"host=%@", [settings objectForKey:(NSString *)kCFProxyHostNameKey]);
    NSLog(@"port=%@", [settings objectForKey:(NSString *)kCFProxyPortNumberKey]);
    NSLog(@"type=%@", [settings objectForKey:(NSString *)kCFProxyTypeKey]);
    if ([[settings objectForKey:(NSString *)kCFProxyTypeKey] isEqualToString:@"kCFProxyTypeNone"])
    {
        //没有设置代理
        return NO;
        
    } else {
        //设置代理了
        return YES;
    }
}
```
### 2、RSA
非对称加密的效率低，所以很少有企业将所有的接口都用非对称加密。
若是关键接口，我们就使用非对称加密。
方案：先通过非对称加密的接口 获取密钥，然后再在后面的接口通信中用这个密钥进行加密。

## [2.防止反编译（防止class-dump、hopper反编）](id:2)
### 1、越狱检测
一般能拿到自己ipa包都需要有一台越狱的手机

+ 判断设备是否安装了越狱常用工具：
一般安装了越狱工具的设备都会存在以下文件：
/Applications/Cydia.app
/Library/MobileSubstrate/MobileSubstrate.dylib
/bin/bash
/usr/sbin/sshd
/etc/apt

+ 判断设备上是否存在cydia应用
+ 是否有权限读取系统应用列表

没有越狱的设备是没有读取所有应用名称的权限
检测当前程序运行的环境变量 DYLD_INSERT_LIBRARIES
非越狱手机DYLD_INSERT_LIBRARIES获取到的环境变量为NULL。

综上所述，检查设备是否越狱

代码

```object-c
+ (BOOL)isJailbroken {
    // 检查是否存在越狱常用文件
    NSArray *jailFilePaths = @[@"/Applications/Cydia.app",
                               @"/Library/MobileSubstrate/MobileSubstrate.dylib",
                               @"/bin/bash",
                               @"/usr/sbin/sshd",
                               @"/etc/apt"];
    for (NSString *filePath in jailFilePaths) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:filePath]) {
            return YES;
        }
    }

    // 检查是否安装了越狱工具Cydia
    if([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"cydia://package/com.example.package"]]){
        return YES;
    }

    // 检查是否有权限读取系统应用列表
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/User/Applications/"]){
        NSArray *applist = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/User/Applications/"
                                                                               error:nil];
        NSLog(@"applist = %@",applist);
        return YES;
    }

    //  检测当前程序运行的环境变量
    char *env = getenv("DYLD_INSERT_LIBRARIES");
    if (env != NULL) {
        return YES;
    }

    return NO;
}
```
### 2、代码混淆
轻量级代码混淆，关键性的代码，方法，以及有语义变量和常亮等做混淆处理，增加破解难度。
使用宏定义的方式混淆。

## [3.阻止动态调试](id:3)
GDB、LLDB是Xcode内置的动态调试工具。使用GDB、LLDB可以动态的调试你的应用程序（通过下断点、打印等方式，查看参数、返回值、函数调用流程等）。

为了阻止hackers使用调试器 GDB、LLDB来攻击你的App，你可以在main.m文件中插入以下代码：
```object-c
#import <dlfcn.h>
#import <sys/types.h>

typedef int (*ptrace_ptr_t)(int _request, pid_t _pid, caddr_t _addr, int _data);
#if !defined(PT_DENY_ATTACH)
#define PT_DENY_ATTACH 31
#endif  // !defined(PT_DENY_ATTACH)

void disable_gdb() {
    void* handle = dlopen(0, RTLD_GLOBAL | RTLD_NOW);
    ptrace_ptr_t ptrace_ptr = dlsym(handle, "ptrace");
    ptrace_ptr(PT_DENY_ATTACH, 0, 0, 0);
    dlclose(handle);
}

int main(int argc, char *argv[]) {
    // Don't interfere with Xcode debugging sessions.
    #if !(DEBUG) 
        disable_gdb();
    #endif

    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil,
            NSStringFromClass([MyAppDelegate class]));
    }
}
```
## [4.防止二次打包](id:4)
iOS 和 OS X 的应用和框架包含了二进制代码和所需要的资源文件（如：图片、不同的语言文件、XIB/Storyboard文件、profile文件等），在通过开发者私钥签名程序包时，对于可执行文件( Mach-O )，会将签名直接写入到该文件中，而对于其他的资源文件，会统一写到 _CodeSignature 文件下的 CodeResources 文件中，它仅仅是一个 plist 格式文件。

这个列表文件中不光包含了文件和它们的签名的列表，还包含了一系列规则，这些规则决定了哪些资源文件应当被设置签名。伴随 OS X 10.10 DP 5 和 10.9.5 版本的发布，苹果改变了代码签名的格式，也改变了有关资源的规则。如果你使用10.9.5或者更高版本的 codesign 工具，在 CodeResources 文件中会有4个不同区域，其中的 rules 和 files 是为老版本准备的，而 files2 和 rules2 是为新的第二版的代码签名准备的。最主要的区别是在新版本中你无法再将某些资源文件排除在代码签名之外，在过去你是可以的，只要在被设置签名的程序包中添加一个名为 ResourceRules.plist 的文件，这个文件会规定哪些资源文件在检查代码签名是否完好时应该被忽略。但是在新版本的代码签名中，这种做法不再有效。所有的代码文件和资源文件都必须 设置签名，不再可以有例外。在新版本的代码签名规定中，一个程序包中的可执行程序包，例如扩展 (extension)，是一个独立的需要设置签名的个体，在检查签名是否完整时应当被单独对待。

有些hacker可能会通过篡改你的程序包（包括资源文件和二进制代码）加入一些广告或则修改你程序的逻辑，然后重新签名打包，由于第三方hacker获取不到签名证书的私钥，因此会替换掉程序包中签名相关的文件embedded.mobileprovision，我们可以直接检查此文件是否被修改，来判断是否被二次打包，如果程序被篡改，则退出程序。
检测embedded.mobileprovision是否被篡改：
```object-c
// 校验值，可通过上一次打包获取
#define PROVISION_HASH @"w2vnN9zRdwo0Z0Q4amDuwM2DKhc="
static NSDictionary * rootDic=nil;

void checkSignatureMsg()
{
    NSString *newPath=[[NSBundle mainBundle]resourcePath];

    if (!rootDic) {

        rootDic = [[NSDictionary alloc] initWithContentsOfFile:[newPath stringByAppendingString:@"/_CodeSignature/CodeResources"]];
    }

    NSDictionary*fileDic = [rootDic objectForKey:@"files2"];

    NSDictionary *infoDic = [fileDic objectForKey:@"embedded.mobileprovision"];
    NSData *tempData = [infoDic objectForKey:@"hash"];
    NSString *hashStr = [tempData base64EncodedStringWithOptions:0];
    if (![PROVISION_HASH isEqualToString:hashStr]) {
        abort();//退出应用
    }
}
```



## [5、开发中代码注意点](id:5)
1. 首先，我们可以通过iTunes 下载 AppStore的ipa文件(苹果 把开发者上传的ipa包 进行了加壳再放到AppStore中)，所以我们从AppStore下载的ipa都是加壳的，所以不能直接用来反编译。得到ipa文件 可以分析APP 里包含的一些资源，如：图片、plist文件、静态wap页、.bundle 等。所以不要 在plist文件、项目中的静态文件中 存储关键的信息，如果要保存，记得对称加密（这样可以增加破解的难度）。如果是越狱的手机，从 手机上的PP助手下载的ipa包 都是 脱壳之后的，可以直接用来反编译。

2. 我们可以用软件 查看 APP的沙盒，查看里面存储的 文件:sqlite、plist（NSUserdefault会存到Library下的Preferences中 的 plist文件中）、图片等，NSUserdefault 中不要保存关键信息，如果要保存，还是加密吧。sqlite也是这样子的。

3. rlease环境下 NSLog 不要打印日志 否则iOS系统日志里都可以查看到，在.pch文件中加下面的几行代码就可以解决。很早大家都这么做了。现在很多APP的部分页面开始使用 Swift，在Swift 文件中是允许用 NSLog 的语法来打印，但是 不要这么做，因为 这样 就会导致这段代码在 release环境 中也可以正常输出。通过 PP助手、iTools，可以直接 查看 iOS的系统日志。也可以直接 通过Xcode-Window-Devices - 点最下面的向上的小箭头，来看日志。 所以Swift中打印 还是用 print吧。AFNetworking 的 allowInvalidCertificates 属性 要设置成 false，validatesDomainName属性 设置成true。否则 HTTPS通信就可以被解密。这块涉及到AFnetworking 去年的通信漏洞 就不详述了。但是一般开发的 测试环境 的HTTPS 不是CA颁发的，而是自签名证书，访问的也不是域名，而是IP。所以可以在测试环境 忽略证书和域名。
