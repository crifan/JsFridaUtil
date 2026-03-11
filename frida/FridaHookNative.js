/*
	File: FridaHookNative.js
	Function: crifan's Frida hook common native related functions
	Author: Crifan Li
	Latest: https://github.com/crifan/JsFridaUtil/blob/main/frida/FridaHookNative.js
	Updated: 20260223
*/

// Frida hook common native functions
class FridaHookNative {
  // static dladdr = null
  // static free = null

  constructor() {
    console.log("FridaHookNative constructor")
  }

  static {
    console.log("FridaHookNative static")
    // FridaHookNative.dladdr = FridaHookNative.genNativeFunc_dladdr()
    // console.log("FridaHookNative.dladdr=" + FridaHookNative.dladdr)

    // FridaHookNative.free = FridaHookNative.genNativeFunc_free()
    // console.log("FridaHookNative.free=" + FridaHookNative.free)
  }

  static hookNative_commonFunc(funcName_native, funcParaList, libFullPath=null, funcName_log=null, isPrintStack=true){
    console.log("hookNative_commonFunc: funcName_native=" + funcName_native + ", funcParaList=" + funcParaList + ", libFullPath=" + libFullPath + ", funcName_log=" + funcName_log)

    var foundNativeFunc = Module.findExportByName(libFullPath, funcName_native)
    console.log("foundNativeFunc=" + foundNativeFunc)
    if (null != foundNativeFunc) {
      Interceptor.attach(foundNativeFunc, {
        onEnter: function (args) {
          // var curFuncName = ""
          // if (funcName_log){
          //   curFuncName = funcName_log
          // } else {
          //   curFuncName = funcName_native
          // }
          // console.log("curFuncName=" + curFuncName)
          // JsUtil.logStr(curFuncName)

          if (isPrintStack){
            // console.log("funcName_log=" + funcName_log)
            FridaUtil.printFunctionCallStack_addr(this.context, funcName_log)
          } else {
            console.log(funcName_log + " called")
          }

          // var logStr = funcName_log + ": [+] libFullPath=" + libFullPath
          // var logStr = `${funcName_log}: [+] libFullPath=${libFullPath}`
          var logStr = `${funcName_log}: [+]`

          // for(var curParaName in funcParaList){
          for (let paraIdx = 0; paraIdx < funcParaList.length; paraIdx++) {
            var curParaValue = args[paraIdx]
            // console.log("curParaValue=" + curParaValue)

            let curParaCfg = funcParaList[paraIdx]
            // console.log("curParaCfg=" + curParaCfg)
            var curParaCfgType = typeof curParaCfg
            // console.log("curParaCfgType=" + curParaCfgType)

            var curParaLog = ""

            var curParaName = null
            if (curParaCfgType === "string"){
              curParaName = curParaCfg

              curParaLog = `${curParaName}=${curParaValue}`
            } else {
              curParaLog = `${curParaName}=${curParaValue}`

              // is 'object' == dict = json
              var curParaDict = curParaCfg
              curParaName = curParaDict["paraName"]
              // console.log("curParaName=" + curParaName)
              var curParaType = curParaDict["paraType"]
              // console.log("curParaType=" + curParaType)

              // if (curParaType == "string"){
              if (curParaType == FridaUtil.StringType.CString){
                // curParaValue = FridaUtil.ptrToUtf8Str(curParaValue)
                var curParaValuePtr = curParaValue
                curParaValue = FridaUtil.ptrToCStr(curParaValuePtr)
                // console.log("curParaValue=" + curParaValue)

                curParaLog = `${curParaName}=${curParaValuePtr}=${curParaValue}`
              // } else if (curParaType == "stdstring"){
              } else if (curParaType == FridaUtil.StringType.StdString){
                var curParaValuePtr = curParaValue
                curParaValue = FridaUtil.ptrToStdStr(curParaValuePtr)
                // console.log("curParaValue=" + curParaValue)

                curParaLog = `${curParaName}=${curParaValuePtr}=${curParaValue}`
              }
            }

            // console.log("[" + paraIdx + "] " + curParaName + "=" + curParaValue)

            if (paraIdx == 0) {
              logStr = `${logStr} ${curParaLog}`
            } else {
              logStr = `${logStr}, ${curParaLog}`
            }
          }
      
          console.log(logStr)
        },
        onLeave: function (retval) {
          console.log("\t " + funcName_log + " retval=" + retval)
        }
      })
    } else {
      console.error("Failed to find function " + funcName_log + " in lib " + libFullPath)
    }
  
  }

  static genNativeFunc_dladdr(){
    var newNativeFunc_dladdr = null
    /*
      int dladdr(const void *, Dl_info *);

      typedef struct dl_info {
              const char      *dli_fname;     // Pathname of shared object
              void            *dli_fbase;     // Base address of shared object
              const char      *dli_sname;     // Name of nearest symbol
              void            *dli_saddr;     // Address of nearest symbol
      } Dl_info;
    */
    var origNativeFunc_dladdr = Module.findExportByName(null, 'dladdr')
    // console.log("origNativeFunc_dladdr=" + origNativeFunc_dladdr)
    if (null != origNativeFunc_dladdr) {
      newNativeFunc_dladdr = new NativeFunction(
        origNativeFunc_dladdr,
        'int',
        ['pointer','pointer']
      )
    }
    return newNativeFunc_dladdr
  }

  static genNativeFunc_free(){
    // void free(void *ptr)
    var newNativeFunc_free = null
    var origNativeFunc_free = Module.findExportByName(null, "free")
    // console.log("origNativeFunc_free=" + origNativeFunc_free)
    if (null != origNativeFunc_free) {
      newNativeFunc_free = new NativeFunction(
        origNativeFunc_free,
        'void',
        ['pointer']
      )
    }
    return newNativeFunc_free
  }

  static hookNative_dlopen(){
    // void *dlopen(const char *filename, int flags);
    Interceptor.attach(Module.findExportByName(null, "dlopen"), {
      onEnter: function (args) {
        var filename = FridaUtil.ptrToCStr(args[0])
        var flags = args[1]
        console.log("dlopen: [+] filename=" + filename + ", flags=" + flags)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_open(){
    // int open(const char *pathname, int flags, mode_t mode);
    Interceptor.attach(Module.findExportByName(null, "open"), {
      onEnter: function (args) {
        var path = FridaUtil.ptrToCStr(args[0])
        var oflags = args[1]
        // console.log("open: [+] path=" + path + ", oflags=" + oflags)
        this._path = path
        this._oflags = oflags
      },
      onLeave: function (retFd) {
        // console.log("\t open retFd=" + retFd)
        console.log("open: [+] path=" + this._path + ", oflags=" + this._oflags + " -> retFd=" + retFd)
      }
    })
  }

  static hookNative_access(){
    // int access(const char *pathname, int mode);
    Interceptor.attach(Module.findExportByName(null, "access"), {
      onEnter: function (args) {
        var pathname = FridaUtil.ptrToCStr(args[0])
        var mode = args[1]
        console.log("access: [+] pathname=" + pathname + ", mode=" + mode)
        this._pathname = pathname
        this._mode = mode
        FridaUtil.printFunctionCallStack_addr(this.context, "hookNative_access")
      },
      onLeave: function (retVal) {
        console.log("access: [+] pathname=" + this._pathname + ", mode=" + this._mode + " -> retVal=" + retVal)
      }
    })
  }

  static hookNative_faccessat(){
    // int faccessat(int dirfd, const char *pathname, int mode, int flags);
    Interceptor.attach(Module.findExportByName(null, "faccessat"), {
      onEnter: function (args) {
        var dirfd = args[0]
        var pathname = FridaUtil.ptrToCStr(args[1])
        var mode = args[2]
        var flags = args[3]
        console.log("faccessat: [+] dirfd=" + dirfd + ", pathname=" + pathname + ", mode=" + mode + ", flags=" + flags)
        this._dirfd = dirfd
        this._pathname = pathname
        this._mode = mode
        this._flags = flags
        FridaUtil.printFunctionCallStack_addr(this.context, "hookNative_faccessat")
      },
      onLeave: function (retVal) {
        console.log("faccessat: [+] dirfd=" + this._dirfd + ", pathname=" + this._pathname + ", mode=" + this._mode + ", flags=" + this._flags + " -> retVal=" + retVal)
      }
    })
  }

  static hookNative_read(){
    // ssize_t read(int fd, void buf[.count], size_t count)
    Interceptor.attach(Module.findExportByName(null, "read"), {
      onEnter: function (args) {
        var fd = args[0]
        var buf = args[1]
        var count = args[2]
        console.log("read: fd=" + fd + ", buf=" + buf + ", count=" + count)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_write(){
    // ssize_t write(int fildes, const void *buf, size_t nbyte)
    Interceptor.attach(Module.findExportByName(null, "write"), {
      onEnter: function (args) {
        var fildes = args[0]
        var buf = args[1]
        var nbyte = args[2]
        console.log("write: fildes=" + fildes + ", buf=" + buf + ", nbyte=" + nbyte)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_close(){
    // int close(int fd)
    Interceptor.attach(Module.findExportByName(null, "close"), {
      onEnter: function (args) {
        var fd = args[0]
        console.log("close: fd=" + fd)
      },
      onLeave: function (retval) {
      }
    })
  }

  static hookNative_remove(){
    // int remove(const char *path)
    Interceptor.attach(Module.findExportByName(null, "remove"), {
      onEnter: function (args) {
        var path = FridaUtil.ptrToCStr(args[0])
        console.log("remove: path=" + path)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_fopen(){
    // FILE *fopen(const char *filename, const char *mode);
    // FILE *fopen(const char *restrict pathname, const char *restrict mode);
  
    Interceptor.attach(Module.findExportByName(null, "fopen"), {
      onEnter: function (args) {
        var pathname = FridaUtil.ptrToCStr(args[0])
        var mode = FridaUtil.ptrToCStr(args[1])
        // console.log("fopen: pathname=" + pathname + ", mode=" + mode)
        this._pathname = pathname
        this._mode = mode

        FridaUtil.printFunctionCallStack_addr(this.context, "hookNative_fopen")
      },
      onLeave: function (retFile) {
        // console.log("fopen: retFile=" + retFile)
        console.log("fopen: pathname=" + this._pathname + ", mode=" + this._mode + " -> retFile=" + retFile)
      }
    })
  
    // var FuncPtr_fopen = Module.findExportByName(null, "fopen")
    // console.log("FuncPtr_fopen=" + FuncPtr_fopen)
    // if (null != FuncPtr_fopen) {
    //   var func_fopen = new NativeFunction(FuncPtr_fopen, 'pointer', ['pointer', 'pointer'])
    //   console.log("func_fopen=" + func_fopen)
    //   Interceptor.replace(func_fopen,
    //     new NativeCallback(function (filename, mode) {
    //       // console.log("filename=" + filename + ", mode=" + mode)
    //       var filenameStr = filename.readUtf8String()
    //       // console.log("filenameStr=" + filenameStr)
    //       var modeStr = mode.readUtf8String()
    //       // console.log("modeStr=" + modeStr)
    //       var retFile = func_fopen(filename, mode)
    //       // console.log("retFile=" + retFile)
    //       console.log("filename=" + filename + "=" + filenameStr + ", mode=" + mode + "=" + modeStr + "-> retFile" + retFile)
    //       return retFile
    //     },
    //     'pointer',
    //     ['pointer', 'pointer'])
    //   )
    // }
  
  }

  static hookNative_flock(){
    // int flock(int fd, int operation);
    Interceptor.attach(Module.findExportByName(null, "flock"), {
      onEnter: function (args) {
        var fd = args[0]
        var operation = args[1]
        console.log("flock: fd=" + fd + ", operation=" + operation)
      },
      onLeave: function (retval) {
      }
    });
  }

  static hookNative_strcpy(){
    const KnownStrLis = [
      "",
      "/",
      "zh",
      "CN",
      "zh_CN",
      "Hans",
      "zh_Hans",
      "zh_Hans_CN",
      "en",
      "US",
      "en_US",
    ]
  
    // char *strcpy(char *restrict dst, const char *restrict src);
    Interceptor.attach(Module.findExportByName(null, "strcpy"), {
      onEnter: function (args) {
        var dst = FridaUtil.ptrToCStr(args[0])
        var src = FridaUtil.ptrToCStr(args[1])
        if (!KnownStrLis.includes(src)) {
          console.log("strcpy: dst=" + dst + ", src=" + src)
        }
      },
      onLeave: function (args) {
      }
    })
  }
  
  static hookNative_strlen(){
    // size_t strlen(const char *str)
    Interceptor.attach(Module.findExportByName(null, "strlen"), {
      onEnter: function (args) {
        var str = FridaUtil.ptrToCStr(args[0])
        console.log("strlen: str=" + str)
      },
      onLeave: function (args) {
      }
    })

    // var FuncPtr_strlen = Module.findExportByName(null, "strlen")
    // console.log("FuncPtr_strlen=" + FuncPtr_strlen)
    // if (null != FuncPtr_strlen) {
    //   var func_strlen = new NativeFunction(FuncPtr_strlen, 'int', ['pointer'])
    //   console.log("func_strlen=" + func_strlen)
    //   Interceptor.replace(func_strlen,
    //     new NativeCallback(function (cStr) {
    //       // console.log("cStr=" + cStr)
    //       var jsStr = cStr.readUtf8String()
    //       console.log("jsStr=" + jsStr)
    //       var retLen = func_strlen(cStr)
    //       // console.log("retLen=" + retLen)
    //       return retLen
    //     },
    //     'int',
    //     ['pointer'])
    //   );
    // }

  }
  
  static hookNative_strncpy(){
    // char *strncpy(char *dest, const char *src, size_t count);
    Interceptor.attach(Module.findExportByName(null, "strncpy"), {
      onEnter: function (args) {
        var dest = FridaUtil.ptrToCStr(args[0])
        var src = FridaUtil.ptrToCStr(args[1])
        var count = args[2]
        console.log("strncpy: dest=" + dest + ", src=" + src + ", count=" + count)
      },
      onLeave: function (args) {
      }
    })
  }
  
  static hookNative_strcat(){
    // char *strcat(char *restrict dst, const char *restrict src);
    Interceptor.attach(Module.findExportByName(null, "strcat"), {
      onEnter: function (args) {
        var dst = FridaUtil.ptrToCStr(args[0])
        var src = FridaUtil.ptrToCStr(args[1])
        console.log("strcat: dst=" + dst + ", src=" + src)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_execlp(){
    // int execlp(const char *path, const char *arg0, ..., NULL);
    Interceptor.attach(Module.findExportByName(null, "execlp"), {
      onEnter: function (args) {
        var path = FridaUtil.ptrToCStr(args[0])
        var arg0 = FridaUtil.ptrToCStr(args[1])
        var arg1 = FridaUtil.ptrToCStr(args[2])
        console.log("execlp: path=" + path + ", arg0=" + arg0 + ", arg1=" + arg1)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_execv(){
    // int execv(const char *pathname, char *const argv[]);
    Interceptor.attach(Module.findExportByName(null, "execv"), {
      onEnter: function (args) {
        var pathname = FridaUtil.ptrToCStr(args[0])
        var argv = args[1]
        console.log("execv: pathname=" + pathname + ", argv=" + argv)
      },
      onLeave: function (args) {
      }
    })
  }

 static hookNative_syscall(isAntiSyscall=false) {
   Interceptor.attach(Module.findExportByName("libc.so", "syscall"), {
     onEnter: function(args) {
       var nr = args[0].toInt32()
       // arm64: __NR_kill=129, __NR_tgkill=131, __NR_exit_group=94, __NR_exit=93, __NR_ptrace=117, __NR_openat=56
       if (nr == 129 || nr == 131) {
         var targetPid = args[1].toInt32()
         var sig = args[2].toInt32()
         console.log("[syscall] kill/tgkill(nr=" + nr + "): pid=" + targetPid + ", sig=" + sig)
         FridaUtil.printFunctionCallStack_addr(this.context, "syscall kill/tgkill")
         if (isAntiSyscall) {
           var isSelfKill = (targetPid == Process.id)
           if (isSelfKill && (sig == 9 || sig == 6 || sig == 11 || sig == 5)) {
             console.log("[anti-syscall] blocked syscall kill/tgkill(pid=" + targetPid + ", sig=" + sig + ")")
             args[2] = ptr(0) // change signal to 0
           }
         }
       } else if (nr == 93 || nr == 94) {
         console.log("[syscall] exit/exit_group(nr=" + nr + "): status=" + args[1])
         FridaUtil.printFunctionCallStack_addr(this.context, "syscall exit/exit_group")
       } else if (nr == 117) {
         // __NR_ptrace = 117 on arm64
         var request = args[1].toInt32()
         console.log("[syscall] ptrace(nr=" + nr + "): request=" + request + ", pid=" + args[2])
         FridaUtil.printFunctionCallStack_addr(this.context, "syscall ptrace")
       } else if (nr == 56) {
         // __NR_openat = 56 on arm64
         var pathname = FridaUtil.ptrToCStr(args[2])
         if (pathname && FridaHookNative.isAntiDebugRelatedPath(pathname)) {
           console.log("[syscall] openat(nr=" + nr + "): pathname=" + pathname)
           FridaUtil.printFunctionCallStack_addr(this.context, "syscall openat [anti-debug]")
         }
       }
     }
   })
 }

  static hookNative_pthread_create(){
    // int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void*), void *arg);
    Interceptor.attach(Module.findExportByName(null, "pthread_create"), {
      onEnter: function (args) {
        var thread = args[0]
        var attr = args[1]
        var start_routine = args[2]
        var arg = args[3]
        console.log("pthread_create: thread=" + thread + ", attr=" + attr + ", start_routine=" + start_routine + ", arg=" + arg)

        FridaUtil.printFunctionCallStack_addr(this.context, "hookNative_pthread_create")
      },
      onLeave: function (retNewPid) {
        console.log("\t pthread_create retNewPid= " + retNewPid)
      }
    })
  }

  static hookNative_clone(){
    // int clone(int (*fn)(void *_Nullable), void *stack, int flags, void *_Nullable arg, ...  /* pid_t *_Nullable parent_tid, void *_Nullable tls, pid_t *_Nullable child_tid */ );
    Interceptor.attach(Module.findExportByName(null, "clone"), {
      onEnter: function (args) {
        var fn = args[0]
        var stack = args[1]
        var flags = args[2]
        var arg = args[3]
        console.log("clone: fn=" + fn + ", stack=" + stack + ", flags=" + flags + ", arg=" + arg)
      },
      onLeave: function (retval) {
      }
    })
  }

  static hookNative_fork(){
    // pid_t fork(void);
    Interceptor.attach(Module.findExportByName(null, "fork"), {
      onEnter: function (args) {
        console.log("fork called")
      },
      onLeave: function (retval) {
        console.log("\t fork retval= " + retval)
      }
    })
  }

  static hookNative_posix_spawn(){
    // int posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]);
    Interceptor.attach(Module.findExportByName(null, "posix_spawn"), {
      onEnter: function (args) {
        var pid = args[0]
        var path = FridaUtil.ptrToCStr(args[1])
        var file_actions = args[2]
        var attrp = args[3]
        var argv = args[4]
        var envp = args[5]
        console.log("posix_spawn: pid=" + pid + ", path=" + path + ", file_actions=" + file_actions + ", attrp=" + attrp + ", argv=" + argv + ", envp=" + envp)
      },
      onLeave: function (retval) {
      }
    })
  }

  static hookNative_posix_spawnp(){
    // int posix_spawnp(pid_t *pid, const char *file, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]);
    Interceptor.attach(Module.findExportByName(null, "posix_spawnp"), {
      onEnter: function (args) {
        var pid = args[0]
        var file = FridaUtil.ptrToCStr(args[1])
        var file_actions = args[2]
        var attrp = args[3]
        var argv = args[4]
        var envp = args[5]
        console.log("posix_spawnp: pid=" + pid + ", file=" + file + ", file_actions=" + file_actions + ", attrp=" + attrp + ", argv=" + argv + ", envp=" + envp)
      },
      onLeave: function (retval) {
      }
    })
  }

  static hookNative_sigaction(){
    // int sigaction(int signum, const struct sigaction *_Nullable restrict act, struct sigaction *_Nullable restrict oldact);
    Interceptor.attach(Module.findExportByName(null, "sigaction"), {
      onEnter: function (args) {
        var signum = args[0]
        var actP = args[1]
        var oldactP = args[2]
        console.log("sigaction: signum=" + signum + ", actP=" + actP + ", oldactP=" + oldactP)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookAndIgnoreSIGSEGV() {
    var SIG_IGN = ptr(1);
    var SIGSEGV = 11;
    var SIGBUS = 7;
    var SIGABRT = 6;
    
    // 1. 先自己注册一个忽略处理器
    var sigaction = new NativeFunction(
      Module.findExportByName("libc.so", "sigaction"),
      'int', ['int', 'pointer', 'pointer']
    );
    
    var act = Memory.alloc(256);
    act.writePointer(SIG_IGN); // sa_handler = SIG_IGN
    
    sigaction(SIGSEGV, act, ptr(0));
    sigaction(SIGBUS, act, ptr(0));
    console.log("[init] Set SIGSEGV/SIGBUS to SIG_IGN");
    
    // 2. 拦截后续的 sigaction 调用，阻止 app 重新注册
    Interceptor.attach(Module.findExportByName("libc.so", "sigaction"), {
      onEnter: function(args) {
        var signum = args[0].toInt32();
        if (signum == SIGSEGV || signum == SIGBUS) {
          console.log("[sigaction] blocked attempt to set handler for sig=" + signum);
          // 把 act 指针改成 null，让调用无效
          args[1] = ptr(0);
        }
      }
    });
    
    // 3. 同时拦截 signal() 函数
    Interceptor.attach(Module.findExportByName("libc.so", "signal"), {
      onEnter: function(args) {
        var signum = args[0].toInt32();
        if (signum == SIGSEGV || signum == SIGBUS) {
          console.log("[signal] blocked attempt to set handler for sig=" + signum);
          args[1] = SIG_IGN;
        }
      }
    });
  }
  
  static hookNative_exit(isAntiExit=false){
    // void exit(int status);
    Interceptor.attach(Module.findExportByName("libc.so", "exit"), {
      onEnter: function (args) {
        var status = args[0].toInt32()
        console.log("[anti-debug] exit: status=" + status)
        // 始终打印调用栈，定位谁在触发exit
        FridaUtil.printFunctionCallStack_addr(this.context, "exit")
        if (isAntiExit) {
          console.log("[anti-exit] blocked exit(" + status + ")")
          args[0] = ptr(0)
        }
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_kill(isAntiKill=false){
    // int kill(pid_t pid, int sig);
    Interceptor.attach(Module.findExportByName("libc.so", "kill"), {
      onEnter: function (args) {
        var pid = args[0].toInt32()
        var sig = args[1].toInt32()
        var isSelfKill = (pid == Process.id)
        console.log("[anti-debug] kill: pid=" + pid + ", sig=" + sig + ", isSelfKill=" + isSelfKill)
        // 始终打印调用栈，定位谁在触发kill
        FridaUtil.printFunctionCallStack_addr(this.context, "kill")
        if (isAntiKill) {
          if (isSelfKill && (sig == 9 || sig == 6 || sig == 11 || sig == 5)) {
            // SIGKILL=9, SIGABRT=6, SIGSEGV=11, SIGTRAP=5
            console.log("[anti-kill] blocked kill(" + pid + ", " + sig + ")")
            args[1] = ptr(0) // 改为信号0（无效信号，不会杀死进程）
          }
        }
      },
      onLeave: function (retval) {
        console.log("\t kill retval=" + retval)
      }
    })
  }

  static hookNative_killpg(){
    // int killpg(int pgrp, int sig)
    Interceptor.attach(Module.findExportByName(null, "killpg"), {
      onEnter: function (args) {
        var pgrp = args[0]
        var sig = args[1]
        console.log("killpg: pgrp=" + pgrp + ", sig=" + sig)
      },
      onLeave: function (args) {
      }
    })
  }

  /*-------------------- Anti-Debug: Process Kill Detection --------------------*/

  static hookNative__exit(isAntiExit=false){
    // void _exit(int status);
    Interceptor.attach(Module.findExportByName("libc.so", "_exit"), {
      onEnter: function (args) {
        var status = args[0].toInt32()
        console.log("[anti-debug] _exit: status=" + status)
        FridaUtil.printFunctionCallStack_addr(this.context, "_exit")
        if (isAntiExit) {
          console.log("[anti-exit] blocked _exit(" + status + ")")
          args[0] = ptr(0)
        }
      }
    })
  }

  static hookNative_abort(isAntiAbort=false){
    // void abort(void);
    var abortAddr = Module.findExportByName("libc.so", "abort")
    if (isAntiAbort) {
      // 用Interceptor.replace彻底替换abort为空函数，阻止进程终止
      Interceptor.replace(abortAddr, new NativeCallback(function() {
        console.log("[anti-abort] ★ abort() 已拦截并阻止 ★")
      }, 'void', []))
    } else {
      Interceptor.attach(abortAddr, {
        onEnter: function (args) {
          console.log("[anti-debug] abort called")
          FridaUtil.printFunctionCallStack_addr(this.context, "abort")
        }
      })
    }
  }

  static hookNative_raise(isAntiRaise=false){
    // int raise(int sig);
    Interceptor.attach(Module.findExportByName("libc.so", "raise"), {
      onEnter: function (args) {
        var sig = args[0].toInt32()
        console.log("[anti-debug] raise: sig=" + sig)
        FridaUtil.printFunctionCallStack_addr(this.context, "raise")
        if (isAntiRaise) {
          if (sig == 6 || sig == 9 || sig == 11) {
            // SIGABRT=6, SIGKILL=9, SIGSEGV=11
            console.log("[anti-raise] blocked raise(" + sig + ")")
            args[0] = ptr(0) // change to signal 0 (no-op)
          }
        }
      },
      onLeave: function (retval) {
        console.log("\t raise retval=" + retval)
      }
    })
  }

  /*-------------------- Anti-Debug: Detection Function Hooks --------------------*/

  static hookNative_ptrace(isAntiPtrace=false){
    // long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
    var ptraceAddr = Module.findExportByName("libc.so", "ptrace")
    if (null == ptraceAddr) {
      console.warn("[anti-debug] ptrace not found in libc.so")
      return
    }
    Interceptor.attach(ptraceAddr, {
      onEnter: function (args) {
        var request = args[0].toInt32()
        var pid = args[1].toInt32()
        var addr = args[2]
        var data = args[3]
        console.log("[anti-debug] ptrace: request=" + request + ", pid=" + pid + ", addr=" + addr + ", data=" + data)
        FridaUtil.printFunctionCallStack_addr(this.context, "ptrace")
        this._request = request
      },
      onLeave: function (retval) {
        console.log("\t ptrace retval=" + retval)
        if (isAntiPtrace) {
          // PTRACE_TRACEME = 0
          if (this._request == 0) {
            console.log("[anti-ptrace] bypassed ptrace(PTRACE_TRACEME), return 0")
            retval.replace(ptr(0))
          }
        }
      }
    })
  }

  static hookNative_inotify_init(){
    // int inotify_init(void);
    var inotifyInitAddr = Module.findExportByName("libc.so", "inotify_init")
    if (null == inotifyInitAddr) {
      console.warn("[anti-debug] inotify_init not found")
      return
    }
    Interceptor.attach(inotifyInitAddr, {
      onEnter: function (args) {
        console.log("[anti-debug] inotify_init called")
        FridaUtil.printFunctionCallStack_addr(this.context, "inotify_init")
      },
      onLeave: function (retval) {
        console.log("\t inotify_init retFd=" + retval)
      }
    })
  }

  static hookNative_inotify_add_watch(){
    // int inotify_add_watch(int fd, const char *pathname, uint32_t mask);
    var inotifyAddWatchAddr = Module.findExportByName("libc.so", "inotify_add_watch")
    if (null == inotifyAddWatchAddr) {
      console.warn("[anti-debug] inotify_add_watch not found")
      return
    }
    Interceptor.attach(inotifyAddWatchAddr, {
      onEnter: function (args) {
        var fd = args[0].toInt32()
        var pathname = FridaUtil.ptrToCStr(args[1])
        var mask = args[2]
        console.log("[anti-debug] inotify_add_watch: fd=" + fd + ", pathname=" + pathname + ", mask=" + mask)
        FridaUtil.printFunctionCallStack_addr(this.context, "inotify_add_watch")
      },
      onLeave: function (retval) {
        console.log("\t inotify_add_watch retval=" + retval)
      }
    })
  }

  // Anti-debug path patterns for /proc, root, frida detection
  static AntiDebugPathPatterns = [
    "/proc/self/status",
    "/proc/self/maps",
    "/proc/self/mem",
    "/proc/self/task",
    "/proc/self/exe",
    "/proc/self/fd",
    "/proc/self/cmdline",
    "/proc/self/wchan",
    "/proc/self/attr",
    "/proc/self/mountinfo",
    "TracerPid",
    "/proc/net/tcp",
    "/proc/net/tcp6",
  ]

  static RootDetectPathPatterns = [
    "/system/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "/data/local/su",
    "/data/local/bin/su",
    "/data/local/xbin/su",
    "/su/bin/su",
    "/system/bin/magisk",
    "magisk",
    "supersu",
    "Superuser",
  ]

  static FridaDetectPathPatterns = [
    "frida",
    "linjector",
    "gmain",
    "gum-js-loop",
    "frida-agent",
    "frida-server",
    "/data/local/tmp/re.frida.server",
  ]

  static isAntiDebugRelatedPath(path){
    if (null == path || path.length == 0) {
      return false
    }
    var allPatterns = FridaHookNative.AntiDebugPathPatterns
      .concat(FridaHookNative.RootDetectPathPatterns)
      .concat(FridaHookNative.FridaDetectPathPatterns)
    for (var i = 0; i < allPatterns.length; i++) {
      if (path.indexOf(allPatterns[i]) !== -1) {
        return true
      }
    }
    return false
  }

  static hookNative_fopen_antiDebug(){
    // FILE *fopen(const char *restrict pathname, const char *restrict mode);
    Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
      onEnter: function (args) {
        var pathname = FridaUtil.ptrToCStr(args[0])
        var mode = FridaUtil.ptrToCStr(args[1])
        this._pathname = pathname
        this._mode = mode
        this._isAntiDebug = FridaHookNative.isAntiDebugRelatedPath(pathname)
        if (this._isAntiDebug) {
          console.log("[anti-debug] fopen: pathname=" + pathname + ", mode=" + mode)
          FridaUtil.printFunctionCallStack_addr(this.context, "fopen [anti-debug]")
        }
      },
      onLeave: function (retFile) {
        if (this._isAntiDebug) {
          console.log("[anti-debug] fopen: pathname=" + this._pathname + ", mode=" + this._mode + " -> retFile=" + retFile)
        }
      }
    })
  }

  static hookNative_open_antiDebug(){
    // int open(const char *pathname, int flags, mode_t mode);
    Interceptor.attach(Module.findExportByName("libc.so", "open"), {
      onEnter: function (args) {
        var path = FridaUtil.ptrToCStr(args[0])
        var oflags = args[1]
        this._path = path
        this._oflags = oflags
        this._isAntiDebug = FridaHookNative.isAntiDebugRelatedPath(path)
        if (this._isAntiDebug) {
          console.log("[anti-debug] open: path=" + path + ", oflags=" + oflags)
          FridaUtil.printFunctionCallStack_addr(this.context, "open [anti-debug]")
        }
      },
      onLeave: function (retFd) {
        if (this._isAntiDebug) {
          console.log("[anti-debug] open: path=" + this._path + ", oflags=" + this._oflags + " -> retFd=" + retFd)
        }
      }
    })
  }

  static hookNative_openat_antiDebug(){
    // int openat(int dirfd, const char *pathname, int flags, ...);
    var openatAddr = Module.findExportByName("libc.so", "openat")
    if (null == openatAddr) {
      console.warn("[anti-debug] openat not found")
      return
    }
    Interceptor.attach(openatAddr, {
      onEnter: function (args) {
        var dirfd = args[0].toInt32()
        var pathname = FridaUtil.ptrToCStr(args[1])
        var flags = args[2]
        this._dirfd = dirfd
        this._pathname = pathname
        this._flags = flags
        this._isAntiDebug = FridaHookNative.isAntiDebugRelatedPath(pathname)
        if (this._isAntiDebug) {
          console.log("[anti-debug] openat: dirfd=" + dirfd + ", pathname=" + pathname + ", flags=" + flags)
          FridaUtil.printFunctionCallStack_addr(this.context, "openat [anti-debug]")
        }
      },
      onLeave: function (retFd) {
        if (this._isAntiDebug) {
          console.log("[anti-debug] openat: dirfd=" + this._dirfd + ", pathname=" + this._pathname + ", flags=" + this._flags + " -> retFd=" + retFd)
        }
      }
    })
  }

  static hookNative_getppid_antiDebug(){
    // pid_t getppid(void);
    // anti-debug: check if parent is not zygote (could mean debugger attached)
    Interceptor.attach(Module.findExportByName("libc.so", "getppid"), {
      onEnter: function (args) {
        // console.log("[anti-debug] getppid called")
      },
      onLeave: function (retPpid) {
        console.log("[anti-debug] getppid -> retPpid=" + retPpid)
      }
    })
  }

  static hookNative_strstr_antiDebug(){
    // char *strstr(const char *haystack, const char *needle);
    // anti-debug: detect string-based checks for "TracerPid", "frida", etc.
    Interceptor.attach(Module.findExportByName("libc.so", "strstr"), {
      onEnter: function (args) {
        try {
          var haystack = FridaUtil.ptrToCStr(args[0])
          var needle = FridaUtil.ptrToCStr(args[1])
          this._haystack = haystack
          this._needle = needle
          this._isAntiDebug = false
          if (needle) {
            var antiDebugNeedles = ["TracerPid", "frida", "gum-js-loop", "gmain", "linjector", "REJECT"]
            for (var i = 0; i < antiDebugNeedles.length; i++) {
              if (needle.indexOf(antiDebugNeedles[i]) !== -1) {
                this._isAntiDebug = true
                console.log("[anti-debug] strstr: needle=" + needle + ", haystack(first100)=" + (haystack ? FridaUtil.truncateStr(haystack, 100) : "null"))
                FridaUtil.printFunctionCallStack_addr(this.context, "strstr [anti-debug]")
                break
              }
            }
          }
        } catch(e) {
          // ignore read errors
        }
      },
      onLeave: function (retval) {
        if (this._isAntiDebug && !retval.isNull()) {
          console.log("[anti-debug] strstr: FOUND needle=" + this._needle + " -> retval=" + retval)
        }
      }
    })
  }

  static hookNative_pread(){
    // ssize_t pread(int fildes, void *buf, size_t nbyte, off_t offset)
    Interceptor.attach(Module.findExportByName(null, "pread"), {
      onEnter: function (args) {
        var fildes = args[0]
        var buf = args[1]
        var nbyte = args[2]
        var offset = args[3]
        console.log("pread: fildes=" + fildes + ", buf=" + buf + ", nbyte=" + nbyte + ", offset=" + offset)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_pwrite(){
    // ssize_t pwrite(int fildes, const void *buf, size_t nbyte, off_t offset)
    Interceptor.attach(Module.findExportByName(null, "pwrite"), {
      onEnter: function (args) {
        var fildes = args[0]
        var buf = args[1]
        var nbyte = args[2]
        var offset = args[3]
        console.log("pwrite: fildes=" + fildes + ", buf=" + buf + ", nbyte=" + nbyte + ", offset=" + offset)
      },
      onLeave: function (args) {
      }
    })
  }

  static hookNative_pipe(){
    // int pipe(int pipefd[2])
    Interceptor.attach(Module.findExportByName(null, "pipe"), {
      onEnter: function (args) {
        var pipefdArray = args[0]
        console.log("pipe: pipefdArray=" + pipefdArray)
      },
      onLeave: function (retval) {
      }
    })
  }

  static hookNative_getpid(){
    // pid_t getpid(void)
    Interceptor.attach(Module.findExportByName(null, "getpid"), {
      onEnter: function (args) {
        // console.log("getpid called")
      },
      onLeave: function (retPid) {
        console.log("\t getpid retPid=" + retPid)
      }
    })
  }

  static hookNative_getppid(){
    // pid_t getppid(void)
    Interceptor.attach(Module.findExportByName(null, "getppid"), {
      onEnter: function (args) {
        console.log("getppid called")
      },
      onLeave: function (retval) {
        console.log("\t getppid retval=" + retval)
      }
    })
  }

  static hookNative_setsid(){
    // pid_t setsid(void)
    Interceptor.attach(Module.findExportByName(null, "setsid"), {
      onEnter: function (args) {
        console.log("setsid called")
      },
      onLeave: function (retval) {
        console.log("\t setsid retval=" + retval)
      }
    })
  }

}
