/*
	File: FridaHookAndroidNative.js
	Function: crifan's Frida hook Android native related functions
	Author: Crifan Li
	Latest: https://github.com/crifan/JsFridaUtil/blob/main/frida/FridaHookAndroidNative.js
	Updated: 20250626
*/

// Frida hook Android native functions
class FridaHookAndroidNative {
  constructor() {
    console.log("FridaHookAndroidNative constructor")
  }

  static JNI_OnLoad(libFullPath) {
    // jint JNI_OnLoad(JavaVM *vm, void *reserved)
    const funcSym = "JNI_OnLoad"
    const funcPtr = Module.findExportByName(libFullPath, funcSym)
    console.log("[+] Hooking " + funcSym + ", funcPtr=" + funcPtr)
    if (null != funcPtr){
      var funcHook = Interceptor.attach(funcPtr, {
        onEnter: function (args) {
          const vm = args[0]
          const reserved = args[1]
          console.log("[+] " + funcSym + "(" + vm + ", " + reserved + ") called")
        },
        onLeave: function (retval) {
          console.log("[+]\t= " + retval)
        }
      })  
    }
  }

  static android_dlopen_ext(libraryName=null, callback_afterLibLoaded=null){
    console.log("android_dlopen_ext: libraryName=" + libraryName + ", callback_afterLibLoaded=" + callback_afterLibLoaded)
    // var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext")
    var funcPtr_android_dlopen_ext = Module.getExportByName(null, "android_dlopen_ext")
    console.log("funcPtr_android_dlopen_ext=" + funcPtr_android_dlopen_ext)
    if (null == funcPtr_android_dlopen_ext) {
      console.log("[-] Not found android_dlopen_ext")
      return
    }

    Interceptor.attach(funcPtr_android_dlopen_ext, {
      onEnter: function (args) {
        // android_dlopen_ext(const char *_Nullable __filename, int __flags, const android_dlextinfo *_Nullable __info)	

        // console.log("args=" + args)
        var filenamePtr = args[0]
        var libFullPath = FridaUtil.ptrToCStr(filenamePtr)
        // console.log("libFullPath=" + libFullPath)
        var flags = args[1]
        var info = args[2]
        if (libraryName) {
          // if(libraryName === libFullPath){
          if(libFullPath.includes(libraryName)){
            console.log("+++ Loaded lib " + libraryName + ", flags=" + flags + ", info=" + info)
            this.isLibLoaded = true

            this._libFullPath = libFullPath
          }
        } else {
          console.log("android_dlopen_ext: [+] libFullPath=" + libFullPath + ", flags=" + flags + ", info=" + info)
        }
      },
  
      onLeave: function () {
        if (libraryName) {
          if (this.isLibLoaded) {
            this.isLibLoaded = false
    
            // if(null != callback_afterLibLoaded) {
            if(callback_afterLibLoaded) {
              // callback_afterLibLoaded(libraryName)
              callback_afterLibLoaded(this._libFullPath)
            }
          }
        }
      }
    })
  
  }

  static waitForLibLoading(libraryName, callback_afterLibLoaded=null){
    console.log("waitForLibLoading: libraryName=" + libraryName + ", callback_afterLibLoaded=" + callback_afterLibLoaded)
    FridaHookAndroidNative.android_dlopen_ext(libraryName, callback_afterLibLoaded)

    // // var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext")
    // var android_dlopen_ext = Module.getExportByName(null, "android_dlopen_ext")
    // console.log("android_dlopen_ext=" + android_dlopen_ext)
    // if (null == android_dlopen_ext) {
    //   return
    // }
  
    // Interceptor.attach(android_dlopen_ext, {
    //   onEnter: function (args) {
    //     // android_dlopen_ext(const char *_Nullable __filename, int __flags, const android_dlextinfo *_Nullable __info)	

    //     // console.log("args=" + args)
    //     var filenamePtr = args[0]
    //     var libFullPath = FridaUtil.ptrToCStr(filenamePtr)
    //     // console.log("libFullPath=" + libFullPath)
    //     var flags = args[1]
    //     var info = args[2]
    //     // console.log("android_dlopen_ext: [+] libFullPath=" + libFullPath + ", flags=" + flags + ", info=" + info)
    //     // if(libraryName === libFullPath){
    //     if(libFullPath.includes(libraryName)){
    //       console.log("+++ Loaded lib " + libraryName + ", flags=" + flags + ", info=" + info)
    //       this.isLibLoaded = true

    //       this._libFullPath = libFullPath
    //     }
    //   },
  
    //   onLeave: function () {
    //     if (this.isLibLoaded) {
    //       this.isLibLoaded = false
  
    //       if(null != callback_afterLibLoaded) {
    //         // callback_afterLibLoaded(libraryName)
    //         callback_afterLibLoaded(this._libFullPath)
    //       }
    //     }
    //   }
    // })
  }

  static hookAfterLibLoaded(libName, callback_afterLibLoaded=null){
    console.log("libName=" + libName)
    FridaHookAndroidNative.waitForLibLoading(libName, callback_afterLibLoaded)
  }

  static findSymbolFromLib(soLibName, jniFuncName, callback_isFound) {
    console.log("soLibName=" + soLibName + ", jniFuncName=" + jniFuncName + ", callback_isFound=" + callback_isFound)
  
    var foundSymbolList = []
    let libSymbolList = Module.enumerateSymbolsSync(soLibName)
    // console.log("libSymbolList=" + libSymbolList)
    for (let i = 0; i < libSymbolList.length; i++) {
        var curSymbol = libSymbolList[i]
        // console.log("[" + i  + "] curSymbol=" + curSymbol)
  
        var symbolName = curSymbol.name
        // console.log("[" + i  + "] symbolName=" + symbolName)

        // var isFound = callback_isFound(symbolName)
        var isFound = callback_isFound(curSymbol, jniFuncName)
        // console.log("isFound=" + isFound)
  
        if (isFound) {
          var symbolAddr = curSymbol.address
          // console.log("symbolAddr=" + symbolAddr)

          foundSymbolList.push(curSymbol)
          console.log("+++ Found [" + i + "] symbol: addr=" + symbolAddr + ", name=" + symbolName)
        }
    }
  
    // console.log("foundSymbolList=" + foundSymbolList)
    return foundSymbolList
  }

  static findFunction_libart_so(jniFuncName, func_isFound) {
    var foundSymbolList = FridaHookAndroidNative.findSymbolFromLib("libart.so", jniFuncName, func_isFound)
    console.log("foundSymbolList=" + foundSymbolList)
    return foundSymbolList
  }

  static isFoundSymbol(curSymbol, symbolName){
    // return symbolName.includes("NewStringUTF")
    // return symbolName.includes("CheckJNI12NewStringUTF")
    // return symbol.name.includes("CheckJNI12NewStringUTF")

    // _ZN3art12_GLOBAL__N_18CheckJNI12NewStringUTFEP7_JNIEnvPKc.llvm.16005601603641821307
    // _ZN3art3JNIILb0EE12NewStringUTFEP7_JNIEnvPKc
    // _ZN3art2gc4Heap24AllocObjectWithAllocatorILb1ELb1ENS_12_GLOBAL__N_119NewStringUTFVisitorEEEPNS_6mirror6ObjectEPNS_6ThreadENS_6ObjPtrINS5_5ClassEEEmNS0_13AllocatorTypeERKT1_
    // _ZNK3art12_GLOBAL__N_119NewStringUTFVisitorclENS_6ObjPtrINS_6mirror6ObjectEEEm
    // _ZN3art2gc4Heap16AllocLargeObjectILb1ENS_12_GLOBAL__N_119NewStringUTFVisitorEEEPNS_6mirror6ObjectEPNS_6ThreadEPNS_6ObjPtrINS5_5ClassEEEmRKT0_
    // _ZZN3art2gc4Heap24AllocObjectWithAllocatorILb1ELb0ENS_12_GLOBAL__N_119NewStringUTFVisitorEEEPNS_6mirror6ObjectEPNS_6ThreadENS_6ObjPtrINS5_5ClassEEEmNS0_13AllocatorTypeERKT1_ENKUlvE_clEv
    // _ZN3art3JNIILb1EE12NewStringUTFEP7_JNIEnvPKc
    // _ZZN3art3JNIILb0EE12NewStringUTFEP7_JNIEnvPKcE19prev_bad_input_time
    // _ZZN3art3JNIILb1EE12NewStringUTFEP7_JNIEnvPKcE19prev_bad_input_time
    // return symbol.name.includes("NewStringUTF")

    // symbolName.includes("RegisterNatives") && symbolName.includes("CheckJNI")
    // return symbolName.includes("CheckJNI15RegisterNatives")
    // return symbolName.includes("RegisterNatives")

    // _ZN3art12_GLOBAL__N_18CheckJNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi.llvm.16005601603641821307
    // _ZN3art3JNIILb0EE15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
    // _ZN3art3JNIILb1EE15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
    // return symbol.name.includes("RegisterNatives")

    // return symbolName.includes("CheckJNI11GetMethodID")
    // return symbolName.includes("GetMethodID")

    // _ZN3art12_GLOBAL__N_18CheckJNI19GetMethodIDInternalEPKcP7_JNIEnvP7_jclassS3_S3_b
    // _ZN3art12_GLOBAL__N_18CheckJNI11GetMethodIDEP7_JNIEnvP7_jclassPKcS7_.llvm.16005601603641821307
    // _ZN3art3JNIILb0EE11GetMethodIDEP7_JNIEnvP7_jclassPKcS7_
    // _ZN3art3JNIILb1EE11GetMethodIDEP7_JNIEnvP7_jclassPKcS7_
    // return symbol.name.includes("GetMethodID")

    return curSymbol.name.includes(symbolName)
  }

  static findJniFunc(jniFuncName){
    var jniSymbolList = FridaHookAndroidNative.findFunction_libart_so(jniFuncName, FridaHookAndroidNative.isFoundSymbol)
    return jniSymbolList
  }

  static doHookJniFunc_multipleMatch(foundSymbolList, callback_onEnter, callback_onLeave=null){
    if (null == foundSymbolList){
      return
    }

    var symbolNum = foundSymbolList.length
    console.log("symbolNum=" + symbolNum)
    if (symbolNum == 0){
      return
    }

    for(var i = 0; i < symbolNum; ++i) {
      var eachSymbol = foundSymbolList[i]
      // console.log("eachSymbol=" + eachSymbol)
      var curSymbolAddr = eachSymbol.address
      console.log("curSymbolAddr=" + curSymbolAddr)

      Interceptor.attach(curSymbolAddr, {
        onEnter: function (args) {
          callback_onEnter(this, eachSymbol, args)
        },
        onLeave: function(retVal){
          if (null != callback_onLeave) {
            callback_onLeave(this, retVal)
          }
        }
      })
    }
  }

  static hookJniFunc(jniFuncName, hookFunc_onEnter, hookFunc_onLeave=null){
    var jniSymbolList = FridaHookAndroidNative.findJniFunc(jniFuncName)
    FridaHookAndroidNative.doHookJniFunc_multipleMatch(jniSymbolList, hookFunc_onEnter, hookFunc_onLeave)
  }

  static hookNative_NewStringUTF(){
    FridaHookAndroidNative.hookJniFunc(
      "NewStringUTF",
      function(thiz, curSymbol, args){
        JsUtil.logStr("Trigged NewStringUTF [" + curSymbol.address + "]")
          // jstring NewStringUTF(JNIEnv *env, const char *bytes);
          var jniEnv = args[0]
          console.log("jniEnv=" + jniEnv)

          var newStrPtr = args[1]
          // var newStr = newStrPtr.readCString()
          // var newStr = FridaUtil.ptrToUtf8Str(newStrPtr)
          var newStr = FridaUtil.ptrToCStr(newStrPtr)
          console.log("newStrPtr=" + newStrPtr + " -> newStr=" + newStr)
      }
    )
  }

  static hookNative_GetMethodID(callback_enableLog=null){
    FridaHookAndroidNative.hookJniFunc(
      "GetMethodID", 
      function(thiz, curSymbol, args){
        var curSymbolAddr = curSymbol.address

        // jmethodID GetMethodID(JNIEnv *env, jclass clazz, const char *name, const char *sig);
        var jniEnv = args[0]

        var clazz = args[1]
        var jclassName = FridaAndroidUtil.getJclassName(clazz)

        var namePtr = args[2]
        var nameStr = FridaUtil.ptrToUtf8Str(namePtr)
        
        var sigPtr = args[3]
        var sigStr = FridaUtil.ptrToUtf8Str(sigPtr)

        thiz.enableLog = false
        if (callback_enableLog) {
          thiz.enableLog = callback_enableLog(jniEnv, jclassName, nameStr, sigStr)
        } else {
          thiz.enableLog = true          
        }

        if (thiz.enableLog) {
          JsUtil.logStr("Trigged GetMethodID [" + curSymbolAddr + "]")

          console.log("jniEnv=" + jniEnv)
          console.log("clazz=" + clazz + " -> jclassName=" + jclassName)
          console.log("namePtr=" + namePtr + " -> nameStr=" + nameStr)
          console.log("sigPtr=" + sigPtr + " -> sigStr=" + sigStr)

          // if ("com.bytedance.mobsec.metasec.ml.MS" == jclassName){
          //   console.log("curSymbolAddr=" + curSymbolAddr)
          //   var libArtFuncPtr_GetMethodID = curSymbolAddr
          //   console.log("libArtFuncPtr_GetMethodID=" + libArtFuncPtr_GetMethodID)
          //   // jmethodID GetMethodID(JNIEnv *env, jclass clazz, const char *name, const char *sig);
          //   var nativeFunc_GetMethodID = new NativeFunction(
          //     libArtFuncPtr_GetMethodID,
          //     // 'jmethodID',
          //     // 'int',
          //     'pointer',
          //     // ['pointer', 'jclass', 'pointer', 'pointer']
          //     // ['pointer', 'int', 'pointer', 'pointer']
          //     ['pointer', 'pointer', 'pointer', 'pointer']
          //     // ['JNIEnv*', 'jclass', 'char*', 'char*']
          //   )
          //   console.log("nativeFunc_GetMethodID=" + nativeFunc_GetMethodID)
          //   // console.log("jniEnv=" + jniEnv + ", clazz=" + clazz + " -> jclassName=" + jclassName)
          //   // var funcName_Bill = "Bill"
          //   // var funcSig_Bill = "()V"
          //   var funcSig_common = Memory.allocUtf8String("()V")
          //   console.log("funcSig_common=" + funcSig_common)

          //   var funcName_Bill = Memory.allocUtf8String("Bill")
          //   console.log("funcName_Bill=" + funcName_Bill)
          //   var jMethodID_Bill = nativeFunc_GetMethodID(jniEnv, clazz, funcName_Bill, funcSig_common)
          //   console.log("jMethodID_Bill=" + jMethodID_Bill)

          //   var funcName_Louis = Memory.allocUtf8String("Louis")
          //   console.log("funcName_Louis=" + funcName_Louis)
          //   var jMethodID_Louis = nativeFunc_GetMethodID(jniEnv, clazz, funcName_Louis, funcSig_common)
          //   console.log("jMethodID_Louis=" + jMethodID_Louis)

          //   var funcName_Zeoy = Memory.allocUtf8String("Zeoy")
          //   console.log("funcName_Zeoy=" + funcName_Zeoy)
          //   var jMethodID_Zeoy = nativeFunc_GetMethodID(jniEnv, clazz, funcName_Zeoy, funcSig_common)
          //   console.log("jMethodID_Zeoy=" + jMethodID_Zeoy)

          //   var funcName_Francies = Memory.allocUtf8String("Francies")
          //   console.log("funcName_Francies=" + funcName_Francies)
          //   var jMethodID_Francies = nativeFunc_GetMethodID(jniEnv, clazz, funcName_Francies, funcSig_common)
          //   console.log("jMethodID_Francies=" + jMethodID_Francies)
          // }

        }
      },
      function(thiz, retVal){
        if (thiz.enableLog) {
          console.log("GetMethodID retVal=" + retVal)
        }
      }
    )
  }

  /* print detail of JNINativeMethod:
    typedef struct {
      const char* name;
      const char* signature;
      void* fnPtr;
    } JNINativeMethod;
  */
  static printJNINativeMethodDetail(methodsPtr, methodNum){
    // console.log("methodsPtr=" + methodsPtr + ", methodNum=" + methodNum)

    // console.log("Process.pointerSize=" + Process.pointerSize) // 8
    let JNINativeMethod_size = Process.pointerSize * 3
    // console.log("JNINativeMethod_size=" + JNINativeMethod_size) // 24

    for (var i = 0; i < methodNum; i++) {
      JsUtil.logStr("method [" + i + "]", true, "-", 80)

      var curPtrStartPos = i * JNINativeMethod_size
      // console.log("curPtrStartPos=" + curPtrStartPos)

      var namePtrPos = methodsPtr.add(curPtrStartPos)
      // console.log("namePtrPos=" + namePtrPos)
      var namePtr = Memory.readPointer(namePtrPos)
      // console.log("namePtr=" + namePtr)
      // var nameStr = Memory.readCString(namePtr)
      var nameStr = FridaUtil.ptrToCStr(namePtr)
      // console.log("nameStr=" + nameStr)
      console.log("name: pos=" + namePtrPos + " -> ptr=" + namePtr + " -> str=" + nameStr)

      var sigPtrPos = methodsPtr.add(curPtrStartPos + Process.pointerSize)
      // var sigPtrPos = namePtrPos.add(Process.pointerSize)
      // console.log("sigPtrPos=" + sigPtrPos)
      var sigPtr = Memory.readPointer(sigPtrPos)
      // console.log("sigPtr=" + sigPtr)
      var sigStr = FridaUtil.ptrToCStr(sigPtr)
      // console.log("sigStr=" + sigStr)
      console.log("signature: pos=" + sigPtrPos + " -> ptr=" + sigPtr + " -> str=" + sigStr)

      var fnPtrPos = methodsPtr.add(curPtrStartPos + Process.pointerSize*2)
      // var fnPtrPos = sigPtrPos.add(Process.pointerSize)
      // console.log("fnPtrPos=" + fnPtrPos)
      var fnPtrPtr = Memory.readPointer(fnPtrPos)
      // console.log("fnPtrPtr=" + fnPtrPtr)
      var foundModule = Process.findModuleByAddress(fnPtrPtr)
      // console.log("foundModule=" + foundModule)
      var moduleBase = foundModule.base
      // console.log("moduleBase=" + moduleBase)
      var offsetInModule = ptr(fnPtrPtr).sub(moduleBase)
      // console.log("offsetInModule=" + offsetInModule)
      console.log("fnPtr: pos=" + fnPtrPos + " -> ptr=" + fnPtrPtr + " -> offset=" + offsetInModule)

      console.log("Module: name=" + foundModule.name + ", base=" + foundModule.base + ", size=" + foundModule.size_ptr + ", path=" + foundModule.path)
    }
  }

  static hookNative_RegisterNatives(){
    // var symbolList_RegisterNatives = find_RegisterNatives()
    // hoook_RegisterNatives(symbolList_RegisterNatives)

    FridaHookAndroidNative.hookJniFunc(
      "RegisterNatives",
      function(thiz, curSymbol, args){
        JsUtil.logStr("Trigged RegisterNatives [" + curSymbol.address + "]")

        // jint RegisterNatives(JNIEnv *env, jclass clazz, const JNINativeMethod *methods, jint nMethods);
        var jniEnv = args[0]
        console.log("jniEnv=" + jniEnv)

        var clazz = args[1]
        var jclassName = FridaAndroidUtil.getJclassName(clazz)
        console.log("clazz=" + clazz + " -> jclassName=" + jclassName)

        var methodsPtr = args[2]
        console.log("methodsPtr=" + methodsPtr)

        var nMethods = args[3]
        var methodNum = parseInt(nMethods)
        console.log("nMethods=" + nMethods + " -> methodNum=" + methodNum)

        FridaHookAndroidNative.printJNINativeMethodDetail(methodsPtr, methodNum)
      }
    )
  }

}