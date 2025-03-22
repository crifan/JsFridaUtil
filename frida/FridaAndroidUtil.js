/*
	File: FridaAndroidUtil.js
	Function: crifan's common Frida Android util related functions
	Author: Crifan Li
	Latest: https://github.com/crifan/JsFridaUtil/blob/main/frida/FridaAndroidUtil.js
	Updated: 20250322
*/

// Frida Android Util
class FridaAndroidUtil {

  // android common root related binary files
  // static RootBinFileList = ["/system/bin/su", "/system/xbin/su", "/system/bin/magisk"]
  static RootBinFileList = [
    "/su",
    "/su/bin/su",
    "/sbin/su",
    "/data/local/xbin/su",
    "/data/local/bin/su",
    "/data/local/su",
    "/system/xbin/su",
    "/system/bin/su",
    "/system/bin/magisk",
    "/system/sd/xbin/su",
    "/system/bin/failsafe/su",
    "/system/bin/cufsdosck",
    "/system/xbin/cufsdosck",
    "/system/bin/cufsmgr",
    "/system/xbin/cufsmgr",
    "/system/bin/cufaevdd",
    "/system/xbin/cufaevdd",
    "/system/bin/conbb",
    "/system/xbin/conbb",
  ]

  // const
  static clsName_Message                      = "android.os.Message"
  static clsName_Messenger                    = "android.os.Messenger"

  static clsName_HttpURLConnection            = "java.net.HttpURLConnection"
  static clsName_URLConnection                = "java.net.URLConnection"
  static clsName_HttpsURLConnection           = "javax.net.ssl.HttpsURLConnection"

  static clsName_HttpURLConnectionImpl        = "com.android.okhttp.internal.huc.HttpURLConnectionImpl"
  static clsName_DelegatingHttpsURLConnection = "com.android.okhttp.internal.huc.DelegatingHttpsURLConnection"
  static clsName_HttpsURLConnectionImpl       = "com.android.okhttp.internal.huc.HttpsURLConnectionImpl"

  // {env: {clazz: className} }
  static cacheDictEnvClazz = {}

  static curThrowableCls = null

  static JavaArray = null
  static JavaArrays = null
  static JavaArrayList = null

  static JavaByteArr = null
  static JavaObjArr = null

  constructor() {
    console.log("FridaAndroidUtil constructor")
  }

  static {
    if (FridaUtil.isAndroid()) {
      FridaAndroidUtil.curThrowableCls = Java.use("java.lang.Throwable")
      console.log("FridaAndroidUtil.curThrowableCls=" + FridaAndroidUtil.curThrowableCls)

      console.log("FridaAndroidUtil.cacheDictEnvClazz=" + FridaAndroidUtil.cacheDictEnvClazz)
  
      FridaAndroidUtil.JavaArray = Java.use('java.lang.reflect.Array')
      console.log("FridaAndroidUtil.JavaArray=" + FridaAndroidUtil.JavaArray)
      FridaAndroidUtil.JavaArrays = Java.use("java.util.Arrays")
      console.log("FridaAndroidUtil.JavaArrays=" + FridaAndroidUtil.JavaArrays)
      FridaAndroidUtil.JavaArrayList = Java.use('java.util.ArrayList')
      console.log("FridaAndroidUtil.JavaArrayList=" + FridaAndroidUtil.JavaArrayList)
  
      FridaAndroidUtil.JavaByteArr = Java.use("[B")
      console.log("FridaAndroidUtil.JavaByteArr=" + FridaAndroidUtil.JavaByteArr)
      // var JavaObjArr = Java.use("[Ljava.lang.Object")
      FridaAndroidUtil.JavaObjArr = Java.use("[Ljava.lang.Object;")
      console.log("FridaAndroidUtil.JavaObjArr=" + FridaAndroidUtil.JavaObjArr)  
    } else {
      console.warn("FridaAndroidUtil: Non Android platfrom, no need init Android related")
    }
  }

  static isClass_HttpURLConnection(curObj){
    var isClsHttpURLConnection = FridaAndroidUtil.isJavaClass(curObj, FridaAndroidUtil.clsName_HttpURLConnection)
    console.log("curObj=" + curObj + " -> isClsHttpURLConnection=" + isClsHttpURLConnection)
    return isClsHttpURLConnection
  }

  static isClass_URLConnection(curObj){
    var isClsURLConnection = FridaAndroidUtil.isJavaClass(curObj, FridaAndroidUtil.clsName_URLConnection)
    console.log("curObj=" + curObj + " -> isClsURLConnection=" + isClsURLConnection)
    return isClsURLConnection
  }

  static isClass_HttpsURLConnection(curObj){
    var isClsHttpsURLConnection = FridaAndroidUtil.isJavaClass(curObj, FridaAndroidUtil.clsName_HttpsURLConnection)
    console.log("curObj=" + curObj + " -> isClsHttpsURLConnection=" + isClsHttpsURLConnection)
    return isClsHttpsURLConnection
  }

  static isClass_HttpURLConnectionImpl(curObj){
    var isClsHttpURLConnectionImpl = FridaAndroidUtil.isJavaClass(curObj, FridaAndroidUtil.clsName_HttpURLConnectionImpl)
    console.log("curObj=" + curObj + " -> isClsHttpURLConnectionImpl=" + isClsHttpURLConnectionImpl)
    return isClsHttpURLConnectionImpl
  }

  static isClass_DelegatingHttpsURLConnection(curObj){
    var isClsDelegatingHttpsURLConnection = FridaAndroidUtil.isJavaClass(curObj, FridaAndroidUtil.clsName_DelegatingHttpsURLConnection)
    console.log("curObj=" + curObj + " -> isClsDelegatingHttpsURLConnection=" + isClsDelegatingHttpsURLConnection)
    return isClsDelegatingHttpsURLConnection
  }

  static isClass_HttpsURLConnectionImpl(curObj){
    var isClsHttpsURLConnectionImpl = FridaAndroidUtil.isJavaClass(curObj, FridaAndroidUtil.clsName_HttpsURLConnectionImpl)
    console.log("curObj=" + curObj + " -> isClsHttpsURLConnectionImpl=" + isClsHttpsURLConnectionImpl)
    return isClsHttpsURLConnectionImpl
  }

  // android.os.Messenger
  // https://developer.android.com/reference/android/os/Messenger
  static printClass_Messenger(inputObj){
    if (inputObj) {
      var curObj = FridaAndroidUtil.castToJavaClass(inputObj, FridaAndroidUtil.clsName_Messenger)
      // console.log("curObj=" + curObj)

      var curClsName = FridaAndroidUtil.getJavaClassName(curObj)
      var clsNameStr = "[" + curClsName + "]"

      var binder = curObj.getBinder()

      console.log("Messenger:" + clsNameStr
        + " CREATOR=" + curObj.CREATOR.value
        + ", binder=" + binder
      )
    } else {
      console.log("Messenger: null")
    }
  }

  // android.os.Message
  // https://developer.android.com/reference/android/os/Message
  static printClass_Message(inputObj, caller=""){
    if (inputObj) {
      var curObj = FridaAndroidUtil.castToJavaClass(inputObj, FridaAndroidUtil.clsName_Message)
      // console.log("curObj=" + curObj)

      var curClsName = FridaAndroidUtil.getJavaClassName(curObj)
      var clsNameStr = "[" + curClsName + "]"

      var callback = curObj.getCallback()
      var dataBundle = curObj.getData()
      var targetHandler = curObj.getTarget()
      var when = curObj.getWhen()
      var isAsync = curObj.isAsynchronous()
      var callerStr = "[caller=" + caller + "] "

      console.log(callerStr + "Message:" + clsNameStr
        + " arg1=" + curObj.arg1.value
        + ", arg2=" + curObj.arg2.value
        + ", obj=" + curObj.obj.value
        + ", replyTo=" + curObj.replyTo.value
        + ", sendingUid=" + curObj.sendingUid.value
        + ", what=" + curObj.what.value

        + ", callback=" + callback
        + ", dataBundle=" + dataBundle
        + ", targetHandler=" + targetHandler
        + ", when=" + when
        + ", isAsync=" + isAsync
      )

      FridaAndroidUtil.printClass_Messenger(curObj.replyTo.value)
    } else {
      console.log("Message: null")
    }
  }

  // java.net.URLConnection
  // https://cs.android.com/android/platform/superproject/main/+/main:libcore/ojluni/src/main/java/java/net/URLConnection.java;drc=bd205f23c74d7498c9958d2bfa8622aacfe59517;l=161
  static printClass_URLConnection(inputObj){
    if (inputObj) {
      var curObj = FridaAndroidUtil.castToJavaClass(inputObj, FridaAndroidUtil.clsName_URLConnection)
      // console.log("curObj=" + curObj)

      var curClsName = FridaAndroidUtil.getJavaClassName(curObj)
      // var curJClassName = FridaAndroidUtil.getJclassName(curObj)
      // console.log("URLConnection: curClsName=" + curClsName + ", curJClassName=" + curJClassName)
      // console.log("URLConnection: curClsName=" + curClsName)
      var clsNameStr = "[" + curClsName + "]"

      // if (FridaAndroidUtil.isClass_URLConnection(curObj)){
        // console.log("URLConnection:"
        //   + " url=" + curObj.url.value
        //   + ", connected=" + curObj.connected.value
        //   + ", doInput=" + curObj.doInput.value
        //   + ", doOutput=" + curObj.doOutput.value
        //   + ", allowUserInteraction=" + curObj.allowUserInteraction.value
        //   + ", useCaches=" + curObj.useCaches.value
        //   + ", ifModifiedSince=" + curObj.ifModifiedSince.value
        //   + ", defaultAllowUserInteraction=" + curObj.defaultAllowUserInteraction.value
        //   + ", defaultUseCaches=" + curObj.defaultUseCaches.value
        //   + ", connectTimeout=" + curObj.connectTimeout.value
        //   + ", readTimeout=" + curObj.readTimeout.value
        //   + ", requests=" + curObj.requests.value
        //   + ", fileNameMap=" + curObj.fileNameMap.value
        // )

        var url = curObj.getURL()
        // console.log("url=" + url)
        var doInput = curObj.getDoInput()
        // console.log("doInput=" + doInput)
        var doOutput = curObj.getDoOutput()
        // console.log("doOutput=" + doOutput)
        var allowUserInteraction = curObj.getAllowUserInteraction()
        // console.log("allowUserInteraction=" + allowUserInteraction)
        var useCaches = curObj.getUseCaches()
        // console.log("useCaches=" + useCaches)
        var ifModifiedSince = curObj.getIfModifiedSince()
        // console.log("ifModifiedSince=" + ifModifiedSince)
        
        var requestHeaderMap = curObj.getRequestProperties() // this is request headers
        // console.log("requestHeaderMap=" + requestHeaderMap)
        var requestHeadersStr = FridaAndroidUtil.mapToStr(requestHeaderMap)
        // console.log("requestHeadersStr=" + requestHeadersStr)

        // // all following field is: response fields, NOT request fields
        // var respHeaders_contentLength = curObj.getContentLength()
        // console.log("respHeaders_contentLength=" + respHeaders_contentLength)
        // var respHeaders_contentLengthLong = curObj.getContentLengthLong()
        // console.log("respHeaders_contentLengthLong=" + respHeaders_contentLengthLong)
        // var respHeaders_contentType = curObj.getContentType()
        // console.log("respHeaders_contentType=" + respHeaders_contentType)
        // var respHeaders_contentEncoding = curObj.getContentEncoding()
        // console.log("respHeaders_contentEncoding=" + respHeaders_contentEncoding)
        // var respHeaders_date = curObj.getDate()
        // console.log("respHeaders_date=" + respHeaders_date)
        // var respHeaders_lastModified = curObj.getLastModified()
        // console.log("respHeaders_lastModified=" + respHeaders_lastModified)

        var defaultAllowUserInteraction = curObj.getDefaultAllowUserInteraction()
        // console.log("defaultAllowUserInteraction=" + defaultAllowUserInteraction)
        var defaultUseCaches = curObj.getDefaultUseCaches()
        // console.log("defaultUseCaches=" + defaultUseCaches)
        var connectTimeout = curObj.getConnectTimeout()
        // console.log("connectTimeout=" + connectTimeout)
        var readTimeout = curObj.getReadTimeout()
        // console.log("readTimeout=" + readTimeout)
        var fileNameMap = curObj.getFileNameMap()
        // console.log("fileNameMap=" + fileNameMap)
        // var fileNameMapStr = FridaAndroidUtil.mapToStr(fileNameMap)
        // console.log("fileNameMapStr=" + fileNameMapStr)

        console.log("URLConnection:" + clsNameStr
          + " url=" + url
          + ", doInput=" + doInput
          + ", doOutput=" + doOutput
          + ", allowUserInteraction=" + allowUserInteraction
          + ", useCaches=" + useCaches
          + ", ifModifiedSince=" + ifModifiedSince
          + ", requestHeadersStr=" + requestHeadersStr

          // // response headers
          // + ", respHeaders_contentLength=" + respHeaders_contentLength
          // + ", respHeaders_contentLengthLong=" + respHeaders_contentLengthLong
          // + ", respHeaders_contentType=" + respHeaders_contentType
          // + ", respHeaders_contentEncoding=" + respHeaders_contentEncoding
          // + ", respHeaders_date=" + respHeaders_date
          // + ", respHeaders_lastModified=" + respHeaders_lastModified

          + ", defaultAllowUserInteraction=" + defaultAllowUserInteraction
          + ", defaultUseCaches=" + defaultUseCaches
          + ", connectTimeout=" + connectTimeout
          + ", readTimeout=" + readTimeout
          + ", fileNameMap=" + fileNameMap
        )

        // } else {
      //   console.warn(curObj + " is Not URLConnection")
      // }
    } else {
      console.log("URLConnection: null")
    }
  }

  // java.net.HttpURLConnection
  static printClass_HttpURLConnection(inputObj){
    if (inputObj) {
      var curObj = FridaAndroidUtil.castToJavaClass(inputObj, FridaAndroidUtil.clsName_HttpURLConnection)
      // console.log("curObj=" + curObj)

      var curClsName = FridaAndroidUtil.getJavaClassName(curObj)
      // var curJClassName = FridaAndroidUtil.getJclassName(curObj)
      // console.log("HttpURLConnection: curClsName=" + curClsName + ", curJClassName=" + curJClassName)
      // console.log("HttpURLConnection: curClsName=" + curClsName)
      var clsNameStr = "[" + curClsName + "]"

      // if (FridaAndroidUtil.isClass_HttpURLConnection(curObj)){
        // var headerFields = curObj.getHeaderFields()
        // console.log("HttpURLConnection: headerFields=" + headerFields)
        // var reqMethod = curObj.getRequestMethod()
        // console.log("HttpURLConnection: reqMethod=" + reqMethod)

        // console.log("HttpURLConnection:"
        //   + "  method=" + curObj.method.value
        //   + ", chunkLength=" + curObj.chunkLength.value
        //   + ", fixedContentLength=" + curObj.fixedContentLength.value
        //   + ", fixedContentLengthLong=" + curObj.fixedContentLengthLong.value
        //   + ", responseCode=" + curObj.responseCode.value
        //   + ", responseMessage=" + curObj.responseMessage.value
        //   + ", instanceFollowRedirects=" + curObj.instanceFollowRedirects.value
        //   + ", followRedirects=" + curObj.followRedirects.value
        // )

        console.log("HttpURLConnection:" + clsNameStr
          + " method=" + curObj.getRequestMethod()
          // + ", responseCode=" + curObj.getResponseCode() // NOTE: will trigger send request !
          // + ", responseMessage=" + curObj.getResponseMessage()  // NOTE: will trigger send request !
          + ", instanceFollowRedirects=" + curObj.getInstanceFollowRedirects()
          + ", followRedirects=" + curObj.getFollowRedirects()
        )
      // } else {
      //   console.warn(curObj + " is Not HttpURLConnection")
      // }

      FridaAndroidUtil.printClass_URLConnection(curObj)
    } else {
      console.log("HttpURLConnection: null")
    }
  }

  // javax.net.ssl.HttpsURLConnection
  static printClass_HttpsURLConnection(inputObj){
    if (inputObj) {
      var curObj = FridaAndroidUtil.castToJavaClass(inputObj, FridaAndroidUtil.clsName_HttpsURLConnection)
      // console.log("curObj=" + curObj)

      var curClsName = FridaAndroidUtil.getJavaClassName(curObj)
      // var curJClassName = FridaAndroidUtil.getJclassName(curObj)
      // console.log("HttpsURLConnection: curClsName=" + curClsName + ", curJClassName=" + curJClassName)
      // console.log("HttpsURLConnection: curClsName=" + curClsName)
      var clsNameStr = "[" + curClsName + "]"

      // if (FridaAndroidUtil.isClass_HttpsURLConnection(curObj)){
        console.log("HttpsURLConnection: " + clsNameStr
          + " no fields"
        )
      // } else {
      //   console.warn(curObj + " is Not HttpsURLConnection")
      // }

      FridaAndroidUtil.printClass_HttpURLConnection(curObj)
    } else {
      console.log("HttpsURLConnection: null")
    }
  }

  // com.android.okhttp.internal.huc.DelegatingHttpsURLConnection
  static printClass_DelegatingHttpsURLConnection(inputObj){
    if (inputObj) {
      var curObj = FridaAndroidUtil.castToJavaClass(inputObj, FridaAndroidUtil.clsName_DelegatingHttpsURLConnection)
      // console.log("curObj=" + curObj)

      var curClsName = FridaAndroidUtil.getJavaClassName(curObj)
      // var curJClassName = FridaAndroidUtil.getJclassName(curObj)
      // console.log("DelegatingHttpsURLConnection: curClsName=" + curClsName + ", curJClassName=" + curJClassName)
      // console.log("DelegatingHttpsURLConnection: curClsName=" + curClsName)
      var clsNameStr = "[" + curClsName + "]"

      // if (FridaAndroidUtil.isClass_DelegatingHttpsURLConnection(curObj)){
        console.log("DelegatingHttpsURLConnection:" + clsNameStr
          + "  delegate=" + curObj.delegate.value
        )
      // } else {
      //   console.warn(curObj + " is Not DelegatingHttpsURLConnection")
      // }

      FridaAndroidUtil.printClass_HttpsURLConnection(curObj)
    } else {
      console.log("DelegatingHttpsURLConnection: null")
    }
  }

  // com.android.okhttp.internal.huc.HttpsURLConnectionImpl
  static printClass_HttpsURLConnectionImpl(inputObj){
    if (inputObj) {
      var curObj = FridaAndroidUtil.castToJavaClass(inputObj, FridaAndroidUtil.clsName_HttpsURLConnectionImpl)
      // console.log("curObj=" + curObj)

      var curClsName = FridaAndroidUtil.getJavaClassName(curObj)
      // var curJClassName = FridaAndroidUtil.getJclassName(curObj)
      // console.log("HttpsURLConnectionImpl: curClsName=" + curClsName + ", curJClassName=" + curJClassName)
      // console.log("HttpsURLConnectionImpl: curClsName=" + curClsName)
      var clsNameStr = "[" + curClsName + "]"

      // if (FridaAndroidUtil.isClass_HttpsURLConnectionImpl(curObj)){
        console.log("HttpsURLConnectionImpl:" + clsNameStr
          + "  delegate=" + curObj.delegate.value
        )
  
        FridaAndroidUtil.printClass_DelegatingHttpsURLConnection(curObj)  
      // } else {
      //   console.warn(curObj + " is Not HttpsURLConnectionImpl")
      // }
    } else {
      console.log("HttpsURLConnectionImpl: null")
    }
  }

  // com.android.okhttp.internal.huc.HttpURLConnectionImpl
  static printClass_HttpURLConnectionImpl(inputObj){
    if (inputObj) {
      var curObj = FridaAndroidUtil.castToJavaClass(inputObj, FridaAndroidUtil.clsName_HttpURLConnectionImpl)
      // console.log("curObj=" + curObj)

      var curClsName = FridaAndroidUtil.getJavaClassName(curObj)
      // var curJClassName = FridaAndroidUtil.getJclassName(curObj)
      // console.log("HttpURLConnectionImpl: curClsName=" + curClsName + ", curJClassName=" + curJClassName)
      // console.log("HttpURLConnectionImpl: curClsName=" + curClsName)
      var clsNameStr = "[" + curClsName + "]"

      // if (FridaAndroidUtil.isClass_HttpURLConnectionImpl(curObj)){
        console.log("HttpURLConnectionImpl:" + clsNameStr
          + "  client=" + curObj.client.value
          + ", requestHeaders=" + curObj.requestHeaders.value
          + ", fixedContentLength=" + curObj.fixedContentLength.value
          + ", followUpCount=" + curObj.followUpCount.value
          + ", httpEngineFailure=" + curObj.httpEngineFailure.value
          + ", httpEngine=" + curObj.httpEngine.value
          + ", responseHeaders=" + curObj.responseHeaders.value
          + ", route=" + curObj.route.value
          + ", handshake=" + curObj.handshake.value
          + ", urlFilter=" + curObj.urlFilter.value
        )
        FridaAndroidUtil.printClass_HttpURLConnection(curObj)
      // } else {
      //   console.warn(curObj + " is Not HttpURLConnectionImpl")
      // }
    } else {
      console.log("HttpURLConnectionImpl: null")
    }
  }

  // HTTP:  com.android.okhttp.internal.huc.HttpURLConnectionImpl
  // HTTPS: com.android.okhttp.internal.huc.HttpsURLConnectionImpl
  static printClass_HttpOrHttpsURLConnectionImpl(curObj){
    if (FridaAndroidUtil.isClass_HttpURLConnectionImpl(curObj)){
      FridaAndroidUtil.printClass_HttpURLConnectionImpl(curObj)
    } else if (FridaAndroidUtil.isClass_HttpsURLConnectionImpl(curObj)){
      FridaAndroidUtil.printClass_HttpsURLConnectionImpl(curObj)
    } else {
      var curClsName = FridaAndroidUtil.getJavaClassName(curObj)
      console.log("curClsName=" + curClsName)

      console.log("Unrecognized URLConnectionImpl class: " + curObj + ", curClsName=" + curClsName)
    }
  }

  // static printRequestBodyInfo(urlConn){
  //   console.log("printRequestBodyInfo: urlConn=" + urlConn)
  //   var requestBody = urlConn.getOutputStream()
  //   console.log("requestBody=" + requestBody)
  //   var reqBodyClsName = FridaAndroidUtil.getJavaClassName(requestBody)
  //   console.log("reqBodyClsName=" + reqBodyClsName)
  // }

  static waitForLibLoading(libraryName, callback_afterLibLoaded=null){
    console.log("libraryName=" + libraryName + ", callback_afterLibLoaded=" + callback_afterLibLoaded)
    // var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext")
    var android_dlopen_ext = Module.getExportByName(null, "android_dlopen_ext")
    console.log("android_dlopen_ext=" + android_dlopen_ext)
    if (null == android_dlopen_ext) {
      return
    }
  
    Interceptor.attach(android_dlopen_ext, {
      onEnter: function (args) {
        // android_dlopen_ext(const char *_Nullable __filename, int __flags, const android_dlextinfo *_Nullable __info)	

        // console.log("args=" + args)
        var filenamePtr = args[0]
        var libFullPath = FridaUtil.ptrToCStr(filenamePtr)
        // console.log("libFullPath=" + libFullPath)
        var flags = args[1]
        var info = args[2]
        // console.log("android_dlopen_ext: [+] libFullPath=" + libFullPath + ", flags=" + flags + ", info=" + info)
        // if(libraryName === libFullPath){
        if(libFullPath.includes(libraryName)){
          console.log("+++ Loaded lib " + libraryName + ", flags=" + flags + ", info=" + info)
          this.isLibLoaded = true

          this._libFullPath = libFullPath
        }
      },
  
      onLeave: function () {
        if (this.isLibLoaded) {
          this.isLibLoaded = false
  
          if(null != callback_afterLibLoaded) {
            // callback_afterLibLoaded(libraryName)
            callback_afterLibLoaded(this._libFullPath)
          }
        }
      }
    })
  
  }

  static hookAfterLibLoaded(libName, callback_afterLibLoaded=null){
    console.log("libName=" + libName)
    FridaAndroidUtil.waitForLibLoading(libName, callback_afterLibLoaded)
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
    var foundSymbolList = FridaAndroidUtil.findSymbolFromLib("libart.so", jniFuncName, func_isFound)
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
    var jniSymbolList = FridaAndroidUtil.findFunction_libart_so(jniFuncName, FridaAndroidUtil.isFoundSymbol)
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
    var jniSymbolList = FridaAndroidUtil.findJniFunc(jniFuncName)
    FridaAndroidUtil.doHookJniFunc_multipleMatch(jniSymbolList, hookFunc_onEnter, hookFunc_onLeave)
  }

  static hookNative_NewStringUTF(){
    FridaAndroidUtil.hookJniFunc(
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
    FridaAndroidUtil.hookJniFunc(
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

    FridaAndroidUtil.hookJniFunc(
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

        FridaAndroidUtil.printJNINativeMethodDetail(methodsPtr, methodNum)
      }
  )

  }

  // java byte array to js byte array
  static javaByteArrToJsByteArr(javaByteArr){
    // var javaByteArrLen = javaByteArr.length
    // console.log("javaByteArrLen=" + javaByteArrLen) // javaByteArrLen=undefined
    var javaByteArrGotLen = FridaAndroidUtil.JavaArray.getLength(javaByteArr)
    console.log("javaByteArrGotLen=" + javaByteArrGotLen) // javaByteArrGotLen=8498
    var jsByteArr = new Array()
    // console.log("jsByteArr=" + jsByteArr)
    for(var i = 0; i < javaByteArrGotLen; ++i) {
      // jsByteArr[i] = javaByteArr[i]
      var curByte = FridaAndroidUtil.JavaArray.get(javaByteArr, i)
      // console.log("curByte=" + curByte)
      jsByteArr[i] = curByte
    }
    // console.log("jsByteArr=" + jsByteArr)
    return jsByteArr
  }

  // java array/list (byte array / List<Integer> )to string
  static javaArrayListToStr(javaArraryList){
    var jsArrayList = FridaAndroidUtil.javaByteArrToJsByteArr(javaArraryList)
    console.log("jsArrayList=" + jsArrayList)
    var jsArrayListStr = jsArrayList.toString()
    console.log("jsArrayListStr=" + jsArrayListStr)
    return jsArrayListStr
  }

  // get java class name from clazz
  // example:
  //  clazz=0x35 -> className=java.lang.ref.Reference
  //  clazz=0xa1 -> className=com.tencent.wcdb.database.SQLiteConnection
  //  clazz=0x91 -> className=java.lang.String
  //  clazz=0x42a6 -> jclassName=java.lang.Integer
  // static getJclassName(clazz){
  // Note: if not use cache, some time will cause Frida crashed: Process terminated
  static getJclassName(clazz, isUseCache=true){
  // static getJclassName(clazz, isUseCache=false){
    // console.log("clazz=" + clazz)
    var isFoundCache = false
    var isNeedAddToCache = false
    var className = ""

    if (null == clazz){
      return className
    }

    var env = Java.vm.tryGetEnv()
    // console.log("env=" + env) // env=[object Object]
    if (null == env){
      return className
    }

    // console.log("isUseCache=" + isUseCache)
    if(isUseCache){
      if (env in FridaAndroidUtil.cacheDictEnvClazz){
        var cachedClazzClassnameDict = FridaAndroidUtil.cacheDictEnvClazz[env]
        if (clazz in cachedClazzClassnameDict) {
          className = cachedClazzClassnameDict[clazz]
          if (JsUtil.strIsEmpty(className)){
            console.warn("clazz=" + clazz + " in cache=" + cachedClazzClassnameDict + ", but empty className")
          } else {
            isFoundCache = true
          }
        }
        else {
          // console.log("clazz=" + clazz + " not in cache=" + cachedClazzClassnameDict)
        }
      }
      else {
        // console.log("env=" + env + " not in cache=" + FridaAndroidUtil.cacheDictEnvClazz)
      }
    }

    // console.log("isFoundCache=" + isFoundCache)
    if (!isFoundCache){
      // var clazzInt = clazz.toInt32(clazzInt)
      // // console.log("clazzInt=" + clazzInt)
      // const ProbablyErrorMinClazzValue = 0x1000
      // var isProbabllyError = clazzInt < ProbablyErrorMinClazzValue
      // if (isProbabllyError) {
      //   // console.warn("Not do getClassName, for probably erro for clazz=" + clazz + ", less then ProbablyErrorMinClazzValue=" + ProbablyErrorMinClazzValue)
      // } else {
      try {
        className = env.getClassName(clazz)
      } catch(err){
        console.error("getJclassName catch: err=" + err + ", for clazz=" + clazz)
      } finally {
        if (JsUtil.strIsEmpty(className)){
          console.error("getJclassName finally: empty className for clazz=" + clazz)
        } else {
          // console.log("getJclassName OK: clazz=" + clazz + " -> className=" + className)
          if (isUseCache){
            isNeedAddToCache = true
          }
        }
      }
      // }
    }

    if (isUseCache && isNeedAddToCache){  
      if (env in FridaAndroidUtil.cacheDictEnvClazz){
        var oldCachedClazzClassnameDict = FridaAndroidUtil.cacheDictEnvClazz[env]
        // console.log("old CachedClazzClassnameDict=" + oldCachedClazzClassnameDict)
        oldCachedClazzClassnameDict[clazz] = className
        // console.log("new CachedClazzClassnameDict=" + oldCachedClazzClassnameDict)
        FridaAndroidUtil.cacheDictEnvClazz[env] = oldCachedClazzClassnameDict
        // console.log("Added clazz=" + clazz + ", className=" + className + " -> to existed env cache:" + FridaAndroidUtil.cacheDictEnvClazz)
      } else {
        FridaAndroidUtil.cacheDictEnvClazz[env] = {
          clazz: className
        }
        // console.log("Added clazz=" + clazz + ", className=" + className + " -> to cache:" + FridaAndroidUtil.cacheDictEnvClazz)
      }
    }

    // var logPrefix = ""
    // if (isFoundCache){
    //   logPrefix = "Cached: "
    // }
    // console.log(logPrefix + "clazz=" + clazz + "-> className=" + className)
    return className
  }

  static getJavaClassName(curObj){
    var javaClsName = null
    if (null != curObj) {
      // javaClsName = curObj.constructor.name
      javaClsName = curObj.$className
      // console.log("javaClsName=" + javaClsName)
      // var objType = (typeof curObj)
      // console.log("objType=" + objType)
    }
    // console.log("javaClsName=" + javaClsName)
    return javaClsName
  }

  static isJavaClass(curObj, expectedClassName){
    var clsName = FridaAndroidUtil.getJavaClassName(curObj)
    // console.log("clsName=" + clsName)
    var isCls = clsName === expectedClassName
    // console.log("isCls=" + isCls)
    return isCls
  } 

  // cast current object to destination class instance
  static castToJavaClass(curObj, toClassName){
    if(curObj){
      // // for debug
      // var objClsName  =FridaAndroidUtil.getJavaClassName(curObj)
      // console.log("objClsName=" + objClsName)

      const toClass = Java.use(toClassName)
      // console.log("toClass=" + toClass)
      var toClassObj = Java.cast(curObj, toClass)
      // console.log("toClassObj=" + toClassObj)
      return toClassObj
    } else{
      return null
    }
  }

  // convert Java map/Collections (java.util.HashMap / java.util.Collections$UnmodifiableMap) to key=value string list
  static mapToKeyValueStrList(curMap){
    var keyValStrList = []
    // var HashMapNode = Java.use('java.util.HashMap$Node')
    // console.log("HashMapNode=" + HashMapNode)
    if((null != curMap) && (curMap != undefined)) {
      // var mapEntrySet = curMap.entrySet()
      // console.log("mapEntrySet=" + mapEntrySet)
      // if (mapEntrySet != undefined) {
      //   var iterator = mapEntrySet.iterator()
      //   console.log("iterator=" + iterator)
      //   while (iterator.hasNext()) {
      //     var nextObj = iterator.next()
      //     console.log("nextObj=" + nextObj)
      //     // var entry = Java.cast(nextObj, HashMapNode)
      //     var entry = nextObj
      //     console.log("entry=" + entry)
      //     var curKey = entry.getKey()
      //     var curVal = entry.getValue()
      //     console.log("key=" + entry.getKey() + ", value=" + entry.getValue());
      //     var keyValStr = `${curKey}=${curVal}`
      //     console.log("keyValStr=" + keyValStr);
      //     keyValStrList.push(keyValStr)
      //   }
      // }
          
      // var curMapJavaClsName = FridaAndroidUtil.getJavaClassName(curMap)
      // console.log("curMapJavaClsName=" + curMapJavaClsName)

      var keys = curMap.keySet()
      // console.log("keys=" + keys)
      var keyIterator = keys.iterator()
      // console.log("keyIterator=" + keyIterator)
      while (keyIterator.hasNext()) {
        var curKey = keyIterator.next()
        // console.log("curKey=" + curKey)
        var curValue = curMap.get(curKey)
        // console.log("curValue=" + curValue)
        var keyValStr = `${curKey}=${curValue}`
        // console.log("keyValStr=" + keyValStr)
        keyValStrList.push(keyValStr)
      }
    }
    // console.log("keyValStrList=" + keyValStrList)
    return keyValStrList
  }

  // convert Java map/Collections (java.util.HashMap / java.util.Collections$UnmodifiableMap) to string
  static mapToStr(curMap){
    //  curMap="<instance: java.util.Map, $className: java.util.HashMap>"
    // return JSON.stringify(curMap, (key, value) => (value instanceof Map ? [...value] : value));
    // var keyValStrList = this.mapToKeyValueStrList(curMap)
    var keyValStrList = FridaAndroidUtil.mapToKeyValueStrList(curMap)
    // console.log("keyValStrList=" + keyValStrList)
    var mapStr = keyValStrList.join(", ")
    var mapStr = `[${mapStr}]`
    // console.log("mapStr=" + mapStr)
    return mapStr
  }

  static describeJavaClass(className) {
    var jClass = Java.use(className);
    console.log(JSON.stringify({
      _name: className,
      _methods: Object.getOwnPropertyNames(jClass.__proto__).filter(m => {
      // _methods: Object.getOwnPropertyDescriptor(jClass.__proto__).filter(m => {
      // _methods: Object.getOwnPropertySymbols(jClass.__proto__).filter(m => {
        return !m.startsWith('$') // filter out Frida related special properties
           || m == 'class' || m == 'constructor' // optional
      }), 
      _fields: jClass.class.getFields().map(f => {
        return f.toString()
      })  
    }, null, 2))
  }

  // enumerate all methods declared in a Java class
  static enumMethods(targetClass) {
    var hook = Java.use(targetClass);
    var ownMethods = hook.class.getDeclaredMethods();
    console.log("---use getDeclaredMethods---")

    // var ownMethods = hook.class.getMethods();
    // console.log("use getMethods")

    hook.$dispose;
    return ownMethods;
  }

  // enumerate all property=field declared in a Java class
  static enumProperties(targetClass) {
    var hook = Java.use(targetClass);
    // var ownMethods = hook.class.getFields();
    // console.log("use getFields")

    var ownFields = hook.class.getDeclaredFields();
    console.log("---use getDeclaredFields---")

    hook.$dispose;
    return ownFields;
  }

  // print single java class all Functions=Methods and Fields=Properties
  static printClassAllMethodsFields(javaClassName) {
    console.log("=============== " + "Class: " + javaClassName + " ===============")

    console.log("-----" + "All Properties" + "-----")
    // var allProperties = enumProperties(javaClassName)
    // var allProperties = this.enumProperties(javaClassName)
    var allProperties = FridaAndroidUtil.enumProperties(javaClassName)
    allProperties.forEach(function(singleProperty) { 
      console.log(singleProperty)
    })

    // console.log("-----" + "All Methods" + "-----")
    // enumerate all methods in a class
    // var allMethods = enumMethods(javaClassName)
    // var allMethods = this.enumMethods(javaClassName)
    var allMethods = FridaAndroidUtil.enumMethods(javaClassName)
    allMethods.forEach(function(singleMethod) { 
      console.log(singleMethod)
    })

    // console.log("")
    console.log("=========== " + "End of class: " + javaClassName + " ===========")
  }

  // generate current stack trace string
  static genStackStr(prefix="") {
    // let newThrowable = ThrowableCls.$new()
    // let newThrowable = this.curThrowableCls.$new()
    let newThrowable = FridaAndroidUtil.curThrowableCls.$new()
    // console.log("genStackStr: newThrowable=" + newThrowable)
    var stackElements = newThrowable.getStackTrace()
    // console.log("genStackStr: stackElements=" + stackElements)
    if (!JsUtil.strIsEmpty(prefix)){
      prefix = prefix + " "
    }
    const linePrefix = "\n  "
    var stackStr = prefix + "java Stack:" + linePrefix + stackElements[0] //method//stackElements[0].getMethodName()
    for (var i = 1; i < stackElements.length; i++) {
      stackStr += linePrefix + "at " + stackElements[i]
    }
    // stackStr = "\n\n" + stackStr
    stackStr = stackStr + "\n"
    // console.log("genStackStr: stackStr=" + stackStr)

    return stackStr
  }

  // 打印当前调用堆栈信息 print call stack
  static printStack(prefix="") {
    var stackStr = FridaAndroidUtil.genStackStr(prefix)
    console.log(stackStr)

    // let newThrowable = ThrowableCls.$new()
    // let curLog = Java.use("android.util.Log")
    // let stackStr = curLog.getStackTraceString(newThrowable)
    // console.log("stackStr=" + stackStr)
  }

  // generate Function call string
  static genFunctionCallStr(funcName, funcParaDict){
    var logStr = `${funcName}:`
    // var logStr = funcName + ":"
    var isFirst = true

    for(var curParaName in funcParaDict){
      let curParaValue = funcParaDict[curParaName]
      var prevStr = ""
      if (isFirst){
        prevStr = " "
        isFirst = false
      } else {
        prevStr = ", "
      }

      logStr = `${logStr}${prevStr}${curParaName}=` + curParaValue
      // logStr = logStr + prevStr + curParaName + "=" + curParaValue
    }

    return logStr
  }

  static printFunctionCallStr(funcName, funcParaDict){
    // var functionCallStr = this.genFunctionCallStr(funcName, funcParaDict)
    var functionCallStr = FridaAndroidUtil.genFunctionCallStr(funcName, funcParaDict)
    console.log(functionCallStr)
  }

  // print Function call and stack trace string
  // static printFunctionCallAndStack(funcName, funcParaDict, filterList=undefined){
  static printFunctionCallAndStack(funcName, funcParaDict, filterList=undefined, isPrintDelimiter=true){
    // console.log("filterList=" + filterList + ", isPrintDelimiter=" + isPrintDelimiter)

    var needPrint = true

    // var functionCallStr = this.genFunctionCallStr(funcName, funcParaDict)
    var functionCallStr = FridaAndroidUtil.genFunctionCallStr(funcName, funcParaDict)

    // var stackStr = this.genStackStr()
    // var stackStr = FridaAndroidUtil.genStackStr()
    var stackStr = FridaAndroidUtil.genStackStr(funcName)

    if (filterList != undefined) {
      needPrint = false

      for (const curFilter of filterList) {
        // console.log("curFilter=" + curFilter)
        if (stackStr.includes(curFilter)) {
          needPrint = true
          // console.log("needPrint=" + needPrint)
          break
        }
      }
    }

    if (needPrint) {
      var delimiterStr = ""
      if(isPrintDelimiter){
        var delimiterFuncName = funcName
        const LineMaxSize = 80
        // const LineMaxSize = 120
        // const LineMaxSize = 160
        if (funcName.length > LineMaxSize) {
          // ConnectionsManager.init(version,layer,apiId,deviceModel,systemVersion,appVersion,langCode,systemLangCode,configPath,logPath,regId,cFingerprint,timezoneOffset,userId,userPremium,enablePushConnection) -> ConnectionsManager.init
          // var shorFuncName = funcName.replace('/([\w\.\:]+)\(.+\)/', "$1")
          var shorFuncName = funcName.replace(/([\w\.\:]+)\(.+\)/, "$1")
          // console.log("shorFuncName=" + shorFuncName)
          delimiterFuncName = shorFuncName
        }
        // JsUtil.logStr(delimiterFuncName)
        delimiterStr = JsUtil.generateLineStr(delimiterFuncName, true, "=", LineMaxSize)
        delimiterStr = delimiterStr + "\n"
        // console.log("delimiterStr=" + delimiterStr)
      }

      var functionCallAndStackStr = `${delimiterStr}${functionCallStr}\n${stackStr}`
      // var functionCallAndStackStr = functionCallStr + "\n" + stackStr
      // return functionCallAndStackStr
      console.log(functionCallAndStackStr)
    }
  }

  // find loaded classes that match a pattern (async)
  // Note: for some app, will crash: Process terminated
  static findClass(pattern) {
    console.log("Finding all classes that match pattern: " + pattern + "\n");

    Java.enumerateLoadedClasses({
      onMatch: function(aClass) {
        if (aClass.match(pattern)){
          console.log(aClass)
        }
      },
      onComplete: function() {}
    });
  }

  // emulate print all Java Classes
  // Note: for some app, will crash: Process terminated
  static printAllClasses() {
    // findClass("*")

    Java.enumerateLoadedClasses({
      onMatch: function(className) {
        console.log(className);
      },
      onComplete: function() {}
    });
  }

}
