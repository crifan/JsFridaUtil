/*
	File: FridaAndroidUtil.js
	Function: crifan's common Frida Android util related functions
	Author: Crifan Li
	Latest: https://github.com/crifan/JsFridaUtil/blob/main/frida/FridaAndroidUtil.js
	Updated: 20251119
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
  // static clsName_Headers_Builder              = "com.android.okhttp.internal.huc.Headers$Builder"
  static clsName_Headers_Builder              = "com.android.okhttp.Headers$Builder"
  

  static clsName_CronetUrlRequest             = "org.chromium.net.impl.CronetUrlRequest"
  static clsName_ByteArrayOutputStream        = "java.io.ByteArrayOutputStream"
  static clsName_FileNotFoundException        = "java.io.FileNotFoundException"
  static clsName_Long                         = "java.lang.Long"
  static clsName_File                         = "java.io.File"
  static clsName_Parcel                       = "android.os.Parcel"
  static clsName_SharedPreferencesImpl_EditorImpl = "android.app.SharedPreferencesImpl$EditorImpl"

  // {env: {clazz: className} }
  static cacheDictEnvClazz = {}

  static curThrowableCls = null

  static JavaArray = null
  static JavaArrays = null
  static JavaArrayList = null

  static JavaByteArr = null
  static JavaObjArr = null

  static StandardCharsets = null
  static ByteArrayOutputStream = null
  static FileNotFoundException = null
  static Long = null
  static Long_0 = null

  // https://source.android.com/docs/core/runtime/dex-format?hl=zh-cn
  // https://cmrodriguez.me/blog/methods/
  static FridaDexTypeMapppingDict = {
    "void":     "V",

    "boolean":  "Z",
    "char":     "C",
    "byte":     "B",
    "short":    "S",
    "int":      "I",
    "long":     "J",
    "float":    "F",
    "double":   "D",

    "char":     "[C",
    "byte[]":   "[B",
    "short[]":  "[S",
    "int[]":    "[I",
    "long[]":   "[J",
    "float[]":  "[F",
    "double[]": "[D",

    "String[]": "[Ljava/lang/String;",
    "Object[]": "[Ljava/lang/Object;",

    // TODO: add more type
  }

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
      
      FridaAndroidUtil.StandardCharsets = Java.use("java.nio.charset.StandardCharsets")
      console.log("FridaAndroidUtil.StandardCharsets=" + FridaAndroidUtil.StandardCharsets)

      FridaAndroidUtil.ByteArrayOutputStream = Java.use(FridaAndroidUtil.clsName_ByteArrayOutputStream)
      console.log("FridaAndroidUtil.ByteArrayOutputStream=" + FridaAndroidUtil.ByteArrayOutputStream)

      FridaAndroidUtil.FileNotFoundException = Java.use(FridaAndroidUtil.clsName_FileNotFoundException)
      console.log("FridaAndroidUtil.FileNotFoundException=" + FridaAndroidUtil.FileNotFoundException)

      FridaAndroidUtil.Long = Java.use(FridaAndroidUtil.clsName_Long)
      console.log("FridaAndroidUtil.Long=" + FridaAndroidUtil.Long)
      // FridaAndroidUtil.Long_0 = FridaAndroidUtil.Long.valueOf(0)
      // FridaAndroidUtil.Long_0 = FridaAndroidUtil.Long.$new(0)
      // FridaAndroidUtil.Long_0 = int64(0)
      FridaAndroidUtil.Long_0 = 0
      console.log("FridaAndroidUtil.Long_0=" + FridaAndroidUtil.Long_0)

    } else {
      console.warn("FridaAndroidUtil: Non Android platfrom, no need init Android related")
    }
  }

  // print/convet Java long (maybe negtive) to (unsigned=positive long value) string
  static printLongToStr(longVal){
    var longStr = FridaAndroidUtil.Long.toUnsignedString(longVal)
    // console.log(`longStr: type=${typeof longStr}, val=${longStr}`)
    return longStr
  }

  static isClass_File(curObj){
    var isClsFile = FridaAndroidUtil.isJavaClass(curObj, FridaAndroidUtil.clsName_File)
    console.log("curObj=" + curObj + " -> isClsFile=" + isClsFile)
    return isClsFile
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

  // Convert com.android.okhttp.Headers$Builder to string
  static HeadersBuilderToString(headersBuilderObj) {
    var headersStr = ""
    if (headersBuilderObj) {
      var headers = headersBuilderObj.build()
      // console.log("headers=" + headers)
      // com.squareup.okhttp.Headers
      headersStr = headers.toString()
    }
    // console.log("headersStr=" + headersStr)
    return headersStr
  }

  static printClass_SharedPreferencesImpl_EditorImpl(inputObj, prefixStr=""){
    // android.app.SharedPreferencesImpl$EditorImpl
    // https://android.googlesource.com/platform/frameworks/base.git/+/master/core/java/android/app/SharedPreferencesImpl.java
    const ClassName = "SharedPreferencesImpl$EditorImpl"
    var newPrefStr  = prefixStr ? (prefixStr + " ") : prefixStr
    if (inputObj) {
      var curClassName = FridaAndroidUtil.getJavaClassName(inputObj)
      if (curClassName === FridaAndroidUtil.clsName_SharedPreferencesImpl_EditorImpl) {
        var curObj = FridaAndroidUtil.castToJavaClass(inputObj, FridaAndroidUtil.clsName_SharedPreferencesImpl_EditorImpl)
        // console.log("curObj=" + curObj)

        var clsNameStr = FridaAndroidUtil.genClassNameStr(curObj)

        console.log(newPrefStr + ClassName + ":" + clsNameStr
          + " mEditorLock=" + curObj.mEditorLock.value
          + ", mModified=" + FridaAndroidUtil.mapToStr(curObj.mModified.value)
          + ", mClear=" + curObj.mClear.value
        )
      } else {
        console.log(newPrefStr + curClassName + ": not a " + ClassName)
      }
    } else {
      console.log(newPrefStr + ClassName + ": null")
    }
  }

  // org.chromium.net.impl.CronetUrlRequest
  static printClass_CronetUrlRequest(inputObj){
    // https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/cronet/android/java/src/org/chromium/net/impl/CronetUrlRequest.java
    if (inputObj) {
      // var curObj = FridaAndroidUtil.castToJavaClass(inputObj, FridaAndroidUtil.clsName_CronetUrlRequest)
      // console.log("curObj=" + curObj)

      var curObj = inputObj
      console.log("curObj=" + curObj)

      var clsNameStr = FridaAndroidUtil.genClassNameStr(curObj)

      console.log("CronetUrlRequest:" + clsNameStr
        + " mInitialUrl=" + curObj.mInitialUrl.value
        + " mInitialMethod=" + curObj.mInitialMethod.value
        + " mRequestHeaders=" + curObj.mRequestHeaders.value
        + " mUploadDataStream=" + curObj.mUploadDataStream.value
        + " mRequestContext=" + curObj.mRequestContext.value
        + " mNetworkHandle=" + curObj.mNetworkHandle.value
        + " mPriority=" + curObj.mPriority.value
        + " mStarted=" + curObj.mStarted.value
        + " mDisableCache=" + curObj.mDisableCache.value
      )
    } else {
      console.log("CronetUrlRequest: null")
    }
  }

  // android.os.Messenger
  static printClass_Messenger(inputObj){
    // https://developer.android.com/reference/android/os/Messenger
    if (inputObj) {
      var curObj = FridaAndroidUtil.castToJavaClass(inputObj, FridaAndroidUtil.clsName_Messenger)
      // console.log("curObj=" + curObj)

      var clsNameStr = FridaAndroidUtil.genClassNameStr(curObj)

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
  static printClass_Message(inputObj, caller=""){
    // https://developer.android.com/reference/android/os/Message
    if (inputObj) {
      var curObj = FridaAndroidUtil.castToJavaClass(inputObj, FridaAndroidUtil.clsName_Message)
      // console.log("curObj=" + curObj)

      var clsNameStr = FridaAndroidUtil.genClassNameStr(curObj)

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
  static printClass_URLConnection(inputObj){
    // https://cs.android.com/android/platform/superproject/main/+/main:libcore/ojluni/src/main/java/java/net/URLConnection.java;drc=bd205f23c74d7498c9958d2bfa8622aacfe59517;l=161
    if (inputObj) {
      var curObj = FridaAndroidUtil.castToJavaClass(inputObj, FridaAndroidUtil.clsName_URLConnection)
      // console.log("curObj=" + curObj)

      var clsNameStr = FridaAndroidUtil.genClassNameStr(curObj)

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

      var clsNameStr = FridaAndroidUtil.genClassNameStr(curObj)

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

      var clsNameStr = FridaAndroidUtil.genClassNameStr(curObj)

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

      var clsNameStr = FridaAndroidUtil.genClassNameStr(curObj)

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

      var clsNameStr = FridaAndroidUtil.genClassNameStr(curObj)

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

      var clsNameStr = FridaAndroidUtil.genClassNameStr(curObj)

      // var reqHeadersStr = FridaAndroidUtil.printClass_Headers_Builder(curObj.requestHeaders.value)
      var reqHeadersStr = FridaAndroidUtil.HeadersBuilderToString(curObj.requestHeaders.value)
      // console.log("reqHeadersStr=" + reqHeadersStr)

      // if (FridaAndroidUtil.isClass_HttpURLConnectionImpl(curObj)){
        console.log("HttpURLConnectionImpl:" + clsNameStr
          + "  client=" + curObj.client.value
          + ", requestHeaders=" + reqHeadersStr
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

  // com.android.okhttp.internal.http.RetryableSink
  static printClass_RetryableSink(inputObj, prefixStr=""){
    // https://cs.android.com/android/platform/superproject/+/master:external/okhttp/repackaged/okhttp/src/main/java/com/android/okhttp/internal/http/RetryableSink.java
    // https://android.googlesource.com/platform/external/okhttp/+/refs/heads/main/okhttp/src/main/java/com/squareup/okhttp/internal/http/RetryableSink.java
    var newPrefStr  = prefixStr ? (prefixStr + " ") : prefixStr
    if (inputObj) {
      var curObj = inputObj
      console.log("curObj=" + curObj)

      var clsNameStr = FridaAndroidUtil.genClassNameStr(curObj)


      console.log(newPrefStr + "RetryableSink:" + clsNameStr
        + " closed=" + curObj.closed.value
        + ", limit=" + curObj.limit.value
        + ", contentLength()=" + curObj.contentLength()
        + ", content=" + curObj.content.value
      )

      FridaAndroidUtil.printClass_Buffer(curObj.content.value, prefixStr)
    } else {
      console.log("RetryableSink: null")
    }
  }

  static printClass_File(inputObj){
    // https://developer.android.com/reference/java/io/File
    if (inputObj) {
      if (FridaAndroidUtil.isClass_File(inputObj)){
        var curObj = FridaAndroidUtil.castToJavaClass(inputObj, FridaAndroidUtil.clsName_File)
        // console.log("curObj=" + curObj)

        var clsNameStr = FridaAndroidUtil.genClassNameStr(curObj)

        console.log("File:" + clsNameStr
          + " separator=" + curObj.separator.value
          + ", pathSeparator=" + curObj.pathSeparator.value
          + ", exists=" + curObj.exists()
          + ", name=" + curObj.getName()
          + ", absPath=" + curObj.getAbsolutePath()
        )
      } else {
        var curClsName = FridaAndroidUtil.getJavaClassName(inputObj)
        console.log(`printClass_File: ${inputObj} is not File class, curClsName=${curClsName}`)
      }
    } else {
      console.log(`printClass_File: inputObj is null`)
    }
  }

  // com.android.okhttp.okio.Buffer
  static printClass_Buffer(inputObj, prefixStr=""){
    // https://android.googlesource.com/platform/external/okhttp/+/refs/heads/main/okio/okio/src/main/java/okio/Buffer.java
    var newPrefStr  = prefixStr ? (prefixStr + " ") : prefixStr
    if (inputObj) {
      var curObj = inputObj
      console.log("curObj=" + curObj)

      var clsNameStr = FridaAndroidUtil.genClassNameStr(curObj)

      var byteArray = curObj.readByteArray()


      console.log(newPrefStr + "Buffer:" + clsNameStr
        // + " size=" + curObj.size.value
        + " size=" + curObj._size.value
        + ", head=" + curObj.head.value
        + ", toString()=" + curObj.toString()
        + ", byteArray=" + byteArray
      )
    } else {
      console.log("Buffer: null")
    }
  }

  // android.util.DisplayMetrics
  static printClass_DisplayMetrics(inputObj, prefixStr=""){
    const ClassName = "DisplayMetrics"
    // https://developer.android.com/reference/android/util/DisplayMetrics#DisplayMetrics()
    var newPrefStr  = prefixStr ? (prefixStr + " ") : prefixStr
    if (inputObj) {
      var curObj = inputObj
      console.log("curObj=" + curObj)

      var clsNameStr = FridaAndroidUtil.genClassNameStr(curObj)


      console.log(newPrefStr + ClassName + ":" + clsNameStr
        + " DENSITY_DEVICE_STABLE=" + curObj.DENSITY_DEVICE_STABLE.value
        + ", density=" + curObj.density.value
        + ", densityDpi=" + curObj.densityDpi.value
        + ", heightPixels=" + curObj.heightPixels.value
        + ", scaledDensity=" + curObj.scaledDensity.value
        + ", widthPixels=" + curObj.widthPixels.value
        + ", xdpi=" + curObj.xdpi.value
        + ", ydpi=" + curObj.ydpi.value
      )
    } else {
      console.log(ClassName + ": null")
    }
  }

  // android.content.pm.ConfigurationInfo
  static printClass_ConfigurationInfo(inputObj, prefixStr=""){
    const ClassName = "ConfigurationInfo"
    // https://developer.android.com/reference/android/content/pm/ConfigurationInfo#INPUT_FEATURE_FIVE_WAY_NAV
    var newPrefStr  = prefixStr ? (prefixStr + " ") : prefixStr
    if (inputObj) {
      var curObj = inputObj
      console.log("curObj=" + curObj)

      var clsNameStr = FridaAndroidUtil.genClassNameStr(curObj)


      console.log(newPrefStr + ClassName + ":" + clsNameStr
        + " reqGlEsVersion=" + curObj.reqGlEsVersion.value
        + ", reqInputFeatures=" + curObj.reqInputFeatures.value
        + ", reqKeyboardType=" + curObj.reqKeyboardType.value
        + ", reqNavigation=" + curObj.reqNavigation.value
        + ", reqTouchScreen=" + curObj.reqTouchScreen.value
      )
    } else {
      console.log(ClassName + ": null")
    }
  }

  // android.content.res.Configuration
  static printClass_Configuration(inputObj, prefixStr=""){
    const ClassName = "Configuration"
    // https://developer.android.com/reference/android/content/res/Configuration#screenLayout
    var newPrefStr  = prefixStr ? (prefixStr + " ") : prefixStr
    if (inputObj) {
      var curObj = inputObj
      console.log("curObj=" + curObj)

      var clsNameStr = FridaAndroidUtil.genClassNameStr(curObj)


      console.log(newPrefStr + ClassName + ":" + clsNameStr
        + " colorMode=" + curObj.colorMode.value
        + ", densityDpi=" + curObj.densityDpi.value
        + ", fontScale=" + curObj.fontScale.value
        + ", fontWeightAdjustment=" + curObj.fontWeightAdjustment.value
        + ", hardKeyboardHidden=" + curObj.hardKeyboardHidden.value
        + ", keyboard=" + curObj.keyboard.value
        + ", keyboardHidden=" + curObj.keyboardHidden.value
        + ", locale=" + curObj.locale.value
        + ", mcc=" + curObj.mcc.value
        + ", mnc=" + curObj.mnc.value
        + ", navigation=" + curObj.navigation.value
        + ", navigationHidden=" + curObj.navigationHidden.value
        + ", orientation=" + curObj.orientation.value
        + ", screenHeightDp=" + curObj.screenHeightDp.value
        + ", screenLayout=" + curObj.screenLayout.value
        + ", screenWidthDp=" + curObj.screenWidthDp.value
        + ", smallestScreenWidthDp=" + curObj.smallestScreenWidthDp.value
        + ", touchscreen=" + curObj.touchscreen.value
        + ", uiMode=" + curObj.uiMode.value
      )
    } else {
      console.log(ClassName + ": null")
    }
  }

  // android.content.pm.FeatureInfo
  static printClass_FeatureInfo(inputObj, prefixStr=""){
    const ClassName = "FeatureInfo"
    // https://developer.android.com/reference/android/content/pm/FeatureInfo
    var newPrefStr  = prefixStr ? (prefixStr + " ") : prefixStr
    if (inputObj) {
      var curObj = inputObj
      console.log("curObj=" + curObj)

      var clsNameStr = FridaAndroidUtil.genClassNameStr(curObj)


      console.log(newPrefStr + ClassName + ":" + clsNameStr
        + " flags=" + curObj.flags.value
        + ", name=" + curObj.name.value
        + ", reqGlEsVersion=" + curObj.reqGlEsVersion.value
        + ", version=" + curObj.version.value
      )
    } else {
      console.log(ClassName + ": null")
    }
  }

  // android.app.ActivityManager.MemoryInfo
  static printClass_ActivityManagerMemoryInfo(inputObj, prefixStr=""){
    const ClassName = "ActivityManager.MemoryInfo"
    // https://developer.android.com/reference/android/app/ActivityManager.MemoryInfo
    var newPrefStr  = prefixStr ? (prefixStr + " ") : prefixStr
    if (inputObj) {
      var curObj = inputObj
      console.log("curObj=" + curObj)

      var clsNameStr = FridaAndroidUtil.genClassNameStr(curObj)


      console.log(newPrefStr + ClassName + ":" + clsNameStr
        + " CREATOR=" + curObj.CREATOR.value
        + ", advertisedMem=" + curObj.advertisedMem.value
        + ", availMem=" + curObj.availMem.value
        + ", lowMemory=" + curObj.lowMemory.value
        + ", threshold=" + curObj.threshold.value
        + ", totalMem=" + curObj.totalMem.value
      )
    } else {
      console.log(ClassName + ": null")
    }
  }

  // android.os.Parcel
  static printClass_Parcel(inputObj, prefixStr=""){
    // https://developer.android.com/reference/android/os/Parcel
    const ClassName = "Parcel"
    var newPrefStr  = prefixStr ? (prefixStr + " ") : prefixStr
    if (inputObj) {
      var curClassName = FridaAndroidUtil.getJavaClassName(inputObj)
      if (curClassName === FridaAndroidUtil.clsName_Parcel) {
        var curObj = FridaAndroidUtil.castToJavaClass(inputObj, FridaAndroidUtil.clsName_Parcel)
        // console.log("curObj=" + curObj)

        var clsNameStr = FridaAndroidUtil.genClassNameStr(curObj)

        var stringCreatorValue = curObj.STRING_CREATOR.value
        var stringCreatorStr = FridaAndroidUtil.valueToNameStr(stringCreatorValue)

        var dataSize = curObj.dataSize()
        var dataPosition = curObj.dataPosition()
        var dataAvail = curObj.dataAvail()
        var dataCapacity = curObj.dataCapacity()
        var hasFileDescriptors = curObj.hasFileDescriptors()

        console.log(newPrefStr + ClassName + ":" + clsNameStr
          + " STRING_CREATOR=" + stringCreatorStr
          + ", dataSize=" + dataSize
          + ", dataPosition=" + dataPosition
          + ", dataAvail=" + dataAvail
          + ", dataCapacity=" + dataCapacity
          + ", hasFileDescriptors=" + hasFileDescriptors
        )
      } else {
        console.log(newPrefStr + ClassName + ": not a Parcel")
      }
    } else {
      console.log(newPrefStr + ClassName + ": null")
    }
  }

  // static printRequestBodyInfo(urlConn){
  //   console.log("printRequestBodyInfo: urlConn=" + urlConn)
  //   var requestBody = urlConn.getOutputStream()
  //   console.log("requestBody=" + requestBody)
  //   var reqBodyClsName = FridaAndroidUtil.getJavaClassName(requestBody)
  //   console.log("reqBodyClsName=" + reqBodyClsName)
  // }

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

  // java ArrayList (byte array / List<Integer> / ArrayList<Map.Entry<String, String>> ) to string
  static javaArrayListToStr(javaArraryList){
    // var jsArrayList = FridaAndroidUtil.javaByteArrToJsByteArr(javaArraryList)
    // console.log("jsArrayList=" + jsArrayList)
    // var jsArrayListStr = jsArrayList.toString()
    // console.log("jsArrayListStr=" + jsArrayListStr)
    // return jsArrayListStr

    var javaObjList = javaArraryList.toArray()
    console.log("javaObjList=" +  javaObjList)
    var javaObjListStr = javaObjList.toString()
    console.log("javaObjListStr=" +  javaObjListStr)
    return javaObjListStr
  }

  // java ByteBuffer to String
  static javaByteBufferToStr(byteBufer, isFlip=true){
    // console.log(`javaByteBufferToStr: byteBufer=${byteBufer}`)
    // javaByteBufferToStr: byteBufer=java.nio.DirectByteBuffer[pos=793 lim=16375 cap=16375]
    if(isFlip){
      byteBufer.flip() // rewind to start position
      console.log(`after flip: ${byteBufer}`)
      // after java.nio.DirectByteBuffer[pos=0 lim=793 cap=16375] flip
    }
    // var utf8CharBuffer = FridaAndroidUtil.StandardCharsets.UTF_8.decode(byteBufer)
    // var charsetUtf8 = FridaAndroidUtil.StandardCharsets.UTF_8
    var charsetUtf8 = FridaAndroidUtil.StandardCharsets.UTF_8.value
    // console.log("charsetUtf8=" + charsetUtf8)
    // charsetUtf8=UTF-8
    var utf8CharBuffer = charsetUtf8.decode(byteBufer)
    // console.log("utf8CharBuffer=" + utf8CharBuffer)
    var utf8BufStr = utf8CharBuffer.toString()
    // console.log("utf8BufStr=" + utf8BufStr)
    return utf8BufStr
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

  // generate the class name string
  // eg: "<clsName=fjiq>"
  static genClassNameStr(curObj){
    var objClsName = FridaAndroidUtil.getJavaClassName(curObj)
    var classNameStr = `<clsName=${objClsName}>`
    return classNameStr
  }

  // generate the class name and value string from current object
  // eg: "<clsName=fjiq>=[object Object]"
  static valueToNameStr(curObj){
    var retStr = ""
    if (curObj){
      var classNameStr = FridaAndroidUtil.genClassNameStr(curObj)
      retStr = `${classNameStr}=${curObj}`
    } else {
      retStr = "<clsName=null>=null"
    }
    return retStr
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

  static printNothing(funcName, funcParaDict){
  }

  static printFunctionCallStr(funcName, funcParaDict){
    // var functionCallStr = this.genFunctionCallStr(funcName, funcParaDict)
    var functionCallStr = FridaAndroidUtil.genFunctionCallStr(funcName, funcParaDict)
    console.log(functionCallStr)
  }

  // generate function call and stack string
  static genFunctionCallAndStack(funcName, funcParaDict, isPrintDelimiter=true){
    // console.log(`funcName=${funcName}, funcParaDict=${funcParaDict}, isPrintDelimiter=${isPrintDelimiter}`)
    var functionCallAndStackStr = ""

    var functionCallStr = FridaAndroidUtil.genFunctionCallStr(funcName, funcParaDict)

    var stackStr = FridaAndroidUtil.genStackStr(funcName)

    var delimiterStr = ""
    if(isPrintDelimiter){
      var delimiterFuncName = funcName
      const LineMaxSize = 80
      // const LineMaxSize = 120
      // const LineMaxSize = 160
      if (funcName.length > LineMaxSize) {
        // ConnectionsManager.init(version,layer,apiId,deviceModel,systemVersion,appVersion,langCode,systemLangCode,configPath,logPath,regId,cFingerprint,timezoneOffset,userId,userPremium,enablePushConnection) -> ConnectionsManager.init
        // var shortFuncName = funcName.replace('/([\w\.\:]+)\(.+\)/', "$1")
        var shortFuncName = funcName.replace(/([\w\.\:]+)\(.+\)/, "$1")
        // console.log("shortFuncName=" + shortFuncName)
        delimiterFuncName = shortFuncName
      }
      // JsUtil.logStr(delimiterFuncName)
      delimiterStr = JsUtil.generateLineStr(delimiterFuncName, true, "=", LineMaxSize)
      delimiterStr = delimiterStr + "\n"
      // console.log("delimiterStr=" + delimiterStr)
    }

    var functionCallAndStackStr = `${delimiterStr}${functionCallStr}\n${stackStr}`
    return functionCallAndStackStr
  }

  // Check whether to show log or not, and show (function call and stack) log if necessary
  static showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict, isShowLogDefault=true){
    var isShowLog = isShowLogDefault
    var curFuncCallStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)

    if (null != callback_isShowLog) {
      isShowLog = callback_isShowLog(curFuncCallStackStr)
    }

    if (isShowLog){
      console.log(curFuncCallStackStr)
    }

    return isShowLog
  }

  // Check whether to show log or not, and show input log if necessary
  static showLogIfNecessary(callback_isShowLog, curLogStr, isShowLogDefault=true){
    var isShowLog = isShowLogDefault

    if (null != callback_isShowLog) {
      isShowLog = callback_isShowLog(curLogStr)
    }

    if (isShowLog){
      console.log(curLogStr)
    }

    return isShowLog
  }

  // print Function call and stack trace string
  static printFunctionCallAndStack(funcName, funcParaDict, whiteList=undefined, isPrintDelimiter=true){
    // console.log("whiteList=" + whiteList + ", isPrintDelimiter=" + isPrintDelimiter)

    var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict, isPrintDelimiter)

    var needPrint = true

    if (whiteList != undefined) {
      needPrint = false

      for (const curFilter of whiteList) {
        // console.log("curFilter=" + curFilter)
        if (funcCallAndStackStr.includes(curFilter)) {
          needPrint = true
          // console.log("needPrint=" + needPrint)
          break
        }
      }
    }

    if (needPrint) {
      console.log(funcCallAndStackStr)
    }
  }

  // common function to decide whether to show log or not
  static func_isShowLog_common(curStr, includeList=[], excludeList=[]){
    // let isShowLog = true
    let isShowLog = false

    // const includeList = [
    //   "X.02J",
    // ]
    for(const eachInclude of includeList){
      if (curStr.includes(eachInclude)){
        isShowLog = true
        break
      }
    }

    // const excludeList = [
    // ]
    // console.log(`excludeList=${excludeList}`)
    for(const eachExclude of excludeList){
      // console.log(`eachExclude=${eachExclude}`)
      if (curStr.includes(eachExclude)){
        // console.log(`eachExclude=${eachExclude} inside curStr=${curStr} => should exclude => is not show log`)
        isShowLog = false
        break
      }
    }

    return isShowLog
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


  static findOverloadFunction(overloads, argTypeList, retType=null){
    var foundOverloadFunc = null

    var argTypeNum = argTypeList.length
    // console.log("argTypeNum=" + argTypeNum)

    overloads.find( function(curOverloadFunc) {
      var overloadArgTypeList = curOverloadFunc.argumentTypes
      // console.log("overloadArgTypeList=" + overloadArgTypeList)
      if ((overloadArgTypeList) && (argTypeNum == overloadArgTypeList.length)){
        var argsFromOverload = curOverloadFunc.argumentTypes.map(argType => argType.className)
        // console.log("argsFromOverload=" + argsFromOverload)
        var overloadArgListJsonStr = JSON.stringify(argsFromOverload)
        // console.log("overloadArgListJsonStr=" + overloadArgListJsonStr)
        var inputArgListJsonStr = JSON.stringify(argTypeList)
        // console.log("inputArgListJsonStr=" + inputArgListJsonStr)
        var isArgsSame = overloadArgListJsonStr === inputArgListJsonStr
        // console.log("isArgsSame=" + isArgsSame)
        if (isArgsSame){
          if (retType){
            var mappedTypeStr = retType
            if (mappedTypeStr in FridaAndroidUtil.FridaDexTypeMapppingDict){
              mappedTypeStr = FridaAndroidUtil.FridaDexTypeMapppingDict[mappedTypeStr]
              // console.log("mapped mappedTypeStr=" + mappedTypeStr)
            }

            var overloadFuncRetType = curOverloadFunc.returnType
            // console.log("overloadFuncRetType=" + overloadFuncRetType)
            var overloadFuncRetTypeStr = overloadFuncRetType.toString()
            // console.log("overloadFuncRetTypeStr=" + overloadFuncRetTypeStr)
            if (mappedTypeStr === overloadFuncRetTypeStr){
              foundOverloadFunc = curOverloadFunc
              return foundOverloadFunc
            } else {
              // console.log("returnType not same: mapped=" + mappedTypeStr + " != current=" + overloadFuncRetTypeStr)
            }
          }
        }
      }
    })

    // console.log("foundOverloadFunc=" + foundOverloadFunc)
    return foundOverloadFunc
  }

  static findClassLoader(className){
    var foundClassLoader = null

    const classLoaders = Java.enumerateClassLoadersSync()
    // console.log("classLoaders=" + classLoaders + ", type=" + (typeof classLoaders))

    for (const loaderIdx in classLoaders) {
      var curClassLoader = classLoaders[loaderIdx]
      var loaderClsName = FridaAndroidUtil.getJavaClassName(curClassLoader)
      console.log(`[${loaderIdx}] loaderClsName=${loaderClsName}, curClassLoader=${curClassLoader}`)

      try {
        if (curClassLoader.findClass(className)){
          // console.log(`Found ${className} in loader ${curClassLoader}`)
          // Found org.chromium.net.impl.CronetUrlRequest in loader dalvik.system.DelegateLastClassLoader[DexPathList[[zip file "/data/user_de/0/com.google.android.gms/app_chimera/m/00000013/CronetDynamite.apk"],nativeLibraryDirectories=[/data/user_de/0/com.google.android.gms/app_chimera/m/00000013/CronetDynamite.apk!/lib/arm64-v8a, /system/lib64, /system_ext/lib64]]]
          foundClassLoader = curClassLoader
          break
        }
      } catch (err){
        // console.log(`${err}`)
      }
    }

    console.log(`findClassLoader: className=${className} => foundClassLoader=${foundClassLoader}`)
    return foundClassLoader
  }

  static setClassLoder(newClassLoader){
    // var oldClassLoader = Java.classFactory.loader
    // console.log(`oldClassLoader=${oldClassLoader}`)
    Java.classFactory.loader = newClassLoader
    console.log(`Set ClassLoader to ${newClassLoader}`)
  }

  static updateClassLoader(className){
    var foundClassLoader = FridaAndroidUtil.findClassLoader(className)
    console.log(`foundClassLoader=${foundClassLoader}`)
    if(foundClassLoader) {
      FridaAndroidUtil.setClassLoder(foundClassLoader)
    } else {
      console.error(`Fail to find classLoader for ${className}`)
    }
  }

}
