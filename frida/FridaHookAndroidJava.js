/*
	File: FridaHookAndroidJava.js
	Function: crifan's Frida hook common Android Java related functions
	Author: Crifan Li
	Latest: https://github.com/crifan/JsFridaUtil/blob/main/frida/FridaHookAndroidJava.js
	Updated: 20250304
*/

// Frida hook common Android/Java class
class FridaHookAndroidJava {
  constructor() {
    console.log("FridaHookAndroidJava constructor")
  }

  static clsName_HttpURLConnection = "java.net.HttpURLConnection"
  static clsName_URLConnection = "java.net.URLConnection"

  static isClass_HttpURLConnection(curObj){
    var isClsHttpURLConnection = FridaAndroidUtil.isJavaClass(curObj, FridaHookAndroidJava.clsName_HttpURLConnection)
    console.log("curObj=" + curObj + " -> isClsHttpURLConnection=" + isClsHttpURLConnection)
    return isClsHttpURLConnection
  }

  static isClass_URLConnection(curObj){
    var isClsURLConnection = FridaAndroidUtil.isJavaClass(curObj, FridaHookAndroidJava.clsName_URLConnection)
    console.log("curObj=" + curObj + " -> isClsURLConnection=" + isClsURLConnection)
    return isClsURLConnection
  }

  // java.net.URLConnection
  static printClass_URLConnection(inputObj){
    if (inputObj) {
      var curObj = FridaAndroidUtil.castToJavaClass(inputObj, FridaHookAndroidJava.clsName_URLConnection)
      console.log("curObj=" + curObj)

      // for debug
      var curClsName = FridaAndroidUtil.getJavaClassName(curObj)
      console.log("URLConnection: curClsName=" + curClsName)

      // if (FridaHookAndroidJava.isClass_URLConnection(curObj)){
        console.log("URLConnection:"
          + " url=" + curObj.url.value
          + ", connected=" + curObj.connected.value
          + ", doInput=" + curObj.doInput.value
          + ", doOutput=" + curObj.doOutput.value
          + ", allowUserInteraction=" + curObj.allowUserInteraction.value
          + ", useCaches=" + curObj.useCaches.value
          + ", ifModifiedSince=" + curObj.ifModifiedSince.value
  
          // extra fields for: Android / (java) private?
          //  https://cs.android.com/android/platform/superproject/main/+/main:libcore/ojluni/src/main/java/java/net/URLConnection.java;drc=bd205f23c74d7498c9958d2bfa8622aacfe59517;l=161
          + ", defaultAllowUserInteraction=" + curObj.defaultAllowUserInteraction.value
          + ", defaultUseCaches=" + curObj.defaultUseCaches.value
          + ", connectTimeout=" + curObj.connectTimeout.value
          + ", readTimeout=" + curObj.readTimeout.value
          + ", requests=" + curObj.requests.value
          + ", fileNameMap=" + curObj.fileNameMap.value
        )

        // var curUrl = curObj.getURL()
        // console.log("URLConnection: curUrl=" + curUrl)
        // var curDoOutput = curObj.getDoOutput()
        // console.log("URLConnection: curDoOutput=" + curDoOutput)

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
      var curObj = FridaAndroidUtil.castToJavaClass(inputObj, FridaHookAndroidJava.clsName_HttpURLConnection)
      console.log("curObj=" + curObj)

      // for debug
      var curClsName = FridaAndroidUtil.getJavaClassName(curObj)
      console.log("HttpURLConnection: curClsName=" + curClsName)

      // if (FridaHookAndroidJava.isClass_HttpURLConnection(curObj)){
        // var headerFields = curObj.getHeaderFields()
        // console.log("HttpURLConnection: headerFields=" + headerFields)
        // var reqMethod = curObj.getRequestMethod()
        // console.log("HttpURLConnection: reqMethod=" + reqMethod)

        console.log("HttpURLConnection:"
          + "  method=" + curObj.method.value
          + ", chunkLength=" + curObj.chunkLength.value
          + ", fixedContentLength=" + curObj.fixedContentLength.value
          + ", fixedContentLengthLong=" + curObj.fixedContentLengthLong.value
          + ", responseCode=" + curObj.responseCode.value
          + ", responseMessage=" + curObj.responseMessage.value
          + ", instanceFollowRedirects=" + curObj.instanceFollowRedirects.value
          + ", followRedirects=" + curObj.followRedirects.value
        )

      // } else {
      //   console.warn(curObj + " is Not HttpURLConnection")
      // }

      FridaHookAndroidJava.printClass_URLConnection(curObj)
    } else {
      console.log("HttpURLConnection: null")
    }
  }

  static JSONObject() {
    /******************** org.json.JSONObject ********************/
    var className_JSONObject = "org.json.JSONObject"
    // FridaAndroidUtil.printClassAllMethodsFields(className_JSONObject)

    var cls_JSONObject = Java.use(className_JSONObject)
    console.log("cls_JSONObject=" + cls_JSONObject)

    // public org.json.JSONObject org.json.JSONObject.put(java.lang.String,java.lang.Object) throws org.json.JSONException
    var func_JSONObject_put = cls_JSONObject.put.overload('java.lang.String', 'java.lang.Object')
    console.log("func_JSONObject_put=" + func_JSONObject_put)
    if (func_JSONObject_put) {
      func_JSONObject_put.implementation = function (str, obj) {
        var funcName = "JSONObject.put(str,obj)"
        var funcParaDict = {
          "str": str,
          "obj": obj,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.put(str, obj)
      }
    }

  }

  static String(callback_String_equals=null) {
    /******************** java.lang.String ********************/
    var className_String = "java.lang.String"
    // FridaAndroidUtil.printClassAllMethodsFields(className_String)

    var cls_String = Java.use(className_String)
    console.log("cls_String=" + cls_String)

    // public String(String original)
    var func_String_ctor = cls_String.$init.overload('java.lang.String')
    // var func_String_ctor = cls_String.getInstance.overload('java.lang.String')
    // var func_String_ctor = cls_String.$new.overload('java.lang.String')
    console.log("func_String_ctor=" + func_String_ctor)
    if (func_String_ctor) {
      func_String_ctor.implementation = function (original) {
        var funcName = "String(orig)"
        var funcParaDict = {
          "original": original,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.$init(original)
      }
    }

    // public boolean equals(Object anObject)
    // public boolean java.lang.String.equals(java.lang.Object)
    var func_String_equals = cls_String.equals
    console.log("func_String_equals=" + func_String_equals)
    if (func_String_equals) {
      func_String_equals.implementation = function (anObject) {
        var funcName = "String.equals(anObject)"
        var funcParaDict = {
          "anObject": anObject,
        }

        var isPrintStack = false
        if(null != callback_String_equals) {
          isPrintStack = callback_String_equals(anObject)
        }

        if(isPrintStack){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        }

        return this.equals(anObject)
      }
    }

  }

  static URL(callback_isPrintStack_URL_init=null) {
    var className_URL = "java.net.URL"
    // FridaAndroidUtil.printClassAllMethodsFields(className_URL)

    var cls_URL = Java.use(className_URL)
    console.log("cls_URL=" + cls_URL)

    // public URL(String url)
    // var func_URL_init = cls_URL.$init
    var func_URL_init = cls_URL.$init.overload('java.lang.String')
    console.log("func_URL_init=" + func_URL_init)
    if (func_URL_init) {
      func_URL_init.implementation = function (url) {
        var funcName = "URL(url)"
        var funcParaDict = {
          "url": url,
        }

        var isPrintStack = false
        if (null != callback_isPrintStack_URL_init){
          isPrintStack = callback_isPrintStack_URL_init(url)
        }

        if (isPrintStack){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        }

        return this.$init(url)
      }
    }
  }

  static HashMap(callback_isPrintStack_put=null, callback_isPrintStack_putAll=null, callback_isPrintStack_get=null) {
    /******************** java.util.HashMap ********************/
    var className_HashMap = "java.util.HashMap"
    // FridaAndroidUtil.printClassAllMethodsFields(className_HashMap)

    var cls_HashMap = Java.use(className_HashMap)
    console.log("cls_HashMap=" + cls_HashMap)
    // var instance_HashMap = cls_HashMap.$new()
    // console.log("instance_HashMap=" + instance_HashMap)

    // public java.lang.Object java.util.HashMap.put(java.lang.Object,java.lang.Object)
    // var func_HashMap_put = cls_HashMap.put('java.lang.Object', 'java.lang.Object')
    // var func_HashMap_put = instance_HashMap.put('java.lang.Object', 'java.lang.Object')
    var func_HashMap_put = cls_HashMap.put
    console.log("func_HashMap_put=" + func_HashMap_put)
    if (func_HashMap_put) {
      func_HashMap_put.implementation = function (keyObj, valueObj) {
        var funcName = "HashMap.put(key,val)"
        var funcParaDict = {
          "keyObj": keyObj,
          "valueObj": valueObj,
        }

        if (null != keyObj) {
          // console.log("keyObj=" + keyObj)
          // console.log("keyObj.value=" + keyObj.value)
          // console.log("keyObj=" + keyObj + ", valueObj=" + valueObj)

          var isPrintStack = false

          // isPrintStack = HookDouyin_feedUrl.HashMap(keyObj, valueObj)
          if (null != callback_isPrintStack_put){
            isPrintStack = callback_isPrintStack_put(keyObj, valueObj)
          }

          if (isPrintStack) {
            FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
          }
        }

        return this.put(keyObj, valueObj)
      }
    }

    // public void java.util.HashMap.putAll(java.util.Map)
    // var func_HashMap_putAll = cls_HashMap.putAll('java.util.Map')
    var func_HashMap_putAll = cls_HashMap.putAll
    console.log("func_HashMap_putAll=" + func_HashMap_putAll)
    if (func_HashMap_putAll) {
      func_HashMap_putAll.implementation = function (newMap) {
        var funcName = "HashMap.putAll(map)"
        var funcParaDict = {
          "newMap": newMap,
        }
        // console.log("newMap=" + newMap)
        var isPrintStack = false
        if (null != callback_isPrintStack_putAll){
          isPrintStack = callback_isPrintStack_putAll(newMap)
        }

        if (isPrintStack){
          console.log("newMapStr=" + FridaAndroidUtil.mapToStr(newMap))
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        }

        return this.putAll(newMap)
      }
    }

    // https://docs.oracle.com/javase/8/docs/api/java/util/HashMap.html#get-java.lang.Object-
    // public V get(Object key)
    var func_HashMap_get = cls_HashMap.get
    console.log("func_HashMap_get=" + func_HashMap_get)
    if (func_HashMap_get) {
      func_HashMap_get.implementation = function (keyObj) {
        var funcName = "HashMap.get(key)"
        var funcParaDict = {
          "keyObj": keyObj,
        }

        var isPrintStack = false
        if (null != callback_isPrintStack_get){
          isPrintStack = callback_isPrintStack_get(keyObj)
        }

        if (isPrintStack){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        }

        var retValObj = this.get(keyObj)
        if (isPrintStack){
          console.log("retValObj=" + retValObj)
        }
        return retValObj
      }
    }

  }
  
  static LinkedHashMap() {
    /******************** java.util.LinkedHashMap ********************/
    var className_LinkedHashMap = "java.util.LinkedHashMap"
    // FridaAndroidUtil.printClassAllMethodsFields(className_LinkedHashMap)

    var cls_LinkedHashMap = Java.use(className_LinkedHashMap)
    console.log("cls_LinkedHashMap=" + cls_LinkedHashMap)

  }

  static RandomAccessFile() {
    /******************** java.io.RandomAccessFile ********************/
    var className_RandomAccessFile = "java.io.RandomAccessFile"
    // FridaAndroidUtil.printClassAllMethodsFields(className_RandomAccessFile)

    var cls_RandomAccessFile = Java.use(className_RandomAccessFile)
    console.log("cls_RandomAccessFile=" + cls_RandomAccessFile)

    // public final java.nio.channels.FileChannel java.io.RandomAccessFile.getChannel()
    var func_RandomAccessFile_getChannel = cls_RandomAccessFile.getChannel
    console.log("func_RandomAccessFile_getChannel=" + func_RandomAccessFile_getChannel)
    if (func_RandomAccessFile_getChannel) {
      func_RandomAccessFile_getChannel.implementation = function () {
        var funcName = "RandomAccessFile.getChannel()"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var fileChannel = this.getChannel()
        console.log("fileChannel=" + fileChannel)
        var filePathValue = this.path.value
        console.log("filePathValue=" + filePathValue)
        return fileChannel
      }
    }
  }

  static NetworkRequest_Builder(){
    var clsName_NetworkRequest_Builder = "android.net.NetworkRequest$Builder"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_NetworkRequest_Builder)

    var cls_NetworkRequest_Builder = Java.use(clsName_NetworkRequest_Builder)
    console.log("cls_NetworkRequest_Builder=" + cls_NetworkRequest_Builder)

    // public Builder ()
    var func_NetworkRequest_Builder_ctor_void = cls_NetworkRequest_Builder.$init.overload()
    console.log("func_NetworkRequest_Builder_ctor_void=" + func_NetworkRequest_Builder_ctor_void)
    if (func_NetworkRequest_Builder_ctor_void) {
      func_NetworkRequest_Builder_ctor_void.implementation = function () {
        var funcName = "NetworkRequest$Builder()"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var newBuilder_void = this.$init()
        console.log("newBuilder_void=" + newBuilder_void)
        return newBuilder_void
      }
    }

    // // Note: Xiaomi8 not exist: .overload('android.net.NetworkRequest')
    // //    -> Error: NetworkRequest$Builder(): specified argument types do not match any of: .overload()
    // // public Builder (NetworkRequest request)
    // var func_NetworkRequest_Builder_ctor_req = cls_NetworkRequest_Builder.$init.overload('android.net.NetworkRequest')
    // console.log("func_NetworkRequest_Builder_ctor_req=" + func_NetworkRequest_Builder_ctor_req)
    // if (func_NetworkRequest_Builder_ctor_req) {
    //   func_NetworkRequest_Builder_ctor_req.implementation = function (request) {
    //     var funcName = "NetworkRequest$Builder(request)"
    //     var funcParaDict = {
    //     }
    //     FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
    //     var newBuilder_req = this.$init(request)
    //     console.log("newBuilder_req=" + newBuilder_req)
    //     return newBuilder_req
    //   }
    // }

  }

  static File(callback_File_ctor_str=null) {
    var className_File = "java.io.File"
    // FridaAndroidUtil.printClassAllMethodsFields(className_File)

    var cls_File = Java.use(className_File)
    console.log("cls_File=" + cls_File)

    // File(String pathname)
    var func_File_ctor_path = cls_File.$init.overload('java.lang.String')
    console.log("func_File_ctor_path=" + func_File_ctor_path)
    if (func_File_ctor_path) {
      func_File_ctor_path.implementation = function (pathname) {
        var funcName = "File(pathname)"
        var funcParaDict = {
          "pathname": pathname,
        }

        var isMatch = false
        if (null != callback_File_ctor_str){
          isMatch = callback_File_ctor_str(pathname)
        }

        if (isMatch){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        }

        // tmp use previould check to bypass new File
        // if (isMatch) {
        //   // return null
        //   pathname = "" // hook bypass return empty File by empty filename
        // }

        var retFile_ctor_path = this.$init(pathname)

        // if (isMatch) {
          console.log("pathname=" + pathname + " => retFile_ctor_path=" + retFile_ctor_path)
        // }

        return retFile_ctor_path
      }
    }

    // public boolean exists ()
    var func_File_exists = cls_File.exists
    console.log("func_File_exists=" + func_File_exists)
    if (func_File_exists) {
      func_File_exists.implementation = function () {
        var funcName = "File.exists()"
        var funcParaDict = {
        }

        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBool_File_exists = this.exists()
        var fileAbsPath = this.getAbsolutePath()
        console.log("fileAbsPath=" + fileAbsPath + " => retBool_File_exists=" + retBool_File_exists)
        return retBool_File_exists
      }
    }

  }

  static Settings_getInt(cls_Settings, Settings_getInt_crName=null, Settings_getInt_crNameDef=null) {
    // static int	getInt(ContentResolver cr, String name)
    // public static int android.provider.Settings$Global.getInt(android.content.ContentResolver,java.lang.String) throws android.provider.Settings$SettingNotFoundException

    // public static int getInt (ContentResolver cr, String name)
    // public static int android.provider.Settings$Secure.getInt(android.content.ContentResolver,java.lang.String) throws android.provider.Settings$SettingNotFoundException

    var func_Settings_getInt_crName = cls_Settings.getInt.overload("android.content.ContentResolver", "java.lang.String")
    console.log("func_Settings_getInt_crName=" + func_Settings_getInt_crName)
    if (func_Settings_getInt_crName) {
      func_Settings_getInt_crName.implementation = function (cr, name) {
        var funcName = "getInt(cr,name)"
        var funcParaDict = {
          "cr": cr,
          "name": name,
        }

        var isMatch = false
        if (null != Settings_getInt_crName){
          isMatch = Settings_getInt_crName(cr, name)
        }

        var retInt_Settings_getInt_crName = 0

        if (isMatch){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

          // retInt_Settings_getInt_crName = 0 // do hook bypass for development_settings_enabled, adb_enabled
          retInt_Settings_getInt_crName = this.getInt(cr, name) // no hook
        } else {
          retInt_Settings_getInt_crName = this.getInt(cr, name)
        }

        console.log("name" + name + " => retInt_Settings_getInt_crName=" + retInt_Settings_getInt_crName)
        return retInt_Settings_getInt_crName
      }
    }

    // static int	getInt(ContentResolver cr, String name, int def)
    // public static int android.provider.Settings$Global.getInt(android.content.ContentResolver,java.lang.String,int)

    // static int	getInt(ContentResolver cr, String name, int def)
    // public static int android.provider.Settings$Secure.getInt(android.content.ContentResolver,java.lang.String,int)

    var func_Settings_getInt_crNameDef = cls_Settings.getInt.overload("android.content.ContentResolver", "java.lang.String", "int")
    console.log("func_Settings_getInt_crNameDef=" + func_Settings_getInt_crNameDef)
    if (func_Settings_getInt_crNameDef) {
      func_Settings_getInt_crNameDef.implementation = function (cr, name, def) {
        var funcName = "getInt(cr,name,def)"
        var funcParaDict = {
          "cr": cr,
          "name": name,
          "def": def,
        }

        var isMatch = false
        if (null != Settings_getInt_crNameDef){
          isMatch = Settings_getInt_crNameDef(cr, name, def)
        }

        var retInt_Settings_getInt_crNameDef = 0

        if (isMatch){
          console.log("isMatch=" + isMatch)
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

          // retInt_Settings_getInt_crNameDef = 0 // do hook bypass for development_settings_enabled, adb_enabled
          retInt_Settings_getInt_crNameDef = this.getInt(cr, name, def) // no hook
        } else {
          retInt_Settings_getInt_crNameDef = this.getInt(cr, name, def)
        }

        console.log("name=" + name + " => retInt_Settings_getInt_crNameDef=" + retInt_Settings_getInt_crNameDef)
        return retInt_Settings_getInt_crNameDef
      }
    }

  }

  static SettingsGlobal(SettingsGlobal_getInt_crName=null, SettingsGlobal_getInt_crNameDef=null) {
    var className_SettingsGlobal = "android.provider.Settings$Global"
    // FridaAndroidUtil.printClassAllMethodsFields(className_SettingsGlobal)

    var cls_SettingsGlobal = Java.use(className_SettingsGlobal)
    console.log("cls_SettingsGlobal=" + cls_SettingsGlobal)

    FridaHookAndroidJava.Settings_getInt(cls_SettingsGlobal, SettingsGlobal_getInt_crName, SettingsGlobal_getInt_crNameDef)
  }

  static SettingsSecure(SettingsSecure_getInt_crName=null, SettingsSecure_getInt_crNameDef=null) {
    var className_SettingsSecure = "android.provider.Settings$Secure"
    // FridaAndroidUtil.printClassAllMethodsFields(className_SettingsSecure)

    var cls_SettingsSecure = Java.use(className_SettingsSecure)
    console.log("cls_SettingsSecure=" + cls_SettingsSecure)

    FridaHookAndroidJava.Settings_getInt(cls_SettingsSecure, SettingsSecure_getInt_crName, SettingsSecure_getInt_crNameDef)
  }

  static NetworkInterface(NetworkInterface_getName=null) {
    var className_NetworkInterface = "java.net.NetworkInterface"
    // FridaAndroidUtil.printClassAllMethodsFields(className_NetworkInterface)

    var cls_NetworkInterface = Java.use(className_NetworkInterface)
    console.log("cls_NetworkInterface=" + cls_NetworkInterface)

    // public String getName()
    // public java.lang.String java.net.NetworkInterface.getName()
    var func_NetworkInterface_getName = cls_NetworkInterface.getName
    console.log("func_NetworkInterface_getName=" + func_NetworkInterface_getName)
    if (func_NetworkInterface_getName) {
      func_NetworkInterface_getName.implementation = function () {
        var funcName = "NetworkInterface.getName()"
        var funcParaDict = {
        }

        var retName = this.getName()

        var isMatch = false
        if (null != NetworkInterface_getName){
          isMatch = NetworkInterface_getName(retName)
        }

        if (isMatch){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

          // do hook bypass
          // retName = "fakeName"
          // retName = ""

          // no hook
        } else {
          // no hook
        }

        console.log("retName=" + retName)
        return retName
      }
    }

  }

  static PackageManager(PackageManager_getApplicationInfo=null) {
    var className_PackageManager = "android.content.pm.PackageManager"
    // FridaAndroidUtil.printClassAllMethodsFields(className_PackageManager)

    var cls_PackageManager = Java.use(className_PackageManager)
    console.log("cls_PackageManager=" + cls_PackageManager)

    // // Note: Xiaomi8 not exist: getApplicationInfo.overload('java.lang.String', 'android.content.pm.PackageManager$ApplicationInfoFlags')
    // // public ApplicationInfo getApplicationInfo(String packageName, PackageManager.ApplicationInfoFlags flags)
    // // public android.content.pm.ApplicationInfo android.content.pm.PackageManager.getApplicationInfo(java.lang.String,android.content.pm.PackageManager$ApplicationInfoFlags) throws android.content.pm.PackageManager$NameNotFoundException
    // // var func_PackageManager_getApplicationInfo = cls_PackageManager.getApplicationInfo
    // var func_PackageManager_getApplicationInfo = cls_PackageManager.getApplicationInfo.overload('java.lang.String', 'android.content.pm.PackageManager$ApplicationInfoFlags')
    // // var func_PackageManager_getApplicationInfo = cls_PackageManager.getApplicationInfo.overload('java.lang.String', 'android.content.pm.PackageManager.ApplicationInfoFlags')
    // console.log("func_PackageManager_getApplicationInfo=" + func_PackageManager_getApplicationInfo)
    // if (func_PackageManager_getApplicationInfo) {
    //   func_PackageManager_getApplicationInfo.implementation = function (packageName, flags) {
    //     var funcName = "PackageManager.getApplicationInfo(packageName,flags)"
    //     var funcParaDict = {
    //       "packageName": packageName,
    //       "flags": flags,
    //     }

    //     var retAppInfo = this.getApplicationInfo(packageName, flags)

    //     var isMatch = false
    //     if (null != PackageManager_getApplicationInfo){
    //       isMatch = PackageManager_getApplicationInfo(packageName)
    //     }

    //     if (isMatch){
    //       FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

    //       // do hook bypass
    //       retAppInfo = ApplicationInfo()
    //     } else {
    //       // no hook
    //     }

    //     console.log("retAppInfo=" + retAppInfo)
    //     return retAppInfo
    //   }
    // }

    // public abstract ApplicationInfo getApplicationInfo (String packageName, int flags)
    // public abstract android.content.pm.ApplicationInfo android.content.pm.PackageManager.getApplicationInfo(java.lang.String,int) throws android.content.pm.PackageManager$NameNotFoundException
    var func_PackageManager_getApplicationInfo_abstract = cls_PackageManager.getApplicationInfo.overload('java.lang.String', 'int')
    console.log("func_PackageManager_getApplicationInfo_abstract=" + func_PackageManager_getApplicationInfo_abstract)
    if (func_PackageManager_getApplicationInfo_abstract) {
      func_PackageManager_getApplicationInfo_abstract.implementation = function (pkgName, flags) {
        var funcName = "PackageManager.getApplicationInfo(pkgName,flags)"
        var funcParaDict = {
          "pkgName": pkgName,
          "flags": flags,
        }

        var retAppInfo_abstract = this.getApplicationInfo(pkgName, flags)

        var isMatch = false
        if (null != PackageManager_getApplicationInfo){
          isMatch = PackageManager_getApplicationInfo(pkgName)
        }

        if (isMatch){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

          // // do hook bypass
          // retAppInfo_abstract = ApplicationInfo()
        } else {
          // no hook
        }

        console.log("retAppInfo_abstract=" + retAppInfo_abstract)
        return retAppInfo_abstract
      }
    }

  }

  static System(callback_isMatch_System_getProperty=null) {
    var className_System = "java.lang.System"
    // FridaAndroidUtil.printClassAllMethodsFields(className_System)

    var cls_System = Java.use(className_System)
    console.log("cls_System=" + cls_System)

    // public static String getProperty(String key) 
    // public static java.lang.String java.lang.System.getProperty(java.lang.String)
    var func_System_getProperty_key = cls_System.getProperty.overload('java.lang.String')
    console.log("func_System_getProperty_key=" + func_System_getProperty_key)
    if (func_System_getProperty_key) {
      func_System_getProperty_key.implementation = function (key) {
        var funcName = "System.getProperty(key)"
        var funcParaDict = {
          "key": key,
        }

        var isMatch = false
        if (null != callback_isMatch_System_getProperty){
          isMatch = callback_isMatch_System_getProperty(key)
        }

        if (isMatch){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        }

        var retPropVal = this.getProperty(key)
        if (isMatch){
          retPropVal = null // enable hook bypass: return null
          console.log("key=" + key + " -> hooked retPropVal=" + retPropVal)
        } else {
          console.log("key=" + key + " -> retPropVal=" + retPropVal)
        }

        return retPropVal
      }
    }
  }


  static HttpURLConnection() {
    // FridaAndroidUtil.printClassAllMethodsFields(FridaHookAndroidJava.clsName_HttpURLConnection)

    var cls_HttpURLConnection = Java.use(FridaHookAndroidJava.clsName_HttpURLConnection)
    console.log("cls_HttpURLConnection=" + cls_HttpURLConnection)

    
    // abstract void    disconnect()
    // public abstract void java.net.HttpURLConnection.disconnect()
    var func_HttpURLConnection_disconnect = cls_HttpURLConnection.disconnect
    console.log("func_HttpURLConnection_disconnect=" + func_HttpURLConnection_disconnect)
    if (func_HttpURLConnection_disconnect) {
      func_HttpURLConnection_disconnect.implementation = function () {
        var funcName = "HttpURLConnection.disconnect"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.disconnect()
      }
    }

    // InputStream    getErrorStream()
    // public java.io.InputStream java.net.HttpURLConnection.getErrorStream()
    var func_HttpURLConnection_getErrorStream = cls_HttpURLConnection.getErrorStream
    console.log("func_HttpURLConnection_getErrorStream=" + func_HttpURLConnection_getErrorStream)
    if (func_HttpURLConnection_getErrorStream) {
      func_HttpURLConnection_getErrorStream.implementation = function () {
        var funcName = "HttpURLConnection.getErrorStream"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retErrorStream = this.getErrorStream()
        console.log("HttpURLConnection.getErrorStream => retErrorStream=" + retErrorStream)
        return retErrorStream
      }
    }

    // static boolean    getFollowRedirects()
    // public static boolean java.net.HttpURLConnection.getFollowRedirects()
    var func_HttpURLConnection_getFollowRedirects = cls_HttpURLConnection.getFollowRedirects
    console.log("func_HttpURLConnection_getFollowRedirects=" + func_HttpURLConnection_getFollowRedirects)
    if (func_HttpURLConnection_getFollowRedirects) {
      func_HttpURLConnection_getFollowRedirects.implementation = function () {
        var funcName = "HttpURLConnection.getFollowRedirects"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retFollowRedirects = this.getFollowRedirects()
        console.log("HttpURLConnection.getFollowRedirects => retFollowRedirects=" + retFollowRedirects)
        return retFollowRedirects
      }
    }

    // String    getHeaderField(int n)
    // public java.lang.String java.net.HttpURLConnection.getHeaderField(int)
    var func_HttpURLConnection_getHeaderField = cls_HttpURLConnection.getHeaderField
    console.log("func_HttpURLConnection_getHeaderField=" + func_HttpURLConnection_getHeaderField)
    if (func_HttpURLConnection_getHeaderField) {
      func_HttpURLConnection_getHeaderField.implementation = function (n) {
        var funcName = "HttpURLConnection.getHeaderField"
        var funcParaDict = {
          "n": n,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retHeaderField = this.getHeaderField(n)
        console.log("HttpURLConnection.getHeaderField => retHeaderField=" + retHeaderField)
        return retHeaderField
      }
    }

    // long    getHeaderFieldDate(String name, long Default)
    // public long java.net.HttpURLConnection.getHeaderFieldDate(java.lang.String,long)
    var func_HttpURLConnection_getHeaderFieldDate = cls_HttpURLConnection.getHeaderFieldDate
    console.log("func_HttpURLConnection_getHeaderFieldDate=" + func_HttpURLConnection_getHeaderFieldDate)
    if (func_HttpURLConnection_getHeaderFieldDate) {
      func_HttpURLConnection_getHeaderFieldDate.implementation = function (name, Default) {
        var funcName = "HttpURLConnection.getHeaderFieldDate"
        var funcParaDict = {
          "name": name,
          "Default": Default,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retHeaderFieldDate = this.getHeaderFieldDate(name, Default)
        console.log("HttpURLConnection.getHeaderFieldDate => retHeaderFieldDate=" + retHeaderFieldDate)
        return retHeaderFieldDate
      }
    }

    // String    getHeaderFieldKey(int n)
    // public java.lang.String java.net.HttpURLConnection.getHeaderFieldKey(int)
    var func_HttpURLConnection_getHeaderFieldKey = cls_HttpURLConnection.getHeaderFieldKey
    console.log("func_HttpURLConnection_getHeaderFieldKey=" + func_HttpURLConnection_getHeaderFieldKey)
    if (func_HttpURLConnection_getHeaderFieldKey) {
      func_HttpURLConnection_getHeaderFieldKey.implementation = function (n) {
        var funcName = "HttpURLConnection.getHeaderFieldKey"
        var funcParaDict = {
          "n": n,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retHeaderFieldKey = this.getHeaderFieldKey(n)
        console.log("HttpURLConnection.getHeaderFieldKey => retHeaderFieldKey=" + retHeaderFieldKey)
        return retHeaderFieldKey
      }
    }

    // boolean    getInstanceFollowRedirects()
    // public boolean java.net.HttpURLConnection.getInstanceFollowRedirects()
    var func_HttpURLConnection_getInstanceFollowRedirects = cls_HttpURLConnection.getInstanceFollowRedirects
    console.log("func_HttpURLConnection_getInstanceFollowRedirects=" + func_HttpURLConnection_getInstanceFollowRedirects)
    if (func_HttpURLConnection_getInstanceFollowRedirects) {
      func_HttpURLConnection_getInstanceFollowRedirects.implementation = function () {
        var funcName = "HttpURLConnection.getInstanceFollowRedirects"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retInstanceFollowRedirects = this.getInstanceFollowRedirects()
        console.log("HttpURLConnection.getInstanceFollowRedirects => retInstanceFollowRedirects=" + retInstanceFollowRedirects)
        return retInstanceFollowRedirects
      }
    }

    // Permission    getPermission()
    // public java.security.Permission java.net.HttpURLConnection.getPermission() throws java.io.IOException
    var func_HttpURLConnection_getPermission = cls_HttpURLConnection.getPermission
    console.log("func_HttpURLConnection_getPermission=" + func_HttpURLConnection_getPermission)
    if (func_HttpURLConnection_getPermission) {
      func_HttpURLConnection_getPermission.implementation = function () {
        var funcName = "HttpURLConnection.getPermission"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retPermission = this.getPermission()
        console.log("HttpURLConnection.getPermission => retPermission=" + retPermission)
        return retPermission
      }
    }

    // String    getRequestMethod()
    // public java.lang.String java.net.HttpURLConnection.getRequestMethod()
    var func_HttpURLConnection_getRequestMethod = cls_HttpURLConnection.getRequestMethod
    console.log("func_HttpURLConnection_getRequestMethod=" + func_HttpURLConnection_getRequestMethod)
    if (func_HttpURLConnection_getRequestMethod) {
      func_HttpURLConnection_getRequestMethod.implementation = function () {
        var funcName = "HttpURLConnection.getRequestMethod"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retRequestMethod = this.getRequestMethod()
        console.log("HttpURLConnection.getRequestMethod => retRequestMethod=" + retRequestMethod)
        return retRequestMethod
      }
    }

    // int    getResponseCode()
    // public int java.net.HttpURLConnection.getResponseCode() throws java.io.IOException
    var func_HttpURLConnection_getResponseCode = cls_HttpURLConnection.getResponseCode
    console.log("func_HttpURLConnection_getResponseCode=" + func_HttpURLConnection_getResponseCode)
    if (func_HttpURLConnection_getResponseCode) {
      func_HttpURLConnection_getResponseCode.implementation = function () {
        var funcName = "HttpURLConnection.getResponseCode"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retResponseCode = this.getResponseCode()
        console.log("HttpURLConnection.getResponseCode => retResponseCode=" + retResponseCode)
        return retResponseCode
      }
    }

    // String    getResponseMessage()
    // public java.lang.String java.net.HttpURLConnection.getResponseMessage() throws java.io.IOException
    var func_HttpURLConnection_getResponseMessage = cls_HttpURLConnection.getResponseMessage
    console.log("func_HttpURLConnection_getResponseMessage=" + func_HttpURLConnection_getResponseMessage)
    if (func_HttpURLConnection_getResponseMessage) {
      func_HttpURLConnection_getResponseMessage.implementation = function () {
        var funcName = "HttpURLConnection.getResponseMessage"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retResponseMessage = this.getResponseMessage()
        console.log("HttpURLConnection.getResponseMessage => retResponseMessage=" + retResponseMessage)
        return retResponseMessage
      }
    }

    // void    setChunkedStreamingMode(int chunklen)
    // public void java.net.HttpURLConnection.setChunkedStreamingMode(int)
    var func_HttpURLConnection_setChunkedStreamingMode = cls_HttpURLConnection.setChunkedStreamingMode
    console.log("func_HttpURLConnection_setChunkedStreamingMode=" + func_HttpURLConnection_setChunkedStreamingMode)
    if (func_HttpURLConnection_setChunkedStreamingMode) {
      func_HttpURLConnection_setChunkedStreamingMode.implementation = function (chunklen) {
        var funcName = "HttpURLConnection.setChunkedStreamingMode"
        var funcParaDict = {
          "chunklen": chunklen,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.setChunkedStreamingMode(chunklen)
      }
    }

    // void    setFixedLengthStreamingMode(int contentLength)
    // public void java.net.HttpURLConnection.setFixedLengthStreamingMode(int)
    var func_HttpURLConnection_setFixedLengthStreamingMode = cls_HttpURLConnection.setFixedLengthStreamingMode.overload("int")
    console.log("func_HttpURLConnection_setFixedLengthStreamingMode=" + func_HttpURLConnection_setFixedLengthStreamingMode)
    if (func_HttpURLConnection_setFixedLengthStreamingMode) {
      func_HttpURLConnection_setFixedLengthStreamingMode.implementation = function (contentLength) {
        var funcName = "HttpURLConnection.setFixedLengthStreamingMode"
        var funcParaDict = {
          "contentLength": contentLength,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.setFixedLengthStreamingMode(contentLength)
      }
    }

    // void    setFixedLengthStreamingMode(long contentLength)
    // public void java.net.HttpURLConnection.setFixedLengthStreamingMode(long)
    var func_HttpURLConnection_setFixedLengthStreamingMode = cls_HttpURLConnection.setFixedLengthStreamingMode.overload("long")
    console.log("func_HttpURLConnection_setFixedLengthStreamingMode=" + func_HttpURLConnection_setFixedLengthStreamingMode)
    if (func_HttpURLConnection_setFixedLengthStreamingMode) {
      func_HttpURLConnection_setFixedLengthStreamingMode.implementation = function (contentLength) {
        var funcName = "HttpURLConnection.setFixedLengthStreamingMode"
        var funcParaDict = {
          "contentLength": contentLength,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.setFixedLengthStreamingMode(contentLength)
      }
    }

    // static void    setFollowRedirects(boolean set)
    // public static void java.net.HttpURLConnection.setFollowRedirects(boolean)
    var func_HttpURLConnection_setFollowRedirects = cls_HttpURLConnection.setFollowRedirects
    console.log("func_HttpURLConnection_setFollowRedirects=" + func_HttpURLConnection_setFollowRedirects)
    if (func_HttpURLConnection_setFollowRedirects) {
      func_HttpURLConnection_setFollowRedirects.implementation = function (set) {
        var funcName = "HttpURLConnection.setFollowRedirects"
        var funcParaDict = {
          "set": set,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.setFollowRedirects(set)
      }
    }

    // void    setInstanceFollowRedirects(boolean followRedirects)
    // public void java.net.HttpURLConnection.setInstanceFollowRedirects(boolean)
    var func_HttpURLConnection_setInstanceFollowRedirects = cls_HttpURLConnection.setInstanceFollowRedirects
    console.log("func_HttpURLConnection_setInstanceFollowRedirects=" + func_HttpURLConnection_setInstanceFollowRedirects)
    if (func_HttpURLConnection_setInstanceFollowRedirects) {
      func_HttpURLConnection_setInstanceFollowRedirects.implementation = function (followRedirects) {
        var funcName = "HttpURLConnection.setInstanceFollowRedirects"
        var funcParaDict = {
          "followRedirects": followRedirects,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.setInstanceFollowRedirects(followRedirects)
      }
    }

    // void    setRequestMethod(String method)
    // public void java.net.HttpURLConnection.setRequestMethod(java.lang.String) throws java.net.ProtocolException
    var func_HttpURLConnection_setRequestMethod = cls_HttpURLConnection.setRequestMethod
    console.log("func_HttpURLConnection_setRequestMethod=" + func_HttpURLConnection_setRequestMethod)
    if (func_HttpURLConnection_setRequestMethod) {
      func_HttpURLConnection_setRequestMethod.implementation = function (method) {
        var funcName = "HttpURLConnection.setRequestMethod"
        var funcParaDict = {
          "method": method,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.setRequestMethod(method)
      }
    }

    // abstract boolean    usingProxy()
    // public abstract boolean java.net.HttpURLConnection.usingProxy()
    var func_HttpURLConnection_usingProxy = cls_HttpURLConnection.usingProxy
    console.log("func_HttpURLConnection_usingProxy=" + func_HttpURLConnection_usingProxy)
    if (func_HttpURLConnection_usingProxy) {
      func_HttpURLConnection_usingProxy.implementation = function () {
        var funcName = "HttpURLConnection.usingProxy"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retboolean = this.usingProxy()
        console.log("HttpURLConnection.usingProxy => retboolean=" + retboolean)
        return retboolean
      }
    }
  }

}