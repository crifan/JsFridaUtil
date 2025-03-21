/*
	File: FridaHookAndroidJava.js
	Function: crifan's Frida hook common Android Java related functions
	Author: Crifan Li
	Latest: https://github.com/crifan/JsFridaUtil/blob/main/frida/FridaHookAndroidJava.js
	Updated: 20250321
*/

// Frida hook common Android/Java class
class FridaHookAndroidJava {
  constructor() {
    console.log("FridaHookAndroidJava constructor")
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
    // FridaAndroidUtil.printClassAllMethodsFields(FridaAndroidUtil.clsName_HttpURLConnection)

    var cls_HttpURLConnection = Java.use(FridaAndroidUtil.clsName_HttpURLConnection)
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

        var retBoolean = this.usingProxy()
        console.log("HttpURLConnection.usingProxy => retBoolean=" + retBoolean)
        return retBoolean
      }
    }
  }

  static IOException() {
    var clsName_IOException = "java.io.IOException"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_IOException)

    var cls_IOException = Java.use(clsName_IOException)
    console.log("cls_IOException=" + cls_IOException)

    
    // IOException()
    // 
    var func_IOException_IOException_void = cls_IOException.$init.overload()
    console.log("func_IOException_IOException_void=" + func_IOException_IOException_void)
    if (func_IOException_IOException_void) {
      func_IOException_IOException_void.implementation = function () {
        var funcName = "IOException"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var newIOException_void = this.$init()
        console.log("IOException => newIOException_void=" + newIOException_void)
        return newIOException_void
      }
    }

    // IOException(String message)
    // 
    var func_IOException_IOException_1str = cls_IOException.$init.overload("java.lang.String")
    console.log("func_IOException_IOException_1str=" + func_IOException_IOException_1str)
    if (func_IOException_IOException_1str) {
      func_IOException_IOException_1str.implementation = function (message) {
        var funcName = "IOException(msg)"
        var funcParaDict = {
          "message": message,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var newIOException_1str = this.$init(message)
        console.log("IOException(msg) => newIOException_1str=" + newIOException_1str)
        return newIOException_1str
      }
    }

    // IOException(String message, Throwable cause)
    // 
    var func_IOException_IOException_2para = cls_IOException.$init.overload("java.lang.String", "java.lang.Throwable")
    console.log("func_IOException_IOException_2para=" + func_IOException_IOException_2para)
    if (func_IOException_IOException_2para) {
      func_IOException_IOException_2para.implementation = function (message, cause) {
        var funcName = "IOException(msg,cause)"
        var funcParaDict = {
          "message": message,
          "cause": cause,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var newIOException_2para = this.$init(message, cause)
        console.log("IOException(msg,cause) => newIOException_2para=" + newIOException_2para)
        return newIOException_2para
      }
    }

    // IOException(Throwable cause)
    // 
    var func_IOException_IOException_1t = cls_IOException.$init.overload("java.lang.Throwable")
    console.log("func_IOException_IOException_1t=" + func_IOException_IOException_1t)
    if (func_IOException_IOException_1t) {
      func_IOException_IOException_1t.implementation = function (cause) {
        var funcName = "IOException(cause)"
        var funcParaDict = {
          "cause": cause,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var newIOException_1t = this.$init(cause)
        console.log("IOException(cause) => newIOException_1t=" + newIOException_1t)
        return newIOException_1t
      }
    }
  }

  static HttpURLConnectionImpl() {
    var clsName_HttpURLConnectionImpl = "com.android.okhttp.internal.huc.HttpURLConnectionImpl"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_HttpURLConnectionImpl)

    var cls_HttpURLConnectionImpl = Java.use(clsName_HttpURLConnectionImpl)
    console.log("cls_HttpURLConnectionImpl=" + cls_HttpURLConnectionImpl)

    
    // public HttpURLConnectionImpl(URL url, OkHttpClient client) {
    // 
    var func_HttpURLConnectionImpl_HttpURLConnectionImpl_2p = cls_HttpURLConnectionImpl.$init.overload("java.net.URL", "com.android.okhttp.OkHttpClient")
    console.log("func_HttpURLConnectionImpl_HttpURLConnectionImpl_2p=" + func_HttpURLConnectionImpl_HttpURLConnectionImpl_2p)
    if (func_HttpURLConnectionImpl_HttpURLConnectionImpl_2p) {
      func_HttpURLConnectionImpl_HttpURLConnectionImpl_2p.implementation = function (url, client) {
        var funcName = "HttpURLConnectionImpl(url,client)"
        var funcParaDict = {
          "url": url,
          "client": client,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var newHttpURLConnectionImpl_2p = this.$init(url, client)
        console.log("HttpURLConnectionImpl(url,client) => newHttpURLConnectionImpl_2p=" + newHttpURLConnectionImpl_2p)
        return newHttpURLConnectionImpl_2p
      }
    }

    // public HttpURLConnectionImpl(URL url, OkHttpClient client, URLFilter urlFilter) {
    // 
    var func_HttpURLConnectionImpl_HttpURLConnectionImpl_3p = cls_HttpURLConnectionImpl.$init.overload("java.net.URL", "com.android.okhttp.OkHttpClient", "com.android.okhttp.internal.URLFilter")
    console.log("func_HttpURLConnectionImpl_HttpURLConnectionImpl_3p=" + func_HttpURLConnectionImpl_HttpURLConnectionImpl_3p)
    if (func_HttpURLConnectionImpl_HttpURLConnectionImpl_3p) {
      func_HttpURLConnectionImpl_HttpURLConnectionImpl_3p.implementation = function (url, client, urlFilter) {
        var funcName = "HttpURLConnectionImpl(url,client,urlFilter)"
        var funcParaDict = {
          "url": url,
          "client": client,
          "urlFilter": urlFilter,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var newHttpURLConnectionImpl_3p = this.$init(url, client, urlFilter)
        console.log("HttpURLConnectionImpl(url,client,urlFilter) => newHttpURLConnectionImpl_3p=" + newHttpURLConnectionImpl_3p)
        return newHttpURLConnectionImpl_3p
      }
    }

    // @Override public final void connect() throws IOException {
    // public final void com.android.okhttp.internal.huc.HttpURLConnectionImpl.connect() throws java.io.IOException
    var func_HttpURLConnectionImpl_connect = cls_HttpURLConnectionImpl.connect
    console.log("func_HttpURLConnectionImpl_connect=" + func_HttpURLConnectionImpl_connect)
    if (func_HttpURLConnectionImpl_connect) {
      func_HttpURLConnectionImpl_connect.implementation = function () {
        var funcName = "HttpURLConnectionImpl.connect"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.connect()
      }
    }

    // @Override public final void disconnect() {
    // public final void com.android.okhttp.internal.huc.HttpURLConnectionImpl.disconnect()
    var func_HttpURLConnectionImpl_disconnect = cls_HttpURLConnectionImpl.disconnect
    console.log("func_HttpURLConnectionImpl_disconnect=" + func_HttpURLConnectionImpl_disconnect)
    if (func_HttpURLConnectionImpl_disconnect) {
      func_HttpURLConnectionImpl_disconnect.implementation = function () {
        var funcName = "HttpURLConnectionImpl.disconnect"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.disconnect()
      }
    }

    // @Override public final InputStream getErrorStream() {
    // public final java.io.InputStream com.android.okhttp.internal.huc.HttpURLConnectionImpl.getErrorStream()
    var func_HttpURLConnectionImpl_getErrorStream = cls_HttpURLConnectionImpl.getErrorStream
    console.log("func_HttpURLConnectionImpl_getErrorStream=" + func_HttpURLConnectionImpl_getErrorStream)
    if (func_HttpURLConnectionImpl_getErrorStream) {
      func_HttpURLConnectionImpl_getErrorStream.implementation = function () {
        var funcName = "HttpURLConnectionImpl.getErrorStream"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retErrorStream = this.getErrorStream()
        console.log("HttpURLConnectionImpl.getErrorStream => retErrorStream=" + retErrorStream)
        return retErrorStream
      }
    }

    // private Headers getHeaders() throws IOException {
    // private com.android.okhttp.Headers com.android.okhttp.internal.huc.HttpURLConnectionImpl.getHeaders() throws java.io.IOException
    var func_HttpURLConnectionImpl_getHeaders = cls_HttpURLConnectionImpl.getHeaders
    console.log("func_HttpURLConnectionImpl_getHeaders=" + func_HttpURLConnectionImpl_getHeaders)
    if (func_HttpURLConnectionImpl_getHeaders) {
      func_HttpURLConnectionImpl_getHeaders.implementation = function () {
        var funcName = "HttpURLConnectionImpl.getHeaders"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retHeaders = this.getHeaders()
        console.log("HttpURLConnectionImpl.getHeaders => retHeaders=" + retHeaders)
        return retHeaders
      }
    }

    // private static String responseSourceHeader(Response response) {
    // private static java.lang.String com.android.okhttp.internal.huc.HttpURLConnectionImpl.responseSourceHeader(com.android.okhttp.Response)
    var func_HttpURLConnectionImpl_responseSourceHeader = cls_HttpURLConnectionImpl.responseSourceHeader
    console.log("func_HttpURLConnectionImpl_responseSourceHeader=" + func_HttpURLConnectionImpl_responseSourceHeader)
    if (func_HttpURLConnectionImpl_responseSourceHeader) {
      func_HttpURLConnectionImpl_responseSourceHeader.implementation = function (response) {
        var funcName = "HttpURLConnectionImpl.responseSourceHeader"
        var funcParaDict = {
          "response": response,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retString = this.responseSourceHeader(response)
        console.log("HttpURLConnectionImpl.responseSourceHeader => retString=" + retString)
        return retString
      }
    }

    // @Override public final String getHeaderField(int position) {
    // public final java.lang.String com.android.okhttp.internal.huc.HttpURLConnectionImpl.getHeaderField(int)
    var func_HttpURLConnectionImpl_getHeaderField_i = cls_HttpURLConnectionImpl.getHeaderField.overload("int")
    console.log("func_HttpURLConnectionImpl_getHeaderField_i=" + func_HttpURLConnectionImpl_getHeaderField_i)
    if (func_HttpURLConnectionImpl_getHeaderField_i) {
      func_HttpURLConnectionImpl_getHeaderField_i.implementation = function (position) {
        var funcName = "HttpURLConnectionImpl.getHeaderField(position)"
        var funcParaDict = {
          "position": position,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retHeaderField_i = this.getHeaderField(position)
        console.log("HttpURLConnectionImpl.getHeaderField(position) => retHeaderField_i=" + retHeaderField_i)
        return retHeaderField_i
      }
    }

    // @Override public final String getHeaderField(String fieldName) {
    // public final java.lang.String com.android.okhttp.internal.huc.HttpURLConnectionImpl.getHeaderField(java.lang.String)
    var func_HttpURLConnectionImpl_getHeaderField_str = cls_HttpURLConnectionImpl.getHeaderField.overload("java.lang.String")
    console.log("func_HttpURLConnectionImpl_getHeaderField_str=" + func_HttpURLConnectionImpl_getHeaderField_str)
    if (func_HttpURLConnectionImpl_getHeaderField_str) {
      func_HttpURLConnectionImpl_getHeaderField_str.implementation = function (fieldName) {
        var funcName = "HttpURLConnectionImpl.getHeaderField(fieldName)"
        var funcParaDict = {
          "fieldName": fieldName,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retHeaderField_str = this.getHeaderField(fieldName)
        console.log("HttpURLConnectionImpl.getHeaderField(fieldName) => retHeaderField_str=" + retHeaderField_str)
        return retHeaderField_str
      }
    }

    // @Override public final String getHeaderFieldKey(int position) {
    // public final java.lang.String com.android.okhttp.internal.huc.HttpURLConnectionImpl.getHeaderFieldKey(int)
    var func_HttpURLConnectionImpl_getHeaderFieldKey = cls_HttpURLConnectionImpl.getHeaderFieldKey
    console.log("func_HttpURLConnectionImpl_getHeaderFieldKey=" + func_HttpURLConnectionImpl_getHeaderFieldKey)
    if (func_HttpURLConnectionImpl_getHeaderFieldKey) {
      func_HttpURLConnectionImpl_getHeaderFieldKey.implementation = function (position) {
        var funcName = "HttpURLConnectionImpl.getHeaderFieldKey"
        var funcParaDict = {
          "position": position,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retHeaderFieldKey = this.getHeaderFieldKey(position)
        console.log("HttpURLConnectionImpl.getHeaderFieldKey => retHeaderFieldKey=" + retHeaderFieldKey)
        return retHeaderFieldKey
      }
    }

    // @Override public final Map<String, List<String>> getHeaderFields() {
    // public final java.util.Map com.android.okhttp.internal.huc.HttpURLConnectionImpl.getHeaderFields()
    var func_HttpURLConnectionImpl_getHeaderFields = cls_HttpURLConnectionImpl.getHeaderFields
    console.log("func_HttpURLConnectionImpl_getHeaderFields=" + func_HttpURLConnectionImpl_getHeaderFields)
    if (func_HttpURLConnectionImpl_getHeaderFields) {
      func_HttpURLConnectionImpl_getHeaderFields.implementation = function () {
        var funcName = "HttpURLConnectionImpl.getHeaderFields"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retHeaderFields = this.getHeaderFields()
        console.log("HttpURLConnectionImpl.getHeaderFields => retHeaderFields=" + retHeaderFields)
        return retHeaderFields
      }
    }

    // @Override public final Map<String, List<String>> getRequestProperties() {
    // public final java.util.Map com.android.okhttp.internal.huc.HttpURLConnectionImpl.getRequestProperties()
    var func_HttpURLConnectionImpl_getRequestProperties = cls_HttpURLConnectionImpl.getRequestProperties
    console.log("func_HttpURLConnectionImpl_getRequestProperties=" + func_HttpURLConnectionImpl_getRequestProperties)
    if (func_HttpURLConnectionImpl_getRequestProperties) {
      func_HttpURLConnectionImpl_getRequestProperties.implementation = function () {
        var funcName = "HttpURLConnectionImpl.getRequestProperties"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retRequestProperties = this.getRequestProperties()
        console.log("HttpURLConnectionImpl.getRequestProperties => retRequestProperties=" + retRequestProperties)
        return retRequestProperties
      }
    }

    // @Override public final InputStream getInputStream() throws IOException {
    // public final java.io.InputStream com.android.okhttp.internal.huc.HttpURLConnectionImpl.getInputStream() throws java.io.IOException
    var func_HttpURLConnectionImpl_getInputStream = cls_HttpURLConnectionImpl.getInputStream
    console.log("func_HttpURLConnectionImpl_getInputStream=" + func_HttpURLConnectionImpl_getInputStream)
    if (func_HttpURLConnectionImpl_getInputStream) {
      func_HttpURLConnectionImpl_getInputStream.implementation = function () {
        var funcName = "HttpURLConnectionImpl.getInputStream"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retInputStream = this.getInputStream()
        console.log("HttpURLConnectionImpl.getInputStream => retInputStream=" + retInputStream)
        return retInputStream
      }
    }

    // @Override public final OutputStream getOutputStream() throws IOException {
    // public final java.io.OutputStream com.android.okhttp.internal.huc.HttpURLConnectionImpl.getOutputStream() throws java.io.IOException
    var func_HttpURLConnectionImpl_getOutputStream = cls_HttpURLConnectionImpl.getOutputStream
    console.log("func_HttpURLConnectionImpl_getOutputStream=" + func_HttpURLConnectionImpl_getOutputStream)
    if (func_HttpURLConnectionImpl_getOutputStream) {
      func_HttpURLConnectionImpl_getOutputStream.implementation = function () {
        var funcName = "HttpURLConnectionImpl.getOutputStream"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retOutputStream = this.getOutputStream()
        console.log("HttpURLConnectionImpl.getOutputStream => retOutputStream=" + retOutputStream)
        return retOutputStream
      }
    }

    // @Override public final Permission getPermission() throws IOException {
    // public final java.security.Permission com.android.okhttp.internal.huc.HttpURLConnectionImpl.getPermission() throws java.io.IOException
    var func_HttpURLConnectionImpl_getPermission = cls_HttpURLConnectionImpl.getPermission
    console.log("func_HttpURLConnectionImpl_getPermission=" + func_HttpURLConnectionImpl_getPermission)
    if (func_HttpURLConnectionImpl_getPermission) {
      func_HttpURLConnectionImpl_getPermission.implementation = function () {
        var funcName = "HttpURLConnectionImpl.getPermission"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retPermission = this.getPermission()
        console.log("HttpURLConnectionImpl.getPermission => retPermission=" + retPermission)
        return retPermission
      }
    }

    // @Override public final String getRequestProperty(String field) {
    // public final java.lang.String com.android.okhttp.internal.huc.HttpURLConnectionImpl.getRequestProperty(java.lang.String)
    var func_HttpURLConnectionImpl_getRequestProperty = cls_HttpURLConnectionImpl.getRequestProperty
    console.log("func_HttpURLConnectionImpl_getRequestProperty=" + func_HttpURLConnectionImpl_getRequestProperty)
    if (func_HttpURLConnectionImpl_getRequestProperty) {
      func_HttpURLConnectionImpl_getRequestProperty.implementation = function (field) {
        var funcName = "HttpURLConnectionImpl.getRequestProperty"
        var funcParaDict = {
          "field": field,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retRequestProperty = this.getRequestProperty(field)
        console.log("HttpURLConnectionImpl.getRequestProperty => retRequestProperty=" + retRequestProperty)
        return retRequestProperty
      }
    }

    // @Override public void setConnectTimeout(int timeoutMillis) {
    // public void com.android.okhttp.internal.huc.HttpURLConnectionImpl.setConnectTimeout(int)
    var func_HttpURLConnectionImpl_setConnectTimeout = cls_HttpURLConnectionImpl.setConnectTimeout
    console.log("func_HttpURLConnectionImpl_setConnectTimeout=" + func_HttpURLConnectionImpl_setConnectTimeout)
    if (func_HttpURLConnectionImpl_setConnectTimeout) {
      func_HttpURLConnectionImpl_setConnectTimeout.implementation = function (timeoutMillis) {
        var funcName = "HttpURLConnectionImpl.setConnectTimeout"
        var funcParaDict = {
          "timeoutMillis": timeoutMillis,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.setConnectTimeout(timeoutMillis)
      }
    }

    // public void setInstanceFollowRedirects(boolean followRedirects) {
    // public void com.android.okhttp.internal.huc.HttpURLConnectionImpl.setInstanceFollowRedirects(boolean)
    var func_HttpURLConnectionImpl_setInstanceFollowRedirects = cls_HttpURLConnectionImpl.setInstanceFollowRedirects
    console.log("func_HttpURLConnectionImpl_setInstanceFollowRedirects=" + func_HttpURLConnectionImpl_setInstanceFollowRedirects)
    if (func_HttpURLConnectionImpl_setInstanceFollowRedirects) {
      func_HttpURLConnectionImpl_setInstanceFollowRedirects.implementation = function (followRedirects) {
        var funcName = "HttpURLConnectionImpl.setInstanceFollowRedirects"
        var funcParaDict = {
          "followRedirects": followRedirects,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.setInstanceFollowRedirects(followRedirects)
      }
    }

    // @Override public boolean getInstanceFollowRedirects() {
    // public boolean com.android.okhttp.internal.huc.HttpURLConnectionImpl.getInstanceFollowRedirects()
    var func_HttpURLConnectionImpl_getInstanceFollowRedirects = cls_HttpURLConnectionImpl.getInstanceFollowRedirects
    console.log("func_HttpURLConnectionImpl_getInstanceFollowRedirects=" + func_HttpURLConnectionImpl_getInstanceFollowRedirects)
    if (func_HttpURLConnectionImpl_getInstanceFollowRedirects) {
      func_HttpURLConnectionImpl_getInstanceFollowRedirects.implementation = function () {
        var funcName = "HttpURLConnectionImpl.getInstanceFollowRedirects"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retInstanceFollowRedirects = this.getInstanceFollowRedirects()
        console.log("HttpURLConnectionImpl.getInstanceFollowRedirects => retInstanceFollowRedirects=" + retInstanceFollowRedirects)
        return retInstanceFollowRedirects
      }
    }

    // @Override public int getConnectTimeout() {
    // public int com.android.okhttp.internal.huc.HttpURLConnectionImpl.getConnectTimeout()
    var func_HttpURLConnectionImpl_getConnectTimeout = cls_HttpURLConnectionImpl.getConnectTimeout
    console.log("func_HttpURLConnectionImpl_getConnectTimeout=" + func_HttpURLConnectionImpl_getConnectTimeout)
    if (func_HttpURLConnectionImpl_getConnectTimeout) {
      func_HttpURLConnectionImpl_getConnectTimeout.implementation = function () {
        var funcName = "HttpURLConnectionImpl.getConnectTimeout"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retConnectTimeout = this.getConnectTimeout()
        console.log("HttpURLConnectionImpl.getConnectTimeout => retConnectTimeout=" + retConnectTimeout)
        return retConnectTimeout
      }
    }

    // @Override public void setReadTimeout(int timeoutMillis) {
    // public void com.android.okhttp.internal.huc.HttpURLConnectionImpl.setReadTimeout(int)
    var func_HttpURLConnectionImpl_setReadTimeout = cls_HttpURLConnectionImpl.setReadTimeout
    console.log("func_HttpURLConnectionImpl_setReadTimeout=" + func_HttpURLConnectionImpl_setReadTimeout)
    if (func_HttpURLConnectionImpl_setReadTimeout) {
      func_HttpURLConnectionImpl_setReadTimeout.implementation = function (timeoutMillis) {
        var funcName = "HttpURLConnectionImpl.setReadTimeout"
        var funcParaDict = {
          "timeoutMillis": timeoutMillis,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.setReadTimeout(timeoutMillis)
      }
    }

    // @Override public int getReadTimeout() {
    // public int com.android.okhttp.internal.huc.HttpURLConnectionImpl.getReadTimeout()
    var func_HttpURLConnectionImpl_getReadTimeout = cls_HttpURLConnectionImpl.getReadTimeout
    console.log("func_HttpURLConnectionImpl_getReadTimeout=" + func_HttpURLConnectionImpl_getReadTimeout)
    if (func_HttpURLConnectionImpl_getReadTimeout) {
      func_HttpURLConnectionImpl_getReadTimeout.implementation = function () {
        var funcName = "HttpURLConnectionImpl.getReadTimeout"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retReadTimeout = this.getReadTimeout()
        console.log("HttpURLConnectionImpl.getReadTimeout => retReadTimeout=" + retReadTimeout)
        return retReadTimeout
      }
    }

    // private void initHttpEngine() throws IOException {
    // private void com.android.okhttp.internal.huc.HttpURLConnectionImpl.initHttpEngine() throws java.io.IOException
    var func_HttpURLConnectionImpl_initHttpEngine = cls_HttpURLConnectionImpl.initHttpEngine
    console.log("func_HttpURLConnectionImpl_initHttpEngine=" + func_HttpURLConnectionImpl_initHttpEngine)
    if (func_HttpURLConnectionImpl_initHttpEngine) {
      func_HttpURLConnectionImpl_initHttpEngine.implementation = function () {
        var funcName = "HttpURLConnectionImpl.initHttpEngine"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.initHttpEngine()
      }
    }

    // private HttpEngine newHttpEngine(String method, StreamAllocation streamAllocation, RetryableSink requestBody, Response priorResponse) throws MalformedURLException, UnknownHostException {
    // private com.android.okhttp.internal.http.HttpEngine com.android.okhttp.internal.huc.HttpURLConnectionImpl.newHttpEngine(java.lang.String,com.android.okhttp.internal.http.StreamAllocation,com.android.okhttp.internal.http.RetryableSink,com.android.okhttp.Response) throws java.net.MalformedURLException,java.net.UnknownHostException
    var func_HttpURLConnectionImpl_newHttpEngine = cls_HttpURLConnectionImpl.newHttpEngine
    console.log("func_HttpURLConnectionImpl_newHttpEngine=" + func_HttpURLConnectionImpl_newHttpEngine)
    if (func_HttpURLConnectionImpl_newHttpEngine) {
      func_HttpURLConnectionImpl_newHttpEngine.implementation = function (method, streamAllocation, requestBody, priorResponse) {
        var funcName = "HttpURLConnectionImpl.newHttpEngine"
        var funcParaDict = {
          "method": method,
          "streamAllocation": streamAllocation,
          "requestBody": requestBody,
          "priorResponse": priorResponse,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retHttpEngine = this.newHttpEngine(method, streamAllocation, requestBody, priorResponse)
        console.log("HttpURLConnectionImpl.newHttpEngine => retHttpEngine=" + retHttpEngine)
        return retHttpEngine
      }
    }

    // private String defaultUserAgent() {
    // private java.lang.String com.android.okhttp.internal.huc.HttpURLConnectionImpl.defaultUserAgent()
    var func_HttpURLConnectionImpl_defaultUserAgent = cls_HttpURLConnectionImpl.defaultUserAgent
    console.log("func_HttpURLConnectionImpl_defaultUserAgent=" + func_HttpURLConnectionImpl_defaultUserAgent)
    if (func_HttpURLConnectionImpl_defaultUserAgent) {
      func_HttpURLConnectionImpl_defaultUserAgent.implementation = function () {
        var funcName = "HttpURLConnectionImpl.defaultUserAgent"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retString = this.defaultUserAgent()
        console.log("HttpURLConnectionImpl.defaultUserAgent => retString=" + retString)
        return retString
      }
    }

    // private HttpEngine getResponse() throws IOException {
    // private com.android.okhttp.internal.http.HttpEngine com.android.okhttp.internal.huc.HttpURLConnectionImpl.getResponse() throws java.io.IOException
    var func_HttpURLConnectionImpl_getResponse = cls_HttpURLConnectionImpl.getResponse
    console.log("func_HttpURLConnectionImpl_getResponse=" + func_HttpURLConnectionImpl_getResponse)
    if (func_HttpURLConnectionImpl_getResponse) {
      func_HttpURLConnectionImpl_getResponse.implementation = function () {
        var funcName = "HttpURLConnectionImpl.getResponse"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retResponse = this.getResponse()
        console.log("HttpURLConnectionImpl.getResponse => retResponse=" + retResponse)
        return retResponse
      }
    }

    // private boolean execute(boolean readResponse) throws IOException {
    // private boolean com.android.okhttp.internal.huc.HttpURLConnectionImpl.execute(boolean) throws java.io.IOException
    var func_HttpURLConnectionImpl_execute = cls_HttpURLConnectionImpl.execute
    console.log("func_HttpURLConnectionImpl_execute=" + func_HttpURLConnectionImpl_execute)
    if (func_HttpURLConnectionImpl_execute) {
      func_HttpURLConnectionImpl_execute.implementation = function (readResponse) {
        var funcName = "HttpURLConnectionImpl.execute"
        var funcParaDict = {
          "readResponse": readResponse,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean = this.execute(readResponse)
        console.log("HttpURLConnectionImpl.execute => retBoolean=" + retBoolean)
        return retBoolean
      }
    }

    // @Override public final boolean usingProxy() {
    // public final boolean com.android.okhttp.internal.huc.HttpURLConnectionImpl.usingProxy()
    var func_HttpURLConnectionImpl_usingProxy = cls_HttpURLConnectionImpl.usingProxy
    console.log("func_HttpURLConnectionImpl_usingProxy=" + func_HttpURLConnectionImpl_usingProxy)
    if (func_HttpURLConnectionImpl_usingProxy) {
      func_HttpURLConnectionImpl_usingProxy.implementation = function () {
        var funcName = "HttpURLConnectionImpl.usingProxy"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean = this.usingProxy()
        console.log("HttpURLConnectionImpl.usingProxy => retBoolean=" + retBoolean)
        return retBoolean
      }
    }

    // @Override public String getResponseMessage() throws IOException {
    // public java.lang.String com.android.okhttp.internal.huc.HttpURLConnectionImpl.getResponseMessage() throws java.io.IOException
    var func_HttpURLConnectionImpl_getResponseMessage = cls_HttpURLConnectionImpl.getResponseMessage
    console.log("func_HttpURLConnectionImpl_getResponseMessage=" + func_HttpURLConnectionImpl_getResponseMessage)
    if (func_HttpURLConnectionImpl_getResponseMessage) {
      func_HttpURLConnectionImpl_getResponseMessage.implementation = function () {
        var funcName = "HttpURLConnectionImpl.getResponseMessage"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retResponseMessage = this.getResponseMessage()
        console.log("HttpURLConnectionImpl.getResponseMessage => retResponseMessage=" + retResponseMessage)
        return retResponseMessage
      }
    }

    // @Override public final int getResponseCode() throws IOException {
    // public final int com.android.okhttp.internal.huc.HttpURLConnectionImpl.getResponseCode() throws java.io.IOException
    var func_HttpURLConnectionImpl_getResponseCode = cls_HttpURLConnectionImpl.getResponseCode
    console.log("func_HttpURLConnectionImpl_getResponseCode=" + func_HttpURLConnectionImpl_getResponseCode)
    if (func_HttpURLConnectionImpl_getResponseCode) {
      func_HttpURLConnectionImpl_getResponseCode.implementation = function () {
        var funcName = "HttpURLConnectionImpl.getResponseCode"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retResponseCode = this.getResponseCode()
        console.log("HttpURLConnectionImpl.getResponseCode => retResponseCode=" + retResponseCode)
        return retResponseCode
      }
    }

    // @Override public final void setRequestProperty(String field, String newValue) {
    // public final void com.android.okhttp.internal.huc.HttpURLConnectionImpl.setRequestProperty(java.lang.String,java.lang.String)
    var func_HttpURLConnectionImpl_setRequestProperty = cls_HttpURLConnectionImpl.setRequestProperty
    console.log("func_HttpURLConnectionImpl_setRequestProperty=" + func_HttpURLConnectionImpl_setRequestProperty)
    if (func_HttpURLConnectionImpl_setRequestProperty) {
      func_HttpURLConnectionImpl_setRequestProperty.implementation = function (field, newValue) {
        var funcName = "HttpURLConnectionImpl.setRequestProperty"
        var funcParaDict = {
          "field": field,
          "newValue": newValue,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.setRequestProperty(field, newValue)
      }
    }

    // @Override public void setIfModifiedSince(long newValue) {
    // public void com.android.okhttp.internal.huc.HttpURLConnectionImpl.setIfModifiedSince(long)
    var func_HttpURLConnectionImpl_setIfModifiedSince = cls_HttpURLConnectionImpl.setIfModifiedSince
    console.log("func_HttpURLConnectionImpl_setIfModifiedSince=" + func_HttpURLConnectionImpl_setIfModifiedSince)
    if (func_HttpURLConnectionImpl_setIfModifiedSince) {
      func_HttpURLConnectionImpl_setIfModifiedSince.implementation = function (newValue) {
        var funcName = "HttpURLConnectionImpl.setIfModifiedSince"
        var funcParaDict = {
          "newValue": newValue,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.setIfModifiedSince(newValue)
      }
    }

    // @Override public final void addRequestProperty(String field, String value) {
    // public final void com.android.okhttp.internal.huc.HttpURLConnectionImpl.addRequestProperty(java.lang.String,java.lang.String)
    var func_HttpURLConnectionImpl_addRequestProperty = cls_HttpURLConnectionImpl.addRequestProperty
    console.log("func_HttpURLConnectionImpl_addRequestProperty=" + func_HttpURLConnectionImpl_addRequestProperty)
    if (func_HttpURLConnectionImpl_addRequestProperty) {
      func_HttpURLConnectionImpl_addRequestProperty.implementation = function (field, value) {
        var funcName = "HttpURLConnectionImpl.addRequestProperty"
        var funcParaDict = {
          "field": field,
          "value": value,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.addRequestProperty(field, value)
      }
    }

    // private void setProtocols(String protocolsString, boolean append) {
    // private void com.android.okhttp.internal.huc.HttpURLConnectionImpl.setProtocols(java.lang.String,boolean)
    var func_HttpURLConnectionImpl_setProtocols = cls_HttpURLConnectionImpl.setProtocols
    console.log("func_HttpURLConnectionImpl_setProtocols=" + func_HttpURLConnectionImpl_setProtocols)
    if (func_HttpURLConnectionImpl_setProtocols) {
      func_HttpURLConnectionImpl_setProtocols.implementation = function (protocolsString, append) {
        var funcName = "HttpURLConnectionImpl.setProtocols"
        var funcParaDict = {
          "protocolsString": protocolsString,
          "append": append,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.setProtocols(protocolsString, append)
      }
    }

    // @Override public void setRequestMethod(String method) throws ProtocolException {
    // public void com.android.okhttp.internal.huc.HttpURLConnectionImpl.setRequestMethod(java.lang.String) throws java.net.ProtocolException
    var func_HttpURLConnectionImpl_setRequestMethod = cls_HttpURLConnectionImpl.setRequestMethod
    console.log("func_HttpURLConnectionImpl_setRequestMethod=" + func_HttpURLConnectionImpl_setRequestMethod)
    if (func_HttpURLConnectionImpl_setRequestMethod) {
      func_HttpURLConnectionImpl_setRequestMethod.implementation = function (method) {
        var funcName = "HttpURLConnectionImpl.setRequestMethod"
        var funcParaDict = {
          "method": method,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.setRequestMethod(method)
      }
    }

    // @Override public void setFixedLengthStreamingMode(int contentLength) {
    // public void com.android.okhttp.internal.huc.HttpURLConnectionImpl.setFixedLengthStreamingMode(int)
    var func_HttpURLConnectionImpl_setFixedLengthStreamingMode_i = cls_HttpURLConnectionImpl.setFixedLengthStreamingMode.overload("int")
    console.log("func_HttpURLConnectionImpl_setFixedLengthStreamingMode_i=" + func_HttpURLConnectionImpl_setFixedLengthStreamingMode_i)
    if (func_HttpURLConnectionImpl_setFixedLengthStreamingMode_i) {
      func_HttpURLConnectionImpl_setFixedLengthStreamingMode_i.implementation = function (contentLength) {
        var funcName = "HttpURLConnectionImpl.setFixedLengthStreamingMode(int)"
        var funcParaDict = {
          "contentLength": contentLength,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.setFixedLengthStreamingMode(contentLength)
      }
    }

    // @Override public void setFixedLengthStreamingMode(long contentLength) {
    // public void com.android.okhttp.internal.huc.HttpURLConnectionImpl.setFixedLengthStreamingMode(long)
    var func_HttpURLConnectionImpl_setFixedLengthStreamingMode_l = cls_HttpURLConnectionImpl.setFixedLengthStreamingMode.overload("long")
    console.log("func_HttpURLConnectionImpl_setFixedLengthStreamingMode_l=" + func_HttpURLConnectionImpl_setFixedLengthStreamingMode_l)
    if (func_HttpURLConnectionImpl_setFixedLengthStreamingMode_l) {
      func_HttpURLConnectionImpl_setFixedLengthStreamingMode_l.implementation = function (contentLength) {
        var funcName = "HttpURLConnectionImpl.setFixedLengthStreamingMode"
        var funcParaDict = {
          "contentLength": contentLength,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.setFixedLengthStreamingMode(contentLength)
      }
    }
  }

  static Bundle() {
    var clsName_Bundle = "android.os.Bundle"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Bundle)

    var cls_Bundle = Java.use(clsName_Bundle)
    console.log("cls_Bundle=" + cls_Bundle)

    
    // Bundle()
    // 
    var func_Bundle_Bundle_0p = cls_Bundle.$init.overload()
    console.log("func_Bundle_Bundle_0p=" + func_Bundle_Bundle_0p)
    if (func_Bundle_Bundle_0p) {
      func_Bundle_Bundle_0p.implementation = function () {
        var funcName = "Bundle_0p"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var newBundle_0p = this.$init()
        console.log("Bundle_0p => newBundle_0p=" + newBundle_0p)
        return newBundle_0p
      }
    }

    // Bundle(Bundle b)
    // Bundle(android.os.Bundle)
    var func_Bundle_Bundle_1pb = cls_Bundle.$init.overload("android.os.Bundle")
    console.log("func_Bundle_Bundle_1pb=" + func_Bundle_Bundle_1pb)
    if (func_Bundle_Bundle_1pb) {
      func_Bundle_Bundle_1pb.implementation = function (b) {
        var funcName = "Bundle_1pb"
        var funcParaDict = {
          "b": b,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var newBundle_1pb = this.$init(b)
        console.log("Bundle_1pb => newBundle_1pb=" + newBundle_1pb)
        return newBundle_1pb
      }
    }

    // Bundle(PersistableBundle b)
    // Bundle(android.os.PersistableBundle)
    var func_Bundle_Bundle_1pb = cls_Bundle.$init.overload("android.os.PersistableBundle")
    console.log("func_Bundle_Bundle_1pb=" + func_Bundle_Bundle_1pb)
    if (func_Bundle_Bundle_1pb) {
      func_Bundle_Bundle_1pb.implementation = function (b) {
        var funcName = "Bundle_1pb"
        var funcParaDict = {
          "b": b,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var newBundle_1pb = this.$init(b)
        console.log("Bundle_1pb => newBundle_1pb=" + newBundle_1pb)
        return newBundle_1pb
      }
    }

    // Bundle(int capacity)
    // Bundle(int)
    var func_Bundle_Bundle_1pc = cls_Bundle.$init.overload("int")
    console.log("func_Bundle_Bundle_1pc=" + func_Bundle_Bundle_1pc)
    if (func_Bundle_Bundle_1pc) {
      func_Bundle_Bundle_1pc.implementation = function (capacity) {
        var funcName = "Bundle_1pc"
        var funcParaDict = {
          "capacity": capacity,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var newBundle_1pc = this.$init(capacity)
        console.log("Bundle_1pc => newBundle_1pc=" + newBundle_1pc)
        return newBundle_1pc
      }
    }

    // Bundle(ClassLoader loader)
    // Bundle(java.lang.ClassLoader)
    var func_Bundle_Bundle_1pl = cls_Bundle.$init.overload("java.lang.ClassLoader")
    console.log("func_Bundle_Bundle_1pl=" + func_Bundle_Bundle_1pl)
    if (func_Bundle_Bundle_1pl) {
      func_Bundle_Bundle_1pl.implementation = function (loader) {
        var funcName = "Bundle_1pl"
        var funcParaDict = {
          "loader": loader,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var newBundle_1pl = this.$init(loader)
        console.log("Bundle_1pl => newBundle_1pl=" + newBundle_1pl)
        return newBundle_1pl
      }
    }

    // Bundle getBundle(String key)
    // public android.os.Bundle android.os.Bundle.getBundle(java.lang.String)
    var func_Bundle_getBundle = cls_Bundle.getBundle
    console.log("func_Bundle_getBundle=" + func_Bundle_getBundle)
    if (func_Bundle_getBundle) {
      func_Bundle_getBundle.implementation = function (key) {
        var funcName = "Bundle.getBundle"
        var funcParaDict = {
          "key": key,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBundle = this.getBundle(key)
        console.log("Bundle.getBundle => retBundle=" + retBundle)
        return retBundle
      }
    }

    // IBinder getBinder(String key)
    // public android.os.IBinder android.os.Bundle.getBinder(java.lang.String)
    var func_Bundle_getBinder = cls_Bundle.getBinder
    console.log("func_Bundle_getBinder=" + func_Bundle_getBinder)
    if (func_Bundle_getBinder) {
      func_Bundle_getBinder.implementation = function (key) {
        var funcName = "Bundle.getBinder"
        var funcParaDict = {
          "key": key,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBinder = this.getBinder(key)
        console.log("Bundle.getBinder => retBinder=" + retBinder)
        return retBinder
      }
    }

    // <T extends Parcelable>T getParcelable(String key)
    // public android.os.Parcelable android.os.Bundle.getParcelable(java.lang.String)
    var func_Bundle_getParcelable_1pk = cls_Bundle.getParcelable.overload("java.lang.String")
    console.log("func_Bundle_getParcelable_1pk=" + func_Bundle_getParcelable_1pk)
    if (func_Bundle_getParcelable_1pk) {
      func_Bundle_getParcelable_1pk.implementation = function (key) {
        var funcName = "Bundle.getParcelable_1pk"
        var funcParaDict = {
          "key": key,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retParcelable_1pk = this.getParcelable(key)
        console.log("Bundle.getParcelable_1pk => retParcelable_1pk=" + retParcelable_1pk)
        return retParcelable_1pk
      }
    }

    // <T>T getParcelable(String key, Class<T> clazz)
    // public java.lang.Object android.os.Bundle.getParcelable(java.lang.String,java.lang.Class)
    var func_Bundle_getParcelable_2pkc = cls_Bundle.getParcelable.overload("java.lang.String", "java.lang.Class")
    console.log("func_Bundle_getParcelable_2pkc=" + func_Bundle_getParcelable_2pkc)
    if (func_Bundle_getParcelable_2pkc) {
      func_Bundle_getParcelable_2pkc.implementation = function (key, clazz) {
        var funcName = "Bundle.getParcelable_2pkc"
        var funcParaDict = {
          "key": key,
          "clazz": clazz,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retParcelable_2pkc = this.getParcelable(key, clazz)
        console.log("Bundle.getParcelable_2pkc => retParcelable_2pkc=" + retParcelable_2pkc)
        return retParcelable_2pkc
      }
    }

    // Parcelable[] getParcelableArray(String key)
    // public android.os.Parcelable[] android.os.Bundle.getParcelableArray(java.lang.String)
    var func_Bundle_getParcelableArray_1pk = cls_Bundle.getParcelableArray.overload("java.lang.String")
    console.log("func_Bundle_getParcelableArray_1pk=" + func_Bundle_getParcelableArray_1pk)
    if (func_Bundle_getParcelableArray_1pk) {
      func_Bundle_getParcelableArray_1pk.implementation = function (key) {
        var funcName = "Bundle.getParcelableArray_1pk"
        var funcParaDict = {
          "key": key,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retParcelableArray_1pk = this.getParcelableArray(key)
        console.log("Bundle.getParcelableArray_1pk => retParcelableArray_1pk=" + retParcelableArray_1pk)
        return retParcelableArray_1pk
      }
    }

    // <T>T[] getParcelableArray(String key, Class<T> clazz)
    // public java.lang.Object[] android.os.Bundle.getParcelableArray(java.lang.String,java.lang.Class)
    var func_Bundle_getParcelableArray_2pkc = cls_Bundle.getParcelableArray.overload("java.lang.String", "java.lang.Class")
    console.log("func_Bundle_getParcelableArray_2pkc=" + func_Bundle_getParcelableArray_2pkc)
    if (func_Bundle_getParcelableArray_2pkc) {
      func_Bundle_getParcelableArray_2pkc.implementation = function (key, clazz) {
        var funcName = "Bundle.getParcelableArray_2pkc"
        var funcParaDict = {
          "key": key,
          "clazz": clazz,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retParcelableArray_2pkc = this.getParcelableArray(key, clazz)
        console.log("Bundle.getParcelableArray_2pkc => retParcelableArray_2pkc=" + retParcelableArray_2pkc)
        return retParcelableArray_2pkc
      }
    }

    // <T> ArrayList<T> getParcelableArrayList(String key, Class<? extends T> clazz)
    // public java.lang.Object android.os.Bundle.getParcelable(java.lang.String,java.lang.Class)
    var func_Bundle_getParcelableArrayList_2pkc = cls_Bundle.getParcelableArrayList.overload("java.lang.String", "java.lang.Class")
    console.log("func_Bundle_getParcelableArrayList_2pkc=" + func_Bundle_getParcelableArrayList_2pkc)
    if (func_Bundle_getParcelableArrayList_2pkc) {
      func_Bundle_getParcelableArrayList_2pkc.implementation = function (key, clazz) {
        var funcName = "Bundle.getParcelableArrayList_2pkc"
        var funcParaDict = {
          "key": key,
          "clazz": clazz,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retParcelableArrayList_2pkc = this.getParcelableArrayList(key, clazz)
        console.log("Bundle.getParcelableArrayList_2pkc => retParcelableArrayList_2pkc=" + retParcelableArrayList_2pkc)
        return retParcelableArrayList_2pkc
      }
    }

    // <T extends Parcelable> ArrayList<T> getParcelableArrayList(String key)
    // public java.util.ArrayList android.os.Bundle.getParcelableArrayList(java.lang.String)
    var func_Bundle_getParcelableArrayList_1pk = cls_Bundle.getParcelableArrayList.overload("java.lang.String")
    console.log("func_Bundle_getParcelableArrayList_1pk=" + func_Bundle_getParcelableArrayList_1pk)
    if (func_Bundle_getParcelableArrayList_1pk) {
      func_Bundle_getParcelableArrayList_1pk.implementation = function (key) {
        var funcName = "Bundle.getParcelableArrayList_1pk"
        var funcParaDict = {
          "key": key,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retParcelableArrayList_1pk = this.getParcelableArrayList(key)
        console.log("Bundle.getParcelableArrayList_1pk => retParcelableArrayList_1pk=" + retParcelableArrayList_1pk)
        return retParcelableArrayList_1pk
      }
    }

    // void putAll(Bundle bundle)
    // public void android.os.Bundle.putAll(android.os.Bundle)
    var func_Bundle_putAll = cls_Bundle.putAll
    console.log("func_Bundle_putAll=" + func_Bundle_putAll)
    if (func_Bundle_putAll) {
      func_Bundle_putAll.implementation = function (bundle) {
        var funcName = "Bundle.putAll"
        var funcParaDict = {
          "bundle": bundle,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.putAll(bundle)
      }
    }

    // void putBinder(String key, IBinder value)
    // public void android.os.Bundle.putBinder(java.lang.String,android.os.IBinder)
    var func_Bundle_putBinder = cls_Bundle.putBinder
    console.log("func_Bundle_putBinder=" + func_Bundle_putBinder)
    if (func_Bundle_putBinder) {
      func_Bundle_putBinder.implementation = function (key, value) {
        var funcName = "Bundle.putBinder"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.putBinder(key, value)
      }
    }

    // void putBundle(String key, Bundle value)
    // public void android.os.Bundle.putBundle(java.lang.String,android.os.Bundle)
    var func_Bundle_putBundle = cls_Bundle.putBundle
    console.log("func_Bundle_putBundle=" + func_Bundle_putBundle)
    if (func_Bundle_putBundle) {
      func_Bundle_putBundle.implementation = function (key, value) {
        var funcName = "Bundle.putBundle"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.putBundle(key, value)
      }
    }

    // void putParcelable(String key, Parcelable value)
    // public void android.os.Bundle.putParcelable(java.lang.String,android.os.Parcelable)
    var func_Bundle_putParcelable = cls_Bundle.putParcelable
    console.log("func_Bundle_putParcelable=" + func_Bundle_putParcelable)
    if (func_Bundle_putParcelable) {
      func_Bundle_putParcelable.implementation = function (key, value) {
        var funcName = "Bundle.putParcelable"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.putParcelable(key, value)
      }
    }

    // void putParcelableArray(String key, Parcelable[] value)
    // public void android.os.Bundle.putParcelableArray(java.lang.String,android.os.Parcelable[])
    var func_Bundle_putParcelableArray = cls_Bundle.putParcelableArray
    console.log("func_Bundle_putParcelableArray=" + func_Bundle_putParcelableArray)
    if (func_Bundle_putParcelableArray) {
      func_Bundle_putParcelableArray.implementation = function (key, value) {
        var funcName = "Bundle.putParcelableArray"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.putParcelableArray(key, value)
      }
    }

    // void putParcelableArrayList(String key, ArrayList<? extends Parcelable> value)
    // public void android.os.Bundle.putParcelableArrayList(java.lang.String,java.util.ArrayList)
    var func_Bundle_putParcelableArrayList = cls_Bundle.putParcelableArrayList
    console.log("func_Bundle_putParcelableArrayList=" + func_Bundle_putParcelableArrayList)
    if (func_Bundle_putParcelableArrayList) {
      func_Bundle_putParcelableArrayList.implementation = function (key, value) {
        var funcName = "Bundle.putParcelableArrayList"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.putParcelableArrayList(key, value)
      }
    }

    // void putSparseParcelableArray(String key, SparseArray<? extends Parcelable> value)
    // public void android.os.Bundle.putSparseParcelableArray(java.lang.String,android.util.SparseArray)
    var func_Bundle_putSparseParcelableArray = cls_Bundle.putSparseParcelableArray
    console.log("func_Bundle_putSparseParcelableArray=" + func_Bundle_putSparseParcelableArray)
    if (func_Bundle_putSparseParcelableArray) {
      func_Bundle_putSparseParcelableArray.implementation = function (key, value) {
        var funcName = "Bundle.putSparseParcelableArray"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.putSparseParcelableArray(key, value)
      }
    }

    // void readFromParcel(Parcel parcel)
    // public void android.os.Bundle.readFromParcel(android.os.Parcel)
    var func_Bundle_readFromParcel = cls_Bundle.readFromParcel
    console.log("func_Bundle_readFromParcel=" + func_Bundle_readFromParcel)
    if (func_Bundle_readFromParcel) {
      func_Bundle_readFromParcel.implementation = function (parcel) {
        var funcName = "Bundle.readFromParcel"
        var funcParaDict = {
          "parcel": parcel,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.readFromParcel(parcel)
      }
    }

    // void writeToParcel(Parcel parcel, int flags)
    // public void android.os.Bundle.writeToParcel(android.os.Parcel,int)
    var func_Bundle_writeToParcel = cls_Bundle.writeToParcel
    console.log("func_Bundle_writeToParcel=" + func_Bundle_writeToParcel)
    if (func_Bundle_writeToParcel) {
      func_Bundle_writeToParcel.implementation = function (parcel, flags) {
        var funcName = "Bundle.writeToParcel"
        var funcParaDict = {
          "parcel": parcel,
          "flags": flags,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.writeToParcel(parcel, flags)
      }
    }

    // void remove(String key)
    // public void android.os.Bundle.remove(java.lang.String)
    var func_Bundle_remove = cls_Bundle.remove
    console.log("func_Bundle_remove=" + func_Bundle_remove)
    if (func_Bundle_remove) {
      func_Bundle_remove.implementation = function (key) {
        var funcName = "Bundle.remove"
        var funcParaDict = {
          "key": key,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.remove(key)
      }
    }
  }

  static BaseBundle() {
    var clsName_BaseBundle = "android.os.BaseBundle"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_BaseBundle)

    var cls_BaseBundle = Java.use(clsName_BaseBundle)
    console.log("cls_BaseBundle=" + cls_BaseBundle)

    
    // boolean containsKey(String key)
    // public boolean android.os.BaseBundle.containsKey(java.lang.String)
    var func_BaseBundle_containsKey = cls_BaseBundle.containsKey
    console.log("func_BaseBundle_containsKey=" + func_BaseBundle_containsKey)
    if (func_BaseBundle_containsKey) {
      func_BaseBundle_containsKey.implementation = function (key) {
        var funcName = "BaseBundle.containsKey"
        var funcParaDict = {
          "key": key,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean = this.containsKey(key)
        console.log("BaseBundle.containsKey => retBoolean=" + retBoolean)
        return retBoolean
      }
    }

    // boolean getBoolean(String key, boolean defaultValue)
    // public boolean android.os.BaseBundle.getBoolean(java.lang.String,boolean)
    var func_BaseBundle_getBoolean_2pkd = cls_BaseBundle.getBoolean.overload("java.lang.String", "boolean")
    console.log("func_BaseBundle_getBoolean_2pkd=" + func_BaseBundle_getBoolean_2pkd)
    if (func_BaseBundle_getBoolean_2pkd) {
      func_BaseBundle_getBoolean_2pkd.implementation = function (key, defaultValue) {
        var funcName = "BaseBundle.getBoolean_2pkd"
        var funcParaDict = {
          "key": key,
          "defaultValue": defaultValue,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean_2pkd = this.getBoolean(key, defaultValue)
        console.log("BaseBundle.getBoolean_2pkd => retBoolean_2pkd=" + retBoolean_2pkd)
        return retBoolean_2pkd
      }
    }

    // boolean getBoolean(String key)
    // public boolean android.os.BaseBundle.getBoolean(java.lang.String)
    var func_BaseBundle_getBoolean_1pk = cls_BaseBundle.getBoolean.overload("java.lang.String")
    console.log("func_BaseBundle_getBoolean_1pk=" + func_BaseBundle_getBoolean_1pk)
    if (func_BaseBundle_getBoolean_1pk) {
      func_BaseBundle_getBoolean_1pk.implementation = function (key) {
        var funcName = "BaseBundle.getBoolean_1pk"
        var funcParaDict = {
          "key": key,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean_1pk = this.getBoolean(key)
        console.log("BaseBundle.getBoolean_1pk => retBoolean_1pk=" + retBoolean_1pk)
        return retBoolean_1pk
      }
    }

    // void putAll(PersistableBundle bundle)
    // public void android.os.BaseBundle.putAll(android.os.PersistableBundle)
    var func_BaseBundle_putAll_1pb = cls_BaseBundle.putAll.overload("android.os.PersistableBundle")
    console.log("func_BaseBundle_putAll_1pb=" + func_BaseBundle_putAll_1pb)
    if (func_BaseBundle_putAll_1pb) {
      func_BaseBundle_putAll_1pb.implementation = function (bundle) {
        var funcName = "BaseBundle.putAll_1pb"
        var funcParaDict = {
          "bundle": bundle,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.putAll(bundle)
      }
    }

    // void putAll(ArrayMap map)
    // void android.os.BaseBundle.putAll(android.util.ArrayMap)
    var func_BaseBundle_putAll_1pm = cls_BaseBundle.putAll.overload("android.util.ArrayMap")
    console.log("func_BaseBundle_putAll_1pm=" + func_BaseBundle_putAll_1pm)
    if (func_BaseBundle_putAll_1pm) {
      func_BaseBundle_putAll_1pm.implementation = function (map) {
        var funcName = "BaseBundle.putAll_1pm"
        var funcParaDict = {
          "map": map,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.putAll(map)
      }
    }

    // void putBoolean(String key, boolean value)
    // public void android.os.BaseBundle.putBoolean(java.lang.String,boolean)
    var func_BaseBundle_putBoolean = cls_BaseBundle.putBoolean
    console.log("func_BaseBundle_putBoolean=" + func_BaseBundle_putBoolean)
    if (func_BaseBundle_putBoolean) {
      func_BaseBundle_putBoolean.implementation = function (key, value) {
        var funcName = "BaseBundle.putBoolean"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.putBoolean(key, value)
      }
    }

    // void putBooleanArray(String key, boolean[] value)
    // public void android.os.BaseBundle.putBooleanArray(java.lang.String,boolean[])
    var func_BaseBundle_putBooleanArray = cls_BaseBundle.putBooleanArray
    console.log("func_BaseBundle_putBooleanArray=" + func_BaseBundle_putBooleanArray)
    if (func_BaseBundle_putBooleanArray) {
      func_BaseBundle_putBooleanArray.implementation = function (key, value) {
        var funcName = "BaseBundle.putBooleanArray"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.putBooleanArray(key, value)
      }
    }

    // void putDouble(String key, double value)
    // public void android.os.BaseBundle.putDouble(java.lang.String,double)
    var func_BaseBundle_putDouble = cls_BaseBundle.putDouble
    console.log("func_BaseBundle_putDouble=" + func_BaseBundle_putDouble)
    if (func_BaseBundle_putDouble) {
      func_BaseBundle_putDouble.implementation = function (key, value) {
        var funcName = "BaseBundle.putDouble"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.putDouble(key, value)
      }
    }

    // void putDoubleArray(String key, double[] value)
    // public void android.os.BaseBundle.putDoubleArray(java.lang.String,double[])
    var func_BaseBundle_putDoubleArray = cls_BaseBundle.putDoubleArray
    console.log("func_BaseBundle_putDoubleArray=" + func_BaseBundle_putDoubleArray)
    if (func_BaseBundle_putDoubleArray) {
      func_BaseBundle_putDoubleArray.implementation = function (key, value) {
        var funcName = "BaseBundle.putDoubleArray"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.putDoubleArray(key, value)
      }
    }

    // void putInt(String key, int value)
    // public void android.os.BaseBundle.putInt(java.lang.String,int)
    var func_BaseBundle_putInt = cls_BaseBundle.putInt
    console.log("func_BaseBundle_putInt=" + func_BaseBundle_putInt)
    if (func_BaseBundle_putInt) {
      func_BaseBundle_putInt.implementation = function (key, value) {
        var funcName = "BaseBundle.putInt"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.putInt(key, value)
      }
    }

    // void putIntArray(String key, int[] value)
    // public void android.os.BaseBundle.putIntArray(java.lang.String,int[])
    var func_BaseBundle_putIntArray = cls_BaseBundle.putIntArray
    console.log("func_BaseBundle_putIntArray=" + func_BaseBundle_putIntArray)
    if (func_BaseBundle_putIntArray) {
      func_BaseBundle_putIntArray.implementation = function (key, value) {
        var funcName = "BaseBundle.putIntArray"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.putIntArray(key, value)
      }
    }

    // void putLong(String key, long value)
    // public void android.os.BaseBundle.putLong(java.lang.String,long)
    var func_BaseBundle_putLong = cls_BaseBundle.putLong
    console.log("func_BaseBundle_putLong=" + func_BaseBundle_putLong)
    if (func_BaseBundle_putLong) {
      func_BaseBundle_putLong.implementation = function (key, value) {
        var funcName = "BaseBundle.putLong"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.putLong(key, value)
      }
    }

    // void putLongArray(String key, long[] value)
    // public void android.os.BaseBundle.putLongArray(java.lang.String,long[])
    var func_BaseBundle_putLongArray = cls_BaseBundle.putLongArray
    console.log("func_BaseBundle_putLongArray=" + func_BaseBundle_putLongArray)
    if (func_BaseBundle_putLongArray) {
      func_BaseBundle_putLongArray.implementation = function (key, value) {
        var funcName = "BaseBundle.putLongArray"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.putLongArray(key, value)
      }
    }

    // void putString(String key, String value)
    // public void android.os.BaseBundle.putString(java.lang.String,java.lang.String)
    var func_BaseBundle_putString = cls_BaseBundle.putString
    console.log("func_BaseBundle_putString=" + func_BaseBundle_putString)
    if (func_BaseBundle_putString) {
      func_BaseBundle_putString.implementation = function (key, value) {
        var funcName = "BaseBundle.putString"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.putString(key, value)
      }
    }

    // void putStringArray(String key, String[] value)
    // public void android.os.BaseBundle.putStringArray(java.lang.String,java.lang.String[])
    var func_BaseBundle_putStringArray = cls_BaseBundle.putStringArray
    console.log("func_BaseBundle_putStringArray=" + func_BaseBundle_putStringArray)
    if (func_BaseBundle_putStringArray) {
      func_BaseBundle_putStringArray.implementation = function (key, value) {
        var funcName = "BaseBundle.putStringArray"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.putStringArray(key, value)
      }
    }

    // void remove(String key)
    // public void android.os.BaseBundle.remove(java.lang.String)
    var func_BaseBundle_remove = cls_BaseBundle.remove
    console.log("func_BaseBundle_remove=" + func_BaseBundle_remove)
    if (func_BaseBundle_remove) {
      func_BaseBundle_remove.implementation = function (key) {
        var funcName = "BaseBundle.remove"
        var funcParaDict = {
          "key": key,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.remove(key)
      }
    }

    // Object get(String key)
    // public java.lang.Object android.os.BaseBundle.get(java.lang.String)
    var func_BaseBundle_get_1pk = cls_BaseBundle.get.overload("java.lang.String")
    console.log("func_BaseBundle_get_1pk=" + func_BaseBundle_get_1pk)
    if (func_BaseBundle_get_1pk) {
      func_BaseBundle_get_1pk.implementation = function (key) {
        var funcName = "BaseBundle.get_1pk"
        var funcParaDict = {
          "key": key,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retObject_1pk = this.get(key)
        console.log("BaseBundle.get_1pk => retObject_1pk=" + retObject_1pk)
        return retObject_1pk
      }
    }

    // <T>T get(String key, Class<T> clazz)
    // java.lang.Object android.os.BaseBundle.get(java.lang.String,java.lang.Class)
    var func_BaseBundle_get_2pkc = cls_BaseBundle.get.overload("java.lang.String", "java.lang.Class")
    console.log("func_BaseBundle_get_2pkc=" + func_BaseBundle_get_2pkc)
    if (func_BaseBundle_get_2pkc) {
      func_BaseBundle_get_2pkc.implementation = function (key, clazz) {
        var funcName = "BaseBundle.get_2pkc"
        var funcParaDict = {
          "key": key,
          "clazz": clazz,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var ret_T_T_2pkc = this.get(key, clazz)
        console.log("BaseBundle.get_2pkc => ret_T_T_2pkc=" + ret_T_T_2pkc)
        return ret_T_T_2pkc
      }
    }

    // String getString(String key)
    // public java.lang.String android.os.BaseBundle.getString(java.lang.String)
    var func_BaseBundle_getString_1pk = cls_BaseBundle.getString.overload("java.lang.String")
    console.log("func_BaseBundle_getString_1pk=" + func_BaseBundle_getString_1pk)
    if (func_BaseBundle_getString_1pk) {
      func_BaseBundle_getString_1pk.implementation = function (key) {
        var funcName = "BaseBundle.getString_1pk"
        var funcParaDict = {
          "key": key,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retString_1pk = this.getString(key)
        console.log("BaseBundle.getString_1pk => retString_1pk=" + retString_1pk)
        return retString_1pk
      }
    }

    // String getString(String key, String defaultValue)
    // public java.lang.String android.os.BaseBundle.getString(java.lang.String,java.lang.String)
    var func_BaseBundle_getString_2pkd = cls_BaseBundle.getString.overload("java.lang.String", "java.lang.String")
    console.log("func_BaseBundle_getString_2pkd=" + func_BaseBundle_getString_2pkd)
    if (func_BaseBundle_getString_2pkd) {
      func_BaseBundle_getString_2pkd.implementation = function (key, defaultValue) {
        var funcName = "BaseBundle.getString_2pkd"
        var funcParaDict = {
          "key": key,
          "defaultValue": defaultValue,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retString_2pkd = this.getString(key, defaultValue)
        console.log("BaseBundle.getString_2pkd => retString_2pkd=" + retString_2pkd)
        return retString_2pkd
      }
    }

    // String[] getStringArray(String key)
    // public java.lang.String[] android.os.BaseBundle.getStringArray(java.lang.String)
    var func_BaseBundle_getStringArray = cls_BaseBundle.getStringArray
    console.log("func_BaseBundle_getStringArray=" + func_BaseBundle_getStringArray)
    if (func_BaseBundle_getStringArray) {
      func_BaseBundle_getStringArray.implementation = function (key) {
        var funcName = "BaseBundle.getStringArray"
        var funcParaDict = {
          "key": key,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retStringArray = this.getStringArray(key)
        console.log("BaseBundle.getStringArray => retStringArray=" + retStringArray)
        return retStringArray
      }
    }
  }

  static Messenger() {
    var clsName_Messenger = "android.os.Messenger"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Messenger)

    var cls_Messenger = Java.use(clsName_Messenger)
    console.log("cls_Messenger=" + cls_Messenger)

    
    // Messenger(Handler target)
    // 
    var func_Messenger_Messenger_1ph = cls_Messenger.$init.overload('android.os.Handler')
    console.log("func_Messenger_Messenger_1ph=" + func_Messenger_Messenger_1ph)
    if (func_Messenger_Messenger_1ph) {
      func_Messenger_Messenger_1ph.implementation = function (targetHandler) {
        var funcName = "Messenger(Handler)"
        var funcParaDict = {
          "targetHandler": targetHandler,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var newMessenger_1ph = this.$init(targetHandler)
        console.log("Messenger(Handler) => newMessenger_1ph=" + newMessenger_1ph)
        return newMessenger_1ph
      }
    }

    // Messenger(IBinder target)
    // 
    var func_Messenger_Messenger_1pi = cls_Messenger.$init.overload('android.os.IBinder')
    console.log("func_Messenger_Messenger_1pi=" + func_Messenger_Messenger_1pi)
    if (func_Messenger_Messenger_1pi) {
      func_Messenger_Messenger_1pi.implementation = function (targetIBinder) {
        var funcName = "Messenger(IBinder)"
        var funcParaDict = {
          "targetIBinder": targetIBinder,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var newMessenger_1pi = this.$init(targetIBinder)
        console.log("Messenger(IBinder) => newMessenger_1pi=" + newMessenger_1pi)
        return newMessenger_1pi
      }
    }

    // int describeContents()
    // public int android.os.Messenger.describeContents()
    var func_Messenger_describeContents = cls_Messenger.describeContents
    console.log("func_Messenger_describeContents=" + func_Messenger_describeContents)
    if (func_Messenger_describeContents) {
      func_Messenger_describeContents.implementation = function () {
        var funcName = "Messenger.describeContents"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retInt = this.describeContents()
        console.log("Messenger.describeContents => retInt=" + retInt)
        return retInt
      }
    }

    // boolean equals(Object otherObj)
    // public boolean android.os.Messenger.equals(java.lang.Object)
    var func_Messenger_equals = cls_Messenger.equals
    console.log("func_Messenger_equals=" + func_Messenger_equals)
    if (func_Messenger_equals) {
      func_Messenger_equals.implementation = function (otherObj) {
        var funcName = "Messenger.equals"
        var funcParaDict = {
          "otherObj": otherObj,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean = this.equals(otherObj)
        console.log("Messenger.equals => retBoolean=" + retBoolean)
        return retBoolean
      }
    }

    // IBinder getBinder()
    // public android.os.IBinder android.os.Messenger.getBinder()
    var func_Messenger_getBinder = cls_Messenger.getBinder
    console.log("func_Messenger_getBinder=" + func_Messenger_getBinder)
    if (func_Messenger_getBinder) {
      func_Messenger_getBinder.implementation = function () {
        var funcName = "Messenger.getBinder"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBinder = this.getBinder()
        console.log("Messenger.getBinder => retBinder=" + retBinder)
        return retBinder
      }
    }

    // int hashCode()
    // public int android.os.Messenger.hashCode()
    var func_Messenger_hashCode = cls_Messenger.hashCode
    console.log("func_Messenger_hashCode=" + func_Messenger_hashCode)
    if (func_Messenger_hashCode) {
      func_Messenger_hashCode.implementation = function () {
        var funcName = "Messenger.hashCode"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retInt = this.hashCode()
        console.log("Messenger.hashCode => retInt=" + retInt)
        return retInt
      }
    }

    // static Messenger readMessengerOrNullFromParcel(Parcel inParcel)
    // public static android.os.Messenger android.os.Messenger.readMessengerOrNullFromParcel(android.os.Parcel)
    var func_Messenger_readMessengerOrNullFromParcel = cls_Messenger.readMessengerOrNullFromParcel
    console.log("func_Messenger_readMessengerOrNullFromParcel=" + func_Messenger_readMessengerOrNullFromParcel)
    if (func_Messenger_readMessengerOrNullFromParcel) {
      func_Messenger_readMessengerOrNullFromParcel.implementation = function (inParcel) {
        var funcName = "Messenger.readMessengerOrNullFromParcel"
        var funcParaDict = {
          "inParcel": inParcel,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retMessenger = this.readMessengerOrNullFromParcel(inParcel)
        console.log("Messenger.readMessengerOrNullFromParcel => retMessenger=" + retMessenger)
        return retMessenger
      }
    }

    // void send(Message message)
    // public void android.os.Messenger.send(android.os.Message) throws android.os.RemoteException
    var func_Messenger_send = cls_Messenger.send
    console.log("func_Messenger_send=" + func_Messenger_send)
    if (func_Messenger_send) {
      func_Messenger_send.implementation = function (message) {
        var funcName = "Messenger.send"
        var funcParaDict = {
          "message": message,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        FridaAndroidUtil.printClass_Message(message)

        return this.send(message)
      }
    }

    // static void writeMessengerOrNullToParcel(Messenger messenger, Parcel out)
    // public static void android.os.Messenger.writeMessengerOrNullToParcel(android.os.Messenger,android.os.Parcel)
    var func_Messenger_writeMessengerOrNullToParcel = cls_Messenger.writeMessengerOrNullToParcel
    console.log("func_Messenger_writeMessengerOrNullToParcel=" + func_Messenger_writeMessengerOrNullToParcel)
    if (func_Messenger_writeMessengerOrNullToParcel) {
      func_Messenger_writeMessengerOrNullToParcel.implementation = function (messenger, out) {
        var funcName = "Messenger.writeMessengerOrNullToParcel"
        var funcParaDict = {
          "messenger": messenger,
          "out": out,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.writeMessengerOrNullToParcel(messenger, out)
      }
    }

    // void writeToParcel(Parcel out, int flags)
    // public void android.os.Messenger.writeToParcel(android.os.Parcel,int)
    var func_Messenger_writeToParcel = cls_Messenger.writeToParcel
    console.log("func_Messenger_writeToParcel=" + func_Messenger_writeToParcel)
    if (func_Messenger_writeToParcel) {
      func_Messenger_writeToParcel.implementation = function (out, flags) {
        var funcName = "Messenger.writeToParcel"
        var funcParaDict = {
          "out": out,
          "flags": flags,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.writeToParcel(out, flags)
      }
    }
  }

  static Message() {
    var clsName_Message = "android.os.Message"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Message)

    var cls_Message = Java.use(clsName_Message)
    console.log("cls_Message=" + cls_Message)

    
    // Message()
    // 
    var func_Message_Message = cls_Message.$init
    console.log("func_Message_Message=" + func_Message_Message)
    if (func_Message_Message) {
      func_Message_Message.implementation = function () {
        var funcName = "Message"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var newMessage = this.$init()
        console.log("Message => newMessage=" + newMessage)
        return newMessage
      }
    }

    // static Message    obtain()
    // public static android.os.Message android.os.Message.obtain()
    var func_Message_obtain_0p = cls_Message.obtain.overload()
    console.log("func_Message_obtain_0p=" + func_Message_obtain_0p)
    if (func_Message_obtain_0p) {
      func_Message_obtain_0p.implementation = function () {
        var funcName = "Message.obtain_0p"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retMessage_0p = this.obtain()
        console.log("Message.obtain_0p => retMessage_0p=" + retMessage_0p)
        return retMessage_0p
      }
    }

    // void    setData(Bundle data)
    // public void android.os.Message.setData(android.os.Bundle)
    var func_Message_setData = cls_Message.setData
    console.log("func_Message_setData=" + func_Message_setData)
    if (func_Message_setData) {
      func_Message_setData.implementation = function (data) {
        var funcName = "Message.setData"
        var funcParaDict = {
          "data": data,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.setData(data)
      }
    }

    // Bundle    getData()
    // public android.os.Bundle android.os.Message.getData()
    var func_Message_getData = cls_Message.getData
    console.log("func_Message_getData=" + func_Message_getData)
    if (func_Message_getData) {
      func_Message_getData.implementation = function () {
        var funcName = "Message.getData"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retData = this.getData()
        console.log("Message.getData => retData=" + retData)
        return retData
      }
    }

    // void    writeToParcel(Parcel dest, int flags)
    // public void android.os.Message.writeToParcel(android.os.Parcel,int)
    var func_Message_writeToParcel = cls_Message.writeToParcel
    console.log("func_Message_writeToParcel=" + func_Message_writeToParcel)
    if (func_Message_writeToParcel) {
      func_Message_writeToParcel.implementation = function (dest, flags) {
        var funcName = "Message.writeToParcel"
        var funcParaDict = {
          "dest": dest,
          "flags": flags,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.writeToParcel(dest, flags)
      }
    }
  }

  static Intent() {
    var clsName_Intent = "android.content.Intent"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Intent)

    var cls_Intent = Java.use(clsName_Intent)
    console.log("cls_Intent=" + cls_Intent)

    
    // public Intent()
    // 
    var func_Intent_Intent_0p = cls_Intent.$init.overload()
    console.log("func_Intent_Intent_0p=" + func_Intent_Intent_0p)
    if (func_Intent_Intent_0p) {
      func_Intent_Intent_0p.implementation = function () {
        var funcName = "Intent_0p"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var newIntent_0p = this.$init()
        console.log("Intent_0p => newIntent_0p=" + newIntent_0p)
        return newIntent_0p
      }
    }

    // public Intent(String action)
    // 
    var func_Intent_Intent_1pa = cls_Intent.$init.overload("java.lang.String")
    console.log("func_Intent_Intent_1pa=" + func_Intent_Intent_1pa)
    if (func_Intent_Intent_1pa) {
      func_Intent_Intent_1pa.implementation = function (action) {
        var funcName = "Intent_1pa"
        var funcParaDict = {
          "action": action,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var newIntent_1pa = this.$init(action)
        console.log("Intent_1pa => newIntent_1pa=" + newIntent_1pa)
        return newIntent_1pa
      }
    }

    // public Intent(String action, Uri uri)
    // 
    var func_Intent_Intent_2pau = cls_Intent.$init.overload("java.lang.String", "android.net.Uri")
    console.log("func_Intent_Intent_2pau=" + func_Intent_Intent_2pau)
    if (func_Intent_Intent_2pau) {
      func_Intent_Intent_2pau.implementation = function (action, uri) {
        var funcName = "Intent_2pau"
        var funcParaDict = {
          "action": action,
          "uri": uri,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var newIntent_2pau = this.$init(action, uri)
        console.log("Intent_2pau => newIntent_2pau=" + newIntent_2pau)
        return newIntent_2pau
      }
    }

    // Intent    setPackage(String packageName)
    // public android.content.Intent android.content.Intent.setPackage(java.lang.String)
    var func_Intent_setPackage = cls_Intent.setPackage
    console.log("func_Intent_setPackage=" + func_Intent_setPackage)
    if (func_Intent_setPackage) {
      func_Intent_setPackage.implementation = function (packageName) {
        var funcName = "Intent.setPackage"
        var funcParaDict = {
          "packageName": packageName,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retIntent = this.setPackage(packageName)
        console.log("Intent.setPackage => retIntent=" + retIntent)
        return retIntent
      }
    }

    // Intent setAction(String action)
    // public android.content.Intent android.content.Intent.setAction(java.lang.String)
    var func_Intent_setAction = cls_Intent.setAction
    console.log("func_Intent_setAction=" + func_Intent_setAction)
    if (func_Intent_setAction) {
      func_Intent_setAction.implementation = function (action) {
        var funcName = "Intent.setAction"
        var funcParaDict = {
          "action": action,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retIntent = this.setAction(action)
        console.log("Intent.setAction => retIntent=" + retIntent)
        return retIntent
      }
    }

    // Intent    putExtras(Intent srcIntent)
    // public android.content.Intent android.content.Intent.putExtras(android.content.Intent)
    var func_Intent_putExtras_1ps = cls_Intent.putExtras.overload("android.content.Intent")
    console.log("func_Intent_putExtras_1ps=" + func_Intent_putExtras_1ps)
    if (func_Intent_putExtras_1ps) {
      func_Intent_putExtras_1ps.implementation = function (srcIntent) {
        var funcName = "Intent.putExtras_1ps"
        var funcParaDict = {
          "srcIntent": srcIntent,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retIntent_1ps = this.putExtras(srcIntent)
        console.log("Intent.putExtras_1ps => retIntent_1ps=" + retIntent_1ps)
        return retIntent_1ps
      }
    }

    // Intent    putExtras(Bundle extrasBundle)
    // public android.content.Intent android.content.Intent.putExtras(android.os.Bundle)
    var func_Intent_putExtras_1pe = cls_Intent.putExtras.overload("android.os.Bundle")
    console.log("func_Intent_putExtras_1pe=" + func_Intent_putExtras_1pe)
    if (func_Intent_putExtras_1pe) {
      func_Intent_putExtras_1pe.implementation = function (extrasBundle) {
        var funcName = "Intent.putExtras_1pe"
        var funcParaDict = {
          "extrasBundle": extrasBundle,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retIntent_1pe = this.putExtras(extrasBundle)
        console.log("Intent.putExtras_1pe => retIntent_1pe=" + retIntent_1pe)
        return retIntent_1pe
      }
    }

    // Intent    putExtra(String name, Parcelable value)
    // public android.content.Intent android.content.Intent.putExtra(java.lang.String,android.os.Parcelable)
    var func_Intent_putExtra_2pnv = cls_Intent.putExtra.overload("java.lang.String", "android.os.Parcelable")
    console.log("func_Intent_putExtra_2pnv=" + func_Intent_putExtra_2pnv)
    if (func_Intent_putExtra_2pnv) {
      func_Intent_putExtra_2pnv.implementation = function (name, value) {
        var funcName = "Intent.putExtra_2pnv"
        var funcParaDict = {
          "name": name,
          "value": value,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retIntent_2pnv = this.putExtra(name, value)
        console.log("Intent.putExtra_2pnv => retIntent_2pnv=" + retIntent_2pnv)
        return retIntent_2pnv
      }
    }

    // Intent    putExtra(String name, String value)
    // public android.content.Intent android.content.Intent.putExtra(java.lang.String,java.lang.String)
    var func_Intent_putExtra_2pnv = cls_Intent.putExtra.overload("java.lang.String", "java.lang.String")
    console.log("func_Intent_putExtra_2pnv=" + func_Intent_putExtra_2pnv)
    if (func_Intent_putExtra_2pnv) {
      func_Intent_putExtra_2pnv.implementation = function (name, value) {
        var funcName = "Intent.putExtra_2pnv"
        var funcParaDict = {
          "name": name,
          "value": value,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retIntent_2pnv = this.putExtra(name, value)
        console.log("Intent.putExtra_2pnv => retIntent_2pnv=" + retIntent_2pnv)
        return retIntent_2pnv
      }
    }

    // Bundle    getExtras()
    // public android.os.Bundle android.content.Intent.getExtras()
    var func_Intent_getExtras = cls_Intent.getExtras
    console.log("func_Intent_getExtras=" + func_Intent_getExtras)
    if (func_Intent_getExtras) {
      func_Intent_getExtras.implementation = function () {
        var funcName = "Intent.getExtras"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retExtras = this.getExtras()
        console.log("Intent.getExtras => retExtras=" + retExtras)
        return retExtras
      }
    }

    // String    getStringExtra(String name)
    // public java.lang.String android.content.Intent.getStringExtra(java.lang.String)
    var func_Intent_getStringExtra = cls_Intent.getStringExtra
    console.log("func_Intent_getStringExtra=" + func_Intent_getStringExtra)
    if (func_Intent_getStringExtra) {
      func_Intent_getStringExtra.implementation = function (name) {
        var funcName = "Intent.getStringExtra"
        var funcParaDict = {
          "name": name,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retStringExtra = this.getStringExtra(name)
        console.log("Intent.getStringExtra => retStringExtra=" + retStringExtra)
        return retStringExtra
      }
    }

    // String    getAction()
    // public java.lang.String android.content.Intent.getAction()
    var func_Intent_getAction = cls_Intent.getAction
    console.log("func_Intent_getAction=" + func_Intent_getAction)
    if (func_Intent_getAction) {
      func_Intent_getAction.implementation = function () {
        var funcName = "Intent.getAction"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retAction = this.getAction()
        console.log("Intent.getAction => retAction=" + retAction)
        return retAction
      }
    }
  }

}