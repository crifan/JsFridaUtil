/*
	File: FridaHookAndroidJava.js
	Function: crifan's Frida hook common Android Java related functions
	Author: Crifan Li
	Latest: https://github.com/crifan/JsFridaUtil/blob/main/frida/FridaHookAndroidJava.js
	Updated: 20251203
*/

// Frida hook common Android/Java class
class FridaHookAndroidJava {
  constructor() {
    console.log("FridaHookAndroidJava constructor")
  }

  static JSONObject(callback_isShowLog=null) {
    var className_JSONObject = "org.json.JSONObject"
    // FridaAndroidUtil.printClassAllMethodsFields(className_JSONObject)

    var cls_JSONObject = Java.use(className_JSONObject)
    console.log("cls_JSONObject=" + cls_JSONObject)

    // curLogFunc = FridaAndroidUtil.printFunctionCallAndStack
    var curLogFunc = FridaAndroidUtil.printFunctionCallStr

    // JSONObject	putOpt(String name, Object value)
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
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        var retJsonObj = this.put(str, obj)
        if (isShowLog){
          console.log(funcName + " => retJsonObj=" + retJsonObj)
        }
        return retJsonObj
      }
    }

    // String	toString()
    // public String toString()
    var func_JSONObject_toString_0p = cls_JSONObject.toString.overload()
    console.log("func_JSONObject_toString_0p=" + func_JSONObject_toString_0p)
    if (func_JSONObject_toString_0p) {
      func_JSONObject_toString_0p.implementation = function () {
        var funcName = "JSONObject.toString()"
        var funcParaDict = {
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        var retJsonStr = this.toString()
        if (isShowLog){
          console.log(funcName + " => retJsonStr=" + retJsonStr)
        }
        return retJsonStr
      }
    }

  }

  static HashMap(callback_isShowLog=null) {
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
        var funcName = "HashMap.put"
        var funcParaDict = {
          "keyObj": keyObj,
          "valueObj": valueObj,
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        var retObj = this.put(keyObj, valueObj)

        if (isShowLog) {
          console.log(funcName + " => retObj=" + retObj)
        }

        return retObj
      }
    }

    // public void java.util.HashMap.putAll(java.util.Map)
    // var func_HashMap_putAll = cls_HashMap.putAll('java.util.Map')
    var func_HashMap_putAll = cls_HashMap.putAll
    console.log("func_HashMap_putAll=" + func_HashMap_putAll)
    if (func_HashMap_putAll) {
      func_HashMap_putAll.implementation = function (newMap) {
        var funcName = "HashMap.putAll"
        var funcParaDict = {
          "newMap": newMap,
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        this.putAll(newMap)
        return
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
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        var retValObj = this.get(keyObj)

        if (isShowLog) {
          console.log(funcName + " => retValObj=" + retValObj)
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
        this.$init()
        var newBuilder_void = this
        console.log("newBuilder_void=" + newBuilder_void)
        return
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
    //     this.$init(request)
    //     var newBuilder_req = this
    //     console.log("newBuilder_req=" + newBuilder_req)
    //     return
    //   }
    // }

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

    const curLogFunc = FridaAndroidUtil.printFunctionCallAndStack
    // const curLogFunc = FridaAndroidUtil.printFunctionCallStr

    // Note: Xiaomi8 not exist: getApplicationInfo.overload('java.lang.String', 'android.content.pm.PackageManager$ApplicationInfoFlags')
    // public ApplicationInfo getApplicationInfo(String packageName, PackageManager.ApplicationInfoFlags flags)
    // public android.content.pm.ApplicationInfo android.content.pm.PackageManager.getApplicationInfo(java.lang.String,android.content.pm.PackageManager$ApplicationInfoFlags) throws android.content.pm.PackageManager$NameNotFoundException
    // var func_PackageManager_getApplicationInfo = cls_PackageManager.getApplicationInfo
    var func_PackageManager_getApplicationInfo = cls_PackageManager.getApplicationInfo.overload('java.lang.String', 'android.content.pm.PackageManager$ApplicationInfoFlags')
    // var func_PackageManager_getApplicationInfo = cls_PackageManager.getApplicationInfo.overload('java.lang.String', 'android.content.pm.PackageManager.ApplicationInfoFlags')
    console.log("func_PackageManager_getApplicationInfo=" + func_PackageManager_getApplicationInfo)
    if (func_PackageManager_getApplicationInfo) {
      func_PackageManager_getApplicationInfo.implementation = function (packageName, flags) {
        var funcName = "PackageManager.getApplicationInfo(packageName,flags)"
        var funcParaDict = {
          "packageName": packageName,
          "flags": flags,
        }

        var retAppInfo = this.getApplicationInfo(packageName, flags)

        var isMatch = false
        if (null != PackageManager_getApplicationInfo){
          isMatch = PackageManager_getApplicationInfo(packageName)
        }

        if (isMatch){
          curLogFunc(funcName, funcParaDict)

          // do hook bypass
          retAppInfo = ApplicationInfo()
        } else {
          // no hook
        }

        console.log("retAppInfo=" + retAppInfo)
        return retAppInfo
      }
    }

    // public abstract ApplicationInfo getApplicationInfo(String packageName, int flags)
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
          curLogFunc(funcName, funcParaDict)

          // // do hook bypass
          // retAppInfo_abstract = ApplicationInfo()
        } else {
          // no hook
        }

        console.log("retAppInfo_abstract=" + retAppInfo_abstract)
        return retAppInfo_abstract
      }
    }


    // abstract PackageInfo getPackageInfo(String packageName, int flags)
    // public abstract android.content.pm.PackageInfo android.content.pm.PackageManager.getPackageInfo(java.lang.String,int) throws android.content.pm.PackageManager$NameNotFoundException
    var func_PackageManager_getPackageInfo_2psi = cls_PackageManager.getPackageInfo.overload('java.lang.String', 'int')
    console.log("func_PackageManager_getPackageInfo_2psi=" + func_PackageManager_getPackageInfo_2psi)
    if (func_PackageManager_getPackageInfo_2psi) {
      func_PackageManager_getPackageInfo_2psi.implementation = function (packageName, flags) {
        var funcName = "PackageManager.getPackageInfo_2psi"
        var funcParaDict = {
          "packageName": packageName,
          "flags": flags,
        }
        curLogFunc(funcName, funcParaDict)

        var retPackageInfo_2psi = this.getPackageInfo(packageName, flags)
        console.log(funcName + " => retPackageInfo_2psi=" + retPackageInfo_2psi)
        return retPackageInfo_2psi
      }
    }

    // PackageInfo getPackageInfo(String packageName, PackageManager.PackageInfoFlags flags)
    // public android.content.pm.PackageInfo android.content.pm.PackageManager.getPackageInfo(java.lang.String,android.content.pm.PackageManager$PackageInfoFlags) throws android.content.pm.PackageManager$NameNotFoundException
    var func_PackageManager_getPackageInfo_2ppf = cls_PackageManager.getPackageInfo.overload('java.lang.String', 'android.content.pm.PackageManager$PackageInfoFlags')
    console.log("func_PackageManager_getPackageInfo_2ppf=" + func_PackageManager_getPackageInfo_2ppf)
    if (func_PackageManager_getPackageInfo_2ppf) {
      func_PackageManager_getPackageInfo_2ppf.implementation = function (packageName, flags) {
        var funcName = "PackageManager.getPackageInfo_2ppf"
        var funcParaDict = {
          "packageName": packageName,
          "flags": flags,
        }
        curLogFunc(funcName, funcParaDict)

        var retPackageInfo_2ppf = this.getPackageInfo(packageName, flags)
        console.log(funcName + " => retPackageInfo_2ppf=" + retPackageInfo_2ppf)
        var isGetSignatures = PackageManager.GET_SIGNATURES & flags
        console.log(funcName + " isGetSignatures=" + isGetSignatures)
        if(isGetSignatures){
          var signatures = retPackageInfo_2ppf.signatures
          console.log(funcName + " signatures=" + signatures)
        }
        return retPackageInfo_2ppf
      }
    }

    // public abstract int checkPermission(String permName, String packageName)
    // public abstract int android.content.pm.PackageManager.checkPermission(java.lang.String,java.lang.String)
    var func_PackageManager_checkPermission = cls_PackageManager.checkPermission
    console.log("func_PackageManager_checkPermission=" + func_PackageManager_checkPermission)
    if (func_PackageManager_checkPermission) {
      func_PackageManager_checkPermission.implementation = function (permName, packageName) {
        var funcName = "PackageManager.checkPermission"
        var funcParaDict = {
          "permName": permName,
          "packageName": packageName,
        }
        curLogFunc(funcName, funcParaDict)

        var retPermissionInt = this.checkPermission(permName, packageName)
        console.log(funcName + " => retPermissionInt=" + retPermissionInt)
        return retPermissionInt
      }
    }

  }

  static Signature() {
    var className_Signature = "android.content.pm.Signature"
    // FridaAndroidUtil.printClassAllMethodsFields(className_Signature)

    var cls_Signature = Java.use(className_Signature)
    console.log("cls_Signature=" + cls_Signature)

    const curLogFunc = FridaAndroidUtil.printFunctionCallAndStack
    // const curLogFunc = FridaAndroidUtil.printFunctionCallStr

    // public byte[] toByteArray()
    // public byte[] android.content.pm.Signature.toByteArray()
    var cls_Signature_toByteArray = cls_Signature.toByteArray
    console.log("cls_Signature_toByteArray=" + cls_Signature_toByteArray)
    if (cls_Signature_toByteArray) {
      cls_Signature_toByteArray.implementation = function () {
        var funcName = "Signature.toByteArray"
        var funcParaDict = {
        }
        curLogFunc(funcName, funcParaDict)

        var retBytes = this.toByteArray()
        console.log(funcName + " => retBytes: len=" + retBytes.length + ", var=" + retBytes)
        return retBytes
      }
    }

  }

  static ApplicationPackageManager() {
    var clsName_ApplicationPackageManager = "android.app.ApplicationPackageManager"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_ApplicationPackageManager)

    var cls_ApplicationPackageManager = Java.use(clsName_ApplicationPackageManager)
    console.log("cls_ApplicationPackageManager=" + cls_ApplicationPackageManager)

    
    // public int checkPermission(String permName, String pkgName)
    // public int android.app.ApplicationPackageManager.checkPermission(java.lang.String,java.lang.String)
    var func_ApplicationPackageManager_checkPermission = cls_ApplicationPackageManager.checkPermission
    console.log("func_ApplicationPackageManager_checkPermission=" + func_ApplicationPackageManager_checkPermission)
    if (func_ApplicationPackageManager_checkPermission) {
      func_ApplicationPackageManager_checkPermission.implementation = function (permName, pkgName) {
        var funcName = "ApplicationPackageManager.checkPermission"
        var funcParaDict = {
          "permName": permName,
          "pkgName": pkgName,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retInt = this.checkPermission(permName, pkgName)
        console.log(funcName + " => retInt=" + retInt)
        return retInt
      }
    }

    // public ApplicationInfo getApplicationInfo(String packageName, int flags) throws NameNotFoundException
    // public android.content.pm.ApplicationInfo android.app.ApplicationPackageManager.getApplicationInfo(java.lang.String,int) throws android.content.pm.PackageManager$NameNotFoundException
    var func_ApplicationPackageManager_getApplicationInfo_2ppf = cls_ApplicationPackageManager.getApplicationInfo.overload('java.lang.String', 'int')
    console.log("func_ApplicationPackageManager_getApplicationInfo_2ppf=" + func_ApplicationPackageManager_getApplicationInfo_2ppf)
    if (func_ApplicationPackageManager_getApplicationInfo_2ppf) {
      func_ApplicationPackageManager_getApplicationInfo_2ppf.implementation = function (packageName, flags) {
        var funcName = "ApplicationPackageManager.getApplicationInfo_2ppf"
        var funcParaDict = {
          "packageName": packageName,
          "flags": flags,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retApplicationInfo_2ppf = this.getApplicationInfo(packageName, flags)
        console.log(funcName + " => retApplicationInfo_2ppf=" + retApplicationInfo_2ppf)
        return retApplicationInfo_2ppf
      }
    }

    // public ApplicationInfo getApplicationInfo(String packageName, ApplicationInfoFlags flags) throws NameNotFoundException
    // public android.content.pm.ApplicationInfo android.app.ApplicationPackageManager.getApplicationInfo(java.lang.String,android.content.pm.PackageManager$ApplicationInfoFlags) throws android.content.pm.PackageManager$NameNotFoundException
    var func_ApplicationPackageManager_getApplicationInfo_2ppf = cls_ApplicationPackageManager.getApplicationInfo.overload('java.lang.String', 'android.content.pm.PackageManager$ApplicationInfoFlags')
    console.log("func_ApplicationPackageManager_getApplicationInfo_2ppf=" + func_ApplicationPackageManager_getApplicationInfo_2ppf)
    if (func_ApplicationPackageManager_getApplicationInfo_2ppf) {
      func_ApplicationPackageManager_getApplicationInfo_2ppf.implementation = function (packageName, flags) {
        var funcName = "ApplicationPackageManager.getApplicationInfo_2ppf"
        var funcParaDict = {
          "packageName": packageName,
          "flags": flags,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retApplicationInfo_2ppf = this.getApplicationInfo(packageName, flags)
        console.log(funcName + " => retApplicationInfo_2ppf=" + retApplicationInfo_2ppf)
        return retApplicationInfo_2ppf
      }
    }

    // public PackageInfo getPackageInfo(String packageName, int flags) throws NameNotFoundException
    // public android.content.pm.PackageInfo android.app.ApplicationPackageManager.getPackageInfo(java.lang.String,int) throws android.content.pm.PackageManager$NameNotFoundException
    var func_ApplicationPackageManager_getPackageInfo_2ppf = cls_ApplicationPackageManager.getPackageInfo.overload('java.lang.String', 'int')
    console.log("func_ApplicationPackageManager_getPackageInfo_2ppf=" + func_ApplicationPackageManager_getPackageInfo_2ppf)
    if (func_ApplicationPackageManager_getPackageInfo_2ppf) {
      func_ApplicationPackageManager_getPackageInfo_2ppf.implementation = function (packageName, flags) {
        var funcName = "ApplicationPackageManager.getPackageInfo_2ppf"
        var funcParaDict = {
          "packageName": packageName,
          "flags": flags,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retPackageInfo_2ppf = this.getPackageInfo(packageName, flags)
        console.log(funcName + " => retPackageInfo_2ppf=" + retPackageInfo_2ppf)
        return retPackageInfo_2ppf
      }
    }

    // public PackageInfo getPackageInfo(String packageName, PackageInfoFlags flags) throws NameNotFoundException
    // public android.content.pm.PackageInfo android.app.ApplicationPackageManager.getPackageInfo(java.lang.String,android.content.pm.PackageManager$PackageInfoFlags) throws android.content.pm.PackageManager$NameNotFoundException
    var func_ApplicationPackageManager_getPackageInfo_2ppf = cls_ApplicationPackageManager.getPackageInfo.overload('java.lang.String', 'android.content.pm.PackageManager$PackageInfoFlags')
    console.log("func_ApplicationPackageManager_getPackageInfo_2ppf=" + func_ApplicationPackageManager_getPackageInfo_2ppf)
    if (func_ApplicationPackageManager_getPackageInfo_2ppf) {
      func_ApplicationPackageManager_getPackageInfo_2ppf.implementation = function (packageName, flags) {
        var funcName = "ApplicationPackageManager.getPackageInfo_2ppf"
        var funcParaDict = {
          "packageName": packageName,
          "flags": flags,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retPackageInfo_2ppf = this.getPackageInfo(packageName, flags)
        console.log(funcName + " => retPackageInfo_2ppf=" + retPackageInfo_2ppf)
        return retPackageInfo_2ppf
      }
    }

    // public PackageInfo getPackageInfo(VersionedPackage versionedPackage, int flags) throws NameNotFoundException
    // public android.content.pm.PackageInfo android.app.ApplicationPackageManager.getPackageInfo(android.content.pm.VersionedPackage,int) throws android.content.pm.PackageManager$NameNotFoundException
    var func_ApplicationPackageManager_getPackageInfo_2pvf = cls_ApplicationPackageManager.getPackageInfo.overload('android.content.pm.VersionedPackage', 'int')
    console.log("func_ApplicationPackageManager_getPackageInfo_2pvf=" + func_ApplicationPackageManager_getPackageInfo_2pvf)
    if (func_ApplicationPackageManager_getPackageInfo_2pvf) {
      func_ApplicationPackageManager_getPackageInfo_2pvf.implementation = function (versionedPackage, flags) {
        var funcName = "ApplicationPackageManager.getPackageInfo_2pvf"
        var funcParaDict = {
          "versionedPackage": versionedPackage,
          "flags": flags,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retPackageInfo_2pvf = this.getPackageInfo(versionedPackage, flags)
        console.log(funcName + " => retPackageInfo_2pvf=" + retPackageInfo_2pvf)
        return retPackageInfo_2pvf
      }
    }

    // public PackageInfo getPackageInfo(VersionedPackage versionedPackage, PackageInfoFlags flags) throws NameNotFoundException
    // public android.content.pm.PackageInfo android.app.ApplicationPackageManager.getPackageInfo(android.content.pm.VersionedPackage,android.content.pm.PackageManager$PackageInfoFlags) throws android.content.pm.PackageManager$NameNotFoundException
    var func_ApplicationPackageManager_getPackageInfo_2pvf = cls_ApplicationPackageManager.getPackageInfo.overload('android.content.pm.VersionedPackage', 'android.content.pm.PackageManager$PackageInfoFlags')
    console.log("func_ApplicationPackageManager_getPackageInfo_2pvf=" + func_ApplicationPackageManager_getPackageInfo_2pvf)
    if (func_ApplicationPackageManager_getPackageInfo_2pvf) {
      func_ApplicationPackageManager_getPackageInfo_2pvf.implementation = function (versionedPackage, flags) {
        var funcName = "ApplicationPackageManager.getPackageInfo_2pvf"
        var funcParaDict = {
          "versionedPackage": versionedPackage,
          "flags": flags,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retPackageInfo_2pvf = this.getPackageInfo(versionedPackage, flags)
        console.log(funcName + " => retPackageInfo_2pvf=" + retPackageInfo_2pvf)
        return retPackageInfo_2pvf
      }
    }

    // public abstract boolean hasSystemFeature(String featureName)
    // public abstract boolean android.content.pm.PackageManager.hasSystemFeature(java.lang.String)
    var func_ApplicationPackageManager_hasSystemFeature_1pf = cls_ApplicationPackageManager.hasSystemFeature.overload('java.lang.String')
    console.log("func_ApplicationPackageManager_hasSystemFeature_1pf=" + func_ApplicationPackageManager_hasSystemFeature_1pf)
    if (func_ApplicationPackageManager_hasSystemFeature_1pf) {
      func_ApplicationPackageManager_hasSystemFeature_1pf.implementation = function (featureName) {
        var funcName = "ApplicationPackageManager.hasSystemFeature(featureName)"
        var funcParaDict = {
          "featureName": featureName,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retHasSystemFeature_1pf = this.hasSystemFeature(featureName)
        console.log(funcName + " => retHasSystemFeature_1pf=" + retHasSystemFeature_1pf)
        return retHasSystemFeature_1pf
      }
    }

    // public abstract boolean hasSystemFeature(String featureName, int version)
    // public abstract boolean android.content.pm.PackageManager.hasSystemFeature(java.lang.String,int)
    var func_ApplicationPackageManager_hasSystemFeature_2pfv = cls_ApplicationPackageManager.hasSystemFeature.overload('java.lang.String', 'int')
    console.log("func_ApplicationPackageManager_hasSystemFeature_2pfv=" + func_ApplicationPackageManager_hasSystemFeature_2pfv)
    if (func_ApplicationPackageManager_hasSystemFeature_2pfv) {
      func_ApplicationPackageManager_hasSystemFeature_2pfv.implementation = function (featureName, version) {
        var funcName = "ApplicationPackageManager.hasSystemFeature(featureName,version)"
        var funcParaDict = {
          "featureName": featureName,
          "version": version,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retHasSystemFeature_2pfv = this.hasSystemFeature(featureName, version)
        console.log(funcName + " => retHasSystemFeature_2pfv=" + retHasSystemFeature_2pfv)
        return retHasSystemFeature_2pfv
      }
    }

    // public String[] getSystemSharedLibraryNames() {
    // public java.lang.String[] android.app.ApplicationPackageManager.getSystemSharedLibraryNames()
    var func_ApplicationPackageManager_getSystemSharedLibraryNames = cls_ApplicationPackageManager.getSystemSharedLibraryNames
    console.log("func_ApplicationPackageManager_getSystemSharedLibraryNames=" + func_ApplicationPackageManager_getSystemSharedLibraryNames)
    if (func_ApplicationPackageManager_getSystemSharedLibraryNames) {
      func_ApplicationPackageManager_getSystemSharedLibraryNames.implementation = function () {
        var funcName = "ApplicationPackageManager.getSystemSharedLibraryNames"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var systemSharedLibraryNames = this.getSystemSharedLibraryNames()
        console.log(funcName + " => systemSharedLibraryNames=" + systemSharedLibraryNames)
        return systemSharedLibraryNames
      }
    }

    // public FeatureInfo[] getSystemAvailableFeatures() {
    // public android.content.pm.FeatureInfo[] android.app.ApplicationPackageManager.getSystemAvailableFeatures()
    var func_ApplicationPackageManager_getSystemAvailableFeatures = cls_ApplicationPackageManager.getSystemAvailableFeatures
    console.log("func_ApplicationPackageManager_getSystemAvailableFeatures=" + func_ApplicationPackageManager_getSystemAvailableFeatures)
    if (func_ApplicationPackageManager_getSystemAvailableFeatures) {
      func_ApplicationPackageManager_getSystemAvailableFeatures.implementation = function () {
        var funcName = "ApplicationPackageManager.getSystemAvailableFeatures"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var systemAvailableFeatures = this.getSystemAvailableFeatures()
        console.log(funcName + " => systemAvailableFeatures=" + systemAvailableFeatures)
        return systemAvailableFeatures
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


  static urlCommon_filterLogByUrl(curUrl, funcName, funcParaDict, curLogFunc, callback_isShowLog=null) {
    var urlLog = `${funcName}: curUrl=${curUrl}`
    // console.log(urlLog)
    var isShowLog = FridaAndroidUtil.showLogIfNecessary(callback_isShowLog, urlLog)
    if(isShowLog) {
      curLogFunc(funcName, funcParaDict)
    }

    return isShowLog
  }

  static HttpURLConnectionImpl(callback_isShowLog=null) {
    var clsName_HttpURLConnectionImpl = "com.android.okhttp.internal.huc.HttpURLConnectionImpl"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_HttpURLConnectionImpl)

    var cls_HttpURLConnectionImpl = Java.use(clsName_HttpURLConnectionImpl)
    console.log("cls_HttpURLConnectionImpl=" + cls_HttpURLConnectionImpl)

    const curLogFunc = FridaAndroidUtil.printFunctionCallAndStack
    // const curLogFunc = FridaAndroidUtil.printFunctionCallStr

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
        var funcCallStr = FridaAndroidUtil.genFunctionCallStr(funcName, funcParaDict)
        var isShowLog = FridaAndroidUtil.showLogIfNecessary(callback_isShowLog, funcCallStr)
        if(isShowLog) {
          curLogFunc(funcName, funcParaDict)
        }

        this.$init(url, client)
        if(isShowLog) {
          var newHttpURLConnectionImpl_2p = this
          console.log(`${funcName} => newHttpURLConnectionImpl_2p=${newHttpURLConnectionImpl_2p}`)
        }
        return
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
        var funcCallStr = FridaAndroidUtil.genFunctionCallStr(funcName, funcParaDict)
        var isShowLog = FridaAndroidUtil.showLogIfNecessary(callback_isShowLog, funcCallStr)
        if(isShowLog) {
          curLogFunc(funcName, funcParaDict)
        }

        this.$init(url, client, urlFilter)
        if(isShowLog) {
          var newHttpURLConnectionImpl_3p = this
          console.log(`${funcName} => newHttpURLConnectionImpl_3p=${newHttpURLConnectionImpl_3p}`)
        }
        return
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.connect()
        return
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.disconnect()
        return
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
        curLogFunc(funcName, funcParaDict)
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retErrorStream = this.getErrorStream()
        if (isShowLog) {
          console.log(`${funcName} => retErrorStream=${retErrorStream}`)
        }
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
        curLogFunc(funcName, funcParaDict)
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retHeaders = this.getHeaders()
        if (isShowLog) {
          console.log(`${funcName} => retHeaders=${retHeaders}`)
        }
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retString = this.responseSourceHeader(response)
        if (isShowLog) {
          console.log(`${funcName} => retString=${retString}`)
        }
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retHeaderField_i = this.getHeaderField(position)
        if (isShowLog) {
          console.log(`${funcName} => retHeaderField_i=${retHeaderField_i}`)
        }
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retHeaderField_str = this.getHeaderField(fieldName)
        if (isShowLog) {
          console.log(`${funcName} => retHeaderField_str=${retHeaderField_str}`)
        }
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retHeaderFieldKey = this.getHeaderFieldKey(position)
        if (isShowLog) {
          console.log(`${funcName} => retHeaderFieldKey=${retHeaderFieldKey}`)
        }
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retHeaderFields = this.getHeaderFields()
        if (isShowLog) {
          console.log(`${funcName} => retHeaderFields=${retHeaderFields}`)
        }
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retRequestProperties = this.getRequestProperties()
        if (isShowLog) {
          console.log(`${funcName} => retRequestProperties=${retRequestProperties}`)
        }
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retInputStream = this.getInputStream()
        if (isShowLog) {
          console.log(`${funcName} => retInputStream=${retInputStream}`)
        }
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retOutputStream = this.getOutputStream()
        if (isShowLog) {
          console.log(`${funcName} => retOutputStream=${retOutputStream}`)
        }
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retPermission = this.getPermission()
        if (isShowLog) {
          console.log(`${funcName} => retPermission=${retPermission}`)
        }
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retRequestProperty = this.getRequestProperty(field)
        if (isShowLog) {
          console.log(`${funcName} => retRequestProperty=${retRequestProperty}`)
        }
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.setConnectTimeout(timeoutMillis)
        return
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.setInstanceFollowRedirects(followRedirects)
        return
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var instanceFollowRedirects = this.getInstanceFollowRedirects()
        if (isShowLog) {
          console.log(`${funcName} => instanceFollowRedirects=${instanceFollowRedirects}`)
        }
        return instanceFollowRedirects
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var connectTimeout = this.getConnectTimeout()
        if (isShowLog) {
          console.log(`${funcName} => connectTimeout=${connectTimeout}`)
        }
        return connectTimeout
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.setReadTimeout(timeoutMillis)
        return
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retReadTimeout = this.getReadTimeout()
        if (isShowLog) {
          console.log(`${funcName} => retReadTimeout=${retReadTimeout}`)
        }
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.initHttpEngine()
        return
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retHttpEngine = this.newHttpEngine(method, streamAllocation, requestBody, priorResponse)
        if (isShowLog) {
          console.log(`${funcName} => retHttpEngine=${retHttpEngine}`)
        }
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retString = this.defaultUserAgent()
        if (isShowLog) {
          console.log(`${funcName} => retString=${retString}`)
        }
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var curHttpEngine = this.getResponse()
        if (isShowLog) {
          console.log(`${funcName} => curHttpEngine=${curHttpEngine}`)
        }

        // // var reqBodyOutStream = curHttpEngine.requestBodyOut.value
        // // console.log("reqBodyOutStream=" + reqBodyOutStream + ", clsName=" + FridaAndroidUtil.getJavaClassName(reqBodyOutStream))
        // // var reqBodyOutStream = this.requestBodyOut
        // var retryableSink = curHttpEngine.getRequestBody()
        // var clsName_RetryableSink = FridaAndroidUtil.getJavaClassName(retryableSink)
        // console.log("retryableSink=" + retryableSink + ", clsName=" + clsName_RetryableSink)
        // // retryableSink=[object Object], clsName=com.android.okhttp.internal.http.RetryableSink
        // // FridaAndroidUtil.printClassAllMethodsFields(clsName_RetryableSink)

        // var curRequest = curHttpEngine.getRequest()
        // console.log("curRequest=" + curRequest + ", clsName=" + FridaAndroidUtil.getJavaClassName(curRequest))

        // FridaAndroidUtil.printClass_RetryableSink(retryableSink)

        return curHttpEngine
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retBoolean = this.execute(readResponse)
        if (isShowLog) {
          console.log(`${funcName} => retBoolean=${retBoolean}`)
        }
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retBoolean = this.usingProxy()
        if (isShowLog) {
          console.log(`${funcName} => retBoolean=${retBoolean}`)
        }
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retResponseMessage = this.getResponseMessage()
        if (isShowLog) {
          console.log(`${funcName} => retResponseMessage=${retResponseMessage}`)
        }
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        // FridaAndroidUtil.printClass_HttpOrHttpsURLConnectionImpl(this)
        var retResponseCode = this.getResponseCode()
        if (isShowLog) {
          console.log(`${funcName} => retResponseCode=${retResponseCode}`)
        }

        // // get request body data
        // var newBaos = FridaAndroidUtil.ByteArrayOutputStream.$new()
        // console.log("newBaos=" + newBaos + ", clsName=" + FridaAndroidUtil.getJavaClassName(newBaos))

        // // var reqBodyOutStream = this.getOutputStream()
        // // console.log("reqBodyOutStream=" + reqBodyOutStream + ", clsName=" + FridaAndroidUtil.getJavaClassName(reqBodyOutStream))
        // // newBaos.writeTo(reqBodyOutStream)

        // var reqBodyRbs = this.getOutputStream() // RealBufferedSink
        // console.log("reqBodyRbs=" + reqBodyRbs + ", clsName=" + FridaAndroidUtil.getJavaClassName(reqBodyRbs))

        // // var reqBodyRbsOutStream = reqBodyRbs.outputStream() // OutputStream
        // // console.log("reqBodyRbsOutStream=" + reqBodyRbsOutStream + ", clsName=" + FridaAndroidUtil.getJavaClassName(reqBodyRbsOutStream))
        // // newBaos.writeTo(reqBodyRbsOutStream)

        // var rbsSize = reqBodyRbs.size
        // console.log("rbsSize=" + rbsSize)
        // var rbsBuffer = reqBodyRbs.buffer
        // console.log("rbsBuffer=" + rbsBuffer + ", clsName=" + FridaAndroidUtil.getJavaClassName(rbsBuffer))

        // var okBufferSize = rbsBuffer.size
        // console.log("okBufferSize=" + okBufferSize)
        // var okBufferHead = rbsBuffer.head
        // console.log("okBufferHead=" + okBufferHead + ", clsName=" + FridaAndroidUtil.getJavaClassName(okBufferHead))

        // var reqBodyByteArr = newBaos.toByteArray()
        // console.log("reqBodyByteArr=" + reqBodyByteArr + ", clsName=" + FridaAndroidUtil.getJavaClassName(reqBodyByteArr))

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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.setRequestProperty(field, newValue)
        return
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.setIfModifiedSince(newValue)
        return
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.addRequestProperty(field, value)
        return
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.setProtocols(protocolsString, append)
        return
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.setRequestMethod(method)
        return
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.setFixedLengthStreamingMode(contentLength)
        return
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.setFixedLengthStreamingMode(contentLength)
        return
      }
    }
  }

  static HttpURLConnection(callback_isShowLog=null) {
    // FridaAndroidUtil.printClassAllMethodsFields(FridaAndroidUtil.clsName_HttpURLConnection)

    var cls_HttpURLConnection = Java.use(FridaAndroidUtil.clsName_HttpURLConnection)
    console.log("cls_HttpURLConnection=" + cls_HttpURLConnection)

    //var  curLogFunc = FridaAndroidUtil.printFunctionCallAndStack
    var curLogFunc = FridaAndroidUtil.printFunctionCallStr

    // static boolean getFollowRedirects()
    // public static boolean java.net.HttpURLConnection.getFollowRedirects()
    var func_HttpURLConnection_getFollowRedirects = cls_HttpURLConnection.getFollowRedirects
    console.log("func_HttpURLConnection_getFollowRedirects=" + func_HttpURLConnection_getFollowRedirects)
    func_HttpURLConnection_getFollowRedirects.implementation = function () {
      var funcName = "HttpURLConnection.getFollowRedirects"
      var funcParaDict = {}
      var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, FridaAndroidUtil.printFunctionCallAndStack, callback_isShowLog)
      var retFollowRedirects = this.getFollowRedirects()
      if (isShowLog) {
        console.log(`${funcName} => retFollowRedirects: type=${typeof retFollowRedirects},val=${retFollowRedirects}`)
      }
      return retFollowRedirects
    }

    // abstract void disconnect()
    // public abstract void java.net.HttpURLConnection.disconnect()
    var func_HttpURLConnection_disconnect = cls_HttpURLConnection.disconnect
    console.log("func_HttpURLConnection_disconnect=" + func_HttpURLConnection_disconnect)
    if (func_HttpURLConnection_disconnect) {
      func_HttpURLConnection_disconnect.implementation = function () {
        var funcName = "HttpURLConnection.disconnect"
        var funcParaDict = {}
        // curLogFunc(funcName, funcParaDict)
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.disconnect()
        return
      }
    }

    // InputStream getErrorStream()
    // public java.io.InputStream java.net.HttpURLConnection.getErrorStream()
    var func_HttpURLConnection_getErrorStream = cls_HttpURLConnection.getErrorStream
    console.log("func_HttpURLConnection_getErrorStream=" + func_HttpURLConnection_getErrorStream)
    if (func_HttpURLConnection_getErrorStream) {
      func_HttpURLConnection_getErrorStream.implementation = function () {
        var funcName = "HttpURLConnection.getErrorStream"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retErrorStream = this.getErrorStream()
        if (isShowLog) {
          console.log(`${funcName} => retErrorStream=${retErrorStream}`)
        }
        return retErrorStream
      }
    }

    // String getHeaderField(int n)
    // public java.lang.String java.net.HttpURLConnection.getHeaderField(int)
    var func_HttpURLConnection_getHeaderField = cls_HttpURLConnection.getHeaderField
    console.log("func_HttpURLConnection_getHeaderField=" + func_HttpURLConnection_getHeaderField)
    if (func_HttpURLConnection_getHeaderField) {
      func_HttpURLConnection_getHeaderField.implementation = function (n) {
        var funcName = "HttpURLConnection.getHeaderField"
        var funcParaDict = {
          "n": n,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retHeaderField = this.getHeaderField(n)
        if (isShowLog) {
          console.log(`${funcName} => retHeaderField=${retHeaderField}`)
        }
        return retHeaderField
      }
    }

    // long getHeaderFieldDate(String name, long Default)
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
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retHeaderFieldDate = this.getHeaderFieldDate(name, Default)
        if (isShowLog) {
          console.log(`${funcName} => retHeaderFieldDate=${retHeaderFieldDate}`)
        }
        return retHeaderFieldDate
      }
    }

    // String getHeaderFieldKey(int n)
    // public java.lang.String java.net.HttpURLConnection.getHeaderFieldKey(int)
    var func_HttpURLConnection_getHeaderFieldKey = cls_HttpURLConnection.getHeaderFieldKey
    console.log("func_HttpURLConnection_getHeaderFieldKey=" + func_HttpURLConnection_getHeaderFieldKey)
    if (func_HttpURLConnection_getHeaderFieldKey) {
      func_HttpURLConnection_getHeaderFieldKey.implementation = function (n) {
        var funcName = "HttpURLConnection.getHeaderFieldKey"
        var funcParaDict = {
          "n": n,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retHeaderFieldKey = this.getHeaderFieldKey(n)
        if (isShowLog) {
          console.log(`${funcName} => retHeaderFieldKey=${retHeaderFieldKey}`)
        }
        return retHeaderFieldKey
      }
    }

    // boolean getInstanceFollowRedirects()
    // public boolean java.net.HttpURLConnection.getInstanceFollowRedirects()
    var func_HttpURLConnection_getInstanceFollowRedirects = cls_HttpURLConnection.getInstanceFollowRedirects
    console.log("func_HttpURLConnection_getInstanceFollowRedirects=" + func_HttpURLConnection_getInstanceFollowRedirects)
    if (func_HttpURLConnection_getInstanceFollowRedirects) {
      func_HttpURLConnection_getInstanceFollowRedirects.implementation = function () {
        var funcName = "HttpURLConnection.getInstanceFollowRedirects"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retInstanceFollowRedirects = this.getInstanceFollowRedirects()
        if (isShowLog) {
          console.log(`${funcName} => retInstanceFollowRedirects=${retInstanceFollowRedirects}`)
        }
        return retInstanceFollowRedirects
      }
    }

    // Permission getPermission()
    // public java.security.Permission java.net.HttpURLConnection.getPermission() throws java.io.IOException
    var func_HttpURLConnection_getPermission = cls_HttpURLConnection.getPermission
    console.log("func_HttpURLConnection_getPermission=" + func_HttpURLConnection_getPermission)
    if (func_HttpURLConnection_getPermission) {
      func_HttpURLConnection_getPermission.implementation = function () {
        var funcName = "HttpURLConnection.getPermission"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retPermission = this.getPermission()
        if (isShowLog) {
          console.log(`${funcName} => retPermission=${retPermission}`)
        }
        return retPermission
      }
    }

    // String getRequestMethod()
    // public java.lang.String java.net.HttpURLConnection.getRequestMethod()
    var func_HttpURLConnection_getRequestMethod = cls_HttpURLConnection.getRequestMethod
    console.log("func_HttpURLConnection_getRequestMethod=" + func_HttpURLConnection_getRequestMethod)
    if (func_HttpURLConnection_getRequestMethod) {
      func_HttpURLConnection_getRequestMethod.implementation = function () {
        var funcName = "HttpURLConnection.getRequestMethod"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retRequestMethod = this.getRequestMethod()
        if (isShowLog) {
          console.log(`${funcName} => retRequestMethod=${retRequestMethod}`)
        }
        return retRequestMethod
      }
    }

    // int getResponseCode()
    // public int java.net.HttpURLConnection.getResponseCode() throws java.io.IOException
    var func_HttpURLConnection_getResponseCode = cls_HttpURLConnection.getResponseCode
    console.log("func_HttpURLConnection_getResponseCode=" + func_HttpURLConnection_getResponseCode)
    if (func_HttpURLConnection_getResponseCode) {
      func_HttpURLConnection_getResponseCode.implementation = function () {
        var funcName = "HttpURLConnection.getResponseCode"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, FridaAndroidUtil.printFunctionCallAndStack, callback_isShowLog)
        var respCode = this.getResponseCode()
        if(isShowLog) {
          console.log(`${funcName} => respCode=${respCode}`)
        }
        return respCode
      }
    }

    // String getResponseMessage()
    // public java.lang.String java.net.HttpURLConnection.getResponseMessage() throws java.io.IOException
    var func_HttpURLConnection_getResponseMessage = cls_HttpURLConnection.getResponseMessage
    console.log("func_HttpURLConnection_getResponseMessage=" + func_HttpURLConnection_getResponseMessage)
    if (func_HttpURLConnection_getResponseMessage) {
      func_HttpURLConnection_getResponseMessage.implementation = function () {
        var funcName = "HttpURLConnection.getResponseMessage"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retResponseMessage = this.getResponseMessage()
        if(isShowLog) {
          console.log(`${funcName} => retResponseMessage=${retResponseMessage}`)
        }
        return retResponseMessage
      }
    }

    // void setChunkedStreamingMode(int chunklen)
    // public void java.net.HttpURLConnection.setChunkedStreamingMode(int)
    var func_HttpURLConnection_setChunkedStreamingMode = cls_HttpURLConnection.setChunkedStreamingMode
    console.log("func_HttpURLConnection_setChunkedStreamingMode=" + func_HttpURLConnection_setChunkedStreamingMode)
    if (func_HttpURLConnection_setChunkedStreamingMode) {
      func_HttpURLConnection_setChunkedStreamingMode.implementation = function (chunklen) {
        var funcName = "HttpURLConnection.setChunkedStreamingMode"
        var funcParaDict = {
          "chunklen": chunklen,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.setChunkedStreamingMode(chunklen)
        return
      }
    }

    // void setFixedLengthStreamingMode(int contentLength)
    // public void java.net.HttpURLConnection.setFixedLengthStreamingMode(int)
    var func_HttpURLConnection_setFixedLengthStreamingMode_1pi = cls_HttpURLConnection.setFixedLengthStreamingMode.overload("int")
    console.log("func_HttpURLConnection_setFixedLengthStreamingMode_1pi=" + func_HttpURLConnection_setFixedLengthStreamingMode_1pi)
    if (func_HttpURLConnection_setFixedLengthStreamingMode_1pi) {
      func_HttpURLConnection_setFixedLengthStreamingMode_1pi.implementation = function (contentLength) {
        var funcName = "HttpURLConnection.setFixedLengthStreamingMode(int)"
        var funcParaDict = {
          "contentLength": contentLength,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, FridaAndroidUtil.printFunctionCallAndStack, callback_isShowLog)
        this.setFixedLengthStreamingMode(contentLength)
        return
      }
    }

    // void setFixedLengthStreamingMode(long contentLength)
    // public void java.net.HttpURLConnection.setFixedLengthStreamingMode(long)
    var func_HttpURLConnection_setFixedLengthStreamingMode_1pl = cls_HttpURLConnection.setFixedLengthStreamingMode.overload("long")
    console.log("func_HttpURLConnection_setFixedLengthStreamingMode_1pl=" + func_HttpURLConnection_setFixedLengthStreamingMode_1pl)
    if (func_HttpURLConnection_setFixedLengthStreamingMode_1pl) {
      func_HttpURLConnection_setFixedLengthStreamingMode_1pl.implementation = function (contentLength) {
        var funcName = "HttpURLConnection.setFixedLengthStreamingMode(long)"
        var funcParaDict = {
          "contentLength": contentLength,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, FridaAndroidUtil.printFunctionCallAndStack, callback_isShowLog)
        this.setFixedLengthStreamingMode(contentLength)
        return
      }
    }

    // static void setFollowRedirects(boolean set)
    // public static void java.net.HttpURLConnection.setFollowRedirects(boolean)
    var func_HttpURLConnection_setFollowRedirects = cls_HttpURLConnection.setFollowRedirects
    console.log("func_HttpURLConnection_setFollowRedirects=" + func_HttpURLConnection_setFollowRedirects)
    if (func_HttpURLConnection_setFollowRedirects) {
      func_HttpURLConnection_setFollowRedirects.implementation = function (set) {
        var funcName = "HttpURLConnection.setFollowRedirects"
        var funcParaDict = {
          "set": set,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.setFollowRedirects(set)
        return
      }
    }

    // void setInstanceFollowRedirects(boolean followRedirects)
    // public void java.net.HttpURLConnection.setInstanceFollowRedirects(boolean)
    var func_HttpURLConnection_setInstanceFollowRedirects = cls_HttpURLConnection.setInstanceFollowRedirects
    console.log("func_HttpURLConnection_setInstanceFollowRedirects=" + func_HttpURLConnection_setInstanceFollowRedirects)
    if (func_HttpURLConnection_setInstanceFollowRedirects) {
      func_HttpURLConnection_setInstanceFollowRedirects.implementation = function (followRedirects) {
        var funcName = "HttpURLConnection.setInstanceFollowRedirects"
        var funcParaDict = {
          "followRedirects": followRedirects,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        this.setInstanceFollowRedirects(followRedirects)
        return
      }
    }

    // void setRequestMethod(String method)
    // public void java.net.HttpURLConnection.setRequestMethod(java.lang.String) throws java.net.ProtocolException
    var func_HttpURLConnection_setRequestMethod = cls_HttpURLConnection.setRequestMethod
    console.log("func_HttpURLConnection_setRequestMethod=" + func_HttpURLConnection_setRequestMethod)
    if (func_HttpURLConnection_setRequestMethod) {
      func_HttpURLConnection_setRequestMethod.implementation = function (method) {
        var funcName = "HttpURLConnection.setRequestMethod"
        var funcParaDict = {
          "method": method,
        }
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, FridaAndroidUtil.printFunctionCallAndStack, callback_isShowLog)
        this.setRequestMethod(method)
        return
      }
    }

    // abstract boolean usingProxy()
    // public abstract boolean java.net.HttpURLConnection.usingProxy()
    var func_HttpURLConnection_usingProxy = cls_HttpURLConnection.usingProxy
    console.log("func_HttpURLConnection_usingProxy=" + func_HttpURLConnection_usingProxy)
    if (func_HttpURLConnection_usingProxy) {
      func_HttpURLConnection_usingProxy.implementation = function () {
        var funcName = "HttpURLConnection.usingProxy"
        var funcParaDict = {}
        var isShowLog = FridaHookAndroidJava.urlCommon_filterLogByUrl(this.url.value, funcName, funcParaDict, curLogFunc, callback_isShowLog)
        var retBoolean = this.usingProxy()
        if(isShowLog) {
          console.log(`${funcName} => retBoolean=${retBoolean}`)
        }
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

        this.$init()
        var newIOException_void = this
        console.log("IOException => newIOException_void=" + newIOException_void)
        return
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

        this.$init(message)
        var newIOException_1str = this
        console.log("IOException(msg) => newIOException_1str=" + newIOException_1str)
        return
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

        this.$init(message, cause)
        var newIOException_2para = this
        console.log("IOException(msg,cause) => newIOException_2para=" + newIOException_2para)
        return
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

        this.$init(cause)
        var newIOException_1t = this
        console.log("IOException(cause) => newIOException_1t=" + newIOException_1t)
        return
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
        // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        FridaAndroidUtil.printFunctionCallStr(funcName, funcParaDict)

        this.$init()
        var newBundle_0p = this
        console.log("Bundle_0p => newBundle_0p=" + newBundle_0p)
        return
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

        this.$init(b)
        var newBundle_1pb = this
        console.log("Bundle_1pb => newBundle_1pb=" + newBundle_1pb)
        return
      }
    }

    // Bundle(PersistableBundle b)
    // Bundle(android.os.PersistableBundle)
    var func_Bundle_Bundle_1ppb = cls_Bundle.$init.overload("android.os.PersistableBundle")
    console.log("func_Bundle_Bundle_1ppb=" + func_Bundle_Bundle_1ppb)
    if (func_Bundle_Bundle_1ppb) {
      func_Bundle_Bundle_1ppb.implementation = function (b) {
        var funcName = "Bundle_1pb"
        var funcParaDict = {
          "b": b,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init(b)
        var newBundle_1pb = this
        console.log("Bundle_1pb => newBundle_1pb=" + newBundle_1pb)
        return
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

        this.$init(capacity)
        var newBundle_1pc = this
        console.log("Bundle_1pc => newBundle_1pc=" + newBundle_1pc)
        return
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

        this.$init(loader)
        var newBundle_1pl = this
        console.log("Bundle_1pl => newBundle_1pl=" + newBundle_1pl)
        return
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
        // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        FridaAndroidUtil.printFunctionCallStr(funcName, funcParaDict)

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
        // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        FridaAndroidUtil.printFunctionCallStr(funcName, funcParaDict)

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
        // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        FridaAndroidUtil.printFunctionCallStr(funcName, funcParaDict)

        return this.remove(key)
      }
    }

  }

  static BaseBundle() {
    var clsName_BaseBundle = "android.os.BaseBundle"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_BaseBundle)

    var cls_BaseBundle = Java.use(clsName_BaseBundle)
    console.log("cls_BaseBundle=" + cls_BaseBundle)

    // const curLogFunc = FridaAndroidUtil.printFunctionCallAndStack
    const curLogFunc = FridaAndroidUtil.printFunctionCallStr

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
        curLogFunc(funcName, funcParaDict)

        var retBoolean = this.containsKey(key)
        console.log(funcName + " => retBoolean=" + retBoolean)
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
        curLogFunc(funcName, funcParaDict)

        var retBoolean_2pkd = this.getBoolean(key, defaultValue)
        console.log(funcName + " => retBoolean_2pkd=" + retBoolean_2pkd)
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
        curLogFunc(funcName, funcParaDict)

        var retBoolean_1pk = this.getBoolean(key)
        console.log(funcName + " => retBoolean_1pk=" + retBoolean_1pk)
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
        curLogFunc(funcName, funcParaDict)

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
        curLogFunc(funcName, funcParaDict)

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
        curLogFunc(funcName, funcParaDict)

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
        curLogFunc(funcName, funcParaDict)

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
        curLogFunc(funcName, funcParaDict)

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
        curLogFunc(funcName, funcParaDict)

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
        curLogFunc(funcName, funcParaDict)

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
        curLogFunc(funcName, funcParaDict)

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
        curLogFunc(funcName, funcParaDict)

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
        curLogFunc(funcName, funcParaDict)

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
        curLogFunc(funcName, funcParaDict)

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
        curLogFunc(funcName, funcParaDict)

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
        curLogFunc(funcName, funcParaDict)

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
        curLogFunc(funcName, funcParaDict)

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
        curLogFunc(funcName, funcParaDict)

        var ret_T_T_2pkc = this.get(key, clazz)
        console.log(funcName + " => ret_T_T_2pkc=" + ret_T_T_2pkc)
        return ret_T_T_2pkc
      }
    }

    // int getInt(String key)
    // public int android.os.BaseBundle.getInt(java.lang.String)
    var func_BaseBundle_getInt_1pk = cls_BaseBundle.getInt.overload("java.lang.String")
    console.log("func_BaseBundle_getInt_1pk=" + func_BaseBundle_getInt_1pk)
    if (func_BaseBundle_getInt_1pk) {
      func_BaseBundle_getInt_1pk.implementation = function (key) {
        var funcName = "BaseBundle.getInt(key)"
        var funcParaDict = {
          "key": key,
        }
        curLogFunc(funcName, funcParaDict)
        // FridaAndroidUtil.printFunctionCallStr(funcName, funcParaDict)

        var retInt_1pk = this.getInt(key)
        console.log(funcName + " => retInt_1pk=" + retInt_1pk)
        return retInt_1pk
      }
    }

    // int getInt(String key, int defaultValue)
    // public int android.os.BaseBundle.getInt(java.lang.String,int)
    var func_BaseBundle_getInt_2pkd = cls_BaseBundle.getInt.overload("java.lang.String", "int")
    console.log("func_BaseBundle_getInt_2pkd=" + func_BaseBundle_getInt_2pkd)
    if (func_BaseBundle_getInt_2pkd) {
      func_BaseBundle_getInt_2pkd.implementation = function (key, defaultValue) {
        var funcName = "BaseBundle.getInt(key,defaultValue)"
        var funcParaDict = {
          "key": key,
          "defaultValue": defaultValue,
        }
        curLogFunc(funcName, funcParaDict)

        var retInt_2pkd = this.getInt(key, defaultValue)
        console.log(funcName + " => retInt_2pkd=" + retInt_2pkd)
        return retInt_2pkd
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
        curLogFunc(funcName, funcParaDict)

        var retString_1pk = this.getString(key)
        console.log(funcName + " => retString_1pk=" + retString_1pk)
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
        curLogFunc(funcName, funcParaDict)

        var retString_2pkd = this.getString(key, defaultValue)
        console.log(funcName + " => retString_2pkd=" + retString_2pkd)
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
        curLogFunc(funcName, funcParaDict)

        var retStringArray = this.getStringArray(key)
        console.log(funcName + " => retStringArray=" + retStringArray)
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

        this.$init(targetHandler)
        var newMessenger_1ph = this
        console.log("Messenger(Handler) => newMessenger_1ph=" + newMessenger_1ph)
        return
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

        this.$init(targetIBinder)
        var newMessenger_1pi = this
        console.log("Messenger(IBinder) => newMessenger_1pi=" + newMessenger_1pi)
        return
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
        FridaAndroidUtil.printClass_Message(message, funcName)
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)


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

        this.$init()
        var newMessage = this
        console.log(funcName + " => newMessage=" + newMessage)
        return
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
        // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        FridaAndroidUtil.printFunctionCallStr(funcName, funcParaDict)

        var retMessage_0p = this.obtain()
        console.log(funcName + " => retMessage_0p=" + retMessage_0p)
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
        // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        FridaAndroidUtil.printFunctionCallStr(funcName, funcParaDict)

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
        console.log(funcName + " => retData=" + retData)
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

  static Intent(callback_isShowLog=null) {
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

        this.$init()
        var newIntent_0p = this
        console.log(funcName + " => newIntent_0p=" + newIntent_0p)
        return
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

        this.$init(action)
        var newIntent_1pa = this
        console.log(funcName + " => newIntent_1pa=" + newIntent_1pa)
        return
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

        this.$init(action, uri)
        var newIntent_2pau = this
        console.log(funcName + " => newIntent_2pau=" + newIntent_2pau)
        return
      }
    }

    // Intent setPackage(String packageName)
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
        console.log(funcName + " => retIntent=" + retIntent)
        return retIntent
      }
    }

    // Intent setAction(String action)
    // public android.content.Intent android.content.Intent.setAction(java.lang.String)
    var func_Intent_setAction = cls_Intent.setAction
    console.log("func_Intent_setAction=" + func_Intent_setAction)
    if (func_Intent_setAction) {
      func_Intent_setAction.implementation = function (action) {
        var isShowLog = true
        if (null != callback_isShowLog) {
          isShowLog = callback_isShowLog(action)
        }

        if (isShowLog){
          var funcName = "Intent.setAction"
          var funcParaDict = {
            "action": action,
          }
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        } else {
          FridaAndroidUtil.printFunctionCallStr(funcName, funcParaDict)
        }

        var retIntent = this.setAction(action)
        console.log("Intent.setAction => retIntent=" + retIntent)
        return retIntent
      }
    }

    // Intent putExtras(Intent srcIntent)
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

    // Intent putExtras(Bundle extrasBundle)
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

    // Intent putExtra(String name, Parcelable value)
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

    // Intent putExtra(String name, String value)
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

    // Bundle getExtras()
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

    // String getStringExtra(String name)
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

    // String getAction()
    // public java.lang.String android.content.Intent.getAction()
    var func_Intent_getAction = cls_Intent.getAction
    console.log("func_Intent_getAction=" + func_Intent_getAction)
    if (func_Intent_getAction) {
      func_Intent_getAction.implementation = function () {
        var isShowLog = true
        if (null != callback_isShowLog) {
          isShowLog = callback_isShowLog(action)
        }

        if (isShowLog){
          var funcName = "Intent.getAction"
          var funcParaDict = {}
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
          } else {
          FridaAndroidUtil.printFunctionCallStr(funcName, funcParaDict)
        }

        var retAction = this.getAction()
        console.log("Intent.getAction => retAction=" + retAction)
        return retAction
      }
    }

  }

  static Handler(callback_isShowLog=null) {
    var clsName_Handler = "android.os.Handler"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Handler)

    var cls_Handler = Java.use(clsName_Handler)
    console.log("cls_Handler=" + cls_Handler)

    
    // void dispatchMessage(Message msg)
    // 
    var func_Handler_dispatchMessage = cls_Handler.dispatchMessage
    console.log("func_Handler_dispatchMessage=" + func_Handler_dispatchMessage)
    if (func_Handler_dispatchMessage) {
      func_Handler_dispatchMessage.implementation = function (msg) {
        var funcName = "Handler.dispatchMessage"
        var funcParaDict = {
          "msg": msg,
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        return this.dispatchMessage(msg)
      }
    }

    // String getMessageName(Message message)
    // 
    var func_Handler_getMessageName = cls_Handler.getMessageName
    console.log("func_Handler_getMessageName=" + func_Handler_getMessageName)
    if (func_Handler_getMessageName) {
      func_Handler_getMessageName.implementation = function (message) {
        var funcName = "Handler.getMessageName"
        var funcParaDict = {
          "message": message,
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        var retMessageName = this.getMessageName(message)
        if (isShowLog) {
          console.log("Handler.getMessageName => retMessageName=" + retMessageName)
        }
        return retMessageName
      }
    }

    // void handleMessage(Message msg)
    // 
    var func_Handler_handleMessage = cls_Handler.handleMessage
    console.log("func_Handler_handleMessage=" + func_Handler_handleMessage)
    if (func_Handler_handleMessage) {
      func_Handler_handleMessage.implementation = function (msg) {
        var funcName = "Handler.handleMessage"
        var funcParaDict = {
          "msg": msg,
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        return this.handleMessage(msg)
      }
    }

    // final boolean sendMessage(Message msg)
    // 
    var func_Handler_sendMessage = cls_Handler.sendMessage
    console.log("func_Handler_sendMessage=" + func_Handler_sendMessage)
    if (func_Handler_sendMessage) {
      func_Handler_sendMessage.implementation = function (msg) {
        var funcName = "Handler.sendMessage"
        var funcParaDict = {
          "msg": msg,
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        var retBoolean = this.sendMessage(msg)
        if (isShowLog) {
          console.log("Handler.sendMessage => retBoolean=" + retBoolean)
        }
        return retBoolean
      }
    }

    // final boolean sendMessageAtFrontOfQueue(Message msg)
    // 
    var func_Handler_sendMessageAtFrontOfQueue = cls_Handler.sendMessageAtFrontOfQueue
    console.log("func_Handler_sendMessageAtFrontOfQueue=" + func_Handler_sendMessageAtFrontOfQueue)
    if (func_Handler_sendMessageAtFrontOfQueue) {
      func_Handler_sendMessageAtFrontOfQueue.implementation = function (msg) {
        var funcName = "Handler.sendMessageAtFrontOfQueue"
        var funcParaDict = {
          "msg": msg,
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        var retBoolean = this.sendMessageAtFrontOfQueue(msg)
        if (isShowLog) {
          console.log("Handler.sendMessageAtFrontOfQueue => retBoolean=" + retBoolean)
        }
        return retBoolean
      }
    }

    // boolean sendMessageAtTime(Message msg, long uptimeMillis)
    // 
    var func_Handler_sendMessageAtTime = cls_Handler.sendMessageAtTime
    console.log("func_Handler_sendMessageAtTime=" + func_Handler_sendMessageAtTime)
    if (func_Handler_sendMessageAtTime) {
      func_Handler_sendMessageAtTime.implementation = function (msg, uptimeMillis) {
        var funcName = "Handler.sendMessageAtTime"
        var funcParaDict = {
          "msg": msg,
          "uptimeMillis": uptimeMillis,
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        var retBoolean = this.sendMessageAtTime(msg, uptimeMillis)
        if (isShowLog) {
          console.log("Handler.sendMessageAtTime => retBoolean=" + retBoolean)
        }
        return retBoolean
      }
    }

    // final boolean sendMessageDelayed(Message msg, long delayMillis)
    // 
    var func_Handler_sendMessageDelayed = cls_Handler.sendMessageDelayed
    console.log("func_Handler_sendMessageDelayed=" + func_Handler_sendMessageDelayed)
    if (func_Handler_sendMessageDelayed) {
      func_Handler_sendMessageDelayed.implementation = function (msg, delayMillis) {
        var funcName = "Handler.sendMessageDelayed"
        var funcParaDict = {
          "msg": msg,
          "delayMillis": delayMillis,
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        var retBoolean = this.sendMessageDelayed(msg, delayMillis)
        if (isShowLog) {
          console.log("Handler.sendMessageDelayed => retBoolean=" + retBoolean)
        }
        return retBoolean
      }
    }

    // final Message obtainMessage(int what, Object obj)
    // public final android.os.Message android.os.Handler.obtainMessage(int,java.lang.Object)
    var func_Handler_obtainMessage_2pwo = cls_Handler.obtainMessage.overload("int", "java.lang.Object")
    console.log("func_Handler_obtainMessage_2pwo=" + func_Handler_obtainMessage_2pwo)
    if (func_Handler_obtainMessage_2pwo) {
      func_Handler_obtainMessage_2pwo.implementation = function (what, obj) {
        var funcName = "Handler.obtainMessage_2pwo"
        var funcParaDict = {
          "what": what,
          "obj": obj,
        }
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        var retMessage_2pwo = this.obtainMessage(what, obj)
        var isShowLog = FridaAndroidUtil.showLogIfNecessary(callback_isShowLog, `${funcCallAndStackStr}\n${funcName} => retMessage_2pwo=${retMessage_2pwo}`)
        return retMessage_2pwo
      }
    }

    // final Message obtainMessage()
    // public final android.os.Message android.os.Handler.obtainMessage()
    var func_Handler_obtainMessage_0p = cls_Handler.obtainMessage.overload()
    console.log("func_Handler_obtainMessage_0p=" + func_Handler_obtainMessage_0p)
    if (func_Handler_obtainMessage_0p) {
      func_Handler_obtainMessage_0p.implementation = function () {
        var funcName = "Handler.obtainMessage_0p"
        var funcParaDict = {}
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        var retMessage_0p = this.obtainMessage()
        var isShowLog = FridaAndroidUtil.showLogIfNecessary(callback_isShowLog, `${funcCallAndStackStr}\n${funcName} => retMessage_0p=${retMessage_0p}`)
        return retMessage_0p
      }
    }

    // final Message obtainMessage(int what, int arg1, int arg2)
    // public final android.os.Message android.os.Handler.obtainMessage(int,int,int)
    var func_Handler_obtainMessage_3pwaa = cls_Handler.obtainMessage.overload("int", "int", "int")
    console.log("func_Handler_obtainMessage_3pwaa=" + func_Handler_obtainMessage_3pwaa)
    if (func_Handler_obtainMessage_3pwaa) {
      func_Handler_obtainMessage_3pwaa.implementation = function (what, arg1, arg2) {
        var funcName = "Handler.obtainMessage_3pwaa"
        var funcParaDict = {
          "what": what,
          "arg1": arg1,
          "arg2": arg2,
        }
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        var retMessage_3pwaa = this.obtainMessage(what, arg1, arg2)
        var isShowLog = FridaAndroidUtil.showLogIfNecessary(callback_isShowLog, `${funcCallAndStackStr}\n${funcName} => retMessage_3pwaa=${retMessage_3pwaa}`)
        return retMessage_3pwaa
      }
    }

    // final Message obtainMessage(int what, int arg1, int arg2, Object obj)
    // public final android.os.Message android.os.Handler.obtainMessage(int,int,int,java.lang.Object)
    var func_Handler_obtainMessage_4pwaao = cls_Handler.obtainMessage.overload("int", "int", "int", "java.lang.Object")
    console.log("func_Handler_obtainMessage_4pwaao=" + func_Handler_obtainMessage_4pwaao)
    if (func_Handler_obtainMessage_4pwaao) {
      func_Handler_obtainMessage_4pwaao.implementation = function (what, arg1, arg2, obj) {
        var funcName = "Handler.obtainMessage_4pwaao"
        var funcParaDict = {
          "what": what,
          "arg1": arg1,
          "arg2": arg2,
          "obj": obj,
        }
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        var retMessage_4pwaao = this.obtainMessage(what, arg1, arg2, obj)
        var isShowLog = FridaAndroidUtil.showLogIfNecessary(callback_isShowLog, `${funcCallAndStackStr}\n${funcName} => retMessage_4pwaao=${retMessage_4pwaao}`)
        return retMessage_4pwaao
      }
    }

    // final Message obtainMessage(int what)
    // public final android.os.Message android.os.Handler.obtainMessage(int)
    var func_Handler_obtainMessage_1pw = cls_Handler.obtainMessage.overload("int")
    console.log("func_Handler_obtainMessage_1pw=" + func_Handler_obtainMessage_1pw)
    if (func_Handler_obtainMessage_1pw) {
      func_Handler_obtainMessage_1pw.implementation = function (what) {
        var funcName = "Handler.obtainMessage_1pw"
        var funcParaDict = {
          "what": what,
        }
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        var retMessage_1pw = this.obtainMessage(what)
        var isShowLog = FridaAndroidUtil.showLogIfNecessary(callback_isShowLog, `${funcCallAndStackStr}\n${funcName} => retMessage_1pw=${retMessage_1pw}`)
        return retMessage_1pw
      }
    }

  }

  static Uri_Builder(callback_isShowLog=null) {
    var clsName_Uri_Builder = "android.net.Uri$Builder"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Uri_Builder)

    var cls_Uri_Builder = Java.use(clsName_Uri_Builder)
    console.log("cls_Uri_Builder=" + cls_Uri_Builder)

    // public Uri build()
    // public android.net.Uri android.net.Uri$Builder.build()
    var func_Uri_Builder_build = cls_Uri_Builder.build
    console.log("func_Uri_Builder_build=" + func_Uri_Builder_build)
    if (func_Uri_Builder_build) {
      func_Uri_Builder_build.implementation = function () {
        var funcName = "Uri$Builder.build"
        var funcParaDict = {}
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)
        var retUri = this.build()
        if (isShowLog) {
          console.log(funcName + " => retUri=" + retUri)
        }
        return retUri
      }
    }

    // public Uri.Builder appendQueryParameter(String key, String value)
    // public android.net.Uri$Builder android.net.Uri$Builder.appendQueryParameter(java.lang.String,java.lang.String)
    var func_Uri_Builder_appendQueryParameter = cls_Uri_Builder.appendQueryParameter
    console.log("func_Uri_Builder_appendQueryParameter=" + func_Uri_Builder_appendQueryParameter)
    if (func_Uri_Builder_appendQueryParameter) {
      func_Uri_Builder_appendQueryParameter.implementation = function (key, value) {
        var funcName = "Uri$Builder.appendQueryParameter"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)
        var retUri_Builder = this.appendQueryParameter(key, value)
        if (isShowLog) {
          console.log(funcName + " => retUri_Builder=" + retUri_Builder)
        }
        return retUri_Builder
      }
    }

  }

  static Uri(callback_isShowLog=null) {
    var clsName_Uri = "android.net.Uri"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Uri)

    var cls_Uri = Java.use(clsName_Uri)
    console.log("cls_Uri=" + cls_Uri)

    // public abstract String getPath()
    // public abstract java.lang.String android.net.Uri.getPath()
    var func_Uri_getPath = cls_Uri.getPath
    console.log("func_Uri_getPath=" + func_Uri_getPath)
    if (func_Uri_getPath) {
      func_Uri_getPath.implementation = function () {
        var funcName = "Uri.getPath"
        var funcParaDict = {}
        // var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        var retPath = this.getPath()
        var isShowLog = FridaAndroidUtil.showLogIfNecessary(callback_isShowLog, `${funcCallAndStackStr}\n${funcName} => retPath=${retPath}`)
        return retPath
      }
    }

    // public abstract String getAuthority()
    // public abstract java.lang.String android.net.Uri.getAuthority()
    var func_Uri_getAuthority = cls_Uri.getAuthority
    console.log("func_Uri_getAuthority=" + func_Uri_getAuthority)
    if (func_Uri_getAuthority) {
      func_Uri_getAuthority.implementation = function () {
        var funcName = "Uri.getAuthority"
        var funcParaDict = {}
        // var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)
        var retAuthority = this.getAuthority()
        // if (isShowLog) {
          console.log(funcName + " => retAuthority=" + retAuthority)
        // }
        return retAuthority
      }
    }

    // public abstract String getEncodedQuery()
    // public abstract java.lang.String android.net.Uri.getEncodedQuery()
    var func_Uri_getEncodedQuery = cls_Uri.getEncodedQuery
    console.log("func_Uri_getEncodedQuery=" + func_Uri_getEncodedQuery)
    if (func_Uri_getEncodedQuery) {
      func_Uri_getEncodedQuery.implementation = function () {
        var funcName = "Uri.getEncodedQuery"
        var funcParaDict = {}
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)
        var retEncodedQuery = this.getEncodedQuery()
        if (isShowLog) {
          console.log(funcName + " => retEncodedQuery=" + retEncodedQuery)
        }
        return retEncodedQuery
      }
    }

    // public static Uri parse(String uriString)
    // public static android.net.Uri android.net.Uri.parse(java.lang.String)
    var func_Uri_parse = cls_Uri.parse
    console.log("func_Uri_parse=" + func_Uri_parse)
    if (func_Uri_parse) {
      func_Uri_parse.implementation = function (uriString) {
        var funcName = "Uri.parse"
        var funcParaDict = {
          "uriString": uriString,
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)
        var retUri = this.parse(uriString)
        // if (isShowLog) {
          console.log(funcName + " => retUri=" + retUri)
        // }
        return retUri
      }
    }

  }

  static CronetUrlRequest_origCode(cls_CronetUrlRequest) {
    // https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/cronet/android/java/src/org/chromium/net/impl/CronetUrlRequest.java

    /* CronetUrlRequest(
            CronetUrlRequestContext requestContext,
            String url,
            int priority,
            UrlRequest.Callback callback,
            Executor executor,
            Collection<Object> requestAnnotations,
            boolean disableCache,
            boolean disableConnectionMigration,
            boolean allowDirectExecutor,
            boolean trafficStatsTagSet,
            int trafficStatsTag,
            boolean trafficStatsUidSet,
            int trafficStatsUid,
            RequestFinishedInfo.Listener requestFinishedListener,
            int idempotency,
            long networkHandle,
            String method,
            ArrayList<Map.Entry<String, String>> requestHeaders,
            UploadDataProvider uploadDataProvider,
            Executor uploadDataProviderExecutor,
            byte[] dictionarySha256Hash,
            ByteBuffer dictionary,
            @NonNull String dictionaryId) {
    */
    // 
    var func_CronetUrlRequest_ctor = cls_CronetUrlRequest.$init
    console.log("func_CronetUrlRequest_ctor=" + func_CronetUrlRequest_ctor)
    if (func_CronetUrlRequest_ctor) {
      func_CronetUrlRequest_ctor.implementation = function (requestContext, url, priority, callback, executor, requestAnnotations, disableCache, disableConnectionMigration, allowDirectExecutor, trafficStatsTagSet, trafficStatsTag, trafficStatsUidSet, trafficStatsUid, requestFinishedListener, idempotency, networkHandle, method, requestHeaders, uploadDataProvider, uploadDataProviderExecutor, dictionarySha256Hash, dictionary, dictionaryId) {
        var funcName = "CronetUrlRequest"
        var funcParaDict = {
          "requestContext": requestContext,
          "url": url,
          "priority": priority,
          "callback": callback,
          "executor": executor,
          "requestAnnotations": requestAnnotations,
          "disableCache": disableCache,
          "disableConnectionMigration": disableConnectionMigration,
          "allowDirectExecutor": allowDirectExecutor,
          "trafficStatsTagSet": trafficStatsTagSet,
          "trafficStatsTag": trafficStatsTag,
          "trafficStatsUidSet": trafficStatsUidSet,
          "trafficStatsUid": trafficStatsUid,
          "requestFinishedListener": requestFinishedListener,
          "idempotency": idempotency,
          "networkHandle": networkHandle,
          "method": method,
          "requestHeaders": requestHeaders,
          "uploadDataProvider": uploadDataProvider,
          "uploadDataProviderExecutor": uploadDataProviderExecutor,
          "dictionarySha256Hash": dictionarySha256Hash,
          "dictionary": dictionary,
          "dictionaryId": dictionaryId,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init(requestContext, url, priority, callback, executor, requestAnnotations, disableCache, disableConnectionMigration, allowDirectExecutor, trafficStatsTagSet, trafficStatsTag, trafficStatsUidSet, trafficStatsUid, requestFinishedListener, idempotency, networkHandle, method, requestHeaders, uploadDataProvider, uploadDataProviderExecutor, dictionarySha256Hash, dictionary, dictionaryId)
        var newCronetUrlRequest = this
        console.log(funcName + " => newCronetUrlRequest=" + newCronetUrlRequest)
        return
      }
    }

    // public void start() {
    // 
    var func_CronetUrlRequest_start = cls_CronetUrlRequest.start
    console.log("func_CronetUrlRequest_start=" + func_CronetUrlRequest_start)
    if (func_CronetUrlRequest_start) {
      func_CronetUrlRequest_start.implementation = function () {
        var funcName = "CronetUrlRequest.start"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.start()
      }
    }

    // private void startInternalLocked() {
    // 
    var func_CronetUrlRequest_startInternalLocked = cls_CronetUrlRequest.startInternalLocked
    console.log("func_CronetUrlRequest_startInternalLocked=" + func_CronetUrlRequest_startInternalLocked)
    if (func_CronetUrlRequest_startInternalLocked) {
      func_CronetUrlRequest_startInternalLocked.implementation = function () {
        var funcName = "CronetUrlRequest.startInternalLocked"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.startInternalLocked()
      }
    }

    // public void followRedirect() {
    // 
    var func_CronetUrlRequest_followRedirect = cls_CronetUrlRequest.followRedirect
    console.log("func_CronetUrlRequest_followRedirect=" + func_CronetUrlRequest_followRedirect)
    if (func_CronetUrlRequest_followRedirect) {
      func_CronetUrlRequest_followRedirect.implementation = function () {
        var funcName = "CronetUrlRequest.followRedirect"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.followRedirect()
      }
    }

    // public void read(ByteBuffer buffer) {
    // 
    var func_CronetUrlRequest_read = cls_CronetUrlRequest.read
    console.log("func_CronetUrlRequest_read=" + func_CronetUrlRequest_read)
    if (func_CronetUrlRequest_read) {
      func_CronetUrlRequest_read.implementation = function (buffer) {
        var funcName = "CronetUrlRequest.read"
        var funcParaDict = {
          "buffer": buffer,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.read(buffer)
      }
    }

    // public void cancel() {
    // 
    var func_CronetUrlRequest_cancel = cls_CronetUrlRequest.cancel
    console.log("func_CronetUrlRequest_cancel=" + func_CronetUrlRequest_cancel)
    if (func_CronetUrlRequest_cancel) {
      func_CronetUrlRequest_cancel.implementation = function () {
        var funcName = "CronetUrlRequest.cancel"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.cancel()
      }
    }

    // public boolean isDone() {
    // 
    var func_CronetUrlRequest_isDone = cls_CronetUrlRequest.isDone
    console.log("func_CronetUrlRequest_isDone=" + func_CronetUrlRequest_isDone)
    if (func_CronetUrlRequest_isDone) {
      func_CronetUrlRequest_isDone.implementation = function () {
        var funcName = "CronetUrlRequest.isDone"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean = this.isDone()
        console.log(funcName + " => retBoolean=" + retBoolean)
        return retBoolean
      }
    }

    // private boolean isDoneLocked() {
    // 
    var func_CronetUrlRequest_isDoneLocked = cls_CronetUrlRequest.isDoneLocked
    console.log("func_CronetUrlRequest_isDoneLocked=" + func_CronetUrlRequest_isDoneLocked)
    if (func_CronetUrlRequest_isDoneLocked) {
      func_CronetUrlRequest_isDoneLocked.implementation = function () {
        var funcName = "CronetUrlRequest.isDoneLocked"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean = this.isDoneLocked()
        console.log(funcName + " => retBoolean=" + retBoolean)
        return retBoolean
      }
    }

    // public void getStatus(UrlRequest.StatusListener unsafeListener) {
    // 
    var func_CronetUrlRequest_getStatus = cls_CronetUrlRequest.getStatus
    console.log("func_CronetUrlRequest_getStatus=" + func_CronetUrlRequest_getStatus)
    if (func_CronetUrlRequest_getStatus) {
      func_CronetUrlRequest_getStatus.implementation = function (unsafeListener) {
        var funcName = "CronetUrlRequest.getStatus"
        var funcParaDict = {
          "unsafeListener": unsafeListener,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.getStatus(unsafeListener)
      }
    }

    // public void setOnDestroyedCallbackForTesting(Runnable onDestroyedCallbackForTesting) {
    // 
    var func_CronetUrlRequest_setOnDestroyedCallbackForTesting = cls_CronetUrlRequest.setOnDestroyedCallbackForTesting
    console.log("func_CronetUrlRequest_setOnDestroyedCallbackForTesting=" + func_CronetUrlRequest_setOnDestroyedCallbackForTesting)
    if (func_CronetUrlRequest_setOnDestroyedCallbackForTesting) {
      func_CronetUrlRequest_setOnDestroyedCallbackForTesting.implementation = function (onDestroyedCallbackForTesting) {
        var funcName = "CronetUrlRequest.setOnDestroyedCallbackForTesting"
        var funcParaDict = {
          "onDestroyedCallbackForTesting": onDestroyedCallbackForTesting,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.setOnDestroyedCallbackForTesting(onDestroyedCallbackForTesting)
      }
    }

    /* public void setOnDestroyedUploadCallbackForTesting(
            Runnable onDestroyedUploadCallbackForTesting) {
    */
    // 
    var func_CronetUrlRequest_setOnDestroyedUploadCallbackForTesting = cls_CronetUrlRequest.setOnDestroyedUploadCallbackForTesting
    console.log("func_CronetUrlRequest_setOnDestroyedUploadCallbackForTesting=" + func_CronetUrlRequest_setOnDestroyedUploadCallbackForTesting)
    if (func_CronetUrlRequest_setOnDestroyedUploadCallbackForTesting) {
      func_CronetUrlRequest_setOnDestroyedUploadCallbackForTesting.implementation = function (onDestroyedUploadCallbackForTesting) {
        var funcName = "CronetUrlRequest.setOnDestroyedUploadCallbackForTesting"
        var funcParaDict = {
          "onDestroyedUploadCallbackForTesting": onDestroyedUploadCallbackForTesting,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.setOnDestroyedUploadCallbackForTesting(onDestroyedUploadCallbackForTesting)
      }
    }

    // public long getUrlRequestAdapterForTesting() {
    // 
    var func_CronetUrlRequest_getUrlRequestAdapterForTesting = cls_CronetUrlRequest.getUrlRequestAdapterForTesting
    console.log("func_CronetUrlRequest_getUrlRequestAdapterForTesting=" + func_CronetUrlRequest_getUrlRequestAdapterForTesting)
    if (func_CronetUrlRequest_getUrlRequestAdapterForTesting) {
      func_CronetUrlRequest_getUrlRequestAdapterForTesting.implementation = function () {
        var funcName = "CronetUrlRequest.getUrlRequestAdapterForTesting"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retUrlRequestAdapterForTesting = this.getUrlRequestAdapterForTesting()
        console.log(funcName + " => retUrlRequestAdapterForTesting=" + retUrlRequestAdapterForTesting)
        return retUrlRequestAdapterForTesting
      }
    }

    // private void postTaskToExecutor(Runnable task, String name) {
    // 
    var func_CronetUrlRequest_postTaskToExecutor = cls_CronetUrlRequest.postTaskToExecutor
    console.log("func_CronetUrlRequest_postTaskToExecutor=" + func_CronetUrlRequest_postTaskToExecutor)
    if (func_CronetUrlRequest_postTaskToExecutor) {
      func_CronetUrlRequest_postTaskToExecutor.implementation = function (task, name) {
        var funcName = "CronetUrlRequest.postTaskToExecutor"
        var funcParaDict = {
          "task": task,
          "name": name,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.postTaskToExecutor(task, name)
      }
    }

    // private static int convertRequestPriority(int priority) {
    // 
    var func_CronetUrlRequest_convertRequestPriority = cls_CronetUrlRequest.convertRequestPriority
    console.log("func_CronetUrlRequest_convertRequestPriority=" + func_CronetUrlRequest_convertRequestPriority)
    if (func_CronetUrlRequest_convertRequestPriority) {
      func_CronetUrlRequest_convertRequestPriority.implementation = function (priority) {
        var funcName = "CronetUrlRequest.convertRequestPriority"
        var funcParaDict = {
          "priority": priority,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retInt = this.convertRequestPriority(priority)
        console.log(funcName + " => retInt=" + retInt)
        return retInt
      }
    }

    // private static int convertIdempotency(int idempotency) {
    // 
    var func_CronetUrlRequest_convertIdempotency = cls_CronetUrlRequest.convertIdempotency
    console.log("func_CronetUrlRequest_convertIdempotency=" + func_CronetUrlRequest_convertIdempotency)
    if (func_CronetUrlRequest_convertIdempotency) {
      func_CronetUrlRequest_convertIdempotency.implementation = function (idempotency) {
        var funcName = "CronetUrlRequest.convertIdempotency"
        var funcParaDict = {
          "idempotency": idempotency,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retInt = this.convertIdempotency(idempotency)
        console.log(funcName + " => retInt=" + retInt)
        return retInt
      }
    }

    /* private UrlResponseInfoImpl prepareResponseInfoOnNetworkThread(
            int httpStatusCode,
            String httpStatusText,
            String[] headers,
            boolean wasCached,
            String negotiatedProtocol,
            String proxyServer,
            long receivedByteCount) {
    */
    // 
    var func_CronetUrlRequest_prepareResponseInfoOnNetworkThread = cls_CronetUrlRequest.prepareResponseInfoOnNetworkThread
    console.log("func_CronetUrlRequest_prepareResponseInfoOnNetworkThread=" + func_CronetUrlRequest_prepareResponseInfoOnNetworkThread)
    if (func_CronetUrlRequest_prepareResponseInfoOnNetworkThread) {
      func_CronetUrlRequest_prepareResponseInfoOnNetworkThread.implementation = function (httpStatusCode, httpStatusText, headers, wasCached, negotiatedProtocol, proxyServer, receivedByteCount) {
        var funcName = "CronetUrlRequest.prepareResponseInfoOnNetworkThread"
        var funcParaDict = {
          "httpStatusCode": httpStatusCode,
          "httpStatusText": httpStatusText,
          "headers": headers,
          "wasCached": wasCached,
          "negotiatedProtocol": negotiatedProtocol,
          "proxyServer": proxyServer,
          "receivedByteCount": receivedByteCount,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retUrlResponseInfoImpl = this.prepareResponseInfoOnNetworkThread(httpStatusCode, httpStatusText, headers, wasCached, negotiatedProtocol, proxyServer, receivedByteCount)
        console.log(funcName + " => retUrlResponseInfoImpl=" + retUrlResponseInfoImpl)
        return retUrlResponseInfoImpl
      }
    }

    // private void checkNotStarted() {
    // 
    var func_CronetUrlRequest_checkNotStarted = cls_CronetUrlRequest.checkNotStarted
    console.log("func_CronetUrlRequest_checkNotStarted=" + func_CronetUrlRequest_checkNotStarted)
    if (func_CronetUrlRequest_checkNotStarted) {
      func_CronetUrlRequest_checkNotStarted.implementation = function () {
        var funcName = "CronetUrlRequest.checkNotStarted"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.checkNotStarted()
      }
    }

    /* private void destroyRequestAdapterLocked(
            @RequestFinishedInfoImpl.FinishedReason int finishedReason) {
    */
    // 
    var func_CronetUrlRequest_destroyRequestAdapterLocked = cls_CronetUrlRequest.destroyRequestAdapterLocked
    console.log("func_CronetUrlRequest_destroyRequestAdapterLocked=" + func_CronetUrlRequest_destroyRequestAdapterLocked)
    if (func_CronetUrlRequest_destroyRequestAdapterLocked) {
      func_CronetUrlRequest_destroyRequestAdapterLocked.implementation = function (finishedReason) {
        var funcName = "CronetUrlRequest.destroyRequestAdapterLocked"
        var funcParaDict = {
          "finishedReason": finishedReason,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.destroyRequestAdapterLocked(finishedReason)
      }
    }

    // private void onNonfinalCallbackException(Exception e) {
    // 
    var func_CronetUrlRequest_onNonfinalCallbackException = cls_CronetUrlRequest.onNonfinalCallbackException
    console.log("func_CronetUrlRequest_onNonfinalCallbackException=" + func_CronetUrlRequest_onNonfinalCallbackException)
    if (func_CronetUrlRequest_onNonfinalCallbackException) {
      func_CronetUrlRequest_onNonfinalCallbackException.implementation = function (e) {
        var funcName = "CronetUrlRequest.onNonfinalCallbackException"
        var funcParaDict = {
          "e": e,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.onNonfinalCallbackException(e)
      }
    }

    // private void onFinalCallbackException(String method, Exception e) {
    // 
    var func_CronetUrlRequest_onFinalCallbackException = cls_CronetUrlRequest.onFinalCallbackException
    console.log("func_CronetUrlRequest_onFinalCallbackException=" + func_CronetUrlRequest_onFinalCallbackException)
    if (func_CronetUrlRequest_onFinalCallbackException) {
      func_CronetUrlRequest_onFinalCallbackException.implementation = function (method, e) {
        var funcName = "CronetUrlRequest.onFinalCallbackException"
        var funcParaDict = {
          "method": method,
          "e": e,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.onFinalCallbackException(method, e)
      }
    }

    // void onUploadException(Throwable e) {
    // 
    var func_CronetUrlRequest_onUploadException = cls_CronetUrlRequest.onUploadException
    console.log("func_CronetUrlRequest_onUploadException=" + func_CronetUrlRequest_onUploadException)
    if (func_CronetUrlRequest_onUploadException) {
      func_CronetUrlRequest_onUploadException.implementation = function (e) {
        var funcName = "CronetUrlRequest.onUploadException"
        var funcParaDict = {
          "e": e,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.onUploadException(e)
      }
    }

    // private void failWithException(final CronetException exception) {
    // 
    var func_CronetUrlRequest_failWithException = cls_CronetUrlRequest.failWithException
    console.log("func_CronetUrlRequest_failWithException=" + func_CronetUrlRequest_failWithException)
    if (func_CronetUrlRequest_failWithException) {
      func_CronetUrlRequest_failWithException.implementation = function (exception) {
        var funcName = "CronetUrlRequest.failWithException"
        var funcParaDict = {
          "exception": exception,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.failWithException(exception)
      }
    }

    /* private void onRedirectReceived(
            final String newLocation,
            int httpStatusCode,
            String httpStatusText,
            String[] headers,
            boolean wasCached,
            String negotiatedProtocol,
            String proxyServer,
            long receivedByteCount) {
    */
    // 
    var func_CronetUrlRequest_onRedirectReceived = cls_CronetUrlRequest.onRedirectReceived
    console.log("func_CronetUrlRequest_onRedirectReceived=" + func_CronetUrlRequest_onRedirectReceived)
    if (func_CronetUrlRequest_onRedirectReceived) {
      func_CronetUrlRequest_onRedirectReceived.implementation = function (newLocation, httpStatusCode, httpStatusText, headers, wasCached, negotiatedProtocol, proxyServer, receivedByteCount) {
        var funcName = "CronetUrlRequest.onRedirectReceived"
        var funcParaDict = {
          "newLocation": newLocation,
          "httpStatusCode": httpStatusCode,
          "httpStatusText": httpStatusText,
          "headers": headers,
          "wasCached": wasCached,
          "negotiatedProtocol": negotiatedProtocol,
          "proxyServer": proxyServer,
          "receivedByteCount": receivedByteCount,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.onRedirectReceived(newLocation, httpStatusCode, httpStatusText, headers, wasCached, negotiatedProtocol, proxyServer, receivedByteCount)
      }
    }

    /* private void onResponseStarted(
            int httpStatusCode,
            String httpStatusText,
            String[] headers,
            boolean wasCached,
            String negotiatedProtocol,
            String proxyServer,
            long receivedByteCount) {
    */
    // 
    var func_CronetUrlRequest_onResponseStarted = cls_CronetUrlRequest.onResponseStarted
    console.log("func_CronetUrlRequest_onResponseStarted=" + func_CronetUrlRequest_onResponseStarted)
    if (func_CronetUrlRequest_onResponseStarted) {
      func_CronetUrlRequest_onResponseStarted.implementation = function (httpStatusCode, httpStatusText, headers, wasCached, negotiatedProtocol, proxyServer, receivedByteCount) {
        var funcName = "CronetUrlRequest.onResponseStarted"
        var funcParaDict = {
          "httpStatusCode": httpStatusCode,
          "httpStatusText": httpStatusText,
          "headers": headers,
          "wasCached": wasCached,
          "negotiatedProtocol": negotiatedProtocol,
          "proxyServer": proxyServer,
          "receivedByteCount": receivedByteCount,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.onResponseStarted(httpStatusCode, httpStatusText, headers, wasCached, negotiatedProtocol, proxyServer, receivedByteCount)
      }
    }

    /* private void onReadCompleted(
            final ByteBuffer byteBuffer,
            int bytesRead,
            int initialPosition,
            int initialLimit,
            long receivedByteCount) {
    */
    // 
    var func_CronetUrlRequest_onReadCompleted = cls_CronetUrlRequest.onReadCompleted
    console.log("func_CronetUrlRequest_onReadCompleted=" + func_CronetUrlRequest_onReadCompleted)
    if (func_CronetUrlRequest_onReadCompleted) {
      func_CronetUrlRequest_onReadCompleted.implementation = function (byteBuffer, bytesRead, initialPosition, initialLimit, receivedByteCount) {
        var funcName = "CronetUrlRequest.onReadCompleted"
        var funcParaDict = {
          "byteBuffer": byteBuffer,
          "bytesRead": bytesRead,
          "initialPosition": initialPosition,
          "initialLimit": initialLimit,
          "receivedByteCount": receivedByteCount,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.onReadCompleted(byteBuffer, bytesRead, initialPosition, initialLimit, receivedByteCount)
      }
    }

    // private void onSucceeded(long receivedByteCount) {
    // 
    var func_CronetUrlRequest_onSucceeded = cls_CronetUrlRequest.onSucceeded
    console.log("func_CronetUrlRequest_onSucceeded=" + func_CronetUrlRequest_onSucceeded)
    if (func_CronetUrlRequest_onSucceeded) {
      func_CronetUrlRequest_onSucceeded.implementation = function (receivedByteCount) {
        var funcName = "CronetUrlRequest.onSucceeded"
        var funcParaDict = {
          "receivedByteCount": receivedByteCount,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.onSucceeded(receivedByteCount)
      }
    }

    /* private void onError(
            int errorCode,
            int nativeError,
            int nativeQuicError,
            @ConnectionCloseSource int source,
            String errorString,
            long receivedByteCount) {
    */
    // 
    var func_CronetUrlRequest_onError = cls_CronetUrlRequest.onError
    console.log("func_CronetUrlRequest_onError=" + func_CronetUrlRequest_onError)
    if (func_CronetUrlRequest_onError) {
      func_CronetUrlRequest_onError.implementation = function (errorCode, nativeError, nativeQuicError, source, errorString, receivedByteCount) {
        var funcName = "CronetUrlRequest.onError"
        var funcParaDict = {
          "errorCode": errorCode,
          "nativeError": nativeError,
          "nativeQuicError": nativeQuicError,
          "source": source,
          "errorString": errorString,
          "receivedByteCount": receivedByteCount,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.onError(errorCode, nativeError, nativeQuicError, source, errorString, receivedByteCount)
      }
    }

    // private void onCanceled() {
    // 
    var func_CronetUrlRequest_onCanceled = cls_CronetUrlRequest.onCanceled
    console.log("func_CronetUrlRequest_onCanceled=" + func_CronetUrlRequest_onCanceled)
    if (func_CronetUrlRequest_onCanceled) {
      func_CronetUrlRequest_onCanceled.implementation = function () {
        var funcName = "CronetUrlRequest.onCanceled"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.onCanceled()
      }
    }

    /* private void onStatus(
            final VersionSafeCallbacks.UrlRequestStatusListener listener, final int loadState) {
    */
    // 
    var func_CronetUrlRequest_onStatus = cls_CronetUrlRequest.onStatus
    console.log("func_CronetUrlRequest_onStatus=" + func_CronetUrlRequest_onStatus)
    if (func_CronetUrlRequest_onStatus) {
      func_CronetUrlRequest_onStatus.implementation = function (listener, loadState) {
        var funcName = "CronetUrlRequest.onStatus"
        var funcParaDict = {
          "listener": listener,
          "loadState": loadState,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.onStatus(listener, loadState)
      }
    }

    /* private void onMetricsCollected(
            long requestStartMs,
            long dnsStartMs,
            long dnsEndMs,
            long connectStartMs,
            long connectEndMs,
            long sslStartMs,
            long sslEndMs,
            long sendingStartMs,
            long sendingEndMs,
            long pushStartMs,
            long pushEndMs,
            long responseStartMs,
            long requestEndMs,
            boolean socketReused,
            long sentByteCount,
            long receivedByteCount,
            boolean quicConnectionMigrationAttempted,
            boolean quicConnectionMigrationSuccessful) {
    */
    // 
    var func_CronetUrlRequest_onMetricsCollected = cls_CronetUrlRequest.onMetricsCollected
    console.log("func_CronetUrlRequest_onMetricsCollected=" + func_CronetUrlRequest_onMetricsCollected)
    if (func_CronetUrlRequest_onMetricsCollected) {
      func_CronetUrlRequest_onMetricsCollected.implementation = function (requestStartMs, dnsStartMs, dnsEndMs, connectStartMs, connectEndMs, sslStartMs, sslEndMs, sendingStartMs, sendingEndMs, pushStartMs, pushEndMs, responseStartMs, requestEndMs, socketReused, sentByteCount, receivedByteCount, quicConnectionMigrationAttempted, quicConnectionMigrationSuccessful) {
        var funcName = "CronetUrlRequest.onMetricsCollected"
        var funcParaDict = {
          "requestStartMs": requestStartMs,
          "dnsStartMs": dnsStartMs,
          "dnsEndMs": dnsEndMs,
          "connectStartMs": connectStartMs,
          "connectEndMs": connectEndMs,
          "sslStartMs": sslStartMs,
          "sslEndMs": sslEndMs,
          "sendingStartMs": sendingStartMs,
          "sendingEndMs": sendingEndMs,
          "pushStartMs": pushStartMs,
          "pushEndMs": pushEndMs,
          "responseStartMs": responseStartMs,
          "requestEndMs": requestEndMs,
          "socketReused": socketReused,
          "sentByteCount": sentByteCount,
          "receivedByteCount": receivedByteCount,
          "quicConnectionMigrationAttempted": quicConnectionMigrationAttempted,
          "quicConnectionMigrationSuccessful": quicConnectionMigrationSuccessful,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.onMetricsCollected(requestStartMs, dnsStartMs, dnsEndMs, connectStartMs, connectEndMs, sslStartMs, sslEndMs, sendingStartMs, sendingEndMs, pushStartMs, pushEndMs, responseStartMs, requestEndMs, socketReused, sentByteCount, receivedByteCount, quicConnectionMigrationAttempted, quicConnectionMigrationSuccessful)
      }
    }

    // private void onNativeAdapterDestroyed() {
    // 
    var func_CronetUrlRequest_onNativeAdapterDestroyed = cls_CronetUrlRequest.onNativeAdapterDestroyed
    console.log("func_CronetUrlRequest_onNativeAdapterDestroyed=" + func_CronetUrlRequest_onNativeAdapterDestroyed)
    if (func_CronetUrlRequest_onNativeAdapterDestroyed) {
      func_CronetUrlRequest_onNativeAdapterDestroyed.implementation = function () {
        var funcName = "CronetUrlRequest.onNativeAdapterDestroyed"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.onNativeAdapterDestroyed()
      }
    }

    // void checkCallingThread() {
    // 
    var func_CronetUrlRequest_checkCallingThread = cls_CronetUrlRequest.checkCallingThread
    console.log("func_CronetUrlRequest_checkCallingThread=" + func_CronetUrlRequest_checkCallingThread)
    if (func_CronetUrlRequest_checkCallingThread) {
      func_CronetUrlRequest_checkCallingThread.implementation = function () {
        var funcName = "CronetUrlRequest.checkCallingThread"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.checkCallingThread()
      }
    }

    // private int mapUrlRequestErrorToApiErrorCode(int errorCode) {
    // 
    var func_CronetUrlRequest_mapUrlRequestErrorToApiErrorCode = cls_CronetUrlRequest.mapUrlRequestErrorToApiErrorCode
    console.log("func_CronetUrlRequest_mapUrlRequestErrorToApiErrorCode=" + func_CronetUrlRequest_mapUrlRequestErrorToApiErrorCode)
    if (func_CronetUrlRequest_mapUrlRequestErrorToApiErrorCode) {
      func_CronetUrlRequest_mapUrlRequestErrorToApiErrorCode.implementation = function (errorCode) {
        var funcName = "CronetUrlRequest.mapUrlRequestErrorToApiErrorCode"
        var funcParaDict = {
          "errorCode": errorCode,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retInt = this.mapUrlRequestErrorToApiErrorCode(errorCode)
        console.log(funcName + " => retInt=" + retInt)
        return retInt
      }
    }

    // private CronetTrafficInfo buildCronetTrafficInfo() {
    // 
    var func_CronetUrlRequest_buildCronetTrafficInfo = cls_CronetUrlRequest.buildCronetTrafficInfo
    console.log("func_CronetUrlRequest_buildCronetTrafficInfo=" + func_CronetUrlRequest_buildCronetTrafficInfo)
    if (func_CronetUrlRequest_buildCronetTrafficInfo) {
      func_CronetUrlRequest_buildCronetTrafficInfo.implementation = function () {
        var funcName = "CronetUrlRequest.buildCronetTrafficInfo"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retCronetTrafficInfo = this.buildCronetTrafficInfo()
        console.log(funcName + " => retCronetTrafficInfo=" + retCronetTrafficInfo)
        return retCronetTrafficInfo
      }
    }

    // private void maybeReportMetrics() {
    // 
    var func_CronetUrlRequest_maybeReportMetrics = cls_CronetUrlRequest.maybeReportMetrics
    console.log("func_CronetUrlRequest_maybeReportMetrics=" + func_CronetUrlRequest_maybeReportMetrics)
    if (func_CronetUrlRequest_maybeReportMetrics) {
      func_CronetUrlRequest_maybeReportMetrics.implementation = function () {
        var funcName = "CronetUrlRequest.maybeReportMetrics"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.maybeReportMetrics()
      }
    }

  }

  static CronetUrlRequest() {
    var clsName_CronetUrlRequest = "org.chromium.net.impl.CronetUrlRequest"
    FridaAndroidUtil.updateClassLoader(clsName_CronetUrlRequest)
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_CronetUrlRequest)

    var cls_CronetUrlRequest = Java.use(clsName_CronetUrlRequest)
    console.log("cls_CronetUrlRequest=" + cls_CronetUrlRequest)

    FridaHookAndroidJava.CronetUrlRequest_origCode(cls_CronetUrlRequest)
  }

  static UUID(callback_isShowLog=null) {
    var clsName_UUID = "java.util.UUID"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_UUID)

    var cls_UUID = Java.use(clsName_UUID)
    console.log("cls_UUID=" + cls_UUID)

    var curLogFunc = FridaAndroidUtil.printFunctionCallAndStack
    // var curLogFunc = FridaAndroidUtil.printFunctionCallStr

    // UUID([B)
    // public java.util.UUID java.util.UUID.<init>(byte[])
    var func_UUID_ctor_1b = cls_UUID.$init.overload('[B')
    console.log("func_UUID_ctor_1b=" + func_UUID_ctor_1b)
    if (func_UUID_ctor_1b) {
      func_UUID_ctor_1b.implementation = function (byteArray) {
        var funcName = "UUID([B)"
        var funcParaDict = {
          "byteArray": byteArray,
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)
        this.$init(byteArray)
        var newUUID_1b = this
        if (isShowLog){
          console.log(funcName + " => newUUID_1b=" + newUUID_1b)
        }
        return
      }
    }

    // UUID(long mostSigBits, long leastSigBits)
    // public java.util.UUID java.util.UUID.<init>(long, long)
    var func_UUID_ctor_2pll = cls_UUID.$init.overload('long', 'long')
    console.log("func_UUID_ctor_2pll=" + func_UUID_ctor_2pll)
    if (func_UUID_ctor_2pll) {
      func_UUID_ctor_2pll.implementation = function (mostSigBits, leastSigBits) {
        var funcName = "UUID(long,long)"
        var funcParaDict = {
          "mostSigBits": mostSigBits,
          "leastSigBits": leastSigBits,
        }

        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        this.$init(mostSigBits, leastSigBits)
        var newUUID_2pll = this
        if (isShowLog){
          console.log(funcName + " => newUUID_2pll=" + newUUID_2pll)
        }
        return
      }
    }

    // static UUID randomUUID()
    // public static java.util.UUID java.util.UUID.randomUUID()
    var func_UUID_randomUUID = cls_UUID.randomUUID
    console.log("func_UUID_randomUUID=" + func_UUID_randomUUID)
    if (func_UUID_randomUUID) {
      func_UUID_randomUUID.implementation = function () {
        var funcName = "UUID.randomUUID"
        var funcParaDict = {}

        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        var retUUID = this.randomUUID()
        if (isShowLog){
          console.log(funcName + " => retUUID=" + retUUID)
        }
        return retUUID
      }
    }

    // long getLeastSignificantBits()
    // public long java.util.UUID.getLeastSignificantBits()
    var func_UUID_getLeastSignificantBits = cls_UUID.getLeastSignificantBits
    console.log("func_UUID_getLeastSignificantBits=" + func_UUID_getLeastSignificantBits)
    if (func_UUID_getLeastSignificantBits) {
      func_UUID_getLeastSignificantBits.implementation = function () {
        var funcName = "UUID.getLeastSignificantBits"
        var funcParaDict = {}

        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        var retLeastSignificantBits = this.getLeastSignificantBits()
        if (isShowLog){
          console.log(funcName + " => retLeastSignificantBits=" + retLeastSignificantBits)
        }
        return retLeastSignificantBits
      }
    }

    // long getMostSignificantBits()
    // public long java.util.UUID.getMostSignificantBits()
    var func_UUID_getMostSignificantBits = cls_UUID.getMostSignificantBits
    console.log("func_UUID_getMostSignificantBits=" + func_UUID_getMostSignificantBits)
    if (func_UUID_getMostSignificantBits) {
      func_UUID_getMostSignificantBits.implementation = function () {
        var funcName = "UUID.getMostSignificantBits"
        var funcParaDict = {}

        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        var retMostSignificantBits = this.getMostSignificantBits()
        if (isShowLog){
          console.log(funcName + " => retMostSignificantBits=" + retMostSignificantBits)
        }
        return retMostSignificantBits
      }
    }

  }

  static Context() {
    var clsName_Context = "android.content.Context"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Context)

    var cls_Context = Java.use(clsName_Context)
    console.log("cls_Context=" + cls_Context)

    // public abstract Context createPackageContext (String packageName, int flags)
    // 
    var func_Context_createPackageContext = cls_Context.createPackageContext
    console.log("func_Context_createPackageContext=" + func_Context_createPackageContext)
    if (func_Context_createPackageContext) {
      func_Context_createPackageContext.implementation = function (packageName, flags) {
        var funcName = "Context.createPackageContext"
        var funcParaDict = {
          "packageName": packageName,
          "flags": flags,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retContext = this.createPackageContext(packageName, flags)
        console.log(funcName + " => retContext=" + retContext)
        return retContext
      }
    }

    // public abstract FileInputStream openFileInput(String name)
    // 
    var func_Context_openFileInput = cls_Context.openFileInput
    console.log("func_Context_openFileInput=" + func_Context_openFileInput)
    if (func_Context_openFileInput) {
      func_Context_openFileInput.implementation = function (name) {
        var funcName = "Context.openFileInput"
        var funcParaDict = {
          "name": name,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retFileInputStream = this.openFileInput(name)
        console.log(funcName + " => retFileInputStream=" + retFileInputStream)
        return retFileInputStream
      }
    }

    // public abstract File getDir(String name, int mode)
    // 
    var func_Context_getDir = cls_Context.getDir
    console.log("func_Context_getDir=" + func_Context_getDir)
    if (func_Context_getDir) {
      func_Context_getDir.implementation = function (name, mode) {
        var funcName = "Context.getDir"
        var funcParaDict = {
          "name": name,
          "mode": mode,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retDir = this.getDir(name, mode)
        console.log(funcName + " => retDir=" + retDir)
        return retDir
      }
    }

    // public abstract SharedPreferences getSharedPreferences(String name, int mode)
    // public abstract android.content.SharedPreferences android.content.Context.getSharedPreferences(java.lang.String,int)
    var func_Context_getSharedPreferences_2psi = cls_Context.getSharedPreferences.overload('java.lang.String', 'int')
    console.log("func_Context_getSharedPreferences_2psi=" + func_Context_getSharedPreferences_2psi)
    if (func_Context_getSharedPreferences_2psi) {
      func_Context_getSharedPreferences_2psi.implementation = function (name, mode) {
        var funcName = "Context.getSharedPreferences_2psi"
        var funcParaDict = {
          "name": name,
          "mode": mode,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retSharedPreferences_2psi = this.getSharedPreferences(name, mode)
        console.log(funcName + " => retSharedPreferences_2psi=" + retSharedPreferences_2psi)
        return retSharedPreferences_2psi
      }
    }

  }

  static ContextWrapper() {
    var clsName_ContextWrapper = "android.content.ContextWrapper"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_ContextWrapper)

    var cls_ContextWrapper = Java.use(clsName_ContextWrapper)
    console.log("cls_ContextWrapper=" + cls_ContextWrapper)

    // public PackageManager getPackageManager()
    // public android.content.pm.PackageManager android.content.ContextWrapper.getPackageManager()
    var func_ContextWrapper_getPackageManager = cls_ContextWrapper.getPackageManager
    console.log("func_ContextWrapper_getPackageManager=" + func_ContextWrapper_getPackageManager)
    if (func_ContextWrapper_getPackageManager) {
      func_ContextWrapper_getPackageManager.implementation = function () {
        var funcName = "ContextWrapper.getPackageManager"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retPackageManager = this.getPackageManager()
        console.log(funcName + " => retPackageManager=" + retPackageManager)
        return retPackageManager
      }
    }

    // public Object getSystemService(String name)
    // public java.lang.Object android.content.ContextWrapper.getSystemService(java.lang.String)
    var func_ContextWrapper_getSystemService = cls_ContextWrapper.getSystemService
    console.log("func_ContextWrapper_getSystemService=" + func_ContextWrapper_getSystemService)
    if (func_ContextWrapper_getSystemService) {
      func_ContextWrapper_getSystemService.implementation = function (name) {
        var funcName = "ContextWrapper.getSystemService"
        var funcParaDict = {
          "name": name,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retSystemService = this.getSystemService(name)
        console.log(funcName + " => retSystemService=" + retSystemService)
        return retSystemService
      }
    }


    // public ContentResolver getContentResolver()
    // public android.content.ContentResolver android.content.ContextWrapper.getContentResolver()
    var func_ContextWrapper_getContentResolver = cls_ContextWrapper.getContentResolver
    console.log("func_ContextWrapper_getContentResolver=" + func_ContextWrapper_getContentResolver)
    if (func_ContextWrapper_getContentResolver) {
      func_ContextWrapper_getContentResolver.implementation = function () {
        var funcName = "ContextWrapper.getContentResolver"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retContentResolver = this.getContentResolver()
        console.log(funcName + " => retContentResolver=" + retContentResolver)
        return retContentResolver
      }
    }

    // SharedPreferences getSharedPreferences(String name, int mode)
    // public android.content.SharedPreferences android.content.ContextWrapper.getSharedPreferences(java.lang.String,int)
    var func_ContextWrapper_getSharedPreferences = cls_ContextWrapper.getSharedPreferences.overload('java.lang.String', 'int')
    console.log("func_ContextWrapper_getSharedPreferences=" + func_ContextWrapper_getSharedPreferences)
    if (func_ContextWrapper_getSharedPreferences) {
      func_ContextWrapper_getSharedPreferences.implementation = function (name, mode) {
        var funcName = "ContextWrapper.getSharedPreferences"
        var funcParaDict = {
          "name": name,
          "mode": mode,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retSharedPreferences = this.getSharedPreferences(name, mode)
        // console.log(funcName + " => retSharedPreferences=" + retSharedPreferences)
        console.log(`${funcName}(name=${name},mode=${mode}) => retSharedPreferences=${retSharedPreferences}`)

        // // for debug: emulate can NOT get checkin related SharedPreferences
        // if (
        //   (name == "Checkin") ||
        //   (name == "constellation_prefs") ||
        //   (name == "CheckinService")
        //  ) {
        //   retSharedPreferences = null
        //   var dbgStr = "for debug: emulate can NOT get checkin related SharedPreferences"
        //   console.log(dbgStr + " " + funcName + " => retSharedPreferences=" + retSharedPreferences)
        // }

        return retSharedPreferences
      }
    }

    // Context createPackageContext(String packageName, int flags)
    // public android.content.Context android.content.ContextWrapper.createPackageContext(java.lang.String,int) throws android.content.pm.PackageManager$NameNotFoundException
    var func_ContextWrapper_createPackageContext = cls_ContextWrapper.createPackageContext
    console.log("func_ContextWrapper_createPackageContext=" + func_ContextWrapper_createPackageContext)
    if (func_ContextWrapper_createPackageContext) {
      func_ContextWrapper_createPackageContext.implementation = function (packageName, flags) {
        var funcName = "ContextWrapper.createPackageContext"
        var funcParaDict = {
          "packageName": packageName,
          "flags": flags,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retContext = this.createPackageContext(packageName, flags)
        // console.log(funcName + " => retContext=" + retContext)
        console.log(`${funcName}(packageName=${packageName},flags=${flags}) => retContext=${retContext}`)
        return retContext
      }
    }

    // FileInputStream openFileInput(String name)
    // public java.io.FileInputStream android.content.ContextWrapper.openFileInput(java.lang.String) throws java.io.FileNotFoundException
    var func_ContextWrapper_openFileInput = cls_ContextWrapper.openFileInput
    console.log("func_ContextWrapper_openFileInput=" + func_ContextWrapper_openFileInput)
    if (func_ContextWrapper_openFileInput) {
      func_ContextWrapper_openFileInput.implementation = function (name) {
        var funcName = "ContextWrapper.openFileInput"
        var funcParaDict = {
          "name": name,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retFileInputStream = this.openFileInput(name)

        // // for debug: emulate can NOT get checkin_id_token
        // if (
        //   name == "checkin_id_token" // /data/user/0/com.google.android.gms/files/checkin_id_token
        //   || name == "security_token" // /data/user/0/com.google.android.gsf/files/security_token
        // ) {
        //   // retFileInputStream = null
        //   // var dbgStr = "for debug: emulate can NOT get checkin_id_token"
        //   // console.log(dbgStr + " " + funcName + " => retFileInputStream=" + retFileInputStream)

        //   // var notFoundException = new FridaAndroidUtil.FileNotFoundException("Emulated file not exist: " + name)
        //   var notFoundException = FridaAndroidUtil.FileNotFoundException.$new("Emulated file not exist: " + name)
        //   console.log(`${funcName}(name=${name}) => notFoundException=${notFoundException}`)
        //   throw notFoundException
        // } else {
          // console.log(funcName + " => retFileInputStream=" + retFileInputStream)
          console.log(`${funcName}(name=${name}) => retFileInputStream=${retFileInputStream}`)
          return retFileInputStream
        // }

      }
    }

    // // public Resources getResources()
    // // public android.content.res.Resources android.content.ContextWrapper.getResources()
    // var func_ContextWrapper_getResources = cls_ContextWrapper.getResources
    // console.log("func_ContextWrapper_getResources=" + func_ContextWrapper_getResources)
    // if (func_ContextWrapper_getResources) {
    //   func_ContextWrapper_getResources.implementation = function () {
    //     var funcName = "ContextWrapper.getResources"
    //     var funcParaDict = {}
    //     FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
    //     var retResources = this.getResources()
    //     console.log(funcName + " => retResources=" + retResources)
    //     return retResources
    //   }
    // }

    // public AssetManager getAssets()
    // public android.content.res.AssetManager android.content.ContextWrapper.getAssets()
    var func_ContextWrapper_getAssets = cls_ContextWrapper.getAssets
    console.log("func_ContextWrapper_getAssets=" + func_ContextWrapper_getAssets)
    if (func_ContextWrapper_getAssets) {
      func_ContextWrapper_getAssets.implementation = function () {
        var funcName = "ContextWrapper.getAssets"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retAssetManager = this.getAssets()
        console.log(funcName + " => retAssetManager=" + retAssetManager)
        return retAssetManager
      }
    }

    // SharedPreferences getSharedPreferences(String name, int mode)
    // public android.content.SharedPreferences android.content.ContextWrapper.getSharedPreferences(java.lang.String,int)
    var func_ContextWrapper_getSharedPreferences_2pnm = cls_ContextWrapper.getSharedPreferences.overload("java.lang.String", "int")
    console.log("func_ContextWrapper_getSharedPreferences_2pnm=" + func_ContextWrapper_getSharedPreferences_2pnm)
    if (func_ContextWrapper_getSharedPreferences_2pnm) {
      func_ContextWrapper_getSharedPreferences_2pnm.implementation = function (name, mode) {
        var funcName = "ContextWrapper.getSharedPreferences(name,mode)"
        var funcParaDict = {
          "name": name,
          "mode": mode
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retSharedPreferences_2pnm = this.getSharedPreferences(name, mode)
        var clsNameValStr = FridaAndroidUtil.valueToNameStr(retSharedPreferences_2pnm)
        console.log(funcName + " => retSharedPreferences_2pnm=" + clsNameValStr)
          return retSharedPreferences_2pnm
      }
    }

  }

  static SharedPreferencesImpl_EditorImpl(){
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_SharedPreferencesImpl_EditorImpl)

    var cls_SharedPreferencesImpl_EditorImpl = Java.use(FridaAndroidUtil.clsName_SharedPreferencesImpl_EditorImpl)
    console.log("cls_SharedPreferencesImpl_EditorImpl=" + cls_SharedPreferencesImpl_EditorImpl)

    const curLogFunc = FridaAndroidUtil.printFunctionCallAndStack
    // const curLogFunc = FridaAndroidUtil.printFunctionCallStr

    // public Editor putString(String key, @Nullable String value) {
    // public android.content.SharedPreferences$Editor android.app.SharedPreferencesImpl$EditorImpl.putString(java.lang.String,java.lang.String)
    var func_SharedPreferencesImpl_EditorImpl_putString = cls_SharedPreferencesImpl_EditorImpl.putString
    console.log("func_SharedPreferencesImpl_EditorImpl_putString=" + func_SharedPreferencesImpl_EditorImpl_putString)
    if (func_SharedPreferencesImpl_EditorImpl_putString) {
      func_SharedPreferencesImpl_EditorImpl_putString.implementation = function (key, value) {
        var funcName = "SharedPreferencesImpl.EditorImpl.putString"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        curLogFunc(funcName, funcParaDict)
        var retEditor = this.putString(key, value)
        console.log(funcName + " => retEditor=" + retEditor)
        return retEditor
      }
    }

    // public Editor putStringSet(String key, @Nullable Set<String> values) {
    // public android.content.SharedPreferences$Editor android.app.SharedPreferencesImpl$EditorImpl.putStringSet(java.lang.String,java.util.Set)
    var func_SharedPreferencesImpl_EditorImpl_putStringSet = cls_SharedPreferencesImpl_EditorImpl.putStringSet
    console.log("func_SharedPreferencesImpl_EditorImpl_putStringSet=" + func_SharedPreferencesImpl_EditorImpl_putStringSet)
    if (func_SharedPreferencesImpl_EditorImpl_putStringSet) {
      func_SharedPreferencesImpl_EditorImpl_putStringSet.implementation = function (key, values) {
        var funcName = "SharedPreferencesImpl.EditorImpl.putStringSet"
        var funcParaDict = {
          "key": key,
          "values": values,
        }
        curLogFunc(funcName, funcParaDict)
        var retEditor = this.putStringSet(key, values)
        console.log(funcName + " => retEditor=" + retEditor)
        return retEditor
      }
    }

    // public Editor remove(String key) {
    // public android.content.SharedPreferences$Editor android.app.SharedPreferencesImpl$EditorImpl.remove(java.lang.String)
    var func_SharedPreferencesImpl_EditorImpl_remove = cls_SharedPreferencesImpl_EditorImpl.remove
    console.log("func_SharedPreferencesImpl_EditorImpl_remove=" + func_SharedPreferencesImpl_EditorImpl_remove)
    if (func_SharedPreferencesImpl_EditorImpl_remove) {
      func_SharedPreferencesImpl_EditorImpl_remove.implementation = function (key) {
        var funcName = "SharedPreferencesImpl.EditorImpl.remove"
        var funcParaDict = {
          "key": key,
        }
        curLogFunc(funcName, funcParaDict)
        var retEditor = this.remove(key)
        console.log(funcName + " => retEditor=" + retEditor)
        return retEditor
      }
    }

    // public Editor putLong(String key, long value) {
    // public android.content.SharedPreferences$Editor android.app.SharedPreferencesImpl$EditorImpl.putLong(java.lang.String,long)
    var func_SharedPreferencesImpl_EditorImpl_putLong = cls_SharedPreferencesImpl_EditorImpl.putLong
    console.log("func_SharedPreferencesImpl_EditorImpl_putLong=" + func_SharedPreferencesImpl_EditorImpl_putLong)
    if (func_SharedPreferencesImpl_EditorImpl_putLong) {
      func_SharedPreferencesImpl_EditorImpl_putLong.implementation = function (key, value) {
        var funcName = "SharedPreferencesImpl.EditorImpl.putLong"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        curLogFunc(funcName, funcParaDict)
        var retEditor = this.putLong(key, value)
        console.log(funcName + " => retEditor=" + retEditor)
        return retEditor
      }
    }

    // public Editor putBoolean(String key, boolean value) {
    // public android.content.SharedPreferences$Editor android.app.SharedPreferencesImpl$EditorImpl.putBoolean(java.lang.String,boolean)
    var func_SharedPreferencesImpl_EditorImpl_putBoolean = cls_SharedPreferencesImpl_EditorImpl.putBoolean
    console.log("func_SharedPreferencesImpl_EditorImpl_putBoolean=" + func_SharedPreferencesImpl_EditorImpl_putBoolean)
    if (func_SharedPreferencesImpl_EditorImpl_putBoolean) {
      func_SharedPreferencesImpl_EditorImpl_putBoolean.implementation = function (key, value) {
        var funcName = "SharedPreferencesImpl.EditorImpl.putBoolean"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        curLogFunc(funcName, funcParaDict)
        var retEditor = this.putBoolean(key, value)
        console.log(funcName + " => retEditor=" + retEditor)
        return retEditor
      }
    }

    // public Editor putFloat(String key, float value) {
    // public android.content.SharedPreferences$Editor android.app.SharedPreferencesImpl$EditorImpl.putFloat(java.lang.String,float)
    var func_SharedPreferencesImpl_EditorImpl_putFloat = cls_SharedPreferencesImpl_EditorImpl.putFloat
    console.log("func_SharedPreferencesImpl_EditorImpl_putFloat=" + func_SharedPreferencesImpl_EditorImpl_putFloat)
    if (func_SharedPreferencesImpl_EditorImpl_putFloat) {
      func_SharedPreferencesImpl_EditorImpl_putFloat.implementation = function (key, value) {
        var funcName = "SharedPreferencesImpl.EditorImpl.putFloat"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        curLogFunc(funcName, funcParaDict)
        var retEditor = this.putFloat(key, value)
        console.log(funcName + " => retEditor=" + retEditor)
        return retEditor
      }
    }

    // public Editor putInt(String key, int value) {
    // public android.content.SharedPreferences$Editor android.app.SharedPreferencesImpl$EditorImpl.putInt(java.lang.String,int)
    var func_SharedPreferencesImpl_EditorImpl_putInt = cls_SharedPreferencesImpl_EditorImpl.putInt
    console.log("func_SharedPreferencesImpl_EditorImpl_putInt=" + func_SharedPreferencesImpl_EditorImpl_putInt)
    if (func_SharedPreferencesImpl_EditorImpl_putInt) {
      func_SharedPreferencesImpl_EditorImpl_putInt.implementation = function (key, value) {
        var funcName = "SharedPreferencesImpl.EditorImpl.putInt"
        var funcParaDict = {
          "key": key,
          "value": value,
        }
        curLogFunc(funcName, funcParaDict)
        var retEditor = this.putInt(key, value)
        console.log(funcName + " => retEditor=" + retEditor)
        return retEditor
      }
    }

  }

  static SharedPreferencesImpl() {
    var clsName_SharedPreferencesImpl = "android.app.SharedPreferencesImpl"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_SharedPreferencesImpl)

    var cls_SharedPreferencesImpl = Java.use(clsName_SharedPreferencesImpl)
    console.log("cls_SharedPreferencesImpl=" + cls_SharedPreferencesImpl)

    const curLogFunc = FridaAndroidUtil.printFunctionCallAndStack
    // const curLogFunc = FridaAndroidUtil.printFunctionCallStr

    // public Map<String, ?> getAll() {
    // public java.util.Map android.app.SharedPreferencesImpl.getAll()
    var func_SharedPreferencesImpl_getAll = cls_SharedPreferencesImpl.getAll
    console.log("func_SharedPreferencesImpl_getAll=" + func_SharedPreferencesImpl_getAll)
    if (func_SharedPreferencesImpl_getAll) {
      func_SharedPreferencesImpl_getAll.implementation = function () {
        var funcName = "SharedPreferencesImpl.getAll"
        var funcParaDict = {}
        curLogFunc(funcName, funcParaDict)
        var retMap = this.getAll()
        console.log(funcName + " => retMap=" + FridaAndroidUtil.mapToStr(retMap))
        return retMap
      }
    }

    // public Editor edit() {
    // public android.app.SharedPreferencesImpl$Editor android.app.SharedPreferencesImpl.edit()
    var func_SharedPreferencesImpl_edit = cls_SharedPreferencesImpl.edit
    console.log("func_SharedPreferencesImpl_edit=" + func_SharedPreferencesImpl_edit)
    if (func_SharedPreferencesImpl_edit) {
      func_SharedPreferencesImpl_edit.implementation = function () {
        var funcName = "SharedPreferencesImpl.edit"
        var funcParaDict = {}
        curLogFunc(funcName, funcParaDict)
        var retEditor = this.edit()
        console.log(funcName + " => retEditor=" + retEditor)
        FridaAndroidUtil.printClass_SharedPreferencesImpl_EditorImpl(retEditor, funcName)
        return retEditor
      }
    }

    // public long getLong(String key, long defValue)
    // public long android.app.SharedPreferencesImpl.getLong(java.lang.String,long)
    var func_SharedPreferencesImpl_getLong = cls_SharedPreferencesImpl.getLong
    console.log("func_SharedPreferencesImpl_getLong=" + func_SharedPreferencesImpl_getLong)
    if (func_SharedPreferencesImpl_getLong) {
      func_SharedPreferencesImpl_getLong.implementation = function (key, defValue) {
        var funcName = "SharedPreferencesImpl.getLong"
        var funcParaDict = {
          "key": key,
          "defValue": defValue,
        }
        curLogFunc(funcName, funcParaDict)
        
        var funcCallStr = `${funcName}(key=${key},defValue=${defValue})`
        var retLong = this.getLong(key, defValue)
        console.log(`${funcCallStr} => retLong=${retLong}`)

        // // for debug: emulate can NOT get checkin related SharedPreferencesImpl getLong values
        // if (JsUtil.isItemInList(key, HookAppJava_GMS.checkinKeyList)) {
        //   retLong = defValue
        //   var dbgStr = "for debug: emulate can NOT get checkin related SharedPreferencesImpl getLong values"
        //   console.log(dbgStr + " " + funcCallStr + " => retLong=" + retLong)
        // }

        return retLong
      }
    }

    // public String getString(String key, String defValue)
    // public java.lang.String android.app.SharedPreferencesImpl.getString(java.lang.String,java.lang.String)
    var func_SharedPreferencesImpl_getString = cls_SharedPreferencesImpl.getString
    console.log("func_SharedPreferencesImpl_getString=" + func_SharedPreferencesImpl_getString)
    if (func_SharedPreferencesImpl_getString) {
      func_SharedPreferencesImpl_getString.implementation = function (key, defValue) {
        var funcName = "SharedPreferencesImpl.getString"
        var funcParaDict = {
          "key": key,
          "defValue": defValue,
        }
        curLogFunc(funcName, funcParaDict)

        var retStr = this.getString(key, defValue)
        console.log(`${funcName}(key=${key},defValue=${defValue}) => retStr=${retStr}`)

        // // for debug: emulate can NOT get checkin related SharedPreferencesImpl getString values
        // if (JsUtil.isItemInList(key, HookAppJava_GMS.checkinKeyList)) {
        //   retStr = defValue
        //   var dbgStr = "for debug: emulate can NOT get checkin related SharedPreferencesImpl getString values"
        //   console.log(dbgStr + " " + funcName + " => retStr=" + retStr)
        // }

        return retStr
      }
    }

    // public Editor edit()
    // public android.app.SharedPreferencesImpl$Editor android.app.SharedPreferencesImpl.edit()
    var func_SharedPreferencesImpl_edit = cls_SharedPreferencesImpl.edit
    console.log("func_SharedPreferencesImpl_edit=" + func_SharedPreferencesImpl_edit)
    if (func_SharedPreferencesImpl_edit) {
      func_SharedPreferencesImpl_edit.implementation = function () {
        var funcName = "SharedPreferencesImpl.edit"
        var funcParaDict = {}
        curLogFunc(funcName, funcParaDict)
        var retEditor = this.edit()
        console.log(funcName + " => retEditor=" + retEditor)
        return retEditor
      }
    }


  }

  static File(callback_isShowLog=null) {
    var className_File = FridaAndroidUtil.clsName_File
    // FridaAndroidUtil.printClassAllMethodsFields(className_File)

    var cls_File = Java.use(className_File)
    console.log("cls_File=" + cls_File)

    // Error: File(): specified argument types do not match any of:
    // .overload('java.lang.String')
    // .overload('java.net.URI')
    // .overload('java.io.File', 'java.lang.String')
    // .overload('java.lang.String', 'int')
    // .overload('java.lang.String', 'java.io.File')
    // .overload('java.lang.String', 'java.lang.String')

    // File(String pathname)
    var func_File_ctor_1pp = cls_File.$init.overload('java.lang.String')
    console.log("func_File_ctor_1pp=" + func_File_ctor_1pp)
    if (func_File_ctor_1pp) {
      func_File_ctor_1pp.implementation = function (pathname) {
        var funcName = "File_1pp"
        var funcParaDict = {
          "pathname": pathname,
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        // // for debug: tmp use previould check to bypass new File
        // pathname = "" // hook bypass return empty File by empty filename

        this.$init(pathname)
        var newFile_1pp = this
        if (isShowLog) {
          console.log(`${funcName}(${pathname}) => newFile_1pp=${newFile_1pp}`)
        }
        return
      }
    }

    // File(URI uri)
    // 
    var func_File_ctor_1pu = cls_File.$init.overload('java.net.URI')
    console.log("func_File_ctor_1pu=" + func_File_ctor_1pu)
    if (func_File_ctor_1pu) {
      func_File_ctor_1pu.implementation = function (uri) {
        var funcName = "File_1pu"
        var funcParaDict = {
          "uri": uri,
        }
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)
        this.$init(uri)
        if (isShowLog) {
          var newFile_1pu = this
          console.log(funcName + " => newFile_1pu=" + newFile_1pu)
        }
        return
      }
    }

    // String getAbsolutePath()
    // 
    var func_File_getAbsolutePath = cls_File.getAbsolutePath
    console.log("func_File_getAbsolutePath=" + func_File_getAbsolutePath)
    if (func_File_getAbsolutePath) {
      func_File_getAbsolutePath.implementation = function () {
        var funcName = "File.getAbsolutePath"
        var funcParaDict = {}
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        var retAbsolutePath = this.getAbsolutePath()
        var isShowLog = FridaAndroidUtil.showLogIfNecessary(callback_isShowLog, `${funcCallAndStackStr}\n${funcName} => retAbsolutePath=${retAbsolutePath}`)
        return retAbsolutePath
      }
    }

    // File getParentFile()
    // 
    var func_File_getParentFile = cls_File.getParentFile
    console.log("func_File_getParentFile=" + func_File_getParentFile)
    if (func_File_getParentFile) {
      func_File_getParentFile.implementation = function () {
        var funcName = "File.getParentFile"
        var funcParaDict = {}
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retParentFile = this.getParentFile()
        var isShowLog = FridaAndroidUtil.showLogIfNecessary(callback_isShowLog, `${funcCallAndStackStr}\n${funcName} => retParentFile=${retParentFile}`)
        return retParentFile
      }
    }

    // public boolean exists()
    // 
    var func_File_exists = cls_File.exists
    console.log("func_File_exists=" + func_File_exists)
    if (func_File_exists) {
      func_File_exists.implementation = function () {
        var funcName = "File.exists"
        var funcParaDict = {}
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        var fileAbsPath = this.getAbsolutePath()
        var isShowLog = FridaAndroidUtil.showLogIfNecessary(callback_isShowLog, `${funcCallAndStackStr}\n${funcName} fileAbsPath=${fileAbsPath}`)
        var retBoolean = this.exists()
        if(isShowLog){
          console.log(funcName + " => retBoolean=" + retBoolean + ",  fileAbsPath=" + fileAbsPath)
        }
        return retBoolean
      }
    }

  }

  static String(func_isShowLog=null) {
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
        // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        FridaAndroidUtil.printFunctionCallStr(funcName, funcParaDict)
        this.$init(original)
        return
      }
    }

    // String(byte[] bytes, Charset charset)
    // 
    var func_String_ctor_2pbc = cls_String.$init.overload('[B', 'java.nio.charset.Charset')
    console.log("func_String_ctor_2pbc=" + func_String_ctor_2pbc)
    if (func_String_ctor_2pbc) {
      func_String_ctor_2pbc.implementation = function (bytes, charset) {
        var funcName = "String(bytes,charset)"
        var funcParaDict = {
          "bytes": bytes,
          "charset": charset,
        }
        // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        FridaAndroidUtil.printFunctionCallStr(funcName, funcParaDict)

        this.$init(bytes, charset)
        var newString_2pbc = this
        console.log(funcName + " => newString_2pbc=" + newString_2pbc)
        return
      }
    }

    // String(byte[] bytes, String charsetName)
    // 
    var func_String_ctor_2pbs = cls_String.$init.overload('[B', 'java.lang.String')
    console.log("func_String_ctor_2pbs=" + func_String_ctor_2pbs)
    if (func_String_ctor_2pbs) {
      func_String_ctor_2pbs.implementation = function (bytes, charsetName) {
        var funcName = "String(bytes,charsetName)"
        var funcParaDict = {
          "bytes": bytes,
          "charsetName": charsetName,
        }
        // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        FridaAndroidUtil.printFunctionCallStr(funcName, funcParaDict)

        this.$init(bytes, charsetName)
        var newString_2pbs = this
        console.log(funcName + " => newString_2pbs=" + newString_2pbs)
        return
      }
    }

    // // public boolean equals(Object anObject)
    // // public boolean java.lang.String.equals(java.lang.Object)
    // var func_String_equals = cls_String.equals
    // console.log("func_String_equals=" + func_String_equals)
    // if (func_String_equals) {
    //   func_String_equals.implementation = function (anObject) {
    //     var funcName = "String.equals(anObject)"
    //     var funcParaDict = {
    //       "anObject": anObject,
    //     }

    //     var isPrintStack = false
    //     if(null != callback_String_equals) {
    //       isPrintStack = callback_String_equals(anObject)
    //     }

    //     if(isPrintStack){
    //       FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
    //     }

    //     return this.equals(anObject)
    //   }
    // }

    // static String format(Locale l, String format, Object... args)
    // public static java.lang.String java.lang.String.format(java.util.Locale,java.lang.String,java.lang.Object[])
    var func_String_format_3plfa = cls_String.format.overload('java.util.Locale', 'java.lang.String', '[Ljava.lang.Object;')
    console.log("func_String_format_3plfa=" + func_String_format_3plfa)
    if (func_String_format_3plfa) {
      func_String_format_3plfa.implementation = function (l, format, args) {
        var funcName = "String.format_3plfa"
        var funcParaDict = {
          "l": l,
          "format": format,
          "args": args,
        }

        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)

        var retString_3plfa = this.format(l, format, args)

        // var isShowLog = true
        var isShowLog = false

        if(func_isShowLog != null) {
          isShowLog = func_isShowLog(retString_3plfa)
          // isShowLog = func_isShowLog(format)
        }

        if (isShowLog){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
          // FridaAndroidUtil.printFunctionCallStr(funcName, funcParaDict)  
        }

        if (isShowLog){
          console.log(funcCallAndStackStr)
          console.log(funcName + " => retString_3plfa=" + retString_3plfa)
        }

        return retString_3plfa
      }
    }

    // static String format(String format, Object... args)
    // public static java.lang.String java.lang.String.format(java.lang.String,java.lang.Object[])
    var func_String_format_2pfa = cls_String.format.overload('java.lang.String', '[Ljava.lang.Object;')
    console.log("func_String_format_2pfa=" + func_String_format_2pfa)
    if (func_String_format_2pfa) {
      func_String_format_2pfa.implementation = function (format, args) {
        var funcName = "String.format_2pfa"
        var funcParaDict = {
          "format": format,
          "args": args,
        }

        var isShowLog = false
        if(func_isShowLog != null) {
          isShowLog = func_isShowLog(format)
        }

        if (isShowLog){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        }

        var retString_2pfa = this.format(format, args)

        if (isShowLog){
          console.log(funcName + " => retString_2pfa=" + retString_2pfa)
        }

        return retString_2pfa
      }
    }

    // String[] split(String regex)
    // public java.lang.String[] java.lang.String.split(java.lang.String)
    var func_String_split_1pr = cls_String.split.overload('java.lang.String')
    console.log("func_String_split_1pr=" + func_String_split_1pr)
    if (func_String_split_1pr) {
      func_String_split_1pr.implementation = function (regex) {
        var funcName = "String.split_1pr"
        var funcParaDict = {
          "regex": regex,
        }

        var isShowLog = false
        if(func_isShowLog != null) {
          isShowLog = func_isShowLog(regex)
        }

        if (isShowLog){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        }

        var retString_1pr = this.split(regex)

        if (isShowLog){
          console.log(funcName + " => retString_1pr=" + retString_1pr)
        }

        return retString_1pr
      }
    }

    // static String valueOf(long l)
    // public static java.lang.String java.lang.String.valueOf(long)
    var func_String_valueOf_1pl = cls_String.valueOf.overload('long')
    console.log("func_String_valueOf_1pl=" + func_String_valueOf_1pl)
    if (func_String_valueOf_1pl) {
      func_String_valueOf_1pl.implementation = function (l) {
        var funcName = "String.valueOf_1pl"
        var funcParaDict = {
          "l": l,
        }

        var isShowLog = false
        if(func_isShowLog != null) {
          isShowLog = func_isShowLog(l.toString())
        }

        if (isShowLog){
          FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        }

        var retString_1pl = this.valueOf(l)

        if (isShowLog){
          console.log(funcName + " => retString_1pl=" + retString_1pl)
        }

        return retString_1pl
      }
    }

  }

  static URL(callback_isShowLog=null) {
    var clsName_URL = "java.net.URL"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_URL)

    var cls_URL = Java.use(clsName_URL)
    console.log("cls_URL=" + cls_URL)

    // const curLogFunc = FridaAndroidUtil.printFunctionCallAndStack
    const curLogFunc = FridaAndroidUtil.printFunctionCallStr
    
    // public URL(String spec)
    // 
    var func_URL_ctor_1ps = cls_URL.$init.overload('java.lang.String')
    console.log("func_URL_ctor_1ps=" + func_URL_ctor_1ps)
    if (func_URL_ctor_1ps) {
      func_URL_ctor_1ps.implementation = function (spec) {
        var funcName = "URL_1ps"
        var funcParaDict = {
          "spec": spec,
        }
        // curLogFunc(funcName, funcParaDict)
        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)
        this.$init(spec)
        var newURL_1ps = this
        // if (isShowLog) {
          console.log(funcName + " => newURL_1ps=" + newURL_1ps)
        // }
        return
      }
    }

    // String getHost()
    // 
    var func_URL_getHost = cls_URL.getHost
    console.log("func_URL_getHost=" + func_URL_getHost)
    if (func_URL_getHost) {
      func_URL_getHost.implementation = function () {
        var funcName = "URL.getHost"
        var funcParaDict = {}
        curLogFunc(funcName, funcParaDict)
        var retHost = this.getHost()
        console.log(funcName + " => retHost=" + retHost)
        return retHost
      }
    }

    // String getPath()
    // 
    var func_URL_getPath = cls_URL.getPath
    console.log("func_URL_getPath=" + func_URL_getPath)
    if (func_URL_getPath) {
      func_URL_getPath.implementation = function () {
        var funcName = "URL.getPath"
        var funcParaDict = {}
        curLogFunc(funcName, funcParaDict)
        var retPath = this.getPath()
        console.log(funcName + " => retPath=" + retPath)
        return retPath
      }
    }

    // int getPort()
    // 
    var func_URL_getPort = cls_URL.getPort
    console.log("func_URL_getPort=" + func_URL_getPort)
    if (func_URL_getPort) {
      func_URL_getPort.implementation = function () {
        var funcName = "URL.getPort"
        var funcParaDict = {}
        curLogFunc(funcName, funcParaDict)
        var retPort = this.getPort()
        console.log(funcName + " => retPort=" + retPort)
        return retPort
      }
    }

    // String getProtocol()
    // 
    var func_URL_getProtocol = cls_URL.getProtocol
    console.log("func_URL_getProtocol=" + func_URL_getProtocol)
    if (func_URL_getProtocol) {
      func_URL_getProtocol.implementation = function () {
        var funcName = "URL.getProtocol"
        var funcParaDict = {}
        curLogFunc(funcName, funcParaDict)
        var retProtocol = this.getProtocol()
        console.log(funcName + " => retProtocol=" + retProtocol)
        return retProtocol
      }
    }

    // String getQuery()
    // 
    var func_URL_getQuery = cls_URL.getQuery
    console.log("func_URL_getQuery=" + func_URL_getQuery)
    if (func_URL_getQuery) {
      func_URL_getQuery.implementation = function () {
        var funcName = "URL.getQuery"
        var funcParaDict = {}
        curLogFunc(funcName, funcParaDict)
        var retQuery = this.getQuery()
        console.log(funcName + " => retQuery=" + retQuery)
        return retQuery
      }
    }

    // public URLConnection openConnection()
    // public java.net.URLConnection java.net.URL.openConnection() throws java.io.IOException
    var func_URL_openConnection_0p = cls_URL.openConnection.overload()
    console.log("func_URL_openConnection_0p=" + func_URL_openConnection_0p)
    if (func_URL_openConnection_0p) {
      func_URL_openConnection_0p.implementation = function () {
        var funcName = "URL.openConnection"
        var funcParaDict = {}
        // curLogFunc(funcName, funcParaDict)
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        var retUrlConn = this.openConnection()
        var isShowLog = FridaAndroidUtil.showLogIfNecessary(callback_isShowLog, `${funcCallAndStackStr}\n${funcName} => retUrlConn=${retUrlConn}`)
        return retUrlConn
      }
    }

  }

  static GZIPOutputStream() {
    var clsName_GZIPOutputStream = "java.util.zip.GZIPOutputStream"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_GZIPOutputStream)

    var cls_GZIPOutputStream = Java.use(clsName_GZIPOutputStream)
    console.log("cls_GZIPOutputStream=" + cls_GZIPOutputStream)

    
    // GZIPOutputStream(OutputStream out)
    // 
    var func_GZIPOutputStream_ctor_1po = cls_GZIPOutputStream.$init.overload('java.io.OutputStream')
    console.log("func_GZIPOutputStream_ctor_1po=" + func_GZIPOutputStream_ctor_1po)
    if (func_GZIPOutputStream_ctor_1po) {
      func_GZIPOutputStream_ctor_1po.implementation = function (out) {
        var funcName = "GZIPOutputStream_1po"
        var funcParaDict = {
          "out": out,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init(out)
        var newGZIPOutputStream_1po = this
        console.log(funcName + " => newGZIPOutputStream_1po=" + newGZIPOutputStream_1po)
        return
      }
    }

    // void write(byte[] buf, int off, int len)
    // public synchronized void java.util.zip.GZIPOutputStream.write(byte[],int,int) throws java.io.IOException
    var func_GZIPOutputStream_write = cls_GZIPOutputStream.write
    console.log("func_GZIPOutputStream_write=" + func_GZIPOutputStream_write)
    if (func_GZIPOutputStream_write) {
      func_GZIPOutputStream_write.implementation = function (buf, off, len) {
        var funcName = "GZIPOutputStream.write"
        var funcParaDict = {
          "buf": buf,
          "off": off,
          "len": len,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.write(buf, off, len)
      }
    }

    // void	finish()
    // public void java.util.zip.GZIPOutputStream.finish() throws java.io.IOException
    var func_GZIPOutputStream_finish = cls_GZIPOutputStream.finish
    console.log("func_GZIPOutputStream_finish=" + func_GZIPOutputStream_finish)
    if (func_GZIPOutputStream_finish) {
      func_GZIPOutputStream_finish.implementation = function () {
        var funcName = "GZIPOutputStream.finish"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var crc = this.crc.vaue
        console.log(funcName + ": crc=" + crc)

        return this.finish()
      }
    }

    // void	close()
    // 
    var func_GZIPOutputStream_close = cls_GZIPOutputStream.close
    console.log("func_GZIPOutputStream_close=" + func_GZIPOutputStream_close)
    if (func_GZIPOutputStream_close) {
      func_GZIPOutputStream_close.implementation = function () {
        var funcName = "GZIPOutputStream.close"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var crc = this.crc.vaue
        console.log(funcName + ": crc=" + crc)

        return this.close()
      }
    }

  }

  static DeflaterOutputStream() {
    var clsName_DeflaterOutputStream = "java.util.zip.DeflaterOutputStream"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_DeflaterOutputStream)

    var cls_DeflaterOutputStream = Java.use(clsName_DeflaterOutputStream)
    console.log("cls_DeflaterOutputStream=" + cls_DeflaterOutputStream)

    // void	close()
    // public void java.util.zip.DeflaterOutputStream.close() throws java.io.IOException
    var func_DeflaterOutputStream_close = cls_DeflaterOutputStream.close
    console.log("func_DeflaterOutputStream_close=" + func_DeflaterOutputStream_close)
    if (func_DeflaterOutputStream_close) {
      func_DeflaterOutputStream_close.implementation = function () {
        var funcName = "DeflaterOutputStream.close"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var buffer = this.buf.vaue
        console.log(funcName + ": buffer=" + buffer)
        var deflater = this.def.vaue
        console.log(funcName + ": deflater=" + deflater)

        // var copiedDos = this.clone()
        // console.log("DeflaterOutputStream: copiedDos=" + copiedDos)
        // if (copiedDos){
        //   var copiedDosBuf = copiedDos.buf
        //   console.log("DeflaterOutputStream: copiedDosBuf=" + copiedDosBuf)
        //   if(copiedDosBuf){
        //     var buffer = copiedDosBuf.value
        //     console.log("DeflaterOutputStream: buffer=" + buffer)
        //   }
        //   var copiedDosDef = copiedDos.def
        //   console.log("DeflaterOutputStream: copiedDosDef=" + copiedDosDef)
        //   if(copiedDosDef){
        //     var deflater = copiedDosDef.value
        //     console.log("DeflaterOutputStream: deflater=" + deflater)  
        //   }
        // }

        return this.close()
      }
    }

    // protected void	deflate()
    // protected void java.util.zip.DeflaterOutputStream.deflate() throws java.io.IOException
    var func_DeflaterOutputStream_deflate = cls_DeflaterOutputStream.deflate
    console.log("func_DeflaterOutputStream_deflate=" + func_DeflaterOutputStream_deflate)
    if (func_DeflaterOutputStream_deflate) {
      func_DeflaterOutputStream_deflate.implementation = function () {
        var funcName = "DeflaterOutputStream.deflate"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var buffer = this.buf.vaue
        console.log(funcName + ": buffer=" + buffer)
        var deflater = this.def.vaue
        console.log(funcName + ": deflater=" + deflater)

        return this.deflate()
      }
    }

    // void	finish()
    // public void java.util.zip.DeflaterOutputStream.finish() throws java.io.IOException
    var func_DeflaterOutputStream_finish = cls_DeflaterOutputStream.finish
    console.log("func_DeflaterOutputStream_finish=" + func_DeflaterOutputStream_finish)
    if (func_DeflaterOutputStream_finish) {
      func_DeflaterOutputStream_finish.implementation = function () {
        var funcName = "DeflaterOutputStream.finish"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var buffer = this.buf.vaue
        console.log(funcName + ": buffer=" + buffer)
        var deflater = this.def.vaue
        console.log(funcName + ": deflater=" + deflater)

        return this.finish()
      }
    }

    // void	flush()
    // public void java.util.zip.DeflaterOutputStream.flush() throws java.io.IOException
    var func_DeflaterOutputStream_flush = cls_DeflaterOutputStream.flush
    console.log("func_DeflaterOutputStream_flush=" + func_DeflaterOutputStream_flush)
    if (func_DeflaterOutputStream_flush) {
      func_DeflaterOutputStream_flush.implementation = function () {
        var funcName = "DeflaterOutputStream.flush"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var buffer = this.buf.vaue
        console.log(funcName + ": buffer=" + buffer)
        var deflater = this.def.vaue
        console.log(funcName + ": deflater=" + deflater)

        return this.flush()
      }
    }

  }

  static BufferedOutputStream() {
    var clsName_BufferedOutputStream = "java.io.BufferedOutputStream"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_BufferedOutputStream)

    var cls_BufferedOutputStream = Java.use(clsName_BufferedOutputStream)
    console.log("cls_BufferedOutputStream=" + cls_BufferedOutputStream)

    // void write(int b)
    // public synchronized void java.io.BufferedOutputStream.write(int) throws java.io.IOException
    var func_BufferedOutputStream_write_1pi = cls_BufferedOutputStream.write.overload('int')
    console.log("func_BufferedOutputStream_write_1pi=" + func_BufferedOutputStream_write_1pi)
    if (func_BufferedOutputStream_write_1pi) {
      func_BufferedOutputStream_write_1pi.implementation = function (b) {
        var funcName = "BufferedOutputStream.write_1pi"
        var funcParaDict = {
          "b": b,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var curBufStr = this.toString()
        console.log(funcName + ": curBufStr=" + curBufStr)

        var buf = this.buf.value
        console.log(funcName + ": buf=" + buf)
        var count = this.count.value
        console.log(funcName + ": count=" + count)

        return this.write(b)
      }
    }

    // void write(byte[] b, int off, int len)
    // public synchronized void java.io.BufferedOutputStream.write(byte[],int,int) throws java.io.IOException
    var func_BufferedOutputStream_write_3pbii = cls_BufferedOutputStream.write.overload('[B', 'int', 'int')
    console.log("func_BufferedOutputStream_write_3pbii=" + func_BufferedOutputStream_write_3pbii)
    if (func_BufferedOutputStream_write_3pbii) {
      func_BufferedOutputStream_write_3pbii.implementation = function (b, off, len) {
        var funcName = "BufferedOutputStream.write_3pbii"
        var funcParaDict = {
          "b": b,
          "off": off,
          "len": len,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var curBufStr = this.toString()
        console.log(funcName + ": curBufStr=" + curBufStr)

        var buf = this.buf.value
        console.log(funcName + ": buf=" + buf)
        var count = this.count.value
        console.log(funcName + ": count=" + count)

        return this.write(b, off, len)
      }
    }

    // void flush()
    // public synchronized void java.io.BufferedOutputStream.flush() throws java.io.IOException
    var func_BufferedOutputStream_flush = cls_BufferedOutputStream.flush
    console.log("func_BufferedOutputStream_flush=" + func_BufferedOutputStream_flush)
    if (func_BufferedOutputStream_flush) {
      func_BufferedOutputStream_flush.implementation = function () {
        var funcName = "BufferedOutputStream.flush"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var curBufStr = this.toString()
        console.log("before " + funcName + ": curBufStr=" + curBufStr)
        
        var buf = this.buf.value
        console.log("before " + funcName + ": buf=" + buf)
        var count = this.count.value
        console.log("before " + funcName + ": count=" + count)

        this.flush()

        var curBufStr = this.toString()
        console.log("after  " + funcName + ": curBufStr=" + curBufStr)
        
        var buf = this.buf.value
        console.log("after  " + funcName + ": buf=" + buf)
        var count = this.count.value
        console.log("after  " + funcName + ": count=" + count)

        return
      }
    }

    // void	close()
    // 
    var func_BufferedOutputStream_close = cls_BufferedOutputStream.close
    console.log("func_BufferedOutputStream_close=" + func_BufferedOutputStream_close)
    if (func_BufferedOutputStream_close) {
      func_BufferedOutputStream_close.implementation = function () {
        var funcName = "BufferedOutputStream.close"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var buf = this.buf.value
        console.log(funcName + " buf=" + buf)
        var count = this.count.value
        console.log(funcName + " count=" + count)

        var curBufStr = this.toString()
        console.log(funcName + " curBufStr=" + curBufStr)
        
        // var copiedBos = this.clone()
        // console.log("BufferedOutputStream: copiedBos=" + copiedBos)
        // if (copiedBos){
        //   var copiedBosBuf = copiedBos.buf
        //   console.log("BufferedOutputStream: copiedBosBuf=" + copiedBosBuf)
        //   if(copiedBosBuf){
        //     var buffer = copiedBosBuf.value
        //     console.log("BufferedOutputStream: buffer=" + buffer)
        //   }
        //   var copiedBosCount = copiedBos.count
        //   console.log("BufferedOutputStream: copiedBosCount=" + copiedBosCount)
        //   if(copiedBosCount){
        //     var count = copiedBosCount.value
        //     console.log("BufferedOutputStream: count=" + count)  
        //   }
        // }

        return this.close()
      }
    }

  }

  static FilterOutputStream() {
    var clsName_FilterOutputStream = "java.io.FilterOutputStream"
    FridaAndroidUtil.printClassAllMethodsFields(clsName_FilterOutputStream)

    var cls_FilterOutputStream = Java.use(clsName_FilterOutputStream)
    console.log("cls_FilterOutputStream=" + cls_FilterOutputStream)

    // void	close()
    // public void java.io.FilterOutputStream.close() throws java.io.IOException
    var func_FilterOutputStream_close = cls_FilterOutputStream.close
    console.log("func_FilterOutputStream_close=" + func_FilterOutputStream_close)
    if (func_FilterOutputStream_close) {
      func_FilterOutputStream_close.implementation = function () {
        var funcName = "FilterOutputStream.close"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var curBufStr = this.toString()
        console.log(funcName + " curBufStr=" + curBufStr)
        var outStream = this.out.value
        console.log(funcName + " outStream=" + outStream)
        // FilterOutputStream.close outStream=buffer(com.android.okhttp.internal.http.RetryableSink@d96946b).outputStream()

        return this.close()
      }
    }

    // void	flush()
    // public void java.io.FilterOutputStream.flush() throws java.io.IOException
    var func_FilterOutputStream_flush = cls_FilterOutputStream.flush
    console.log("func_FilterOutputStream_flush=" + func_FilterOutputStream_flush)
    if (func_FilterOutputStream_flush) {
      func_FilterOutputStream_flush.implementation = function () {
        var funcName = "FilterOutputStream.flush"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var curBufStr = this.toString()
        console.log(funcName + ": curBufStr=" + curBufStr)
        var outStream = this.out.value
        console.log(funcName + ": outStream=" + outStream)

        return this.close()
      }
    }

  }

  static RetryableSink() {
    var clsName_RetryableSink = "com.android.okhttp.internal.http.RetryableSink"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_RetryableSink)

    var cls_RetryableSink = Java.use(clsName_RetryableSink)
    console.log("cls_RetryableSink=" + cls_RetryableSink)

    // @Override public void close() throws IOException {
    // public void com.android.okhttp.internal.http.RetryableSink.close() throws java.io.IOException
    var func_RetryableSink_close = cls_RetryableSink.close
    console.log("func_RetryableSink_close=" + func_RetryableSink_close)
    if (func_RetryableSink_close) {
      func_RetryableSink_close.implementation = function () {
        var funcName = "RetryableSink.close"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        FridaAndroidUtil.printClass_RetryableSink(this, `Before ${funcName}` )

        return this.close()
      }
    }

    // @Override public void write(Buffer source, long byteCount) throws IOException {
    // public void com.android.okhttp.internal.http.RetryableSink.write(com.android.okhttp.okio.Buffer,long) throws java.io.IOException
    var func_RetryableSink_write = cls_RetryableSink.write
    console.log("func_RetryableSink_write=" + func_RetryableSink_write)
    if (func_RetryableSink_write) {
      func_RetryableSink_write.implementation = function (source, byteCount) {
        var funcName = "RetryableSink.write"
        var funcParaDict = {
          "source": source,
          "byteCount": byteCount,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var content = this.content.value
        console.log(funcName + " content=" + content)

        return this.write(source, byteCount)
      }
    }

    // @Override public void flush() throws IOException {
    // public void com.android.okhttp.internal.http.RetryableSink.flush() throws java.io.IOException
    var func_RetryableSink_flush = cls_RetryableSink.flush
    console.log("func_RetryableSink_flush=" + func_RetryableSink_flush)
    if (func_RetryableSink_flush) {
      func_RetryableSink_flush.implementation = function () {
        var funcName = "RetryableSink.flush"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var content = this.content.value
        console.log(funcName + " content=" + content)

        return this.flush()
      }
    }

    // public long contentLength() throws IOException {
    // public long com.android.okhttp.internal.http.RetryableSink.contentLength() throws java.io.IOException
    var func_RetryableSink_contentLength = cls_RetryableSink.contentLength
    console.log("func_RetryableSink_contentLength=" + func_RetryableSink_contentLength)
    if (func_RetryableSink_contentLength) {
      func_RetryableSink_contentLength.implementation = function () {
        var funcName = "RetryableSink.contentLength"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        
        var retContentLength = this.contentLength()
        console.log(funcName + " => retContentLength=" + retContentLength)

        return retContentLength
      }
    }

    // public void writeToSocket(Sink socketOut) throws IOException {
    // public void com.android.okhttp.internal.http.RetryableSink.writeToSocket(com.android.okhttp.okio.Sink) throws java.io.IOException
    var func_RetryableSink_writeToSocket = cls_RetryableSink.writeToSocket
    console.log("func_RetryableSink_writeToSocket=" + func_RetryableSink_writeToSocket)
    if (func_RetryableSink_writeToSocket) {
      func_RetryableSink_writeToSocket.implementation = function (socketOut) {
        var funcName = "RetryableSink.writeToSocket"
        var funcParaDict = {
          "socketOut": socketOut,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var content = this.content.value
        console.log(funcName + " content=" + content)

        return this.writeToSocket(socketOut)
      }
    }

  }

  static Buffer() {
    // var clsName_Buffer = "okio.Buffer"
    var clsName_Buffer = "com.android.okhttp.okio.Buffer"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Buffer)

    var cls_Buffer = Java.use(clsName_Buffer)
    console.log("cls_Buffer=" + cls_Buffer)

    // @Override public int read(byte[] sink) {
    // public int com.android.okhttp.okio.Buffer.read(byte[])
    var func_Buffer_read_1ps = cls_Buffer.read.overload('[B')
    console.log("func_Buffer_read_1ps=" + func_Buffer_read_1ps)
    if (func_Buffer_read_1ps) {
      func_Buffer_read_1ps.implementation = function (sink) {
        var funcName = "okio.Buffer.read_1ps"
        var funcParaDict = {
          "sink": sink,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var curBufStr = this.toString()
        console.log(funcName + " curBufStr=" + curBufStr)
        var head = this.head.value
        console.log(funcName + " head=" + head)
        var size = this.size.value
        console.log(funcName + " size=" + size)

        var readCnt = this.read(sink)
        console.log(funcName + " => readCnt=" + readCnt)
        return readCnt
      }
    }

    // @Override public int read(byte[] sink, int offset, int byteCount) {
    // public int com.android.okhttp.okio.Buffer.read(byte[],int,int)
    var func_Buffer_read_3psob = cls_Buffer.read.overload('[B', 'int', 'int')
    console.log("func_Buffer_read_3psob=" + func_Buffer_read_3psob)
    if (func_Buffer_read_3psob) {
      func_Buffer_read_3psob.implementation = function (sink, offset, byteCount) {
        var funcName = "okio.Buffer.read_3psob"
        var funcParaDict = {
          "sink": sink,
          "offset": offset,
          "byteCount": byteCount,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var curBufStr = this.toString()
        console.log(funcName + " curBufStr=" + curBufStr)
        var head = this.head.value
        console.log(funcName + " head=" + head)
        var size = this.size.value
        console.log(funcName + " size=" + size)

        var readCnt = this.read(sink, offset, byteCount)
        console.log(funcName + " => readCnt=" + readCnt)
        return readCnt
      }
    }

    // @Override public long read(Buffer sink, long byteCount) {
    // public long com.android.okhttp.okio.Buffer.read(com.android.okhttp.okio.Buffer,long)
    var func_Buffer_read_2psb = cls_Buffer.read.overload('com.android.okhttp.okio.Buffer', 'long')
    console.log("func_Buffer_read_2psb=" + func_Buffer_read_2psb)
    if (func_Buffer_read_2psb) {
      func_Buffer_read_2psb.implementation = function (sink, byteCount) {
        var funcName = "okio.Buffer.read_2psb"
        var funcParaDict = {
          "sink": sink,
          "byteCount": byteCount,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var curBufStr = this.toString()
        console.log(funcName + " curBufStr=" + curBufStr)
        var head = this.head.value
        console.log(funcName + " head=" + head)
        var size = this.size.value
        console.log(funcName + " size=" + size)

        var readCnt = this.read(sink, byteCount)
        console.log(funcName + " => readCnt=" + readCnt)
        return readCnt
      }
    }

    // @Override public void readFully(byte[] sink) throws EOFException {
    // public void com.android.okhttp.okio.Buffer.readFully(byte[]) throws java.io.EOFException
    var func_Buffer_readFully_1ps = cls_Buffer.readFully.overload('[B')
    console.log("func_Buffer_readFully_1ps=" + func_Buffer_readFully_1ps)
    if (func_Buffer_readFully_1ps) {
      func_Buffer_readFully_1ps.implementation = function (sink) {
        var funcName = "okio.Buffer.readFully_1ps"
        var funcParaDict = {
          "sink": sink,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var curBufStr = this.toString()
        console.log(funcName + " curBufStr=" + curBufStr)
        var head = this.head.value
        console.log(funcName + " head=" + head)
        var size = this.size.value
        console.log(funcName + " size=" + size)

        return this.readFully(sink)
      }
    }

    // @Override public void readFully(Buffer sink, long byteCount) throws EOFException {
    // public void com.android.okhttp.okio.Buffer.readFully(com.android.okhttp.okio.Buffer,long) throws java.io.EOFException
    var func_Buffer_readFully_2psb = cls_Buffer.readFully.overload('com.android.okhttp.okio.Buffer', 'long')
    console.log("func_Buffer_readFully_2psb=" + func_Buffer_readFully_2psb)
    if (func_Buffer_readFully_2psb) {
      func_Buffer_readFully_2psb.implementation = function (sink, byteCount) {
        var funcName = "okio.Buffer.readFully_2psb"
        var funcParaDict = {
          "sink": sink,
          "byteCount": byteCount,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var curBufStr = this.toString()
        console.log(funcName + " curBufStr=" + curBufStr)
        var head = this.head.value
        console.log(funcName + " head=" + head)
        var size = this.size.value
        console.log(funcName + " size=" + size)

        return this.readFully(sink, byteCount)
      }
    }

  }

  static TelephonyManager() {
    var clsName_TelephonyManager = "android.telephony.TelephonyManager"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_TelephonyManager)

    var cls_TelephonyManager = Java.use(clsName_TelephonyManager)
    console.log("cls_TelephonyManager=" + cls_TelephonyManager)
    
    // String getDeviceId()
    // public java.lang.String android.telephony.TelephonyManager.getDeviceId()
    var func_TelephonyManager_getDeviceId_0p = cls_TelephonyManager.getDeviceId.overload()
    console.log("func_TelephonyManager_getDeviceId_0p=" + func_TelephonyManager_getDeviceId_0p)
    if (func_TelephonyManager_getDeviceId_0p) {
      func_TelephonyManager_getDeviceId_0p.implementation = function () {
        var funcName = "TelephonyManager.getDeviceId_0p"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retDeviceId_0p = this.getDeviceId()
        console.log(funcName + " => retDeviceId_0p=" + retDeviceId_0p)
        return retDeviceId_0p
      }
    }

    // String getDeviceId(int slotIndex)
    // public java.lang.String android.telephony.TelephonyManager.getDeviceId(int)
    var func_TelephonyManager_getDeviceId_1ps = cls_TelephonyManager.getDeviceId.overload('int')
    console.log("func_TelephonyManager_getDeviceId_1ps=" + func_TelephonyManager_getDeviceId_1ps)
    if (func_TelephonyManager_getDeviceId_1ps) {
      func_TelephonyManager_getDeviceId_1ps.implementation = function (slotIndex) {
        var funcName = "TelephonyManager.getDeviceId_1ps"
        var funcParaDict = {
          "slotIndex": slotIndex,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retDeviceId_1ps = this.getDeviceId(slotIndex)
        console.log(funcName + " => retDeviceId_1ps=" + retDeviceId_1ps)
        return retDeviceId_1ps
      }
    }

    // String getImei(int slotIndex)
    // public java.lang.String android.telephony.TelephonyManager.getImei(int)
    var func_TelephonyManager_getImei_1ps = cls_TelephonyManager.getImei.overload('int')
    console.log("func_TelephonyManager_getImei_1ps=" + func_TelephonyManager_getImei_1ps)
    if (func_TelephonyManager_getImei_1ps) {
      func_TelephonyManager_getImei_1ps.implementation = function (slotIndex) {
        var funcName = "TelephonyManager.getImei(slotIndex)"
        var funcParaDict = {
          "slotIndex": slotIndex,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retImei_1ps = this.getImei(slotIndex)
        console.log(funcName + " => retImei_1ps=" + retImei_1ps)
        return retImei_1ps
      }
    }

    // String getImei()
    // public java.lang.String android.telephony.TelephonyManager.getImei()
    var func_TelephonyManager_getImei_0p = cls_TelephonyManager.getImei.overload()
    console.log("func_TelephonyManager_getImei_0p=" + func_TelephonyManager_getImei_0p)
    if (func_TelephonyManager_getImei_0p) {
      func_TelephonyManager_getImei_0p.implementation = function () {
        var funcName = "TelephonyManager.getImei()"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retImei_0p = this.getImei()
        console.log(funcName + " => retImei_0p=" + retImei_0p)
        return retImei_0p
      }
    }

    // public String getMeid()
    // public java.lang.String android.telephony.TelephonyManager.getMeid()
    var func_TelephonyManager_getMeid_0p = cls_TelephonyManager.getMeid.overload()
    console.log("func_TelephonyManager_getMeid_0p=" + func_TelephonyManager_getMeid_0p)
    if (func_TelephonyManager_getMeid_0p) {
      func_TelephonyManager_getMeid_0p.implementation = function () {
        var funcName = "TelephonyManager.getMeid()"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retMeid_0p = this.getMeid()
        console.log(funcName + " => retMeid_0p=" + retMeid_0p)
        return retMeid_0p
      }
    }

    // public String getMeid(int slotIndex)
    // public java.lang.String android.telephony.TelephonyManager.getMeid(int)
    var func_TelephonyManager_getMeid_1ps = cls_TelephonyManager.getMeid.overload('int')
    console.log("func_TelephonyManager_getMeid_1ps=" + func_TelephonyManager_getMeid_1ps)
    if (func_TelephonyManager_getMeid_1ps) {
      func_TelephonyManager_getMeid_1ps.implementation = function (slotIndex) {
        var funcName = "TelephonyManager.getMeid(slotIndex)"
        var funcParaDict = {
          "slotIndex": slotIndex,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retMeid_1ps = this.getMeid(slotIndex)
        console.log(funcName + " => retMeid_1ps=" + retMeid_1ps)
        return retMeid_1ps
      }
    }

    // public String getSimOperator()
    // public java.lang.String android.telephony.TelephonyManager.getSimOperator()
    var func_TelephonyManager_getSimOperator_0p = cls_TelephonyManager.getSimOperator.overload()
    console.log("func_TelephonyManager_getSimOperator_0p=" + func_TelephonyManager_getSimOperator_0p)
    if (func_TelephonyManager_getSimOperator_0p) {
      func_TelephonyManager_getSimOperator_0p.implementation = function () {
        var funcName = "TelephonyManager.getSimOperator()"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retSimOperator_0p = this.getSimOperator()
        console.log(funcName + " => retSimOperator_0p=" + retSimOperator_0p)
        return retSimOperator_0p
      }
    }

    // public String getSimSerialNumber()
    // public java.lang.String android.telephony.TelephonyManager.getSimSerialNumber()
    var func_TelephonyManager_getSimSerialNumber_0p = cls_TelephonyManager.getSimSerialNumber.overload()
    console.log("func_TelephonyManager_getSimSerialNumber_0p=" + func_TelephonyManager_getSimSerialNumber_0p)
    if (func_TelephonyManager_getSimSerialNumber_0p) {
      func_TelephonyManager_getSimSerialNumber_0p.implementation = function () {
        var funcName = "TelephonyManager.getSimSerialNumber()"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retSimSerialNumber_0p = this.getSimSerialNumber()
        console.log(funcName + " => retSimSerialNumber_0p=" + retSimSerialNumber_0p)
        return retSimSerialNumber_0p
      }
    }
    
    // public String getSubscriberId()
    // public java.lang.String android.telephony.TelephonyManager.getSubscriberId()
    var func_TelephonyManager_getSubscriberId_0p = cls_TelephonyManager.getSubscriberId.overload()
    console.log("func_TelephonyManager_getSubscriberId_0p=" + func_TelephonyManager_getSubscriberId_0p)
    if (func_TelephonyManager_getSubscriberId_0p) {
      func_TelephonyManager_getSubscriberId_0p.implementation = function () {
        var funcName = "TelephonyManager.getSubscriberId()"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retSubscriberId_0p = this.getSubscriberId()
        console.log(funcName + " => retSubscriberId_0p=" + retSubscriberId_0p)
        return retSubscriberId_0p
      }
    }
    
    // public String getSimOperatorName()
    // public java.lang.String android.telephony.TelephonyManager.getSimOperatorName()
    var func_TelephonyManager_getSimOperatorName_0p = cls_TelephonyManager.getSimOperatorName.overload()
    console.log("func_TelephonyManager_getSimOperatorName_0p=" + func_TelephonyManager_getSimOperatorName_0p)
    if (func_TelephonyManager_getSimOperatorName_0p) {
      func_TelephonyManager_getSimOperatorName_0p.implementation = function () {
        var funcName = "TelephonyManager.getSimOperatorName()"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retSimOperatorName_0p = this.getSimOperatorName()
        console.log(funcName + " => retSimOperatorName_0p=" + retSimOperatorName_0p)
        return retSimOperatorName_0p
      }
    }
    
    // public boolean isNetworkRoaming()
    // public boolean android.telephony.TelephonyManager.isNetworkRoaming()
    var func_TelephonyManager_isNetworkRoaming_0p = cls_TelephonyManager.isNetworkRoaming.overload()
    console.log("func_TelephonyManager_isNetworkRoaming_0p=" + func_TelephonyManager_isNetworkRoaming_0p)
    if (func_TelephonyManager_isNetworkRoaming_0p) {
      func_TelephonyManager_isNetworkRoaming_0p.implementation = function () {
        var funcName = "TelephonyManager.isNetworkRoaming()"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var isNetRoaming_0p = this.isNetworkRoaming()
        console.log(funcName + " => isNetRoaming_0p=" + isNetRoaming_0p)
        return isNetRoaming_0p
      }
    }
    
    // public String getGroupIdLevel1()
    // public java.lang.String android.telephony.TelephonyManager.getGroupIdLevel1()
    var func_TelephonyManager_getGroupIdLevel1_0p = cls_TelephonyManager.getGroupIdLevel1.overload()
    console.log("func_TelephonyManager_getGroupIdLevel1_0p=" + func_TelephonyManager_getGroupIdLevel1_0p)
    if (func_TelephonyManager_getGroupIdLevel1_0p) {
      func_TelephonyManager_getGroupIdLevel1_0p.implementation = function () {
        var funcName = "TelephonyManager.getGroupIdLevel1()"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var groupIdLevel1_0p = this.getGroupIdLevel1()
        console.log(funcName + " => groupIdLevel1_0p=" + groupIdLevel1_0p)
        return groupIdLevel1_0p
      }
    }

    // public int getSimCarrierId()
    // public int android.telephony.TelephonyManager.getSimCarrierId()
    var func_TelephonyManager_getSimCarrierId = cls_TelephonyManager.getSimCarrierId
    console.log("func_TelephonyManager_getSimCarrierId=" + func_TelephonyManager_getSimCarrierId)
    if (func_TelephonyManager_getSimCarrierId) {
      func_TelephonyManager_getSimCarrierId.implementation = function () {
        var funcName = "TelephonyManager.getSimCarrierId"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retSimCarrierId = this.getSimCarrierId()
        console.log(funcName + " => retSimCarrierId=" + retSimCarrierId)
        return retSimCarrierId
      }
    }

    // public boolean isVoiceCapable()
    // public boolean android.telephony.TelephonyManager.isVoiceCapable()
    var func_TelephonyManager_isVoiceCapable = cls_TelephonyManager.isVoiceCapable
    console.log("func_TelephonyManager_isVoiceCapable=" + func_TelephonyManager_isVoiceCapable)
    if (func_TelephonyManager_isVoiceCapable) {
      func_TelephonyManager_isVoiceCapable.implementation = function () {
        var funcName = "TelephonyManager.isVoiceCapable"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retIsVoiceCapable = this.isVoiceCapable()
        console.log(funcName + " => retIsVoiceCapable=" + retIsVoiceCapable)
        return retIsVoiceCapable
      }
    }

  }

  static ConnectivityManager() {
    var clsName_ConnectivityManager = "android.net.ConnectivityManager"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_ConnectivityManager)

    var cls_ConnectivityManager = Java.use(clsName_ConnectivityManager)
    console.log("cls_ConnectivityManager=" + cls_ConnectivityManager)
    
    // public NetworkInfo getActiveNetworkInfo()
    // 
    var func_ConnectivityManager_getActiveNetworkInfo = cls_ConnectivityManager.getActiveNetworkInfo
    console.log("func_ConnectivityManager_getActiveNetworkInfo=" + func_ConnectivityManager_getActiveNetworkInfo)
    if (func_ConnectivityManager_getActiveNetworkInfo) {
      func_ConnectivityManager_getActiveNetworkInfo.implementation = function () {
        var funcName = "ConnectivityManager.getActiveNetworkInfo"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retNetworkInfo = this.getActiveNetworkInfo()
        console.log(funcName + " => retNetworkInfo=" + retNetworkInfo)
        return retNetworkInfo
      }
    }

    // public Network getActiveNetwork()
    // 
    var func_ConnectivityManager_getActiveNetwork = cls_ConnectivityManager.getActiveNetwork
    console.log("func_ConnectivityManager_getActiveNetwork=" + func_ConnectivityManager_getActiveNetwork)
    if (func_ConnectivityManager_getActiveNetwork) {
      func_ConnectivityManager_getActiveNetwork.implementation = function () {
        var funcName = "ConnectivityManager.getActiveNetwork"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retNetwork = this.getActiveNetwork()
        console.log(funcName + " => retNetwork=" + retNetwork)
        return retNetwork
      }
    }

    // public NetworkCapabilities getNetworkCapabilities(Network network)
    // 
    var func_ConnectivityManager_getNetworkCapabilities = cls_ConnectivityManager.getNetworkCapabilities
    console.log("func_ConnectivityManager_getNetworkCapabilities=" + func_ConnectivityManager_getNetworkCapabilities)
    if (func_ConnectivityManager_getNetworkCapabilities) {
      func_ConnectivityManager_getNetworkCapabilities.implementation = function (network) {
        var funcName = "ConnectivityManager.getNetworkCapabilities"
        var funcParaDict = {
          "network": network
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retNetworkCapabilities = this.getNetworkCapabilities(network)
        console.log(funcName + " => retNetworkCapabilities=" + retNetworkCapabilities)
        return retNetworkCapabilities
      }
    }

  }

  static NetworkInfo() {
    var clsName_NetworkInfo = "android.net.NetworkInfo"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_NetworkInfo)

    var cls_NetworkInfo = Java.use(clsName_NetworkInfo)
    console.log("cls_NetworkInfo=" + cls_NetworkInfo)

    
    // public String getTypeName()
    // public java.lang.String android.net.NetworkInfo.getTypeName()
    var func_NetworkInfo_getTypeName = cls_NetworkInfo.getTypeName
    console.log("func_NetworkInfo_getTypeName=" + func_NetworkInfo_getTypeName)
    if (func_NetworkInfo_getTypeName) {
      func_NetworkInfo_getTypeName.implementation = function () {
        var funcName = "NetworkInfo.getTypeName"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retTypeName = this.getTypeName()
        console.log(funcName + " => retTypeName=" + retTypeName)
        return retTypeName
      }
    }

    // public String getSubtypeName()
    // public java.lang.String android.net.NetworkInfo.getSubtypeName()
    var func_NetworkInfo_getSubtypeName = cls_NetworkInfo.getSubtypeName
    console.log("func_NetworkInfo_getSubtypeName=" + func_NetworkInfo_getSubtypeName)
    if (func_NetworkInfo_getSubtypeName) {
      func_NetworkInfo_getSubtypeName.implementation = function () {
        var funcName = "NetworkInfo.getSubtypeName"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retSubtypeName = this.getSubtypeName()
        console.log(funcName + " => retSubtypeName=" + retSubtypeName)
        return retSubtypeName
      }
    }

    // public boolean isRoaming()
    // public boolean android.net.NetworkInfo.isRoaming()
    var func_NetworkInfo_isRoaming = cls_NetworkInfo.isRoaming
    console.log("func_NetworkInfo_isRoaming=" + func_NetworkInfo_isRoaming)
    if (func_NetworkInfo_isRoaming) {
      func_NetworkInfo_isRoaming.implementation = function () {
        var funcName = "NetworkInfo.isRoaming"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean = this.isRoaming()
        console.log(funcName + " => retBoolean=" + retBoolean)
        return retBoolean
      }
    }

    // public String getExtraInfo()
    // public java.lang.String android.net.NetworkInfo.getExtraInfo()
    var func_NetworkInfo_getExtraInfo = cls_NetworkInfo.getExtraInfo
    console.log("func_NetworkInfo_getExtraInfo=" + func_NetworkInfo_getExtraInfo)
    if (func_NetworkInfo_getExtraInfo) {
      func_NetworkInfo_getExtraInfo.implementation = function () {
        var funcName = "NetworkInfo.getExtraInfo"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retExtraInfo = this.getExtraInfo()
        console.log(funcName + " => retExtraInfo=" + retExtraInfo)
        return retExtraInfo
      }
    }
  
  }

  static SubscriptionManager() {
    var clsName_SubscriptionManager = "android.telephony.SubscriptionManager"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_SubscriptionManager)

    var cls_SubscriptionManager = Java.use(clsName_SubscriptionManager)
    console.log("cls_SubscriptionManager=" + cls_SubscriptionManager)

    
    // public List<SubscriptionInfo> getActiveSubscriptionInfoList()
    // public java.util.List android.telephony.SubscriptionManager.getActiveSubscriptionInfoList()
    var func_SubscriptionManager_getActiveSubscriptionInfoList = cls_SubscriptionManager.getActiveSubscriptionInfoList.overload()
    console.log("func_SubscriptionManager_getActiveSubscriptionInfoList=" + func_SubscriptionManager_getActiveSubscriptionInfoList)
    if (func_SubscriptionManager_getActiveSubscriptionInfoList) {
      func_SubscriptionManager_getActiveSubscriptionInfoList.implementation = function () {
        var funcName = "SubscriptionManager.getActiveSubscriptionInfoList"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retActiveSubscriptionInfoList = this.getActiveSubscriptionInfoList()
        console.log(funcName + " => retActiveSubscriptionInfoList=" + retActiveSubscriptionInfoList)
        return retActiveSubscriptionInfoList
      }
    }

    // public static int getDefaultVoiceSubscriptionId()
    // public static int android.telephony.SubscriptionManager.getDefaultVoiceSubscriptionId()
    var func_SubscriptionManager_getDefaultVoiceSubscriptionId = cls_SubscriptionManager.getDefaultVoiceSubscriptionId
    console.log("func_SubscriptionManager_getDefaultVoiceSubscriptionId=" + func_SubscriptionManager_getDefaultVoiceSubscriptionId)
    if (func_SubscriptionManager_getDefaultVoiceSubscriptionId) {
      func_SubscriptionManager_getDefaultVoiceSubscriptionId.implementation = function () {
        var funcName = "SubscriptionManager.getDefaultVoiceSubscriptionId"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retDefaultVoiceSubscriptionId = this.getDefaultVoiceSubscriptionId()
        console.log(funcName + " => retDefaultVoiceSubscriptionId=" + retDefaultVoiceSubscriptionId)
        return retDefaultVoiceSubscriptionId
      }
    }

    // public static int getDefaultDataSubscriptionId()
    // public static int android.telephony.SubscriptionManager.getDefaultDataSubscriptionId()
    var func_SubscriptionManager_getDefaultDataSubscriptionId = cls_SubscriptionManager.getDefaultDataSubscriptionId
    console.log("func_SubscriptionManager_getDefaultDataSubscriptionId=" + func_SubscriptionManager_getDefaultDataSubscriptionId)
    if (func_SubscriptionManager_getDefaultDataSubscriptionId) {
      func_SubscriptionManager_getDefaultDataSubscriptionId.implementation = function () {
        var funcName = "SubscriptionManager.getDefaultDataSubscriptionId"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retDefaultDataSubscriptionId = this.getDefaultDataSubscriptionId()
        console.log(funcName + " => retDefaultDataSubscriptionId=" + retDefaultDataSubscriptionId)
        return retDefaultDataSubscriptionId
      }
    }

    // public static int getDefaultSmsSubscriptionId()
    // public static int android.telephony.SubscriptionManager.getDefaultSmsSubscriptionId()
    var func_SubscriptionManager_getDefaultSmsSubscriptionId = cls_SubscriptionManager.getDefaultSmsSubscriptionId
    console.log("func_SubscriptionManager_getDefaultSmsSubscriptionId=" + func_SubscriptionManager_getDefaultSmsSubscriptionId)
    if (func_SubscriptionManager_getDefaultSmsSubscriptionId) {
      func_SubscriptionManager_getDefaultSmsSubscriptionId.implementation = function () {
        var funcName = "SubscriptionManager.getDefaultSmsSubscriptionId"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var retDefaultSmsSubscriptionId = this.getDefaultSmsSubscriptionId()
        console.log(funcName + " => retDefaultSmsSubscriptionId=" + retDefaultSmsSubscriptionId)
        return retDefaultSmsSubscriptionId
      }
    }

  }

  static SubscriptionInfo() {
    var clsName_SubscriptionInfo = "android.telephony.SubscriptionInfo"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_SubscriptionInfo)

    var cls_SubscriptionInfo = Java.use(clsName_SubscriptionInfo)
    console.log("cls_SubscriptionInfo=" + cls_SubscriptionInfo)

    
    // public int getSubscriptionId()
    // public int android.telephony.SubscriptionInfo.getSubscriptionId()
    var func_SubscriptionInfo_getSubscriptionId = cls_SubscriptionInfo.getSubscriptionId
    console.log("func_SubscriptionInfo_getSubscriptionId=" + func_SubscriptionInfo_getSubscriptionId)
    if (func_SubscriptionInfo_getSubscriptionId) {
      func_SubscriptionInfo_getSubscriptionId.implementation = function () {
        var funcName = "SubscriptionInfo.getSubscriptionId"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retSubscriptionId = this.getSubscriptionId()
        console.log(funcName + " => retSubscriptionId=" + retSubscriptionId)
        return retSubscriptionId
      }
    }
    
    // public CharSequence getCarrierName()
    // public java.lang.CharSequence android.telephony.SubscriptionInfo.getCarrierName()
    var func_SubscriptionInfo_getCarrierName = cls_SubscriptionInfo.getCarrierName
    console.log("func_SubscriptionInfo_getCarrierName=" + func_SubscriptionInfo_getCarrierName)
    if (func_SubscriptionInfo_getCarrierName) {
      func_SubscriptionInfo_getCarrierName.implementation = function () {
        var funcName = "SubscriptionInfo.getCarrierName"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retCarrierNameCharSeq = this.getCarrierName()
        console.log(funcName + " => retCarrierNameCharSeq=" + retCarrierNameCharSeq)
        return retCarrierNameCharSeq
      }
    }
    
    // public int getDataRoaming()
    // public int android.telephony.SubscriptionInfo.getDataRoaming()
    var func_SubscriptionInfo_getDataRoaming = cls_SubscriptionInfo.getDataRoaming
    console.log("func_SubscriptionInfo_getDataRoaming=" + func_SubscriptionInfo_getDataRoaming)
    if (func_SubscriptionInfo_getDataRoaming) {
      func_SubscriptionInfo_getDataRoaming.implementation = function () {
        var funcName = "SubscriptionInfo.getDataRoaming"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retDataRoaming = this.getDataRoaming()
        console.log(funcName + " => retDataRoaming=" + retDataRoaming)
        return retDataRoaming
      }
    }

  }

  static Boolean(callback_isShowLog=null) {
    var clsName_Boolean = "java.lang.Boolean"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Boolean)

    var cls_Boolean = Java.use(clsName_Boolean)
    console.log("cls_Boolean=" + cls_Boolean)

    
    // boolean booleanValue()
    // 
    var func_Boolean_booleanValue = cls_Boolean.booleanValue
    console.log("func_Boolean_booleanValue=" + func_Boolean_booleanValue)
    if (func_Boolean_booleanValue) {
      func_Boolean_booleanValue.implementation = function () {
        var funcName = "Boolean.booleanValue"
        var funcParaDict = {}
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)

        var isShowLog = true
        if (null != callback_isShowLog) {
          isShowLog = callback_isShowLog(funcCallAndStackStr)
        }

        if (isShowLog) {
          // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
          console.log(funcCallAndStackStr)
        }

        var retBoolean = this.booleanValue()
        if (isShowLog) {
          console.log(funcName + " => retBoolean=" + retBoolean)
        }
        return retBoolean
      }
    }

  }

  static TimeZone() {
    var clsName_TimeZone = "android.icu.util.TimeZone"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_TimeZone)

    var cls_TimeZone = Java.use(clsName_TimeZone)
    console.log("cls_TimeZone=" + cls_TimeZone)

    
    // public static TimeZone getDefault()
    // 
    var func_TimeZone_getDefault = cls_TimeZone.getDefault
    console.log("func_TimeZone_getDefault=" + func_TimeZone_getDefault)
    if (func_TimeZone_getDefault) {
      func_TimeZone_getDefault.implementation = function () {
        var funcName = "TimeZone.getDefault"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retDefault = this.getDefault()
        console.log(funcName + " => retDefault=" + retDefault)
        return retDefault
      }
    }

    // public String getID()
    // 
    var func_TimeZone_getID = cls_TimeZone.getID
    console.log("func_TimeZone_getID=" + func_TimeZone_getID)
    if (func_TimeZone_getID) {
      func_TimeZone_getID.implementation = function () {
        var funcName = "TimeZone.getID"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retID = this.getID()
        console.log(funcName + " => retID=" + retID)
        return retID
      }
    }
  }

  static ZipFile() {
    var clsName_ZipFile = "java.util.zip.ZipFile"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_ZipFile)

    var cls_ZipFile = Java.use(clsName_ZipFile)
    console.log("cls_ZipFile=" + cls_ZipFile)

    
    // public ZipFile(File file)
    // 
    var func_ZipFile_ctor_1pf = cls_ZipFile.$init.overload('java.io.File')
    console.log("func_ZipFile_ctor_1pf=" + func_ZipFile_ctor_1pf)
    if (func_ZipFile_ctor_1pf) {
      func_ZipFile_ctor_1pf.implementation = function (file) {
        var funcName = "ZipFile_1pf"
        var funcParaDict = {
          "file": file,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init(file)
        var newZipFile_1pf = this
        console.log(funcName + " => newZipFile_1pf=" + newZipFile_1pf)
        return
      }
    }

    // public ZipFile(String name)
    // 
    var func_ZipFile_ctor_1pn = cls_ZipFile.$init.overload('java.lang.String')
    console.log("func_ZipFile_ctor_1pn=" + func_ZipFile_ctor_1pn)
    if (func_ZipFile_ctor_1pn) {
      func_ZipFile_ctor_1pn.implementation = function (name) {
        var funcName = "ZipFile_1pn"
        var funcParaDict = {
          "name": name,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init(name)
        var newZipFile_1pn = this
        console.log(funcName + " => newZipFile_1pn=" + newZipFile_1pn)
        return
      }
    }

    // public Enumeration<?extends ZipEntry> entries()
    // public java.util.Enumeration java.util.zip.ZipFile.entries()
    var func_ZipFile_entries = cls_ZipFile.entries
    console.log("func_ZipFile_entries=" + func_ZipFile_entries)
    if (func_ZipFile_entries) {
      func_ZipFile_entries.implementation = function () {
        var funcName = "ZipFile.entries"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retExtends_ZipEntry_ = this.entries()
        console.log(funcName + " => retExtends_ZipEntry_=" + retExtends_ZipEntry_)
        return retExtends_ZipEntry_
      }
    }

    // public InputStream getInputStream(ZipEntry entry)
    // public java.io.InputStream java.util.zip.ZipFile.getInputStream(java.util.zip.ZipEntry) throws java.io.IOException
    var func_ZipFile_getInputStream = cls_ZipFile.getInputStream
    console.log("func_ZipFile_getInputStream=" + func_ZipFile_getInputStream)
    if (func_ZipFile_getInputStream) {
      func_ZipFile_getInputStream.implementation = function (entry) {
        var funcName = "ZipFile.getInputStream"
        var funcParaDict = {
          "entry": entry,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retInputStream = this.getInputStream(entry)
        console.log(funcName + " => retInputStream=" + retInputStream)
        return retInputStream
      }
    }
  }

  static MessageDigest() {
    var clsName_MessageDigest = "java.security.MessageDigest"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_MessageDigest)

    var cls_MessageDigest = Java.use(clsName_MessageDigest)
    console.log("cls_MessageDigest=" + cls_MessageDigest)

    
    // void update(byte[] input)
    // public void java.security.MessageDigest.update(byte[])
    var func_MessageDigest_update_1pi = cls_MessageDigest.update.overload('[B')
    console.log("func_MessageDigest_update_1pi=" + func_MessageDigest_update_1pi)
    if (func_MessageDigest_update_1pi) {
      func_MessageDigest_update_1pi.implementation = function (input) {
        var funcName = "MessageDigest.update_1pi"
        var funcParaDict = {
          "input": input,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.update(input)
      }
    }

    // void update(byte[] input, int offset, int len)
    // public void java.security.MessageDigest.update(byte[],int,int)
    var func_MessageDigest_update_3piol = cls_MessageDigest.update.overload('[B', 'int', 'int')
    console.log("func_MessageDigest_update_3piol=" + func_MessageDigest_update_3piol)
    if (func_MessageDigest_update_3piol) {
      func_MessageDigest_update_3piol.implementation = function (input, offset, len) {
        var funcName = "MessageDigest.update_3piol"
        var funcParaDict = {
          "input": input,
          "offset": offset,
          "len": len,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.update(input, offset, len)
      }
    }

    // byte[] digest()
    // 
    var func_MessageDigest_digest_0p = cls_MessageDigest.digest.overload()
    console.log("func_MessageDigest_digest_0p=" + func_MessageDigest_digest_0p)
    if (func_MessageDigest_digest_0p) {
      func_MessageDigest_digest_0p.implementation = function () {
        var funcName = "MessageDigest.digest_0p"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retByte___0p = this.digest()
        console.log(funcName + " => retByte___0p=" + retByte___0p)
        return retByte___0p
      }
    }
  }

  static Base64(callback_isShowLog=null) {
    var clsName_Base64 = "android.util.Base64"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Base64)

    var cls_Base64 = Java.use(clsName_Base64)
    console.log("cls_Base64=" + cls_Base64)

    // static String encodeToString(byte[] input, int offset, int len, int flags)
    // public static java.lang.String android.util.Base64.encodeToString(byte[],int,int,int)
    var func_Base64_encodeToString_4piolf = cls_Base64.encodeToString.overload('[B', 'int', 'int', 'int')
    console.log("func_Base64_encodeToString_4piolf=" + func_Base64_encodeToString_4piolf)
    if (func_Base64_encodeToString_4piolf) {
      func_Base64_encodeToString_4piolf.implementation = function (input, offset, len, flags) {
        var funcName = "Base64.encodeToString_4piolf"
        var funcParaDict = {
          "input": input,
          "offset": offset,
          "len": len,
          "flags": flags,
        }

        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        var retString_4piolf = this.encodeToString(input, offset, len, flags)
        if (isShowLog){
          console.log(funcName + " => retString_4piolf=" + retString_4piolf)
        }
        return retString_4piolf
      }
    }

    // static String encodeToString(byte[] input, int flags)
    // public static java.lang.String android.util.Base64.encodeToString(byte[],int)
    var func_Base64_encodeToString_2pif = cls_Base64.encodeToString.overload('[B', 'int')
    console.log("func_Base64_encodeToString_2pif=" + func_Base64_encodeToString_2pif)
    if (func_Base64_encodeToString_2pif) {
      func_Base64_encodeToString_2pif.implementation = function (input, flags) {
        var funcName = "Base64.encodeToString_2pif"
        var funcParaDict = {
          "input": input,
          "flags": flags,
        }

        var isShowLog = FridaAndroidUtil.showFuncCallAndStackLogIfNecessary(callback_isShowLog, funcName, funcParaDict)

        var retString_2pif = this.encodeToString(input, flags)
        if (isShowLog){
          console.log(funcName + " => retString_2pif=" + retString_2pif)
        }
        return retString_2pif
      }
    }

  }

  static ActivityManager() {
    var clsName_ActivityManager = "android.app.ActivityManager"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_ActivityManager)

    var cls_ActivityManager = Java.use(clsName_ActivityManager)
    console.log("cls_ActivityManager=" + cls_ActivityManager)

    // public ConfigurationInfo getDeviceConfigurationInfo()
    // public android.content.pm.ConfigurationInfo android.app.ActivityManager.getDeviceConfigurationInfo()
    var func_ActivityManager_getDeviceConfigurationInfo = cls_ActivityManager.getDeviceConfigurationInfo
    console.log("func_ActivityManager_getDeviceConfigurationInfo=" + func_ActivityManager_getDeviceConfigurationInfo)
    if (func_ActivityManager_getDeviceConfigurationInfo) {
      func_ActivityManager_getDeviceConfigurationInfo.implementation = function () {
        var funcName = "ActivityManager.getDeviceConfigurationInfo"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retDeviceConfigurationInfo = this.getDeviceConfigurationInfo()
        console.log(funcName + " => retDeviceConfigurationInfo=" + retDeviceConfigurationInfo)
        FridaAndroidUtil.printClass_ConfigurationInfo(retDeviceConfigurationInfo)
        return retDeviceConfigurationInfo
      }
    }

    // void getMemoryInfo(ActivityManager.MemoryInfo outInfo)
    // public void android.app.ActivityManager.getMemoryInfo(android.app.ActivityManager$MemoryInfo)
    var func_ActivityManager_getMemoryInfo = cls_ActivityManager.getMemoryInfo
    console.log("func_ActivityManager_getMemoryInfo=" + func_ActivityManager_getMemoryInfo)
    if (func_ActivityManager_getMemoryInfo) {
      func_ActivityManager_getMemoryInfo.implementation = function (outInfo) {
        var funcName = "ActivityManager.getMemoryInfo"
        var funcParaDict = {
          "outInfo": outInfo,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.getMemoryInfo(outInfo)
        FridaAndroidUtil.printClass_ActivityManagerMemoryInfo(outInfo, "After " + funcName)
        return 
      }
    }
    
    // boolean isLowRamDevice()
    // public boolean android.app.ActivityManager.isLowRamDevice()
    var func_ActivityManager_isLowRamDevice = cls_ActivityManager.isLowRamDevice
    console.log("func_ActivityManager_isLowRamDevice=" + func_ActivityManager_isLowRamDevice)
    if (func_ActivityManager_isLowRamDevice) {
      func_ActivityManager_isLowRamDevice.implementation = function () {
        var funcName = "ActivityManager.isLowRamDevice"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var isLowRamDev = this.isLowRamDevice()
        console.log(funcName + " => isLowRamDev=" + isLowRamDev)
        return isLowRamDev
      }
    }

  }

  static DisplayManager() {
    var clsName_DisplayManager = "android.hardware.display.DisplayManager"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_DisplayManager)

    var cls_DisplayManager = Java.use(clsName_DisplayManager)
    console.log("cls_DisplayManager=" + cls_DisplayManager)
    
    // public Display getDisplay(int displayId)
    // 
    var func_DisplayManager_getDisplay = cls_DisplayManager.getDisplay
    console.log("func_DisplayManager_getDisplay=" + func_DisplayManager_getDisplay)
    if (func_DisplayManager_getDisplay) {
      func_DisplayManager_getDisplay.implementation = function (displayId) {
        var funcName = "DisplayManager.getDisplay"
        var funcParaDict = {
          "displayId": displayId,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retDisplay = this.getDisplay(displayId)
        console.log(funcName + " => retDisplay=" + retDisplay)
        return retDisplay
      }
    }

    // public Point getStableDisplaySize()
    // 
    var func_DisplayManager_getStableDisplaySize = cls_DisplayManager.getStableDisplaySize
    console.log("func_DisplayManager_getStableDisplaySize=" + func_DisplayManager_getStableDisplaySize)
    if (func_DisplayManager_getStableDisplaySize) {
      func_DisplayManager_getStableDisplaySize.implementation = function () {
        var funcName = "DisplayManager.getStableDisplaySize"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retStableDisplaySize = this.getStableDisplaySize()
        console.log(funcName + " => retStableDisplaySize=" + retStableDisplaySize)
        return retStableDisplaySize
      }
    }
  }

  static Display() {
    var clsName_Display = "android.view.Display"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Display)

    var cls_Display = Java.use(clsName_Display)
    console.log("cls_Display=" + cls_Display)

    
    // void getRealMetrics(DisplayMetrics outMetrics)
    // 
    var func_Display_getRealMetrics = cls_Display.getRealMetrics
    console.log("func_Display_getRealMetrics=" + func_Display_getRealMetrics)
    if (func_Display_getRealMetrics) {
      func_Display_getRealMetrics.implementation = function (outMetrics) {
        var funcName = "Display.getRealMetrics"
        var funcParaDict = {
          "outMetrics": outMetrics,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.getRealMetrics(outMetrics)
        FridaAndroidUtil.printClass_DisplayMetrics(outMetrics, `After ${funcName}`)
        return
      }
    }
  }

  static DisplayMetrics() {
    var clsName_DisplayMetrics = "android.util.DisplayMetrics"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_DisplayMetrics)

    var cls_DisplayMetrics = Java.use(clsName_DisplayMetrics)
    console.log("cls_DisplayMetrics=" + cls_DisplayMetrics)

    // public DisplayMetrics()
    // 
    var func_DisplayMetrics_ctor = cls_DisplayMetrics.$init
    console.log("func_DisplayMetrics_ctor=" + func_DisplayMetrics_ctor)
    if (func_DisplayMetrics_ctor) {
      func_DisplayMetrics_ctor.implementation = function () {
        var funcName = "DisplayMetrics"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init()
        var newDisplayMetrics = this
        console.log(funcName + " => newDisplayMetrics=" + newDisplayMetrics)
        FridaAndroidUtil.printClass_DisplayMetrics(newDisplayMetrics, "After DisplayMetrics()")
        return
      }
    }
  }

  static Resources() {
    var clsName_Resources = "android.content.res.Resources"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Resources)

    var cls_Resources = Java.use(clsName_Resources)
    console.log("cls_Resources=" + cls_Resources)

    // public Configuration getConfiguration()
    // public android.content.res.Configuration android.content.res.Resources.getConfiguration()
    var func_Resources_getConfiguration = cls_Resources.getConfiguration
    console.log("func_Resources_getConfiguration=" + func_Resources_getConfiguration)
    if (func_Resources_getConfiguration) {
      func_Resources_getConfiguration.implementation = function () {
        var funcName = "Resources.getConfiguration"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retConfiguration = this.getConfiguration()
        console.log(funcName + " => retConfiguration=" + retConfiguration)
        FridaAndroidUtil.printClass_Configuration(retConfiguration, `After ${funcName}`)
        return retConfiguration
      }
    }
  }

  static AssetManager() {
    var clsName_AssetManager = "android.content.res.AssetManager"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_AssetManager)

    var cls_AssetManager = Java.use(clsName_AssetManager)
    console.log("cls_AssetManager=" + cls_AssetManager)

    // public String[] getLocales()
    // 
    var func_AssetManager_getLocales = cls_AssetManager.getLocales
    console.log("func_AssetManager_getLocales=" + func_AssetManager_getLocales)
    if (func_AssetManager_getLocales) {
      func_AssetManager_getLocales.implementation = function () {
        var funcName = "AssetManager.getLocales"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retLocales = this.getLocales()
        console.log(funcName + " => retLocales=" + retLocales)
        return retLocales
      }
    }
  }

  static EGLDisplay() {
    var clsName_EGLDisplay = "android.opengl.EGLDisplay"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_EGLDisplay)

    var cls_EGLDisplay = Java.use(clsName_EGLDisplay)
    console.log("cls_EGLDisplay=" + cls_EGLDisplay)
  }

  static EGL_EGLDisplay() {
    var clsName_EGL_EGLDisplay = "javax.microedition.khronos.egl.EGLDisplay"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_EGL_EGLDisplay)

    var cls_EGL_EGLDisplay = Java.use(clsName_EGL_EGLDisplay)
    console.log("cls_EGL_EGLDisplay=" + cls_EGL_EGLDisplay)
  }

  // static EGL_EGL10() {
  //   var clsName_EGL_EGL10 = "javax.microedition.khronos.egl.EGL10"
  //   // FridaAndroidUtil.printClassAllMethodsFields(clsName_EGL_EGL10)

  //   var cls_EGL_EGL10 = Java.use(clsName_EGL_EGL10)
  //   console.log("cls_EGL_EGL10=" + cls_EGL_EGL10)
  // }

  static EGL10() {
    var clsName_EGL10 = "javax.microedition.khronos.egl.EGL10"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_EGL10)

    var cls_EGL10 = Java.use(clsName_EGL10)
    console.log("cls_EGL10=" + cls_EGL10)

    // abstract EGLDisplay eglGetDisplay(Object native_display)
    // public abstract javax.microedition.khronos.egl.EGLDisplay javax.microedition.khronos.egl.EGL10.eglGetDisplay(java.lang.Object)
    var func_EGL10_eglGetDisplay = cls_EGL10.eglGetDisplay
    console.log("func_EGL10_eglGetDisplay=" + func_EGL10_eglGetDisplay)
    if (func_EGL10_eglGetDisplay) {
      func_EGL10_eglGetDisplay.implementation = function (native_display) {
        var funcName = "EGL10.eglGetDisplay"
        var funcParaDict = {
          "native_display": native_display,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retEGLDisplay = this.eglGetDisplay(native_display)
        console.log(funcName + " => retEGLDisplay=" + retEGLDisplay)
        return retEGLDisplay
      }
    }

    // abstract boolean eglGetConfigs(EGLDisplay display, EGLConfig[] configs, int config_size, int[] num_config)
    // public abstract boolean javax.microedition.khronos.egl.EGL10.eglGetConfigs(javax.microedition.khronos.egl.EGLDisplay,javax.microedition.khronos.egl.EGLConfig[],int,int[])
    var func_EGL10_eglGetConfigs = cls_EGL10.eglGetConfigs
    console.log("func_EGL10_eglGetConfigs=" + func_EGL10_eglGetConfigs)
    if (func_EGL10_eglGetConfigs) {
      func_EGL10_eglGetConfigs.implementation = function (display, configs, config_size, num_config) {
        var funcName = "EGL10.eglGetConfigs"
        var funcParaDict = {
          "display": display,
          "configs": configs,
          "config_size": config_size,
          "num_config": num_config,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean = this.eglGetConfigs(display, configs, config_size, num_config)
        console.log(funcName + " => retBoolean=" + retBoolean)
        return retBoolean
      }
    }

    // abstract boolean eglGetConfigAttrib(EGLDisplay display, EGLConfig config, int attribute, int[] value)
    // public abstract boolean javax.microedition.khronos.egl.EGL10.eglGetConfigAttrib(javax.microedition.khronos.egl.EGLDisplay,javax.microedition.khronos.egl.EGLConfig,int,int[])
    var func_EGL10_eglGetConfigAttrib = cls_EGL10.eglGetConfigAttrib
    console.log("func_EGL10_eglGetConfigAttrib=" + func_EGL10_eglGetConfigAttrib)
    if (func_EGL10_eglGetConfigAttrib) {
      func_EGL10_eglGetConfigAttrib.implementation = function (display, config, attribute, value) {
        var funcName = "EGL10.eglGetConfigAttrib"
        var funcParaDict = {
          "display": display,
          "config": config,
          "attribute": attribute,
          "value": value,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean = this.eglGetConfigAttrib(display, config, attribute, value)
        console.log(funcName + " => retBoolean=" + retBoolean)
        return retBoolean
      }
    }

    // abstract boolean eglTerminate(EGLDisplay display)
    // public abstract boolean javax.microedition.khronos.egl.EGL10.eglTerminate(javax.microedition.khronos.egl.EGLDisplay)
    var func_EGL10_eglTerminate = cls_EGL10.eglTerminate
    console.log("func_EGL10_eglTerminate=" + func_EGL10_eglTerminate)
    if (func_EGL10_eglTerminate) {
      func_EGL10_eglTerminate.implementation = function (display) {
        var funcName = "EGL10.eglTerminate"
        var funcParaDict = {
          "display": display,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean = this.eglTerminate(display)
        console.log(funcName + " => retBoolean=" + retBoolean)
        return retBoolean
      }
    }
  }

  static EGLContext() {
    var clsName_EGLContext = "javax.microedition.khronos.egl.EGLContext"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_EGLContext)

    var cls_EGLContext = Java.use(clsName_EGLContext)
    console.log("cls_EGLContext=" + cls_EGLContext)

    
    // public EGLContext()
    // 
    var func_EGLContext_ctor = cls_EGLContext.$init
    console.log("func_EGLContext_ctor=" + func_EGLContext_ctor)
    if (func_EGLContext_ctor) {
      func_EGLContext_ctor.implementation = function () {
        var funcName = "EGLContext"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init()
        var newEGLContext = this
        console.log(funcName + " => newEGLContext=" + newEGLContext)
        return
      }
    }

    // static EGL getEGL()
    // public static javax.microedition.khronos.egl.EGL javax.microedition.khronos.egl.EGLContext.getEGL()
    var func_EGLContext_getEGL = cls_EGLContext.getEGL
    console.log("func_EGLContext_getEGL=" + func_EGLContext_getEGL)
    if (func_EGLContext_getEGL) {
      func_EGLContext_getEGL.implementation = function () {
        var funcName = "EGLContext.getEGL"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retEGL = this.getEGL()
        var clsName = FridaAndroidUtil.getJavaClassName(retEGL)
        console.log(funcName + " => retEGL=" + retEGL + ", clsName=" + clsName)

        return retEGL
      }
    }

    // abstract GL getGL()
    // public abstract javax.microedition.khronos.opengles.GL javax.microedition.khronos.egl.EGLContext.getGL()
    var func_EGLContext_getGL = cls_EGLContext.getGL
    console.log("func_EGLContext_getGL=" + func_EGLContext_getGL)
    if (func_EGLContext_getGL) {
      func_EGLContext_getGL.implementation = function () {
        var funcName = "EGLContext.getGL"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retGL = this.getGL()
        console.log(funcName + " => retGL=" + retGL)
        return retGL
      }
    }
  }

  static Runtime() {
    var clsName_Runtime = "java.lang.Runtime"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Runtime)

    var cls_Runtime = Java.use(clsName_Runtime)
    console.log("cls_Runtime=" + cls_Runtime)

    // public int availableProcessors()
    // public int java.lang.Runtime.availableProcessors()
    var func_Runtime_availableProcessors = cls_Runtime.availableProcessors
    console.log("func_Runtime_availableProcessors=" + func_Runtime_availableProcessors)
    if (func_Runtime_availableProcessors) {
      func_Runtime_availableProcessors.implementation = function () {
        var funcName = "Runtime.availableProcessors"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var availableProcessors = this.availableProcessors()
        console.log(funcName + " => availableProcessors=" + availableProcessors)
        return availableProcessors
      }
    }
  }

  static KeyguardManager() {
    var clsName_KeyguardManager = "android.app.KeyguardManager"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_KeyguardManager)

    var cls_KeyguardManager = Java.use(clsName_KeyguardManager)
    console.log("cls_KeyguardManager=" + cls_KeyguardManager)

    
    // public boolean isDeviceSecure()
    // public boolean android.app.KeyguardManager.isDeviceSecure()
    var func_KeyguardManager_isDeviceSecure = cls_KeyguardManager.isDeviceSecure.overload()
    console.log("func_KeyguardManager_isDeviceSecure=" + func_KeyguardManager_isDeviceSecure)
    if (func_KeyguardManager_isDeviceSecure) {
      func_KeyguardManager_isDeviceSecure.implementation = function () {
        var funcName = "KeyguardManager.isDeviceSecure"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean = this.isDeviceSecure()
        console.log(funcName + " => retBoolean=" + retBoolean)
        return retBoolean
      }
    }
  }

  static SystemProperties() {
    var clsName_SystemProperties = "android.os.SystemProperties"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_SystemProperties)

    var cls_SystemProperties = Java.use(clsName_SystemProperties)
    console.log("cls_SystemProperties=" + cls_SystemProperties)

    
    // public static String get(String key)
    // public static java.lang.String android.os.SystemProperties.get(java.lang.String)
    var func_SystemProperties_get_1pk = cls_SystemProperties.get.overload('java.lang.String')
    console.log("func_SystemProperties_get_1pk=" + func_SystemProperties_get_1pk)
    if (func_SystemProperties_get_1pk) {
      func_SystemProperties_get_1pk.implementation = function (key) {
        var funcName = "SystemProperties.get(key)"
        var funcParaDict = {
          "key": key,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retStr_1pk = this.get(key)
        console.log(funcName + " => retStr_1pk=" + retStr_1pk)
        return retStr_1pk
      }
    }

    // public static String get(String key, String def)
    // public static java.lang.String android.os.SystemProperties.get(java.lang.String,java.lang.String)
    var func_SystemProperties_get_2pkd = cls_SystemProperties.get.overload('java.lang.String', 'java.lang.String')
    console.log("func_SystemProperties_get_2pkd=" + func_SystemProperties_get_2pkd)
    if (func_SystemProperties_get_2pkd) {
      func_SystemProperties_get_2pkd.implementation = function (key, def) {
        var funcName = "SystemProperties.get(key,def)"
        var funcParaDict = {
          "key": key,
          "def": def,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retStr_2pkd = this.get(key, def)
        console.log(funcName + " => retStr_2pkd=" + retStr_2pkd)
        return retStr_2pkd
      }
    }
  }

  static UserManager() {
    var clsName_UserManager = "android.os.UserManager"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_UserManager)

    var cls_UserManager = Java.use(clsName_UserManager)
    console.log("cls_UserManager=" + cls_UserManager)

    const curLogFunc = FridaAndroidUtil.printFunctionCallAndStack
    // const curLogFunc = FridaAndroidUtil.printFunctionCallStr

    // 
    // public int android.os.UserManager.getUserSerialNumber(int)
    var func_getUserSerialNumber = cls_UserManager.getUserSerialNumber
    console.log("func_getUserSerialNumber=" + func_getUserSerialNumber)
    if (func_getUserSerialNumber) {
      func_getUserSerialNumber.implementation = function (user) {
        var funcName = "UserManager.getUserSerialNumber(user)"
        var funcParaDict = {
          "user": user,
        }
        curLogFunc(funcName, funcParaDict)

        var retUserSerNr = this.getUserSerialNumber(user)
        console.log(funcName + " => retUserSerNr=" + retUserSerNr)
        return retUserSerNr
      }
    }
    
    // public boolean isUserUnlocked()
    // public boolean android.os.UserManager.isUserUnlocked()
    var func_UserManager_isUserUnlocked = cls_UserManager.isUserUnlocked.overload()
    console.log("func_UserManager_isUserUnlocked=" + func_UserManager_isUserUnlocked)
    if (func_UserManager_isUserUnlocked) {
      func_UserManager_isUserUnlocked.implementation = function() {
        var funcName = "UserManager.isUserUnlocked"
        var funcParaDict = {}
        curLogFunc(funcName, funcParaDict)

        var retIsUserUnlocked = this.isUserUnlocked()
        console.log(funcName + " => retIsUserUnlocked=" + retIsUserUnlocked)
        return retIsUserUnlocked
      }
    }

  }

  static StringBuilder(callback_isShowLog=null) {
    var clsName_StringBuilder = "java.lang.StringBuilder"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_StringBuilder)

    var cls_StringBuilder = Java.use(clsName_StringBuilder)
    console.log("cls_StringBuilder=" + cls_StringBuilder)

    // // public String toString()
    // // public java.lang.String java.lang.StringBuilder.toString()
    // var func_StringBuilder_toString = cls_StringBuilder.toString
    // console.log("func_StringBuilder_toString=" + func_StringBuilder_toString)
    // if (func_StringBuilder_toString) {
    //   func_StringBuilder_toString.implementation = function () {
    //     var funcName = "StringBuilder.toString"
    //     var funcParaDict = {}

    //     var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)

    //     var isShowLog = true
    //     if (null != callback_isShowLog) {
    //       isShowLog = callback_isShowLog(funcCallAndStackStr)
    //     }

    //     // if (isShowLog) {
    //     //   console.log(funcCallAndStackStr)
    //     // }

    //     var retString = this.toString()

    //     if (isShowLog) {
    //       console.log(funcName + " => retString=" + retString)
    //     }

    //     return retString
    //   }
    // }

    // public StringBuilder append(String str)
    // public java.lang.AbstractStringBuilder java.lang.StringBuilder.append(java.lang.String)
    var func_StringBuilder_append_1ps = cls_StringBuilder.append.overload('java.lang.String')
    console.log("func_StringBuilder_append_1ps=" + func_StringBuilder_append_1ps)
    if (func_StringBuilder_append_1ps) {
      func_StringBuilder_append_1ps.implementation = function (str) {
        var funcName = "StringBuilder.append(str)"
        var funcParaDict = {
          "str": str,
        }
        // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)

        var isShowLog = true
        if (null != callback_isShowLog) {
          isShowLog = callback_isShowLog(funcCallAndStackStr)
        }

        if (isShowLog) {
          console.log(funcCallAndStackStr)
        }

        var retStringBuilder_1ps = this.append(str)

        if (isShowLog) {
          console.log(funcName + " => retStringBuilder_1ps=" + retStringBuilder_1ps)
        }

        return retStringBuilder_1ps
      }
    }

  }

  static ArrayBlockingQueue() {
    var clsName_ArrayBlockingQueue = "java.util.concurrent.ArrayBlockingQueue"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_ArrayBlockingQueue)

    var cls_ArrayBlockingQueue = Java.use(clsName_ArrayBlockingQueue)
    console.log("cls_ArrayBlockingQueue=" + cls_ArrayBlockingQueue)

    // public ArrayBlockingQueue(int capacity)
    // 
    var func_ArrayBlockingQueue_ctor_1pc = cls_ArrayBlockingQueue.$init.overload('int')
    console.log("func_ArrayBlockingQueue_ctor_1pc=" + func_ArrayBlockingQueue_ctor_1pc)
    if (func_ArrayBlockingQueue_ctor_1pc) {
      func_ArrayBlockingQueue_ctor_1pc.implementation = function (capacity) {
        var funcName = "ArrayBlockingQueue_1pc"
        var funcParaDict = {
          "capacity": capacity,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init(capacity)
        var newArrayBlockingQueue_1pc = this
        console.log(funcName + " => newArrayBlockingQueue_1pc=" + newArrayBlockingQueue_1pc)
        return
      }
    }

    // public boolean offer(E e)
    // public boolean java.util.concurrent.ArrayBlockingQueue.offer(java.lang.Object)
    var func_ArrayBlockingQueue_offer_1pe = cls_ArrayBlockingQueue.offer.overload('java.lang.Object')
    console.log("func_ArrayBlockingQueue_offer_1pe=" + func_ArrayBlockingQueue_offer_1pe)
    if (func_ArrayBlockingQueue_offer_1pe) {
      func_ArrayBlockingQueue_offer_1pe.implementation = function (e) {
        var funcName = "ArrayBlockingQueue.offer_1pe"
        var funcParaDict = {
          "e": e,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean_1pe = this.offer(e)
        console.log(funcName + " => retBoolean_1pe=" + retBoolean_1pe)
        return retBoolean_1pe
      }
    }

    // public E poll()
    // public java.lang.Object java.util.concurrent.ArrayBlockingQueue.poll()
    var func_ArrayBlockingQueue_poll_0p = cls_ArrayBlockingQueue.poll.overload()
    console.log("func_ArrayBlockingQueue_poll_0p=" + func_ArrayBlockingQueue_poll_0p)
    if (func_ArrayBlockingQueue_poll_0p) {
      func_ArrayBlockingQueue_poll_0p.implementation = function () {
        var funcName = "ArrayBlockingQueue.poll_0p"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retE_0p = this.poll()
        console.log(funcName + " => retE_0p=" + retE_0p)
        return retE_0p
      }
    }
  }

  static Parcel(callback_isShowLog=null) {
    var clsName_Parcel = "android.os.Parcel"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_Parcel)

    var cls_Parcel = Java.use(clsName_Parcel)
    console.log("cls_Parcel=" + cls_Parcel)

    // static Parcel obtain()
    // public static android.os.Parcel android.os.Parcel.obtain()
    var func_Parcel_obtain = cls_Parcel.obtain.overload()
    console.log("func_Parcel_obtain=" + func_Parcel_obtain)
    if (func_Parcel_obtain) {
      func_Parcel_obtain.implementation = function () {
        var funcName = "Parcel.obtain"
        var funcParaDict = {}
        // var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallStr(funcName, funcParaDict)

        var isShowLog = true
        if (null != callback_isShowLog) {
          isShowLog = callback_isShowLog(funcCallAndStackStr)
        }

        if (isShowLog) {
          console.log(funcCallAndStackStr)
        }

        var retParcel = this.obtain()

        if (isShowLog) {
          console.log(funcName + " => retParcel=" + retParcel)
        }

        return retParcel
      }
    }

    // byte[] createByteArray()
    // public final byte[] android.os.Parcel.createByteArray()
    var func_Parcel_createByteArray = cls_Parcel.createByteArray
    console.log("func_Parcel_createByteArray=" + func_Parcel_createByteArray)
    if (func_Parcel_createByteArray) {
      func_Parcel_createByteArray.implementation = function () {
        var funcName = "Parcel.createByteArray"
        var funcParaDict = {}
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)

        var isShowLog = true
        if (null != callback_isShowLog) {
          isShowLog = callback_isShowLog(funcCallAndStackStr)
        }

        if (isShowLog) {
          console.log(funcCallAndStackStr)
        }

        var retByte__ = this.createByteArray()

        if (isShowLog) {
          console.log(funcName + " => retByte__=" + retByte__)
        }

        return retByte__
      }
    }

    // void writeMap(Map<K, V> val)
    // public final void android.os.Parcel.writeMap(java.util.Map)
    var func_Parcel_writeMap = cls_Parcel.writeMap
    console.log("func_Parcel_writeMap=" + func_Parcel_writeMap)
    if (func_Parcel_writeMap) {
      func_Parcel_writeMap.implementation = function (val) {
        var funcName = "Parcel.writeMap"
        var funcParaDict = {
          "val": val,
        }
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)

        var isShowLog = true
        if (null != callback_isShowLog) {
          isShowLog = callback_isShowLog(funcCallAndStackStr)
        }

        if (isShowLog) {
          console.log(funcCallAndStackStr)
        }

        this.writeMap(val)
        return 
      }
    }

    // void writeInterfaceToken(String interfaceName)
    // public final void android.os.Parcel.writeInterfaceToken(java.lang.String)
    var func_Parcel_writeInterfaceToken = cls_Parcel.writeInterfaceToken
    console.log("func_Parcel_writeInterfaceToken=" + func_Parcel_writeInterfaceToken)
    if (func_Parcel_writeInterfaceToken) {
      func_Parcel_writeInterfaceToken.implementation = function (interfaceName) {
        var funcName = "Parcel.writeInterfaceToken"
        var funcParaDict = {
          "interfaceName": interfaceName,
        }
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)

        var isShowLog = true
        if (null != callback_isShowLog) {
          isShowLog = callback_isShowLog(funcCallAndStackStr)
        }

        if (isShowLog) {
          console.log(funcCallAndStackStr)
        }

        this.writeInterfaceToken(interfaceName)
        return 
      }
    }

    // void readException()
    // public final void android.os.Parcel.readException()
    var func_Parcel_readException_0p = cls_Parcel.readException.overload()
    console.log("func_Parcel_readException_0p=" + func_Parcel_readException_0p)
    if (func_Parcel_readException_0p) {
      func_Parcel_readException_0p.implementation = function () {
        var funcName = "Parcel.readException_0p"
        var funcParaDict = {}
        // var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallStr(funcName, funcParaDict)

        var isShowLog = true
        if (null != callback_isShowLog) {
          isShowLog = callback_isShowLog(funcCallAndStackStr)
        }

        if (isShowLog) {
          console.log(funcCallAndStackStr)
        }

        return this.readException()        
      }
    }

    // void writeParcelable(Parcelable p, int parcelableFlags)
    // public final void android.os.Parcel.writeParcelable(android.os.Parcelable,int)
    var func_Parcel_writeParcelable = cls_Parcel.writeParcelable
    console.log("func_Parcel_writeParcelable=" + func_Parcel_writeParcelable)
    if (func_Parcel_writeParcelable) {
      func_Parcel_writeParcelable.implementation = function (p, parcelableFlags) {
        var funcName = "Parcel.writeParcelable"
        var funcParaDict = {
          "p": p,
          "parcelableFlags": parcelableFlags,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)

        var isShowLog = true
        if (null != callback_isShowLog) {
          isShowLog = callback_isShowLog(funcCallAndStackStr)
        }

        if (isShowLog) {
          console.log(funcCallAndStackStr)
        }

        return this.writeParcelable(p, parcelableFlags)
      }
    }

    // IBinder readStrongBinder()
    // public final android.os.IBinder android.os.Parcel.readStrongBinder()
    var func_Parcel_readStrongBinder = cls_Parcel.readStrongBinder
    console.log("func_Parcel_readStrongBinder=" + func_Parcel_readStrongBinder)
    if (func_Parcel_readStrongBinder) {
      func_Parcel_readStrongBinder.implementation = function () {
        var funcName = "Parcel.readStrongBinder"
        var funcParaDict = {}
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)

        var isShowLog = true
        if (null != callback_isShowLog) {
          isShowLog = callback_isShowLog(funcCallAndStackStr)
        }

        if (isShowLog) {
          console.log(funcCallAndStackStr)
        }

        var retIBinder = this.readStrongBinder()

        if (isShowLog) {
          var binderInterfaceDescriptor = retIBinder.getInterfaceDescriptor()
          console.log(funcName + " => retIBinder=" + FridaAndroidUtil.valueToNameStr(retIBinder) + ", binderInterfaceDescriptor=" + binderInterfaceDescriptor)
        }

        return retIBinder
      }
    }

  }

  static BinderProxy(callback_isShowLog=null) {
    var clsName_BinderProxy = "android.os.BinderProxy"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_BinderProxy)

    var cls_BinderProxy = Java.use(clsName_BinderProxy)
    console.log("cls_BinderProxy=" + cls_BinderProxy)

    // public boolean transact(int code, Parcel data, Parcel reply, int flags) throws RemoteException
    // public boolean android.os.BinderProxy.transact(int,android.os.Parcel,android.os.Parcel,int) throws android.os.RemoteException
    var func_BinderProxy_transact = cls_BinderProxy.transact
    console.log("func_BinderProxy_transact=" + func_BinderProxy_transact)
    if (func_BinderProxy_transact) {
      func_BinderProxy_transact.implementation = function (code, data, reply, flags) {
        var funcName = "BinderProxy.transact"
        var funcParaDict = {
          "code": code,
          "data": data,
          "reply": reply,
          "flags": flags,
        }

        // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        var isShowLog = true
        if (null != callback_isShowLog) {
          isShowLog = callback_isShowLog(funcCallAndStackStr)
        }
        if (isShowLog) {
          console.log(funcCallAndStackStr)
          console.log(funcName + "data=" + FridaAndroidUtil.printClass_Parcel(data) + ", reply=" + FridaAndroidUtil.printClass_Parcel(reply))
        }

        var retBoolean = this.transact(code, data, reply, flags)

        if (isShowLog) {
          console.log(funcName + " => retBoolean=" + retBoolean)
        }

        return retBoolean
      }
    }

  }

  static FileInputStream() {
    var clsName_FileInputStream = "java.io.FileInputStream"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_FileInputStream)

    var cls_FileInputStream = Java.use(clsName_FileInputStream)
    console.log("cls_FileInputStream=" + cls_FileInputStream)

    // public FileInputStream(File file) throws FileNotFoundException
    // 
    var func_FileInputStream_ctor_1pf = cls_FileInputStream.$init.overload('java.io.File')
    console.log("func_FileInputStream_ctor_1pf=" + func_FileInputStream_ctor_1pf)
    if (func_FileInputStream_ctor_1pf) {
      func_FileInputStream_ctor_1pf.implementation = function (file) {
        var funcName = "FileInputStream_1pf"
        var funcParaDict = {
          "file": file,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init(file)
        var newFileInputStream_1pf = this
        console.log(funcName + " => newFileInputStream_1pf=" + newFileInputStream_1pf)
        return
      }
    }

    // public FileInputStream(FileDescriptor fdObj) throws SecurityException
    // 
    var func_FileInputStream_ctor_1pf = cls_FileInputStream.$init.overload('java.io.FileDescriptor')
    console.log("func_FileInputStream_ctor_1pf=" + func_FileInputStream_ctor_1pf)
    if (func_FileInputStream_ctor_1pf) {
      func_FileInputStream_ctor_1pf.implementation = function (fdObj) {
        var funcName = "FileInputStream_1pf"
        var funcParaDict = {
          "fdObj": fdObj,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init(fdObj)
        var newFileInputStream_1pf = this
        console.log(funcName + " => newFileInputStream_1pf=" + newFileInputStream_1pf)
        return
      }
    }

    // public FileInputStream(String name) throws FileNotFoundException
    // 
    var func_FileInputStream_ctor_1pn = cls_FileInputStream.$init.overload('java.lang.String')
    console.log("func_FileInputStream_ctor_1pn=" + func_FileInputStream_ctor_1pn)
    if (func_FileInputStream_ctor_1pn) {
      func_FileInputStream_ctor_1pn.implementation = function (name) {
        var funcName = "FileInputStream_1pn"
        var funcParaDict = {
          "name": name,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init(name)
        var newFileInputStream_1pn = this
        console.log(funcName + " => newFileInputStream_1pn=" + newFileInputStream_1pn)
        return
      }
    }

    // public FileChannel getChannel()
    // 
    var func_FileInputStream_getChannel = cls_FileInputStream.getChannel
    console.log("func_FileInputStream_getChannel=" + func_FileInputStream_getChannel)
    if (func_FileInputStream_getChannel) {
      func_FileInputStream_getChannel.implementation = function () {
        var funcName = "FileInputStream.getChannel"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retChannel = this.getChannel()
        console.log(funcName + " => retChannel=" + retChannel)
        return retChannel
      }
    }
  }

  static LinkedBlockingQueue(callback_isShowLog=null) {
    var clsName_LinkedBlockingQueue = "java.util.concurrent.LinkedBlockingQueue"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_LinkedBlockingQueue)

    var cls_LinkedBlockingQueue = Java.use(clsName_LinkedBlockingQueue)
    console.log("cls_LinkedBlockingQueue=" + cls_LinkedBlockingQueue)

    
    // public LinkedBlockingQueue()
    // 
    var func_LinkedBlockingQueue_ctor_0p = cls_LinkedBlockingQueue.$init.overload()
    console.log("func_LinkedBlockingQueue_ctor_0p=" + func_LinkedBlockingQueue_ctor_0p)
    if (func_LinkedBlockingQueue_ctor_0p) {
      func_LinkedBlockingQueue_ctor_0p.implementation = function () {
        var funcName = "LinkedBlockingQueue_0p"
        var funcParaDict = {}
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        this.$init()
        var newLinkedBlockingQueue_0p = this
        var isShowLog = FridaAndroidUtil.showLogIfNecessary(callback_isShowLog, `${funcCallAndStackStr}\n${funcName} => newLinkedBlockingQueue_0p=${newLinkedBlockingQueue_0p}`, false)
        return
      }
    }

    // boolean offer(E e)
    // public boolean java.util.concurrent.LinkedBlockingQueue.offer(java.lang.Object)
    var func_LinkedBlockingQueue_offer_1pe = cls_LinkedBlockingQueue.offer.overload("java.lang.Object")
    console.log("func_LinkedBlockingQueue_offer_1pe=" + func_LinkedBlockingQueue_offer_1pe)
    if (func_LinkedBlockingQueue_offer_1pe) {
      func_LinkedBlockingQueue_offer_1pe.implementation = function (e) {
        var funcName = "LinkedBlockingQueue.offer_1pe"
        var funcParaDict = {
          "e": e,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean_1pe = this.offer(e)
        console.log(funcName + " => retBoolean_1pe=" + retBoolean_1pe)
        return retBoolean_1pe
      }
    }

    // boolean offer(E e, long timeout, TimeUnit unit)
    // public boolean java.util.concurrent.LinkedBlockingQueue.offer(java.lang.Object,long,java.util.concurrent.TimeUnit) throws java.lang.InterruptedException
    var func_LinkedBlockingQueue_offer_3petu = cls_LinkedBlockingQueue.offer.overload("java.lang.Object", "long", "java.util.concurrent.TimeUnit")
    console.log("func_LinkedBlockingQueue_offer_3petu=" + func_LinkedBlockingQueue_offer_3petu)
    if (func_LinkedBlockingQueue_offer_3petu) {
      func_LinkedBlockingQueue_offer_3petu.implementation = function (e, timeout, unit) {
        var funcName = "LinkedBlockingQueue.offer_3petu"
        var funcParaDict = {
          "e": e,
          "timeout": timeout,
          "unit": unit,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean_3petu = this.offer(e, timeout, unit)
        console.log(funcName + " => retBoolean_3petu=" + retBoolean_3petu)
        return retBoolean_3petu
      }
    }

    // E poll()
    // public java.lang.Object java.util.concurrent.LinkedBlockingQueue.poll()
    var func_LinkedBlockingQueue_poll_0p = cls_LinkedBlockingQueue.poll.overload()
    console.log("func_LinkedBlockingQueue_poll_0p=" + func_LinkedBlockingQueue_poll_0p)
    if (func_LinkedBlockingQueue_poll_0p) {
      func_LinkedBlockingQueue_poll_0p.implementation = function () {
        var funcName = "LinkedBlockingQueue.poll_0p"
        var funcParaDict = {}
        // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)
        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        // var isShowLog = true
        var isShowLog = false
        if (null != callback_isShowLog) {
          isShowLog = callback_isShowLog(funcCallAndStackStr)
        }
        if (isShowLog) {
          // console.log(funcCallAndStackStr)
        }

        var retE_0p = this.poll()

        if (isShowLog) {
          if (retE_0p) {
            console.log(funcCallAndStackStr)

            console.log(funcName + " => retE_0p=" + FridaAndroidUtil.valueToNameStr(retE_0p))
          }
        }

        return retE_0p
      }
    }

    // E poll(long timeout, TimeUnit unit)
    // public java.lang.Object java.util.concurrent.LinkedBlockingQueue.poll(long,java.util.concurrent.TimeUnit) throws java.lang.InterruptedException
    var func_LinkedBlockingQueue_poll_2ptu = cls_LinkedBlockingQueue.poll.overload("long", "java.util.concurrent.TimeUnit")
    console.log("func_LinkedBlockingQueue_poll_2ptu=" + func_LinkedBlockingQueue_poll_2ptu)
    if (func_LinkedBlockingQueue_poll_2ptu) {
      func_LinkedBlockingQueue_poll_2ptu.implementation = function (timeout, unit) {
        var funcName = "LinkedBlockingQueue.poll_2ptu"
        var funcParaDict = {
          "timeout": timeout,
          "unit": unit,
        }
        // FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var funcCallAndStackStr = FridaAndroidUtil.genFunctionCallAndStack(funcName, funcParaDict)
        // var isShowLog = true
        var isShowLog = false
        if (null != callback_isShowLog) {
          isShowLog = callback_isShowLog(funcCallAndStackStr)
        }
        if (isShowLog) {
          // console.log(funcCallAndStackStr)
        }

        var retE_2ptu = this.poll(timeout, unit)

        if (isShowLog) {
          if (retE_2ptu) {
            console.log(funcCallAndStackStr)

            console.log(funcName + " => retE_2ptu=" + FridaAndroidUtil.valueToNameStr(retE_2ptu))
          }
        }

        return retE_2ptu
      }
    }

    // void put(E e)
    // public void java.util.concurrent.LinkedBlockingQueue.put(java.lang.Object) throws java.lang.InterruptedException
    var func_LinkedBlockingQueue_put = cls_LinkedBlockingQueue.put
    console.log("func_LinkedBlockingQueue_put=" + func_LinkedBlockingQueue_put)
    if (func_LinkedBlockingQueue_put) {
      func_LinkedBlockingQueue_put.implementation = function (e) {
        var funcName = "LinkedBlockingQueue.put"
        var funcParaDict = {
          "e": e,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.put(e)
      }
    }

  }

}