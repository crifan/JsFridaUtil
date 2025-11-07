/*
	File: FridaHookAndroid_Google.js
	Function: Frida hook common Android's class of com.google.xxx
	Author: Crifan Li
	Latest: https://github.com/crifan/JsFridaUtil/blob/main/frida/FridaHookAndroid_Google.js
	Updated: 20251107
*/

// Frida hook common Android's class of com.google.xxx
class FridaHookAndroid_Google {
  constructor() {
    console.log("FridaHookAndroid_Google constructor")
  }

  static {
    console.log("FridaHookAndroid_Google static")
  }

  //---------- com.google.firebase ----------

  static RandomFidGenerator() {
    var clsName_RandomFidGenerator = "com.google.firebase.installations.RandomFidGenerator"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_RandomFidGenerator)

    var cls_RandomFidGenerator = Java.use(clsName_RandomFidGenerator)
    console.log("cls_RandomFidGenerator=" + cls_RandomFidGenerator)

    
    // private static String encodeFidBase64UrlSafe(byte[] bArr) {
    // 
    var func_RandomFidGenerator_encodeFidBase64UrlSafe = cls_RandomFidGenerator.encodeFidBase64UrlSafe
    console.log("func_RandomFidGenerator_encodeFidBase64UrlSafe=" + func_RandomFidGenerator_encodeFidBase64UrlSafe)
    if (func_RandomFidGenerator_encodeFidBase64UrlSafe) {
      func_RandomFidGenerator_encodeFidBase64UrlSafe.implementation = function (bArr) {
        var funcName = "RandomFidGenerator.encodeFidBase64UrlSafe"
        var funcParaDict = {
          "bArr": bArr,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retString = this.encodeFidBase64UrlSafe(bArr)
        console.log("RandomFidGenerator.encodeFidBase64UrlSafe => retString=" + retString)
        return retString
      }
    }

    // private static byte[] getBytesFromUUID(UUID uuid, byte[] bArr) {
    // 
    var func_RandomFidGenerator_getBytesFromUUID = cls_RandomFidGenerator.getBytesFromUUID
    console.log("func_RandomFidGenerator_getBytesFromUUID=" + func_RandomFidGenerator_getBytesFromUUID)
    if (func_RandomFidGenerator_getBytesFromUUID) {
      func_RandomFidGenerator_getBytesFromUUID.implementation = function (uuid, bArr) {
        var funcName = "RandomFidGenerator.getBytesFromUUID"
        var funcParaDict = {
          "uuid": uuid,
          "bArr": bArr,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retbyte__ = this.getBytesFromUUID(uuid, bArr)
        console.log("RandomFidGenerator.getBytesFromUUID => retbyte__=" + retbyte__)
        return retbyte__
      }
    }

    // public String createRandomFid() {
    // 
    var func_RandomFidGenerator_createRandomFid = cls_RandomFidGenerator.createRandomFid
    console.log("func_RandomFidGenerator_createRandomFid=" + func_RandomFidGenerator_createRandomFid)
    if (func_RandomFidGenerator_createRandomFid) {
      func_RandomFidGenerator_createRandomFid.implementation = function () {
        var funcName = "RandomFidGenerator.createRandomFid"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retString = this.createRandomFid()
        console.log("RandomFidGenerator.createRandomFid => retString=" + retString)

        // for debug: use Python generated fid to test
        retString = "t8hVM_BzQkuIoUCDFV-0T7"
        console.log("for debug: use Python generated fid => retString=" + retString)

        return retString
      }
    }

  }

  static FirebaseInstallationServiceClient() {
    var clsName_FirebaseInstallationServiceClient = "com.google.firebase.installations.remote.FirebaseInstallationServiceClient"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_FirebaseInstallationServiceClient)

    var cls_FirebaseInstallationServiceClient = Java.use(clsName_FirebaseInstallationServiceClient)
    console.log("cls_FirebaseInstallationServiceClient=" + cls_FirebaseInstallationServiceClient)

    // public FirebaseInstallationServiceClient(Context context, Provider userAgentPublisher, Provider heartbeatInfo) {
    // 
    var func_FirebaseInstallationServiceClient_ctor = cls_FirebaseInstallationServiceClient.$init
    console.log("func_FirebaseInstallationServiceClient_ctor=" + func_FirebaseInstallationServiceClient_ctor)
    if (func_FirebaseInstallationServiceClient_ctor) {
      func_FirebaseInstallationServiceClient_ctor.implementation = function (context, userAgentPublisher, heartbeatInfo) {
        var funcName = "FirebaseInstallationServiceClient"
        var funcParaDict = {
          "context": context,
          "userAgentPublisher": userAgentPublisher,
          "heartbeatInfo": heartbeatInfo,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var newFirebaseInstallationServiceClient = this.$init(context, userAgentPublisher, heartbeatInfo)
        console.log(funcName + " => newFirebaseInstallationServiceClient=" + newFirebaseInstallationServiceClient)
        return newFirebaseInstallationServiceClient
      }
    }

    // private static String availableFirebaseOptions(String appId, String apiKey, String projectId) {
    // 
    var func_FirebaseInstallationServiceClient_availableFirebaseOptions = cls_FirebaseInstallationServiceClient.availableFirebaseOptions
    console.log("func_FirebaseInstallationServiceClient_availableFirebaseOptions=" + func_FirebaseInstallationServiceClient_availableFirebaseOptions)
    if (func_FirebaseInstallationServiceClient_availableFirebaseOptions) {
      func_FirebaseInstallationServiceClient_availableFirebaseOptions.implementation = function (appId, apiKey, projectId) {
        var funcName = "FirebaseInstallationServiceClient.availableFirebaseOptions"
        var funcParaDict = {
          "appId": appId,
          "apiKey": apiKey,
          "projectId": projectId,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retString = this.availableFirebaseOptions(appId, apiKey, projectId)
        console.log(funcName + " => retString=" + retString)
        return retString
      }
    }

    // private static JSONObject buildCreateFirebaseInstallationRequestBody(String fid, String appId) {
    // 
    var func_FirebaseInstallationServiceClient_buildCreateFirebaseInstallationRequestBody = cls_FirebaseInstallationServiceClient.buildCreateFirebaseInstallationRequestBody
    console.log("func_FirebaseInstallationServiceClient_buildCreateFirebaseInstallationRequestBody=" + func_FirebaseInstallationServiceClient_buildCreateFirebaseInstallationRequestBody)
    if (func_FirebaseInstallationServiceClient_buildCreateFirebaseInstallationRequestBody) {
      func_FirebaseInstallationServiceClient_buildCreateFirebaseInstallationRequestBody.implementation = function (fid, appId) {
        var funcName = "FirebaseInstallationServiceClient.buildCreateFirebaseInstallationRequestBody"
        var funcParaDict = {
          "fid": fid,
          "appId": appId,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retJSONObject = this.buildCreateFirebaseInstallationRequestBody(fid, appId)
        console.log(funcName + " => retJSONObject=" + retJSONObject)
        return retJSONObject
      }
    }

    // private static JSONObject buildGenerateAuthTokenRequestBody() {
    // 
    var func_FirebaseInstallationServiceClient_buildGenerateAuthTokenRequestBody = cls_FirebaseInstallationServiceClient.buildGenerateAuthTokenRequestBody
    console.log("func_FirebaseInstallationServiceClient_buildGenerateAuthTokenRequestBody=" + func_FirebaseInstallationServiceClient_buildGenerateAuthTokenRequestBody)
    if (func_FirebaseInstallationServiceClient_buildGenerateAuthTokenRequestBody) {
      func_FirebaseInstallationServiceClient_buildGenerateAuthTokenRequestBody.implementation = function () {
        var funcName = "FirebaseInstallationServiceClient.buildGenerateAuthTokenRequestBody"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retJSONObject = this.buildGenerateAuthTokenRequestBody()
        console.log(funcName + " => retJSONObject=" + retJSONObject)
        return retJSONObject
      }
    }

    // private String getFingerprintHashForPackage() {
    // 
    var func_FirebaseInstallationServiceClient_getFingerprintHashForPackage = cls_FirebaseInstallationServiceClient.getFingerprintHashForPackage
    console.log("func_FirebaseInstallationServiceClient_getFingerprintHashForPackage=" + func_FirebaseInstallationServiceClient_getFingerprintHashForPackage)
    if (func_FirebaseInstallationServiceClient_getFingerprintHashForPackage) {
      func_FirebaseInstallationServiceClient_getFingerprintHashForPackage.implementation = function () {
        var funcName = "FirebaseInstallationServiceClient.getFingerprintHashForPackage"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retFingerprintHashForPackage = this.getFingerprintHashForPackage()
        console.log(funcName + " => retFingerprintHashForPackage=" + retFingerprintHashForPackage)
        return retFingerprintHashForPackage
      }
    }

    // private URL getFullyQualifiedRequestUri(String queryStr) {
    // 
    var func_FirebaseInstallationServiceClient_getFullyQualifiedRequestUri = cls_FirebaseInstallationServiceClient.getFullyQualifiedRequestUri
    console.log("func_FirebaseInstallationServiceClient_getFullyQualifiedRequestUri=" + func_FirebaseInstallationServiceClient_getFullyQualifiedRequestUri)
    if (func_FirebaseInstallationServiceClient_getFullyQualifiedRequestUri) {
      func_FirebaseInstallationServiceClient_getFullyQualifiedRequestUri.implementation = function (queryStr) {
        var funcName = "FirebaseInstallationServiceClient.getFullyQualifiedRequestUri"
        var funcParaDict = {
          "queryStr": queryStr,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retFullyQualifiedRequestUri = this.getFullyQualifiedRequestUri(queryStr)
        console.log(funcName + " => retFullyQualifiedRequestUri=" + retFullyQualifiedRequestUri)
        return retFullyQualifiedRequestUri
      }
    }

    // private static byte[] getJsonBytes(JSONObject jSONObject) {
    // 
    var func_FirebaseInstallationServiceClient_getJsonBytes = cls_FirebaseInstallationServiceClient.getJsonBytes
    console.log("func_FirebaseInstallationServiceClient_getJsonBytes=" + func_FirebaseInstallationServiceClient_getJsonBytes)
    if (func_FirebaseInstallationServiceClient_getJsonBytes) {
      func_FirebaseInstallationServiceClient_getJsonBytes.implementation = function (jSONObject) {
        var funcName = "FirebaseInstallationServiceClient.getJsonBytes"
        var funcParaDict = {
          "jSONObject": jSONObject,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retJsonBytes = this.getJsonBytes(jSONObject)
        console.log(funcName + " => retJsonBytes=" + retJsonBytes)
        return retJsonBytes
      }
    }

    // private static boolean isSuccessfulResponseCode(int i) {
    // 
    var func_FirebaseInstallationServiceClient_isSuccessfulResponseCode = cls_FirebaseInstallationServiceClient.isSuccessfulResponseCode
    console.log("func_FirebaseInstallationServiceClient_isSuccessfulResponseCode=" + func_FirebaseInstallationServiceClient_isSuccessfulResponseCode)
    if (func_FirebaseInstallationServiceClient_isSuccessfulResponseCode) {
      func_FirebaseInstallationServiceClient_isSuccessfulResponseCode.implementation = function (i) {
        var funcName = "FirebaseInstallationServiceClient.isSuccessfulResponseCode"
        var funcParaDict = {
          "i": i,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean = this.isSuccessfulResponseCode(i)
        console.log(funcName + " => retBoolean=" + retBoolean)
        return retBoolean
      }
    }

    // private static void logBadConfigError() {
    // 
    var func_FirebaseInstallationServiceClient_logBadConfigError = cls_FirebaseInstallationServiceClient.logBadConfigError
    console.log("func_FirebaseInstallationServiceClient_logBadConfigError=" + func_FirebaseInstallationServiceClient_logBadConfigError)
    if (func_FirebaseInstallationServiceClient_logBadConfigError) {
      func_FirebaseInstallationServiceClient_logBadConfigError.implementation = function () {
        var funcName = "FirebaseInstallationServiceClient.logBadConfigError"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.logBadConfigError()
      }
    }

    // private static void logFisCommunicationError(HttpURLConnection httpURLConnection, String appId, String apiKey, String projectId) {
    // 
    var func_FirebaseInstallationServiceClient_logFisCommunicationError = cls_FirebaseInstallationServiceClient.logFisCommunicationError
    console.log("func_FirebaseInstallationServiceClient_logFisCommunicationError=" + func_FirebaseInstallationServiceClient_logFisCommunicationError)
    if (func_FirebaseInstallationServiceClient_logFisCommunicationError) {
      func_FirebaseInstallationServiceClient_logFisCommunicationError.implementation = function (httpURLConnection, appId, apiKey, projectId) {
        var funcName = "FirebaseInstallationServiceClient.logFisCommunicationError"
        var funcParaDict = {
          "httpURLConnection": httpURLConnection,
          "appId": appId,
          "apiKey": apiKey,
          "projectId": projectId,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.logFisCommunicationError(httpURLConnection, appId, apiKey, projectId)
      }
    }

    // private HttpURLConnection openHttpURLConnection(URL url, String xGoogApiKey) {
    // 
    var func_FirebaseInstallationServiceClient_openHttpURLConnection = cls_FirebaseInstallationServiceClient.openHttpURLConnection
    console.log("func_FirebaseInstallationServiceClient_openHttpURLConnection=" + func_FirebaseInstallationServiceClient_openHttpURLConnection)
    if (func_FirebaseInstallationServiceClient_openHttpURLConnection) {
      func_FirebaseInstallationServiceClient_openHttpURLConnection.implementation = function (url, xGoogApiKey) {
        var funcName = "FirebaseInstallationServiceClient.openHttpURLConnection"
        var funcParaDict = {
          "url": url,
          "xGoogApiKey": xGoogApiKey,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retHttpURLConnection = this.openHttpURLConnection(url, xGoogApiKey)
        console.log(funcName + " => retHttpURLConnection=" + retHttpURLConnection)
        return retHttpURLConnection
      }
    }

    // static long parseTokenExpirationTimestamp(String expiresIn) {
    // 
    var func_FirebaseInstallationServiceClient_parseTokenExpirationTimestamp = cls_FirebaseInstallationServiceClient.parseTokenExpirationTimestamp
    console.log("func_FirebaseInstallationServiceClient_parseTokenExpirationTimestamp=" + func_FirebaseInstallationServiceClient_parseTokenExpirationTimestamp)
    if (func_FirebaseInstallationServiceClient_parseTokenExpirationTimestamp) {
      func_FirebaseInstallationServiceClient_parseTokenExpirationTimestamp.implementation = function (expiresIn) {
        var funcName = "FirebaseInstallationServiceClient.parseTokenExpirationTimestamp"
        var funcParaDict = {
          "expiresIn": expiresIn,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retLong = this.parseTokenExpirationTimestamp(expiresIn)
        console.log(funcName + " => retLong=" + retLong)
        return retLong
      }
    }

    // private InstallationResponse readCreateResponse(HttpURLConnection httpURLConnection) {
    // 
    var func_FirebaseInstallationServiceClient_readCreateResponse = cls_FirebaseInstallationServiceClient.readCreateResponse
    console.log("func_FirebaseInstallationServiceClient_readCreateResponse=" + func_FirebaseInstallationServiceClient_readCreateResponse)
    if (func_FirebaseInstallationServiceClient_readCreateResponse) {
      func_FirebaseInstallationServiceClient_readCreateResponse.implementation = function (httpURLConnection) {
        var funcName = "FirebaseInstallationServiceClient.readCreateResponse"
        var funcParaDict = {
          "httpURLConnection": httpURLConnection,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retInstallationResponse = this.readCreateResponse(httpURLConnection)
        console.log(funcName + " => retInstallationResponse=" + retInstallationResponse)
        return retInstallationResponse
      }
    }

    // private static String readErrorResponse(HttpURLConnection httpURLConnection) {
    // 
    var func_FirebaseInstallationServiceClient_readErrorResponse = cls_FirebaseInstallationServiceClient.readErrorResponse
    console.log("func_FirebaseInstallationServiceClient_readErrorResponse=" + func_FirebaseInstallationServiceClient_readErrorResponse)
    if (func_FirebaseInstallationServiceClient_readErrorResponse) {
      func_FirebaseInstallationServiceClient_readErrorResponse.implementation = function (httpURLConnection) {
        var funcName = "FirebaseInstallationServiceClient.readErrorResponse"
        var funcParaDict = {
          "httpURLConnection": httpURLConnection,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retString = this.readErrorResponse(httpURLConnection)
        console.log(funcName + " => retString=" + retString)
        return retString
      }
    }

    // private TokenResult readGenerateAuthTokenResponse(HttpURLConnection httpURLConnection) {
    // 
    var func_FirebaseInstallationServiceClient_readGenerateAuthTokenResponse = cls_FirebaseInstallationServiceClient.readGenerateAuthTokenResponse
    console.log("func_FirebaseInstallationServiceClient_readGenerateAuthTokenResponse=" + func_FirebaseInstallationServiceClient_readGenerateAuthTokenResponse)
    if (func_FirebaseInstallationServiceClient_readGenerateAuthTokenResponse) {
      func_FirebaseInstallationServiceClient_readGenerateAuthTokenResponse.implementation = function (httpURLConnection) {
        var funcName = "FirebaseInstallationServiceClient.readGenerateAuthTokenResponse"
        var funcParaDict = {
          "httpURLConnection": httpURLConnection,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retTokenResult = this.readGenerateAuthTokenResponse(httpURLConnection)
        console.log(funcName + " => retTokenResult=" + retTokenResult)
        return retTokenResult
      }
    }

    // private void writeFIDCreateRequestBodyToOutputStream(HttpURLConnection httpURLConnection, String fid, String appId) {
    // 
    var func_FirebaseInstallationServiceClient_writeFIDCreateRequestBodyToOutputStream = cls_FirebaseInstallationServiceClient.writeFIDCreateRequestBodyToOutputStream
    console.log("func_FirebaseInstallationServiceClient_writeFIDCreateRequestBodyToOutputStream=" + func_FirebaseInstallationServiceClient_writeFIDCreateRequestBodyToOutputStream)
    if (func_FirebaseInstallationServiceClient_writeFIDCreateRequestBodyToOutputStream) {
      func_FirebaseInstallationServiceClient_writeFIDCreateRequestBodyToOutputStream.implementation = function (httpURLConnection, fid, appId) {
        var funcName = "FirebaseInstallationServiceClient.writeFIDCreateRequestBodyToOutputStream"
        var funcParaDict = {
          "httpURLConnection": httpURLConnection,
          "fid": fid,
          "appId": appId,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.writeFIDCreateRequestBodyToOutputStream(httpURLConnection, fid, appId)
      }
    }

    // private void writeGenerateAuthTokenRequestBodyToOutputStream(HttpURLConnection httpURLConnection) {
    // 
    var func_FirebaseInstallationServiceClient_writeGenerateAuthTokenRequestBodyToOutputStream = cls_FirebaseInstallationServiceClient.writeGenerateAuthTokenRequestBodyToOutputStream
    console.log("func_FirebaseInstallationServiceClient_writeGenerateAuthTokenRequestBodyToOutputStream=" + func_FirebaseInstallationServiceClient_writeGenerateAuthTokenRequestBodyToOutputStream)
    if (func_FirebaseInstallationServiceClient_writeGenerateAuthTokenRequestBodyToOutputStream) {
      func_FirebaseInstallationServiceClient_writeGenerateAuthTokenRequestBodyToOutputStream.implementation = function (httpURLConnection) {
        var funcName = "FirebaseInstallationServiceClient.writeGenerateAuthTokenRequestBodyToOutputStream"
        var funcParaDict = {
          "httpURLConnection": httpURLConnection,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.writeGenerateAuthTokenRequestBodyToOutputStream(httpURLConnection)
      }
    }

    // private static void writeRequestBodyToOutputStream(URLConnection uRLConnection, byte[] bArr) {
    // 
    var func_FirebaseInstallationServiceClient_writeRequestBodyToOutputStream = cls_FirebaseInstallationServiceClient.writeRequestBodyToOutputStream
    console.log("func_FirebaseInstallationServiceClient_writeRequestBodyToOutputStream=" + func_FirebaseInstallationServiceClient_writeRequestBodyToOutputStream)
    if (func_FirebaseInstallationServiceClient_writeRequestBodyToOutputStream) {
      func_FirebaseInstallationServiceClient_writeRequestBodyToOutputStream.implementation = function (uRLConnection, bArr) {
        var funcName = "FirebaseInstallationServiceClient.writeRequestBodyToOutputStream"
        var funcParaDict = {
          "uRLConnection": uRLConnection,
          "bArr": bArr,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.writeRequestBodyToOutputStream(uRLConnection, bArr)
      }
    }

    // public InstallationResponse createFirebaseInstallation(String apiKey, String fid, String projectId, String appId, String token) {
    // 
    var func_FirebaseInstallationServiceClient_createFirebaseInstallation = cls_FirebaseInstallationServiceClient.createFirebaseInstallation
    console.log("func_FirebaseInstallationServiceClient_createFirebaseInstallation=" + func_FirebaseInstallationServiceClient_createFirebaseInstallation)
    if (func_FirebaseInstallationServiceClient_createFirebaseInstallation) {
      func_FirebaseInstallationServiceClient_createFirebaseInstallation.implementation = function (apiKey, fid, projectId, appId, token) {
        var funcName = "FirebaseInstallationServiceClient.createFirebaseInstallation"
        var funcParaDict = {
          "apiKey": apiKey,
          "fid": fid,
          "projectId": projectId,
          "appId": appId,
          "token": token,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retInstallationResponse = this.createFirebaseInstallation(apiKey, fid, projectId, appId, token)
        console.log(funcName + " => retInstallationResponse=" + retInstallationResponse)
        return retInstallationResponse
      }
    }

    // public TokenResult generateAuthToken(String apiKey, String fid, String projectId, String refreshToken) {
    // 
    var func_FirebaseInstallationServiceClient_generateAuthToken = cls_FirebaseInstallationServiceClient.generateAuthToken
    console.log("func_FirebaseInstallationServiceClient_generateAuthToken=" + func_FirebaseInstallationServiceClient_generateAuthToken)
    if (func_FirebaseInstallationServiceClient_generateAuthToken) {
      func_FirebaseInstallationServiceClient_generateAuthToken.implementation = function (apiKey, fid, projectId, refreshToken) {
        var funcName = "FirebaseInstallationServiceClient.generateAuthToken"
        var funcParaDict = {
          "apiKey": apiKey,
          "fid": fid,
          "projectId": projectId,
          "refreshToken": refreshToken,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retTokenResult = this.generateAuthToken(apiKey, fid, projectId, refreshToken)
        console.log(funcName + " => retTokenResult=" + retTokenResult)
        return retTokenResult
      }
    }

  }

  //---------- com.google.android.gms ----------

  static zzw() {
    var clsName_zzw = "com.google.android.gms.tasks.zzw"
    // FridaAndroidUtil.printClassAllMethodsFields(clsName_zzw)

    var cls_zzw = Java.use(clsName_zzw)
    console.log("cls_zzw=" + cls_zzw)

    // zzw()
    // 
    var func_zzw_ctor = cls_zzw.$init
    console.log("func_zzw_ctor=" + func_zzw_ctor)
    if (func_zzw_ctor) {
      func_zzw_ctor.implementation = function () {
        var funcName = "zzw"
        var funcParaDict = {
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        this.$init()
        var newZzw = this
        console.log(funcName + " => newZzw=" + newZzw)
        return
      }
    }
    
    // private final void zzf() {
    // 
    var func_zzw_zzf = cls_zzw.zzf
    console.log("func_zzw_zzf=" + func_zzw_zzf)
    if (func_zzw_zzf) {
      func_zzw_zzf.implementation = function () {
        var funcName = "zzw.zzf"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.zzf()
      }
    }

    // private final void zzg() {
    // 
    var func_zzw_zzg = cls_zzw.zzg
    console.log("func_zzw_zzg=" + func_zzw_zzg)
    if (func_zzw_zzg) {
      func_zzw_zzg.implementation = function () {
        var funcName = "zzw.zzg"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.zzg()
      }
    }

    // private final void zzh() {
    // 
    var func_zzw_zzh = cls_zzw.zzh
    console.log("func_zzw_zzh=" + func_zzw_zzh)
    if (func_zzw_zzh) {
      func_zzw_zzh.implementation = function () {
        var funcName = "zzw.zzh"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.zzh()
      }
    }

    // private final void zzi() {
    // 
    var func_zzw_zzi = cls_zzw.zzi
    console.log("func_zzw_zzi=" + func_zzw_zzi)
    if (func_zzw_zzi) {
      func_zzw_zzi.implementation = function () {
        var funcName = "zzw.zzi"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.zzi()
      }
    }

    // public final Task addOnCanceledListener(OnCanceledListener onCanceledListener) {
    // 
    var func_zzw_addOnCanceledListener_1po = cls_zzw.addOnCanceledListener.overload('com.google.android.gms.tasks.OnCanceledListener')
    console.log("func_zzw_addOnCanceledListener_1po=" + func_zzw_addOnCanceledListener_1po)
    if (func_zzw_addOnCanceledListener_1po) {
      func_zzw_addOnCanceledListener_1po.implementation = function (onCanceledListener) {
        var funcName = "zzw.addOnCanceledListener_1po"
        var funcParaDict = {
          "onCanceledListener": onCanceledListener,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retTask_1po = this.addOnCanceledListener(onCanceledListener)
        console.log(funcName + " => retTask_1po=" + retTask_1po)
        return retTask_1po
      }
    }

    // public final Task addOnCompleteListener(OnCompleteListener onCompleteListener) {
    // 
    var func_zzw_addOnCompleteListener_1po = cls_zzw.addOnCompleteListener.overload('com.google.android.gms.tasks.OnCompleteListener')
    console.log("func_zzw_addOnCompleteListener_1po=" + func_zzw_addOnCompleteListener_1po)
    if (func_zzw_addOnCompleteListener_1po) {
      func_zzw_addOnCompleteListener_1po.implementation = function (onCompleteListener) {
        var funcName = "zzw.addOnCompleteListener_1po"
        var funcParaDict = {
          "onCompleteListener": onCompleteListener,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retTask_1po = this.addOnCompleteListener(onCompleteListener)
        console.log(funcName + " => retTask_1po=" + retTask_1po)
        return retTask_1po
      }
    }

    // public final Task addOnFailureListener(OnFailureListener onFailureListener) {
    // 
    var func_zzw_addOnFailureListener_1po = cls_zzw.addOnFailureListener.overload('com.google.android.gms.tasks.OnFailureListener')
    console.log("func_zzw_addOnFailureListener_1po=" + func_zzw_addOnFailureListener_1po)
    if (func_zzw_addOnFailureListener_1po) {
      func_zzw_addOnFailureListener_1po.implementation = function (onFailureListener) {
        var funcName = "zzw.addOnFailureListener_1po"
        var funcParaDict = {
          "onFailureListener": onFailureListener,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retTask_1po = this.addOnFailureListener(onFailureListener)
        console.log(funcName + " => retTask_1po=" + retTask_1po)
        return retTask_1po
      }
    }

    // public final Task addOnSuccessListener(OnSuccessListener onSuccessListener) {
    // 
    var func_zzw_addOnSuccessListener_1po = cls_zzw.addOnSuccessListener.overload('com.google.android.gms.tasks.OnSuccessListener')
    console.log("func_zzw_addOnSuccessListener_1po=" + func_zzw_addOnSuccessListener_1po)
    if (func_zzw_addOnSuccessListener_1po) {
      func_zzw_addOnSuccessListener_1po.implementation = function (onSuccessListener) {
        var funcName = "zzw.addOnSuccessListener_1po"
        var funcParaDict = {
          "onSuccessListener": onSuccessListener,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retTask_1po = this.addOnSuccessListener(onSuccessListener)
        console.log(funcName + " => retTask_1po=" + retTask_1po)
        return retTask_1po
      }
    }

    // public final Task continueWith(Continuation continuation) {
    // 
    var func_zzw_continueWith_1pc = cls_zzw.continueWith.overload('com.google.android.gms.tasks.Continuation')
    console.log("func_zzw_continueWith_1pc=" + func_zzw_continueWith_1pc)
    if (func_zzw_continueWith_1pc) {
      func_zzw_continueWith_1pc.implementation = function (continuation) {
        var funcName = "zzw.continueWith_1pc"
        var funcParaDict = {
          "continuation": continuation,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retTask_1pc = this.continueWith(continuation)
        console.log(funcName + " => retTask_1pc=" + retTask_1pc)
        return retTask_1pc
      }
    }

    // public final Task continueWithTask(Continuation continuation) {
    // 
    var func_zzw_continueWithTask_1pc = cls_zzw.continueWithTask.overload('com.google.android.gms.tasks.Continuation')
    console.log("func_zzw_continueWithTask_1pc=" + func_zzw_continueWithTask_1pc)
    if (func_zzw_continueWithTask_1pc) {
      func_zzw_continueWithTask_1pc.implementation = function (continuation) {
        var funcName = "zzw.continueWithTask_1pc"
        var funcParaDict = {
          "continuation": continuation,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retTask_1pc = this.continueWithTask(continuation)
        console.log(funcName + " => retTask_1pc=" + retTask_1pc)
        return retTask_1pc
      }
    }

    // public final Exception getException() {
    // 
    var func_zzw_getException = cls_zzw.getException
    console.log("func_zzw_getException=" + func_zzw_getException)
    if (func_zzw_getException) {
      func_zzw_getException.implementation = function () {
        var funcName = "zzw.getException"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retException = this.getException()
        console.log(funcName + " => retException=" + retException)
        return retException
      }
    }

    // public final Object getResult() {
    // 
    var func_zzw_getResult_0p = cls_zzw.getResult.overload()
    console.log("func_zzw_getResult_0p=" + func_zzw_getResult_0p)
    if (func_zzw_getResult_0p) {
      func_zzw_getResult_0p.implementation = function () {
        var funcName = "zzw.getResult_0p"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retResult_0p = this.getResult()
        console.log(funcName + " => retResult_0p=" + retResult_0p)
        return retResult_0p
      }
    }

    // public final boolean isComplete() {
    // 
    var func_zzw_isComplete = cls_zzw.isComplete
    console.log("func_zzw_isComplete=" + func_zzw_isComplete)
    if (func_zzw_isComplete) {
      func_zzw_isComplete.implementation = function () {
        var funcName = "zzw.isComplete"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean = this.isComplete()
        console.log(funcName + " => retBoolean=" + retBoolean)
        return retBoolean
      }
    }

    // public final boolean isSuccessful() {
    // 
    var func_zzw_isSuccessful = cls_zzw.isSuccessful
    console.log("func_zzw_isSuccessful=" + func_zzw_isSuccessful)
    if (func_zzw_isSuccessful) {
      func_zzw_isSuccessful.implementation = function () {
        var funcName = "zzw.isSuccessful"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean = this.isSuccessful()
        console.log(funcName + " => retBoolean=" + retBoolean)
        return retBoolean
      }
    }

    // public final Task onSuccessTask(SuccessContinuation successContinuation) {
    // 
    var func_zzw_onSuccessTask_1ps = cls_zzw.onSuccessTask.overload('com.google.android.gms.tasks.SuccessContinuation')
    console.log("func_zzw_onSuccessTask_1ps=" + func_zzw_onSuccessTask_1ps)
    if (func_zzw_onSuccessTask_1ps) {
      func_zzw_onSuccessTask_1ps.implementation = function (successContinuation) {
        var funcName = "zzw.onSuccessTask_1ps"
        var funcParaDict = {
          "successContinuation": successContinuation,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retTask_1ps = this.onSuccessTask(successContinuation)
        console.log(funcName + " => retTask_1ps=" + retTask_1ps)
        return retTask_1ps
      }
    }

    // public final void zza(Exception exc) {
    // 
    var func_zzw_zza = cls_zzw.zza
    console.log("func_zzw_zza=" + func_zzw_zza)
    if (func_zzw_zza) {
      func_zzw_zza.implementation = function (exc) {
        var funcName = "zzw.zza"
        var funcParaDict = {
          "exc": exc,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.zza(exc)
      }
    }

    // public final void zzb(Object obj) {
    // 
    var func_zzw_zzb = cls_zzw.zzb
    console.log("func_zzw_zzb=" + func_zzw_zzb)
    if (func_zzw_zzb) {
      func_zzw_zzb.implementation = function (obj) {
        var funcName = "zzw.zzb"
        var funcParaDict = {
          "obj": obj,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        return this.zzb(obj)
      }
    }

    // public final boolean zzc() {
    // 
    var func_zzw_zzc = cls_zzw.zzc
    console.log("func_zzw_zzc=" + func_zzw_zzc)
    if (func_zzw_zzc) {
      func_zzw_zzc.implementation = function () {
        var funcName = "zzw.zzc"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean = this.zzc()
        console.log(funcName + " => retBoolean=" + retBoolean)
        return retBoolean
      }
    }

    // public final boolean zzd(Exception exc) {
    // 
    var func_zzw_zzd = cls_zzw.zzd
    console.log("func_zzw_zzd=" + func_zzw_zzd)
    if (func_zzw_zzd) {
      func_zzw_zzd.implementation = function (exc) {
        var funcName = "zzw.zzd"
        var funcParaDict = {
          "exc": exc,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean = this.zzd(exc)
        console.log(funcName + " => retBoolean=" + retBoolean)
        return retBoolean
      }
    }

    // public final boolean zze(Object obj) {
    // 
    var func_zzw_zze = cls_zzw.zze
    console.log("func_zzw_zze=" + func_zzw_zze)
    if (func_zzw_zze) {
      func_zzw_zze.implementation = function (obj) {
        var funcName = "zzw.zze"
        var funcParaDict = {
          "obj": obj,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean = this.zze(obj)
        console.log(funcName + " => retBoolean=" + retBoolean)
        return retBoolean
      }
    }

    // public final boolean isCanceled() {
    // 
    var func_zzw_isCanceled = cls_zzw.isCanceled
    console.log("func_zzw_isCanceled=" + func_zzw_isCanceled)
    if (func_zzw_isCanceled) {
      func_zzw_isCanceled.implementation = function () {
        var funcName = "zzw.isCanceled"
        var funcParaDict = {}
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retBoolean = this.isCanceled()
        console.log(funcName + " => retBoolean=" + retBoolean)
        return retBoolean
      }
    }

    // public final Task addOnCanceledListener(Activity activity, OnCanceledListener onCanceledListener) {
    // 
    var func_zzw_addOnCanceledListener_2pao = cls_zzw.addOnCanceledListener.overload('android.app.Activity', 'com.google.android.gms.tasks.OnCanceledListener')
    console.log("func_zzw_addOnCanceledListener_2pao=" + func_zzw_addOnCanceledListener_2pao)
    if (func_zzw_addOnCanceledListener_2pao) {
      func_zzw_addOnCanceledListener_2pao.implementation = function (activity, onCanceledListener) {
        var funcName = "zzw.addOnCanceledListener_2pao"
        var funcParaDict = {
          "activity": activity,
          "onCanceledListener": onCanceledListener,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retTask_2pao = this.addOnCanceledListener(activity, onCanceledListener)
        console.log(funcName + " => retTask_2pao=" + retTask_2pao)
        return retTask_2pao
      }
    }

    // public final Task addOnCompleteListener(Activity activity, OnCompleteListener onCompleteListener) {
    // 
    var func_zzw_addOnCompleteListener_2pao = cls_zzw.addOnCompleteListener.overload('android.app.Activity', 'com.google.android.gms.tasks.OnCompleteListener')
    console.log("func_zzw_addOnCompleteListener_2pao=" + func_zzw_addOnCompleteListener_2pao)
    if (func_zzw_addOnCompleteListener_2pao) {
      func_zzw_addOnCompleteListener_2pao.implementation = function (activity, onCompleteListener) {
        var funcName = "zzw.addOnCompleteListener_2pao"
        var funcParaDict = {
          "activity": activity,
          "onCompleteListener": onCompleteListener,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retTask_2pao = this.addOnCompleteListener(activity, onCompleteListener)
        console.log(funcName + " => retTask_2pao=" + retTask_2pao)
        return retTask_2pao
      }
    }

    // public final Task addOnFailureListener(Activity activity, OnFailureListener onFailureListener) {
    // 
    var func_zzw_addOnFailureListener_2pao = cls_zzw.addOnFailureListener.overload('android.app.Activity', 'com.google.android.gms.tasks.OnFailureListener')
    console.log("func_zzw_addOnFailureListener_2pao=" + func_zzw_addOnFailureListener_2pao)
    if (func_zzw_addOnFailureListener_2pao) {
      func_zzw_addOnFailureListener_2pao.implementation = function (activity, onFailureListener) {
        var funcName = "zzw.addOnFailureListener_2pao"
        var funcParaDict = {
          "activity": activity,
          "onFailureListener": onFailureListener,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retTask_2pao = this.addOnFailureListener(activity, onFailureListener)
        console.log(funcName + " => retTask_2pao=" + retTask_2pao)
        return retTask_2pao
      }
    }

    // public final Task addOnSuccessListener(Activity activity, OnSuccessListener onSuccessListener) {
    // 
    var func_zzw_addOnSuccessListener_2pao = cls_zzw.addOnSuccessListener.overload('android.app.Activity', 'com.google.android.gms.tasks.OnSuccessListener')
    console.log("func_zzw_addOnSuccessListener_2pao=" + func_zzw_addOnSuccessListener_2pao)
    if (func_zzw_addOnSuccessListener_2pao) {
      func_zzw_addOnSuccessListener_2pao.implementation = function (activity, onSuccessListener) {
        var funcName = "zzw.addOnSuccessListener_2pao"
        var funcParaDict = {
          "activity": activity,
          "onSuccessListener": onSuccessListener,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retTask_2pao = this.addOnSuccessListener(activity, onSuccessListener)
        console.log(funcName + " => retTask_2pao=" + retTask_2pao)
        return retTask_2pao
      }
    }

    // public final Task continueWith(Executor executor, Continuation continuation) {
    // 
    var func_zzw_continueWith_2pec = cls_zzw.continueWith.overload('java.util.concurrent.Executor', 'com.google.android.gms.tasks.Continuation')
    console.log("func_zzw_continueWith_2pec=" + func_zzw_continueWith_2pec)
    if (func_zzw_continueWith_2pec) {
      func_zzw_continueWith_2pec.implementation = function (executor, continuation) {
        var funcName = "zzw.continueWith_2pec"
        var funcParaDict = {
          "executor": executor,
          "continuation": continuation,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retTask_2pec = this.continueWith(executor, continuation)
        console.log(funcName + " => retTask_2pec=" + retTask_2pec)
        return retTask_2pec
      }
    }

    // public final Task continueWithTask(Executor executor, Continuation continuation) {
    // 
    var func_zzw_continueWithTask_2pec = cls_zzw.continueWithTask.overload('java.util.concurrent.Executor', 'com.google.android.gms.tasks.Continuation')
    console.log("func_zzw_continueWithTask_2pec=" + func_zzw_continueWithTask_2pec)
    if (func_zzw_continueWithTask_2pec) {
      func_zzw_continueWithTask_2pec.implementation = function (executor, continuation) {
        var funcName = "zzw.continueWithTask_2pec"
        var funcParaDict = {
          "executor": executor,
          "continuation": continuation,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retTask_2pec = this.continueWithTask(executor, continuation)
        console.log(funcName + " => retTask_2pec=" + retTask_2pec)
        return retTask_2pec
      }
    }

    // public final Object getResult(Class cls) throws Throwable {
    // 
    var func_zzw_getResult_1pc = cls_zzw.getResult.overload('java.lang.Class')
    console.log("func_zzw_getResult_1pc=" + func_zzw_getResult_1pc)
    if (func_zzw_getResult_1pc) {
      func_zzw_getResult_1pc.implementation = function (cls) {
        var funcName = "zzw.getResult_1pc"
        var funcParaDict = {
          "cls": cls,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retResult_1pc = this.getResult(cls)
        console.log(funcName + " => retResult_1pc=" + retResult_1pc)
        return retResult_1pc
      }
    }

    // public final Task onSuccessTask(Executor executor, SuccessContinuation successContinuation) {
    // 
    var func_zzw_onSuccessTask_2pes = cls_zzw.onSuccessTask.overload('java.util.concurrent.Executor', 'com.google.android.gms.tasks.SuccessContinuation')
    console.log("func_zzw_onSuccessTask_2pes=" + func_zzw_onSuccessTask_2pes)
    if (func_zzw_onSuccessTask_2pes) {
      func_zzw_onSuccessTask_2pes.implementation = function (executor, successContinuation) {
        var funcName = "zzw.onSuccessTask_2pes"
        var funcParaDict = {
          "executor": executor,
          "successContinuation": successContinuation,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retTask_2pes = this.onSuccessTask(executor, successContinuation)
        console.log(funcName + " => retTask_2pes=" + retTask_2pes)
        return retTask_2pes
      }
    }

    // public final Task addOnCanceledListener(Executor executor, OnCanceledListener onCanceledListener) {
    // 
    var func_zzw_addOnCanceledListener_2peo = cls_zzw.addOnCanceledListener.overload('java.util.concurrent.Executor', 'com.google.android.gms.tasks.OnCanceledListener')
    console.log("func_zzw_addOnCanceledListener_2peo=" + func_zzw_addOnCanceledListener_2peo)
    if (func_zzw_addOnCanceledListener_2peo) {
      func_zzw_addOnCanceledListener_2peo.implementation = function (executor, onCanceledListener) {
        var funcName = "zzw.addOnCanceledListener_2peo"
        var funcParaDict = {
          "executor": executor,
          "onCanceledListener": onCanceledListener,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retTask_2peo = this.addOnCanceledListener(executor, onCanceledListener)
        console.log(funcName + " => retTask_2peo=" + retTask_2peo)
        return retTask_2peo
      }
    }

    // public final Task addOnCompleteListener(Executor executor, OnCompleteListener onCompleteListener) {
    // 
    var func_zzw_addOnCompleteListener_2peo = cls_zzw.addOnCompleteListener.overload('java.util.concurrent.Executor', 'com.google.android.gms.tasks.OnCompleteListener')
    console.log("func_zzw_addOnCompleteListener_2peo=" + func_zzw_addOnCompleteListener_2peo)
    if (func_zzw_addOnCompleteListener_2peo) {
      func_zzw_addOnCompleteListener_2peo.implementation = function (executor, onCompleteListener) {
        var funcName = "zzw.addOnCompleteListener_2peo"
        var funcParaDict = {
          "executor": executor,
          "onCompleteListener": onCompleteListener,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retTask_2peo = this.addOnCompleteListener(executor, onCompleteListener)
        console.log(funcName + " => retTask_2peo=" + retTask_2peo)
        return retTask_2peo
      }
    }

    // public final Task addOnFailureListener(Executor executor, OnFailureListener onFailureListener) {
    // 
    var func_zzw_addOnFailureListener_2peo = cls_zzw.addOnFailureListener.overload('java.util.concurrent.Executor', 'com.google.android.gms.tasks.OnFailureListener')
    console.log("func_zzw_addOnFailureListener_2peo=" + func_zzw_addOnFailureListener_2peo)
    if (func_zzw_addOnFailureListener_2peo) {
      func_zzw_addOnFailureListener_2peo.implementation = function (executor, onFailureListener) {
        var funcName = "zzw.addOnFailureListener_2peo"
        var funcParaDict = {
          "executor": executor,
          "onFailureListener": onFailureListener,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retTask_2peo = this.addOnFailureListener(executor, onFailureListener)
        console.log(funcName + " => retTask_2peo=" + retTask_2peo)
        return retTask_2peo
      }
    }

    // public final Task addOnSuccessListener(Executor executor, OnSuccessListener onSuccessListener) {
    // 
    var func_zzw_addOnSuccessListener_2peo = cls_zzw.addOnSuccessListener.overload('java.util.concurrent.Executor', 'com.google.android.gms.tasks.OnSuccessListener')
    console.log("func_zzw_addOnSuccessListener_2peo=" + func_zzw_addOnSuccessListener_2peo)
    if (func_zzw_addOnSuccessListener_2peo) {
      func_zzw_addOnSuccessListener_2peo.implementation = function (executor, onSuccessListener) {
        var funcName = "zzw.addOnSuccessListener_2peo"
        var funcParaDict = {
          "executor": executor,
          "onSuccessListener": onSuccessListener,
        }
        FridaAndroidUtil.printFunctionCallAndStack(funcName, funcParaDict)

        var retTask_2peo = this.addOnSuccessListener(executor, onSuccessListener)
        console.log(funcName + " => retTask_2peo=" + retTask_2peo)
        return retTask_2peo
      }
    }

  }

}
