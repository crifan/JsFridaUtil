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

  // com.google.firebase

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

}
