# JsFridaUtil

* Update: `20250404`

## Function

JS and Frida Util functions

## Files

* [JsFridaUtil](https://github.com/crifan/JsFridaUtil/)
  * [JsUtil.js](https://github.com/crifan/JsFridaUtil/blob/main/JsUtil.js)
  * [Frida](https://github.com/crifan/JsFridaUtil/tree/main/frida)
    * common
      * Util
        * [FridaUtil.js](https://github.com/crifan/JsFridaUtil/blob/main/frida/FridaUtil.js)
      * Hook
        * Native
          * [FridaHookNative.js](https://github.com/crifan/JsFridaUtil/blob/main/frida/FridaHookNative.js)
    * Android
      * Util
        * [FridaAndroidUtil.js](https://github.com/crifan/JsFridaUtil/blob/main/frida/FridaAndroidUtil.js)
      * Hook
        * Java
          * [FridaHookAndroidJava.js](https://github.com/crifan/JsFridaUtil/blob/main/frida/FridaHookAndroidJava.js)
        * Native
          * [FridaHookAndroidNative.js](https://github.com/crifan/JsFridaUtil/blob/main/frida/FridaHookAndroidNative.js)
    * iOS
      * Util
        * [FridaiOSUtil.js](https://github.com/crifan/JsFridaUtil/blob/main/frida/FridaiOSUtil.js)
      * Hook
        * Native
          * [FridaHookiOSNative.js](https://github.com/crifan/JsFridaUtil/blob/main/frida/FridaHookiOSNative.js)

### Tools

#### FridaJsSyncWithFridaUtil

* `tools/syncCode/FridaJsSyncWithFridaUtil.py`
  * auto sync to latest code between FridaUtil and HookJs
    * readme: `tools/syncCode/README.md`

## Usage

### Example

* https://github.com/crifan/FridaHookTemplate
