# FridaJsSyncWithFridaUtil

* Update: `20250404`

## Function

Sync code between Frida Hook js file and here js Frida Util

## Usage

1. update config
  * change `fridaHookJsFile` in `tools/syncCode/syncConfig.json` to your frida hook js file
    * eg:
      * `/Users/crifan/dev/dev_root/xxx/frida_js/hook_SomeApp.js`
2. run script
  ```bash
  python3 tools/syncCode/FridaJsSyncWithFridaUtil.py
  ```
