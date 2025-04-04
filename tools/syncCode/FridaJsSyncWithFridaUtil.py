# Function: Sync code between Frida Hook js file and here js Frida Util
# Author: Crifan Li
# Link: https://github.com/crifan/JsFridaUtil/blob/main/tools/syncCode/FridaJsSyncWithFridaUtil.py
# Update: 20250404

import json
import codecs
import string
import os
import re
from datetime import datetime

################################################################################
# Config
################################################################################

# inputConfigFile = "tools/syncCode/syncConfig.json"
inputConfigFile = "syncConfig.json"

"""

tools/syncCode/syncConfig.json

{
  "fridaHookJsFile": "/xxx/frida_js/hook_yyy.js"
}

"""

################################################################################
# Const
################################################################################

mainDelimeterNum = 40
mainDelimeterChar = "="
mainDelimeterStr = mainDelimeterChar*mainDelimeterNum

subDelimeterNum = 30
subDelimeterChar = "-"
subDelimeterStr = subDelimeterChar*subDelimeterNum

################################################################################
# Util Functions
################################################################################
class CommonUtil:

  def datetimeToStr(inputDatetime, format="%Y%m%d_%H%M%S"):
      """Convert datetime to string

      Args:
          inputDatetime (datetime): datetime value
      Returns:
          str
      Raises:
      Examples:
          datetime.datetime(2020, 4, 21, 15, 44, 13, 2000) -> '20200421_154413'
      """
      datetimeStr = inputDatetime.strftime(format=format)
      # print("inputDatetime=%s -> datetimeStr=%s" % (inputDatetime, datetimeStr)) # 2020-04-21 15:08:59.787623
      return datetimeStr

  def getCurDatetimeStr(outputFormat="%Y%m%d_%H%M%S"):
      """
      get current datetime then format to string

      eg:
          20171111_220722

      :param outputFormat: datetime output format
      :return: current datetime formatted string
      """
      curDatetime = datetime.now() # 2017-11-11 22:07:22.705101
      # curDatetimeStr = curDatetime.strftime(format=outputFormat) #'20171111_220722'
      curDatetimeStr = CommonUtil.datetimeToStr(curDatetime, format=outputFormat)
      return curDatetimeStr

  def loadJsonFromFile(fullFilename, fileEncoding="utf-8"):
      """load and parse json dict from file"""
      with codecs.open(fullFilename, 'r', encoding=fileEncoding) as jsonFp:
          jsonDict = json.load(jsonFp)
          # logging.debug("Complete load json from %s", fullFilename)
          return jsonDict

  def saveJsonToFile(fullFilename, jsonValue, indent=2, fileEncoding="utf-8"):
      """
          save json dict into file
          for non-ascii string, output encoded string, without \\u xxxx
      """
      with codecs.open(fullFilename, 'w', encoding=fileEncoding) as jsonFp:
          json.dump(jsonValue, jsonFp, indent=indent, ensure_ascii=False)
          # logging.debug("Complete save json %s", fullFilename)

  def loadTextFromFile(fullFilename, fileEncoding="utf-8"):
      """load file text content from file"""
      with codecs.open(fullFilename, 'r', encoding=fileEncoding) as fp:
          allText = fp.read()
          # logging.debug("Complete load text from %s", fullFilename)
          return allText

  def saveTextToFile(fullFilename, text, fileEncoding="utf-8"):
      """save text content into file"""
      with codecs.open(fullFilename, 'w', encoding=fileEncoding) as fp:
          fp.write(text)
          fp.close()

  def createFolder(folderFullPath):
    """
      create folder, even if already existed
      Note: for Python 3.2+
    """
    os.makedirs(folderFullPath, exist_ok=True)


################################################################################
# Current Functions
################################################################################

def updateNewContent(updatedMatch, classCodeMatch, origAllText, newUpdated, newClassCode, destFileFullPath):
  newAllText_strList = list(origAllText)

  # replace update=date
  updated_start, updated_end = updatedMatch.span("classUpdated")
  print("%s updated: start=%d, end=%d" % (className, updated_start, updated_end))
  newAllText_strList[updated_start:updated_end] = newUpdated

  # replce code
  fridaUtil_classCode_start, fridaUtil_classCode_end = classCodeMatch.span("classCode")
  print("%s classCode: start=%d, end=%d" % (className, fridaUtil_classCode_start, fridaUtil_classCode_end))
  newAllText_strList[fridaUtil_classCode_start:fridaUtil_classCode_end] = newClassCode

  newAllText = "".join(newAllText_strList)

  # for debug: save updated, for later compare
  debugClass_filename = "%s_updated_%s.js" % (className, newUpdated)
  debugClass_filePath = os.path.join(debugFolder, debugClass_filename)
  CommonUtil.saveTextToFile(debugClass_filePath, newAllText)

  # write back updated content
  CommonUtil.saveTextToFile(destFileFullPath, newAllText)
  print("Saved new content to destFileFullPath=%s" % destFileFullPath)

################################################################################
# Main
################################################################################

curDateTimeStr = CommonUtil.getCurDatetimeStr()
print("curDateTimeStr=%s" % curDateTimeStr)

curFilePath = os.path.abspath(__file__)
# curFilePath=/Users/crifan/dev/dev_root/crifan/github/JsFridaUtil/tools/syncCode/FridaJsSyncWithFridaUtil.py
# print("curFilePath=%s" % curFilePath)
curFileFoler = os.path.dirname(curFilePath)
# print("curFileFoler=%s" % curFileFoler)
# curFileFoler=/Users/crifan/dev/dev_root/crifan/github/JsFridaUtil/tools/syncCode
fridaUtilRootFoler = os.path.abspath(os.path.join(curFileFoler, "..", ".."))
print("fridaUtilRootFoler=%s" % fridaUtilRootFoler)
# fridaUtilRootFoler=/Users/crifan/dev/dev_root/crifan/github/JsFridaUtil

# print("inputConfigFile=%s" % inputConfigFile)
inputConfigFullPath = os.path.join(curFileFoler, inputConfigFile)
print("inputConfigFullPath=%s" % inputConfigFullPath)
configDict = CommonUtil.loadJsonFromFile(inputConfigFullPath)
print("configDict=%s" % configDict)

fridaHookJsFile = configDict["fridaHookJsFile"]
print("fridaHookJsFile=%s" % fridaHookJsFile)

fridaHookJs_AllText = CommonUtil.loadTextFromFile(fridaHookJsFile)
# print("fridaHookJs_AllText=%s" % fridaHookJs_AllText)

toSyncClassDictList = [
    {
        "subPath": "",
        "className": "JsUtil",
    },
    {
        "subPath": "frida",
        "className": "FridaUtil",
    },
    {
        "subPath": "frida",
        "className": "FridaHookNative",
    },
    {
        "subPath": "frida",
        "className": "FridaAndroidUtil",
    },
    {
        "subPath": "frida",
        "className": "FridaHookAndroidJava",
    },
    {
        "subPath": "frida",
        "className": "FridaHookAndroidNative",
    },
    {
        "subPath": "frida",
        "className": "FridaiOSUtil",
    },
    {
        "subPath": "frida",
        "className": "FridaHookiOSNative",
    },
]
# print("toSyncClassDictList=%s" % toSyncClassDictList)

# for debug: init debug folder
debugFolder = os.path.join(curFileFoler, "debugging", curDateTimeStr)
# print("debugFolder=%s" % debugFolder)
CommonUtil.createFolder(debugFolder)

for idx, eachClassDict in enumerate(toSyncClassDictList):
  classSubPath = eachClassDict["subPath"]
  className = eachClassDict["className"]
  print("%s [%s] %s %s" % (mainDelimeterStr, idx, className, mainDelimeterStr))
  # print("eachClassDict=%s" % eachClassDict)
  # print("classSubPath=%s, className=%s" % (classSubPath, className))
  classFileFoler = os.path.join(fridaUtilRootFoler, classSubPath)
  # print("classFileFoler=%s" % classFileFoler)
  classFileName = "%s.js" % className
  # print("classFileName=%s" % classFileName)
  classFileFullPath = os.path.join(classFileFoler, classFileName)
  print("Load text from: classFileFullPath=%s" % classFileFullPath)
  fridaUtil_curCls_AllText = CommonUtil.loadTextFromFile(classFileFullPath)
  # print("fridaUtil_curCls_AllText=%s" % fridaUtil_curCls_AllText)

  updated_P = r"Updated:\s+(?P<classUpdated>\d+)"
  newLine_P = r"\s+"

  Description_P = r"^//\s+(?P<classDescription>.+?$)"

  # ClassCode_P = r"(?P<classCode>class\s+" + className + r"\s+\{.+" + r"^\})"
  # ClassCode_P = r"^class\s+" + className + r".+^\}"
  # ClassCode_P = r"^class\s+" + className
  ClassCode_P = r"(?P<classCode>^class\s+" + className + r"\s+\{.+?^\})"

  # 	Latest: https://github.com/crifan/JsFridaUtil/blob/main/frida/FridaiOSUtil.js
	# 	Updated: 20240823
  fridaUtil_curClsHeader_P = \
    r"Latest: (?P<classUrl>https://.+" + className + r"\.js$)" + newLine_P \
    + updated_P

  fridaUtil_curClsHeader_Match = re.search(fridaUtil_curClsHeader_P, fridaUtil_curCls_AllText, re.MULTILINE)
  # print("fridaUtil_curClsHeader_Match=%s" % fridaUtil_curClsHeader_Match)
  if fridaUtil_curClsHeader_Match:
    classUrl = fridaUtil_curClsHeader_Match.group("classUrl")
    # print("classUrl=%s" % classUrl)
    classUpdated_fridaUtil = fridaUtil_curClsHeader_Match.group("classUpdated")
    print("classUpdated_fridaUtil=%s" % classUpdated_fridaUtil)
    classUpdatedInt_fridaUtil = int(classUpdated_fridaUtil)
    # print("classUpdatedInt_fridaUtil=%s" % classUpdatedInt_fridaUtil)

    """
      // https://github.com/crifan/JsFridaUtil/blob/main/JsUtil.js
      // Updated: 20250325
      // pure JavaScript utils
      class JsUtil {
        ...
      }
    """
    hookJs_curCls_ClassUrl_P = r"^//\s+" + classUrl
    hookJs_curCls_Updated_P = r"^//\s+" + updated_P

    hookJs_curCls_P = \
      hookJs_curCls_ClassUrl_P + newLine_P + \
      hookJs_curCls_Updated_P + newLine_P + \
      Description_P + newLine_P + \
      ClassCode_P
    hookJs_curCls_Match = re.search(hookJs_curCls_P, fridaHookJs_AllText, re.MULTILINE | re.DOTALL)
    # print("hookJs_curCls_Match=%s" % hookJs_curCls_Match)
    if hookJs_curCls_Match:
      hookJs_curCls_allText = hookJs_curCls_Match.group(0)
      # print("hookJs_curCls_allText=%s" % hookJs_curCls_allText)
      classUpdated_hookJs = hookJs_curCls_Match.group("classUpdated")
      print("classUpdated_hookJs=%s" % classUpdated_hookJs)
      classUpdatedInt_hookJs = int(classUpdated_hookJs)
      # print("classUpdatedInt_hookJs=%s" % classUpdatedInt_hookJs)
      classDescription_hookJs = hookJs_curCls_Match.group("classDescription")
      # print("classDescription_hookJs=%s" % classDescription_hookJs)
      classCode_hookJs = hookJs_curCls_Match.group("classCode")
      # print("classCode_hookJs=%s" % classCode_hookJs)
      print("")
    else:
      print("WARN: not found class %s in frida hook js file %s" % (className, fridaHookJsFile))
      continue

    if classUpdatedInt_hookJs != classUpdatedInt_fridaUtil:
      # find frida util class code
      fridaUtil_curClsCode_P = \
        Description_P + newLine_P + \
        ClassCode_P
      fridaUtil_curClsCode_Match = re.search(fridaUtil_curClsCode_P, fridaUtil_curCls_AllText, re.MULTILINE | re.DOTALL)
      # print("fridaUtil_curClsCode_Match=%s" % fridaUtil_curClsCode_Match)
      if fridaUtil_curClsCode_Match:
        classDescription_fridaUtil = fridaUtil_curClsCode_Match.group("classDescription")
        # print("classDescription_fridaUtil=%s" % classDescription_fridaUtil)
        classCode_fridaUtil = fridaUtil_curClsCode_Match.group("classCode")
        # print("classCode_fridaUtil=%s" % classCode_fridaUtil)
      else:
        raise Exception("Not found %s class info for %s" % (className, classFileFullPath))

      # for debug: output to file, for later compare
      debugClass_fridaUtil_filename = "%s_fridaUtil_%s.js" % (className, classUpdatedInt_fridaUtil)
      debugClass_fridaUtil_filePath = os.path.join(debugFolder, debugClass_fridaUtil_filename)
      CommonUtil.saveTextToFile(debugClass_fridaUtil_filePath, classCode_fridaUtil)
      debugClass_hookJs_filename = "%s_hookJs_%s.js" % (className, classUpdatedInt_hookJs)
      debugClass_hookJs_filePath = os.path.join(debugFolder, debugClass_hookJs_filename)
      CommonUtil.saveTextToFile(debugClass_hookJs_filePath, classCode_hookJs)

      if classUpdatedInt_hookJs > classUpdatedInt_fridaUtil:
        print("%s: hookJs=%d > fridaUtil=%d ==>> try use hookJs to repace fridaUtil" % (className, classUpdatedInt_hookJs, classUpdatedInt_fridaUtil))

        # # fridaUtil_curCls_newAllText = fridaUtil_curCls_AllText
        # fridaUtil_curCls_newAllText_strList = list(fridaUtil_curCls_AllText)

        # # replace update=date
        # # fridaUtil_updated_start = fridaUtil_curClsHeader_Match.start("classUpdated")
        # # fridaUtil_updated_end = fridaUtil_curClsHeader_Match.end("classUpdated")
        # fridaUtil_updated_start, fridaUtil_updated_end = fridaUtil_curClsHeader_Match.span("classUpdated")
        # print("fridaUtil %s updated: start=%d, end=%d" % (className, fridaUtil_updated_start, fridaUtil_updated_end))
        # fridaUtil_curCls_newAllText_strList[fridaUtil_updated_start:fridaUtil_updated_end] = classUpdated_hookJs

        # # replce code
        # # fridaUtil_classCode_start = fridaUtil_curClsCode_Match.start("classCode")
        # # fridaUtil_classCode_end = fridaUtil_curClsCode_Match.end("classCode")
        # fridaUtil_classCode_start, fridaUtil_classCode_end = fridaUtil_curClsCode_Match.span("classCode")
        # print("fridaUtil %s classCode: start=%d, end=%d" % (className, fridaUtil_classCode_start, fridaUtil_classCode_end))
        # fridaUtil_curCls_newAllText_strList[fridaUtil_classCode_start:fridaUtil_classCode_end] = classCode_hookJs

        # fridaUtil_curCls_newAllText = "".join(fridaUtil_curCls_newAllText_strList)

        # # for debug: save updated fridaUtil, for later compare
        # debugClass_fridaUtil_filename = "%s_fridaUtil_updated_%s.js" % (className, classUpdated_hookJs)
        # debugClass_fridaUtil_filePath = os.path.join(debugFolder, debugClass_fridaUtil_filename)
        # CommonUtil.saveTextToFile(debugClass_fridaUtil_filePath, fridaUtil_curCls_newAllText)

        # # write back updated content
        # CommonUtil.saveTextToFile(classFileFullPath, fridaUtil_curCls_newAllText)

        updateNewContent(fridaUtil_curClsHeader_Match, fridaUtil_curClsCode_Match, fridaUtil_curCls_AllText, classUpdated_hookJs, classCode_hookJs, classFileFullPath)

      elif classUpdatedInt_fridaUtil > classUpdatedInt_hookJs:
        print("%s: fridaUtil=%d > hookJs=%d ==>> try use fridaUtil to repace hookJs" % (className, classUpdatedInt_fridaUtil, classUpdatedInt_hookJs))

        # fridaHookJs_newAllText_strList = list(fridaHookJs_AllText)

        # # replace update=date
        # hookJs_updated_start, hookJs_updated_end = hookJs_curCls_Match.span("classUpdated")
        # print("hookJs %s updated: start=%d, end=%d" % (className, hookJs_updated_start, hookJs_updated_end))
        # fridaHookJs_newAllText_strList[hookJs_updated_start:hookJs_updated_end] = classUpdated_fridaUtil

        # # replce code
        # hookJs_classCode_start, hookJs_classCode_end = hookJs_curCls_Match.span("classCode")
        # print("hookJs %s classCode: start=%d, end=%d" % (className, hookJs_classCode_start, hookJs_classCode_end))
        # fridaHookJs_newAllText_strList[hookJs_classCode_start:hookJs_classCode_end] = classCode_fridaUtil

        # fridaUtil_curCls_newAllText = "".join(fridaUtil_curCls_newAllText_strList)

        # updateNewContent(hookJs_curCls_Match, hookJs_curCls_Match, fridaHookJs_AllText, classUpdated_fridaUtil, classCode_fridaUtil, fridaHookJsFile)

        # 1. generate new text
        newText = """// %s
// Updated: %s
// %s
%s""" % (classUrl, classUpdated_fridaUtil, classDescription_fridaUtil, classCode_fridaUtil)
        # 2. replace old to new text
        fridaHookJs_AllText = fridaHookJs_AllText.replace(hookJs_curCls_allText, newText)
        CommonUtil.saveTextToFile(fridaHookJsFile, fridaHookJs_AllText)
        print("Saved new content to fridaHookJsFile=%s" % fridaHookJsFile)

    else:
      print("classUpdatedInt same, so no sync/update")
      print("")

  else:
    raise Exception("Not found class info for %s" % classFileFullPath)
