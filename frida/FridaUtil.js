/*
	File: FridaUtil.js
	Function: crifan's common Frida util related functions
	Author: Crifan Li
	Latest: https://github.com/crifan/JsFridaUtil/blob/main/frida/FridaUtil.js
	Updated: 20250226
*/

// Frida Common Util
class FridaUtil {
  // for Stalker onEnter transform, is show opcode string or not
  static isShowOpcode = true

  static StringType = Object.freeze({
  // const StringType = {
    CString: "CString",
    UTF8String: "UTF8String",
    StdString: "StdString"
  })
  
  constructor() {
    console.log("FridaUtil constructor")
    console.log("FridaUtil Process.platform=" + Process.platform)
  }

  static isiOS(){
    var platform = Process.platform
    // console.log("platform=" + platform)
    var isJavaAvailable = Java.available
    // console.log("isJavaAvailable=" + isJavaAvailable)
    var isDarwin = platform === "darwin"
    // console.log("isDarwin=" + isDarwin)
    var isiOSOS = (!isJavaAvailable) && isDarwin
    // console.log("isiOSOS=" + isiOSOS)
    return isiOSOS
  }

  static isAndroid(){
    var platform = Process.platform
    // console.log("platform=" + platform)
    var isJavaAvailable = Java.available
    // console.log("isJavaAvailable=" + isJavaAvailable)
    var isLinux = platform === "linux"
    // console.log("isLinux=" + isLinux)
    var isAndroidOS = isJavaAvailable && isLinux
    // console.log("isAndroidOS=" + isAndroidOS)
    return isAndroidOS
  }

  // Frida pointer to UTF-8 string
  static ptrToUtf8Str(curPtr){
    var curUtf8Str = curPtr.readUtf8String()
    // console.log("curUtf8Str=" + curUtf8Str)
    return curUtf8Str
  }

  // Frida pointer to C string
  static ptrToCStr(curPtr){
    // var curCStr = Memory.readCString(curPtr)
    var curCStr = curPtr.readCString()
    // var curCStr = curPtr.readUtf8String()
    // console.log("curCStr=" + curCStr)
    return curCStr
  }

  // Frida pointer to C++ std::string
  static ptrToStdStr(stdStrPtr){
    var realStrPtr = null
    var firstU8 = stdStrPtr.readU8()
    // console.log("firstU8=" + firstU8)
    const isTiny = (firstU8 & 1) === 0
    // console.log("isTiny=" + isTiny)
    if (isTiny) {
      realStrPtr = stdStrPtr.add(1)
    } else {
      var realStrPtrPtr = stdStrPtr.add(2 * Process.pointerSize)
      // console.log("realStrPtrPtr=" + realStrPtrPtr)
      realStrPtr = realStrPtrPtr.readPointer()
    }
    // console.log("realStrPtr=" + realStrPtr)
    var stdUtf8Str = realStrPtr.readUtf8String()  
    // console.log("stdStrPtr=" + stdStrPtr + " -> stdUtf8Str=" + stdUtf8Str)
    return stdUtf8Str
  }

  static genModuleInfoStr(foundModule){
    // console.log("Module: name=" + foundModule.name + ", base=" + foundModule.base + ", size=" + foundModule.size + ", path=" + foundModule.path)
    var endAddress = foundModule.base.add(foundModule.size)
    var sizeHexStr = JsUtil.intToHexStr(foundModule.size)
    // console.log("Module: name=" + foundModule.name + ", address=[" + foundModule.base + "-" + endAddress + "], size=" + sizeHexStr + "=" + foundModule.size + ", path=" + foundModule.path)
    var moduleInfoStr = "Module: address=[" + foundModule.base + "-" + endAddress + "], name=" + foundModule.name + ", size=" + sizeHexStr + "=" + foundModule.size + ", path=" + foundModule.path
    return moduleInfoStr
  }

  // print module basic info: name, base, size, path
  static printModuleBasicInfo(foundModule){
    var moduleInfoStr = FridaUtil.genModuleInfoStr(foundModule)
    console.log(moduleInfoStr)
  }

  // print module symbols
  static printModuleSymbols(foundModule){
    var curSymbolList = foundModule.enumerateSymbols()
    console.log("Symbol: length=" + curSymbolList.length + ", list=" + curSymbolList)
    for(var i = 0; i < curSymbolList.length; i++) {
      console.log("---------- Symbol [" + i + "]----------")
      var curSymbol = curSymbolList[i]
      var sectionStr = JSON.stringify(curSymbol.section)
      console.log("name=" + curSymbol.name + ", address=" + curSymbol.address + "isGlobal=" + curSymbol.isGlobal + ", type=" + curSymbol.type + ", section=" + sectionStr)
    }
  }

  // print module exports
  static printModuleExports(foundModule){
    var curExportList = foundModule.enumerateExports()
    console.log("Export: length=" + curExportList.length + ", list=" + curExportList)
    for(var i = 0; i < curExportList.length; i++) {
      console.log("---------- Export [" + i + "]----------")
      var curExport = curExportList[i]
      console.log("type=" + curExport.type + ", name=" + curExport.name + ", address=" + curExport.address)
    }
  }

  // print module info
  static printModuleInfo(moduleName){
    const foundModule = Module.load(moduleName)
    // const foundModule = Module.ensureInitialized()
    console.log("foundModule=" + foundModule)
  
    if (null == foundModule) {
      return
    }

    FridaUtil.printModuleBasicInfo(foundModule)

    FridaUtil.printModuleSymbols(foundModule)
    FridaUtil.printModuleExports(foundModule)
  }

  // print process basic info
  static printProcessBasicInfo(){
    console.log(
      "Process: id=" + Process.id
      + ", currentThreadId=" + Process.getCurrentThreadId()
      + ", currentDir=" + Process.getCurrentDir()
      + ", homeDir=" + Process.getHomeDir()
      + ", tmpDir=" + Process.getTmpDir()
      + ", arch=" + Process.arch
      + ", platform=" + Process.platform
      + ", pageSize=" + Process.pageSize
      + ", pointerSize=" + Process.pointerSize
      + ", codeSigningPolicy=" + Process.codeSigningPolicy
      + ", isDebuggerAttached=" + Process.isDebuggerAttached()
    )
  }

  // print all loaded modules basic info of current process
  //  Note: similar to `image list` in lldb
  static printAllLoadedModules(isSort=true){
    FridaUtil.printProcessBasicInfo()

    var moduleList = []

    Process.enumerateModules({
      onMatch: function(module){
        // console.log('Module name: ' + module.name + " - " + "Base Address: " + module.base.toString());
        // FridaUtil.printModuleBasicInfo(module)
        moduleList.push(module)
      }, 
      onComplete: function(){}
    })

    if (isSort) {
      // moduleList.sort(function(moduleA, moduleB) {
      //   // var isLarge = moduleA.base > moduleB.base
      //   // console.log("moduleA.base=" + moduleA.base + ", moduleB.base=" + moduleB.base + " -> isLarge=" + isLarge)
      //   var addrDiff = moduleA.base - moduleB.base
      //   console.log("moduleA.base=" + moduleA.base + ", moduleB.base=" + moduleB.base + " -> addrDiff=" + addrDiff)
      //   return addrDiff
      // })
      JsUtil.sortByKey(moduleList, "base")
    }

    for(var i = 0; i < moduleList.length; i++) {
      var curModule = moduleList[i]
      // var prefixStr = "\t"
      var prefixStr = "  "
      console.log(prefixStr + FridaUtil.genModuleInfoStr(curModule))
    }

  }

  static printModuleInfoAndStalkerExclude(moduleName){
    var foundModule = Process.getModuleByName(moduleName)
    console.log("moduleName=" + moduleName + " -> foundModule=" + foundModule)
    if (null != foundModule) {
      Stalker.exclude(foundModule)
      // console.log("Stalker.exclude for module:")
      // FridaUtil.printModuleBasicInfo(foundModule)
      console.log("Stalker.exclude for: " + FridaUtil.genModuleInfoStr(foundModule))
    }
  }

  // print function call and stack, output content type is: address
  static printFunctionCallStack_addr(curContext, prefix="", isPrintDelimiter=true){
    var delimiterStr = ""
    if(isPrintDelimiter){
      // JsUtil.logStr(prefix)
      delimiterStr = JsUtil.generateLineStr(prefix, true, "=", 80) + "\n"
    }

    // const linePrefix = "\n"
    // const linePrefix = "\n\t"
    const linePrefix = "\n  "
    // const linePrefix = "\n "
    var backtracerType = Backtracer.ACCURATE
    // var backtracerType = Backtracer.FUZZY
    var stackStr = Thread.backtrace(curContext, backtracerType).map(DebugSymbol.fromAddress).join(linePrefix)

    var prefixStr = prefix
    if (!JsUtil.strIsEmpty(prefix)){
      prefixStr = prefix + " "
    }
    prefixStr = prefixStr + 'addr Stack:' + linePrefix

    var endStr = "\n"

    var fullStr = delimiterStr + prefixStr + stackStr + endStr

    console.log(fullStr)
  }

  // static dumpMemory(toDumpPtr, byteLen=128){
  static dumpMemory(toDumpPtr, prefixStr="", byteLen=128){
    var buf = toDumpPtr.readByteArray(byteLen)
    var dumpHexStr = hexdump(
      buf,
      {
        offset: 0,
        length: byteLen,
        header: true,
        ansi: true
      }
    )

    if (JsUtil.strIsEmpty(prefixStr)){
      prefixStr = `[${toDumpPtr}] `
    } else {
      prefixStr = prefixStr + " "
    }

    console.log(prefixStr + "Dump Memory:\n" + dumpHexStr)
  }

  // convert ByteArray to Opcode string
  static byteArrayToOpcodeStr(byteArr){
    var byteStrList = []
    for(var i = 0; i < byteArr.length; i++) {
      var curByte = byteArr[i]
      // console.log("curByte=" + curByte)
      var curByteStr = JsUtil.intToHexStr(curByte, "", true)
      // console.log("curByteStr=" + curByteStr)
      byteStrList.push(curByteStr)
    }
    // console.log("byteStrList=" + byteStrList)
    var opcodeStr = byteStrList.join(" ")
    // console.log("byteArr=" + byteArr + " -> opcodeStr=" + opcodeStr)
    return opcodeStr
  }

  // read byte array from address
  // Note: curAddress is NativePointer
  static readAddressByteArray(curAddress, byteSize){
    // console.log("curAddress=" + curAddress + ", byteSize=" + byteSize)
    // var instructionByteArrBuffer = curAddress.readByteArray(byteSize)
    var curByteArray = []
    for(var i = 0; i < byteSize; i++){
      var curAddr = curAddress.add(i)
      // console.log("curAddr=" + curAddr)
      var byteU8 = curAddr.readU8()
      // console.log("byteU8=" + byteU8)
      curByteArray.push(byteU8)
    }
    // console.log("curByteArray=" + curByteArray)
    return curByteArray
  }

  static genInstructionOpcodeStr(instruction){
    var instructionByteArr = FridaUtil.readAddressByteArray(instruction.address, instruction.size)
    // console.log("instructionByteArr=" + instructionByteArr)

    // var instructionOpcodeStr = hexdump(
    //   instructionByteArr,
    //   {
    //     offset: 0, 
    //     length: curInstructionSize,
    //     header: false,
    //     ansi: false
    //   }
    // )
    var instructionOpcodeStr = FridaUtil.byteArrayToOpcodeStr(instructionByteArr)
    // console.log("instructionOpcodeStr=" + instructionOpcodeStr)
    return instructionOpcodeStr
  }

  static printInstructionInfo(instruction){
    // Instruction: address=0x252c0edf8,toString()=br x10,next=0x4,size=4,mnemonic=br,opStr=x10,operands=[{"type":"reg","value":"x10","access":"r"}],regsAccessed={"read":["x10"],"written":[]},regsRead=[],regsWritten=[],groups=["jump"],toJSON()={"address":"0x252c0edf8","next":"0x4","size":4,"mnemonic":"br","opStr":"x10","operands":[{"type":"reg","value":"x10","access":"r"}],"regsAccessed":{"read":["x10"],"written":[]},"regsRead":[],"regsWritten":[],"groups":["jump"]}
    console.log("Instruction: address=" + instruction.address
      + ",toString()=" + instruction.toString()
      + ",toJSON()=" + JSON.stringify(instruction.toJSON())
      // + ",next=" + instruction.next
      // + ",size=" + instruction.size
      // + ",mnemonic=" + instruction.mnemonic
      // + ",opStr=" + instruction.opStr
      // + ",operands=" + JSON.stringify(instruction.operands)
      // + ",regsAccessed=" + JSON.stringify(instruction.regsAccessed)
      // + ",regsRead=" + JSON.stringify(instruction.regsRead)
      // + ",regsWritten=" + JSON.stringify(instruction.regsWritten)
      // + ",groups=" + JSON.stringify(instruction.groups)
    )
  }

  // Frida Stalker hoo unknown name native function
  static stalkerHookUnnameNative(moduleBaseAddress, funcRelativeStartAddr, functionSize, argNum, hookFuncMap){
    console.log("Frida Stalker hook: module: baseAddress=" + moduleBaseAddress + ", isShowOpcode=" + FridaUtil.isShowOpcode)

    var functionSizeHexStr = JsUtil.intToHexStr(functionSize)
    var funcRelativeStartAddrHexStr = JsUtil.intToHexStr(funcRelativeStartAddr)
    var funcRelativeEndAddr = funcRelativeStartAddr + functionSize
    var funcRelativeEndAddrHexStr = JsUtil.intToHexStr(funcRelativeEndAddr)
    console.log("function: relativeStartAddr=" + funcRelativeStartAddrHexStr + ", size=" + functionSize + "=" + functionSizeHexStr + ", relativeEndAddr=" + funcRelativeEndAddrHexStr)

    const funcRealStartAddr = moduleBaseAddress.add(funcRelativeStartAddr)
    // var funcRealEndAddr = funcRealStartAddr + functionSize
    const funcRealEndAddr = funcRealStartAddr.add(functionSize)
    console.log("funcRealStartAddr=" + funcRealStartAddr + ", funcRealEndAddr=" + funcRealEndAddr)
    var curTid = null
    console.log("curTid=" + curTid)
    Interceptor.attach(funcRealStartAddr, {
      onEnter: function(args) {
        JsUtil.logStr("Trigged addr: relative [" + funcRelativeStartAddrHexStr + "] = real [" + funcRealStartAddr + "]")

        for(var i = 0; i < argNum; i++) {
          var curArg = args[i]
          console.log("arg[" + i  + "]=" + curArg)
        }

        var curTid = Process.getCurrentThreadId()
        console.log("curTid=" + curTid)
        Stalker.follow(curTid, {
            events: {
              call: false, // CALL instructions: yes please            
              ret: true, // RET instructions
              exec: false, // all instructions: not recommended as it's
              block: false, // block executed: coarse execution trace
              compile: false // block compiled: useful for coverage
            },
            // onReceive: Called with `events` containing a binary blob comprised of one or more GumEvent structs. See `gumevent.h` for details about the format. Use `Stalker.parse()` to examine the data.
            onReceive(events) {
              var parsedEvents = Stalker.parse(events)
              // var parsedEventsStr = JSON.stringify(parsedEventsStr)
              // console.log(">>> into onReceive: parsedEvents=" + parsedEvents + ", parsedEventsStr=" + parsedEventsStr);
              console.log(">>> into onReceive: parsedEvents=" + parsedEvents);
            },

            // transform: (iterator: StalkerArm64Iterator) => {
            transform: function (iterator) {
              // https://www.radare.org/doc/frida/interfaces/StalkerArmIterator.html

              // console.log("iterator=" + iterator)
              var instruction = iterator.next()
              const startAddress = instruction.address
              // console.log("+++ into iterator: startAddress=" + startAddress)
              // const isAppCode = startAddress.compare(funcRealStartAddr) >= 0 && startAddress.compare(funcRealEndAddr) === -1
              // const isAppCode = (startAddress.compare(funcRealStartAddr) >= 0) && (startAddress.compare(funcRealEndAddr) < 0)
              const gt_realStartAddr = startAddress.compare(funcRealStartAddr) >= 0
              const lt_realEndAddr = startAddress.compare(funcRealEndAddr) < 0
              var isAppCode = gt_realStartAddr && lt_realEndAddr
              console.log("+++ into iterator: startAddress=" + startAddress + ", isAppCode=" + isAppCode)

              // // for debug
              // isAppCode = true

              // console.log("isAppCode=" + isAppCode + ", gt_realStartAddr=" + gt_realStartAddr + ", lt_realEndAddr=" + lt_realEndAddr)
              do {
                if (isAppCode) {
                  // is origal function code = which we focus on
                  // FridaUtil.printInstructionInfo(instruction)

                  var curRealAddr = instruction.address
                  // console.log("curRealAddr=" + curRealAddr)
                  // const isAppCode = curRealAddr.compare(funcRealStartAddr) >= 0 && curRealAddr.compare(funcRealEndAddr) === -1
                  // console.log(curRealAddr + ": isAppCode=" + isAppCode)
                  var curOffsetHexPtr = curRealAddr.sub(funcRealStartAddr)
                  var curOffsetInt = curOffsetHexPtr.toInt32()
                  console.log("current: realAddr=" + curRealAddr + " -> offset: hex=" + curOffsetHexPtr + "=" + curOffsetInt)

                  // var instructionStr = instruction.mnemonic + " " + instruction.opStr
                  var instructionStr = instruction.toString()
                  // console.log("\t" + curRealAddr + ": " + instructionStr);
                  // console.log("\t" + curRealAddr + " <+" + curOffsetHexPtr + ">: " + instructionStr)
                  // console.log("\t" + curRealAddr + " <+" + curOffsetInt + ">: " + instructionStr)

                  var opcodeStr = ""
                  if (FridaUtil.isShowOpcode) {
                    opcodeStr = " " + FridaUtil.genInstructionOpcodeStr(instruction)
                  }
                  var instructionFullLogStr = "\t" + curRealAddr + " <+" + curOffsetInt + ">" + opcodeStr + ": " + instructionStr
                  console.log(instructionFullLogStr)
                  // 0x252c0edf8 <+356>: br x10
                  // 0x252c0edf8 <+356> 40 01 1F D6: br x10

                  if (curOffsetInt in hookFuncMap){
                    console.log("offset: " + curOffsetHexPtr + "=" + curOffsetInt)
                    // let curHookFunc = hookFuncMap.get(curOffsetInt)
                    var curHookFunc = hookFuncMap[curOffsetInt]
                    // console.log("curOffsetInt=" + curOffsetInt + " -> curHookFunc=" + curHookFunc)

                    // putCallout -> https://www.radare.org/doc/frida/interfaces/StalkerArmIterator.html#putCallout
                    // StalkerScriptCallout -> https://www.radare.org/doc/frida/types/StalkerScriptCallout.html
                    // CpuContext -> https://www.radare.org/doc/frida/types/CpuContext.html
                    // Arm64CpuContext -> https://www.radare.org/doc/frida/interfaces/Arm64CpuContext.html

                    // work: normal
                    iterator.putCallout(curHookFunc)

                    // var extraDataDict = {
                    //   "curOffsetInt": curOffsetInt
                    // }
                    // Not work: abnormal
                    // iterator.putCallout((context) => {
                    // // iterator.putCallout((context, extraDataDict) => {
                    //   // console.log("match offset: " + curOffsetHexPtr + ", curRealAddr=" + curRealAddr)
                    //   // curHookFunc(context, curOffsetInt, moduleBaseAddress)
                    //   // context.curOffsetInt = curOffsetInt
                    //   // context.curOffsetHexPtr = curOffsetHexPtr
                    //   // context.moduleBaseAddress = moduleBaseAddress
                    //   // context[curOffsetInt] = curOffsetInt
                    //   // context[curOffsetHexPtr] = curOffsetHexPtr
                    //   // context[moduleBaseAddress] = moduleBaseAddress
                    //   // curHookFunc(context, extraDataDict)
                    //   curHookFunc(context)
                    // })
                  }

                }
                iterator.keep()
              } while ((instruction = iterator.next()) !== null)
            }
        });

        // function needDebug(context) {
        //     console.log("into needDebug")
        //     // console.log("into needDebug: context=" + context)
        //     // var contextStr = JSON.stringify(context, null, 2)
        //     // console.log("context=" + contextStr)
        //     // var x9Value1 = context.x9
        //     // var x9Value2 = context["x9"]
        //     // console.log("x9Value1=" + x9Value1 + ", x9Value2=" + x9Value2)
        // }
      },
      onLeave: function(retval) {
        console.log("addr: relative [" + funcRelativeStartAddrHexStr + "] real [" + funcRealStartAddr + "] -> retval=" + retval)
        if (curTid != null) {
          Stalker.unfollow(curTid)
          console.log("Stalker.unfollow curTid=", curTid)
        }
      }
    })
  }


}