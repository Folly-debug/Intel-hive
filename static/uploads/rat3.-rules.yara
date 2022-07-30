/*
   YARA Rule Set
   Author: mr R3b00t
   Date: 2022-04-11
   Identifier: rat
   Reference: http://dsec.org Malware Analysis Lab
*/

/* Rule Set ----------------------------------------------------------------- */

rule Unknown_RAT {
   meta:
      description = "rat - file Unknown_RAT.exe"
      author = "mr R3b00t"
      reference = "http://dsec.org Malware Analysis Lab"
      date = "2022-04-11"
      hash1 = "481eae82ac4cd1a9cfadc026a628b18d7b4c54f50385d28c505fbcb3e999b8b0"
   strings:
      $x1 = "yIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyTok" ascii
      $x2 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
      $s3 = "@cmd.exe /c " fullword ascii
      $s4 = "@\\\\.\\pipe\\stdin" fullword ascii
      $s5 = "nospexecProcess" fullword ascii
      $s6 = "GUID_PROCESSOR_PARKING_HEADROOM_THRESHOLD" fullword ascii
      $s7 = "GUID_PROCESSOR_PARKING_CORE_OVERRIDE" fullword ascii
      $s8 = "!GUID_PROCESSOR_PARKING_CORE_OVERRIDE" fullword ascii
      $s9 = "!GUID_PROCESSOR_PARKING_HEADROOM_THRESHOLD" fullword ascii
      $s10 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"winim\" type=\"win32\"/><dependency><dependentAssembly>" ascii
      $s11 = "@\\\\.\\pipe\\stdout" fullword ascii
      $s12 = "@net.nim(1062, 14) `size - read >= chunk` " fullword ascii
      $s13 = "@Ws2_32.dll" fullword ascii
      $s14 = "!IID_IDropTarget" fullword ascii
      $s15 = "GUID_PROCESSOR_IDLE_DISABLE" fullword ascii
      $s16 = "!GUID_PROCESSOR_PARKING_PERF_STATE" fullword ascii
      $s17 = "IID_IProcessLock" fullword ascii
      $s18 = "!GUID_PROCESSOR_CORE_PARKING_DECREASE_THRESHOLD" fullword ascii
      $s19 = "!GUID_PROCESSOR_CORE_PARKING_INCREASE_TIME" fullword ascii
      $s20 = "GUID_PROCESSOR_PERF_HISTORY" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

