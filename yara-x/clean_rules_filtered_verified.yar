import "hash"
import "elf"
import "console"
import "math"
import "time"

rule LinuxDDOS_Agent {
  meta:
    author      = "Damian Baran"
    reference   = "https://github.com/nxdamian/YARA-Public"
    type        = "info"
    severity    = 1
    description = "Search for LinuxDDOS_Agent malware"

  strings:
    $LinDDOS_1  = "eth0:%Lu %Lu %Lu %Lu %Lu %Lu %Lu %Lu %Lu"
    $LinDDOS_2  = "VERSONEX:%s|%d|%d|%s"
    $LinDDOS_3  = "Mr.Black"
    $LinDDOS_4  = "/etc/init.d/pktmak"
    $LinDDOS_5  = "code:102 write autorun script fail!"
    $LinDDOS_6  = "chmod 777 /etc/init.d/pktmake"
    $LinDDOS_7  = "ln  -s  -f  /etc/init.d/pktmake  /etc/rc2.d/S99pktmake"
    $LinDDOS_8  = "ln  -s  -f  /etc/init.d/pktmake  /etc/rc.d/rc6.d/S99pktmake"
    $LinDDOS_9  = "killall  pktmake"
    $LinDDOS_10 = "/bin/pktmak"
    $LinDDOS_11 = "./bin/pktmake -kill %"
    $LinDDOS_12 = "SendSysInfo "
    $LinDDOS_13 = "7IAttack"
    $LinDDOS_14 = "dosset.dtdb"
    $LinDDOS_15 = "47.f3322.org"
    $LinDDOS_16 = "g_bAttack"
    $LinDDOS_17 = "AttackWorker"
    $LinDDOS_18 = "DealwithDDoS"
    $LinDDOS_19 = "k00lip"
    $LinDDOS_20 = "dnsAmp"
    $LinDDOS_21 = "g_bAttack.bcopy"
    $LinDDOS_22 = "DealWithDDoS"

  condition:
    any of them
}

private rule file_elf_header {
  meta:
    description   = "Matches ELF file \x7fELF header as uint32"
    last_modified = "2024-01-02"
    author        = "@petermstewart"
    DaysofYara    = "2/100"

  condition:
    uint32(0) == 0x464c457f
}

rule Rootkit_Linux_Libprocesshider {
  meta:
    description = "Detects libprocesshider Linux process hiding library"
    author      = "mmuir@cadosecurity.com"
    date        = "2202-05-12"
    license     = "Apache License 2.0"

  strings:
    $str1 = "readdir"
    $str2 = "/proc/self/fd/"
    $str3 = "processhider.c"
    $str4 = "get_process_name"
    $str5 = "/proc/%s/stat"
    $str6 = "process_to_filter"
    $str7 = "get_dir_name"

  condition:
    uint32(0) == 0x464c457f and
    uint8(16) == 0x0003 and
    all of them
}

rule MALWARE_Linux_RansomExx {
  meta:
    author      = "ditekshen"
    description = "Detects RansomEXX ransomware"
    clamav_sig  = "MALWARE.Linux.Ransomware.RansomEXX"

  strings:
    $c1 = "crtstuff.c" fullword ascii
    $c2 = "cryptor.c" fullword ascii
    $c3 = "ransomware.c" fullword ascii
    $c4 = "logic.c" fullword ascii
    $c5 = "enum_files.c" fullword ascii
    $c6 = "readme.c" fullword ascii
    $c7 = "ctr_drbg.c" fullword ascii
    $s1 = "regenerate_pre_data" fullword ascii
    $s2 = "g_RansomHeader" fullword ascii
    $s3 = "CryptOneBlock" fullword ascii
    $s4 = "RansomLogic" fullword ascii
    $s5 = "CryptOneFile" fullword ascii
    $s6 = "encrypt_worker" fullword ascii
    $s7 = "list_dir" fullword ascii
    $s8 = "ctr_drbg_update_internal" fullword ascii

  condition:
    uint16(0) == 0x457f and (5 of ($s*) or 6 of ($s*) or (3 of ($c*) and 3 of ($s*)))
}

private rule ESET_Apachemodule_PRIVATE {
  meta:
    description = "Apache 2.4 module ELF shared library"
    author      = "ESET, spol. s r.o."
    id          = "2082e50e-1726-5540-a962-e0aeca1ebaaf"
    date        = "2024-04-27"
    modified    = "2024-04-27"
    reference   = "https://github.com/eset/malware-ioc/"
    source_url  = "https://github.com/eset/malware-ioc/blob/21381c70ad030105cf9edb092dfd1cae29753286/windigo/helimod.yar#L3-L30"
    license_url = "https://github.com/eset/malware-ioc/blob/21381c70ad030105cf9edb092dfd1cae29753286/LICENSE"
    hash        = "e39667aa137e315bc26eaef791ccab52938fd809"
    logic_hash  = "213fe381aa0bf9f148e488f7af74ac63073776c2868e42d2dcca7fdbca55fabb"
    score       = 75
    quality     = 80
    tags        = ""
    license     = "BSD 2-Clause"
    version     = 1

  strings:
    $magic = "42PA"

  condition:
    for any s in elf.dynsym: (s.type == elf.STT_OBJECT and for any seg in elf.segments: (seg.type == elf.PT_LOAD and s.value >= seg.virtual_address and s.value < (seg.virtual_address + seg.file_size) and $magic at (s.value - seg.virtual_address + seg.offset) + 0x28))
}

rule P2PinfectBash {
  meta:
    author      = "nbill@cadosecurity.com"
    description = "Detects P2Pinfect bash payload"

  strings:
    $h1 = { 4C 89 EF 48 89 DE 48 8D 15 ?? ?? ?? 00 6A 0A 59 E8 17 6C 01 00 84 C0 0F 85 0F 03 00 00 }
    $h2 = { 48 8B 9C 24 ?? ?? 00 00 4C 89 EF 48 89 DE 48 8D 15 ?? ?? ?? 00 6A 09 59 E8 34 6C 01 00 84 C0 0F 85 AC 02 00 00 }
    $h3 = { 4C 89 EF 48 89 DE 48 8D 15 ?? ?? ?? 00 6A 03 59 E8 DD 6B 01 00 84 C0 0F 85 DF 03 00 00 }

  condition:
    uint16(0) == 0x457f and all of them
}

rule Linux_Trojan_Pumakit {
  meta:
    author        = "Elastic Security"
    creation_date = "2024-12-09"
    last_modified = "2024-12-09"
    os            = "Linux"
    arch          = "x86, arm64"
    threat_name   = "Linux.Trojan.Pumakit"

  strings:
    $str1  = "PUMA %s"
    $str2  = "Kitsune PID %ld"
    $str3  = "/usr/share/zov_f"
    $str4  = "zarya"
    $str5  = ".puma-config"
    $str6  = "ping_interval_s"
    $str7  = "session_timeout_s"
    $str8  = "c2_timeout_s"
    $str9  = "LD_PRELOAD=/lib64/libs.so"
    $str10 = "kit_so_len"
    $str11 = "opsecurity1.art"
    $str12 = "89.23.113.204"

  condition:
    4 of them
}

rule ELF_Chaos_RAT {
  meta:
    description = "Detects Linux ELF binaries <10MB with indicators of CHAOS-RAT-generated payloads"
    author      = "Acronis TRU"
    date        = "2025-04-16"

  strings:
    $chaos    = "tiagorlampert/CHAOS" ascii
    $library1 = "BurntSushi/xgb" ascii
    $library2 = "gen2brain/shm" ascii
    $library3 = "kbinani/screenshot" ascii

  condition:
    uint32(0) == 0x464c457f and  // ELF magic number in little-endian
    filesize < 10MB and $chaos and
    2 of ($library*)
}

rule EquationGroup_cryptTool {
  meta:
    description = "Equation Group hack tool leaked by ShadowBrokers- file cryptTool"
    author      = "Florian Roth"
    reference   = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    date        = "2017-04-08"
    hash1       = "96947ad30a2ab15ca5ef53ba8969b9d9a89c48a403e8b22dd5698145ac6695d2"

  strings:
    $s1 = "The encryption key is " fullword ascii
    $s2 = "___tempFile2.out" fullword ascii

  condition:
    (uint16(0) == 0x457f and filesize < 200KB and all of them)
}

rule EquationGroup_slugger2 {
  meta:
    description = "Equation Group hack tool leaked by ShadowBrokers- file slugger2"
    author      = "Florian Roth"
    reference   = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    date        = "2017-04-08"
    hash1       = "a6a9ab66d73e4b443a80a69ef55a64da7f0af08dfaa7e17eb19c327301a70bdf"

  strings:
    $x1 = "usage: %s hostip port cmd [printer_name]" fullword ascii
    $x2 = "command must be less than 61 chars" fullword ascii

    $s1 = "__rw_read_waiting" fullword ascii
    $s2 = "completed.1" fullword ascii
    $s3 = "__mutexkind" fullword ascii
    $s4 = "__rw_pshared" fullword ascii

  condition:
    (uint16(0) == 0x457f and filesize < 50KB and (4 of them and 1 of ($x*))) or (all of them)
}

rule EQGRP_bo {
  meta:
    description = "EQGRP Toolset Firewall - file bo"
    author      = "Florian Roth"
    reference   = "Research"
    date        = "2016-08-16"
    hash1       = "aa8b363073e8ae754b1836c30f440d7619890ded92fb5b97c73294b15d22441d"

  strings:
    $s1 = "ERROR: failed to open %s: %d" fullword ascii
    $s2 = "__libc_start_main@@GLIBC_2.0" fullword ascii
    $s3 = "serial number: %s" fullword ascii
    $s4 = "strerror@@GLIBC_2.0" fullword ascii
    $s5 = "ERROR: mmap failed: %d" fullword ascii

  condition:
    (uint16(0) == 0x457f and filesize < 20KB and all of them)
}

rule Hajime_generic_ARCH: MALW {
  meta:
    description = "Hajime Botnet - generic arch"
    author      = "Joan Soriano / @joanbtl"
    date        = "2017-05-01"
    version     = "1.0"
    MD5         = "77122e0e6fcf18df9572d80c4eedd88d"
    SHA1        = "108ee460d4c11ea373b7bba92086dd8023c0654f"
    ref1        = "https://www.symantec.com/connect/blogs/hajime-worm-battles-mirai-control-internet-things/"
    ref2        = "https://security.rapiditynetworks.com/publications/2016-10-16/hajime.pdf"

  strings:
    $userpass = "%d (!=0),user/pass auth will not work, ignored.\n"
    $etcTZ    = "/etc/TZ"
    $Mvrs     = ",M4.1.0,M10.5.0"
    $bld      = "%u.%u.%u.%u.in-addr.arpa"

  condition:
    $userpass and $etcTZ and $Mvrs and $bld

}

rule Hajime_MIPS: MALW {
  meta:
    description = "Hajime Botnet - MIPS"
    author      = "Joan Soriano / @joanbtl"
    date        = "2017-05-01"
    version     = "1.0"
    MD5         = "77122e0e6fcf18df9572d80c4eedd88d"
    SHA1        = "108ee460d4c11ea373b7bba92086dd8023c0654f"
    ref1        = "https://www.symantec.com/connect/blogs/hajime-worm-battles-mirai-control-internet-things/"
    ref2        = "https://security.rapiditynetworks.com/publications/2016-10-16/hajime.pdf"

  strings:
    $userpass = "%d (!=0),user/pass auth will not work, ignored.\n"
    $etcTZ    = "/etc/TZ"
    $Mvrs     = ",M4.1.0,M10.5.0"
    $bld      = "%u.%u.%u.%u.in-addr.arpa"

  condition:
    $userpass and $etcTZ and $Mvrs and $bld and hash.sha1(0, filesize) == "108ee460d4c11ea373b7bba92086dd8023c0654f"

}

rule Hajime_ARM5: MALW {
  meta:
    description = "Hajime Botnet - ARM5"
    author      = "Joan Soriano / @joanbtl"
    date        = "2017-05-01"
    version     = "1.0"
    MD5         = "d8821a03b9dc484144285d9051e0b2d3"
    SHA1        = "89ec638b95b289dbce0535b4a2c5aad90c169d06"
    ref1        = "https://www.symantec.com/connect/blogs/hajime-worm-battles-mirai-control-internet-things/"
    ref2        = "https://security.rapiditynetworks.com/publications/2016-10-16/hajime.pdf"

  strings:
    $userpass = "%d (!=0),user/pass auth will not work, ignored.\n"
    $etcTZ    = "/etc/TZ"
    $Mvrs     = ",M4.1.0,M10.5.0"
    $bld      = "%u.%u.%u.%u.in-addr.arpa"

  condition:
    $userpass and $etcTZ and $Mvrs and $bld and hash.sha1(0, filesize) == "89ec638b95b289dbce0535b4a2c5aad90c169d06"

}

rule Hajime_SH4: MALW {
  meta:
    description = "Hajime Botnet - SH4"
    author      = "Joan Soriano / @joanbtl"
    date        = "2017-05-01"
    version     = "1.0"
    MD5         = "6f39d7311091166a285fb0654b454761"
    SHA1        = "3ed95ead04e59a2833538541978b79a9a8cb5290"
    ref1        = "https://www.symantec.com/connect/blogs/hajime-worm-battles-mirai-control-internet-things/"
    ref2        = "https://security.rapiditynetworks.com/publications/2016-10-16/hajime.pdf"

  strings:
    $userpass = "%d (!=0),user/pass auth will not work, ignored.\n"
    $etcTZ    = "/etc/TZ"
    $Mvrs     = ",M4.1.0,M10.5.0"
    $bld      = "%u.%u.%u.%u.in-addr.arpa"

  condition:
    $userpass and $etcTZ and $Mvrs and $bld and hash.sha1(0, filesize) == "3ed95ead04e59a2833538541978b79a9a8cb5290"

}

rule Hajime_DOWNLOADER: MALW {
  meta:
    description = "Hajime Botnet - Downloader"
    author      = "Joan Soriano / @joanbtl"
    date        = "2017-05-01"
    version     = "1.0"
    MD5         = "f1cc4275d29b7eaa92a4cca015af227e"
    SHA1        = "e649e0d97cc23c8c4bbd78be430a49a4babbccd7"
    ref1        = "https://www.symantec.com/connect/blogs/hajime-worm-battles-mirai-control-internet-things/"
    ref2        = "https://security.rapiditynetworks.com/publications/2016-10-16/hajime.pdf"

  strings:
    $get = "GET /r/sr.arm5 HTTP/1.0"
    $nif = "NIF\n"

  condition:
    $get and $nif and filesize < 700KB and hash.sha1(0, filesize) == "e649e0d97cc23c8c4bbd78be430a49a4babbccd7"

}

rule LinuxBew: MALW {
  meta:
    description = "Linux.Bew Backdoor"
    author      = "Joan Soriano / @w0lfvan"
    date        = "2017-07-10"
    version     = "1.0"
    MD5         = "27d857e12b9be5d43f935b8cc86eaabf"
    SHA256      = "80c4d1a1ef433ac44c4fe72e6ca42395261fbca36eff243b07438263a1b1cf06"

  strings:
    $a = "src/secp256k1.c"
    $b = "hfir.u230.org"
    $c = "tempfile-x11session"

  condition:
    all of them
}

rule LinuxHelios: MALW {
  meta:
    description = "Linux.Helios"
    author      = "Joan Soriano / @w0lfvan"
    date        = "2017-10-19"
    version     = "1.0"
    MD5         = "1a35193f3761662a9a1bd38b66327f49"
    SHA256      = "72c2e804f185bef777e854fe86cff3e86f00290f32ae8b3cb56deedf201f1719"

  strings:
    $a = "LIKE A GOD!!! IP:%s User:%s Pass:%s"
    $b = "smack"
    $c = "PEACE OUT IMMA DUP\n"

  condition:
    all of them
}

rule LuaBot: MALW {
  meta:
    description = "LuaBot"
    author      = "Joan Soriano / @joanbtl"
    date        = "2017-06-07"
    version     = "1.0"
    MD5         = "9df3372f058874fa964548cbb74c74bf"
    SHA1        = "89226865501ee7d399354656d870b4a9c02db1d3"
    ref1        = "http://blog.malwaremustdie.org/2016/09/mmd-0057-2016-new-elf-botnet-linuxluabot.html"

  strings:
    $a = "LUA_PATH"
    $b = "Hi. Happy reversing, you can mail me: luabot@yandex.ru"
    $c = "/tmp/lua_XXXXXX"
    $d = "NOTIFY"
    $e = "UPDATE"

  condition:
    all of them
}

rule Mirai_1: MALW {
  meta:
    description = "Mirai Variant 1"
    author      = "Joan Soriano / @joanbtl"
    date        = "2017-04-16"
    version     = "1.0"
    MD5         = "655c3cf460489a7d032c37cd5b84a3a8"
    SHA1        = "4dd3803956bc31c8c7c504734bddec47a1b57d58"

  strings:
    $dir1  = "/dev/watchdog"
    $dir2  = "/dev/misc/watchdog"
    $pass1 = "PMMV"
    $pass2 = "FGDCWNV"
    $pass3 = "OMVJGP"

  condition:
    $dir1 and $pass1 and $pass2 and not $pass3 and not $dir2

}

rule Mirai_2: MALW {
  meta:
    description = "Mirai Variant 2"
    author      = "Joan Soriano / @joanbtl"
    date        = "2017-04-16"
    version     = "1.0"
    MD5         = "0e5bda9d39b03ce79ab8d421b90c0067"
    SHA1        = "96f42a9fad2923281d21eca7ecdd3161d2b61655"

  strings:
    $dir1 = "/dev/watchdog"
    $dir2 = "/dev/misc/watchdog"
    $s1   = "PMMV"
    $s2   = "ZOJFKRA"
    $s3   = "FGDCWNV"
    $s4   = "OMVJGP"

  condition:
    $dir1 and $dir2 and $s1 and $s2 and $s3 and not $s4

}

rule Mirai_3: MALW {
  meta:
    description = "Mirai Variant 3"
    author      = "Joan Soriano / @joanbtl"
    date        = "2017-04-16"
    version     = "1.0"
    MD5         = "bb22b1c921ad8fa358d985ff1e51a5b8"
    SHA1        = "432ef83c7692e304c621924bc961d95c4aea0c00"

  strings:
    $dir1 = "/dev/watchdog"
    $dir2 = "/dev/misc/watchdog"
    $s1   = "PMMV"
    $s2   = "ZOJFKRA"
    $s3   = "FGDCWNV"
    $s4   = "OMVJGP"
    $ssl  = "ssl3_ctrl"

  condition:
    $dir1 and $dir2 and $s1 and $s2 and $s3 and $s4 and not $ssl

}

rule Mirai_4: MALW {
  meta:
    description = "Mirai Variant 4"
    author      = "Joan Soriano / @joanbtl"
    date        = "2017-04-16"
    version     = "1.0"
    MD5         = "f832ef7a4fcd252463adddfa14db43fb"
    SHA1        = "4455d237aadaf28aafce57097144beac92e55110"

  strings:
    $s1 = "210765"
    $s2 = "qllw"
    $s3 = ";;;;;;"

  condition:
    $s1 and $s2 and $s3
}

rule Mirai_Dwnl: MALW {
  meta:
    description = "Mirai Downloader"
    author      = "Joan Soriano / @joanbtl"
    date        = "2017-04-16"
    version     = "1.0"
    MD5         = "85784b54dee0b7c16c57e3a3a01db7e6"
    SHA1        = "6f6c625ef730beefbc23c7f362af329426607dee"

  strings:
    $s1 = "GET /mirai/"
    $s2 = "dvrHelper"

  condition:
    $s1 and $s2
}

rule Mirai_5: MALW {
  meta:
    description = "Mirai Variant 5"
    author      = "Joan Soriano / @joanbtl"
    date        = "2017-04-16"
    version     = "1.0"
    MD5         = "7e17c34cddcaeb6755c457b99a8dfe32"
    SHA1        = "b63271672d6a044704836d542d92b98e2316ad24"

  strings:
    $dir1 = "/dev/watchdog"
    $dir2 = "/dev/misc/watchdog"
    $s1   = "PMMV"
    $s2   = "ZOJFKRA"
    $s3   = "FGDCWNV"
    $s4   = "OMVJGP"
    $ssl  = "ssl3_ctrl"

  condition:
    $dir1 and $dir2 and $s1 and $s2 and $s3 and $s4 and $ssl

}

rule ELF_Linux_Torte_domains {
  meta:
    author      = "@mmorenog,@yararules"
    description = "Detects ELF Linux/Torte infection"
    ref1        = "http://blog.malwaremustdie.org/2016/01/mmd-0050-2016-incident-report-elf.html"

  strings:
    $1 = "pages.touchpadz.com" ascii wide nocase
    $2 = "bat.touchpadz.com" ascii wide nocase
    $3 = "stat.touchpadz.com" ascii wide nocase
    $4 = "sk2.touchpadz.com" ascii wide nocase

  condition:
    any of them
}

rule ggupdate_linux {
  meta:
    description = "ggupdate keylogger (Linux)"

  strings:
    // 4611DAA8CF018B897A76FBAB51665C62
    $s1 = "%s.Identifier"
    $s2 = "0:%llu:%s;"
    $s3 = "%s%.2d-%.2d-%.4d"
    $s4 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]"

  condition:
    file_elf_header and 3 of them
}

rule jellyfish_gpu_rootkit_server: malware linux rootkit {
  meta:
    author      = "@h3x2b <tracker@h3x.eu>"
    description = "Detects Jellyfish samples - 201505"
  //Check also:
  //http://tracker.h3x.eu/corpus/690
  //http://tracker.h3x.eu/info/690
  //Samples:
  //057a8ff761b5768f1fa82a463d2bdbf8  jellyfish-master.zip

  strings:
    $m_01 = "gpu.txt"

    $o_01 = "socket failed!"
    $o_02 = "couldn't bind socket!"
    $o_03 = "couldn't setup listener socket!"
    $o_04 = "accept() socket failed!"
    $o_05 = "recv() failed! trying again...\n"
    $o_06 = "%s  |  Logged to gpu.txt\n"

  condition:
    //ELF magic
    uint32(0) == 0x464c457f and

    //Contains all mandatory strings
    all of ($m_*) and

    //Contains some optional strings
    4 of ($o_*)

}

rule mirai_20161004: malware linux {
  meta:
    author      = "@h3x2b <tracker@h3x.eu>"
    description = "Detects Mirai samples - 20161004"
  //Check also:
  //http://tracker.h3x.eu/corpus/680
  //http://tracker.h3x.eu/info/680
  //http://blog.malwaremustdie.org/2016/08/mmd-0056-2016-linuxmirai-just.html

  strings:
    $mirai_00 = "/dev/null"
    $mirai_01 = "LCOGQGPTGP"

  condition:
    //ELF magic
    uint32(0) == 0x464c457f and

    //Contains all of the strings
    all of ($mirai_*)
}

rule stdbot_std: malware linux {
  meta:
    author      = "@h3x2b <tracker@h3x.eu>"
    description = "Detects STDbot samples - 20161009"
  //Check also:
  //http://tracker.h3x.eu/corpus/760
  //http://tracker.h3x.eu/info/760
  //http://blog.malwaremustdie.org/2016/02/mmd-0052-2016-skidddos-elf-distribution.html
  //http://blog.malwaremustdie.org/2016/04/mmd-0053-2016-bit-about-elfstd-irc-bot.html

  strings:
    $irc_00 = "CONNECT"
    $irc_01 = "NICK"
    $irc_02 = "PING"
    $irc_03 = "JOIN"

    $std_00 = ":>bot +std"
    $std_01 = "PRIVMSG"
    $std_02 = "[STD]Hitting"

  condition:
    //ELF magic
    uint32(0) == 0x464c457f and

    //Contains all of the IRC strings
    all of ($irc_*) and

    //Contains all of the strings
    all of ($std_*)
}

rule stdbot_std2: malware linux {
  meta:
    author      = "@h3x2b <tracker@h3x.eu>"
    description = "Detects STDbot samples - 20161009"
  //Check also:
  //http://tracker.h3x.eu/corpus/760
  //http://tracker.h3x.eu/info/760
  //http://blog.malwaremustdie.org/2016/04/mmd-0053-2016-bit-about-elfstd-irc-bot.html
  //Samples:
  //fa856be9e8018c3a7d4d2351398192d8  pty
  //80ffb3ad788b73397ce84b1aadf99b  tty0
  //d47a5da273175a5971638995146e8056  tty1
  //2c1b9924092130f5c241afcedfb1b198  tty2
  //f6fc2dc7e6fa584186a3ed8bc96932ca  tty3
  //b629686b475eeec7c47daa72ec5dffc0  tty4
  //c97f99cdafcef0ac7b484e79ca7ed503  tty5

  strings:
    $std_00 = "shitteru koto dake"
    $std_01 = "nandemo wa shiranai wa yo"

  condition:
    //ELF magic
    uint32(0) == 0x464c457f and

    //Contains all of the strings
    all of ($std_*)
}

rule torlus_server: malware linux {
  meta:
    author      = "@h3x2b <tracker@h3x.eu>"
    description = "Detects Torlus/LizKebab/GayFgt/Bashdoor server samples"
  //Check also:
  //http://tracker.h3x.eu/corpus/690
  //http://tracker.h3x.eu/info/690
  //Samples:
  //https://github.com/gh0std4ncer/lizkebab/blob/master/client.c

  strings:
    $cmd_00 = "PING"
    $cmd_01 = "PONG"
    $cmd_02 = "BUILD"
    $cmd_03 = "REPORT"

    $msg_01 = "!* SCANNER ON\n"
    $msg_02 = "!* FATCOCK\n"
    $msg_03 = "buf: \"%s\"\n"
    $msg_04 = "%c]0;Bots connected: %d | Clients connected: %d%c"
    $msg_05 = "WELCOME TO THE BALL PIT"

  condition:
    //ELF magic
    uint32(0) == 0x464c457f and

    //Contains majority of commands
    4 of ($cmd_*) and

    //Contains some message strings
    2 of ($msg_*)

}

rule venom_20170125: malware linux {
  meta:
    author      = "@h3x2b <tracker@h3x.eu>"
    description = "Detects Venom samples - 20170125"
  // Check also:
  // https://wiki.egi.eu/w/images/c/ce/Report-venom.pdf

  strings:
    $venom_00 = "justCANTbeSTOPPED"
    $venom_01 = "%%VENOM%AUTHENTICATE%%"
    $venom_02 = "%%VENOM%OK%OK%%"

  condition:
    //ELF magic
    uint32(0) == 0x464c457f and

    //Contains all of the strings
    all of ($venom_*)
}

rule dropperMapin {
  meta:
    author      = "https://twitter.com/plutec_net"
    source      = "https://koodous.com/"
    reference   = "http://www.welivesecurity.com/2015/09/22/android-trojan-drops-in-despite-googles-bouncer/"
    description = "This rule detects mapin dropper files"
    sample      = "7e97b234a5f169e41a2d6d35fadc786f26d35d7ca60ab646fff947a294138768"
    sample2     = "bfd13f624446a2ce8dec9006a16ae2737effbc4e79249fd3d8ea2dc1ec809f1a"

  strings:
    $a = ":Write APK file (from txt in assets) to SDCard sucessfully!"
    $b = "4Write APK (from Txt in assets) file to SDCard  Fail!"
    $c = "device_admin"

  condition:
    all of them
}

rule Mapin {
  meta:
    author      = "https://twitter.com/plutec_net"
    source      = "https://koodous.com/"
    reference   = "http://www.welivesecurity.com/2015/09/22/android-trojan-drops-in-despite-googles-bouncer/"
    description = "Mapin trojan, not for droppers"
    sample      = "7f208d0acee62712f3fa04b0c2744c671b3a49781959aaf6f72c2c6672d53776"

  strings:
    $a = "138675150963"  //GCM id
    $b = "res/xml/device_admin.xml"
    $c = "Device registered: regId ="

  condition:
    all of them

}

rule koler_D {
  meta:
    description = "Koler.D class"

  strings:
    $0 = "ZActivity"
    $a = "Lcom/android/zics/ZRuntimeInterface"

  condition:
    ($0 and $a)

}

rule android_tempting_cedar_spyware {
  meta:
    Author    = "@X0RC1SM"
    Date      = "2018-03-06"
    Reference = "https://blog.avast.com/avast-tracks-down-tempting-cedar-spyware"

  strings:
    $PK_HEADER = { 50 4B 03 04 }
    $MANIFEST  = "META-INF/MANIFEST.MF"
    $DEX_FILE  = "classes.dex"
    $string    = "rsdroid.crt"

  condition:
    $PK_HEADER in (0..4) and $MANIFEST and $DEX_FILE and any of ($string*)
}

rule single_load_rwe {
  meta:
    description = "Flags binaries with a single LOAD segment marked as RWE."
    family      = "Stager"
    filetype    = "ELF"
    hash        = "711a06265c71a7157ef1732c56e02a992e56e9d9383ca0f6d98cd96a30e37299"

  condition:
    elf.segments.len() == 1 and
    elf.segments[0].type == elf.PT_LOAD and
    elf.segments[0].flags == elf.PF_R | elf.PF_W | elf.PF_X
}

rule fake_section_headers_conflicting_entry_point_address {
  meta:
    description = "A fake sections header has been added to the binary."
    family      = "Obfuscation"
    filetype    = "ELF"
    hash        = "a2301180df014f216d34cec8a6a6549638925ae21995779c2d7d2827256a8447"

  condition:
    elf.type == elf.ET_EXEC and
    elf.entry_point < filesize and  // file scanning only
    elf.segments.len() > 0 and
    elf.sections.len() > 0 and
    not
    (
      for any i in (0..elf.segments.len()):
      (
        (elf.segments[i].offset <= elf.entry_point) and
        ((elf.segments[i].offset + elf.segments[i].file_size) >= elf.entry_point) and
        for any j in (0..elf.sections.len()):
        (
          elf.sections[j].offset <= elf.entry_point and
          ((elf.sections[j].offset + elf.sections[j].size) >= elf.entry_point) and
          (elf.segments[i].virtual_address + (elf.entry_point - elf.segments[i].offset)) ==
          (elf.sections[j].address + (elf.entry_point - elf.sections[j].offset))
        )
      )
    )
}

rule fake_dynamic_symbols {
  meta:
    description = "A fake dynamic symbol table has been added to the binary"
    family      = "Obfuscation"
    filetype    = "ELF"
    hash        = "51676ae7e151a0b906c3a8ad34f474cb5b65eaa3bf40bb09b00c624747bcb241"

  condition:
    elf.type == elf.ET_EXEC and
    elf.entry_point < filesize and  // file scanning only
    elf.sections.len() > 0 and
    elf.dynamic_section_entries > 0 and
    for any i in (0..elf.dynamic_section_entries):
    (
      elf.dynamic[i].type == elf.DT_SYMTAB and
      not
      (
        for any j in (0..elf.sections.len()):
        (
          elf.sections[j].type == elf.SHT_DYNSYM and
          for any k in (0..elf.segments.len()):
          (
            (elf.segments[k].virtual_address <= elf.dynamic[i].val) and
            ((elf.segments[k].virtual_address + elf.segments[k].file_size) >= elf.dynamic[i].val) and
            (elf.segments[k].offset + (elf.dynamic[i].val - elf.segments[k].virtual_address)) == elf.sections[j].offset
          )
        )
      )
    )
}

rule venom {
  meta:
    description = "Venom Linux Rootkit"
    author      = "Rich Walchuck"
    source      = "https://security.web.cern.ch/security/venom.shtml"
    hash        = "a5f4fc353794658a5ca2471686980569"
    date        = "2017-01-31"

  strings:
    $string0 = "%%VENOM%OK%OK%%"
    $string1 = "%%VENOM%WIN%WN%%"
    $string2 = "%%VENOM%CTRL%MODE%%"
    $string3 = "%%VENOM%AUTHENTICATE%%"
    $string4 = "venom by mouzone"
    $string5 = "justCANTbeSTOPPED"

  condition:
    any of them
}

rule Banker {
  meta:
    description = "Detects a Banker"
    author      = "vitorafonso"
    sample      = "e5df30b41b0c50594c2b77c1d5d6916a9ce925f792c563f692426c2d50aa2524"
    report      = "https://blog.fortinet.com/2016/11/01/android-banking-malware-masquerades-as-flash-player-targeting-large-banks-and-popular-social-media-apps"

  strings:
    $a1  = "kill_on"
    $a2  = "intercept_down"
    $a3  = "send_sms"
    $a4  = "check_manager_status"
    $a5  = "browserappsupdate"
    $a6  = "YnJvd3NlcmFwcHN1cGRhdGU="  // browserappsupdate
    $a7  = "browserrestart"
    $a8  = "YnJvd3NlcnJlc3RhcnQ="  // browserrestart
    $a9  = "setMobileDataEnabled"
    $a10 = "adminPhone"

  condition:
    8 of ($a*)

}

rule APT_MAL_LNX_Turla_Apr202004_1 {
  meta:
    description = "Detects Turla Linux malware x64 x32"
    date        = "2020-04-24"
    author      = "Leonardo S.p.A."
    reference   = "https://www.leonardocompany.com/en/news-and-stories-detail/-/detail/knowledge-the-basis-of-protection"
    hash1       = "67d9556c695ef6c51abf6fbab17acb3466e3149cf4d20cb64d6d34dc969b6502"
    hash2       = "8ccc081d4940c5d8aa6b782c16ed82528c0885bbb08210a8d0a8c519c54215bc"
    hash3       = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667"
    hash4       = "1d5e4466a6c5723cd30caf8b1c3d33d1a3d4c94c25e2ebe186c02b8b41daf905"
    hash5       = "2dabb2c5c04da560a6b56dbaa565d1eab8189d1fa4a85557a22157877065ea08"
    hash6       = "3e138e4e34c6eed3506efc7c805fce19af13bd62aeb35544f81f111e83b5d0d4"
    hash7       = "5a204263cac112318cd162f1c372437abf7f2092902b05e943e8784869629dd8"
    hash8       = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667"
    hash9       = "d49690ccb82ff9d42d3ee9d7da693fd7d302734562de088e9298413d56b86ed0"

  strings:
    $ = "/root/.hsperfdata" ascii fullword
    $ = "Desc| Filename | size |state|" ascii fullword
    $ = "VS filesystem: %s" ascii fullword
    $ = "File already exist on remote filesystem !" ascii fullword
    $ = "/tmp/.sync.pid" ascii fullword
    $ = "rem_fd: ssl " ascii fullword
    $ = "TREX_PID=%u" ascii fullword
    $ = "/tmp/.xdfg" ascii fullword
    $ = "__we_are_happy__" ascii fullword
    $ = "/root/.sess" ascii fullword
  /* $ = "ZYSZLRTS^Z@@NM@@G_Y_FE" ascii fullword */

  condition:
    uint16(0) == 0x457f and filesize < 5000KB and
    4 of them
}

rule Mirai_Botnet_Malware {
  meta:
    description = "Detects Mirai Botnet Malware"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Florian Roth"
    reference   = "Internal Research"
    date        = "2016-10-04"
    hash1       = "05c78c3052b390435e53a87e3d31e9fb17f7c76bb4df2814313bca24735ce81c"
    hash2       = "05c78c3052b390435e53a87e3d31e9fb17f7c76bb4df2814313bca24735ce81c"
    hash3       = "20683ff7a5fec1237fc09224af40be029b9548c62c693844624089af568c89d4"
    hash4       = "2efa09c124f277be2199bee58f49fc0ce6c64c0bef30079dfb3d94a6de492a69"
    hash5       = "420bf9215dfb04e5008c5e522eee9946599e2b323b17f17919cd802ebb012175"
    hash6       = "62cdc8b7fffbaf5683a466f6503c03e68a15413a90f6afd5a13ba027631460c6"
    hash7       = "70bb0ec35dd9afcfd52ec4e1d920e7045dc51dca0573cd4c753987c9d79405c0"
    hash8       = "89570ae59462e6472b6769545a999bde8457e47ae0d385caaa3499ab735b8147"
    hash9       = "bf0471b37dba7939524a30d7d5afc8fcfb8d4a7c9954343196737e72ea4e2dc4"
    hash10      = "c61bf95146c68bfbbe01d7695337ed0e93ea759f59f651799f07eecdb339f83f"
    hash11      = "d9573c3850e2ae35f371dff977fc3e5282a5e67db8e3274fd7818e8273fd5c89"
    hash12      = "f1100c84abff05e0501e77781160d9815628e7fd2de9e53f5454dbcac7c84ca5"
    hash13      = "fb713ccf839362bf0fbe01aedd6796f4d74521b133011b408e42c1fd9ab8246b"

  strings:
    $x1 = "POST /cdn-cgi/" fullword ascii
    $x2 = "/dev/misc/watchdog" fullword ascii
    $x3 = "/dev/watchdog" ascii
    $x4 = "\\POST /cdn-cgi/" fullword ascii
    $x5 = ".mdebug.abi32" fullword ascii

    $s1 = "LCOGQGPTGP" fullword ascii
    $s2 = "QUKLEKLUKVJOG" fullword ascii
    $s3 = "CFOKLKQVPCVMP" fullword ascii
    $s4 = "QWRGPTKQMP" fullword ascii
    $s5 = "HWCLVGAJ" fullword ascii
    $s6 = "NKQVGLKLE" fullword ascii

  condition:
    uint16(0) == 0x457f and filesize < 200KB and
    (
      (1 of ($x*) and 1 of ($s*)) or
      4 of ($s*)
    )
}

rule miner_g_p_0 {
  meta:
    description = "miner-exe - from files g, p"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-22"
    hash1       = "7fe9d6d8b9390020862ca7dc9e69c1e2b676db5898e4bfad51d66250e9af3eaf"
    hash2       = "63210b24f42c05b2c5f8fd62e98dba6de45c7d751a2e55700d22983772886017"

  strings:
    $s1  = "TLS generation counter wrapped!  Please report as described in <http://www.debian.org/Bugs/>." fullword ascii
    $s2  = "%s: Symbol `%s' has different size in shared object, consider re-linking" fullword ascii
    $s3  = "relocation processing: %s%s" fullword ascii
    $s4  = "ELF load command address/offset not properly aligned" fullword ascii
    $s5  = "version == ((void *)0) || (flags & ~(DL_LOOKUP_ADD_DEPENDENCY | DL_LOOKUP_GSCOPE_LOCK)) == 0" fullword ascii
    $s6  = "%s%s%s:%u: %s%sAssertion `%s' failed." fullword ascii
    $s7  = "__pthread_mutex_lock" fullword ascii
    $s8  = "lead_zero <= (uintmax_t) ((9223372036854775807L) - 16384 - 3) / 4" fullword ascii
    $s9  = "lead_zero <= (uintmax_t) ((9223372036854775807L) - 1024 - 3) / 4" fullword ascii
    $s10 = "int_no <= (uintmax_t) ((9223372036854775807L) + (-1021) - 53) / 4" fullword ascii
    $s11 = "int_no <= (uintmax_t) ((9223372036854775807L) + (-125) - 24) / 4" fullword ascii
    $s12 = "int_no <= (uintmax_t) ((9223372036854775807L) + (-16381) - 64) / 4" fullword ascii
    $s13 = "headmap.len == archive_stat.st_size" fullword ascii
    $s14 = "lead_zero <= (uintmax_t) ((9223372036854775807L) - 4932 - 1)" fullword ascii
    $s15 = "lead_zero <= (uintmax_t) ((9223372036854775807L) - 38 - 1)" fullword ascii
    $s16 = "lead_zero <= (uintmax_t) ((9223372036854775807L) - 308 - 1)" fullword ascii
    $s17 = "int_no <= (uintmax_t) ((9223372036854775807L) + (-307) - 53)" fullword ascii
    $s18 = "int_no <= (uintmax_t) ((9223372036854775807L) + (-4931) - 64)" fullword ascii
    $s19 = "int_no <= (uintmax_t) ((9223372036854775807L) + (-37) - 24)" fullword ascii
    $s20 = "(char *) ((void*)((char*)(p) + 2*(sizeof(size_t)))) + 4 * (sizeof(size_t)) <= paligned_mem" fullword ascii

  condition:
    (uint16(0) == 0x457f and
      filesize < 9000KB and (8 of them)
    ) or (all of them)
}

rule miner_s_m_1 {
  meta:
    description = "miner-exe - from files s, m"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-22"
    hash1       = "1fd02c046f386f0c8779cef3d207613f3ecaa1aac27b88d0898fa145f584dc22"
    hash2       = "c3ef8a6eb848c99b8239af46b46376193388c6e5fe55980d00f65818dba0b047"

  strings:
    $s1  = "hash > target (false positive)" fullword ascii
    $s2  = "rpc2_login_decode" fullword ascii
    $s3  = "hash <= target" fullword ascii
    $s4  = "Skein1024_Process_Block" fullword ascii
    $s5  = "Skein_512_Process_Block" fullword ascii
    $s6  = "Skein_256_Process_Block" fullword ascii
    $s7  = "[X]^WTQRC@EFOLIJkhmngdabspuv" fullword ascii  /* reversed goodware string 'vupsbadgnmhkJILOFE@CRQTW^]X[' */
    $s8  = "|yz;8=>7412# %&/,)*" fullword ascii  /* reversed goodware string '*),/&% #2147>=8;zy|' */
    $s9  = "dump_to_strbuffer" fullword ascii
    $s10 = "rpc2_login_lock" fullword ascii
    $s11 = "rpc2_login" fullword ascii
    $s12 = "num_processors" fullword ascii
    $s13 = "Target: %s" fullword ascii
    $s14 = "json_dump_file" fullword ascii
    $s15 = "dump_string" fullword ascii
    $s16 = "|ungXQJC4=&/" fullword ascii  /* reversed goodware string '/&=4CJQXgnu|' */
    $s17 = "rpc2_target" fullword ascii
    $s18 = "AO]Sywek1?-#" fullword ascii  /* reversed goodware string '#-?1kewyS]OA' */
    $s19 = "dump_to_file" fullword ascii
    $s20 = "diff_to_target" fullword ascii

  condition:
    (uint16(0) == 0x457f and
      filesize < 700KB and (8 of them)
    ) or (all of them)
}

rule miner_s_m_p_2 {
  meta:
    description = "miner-exe - from files s, m, p"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-22"
    hash1       = "1fd02c046f386f0c8779cef3d207613f3ecaa1aac27b88d0898fa145f584dc22"
    hash2       = "c3ef8a6eb848c99b8239af46b46376193388c6e5fe55980d00f65818dba0b047"
    hash3       = "63210b24f42c05b2c5f8fd62e98dba6de45c7d751a2e55700d22983772886017"

  strings:
    $x1  = "{\"method\": \"login\", \"params\": {\"login\": \"%s\", \"pass\": \"%s\", \"agent\": \"cpuminer-multi/0.1\"}, \"id\": 1}" fullword ascii
    $s2  = "-x, --proxy=[PROTOCOL://]HOST[:PORT]  connect through a proxy" fullword ascii
    $s3  = "-P, --protocol-dump   verbose dump of protocol-level activities" fullword ascii
    $s4  = "-t, --threads=N       number of miner threads (default: number of processors)" fullword ascii
    $s5  = "{\"method\": \"submit\", \"params\": {\"id\": \"%s\", \"job_id\": \"%s\", \"nonce\": \"%s\", \"result\": \"%s\"}, \"id\":1}" fullword ascii
    $s6  = "User-Agent: cpuminer/2.3.3" fullword ascii
    $s7  = "{\"method\": \"getjob\", \"params\": {\"id\": \"%s\"}, \"id\":1}" fullword ascii
    $s8  = "{\"method\": \"getwork\", \"params\": [ \"%s\" ], \"id\":1}" fullword ascii
    $s9  = "getwork failed, retry after %d seconds" fullword ascii
    $s10 = "Failed to call rpc command after %i tries" fullword ascii
    $s11 = "Failed to get Stratum session id" fullword ascii
    $s12 = "{\"id\": 2, \"method\": \"mining.authorize\", \"params\": [\"%s\", \"%s\"]}" fullword ascii
    $s13 = "-O, --userpass=U:P    username:password pair for mining server" fullword ascii
    $s14 = "-S, --syslog          use system log for output messages" fullword ascii
    $s15 = "{\"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\":4}" fullword ascii
    $s16 = "%s: unsupported non-option argument '%s'" fullword ascii
    $s17 = "-p, --pass=PASSWORD   password for mining server" fullword ascii
    $s18 = "client.get_version" fullword ascii
    $s19 = "Tried to call rpc2 command before authentication" fullword ascii
    $s20 = "-s, --scantime=N      upper bound on time spent scanning current work when" fullword ascii

  condition:
    (uint16(0) == 0x457f and
      filesize < 9000KB and (1 of ($x*) and 4 of them)
    ) or (all of them)
}

rule Rana_Android_resources {
  meta:
    author    = "ReversingLabs"
    reference = "https://blog.reversinglabs.com/blog/rana-android-malware"

  strings:
    $res1 = "res/raw/cng.cn" fullword wide ascii
    $res2 = "res/raw/att.cn" fullword wide ascii
    $res3 = "res/raw/odr.od" fullword wide ascii

  condition:
    any of them  /* any string in the rule */
}

rule elf_babuk_auto {
  meta:
    author             = "Felix Bilstein - yara-signator at cocacoding dot com"
    date               = "2023-07-11"
    version            = "1"
    description        = "Detects elf.babuk."
    info               = "autogenerated rule brought to you by yara-signator"
    tool               = "yara-signator v0.6.0"
    signator_config    = "callsandjumps;datarefs;binvalue"
    malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.babuk"
    malpedia_rule_date = "20230705"
    malpedia_hash      = "42d0574f4405bd7d2b154d321d345acb18834a41"
    malpedia_version   = "20230715"
    malpedia_license   = "CC BY-SA 4.0"
    malpedia_sharing   = "TLP:WHITE"
  /* DISCLAIMER
   * The strings used in this rule have been automatically selected from the
   * disassembly of memory dumps and unpacked files, using YARA-Signator.
   * The code and documentation is published here:
   * https://github.com/fxb-cocacoding/yara-signator
   * As Malpedia is used as data source, please note that for a given
   * number of families, only single samples are documented.
   * This likely impacts the degree of generalization these rules will offer.
   * Take the described generation method also into consideration when you
   * apply the rules in your use cases and assign them confidence levels.
   */

  strings:
    $sequence_0 = { 8b 8c 24 6c 01 00 00 01 e9 89 8c 24 d4 03 00 00 8b ac 24 40 01 00 00 01 cd 89 ac 24 d0 03 00 00 8b 8c 24 18 01 00 00 }
    // n = 7, score = 200
    //   8b8c246c010000       | mov                 ecx, dword ptr [esp + 0x16c]
    //   01e9                 | add                 ecx, ebp
    //   898c24d4030000       | mov                 dword ptr [esp + 0x3d4], ecx
    //   8bac2440010000       | mov                 ebp, dword ptr [esp + 0x140]
    //   01cd                 | add                 ebp, ecx
    //   89ac24d0030000       | mov                 dword ptr [esp + 0x3d0], ebp
    //   8b8c2418010000       | mov                 ecx, dword ptr [esp + 0x118]
    $sequence_1 = { e8 ?? ?? ?? ?? 8b 48 18 8b 89 c8 00 00 00 c7 01 00 00 00 00 8b 48 18 84 01 81 c1 c4 00 00 00 }
    // n = 7, score = 200
    //   e8????????           |                     
    //   8b4818               | mov                 ecx, dword ptr [eax + 0x18]
    //   8b89c8000000         | mov                 ecx, dword ptr [ecx + 0xc8]
    //   c70100000000         | mov                 dword ptr [ecx], 0
    //   8b4818               | mov                 ecx, dword ptr [eax + 0x18]
    //   8401                 | test                byte ptr [ecx], al
    //   81c1c4000000         | add                 ecx, 0xc4
    $sequence_2 = { 90 ff 81 94 00 00 00 8b 48 18 8b 49 70 85 c9 0f 84 31 02 00 00 8b 0d ?? ?? ?? ?? }
    // n = 7, score = 200
    //   90                   | nop                 
    //   ff8194000000         | inc                 dword ptr [ecx + 0x94]
    //   8b4818               | mov                 ecx, dword ptr [eax + 0x18]
    //   8b4970               | mov                 ecx, dword ptr [ecx + 0x70]
    //   85c9                 | test                ecx, ecx
    //   0f8431020000         | je                  0x237
    //   8b0d????????         |                     
    $sequence_3 = { 0f 85 7d 01 00 00 8d 7c 24 24 31 c0 e8 ?? ?? ?? ?? 8b 8c 24 88 00 00 00 8b 11 89 d3 }
    // n = 7, score = 200
    //   0f857d010000         | jne                 0x183
    //   8d7c2424             | lea                 edi, [esp + 0x24]
    //   31c0                 | xor                 eax, eax
    //   e8????????           |                     
    //   8b8c2488000000       | mov                 ecx, dword ptr [esp + 0x88]
    //   8b11                 | mov                 edx, dword ptr [ecx]
    //   89d3                 | mov                 ebx, edx
    $sequence_4 = { c7 44 24 08 00 00 00 00 c7 44 24 0c 22 00 00 00 c7 44 24 10 ff ff ff ff c7 44 24 14 00 00 00 00 e8 ?? ?? ?? ?? 8b 44 24 1c 8b 4c 24 18 }
    // n = 7, score = 200
    //   c744240800000000     | mov                 dword ptr [esp + 8], 0
    //   c744240c22000000     | mov                 dword ptr [esp + 0xc], 0x22
    //   c7442410ffffffff     | mov                 dword ptr [esp + 0x10], 0xffffffff
    //   c744241400000000     | mov                 dword ptr [esp + 0x14], 0
    //   e8????????           |                     
    //   8b44241c             | mov                 eax, dword ptr [esp + 0x1c]
    //   8b4c2418             | mov                 ecx, dword ptr [esp + 0x18]
    $sequence_5 = { 85 c0 75 0c 8b 44 24 28 89 88 c8 00 00 00 eb d4 8b 54 24 28 8d ba c8 00 00 00 }
    // n = 7, score = 200
    //   85c0                 | test                eax, eax
    //   750c                 | jne                 0xe
    //   8b442428             | mov                 eax, dword ptr [esp + 0x28]
    //   8988c8000000         | mov                 dword ptr [eax + 0xc8], ecx
    //   ebd4                 | jmp                 0xffffffd6
    //   8b542428             | mov                 edx, dword ptr [esp + 0x28]
    //   8dbac8000000         | lea                 edi, [edx + 0xc8]
    $sequence_6 = { 8b 89 fc ff ff ff 3b 61 08 0f 86 e3 00 00 00 83 ec 24 8b 44 24 28 8b 88 1c 03 00 00 89 4c 24 14 }
    // n = 7, score = 200
    //   8b89fcffffff         | mov                 ecx, dword ptr [ecx - 4]
    //   3b6108               | cmp                 esp, dword ptr [ecx + 8]
    //   0f86e3000000         | jbe                 0xe9
    //   83ec24               | sub                 esp, 0x24
    //   8b442428             | mov                 eax, dword ptr [esp + 0x28]
    //   8b881c030000         | mov                 ecx, dword ptr [eax + 0x31c]
    //   894c2414             | mov                 dword ptr [esp + 0x14], ecx
    $sequence_7 = { 8b 54 24 44 f7 e2 89 94 24 48 02 00 00 89 44 24 3c 8b 44 24 34 8b 54 24 38 f7 e2 }
    // n = 7, score = 200
    //   8b542444             | mov                 edx, dword ptr [esp + 0x44]
    //   f7e2                 | mul                 edx
    //   89942448020000       | mov                 dword ptr [esp + 0x248], edx
    //   8944243c             | mov                 dword ptr [esp + 0x3c], eax
    //   8b442434             | mov                 eax, dword ptr [esp + 0x34]
    //   8b542438             | mov                 edx, dword ptr [esp + 0x38]
    //   f7e2                 | mul                 edx
    $sequence_8 = { c3 0f b6 98 7c 01 00 00 84 db 75 89 89 0c 24 e8 ?? ?? ?? ?? 83 c4 28 }
    // n = 7, score = 200
    //   c3                   | ret                 
    //   0fb6987c010000       | movzx               ebx, byte ptr [eax + 0x17c]
    //   84db                 | test                bl, bl
    //   7589                 | jne                 0xffffff8b
    //   890c24               | mov                 dword ptr [esp], ecx
    //   e8????????           |                     
    //   83c428               | add                 esp, 0x28
    $sequence_9 = { 8b bc 24 b8 03 00 00 01 fe 11 d1 8b 94 24 94 02 00 00 0f af d5 8d 3c d2 }
  // n = 6, score = 200
  //   8bbc24b8030000       | mov                 edi, dword ptr [esp + 0x3b8]
  //   01fe                 | add                 esi, edi
  //   11d1                 | adc                 ecx, edx
  //   8b942494020000       | mov                 edx, dword ptr [esp + 0x294]
  //   0fafd5               | imul                edx, ebp
  //   8d3cd2               | lea                 edi, [edx + edx*8]

  condition:
    7 of them and filesize < 4186112
}

rule elf_bashlite_auto {
  meta:
    author             = "Felix Bilstein - yara-signator at cocacoding dot com"
    date               = "2023-07-11"
    version            = "1"
    description        = "Detects elf.bashlite."
    info               = "autogenerated rule brought to you by yara-signator"
    tool               = "yara-signator v0.6.0"
    signator_config    = "callsandjumps;datarefs;binvalue"
    malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.bashlite"
    malpedia_rule_date = "20230705"
    malpedia_hash      = "42d0574f4405bd7d2b154d321d345acb18834a41"
    malpedia_version   = "20230715"
    malpedia_license   = "CC BY-SA 4.0"
    malpedia_sharing   = "TLP:WHITE"
  /* DISCLAIMER
   * The strings used in this rule have been automatically selected from the
   * disassembly of memory dumps and unpacked files, using YARA-Signator.
   * The code and documentation is published here:
   * https://github.com/fxb-cocacoding/yara-signator
   * As Malpedia is used as data source, please note that for a given
   * number of families, only single samples are documented.
   * This likely impacts the degree of generalization these rules will offer.
   * Take the described generation method also into consideration when you
   * apply the rules in your use cases and assign them confidence levels.
   */

  strings:
    $sequence_0 = { f7 d0 21 d0 33 45 fc c9 c3 }
    // n = 5, score = 300
    //   f7d0                 | not                 eax
    //   21d0                 | and                 eax, edx
    //   3345fc               | xor                 eax, dword ptr [ebp - 4]
    //   c9                   | leave               
    //   c3                   | ret                 
    $sequence_1 = { 89 45 ec 83 7d ec 00 75 0b 8b 45 ec }
    // n = 4, score = 300
    //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
    //   837dec00             | cmp                 dword ptr [ebp - 0x14], 0
    //   750b                 | jne                 0xd
    //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
    $sequence_2 = { e8 ?? ?? ?? ?? 89 c2 89 d0 c1 e8 1f }
    // n = 4, score = 300
    //   e8????????           |                     
    //   89c2                 | mov                 edx, eax
    //   89d0                 | mov                 eax, edx
    //   c1e81f               | shr                 eax, 0x1f
    $sequence_3 = { 76 0f e8 ?? ?? ?? ?? c7 00 1c 00 00 00 31 c0 }
    // n = 4, score = 300
    //   760f                 | jbe                 0x11
    //   e8????????           |                     
    //   c7001c000000         | mov                 dword ptr [eax], 0x1c
    //   31c0                 | xor                 eax, eax
    $sequence_4 = { eb 19 e8 ?? ?? ?? ?? c7 00 16 00 00 00 e8 ?? ?? ?? ?? c7 00 16 00 00 00 }
    // n = 5, score = 300
    //   eb19                 | jmp                 0x1b
    //   e8????????           |                     
    //   c70016000000         | mov                 dword ptr [eax], 0x16
    //   e8????????           |                     
    //   c70016000000         | mov                 dword ptr [eax], 0x16
    $sequence_5 = { eb 0a c7 85 ec ef ff ff 00 00 00 00 8b 85 ec ef ff ff c9 }
    // n = 4, score = 300
    //   eb0a                 | jmp                 0xc
    //   c785ecefffff00000000     | mov    dword ptr [ebp - 0x1014], 0
    //   8b85ecefffff         | mov                 eax, dword ptr [ebp - 0x1014]
    //   c9                   | leave               
    $sequence_6 = { 75 0c e8 ?? ?? ?? ?? 8b 00 83 f8 73 }
    // n = 4, score = 300
    //   750c                 | jne                 0xe
    //   e8????????           |                     
    //   8b00                 | mov                 eax, dword ptr [eax]
    //   83f873               | cmp                 eax, 0x73
    $sequence_7 = { 85 c0 75 0c c7 85 ec ef ff ff 01 00 00 00 eb 0a }
  // n = 4, score = 300
  //   85c0                 | test                eax, eax
  //   750c                 | jne                 0xe
  //   c785ecefffff01000000     | mov    dword ptr [ebp - 0x1014], 1
  //   eb0a                 | jmp                 0xc

  condition:
    7 of them and filesize < 2310144
}

rule elf_blackcat_auto {
  meta:
    author             = "Felix Bilstein - yara-signator at cocacoding dot com"
    date               = "2023-07-11"
    version            = "1"
    description        = "Detects elf.blackcat."
    info               = "autogenerated rule brought to you by yara-signator"
    tool               = "yara-signator v0.6.0"
    signator_config    = "callsandjumps;datarefs;binvalue"
    malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.blackcat"
    malpedia_rule_date = "20230705"
    malpedia_hash      = "42d0574f4405bd7d2b154d321d345acb18834a41"
    malpedia_version   = "20230715"
    malpedia_license   = "CC BY-SA 4.0"
    malpedia_sharing   = "TLP:WHITE"
  /* DISCLAIMER
   * The strings used in this rule have been automatically selected from the
   * disassembly of memory dumps and unpacked files, using YARA-Signator.
   * The code and documentation is published here:
   * https://github.com/fxb-cocacoding/yara-signator
   * As Malpedia is used as data source, please note that for a given
   * number of families, only single samples are documented.
   * This likely impacts the degree of generalization these rules will offer.
   * Take the described generation method also into consideration when you
   * apply the rules in your use cases and assign them confidence levels.
   */

  strings:
    $sequence_0 = { 0f 0b 0f 0b 90 90 90 }
    // n = 5, score = 200
    //   0f0b                 | mov                 byte ptr [esp + 0xd], al
    //   0f0b                 | mov                 eax, ebp
    //   90                   | shr                 eax, 6
    //   90                   | and                 al, 0x3f
    //   90                   | or                  al, 0x80
    $sequence_1 = { 83 e1 3f 09 f1 09 d1 81 f9 ?? ?? ?? ?? }
    // n = 4, score = 200
    //   83e13f               | je                  0x4be
    //   09f1                 | and                 eax, 0xfffffff0
    //   09d1                 | add                 ecx, eax
    //   81f9????????         |                     
    $sequence_2 = { f2 0f 5c c3 f2 0f 59 c1 f2 0f 58 c3 f2 0f 5d c2 }
    // n = 4, score = 200
    //   f20f5cc3             | movsd               qword ptr [esp + 0x60], xmm4
    //   f20f59c1             | addsd               xmm2, xmm4
    //   f20f58c3             | movd                xmm4, eax
    //   f20f5dc2             | lea                 eax, [edi + 0x10]
    $sequence_3 = { 89 c1 c1 e9 02 69 d1 ?? ?? ?? ?? c1 ea 11 6b ca 64 }
    // n = 5, score = 200
    //   89c1                 | mov                 ebx, edx
    //   c1e902               | imul                ebp, eax
    //   69d1????????         |                     
    //   c1ea11               | mul                 edi
    //   6bca64               | add                 edx, ebp
    $sequence_4 = { 66 0f 70 c9 00 66 0f 6f d1 66 0f 74 d0 66 0f d7 ea 66 0f 6f d0 }
    // n = 5, score = 200
    //   660f70c900           | or                  edi, esi
    //   660f6fd1             | test                eax, 0xc000000
    //   660f74d0             | movd                esi, xmm1
    //   660fd7ea             | jne                 0x434
    //   660f6fd0             | pshufd              xmm1, xmm0, 0x55
    $sequence_5 = { 66 0f 2e c1 0f b6 db 0f 43 dd 80 fb ff }
    // n = 4, score = 200
    //   660f2ec1             | test                dh, dh
    //   0fb6db               | jne                 0x126
    //   0f43dd               | jae                 0x145
    //   80fbff               | inc                 eax
    $sequence_6 = { d1 e9 01 d1 c1 e9 02 8d 14 cd 00 00 00 00 29 ca }
    // n = 5, score = 200
    //   d1e9                 | mov                 edx, dword ptr [ebx + 0x26c]
    //   01d1                 | lea                 ecx, [ebx - 0x3348]
    //   c1e902               | lea                 edi, [ebx - 0x38884]
    //   8d14cd00000000       | mov                 dword ptr [esp + 0x1fc], 0
    //   29ca                 | mov                 dword ptr [esp + 0x200], edx
    $sequence_7 = { 09 f2 c1 e2 06 83 e0 3f 09 d0 3d ?? ?? ?? ?? }
    // n = 5, score = 200
    //   09f2                 | je                  0x75
    //   c1e206               | dec                 eax
    //   83e03f               | add                 edx, 4
    //   09d0                 | or                  edi, ebp
    //   3d????????           |                     
    $sequence_8 = { 5b c3 e8 ?? ?? ?? ?? 89 c2 }
    // n = 4, score = 200
    //   5b                   | mov                 esi, ecx
    //   c3                   | xchg                byte ptr [ecx + 0x54], al
    //   e8????????           |                     
    //   89c2                 | pop                 ebx
    $sequence_9 = { e9 ?? ?? ?? ?? b8 ?? ?? ?? ?? eb 59 b8 ?? ?? ?? ?? eb 52 b8 ?? ?? ?? ?? eb 4b }
  // n = 7, score = 200
  //   e9????????           |                     
  //   b8????????           |                     
  //   eb59                 | mov                 byte ptr [esp + 0x1c], 1
  //   b8????????           |                     
  //   eb52                 | mov                 dword ptr [esp + 0xf4], 0
  //   b8????????           |                     
  //   eb4b                 | lea                 ecx, [ebx - 0x3a3a7]

  condition:
    7 of them and filesize < 8011776
}

rule elf_gobrat_auto {
  meta:
    author             = "Felix Bilstein - yara-signator at cocacoding dot com"
    date               = "2023-07-11"
    version            = "1"
    description        = "Detects elf.gobrat."
    info               = "autogenerated rule brought to you by yara-signator"
    tool               = "yara-signator v0.6.0"
    signator_config    = "callsandjumps;datarefs;binvalue"
    malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.gobrat"
    malpedia_rule_date = "20230705"
    malpedia_hash      = "42d0574f4405bd7d2b154d321d345acb18834a41"
    malpedia_version   = "20230715"
    malpedia_license   = "CC BY-SA 4.0"
    malpedia_sharing   = "TLP:WHITE"
  /* DISCLAIMER
   * The strings used in this rule have been automatically selected from the
   * disassembly of memory dumps and unpacked files, using YARA-Signator.
   * The code and documentation is published here:
   * https://github.com/fxb-cocacoding/yara-signator
   * As Malpedia is used as data source, please note that for a given
   * number of families, only single samples are documented.
   * This likely impacts the degree of generalization these rules will offer.
   * Take the described generation method also into consideration when you
   * apply the rules in your use cases and assign them confidence levels.
   */

  strings:
    $sequence_0 = { e8 ?? ?? ?? ?? 48 8b 54 24 78 48 8b 5c 24 60 48 89 ce 48 8b 4c 24 58 c6 04 18 00 0f 1f 44 00 00 }
    // n = 7, score = 100
    //   e8????????           |                     
    //   488b542478           | cmp                 esp, dword ptr [esi + 0x10]
    //   488b5c2460           | jbe                 0x16f7
    //   4889ce               | dec                 eax
    //   488b4c2458           | sub                 esp, 0x228
    //   c6041800             | dec                 eax
    //   0f1f440000           | mov                 dword ptr [esp + 0x220], ebp
    $sequence_1 = { ff d1 0f 1f 00 48 85 ff 0f 85 92 01 00 00 48 85 db 0f 86 a2 01 00 00 0f b6 10 }
    // n = 7, score = 100
    //   ffd1                 | mov                 ecx, eax
    //   0f1f00               | dec                 eax
    //   4885ff               | mov                 eax, 0xfffffffe
    //   0f8592010000         | dec                 eax
    //   4885db               | mov                 ebp, dword ptr [esp + 0x138]
    //   0f86a2010000         | jne                 0x10d
    //   0fb610               | cmp                 byte ptr [edi + 2], 0x70
    $sequence_2 = { e8 ?? ?? ?? ?? 48 8b 44 24 38 48 8b 4c 24 18 4c 8b 4c 24 20 48 85 c9 75 1f 4d 85 c9 }
    // n = 7, score = 100
    //   e8????????           |                     
    //   488b442438           | jbe                 0xacc
    //   488b4c2418           | dec                 eax
    //   4c8b4c2420           | sub                 esp, 0x90
    //   4885c9               | dec                 eax
    //   751f                 | mov                 dword ptr [esp + 0x88], ebp
    //   4d85c9               | dec                 eax
    $sequence_3 = { e8 ?? ?? ?? ?? 48 89 c7 48 8b 73 10 48 8d 56 01 4c 8b 43 08 4c 8b 4b 18 49 39 d1 }
    // n = 7, score = 100
    //   e8????????           |                     
    //   4889c7               | mov                 dword ptr [eax + esi], edx
    //   488b7310             | dec                 ecx
    //   488d5601             | lea                 edi, [eax + esi]
    //   4c8b4308             | dec                 eax
    //   4c8b4b18             | lea                 edi, [edi + 8]
    //   4939d1               | dec                 esp
    $sequence_4 = { e9 ?? ?? ?? ?? 84 06 48 8b 86 10 12 00 00 48 85 c0 74 0c 0f 1f 00 48 39 d8 }
    // n = 7, score = 100
    //   e9????????           |                     
    //   8406                 | dec                 eax
    //   488b8610120000       | lea                 eax, [0x1c6bd4]
    //   4885c0               | dec                 eax
    //   740c                 | mov                 dword ptr [eax + 8], 0x13
    //   0f1f00               | mov                 word ptr [eax + 0x10], 1
    //   4839d8               | xor                 ecx, ecx
    $sequence_5 = { 75 15 41 38 d1 74 08 44 0f b6 5c 24 37 eb 1d 44 0f b6 5c 24 37 eb 2f }
    // n = 7, score = 100
    //   7515                 | cmp                 eax, esi
    //   4138d1               | jae                 0xa98
    //   7408                 | dec                 eax
    //   440fb65c2437         | mov                 dword ptr [esp + 0x68], edi
    //   eb1d                 | dec                 esp
    //   440fb65c2437         | mov                 dword ptr [esp + 0xb8], edx
    //   eb2f                 | dec                 esp
    $sequence_6 = { e8 ?? ?? ?? ?? 48 8b 6d 00 4c 8b 94 24 d0 02 00 00 4c 89 94 24 88 01 00 00 48 8d bc 24 90 01 00 00 48 8d b4 24 d8 02 00 00 66 0f 1f 84 00 00 00 00 00 }
    // n = 7, score = 100
    //   e8????????           |                     
    //   488b6d00             | dec                 ebp
    //   4c8b9424d0020000     | adc                 eax, ebx
    //   4c89942488010000     | dec                 ebp
    //   488dbc2490010000     | add                 eax, ebp
    //   488db424d8020000     | dec                 esp
    //   660f1f840000000000     | mov    eax, dword ptr [esp + 0x5d8]
    $sequence_7 = { e9 ?? ?? ?? ?? 48 83 f8 07 0f 85 5b 01 00 00 48 83 f9 04 74 14 66 0f 1f 84 00 00 00 00 00 90 }
    // n = 7, score = 100
    //   e9????????           |                     
    //   4883f807             | nop                 
    //   0f855b010000         | dec                 eax
    //   4883f904             | test                ebx, ebx
    //   7414                 | jne                 0x5bd
    //   660f1f840000000000     | dec    eax
    //   90                   | lea                 eax, [0x1861c8]
    $sequence_8 = { eb 14 48 8d 57 18 48 89 f9 48 89 d7 66 90 e8 ?? ?? ?? ?? 48 89 cf }
    // n = 7, score = 100
    //   eb14                 | cmp                 ecx, 3
    //   488d5718             | jbe                 0x15d3
    //   4889f9               | mov                 dword ptr [ebx], esi
    //   4889d7               | dec                 eax
    //   6690                 | mov                 ebp, dword ptr [esp + 0x10]
    //   e8????????           |                     
    //   4889cf               | dec                 eax
    $sequence_9 = { e8 ?? ?? ?? ?? b8 05 00 00 00 48 89 c1 66 90 e8 ?? ?? ?? ?? b8 04 00 00 00 48 89 c1 }
  // n = 7, score = 100
  //   e8????????           |                     
  //   b805000000           | dec                 ebp
  //   4889c1               | test                esp, esp
  //   6690                 | je                  0x163d
  //   e8????????           |                     
  //   b804000000           | dec                 edi
  //   4889c1               | lea                 edi, [edx + ebp]

  condition:
    7 of them and filesize < 12853248
}

rule elf_hideandseek_auto {
  meta:
    author             = "Felix Bilstein - yara-signator at cocacoding dot com"
    date               = "2023-07-11"
    version            = "1"
    description        = "Detects elf.hideandseek."
    info               = "autogenerated rule brought to you by yara-signator"
    tool               = "yara-signator v0.6.0"
    signator_config    = "callsandjumps;datarefs;binvalue"
    malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.hideandseek"
    malpedia_rule_date = "20230705"
    malpedia_hash      = "42d0574f4405bd7d2b154d321d345acb18834a41"
    malpedia_version   = "20230715"
    malpedia_license   = "CC BY-SA 4.0"
    malpedia_sharing   = "TLP:WHITE"
  /* DISCLAIMER
   * The strings used in this rule have been automatically selected from the
   * disassembly of memory dumps and unpacked files, using YARA-Signator.
   * The code and documentation is published here:
   * https://github.com/fxb-cocacoding/yara-signator
   * As Malpedia is used as data source, please note that for a given
   * number of families, only single samples are documented.
   * This likely impacts the degree of generalization these rules will offer.
   * Take the described generation method also into consideration when you
   * apply the rules in your use cases and assign them confidence levels.
   */

  strings:
    $sequence_0 = { 8b 44 24 24 39 74 24 20 75 04 89 c6 eb 21 39 44 24 20 }
    // n = 6, score = 100
    //   8b442424             | mov                 eax, dword ptr [esp + 0x24]
    //   39742420             | cmp                 dword ptr [esp + 0x20], esi
    //   7504                 | jne                 6
    //   89c6                 | mov                 esi, eax
    //   eb21                 | jmp                 0x23
    //   39442420             | cmp                 dword ptr [esp + 0x20], eax
    $sequence_1 = { 40 66 3b 47 f0 66 89 47 ee 72 38 52 52 }
    // n = 6, score = 100
    //   40                   | inc                 eax
    //   663b47f0             | cmp                 ax, word ptr [edi - 0x10]
    //   668947ee             | mov                 word ptr [edi - 0x12], ax
    //   7238                 | jb                  0x3a
    //   52                   | push                edx
    //   52                   | push                edx
    $sequence_2 = { 50 e8 ?? ?? ?? ?? 58 5a 6a 40 8d 84 24 b0 21 00 00 50 }
    // n = 7, score = 100
    //   50                   | push                eax
    //   e8????????           |                     
    //   58                   | pop                 eax
    //   5a                   | pop                 edx
    //   6a40                 | push                0x40
    //   8d8424b0210000       | lea                 eax, [esp + 0x21b0]
    //   50                   | push                eax
    $sequence_3 = { be 04 00 00 00 83 c4 10 84 c0 75 19 e9 ?? ?? ?? ?? }
    // n = 5, score = 100
    //   be04000000           | mov                 esi, 4
    //   83c410               | add                 esp, 0x10
    //   84c0                 | test                al, al
    //   7519                 | jne                 0x1b
    //   e9????????           |                     
    $sequence_4 = { 89 c3 85 c0 0f 85 25 01 00 00 8b 44 24 30 8d 74 24 28 f6 00 01 0f 84 54 ff ff ff }
    // n = 7, score = 100
    //   89c3                 | mov                 ebx, eax
    //   85c0                 | test                eax, eax
    //   0f8525010000         | jne                 0x12b
    //   8b442430             | mov                 eax, dword ptr [esp + 0x30]
    //   8d742428             | lea                 esi, [esp + 0x28]
    //   f60001               | test                byte ptr [eax], 1
    //   0f8454ffffff         | je                  0xffffff5a
    $sequence_5 = { 8b 45 f4 8a 4d f0 d3 e8 89 d7 8a 4d e4 09 c7 8b 75 f4 }
    // n = 7, score = 100
    //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
    //   8a4df0               | mov                 cl, byte ptr [ebp - 0x10]
    //   d3e8                 | shr                 eax, cl
    //   89d7                 | mov                 edi, edx
    //   8a4de4               | mov                 cl, byte ptr [ebp - 0x1c]
    //   09c7                 | or                  edi, eax
    //   8b75f4               | mov                 esi, dword ptr [ebp - 0xc]
    $sequence_6 = { 56 57 e8 ?? ?? ?? ?? 83 c4 10 85 c0 75 10 50 }
    // n = 7, score = 100
    //   56                   | push                esi
    //   57                   | push                edi
    //   e8????????           |                     
    //   83c410               | add                 esp, 0x10
    //   85c0                 | test                eax, eax
    //   7510                 | jne                 0x12
    //   50                   | push                eax
    $sequence_7 = { 53 83 ec 1c 8b 5c 24 30 8b 7c 24 38 8b 6c 24 3c 8b 74 24 40 85 db }
    // n = 7, score = 100
    //   53                   | push                ebx
    //   83ec1c               | sub                 esp, 0x1c
    //   8b5c2430             | mov                 ebx, dword ptr [esp + 0x30]
    //   8b7c2438             | mov                 edi, dword ptr [esp + 0x38]
    //   8b6c243c             | mov                 ebp, dword ptr [esp + 0x3c]
    //   8b742440             | mov                 esi, dword ptr [esp + 0x40]
    //   85db                 | test                ebx, ebx
    $sequence_8 = { 8b 1f 89 d8 0f af 06 85 c0 79 2c 56 57 }
    // n = 7, score = 100
    //   8b1f                 | mov                 ebx, dword ptr [edi]
    //   89d8                 | mov                 eax, ebx
    //   0faf06               | imul                eax, dword ptr [esi]
    //   85c0                 | test                eax, eax
    //   792c                 | jns                 0x2e
    //   56                   | push                esi
    //   57                   | push                edi
    $sequence_9 = { e8 ?? ?? ?? ?? eb 09 50 57 56 56 e8 ?? ?? ?? ?? }
  // n = 7, score = 100
  //   e8????????           |                     
  //   eb09                 | jmp                 0xb
  //   50                   | push                eax
  //   57                   | push                edi
  //   56                   | push                esi
  //   56                   | push                esi
  //   e8????????           |                     

  condition:
    7 of them and filesize < 196608
}

rule elf_mirai_auto {
  meta:
    author             = "Felix Bilstein - yara-signator at cocacoding dot com"
    date               = "2023-07-11"
    version            = "1"
    description        = "Detects elf.mirai."
    info               = "autogenerated rule brought to you by yara-signator"
    tool               = "yara-signator v0.6.0"
    signator_config    = "callsandjumps;datarefs;binvalue"
    malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.mirai"
    malpedia_rule_date = "20230705"
    malpedia_hash      = "42d0574f4405bd7d2b154d321d345acb18834a41"
    malpedia_version   = "20230715"
    malpedia_license   = "CC BY-SA 4.0"
    malpedia_sharing   = "TLP:WHITE"
  /* DISCLAIMER
   * The strings used in this rule have been automatically selected from the
   * disassembly of memory dumps and unpacked files, using YARA-Signator.
   * The code and documentation is published here:
   * https://github.com/fxb-cocacoding/yara-signator
   * As Malpedia is used as data source, please note that for a given
   * number of families, only single samples are documented.
   * This likely impacts the degree of generalization these rules will offer.
   * Take the described generation method also into consideration when you
   * apply the rules in your use cases and assign them confidence levels.
   */

  strings:
    $sequence_0 = { 66 89 41 04 74 06 66 c7 41 06 40 00 c6 41 09 11 }
    // n = 4, score = 300
    //   66894104             | mov                 word ptr [ecx + 4], ax
    //   7406                 | je                  8
    //   66c741064000         | mov                 word ptr [ecx + 6], 0x40
    //   c6410911             | mov                 byte ptr [ecx + 9], 0x11
    $sequence_1 = { 89 43 30 c6 43 38 01 c6 43 39 03 c6 43 3a 03 c6 43 3b 06 }
    // n = 5, score = 300
    //   894330               | mov                 dword ptr [ebx + 0x30], eax
    //   c6433801             | mov                 byte ptr [ebx + 0x38], 1
    //   c6433903             | mov                 byte ptr [ebx + 0x39], 3
    //   c6433a03             | mov                 byte ptr [ebx + 0x3a], 3
    //   c6433b06             | mov                 byte ptr [ebx + 0x3b], 6
    $sequence_2 = { 8d 42 9f 3c 19 77 05 8d 42 e0 }
    // n = 4, score = 300
    //   8d429f               | lea                 eax, [edx - 0x61]
    //   3c19                 | cmp                 al, 0x19
    //   7705                 | ja                  7
    //   8d42e0               | lea                 eax, [edx - 0x20]
    $sequence_3 = { 66 89 43 2a e8 ?? ?? ?? ?? c7 43 34 00 00 00 00 89 43 30 c6 43 38 01 }
    // n = 5, score = 300
    //   6689432a             | mov                 word ptr [ebx + 0x2a], ax
    //   e8????????           |                     
    //   c7433400000000       | mov                 dword ptr [ebx + 0x34], 0
    //   894330               | mov                 dword ptr [ebx + 0x30], eax
    //   c6433801             | mov                 byte ptr [ebx + 0x38], 1
    $sequence_4 = { c1 ea 02 8d 14 92 29 d0 83 f8 04 }
    // n = 4, score = 300
    //   c1ea02               | shr                 edx, 2
    //   8d1492               | lea                 edx, [edx + edx*4]
    //   29d0                 | sub                 eax, edx
    //   83f804               | cmp                 eax, 4
    $sequence_5 = { c1 ea 03 89 d0 c1 e0 05 01 d0 }
    // n = 4, score = 300
    //   c1ea03               | shr                 edx, 3
    //   89d0                 | mov                 eax, edx
    //   c1e005               | shl                 eax, 5
    //   01d0                 | add                 eax, edx
    $sequence_6 = { 80 7c 24 2b 00 66 89 43 04 74 06 66 c7 43 06 40 00 c6 43 09 2f }
    // n = 5, score = 300
    //   807c242b00           | cmp                 byte ptr [esp + 0x2b], 0
    //   66894304             | mov                 word ptr [ebx + 4], ax
    //   7406                 | je                  8
    //   66c743064000         | mov                 word ptr [ebx + 6], 0x40
    //   c643092f             | mov                 byte ptr [ebx + 9], 0x2f
    $sequence_7 = { c1 e0 05 01 d0 89 ca 29 c2 }
  // n = 4, score = 300
  //   c1e005               | shl                 eax, 5
  //   01d0                 | add                 eax, edx
  //   89ca                 | mov                 edx, ecx
  //   29c2                 | sub                 edx, eax

  condition:
    7 of them and filesize < 2228224
}

rule elf_persirai_auto {
  meta:
    author             = "Felix Bilstein - yara-signator at cocacoding dot com"
    date               = "2023-07-11"
    version            = "1"
    description        = "Detects elf.persirai."
    info               = "autogenerated rule brought to you by yara-signator"
    tool               = "yara-signator v0.6.0"
    signator_config    = "callsandjumps;datarefs;binvalue"
    malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.persirai"
    malpedia_rule_date = "20230705"
    malpedia_hash      = "42d0574f4405bd7d2b154d321d345acb18834a41"
    malpedia_version   = "20230715"
    malpedia_license   = "CC BY-SA 4.0"
    malpedia_sharing   = "TLP:WHITE"
  /* DISCLAIMER
   * The strings used in this rule have been automatically selected from the
   * disassembly of memory dumps and unpacked files, using YARA-Signator.
   * The code and documentation is published here:
   * https://github.com/fxb-cocacoding/yara-signator
   * As Malpedia is used as data source, please note that for a given
   * number of families, only single samples are documented.
   * This likely impacts the degree of generalization these rules will offer.
   * Take the described generation method also into consideration when you
   * apply the rules in your use cases and assign them confidence levels.
   */

  strings:
    $sequence_0 = { eb 0f 31 db eb 2f 0d ff ff 1f 00 8d b0 21 fe ff ff 8d 6c 24 0c 8b 5e 3c }
    // n = 7, score = 100
    //   eb0f                 | jmp                 0x11
    //   31db                 | xor                 ebx, ebx
    //   eb2f                 | jmp                 0x31
    //   0dffff1f00           | or                  eax, 0x1fffff
    //   8db021feffff         | lea                 esi, [eax - 0x1df]
    //   8d6c240c             | lea                 ebp, [esp + 0xc]
    //   8b5e3c               | mov                 ebx, dword ptr [esi + 0x3c]
    $sequence_1 = { 75 24 eb 0a 8b 40 1c 89 da e8 ?? ?? ?? ?? 89 b3 bc 01 00 00 85 f6 }
    // n = 7, score = 100
    //   7524                 | jne                 0x26
    //   eb0a                 | jmp                 0xc
    //   8b401c               | mov                 eax, dword ptr [eax + 0x1c]
    //   89da                 | mov                 edx, ebx
    //   e8????????           |                     
    //   89b3bc010000         | mov                 dword ptr [ebx + 0x1bc], esi
    //   85f6                 | test                esi, esi
    $sequence_2 = { 6a 02 e8 ?? ?? ?? ?? 83 c4 10 83 c4 0c c3 83 ec 0c 8b 44 24 14 }
    // n = 7, score = 100
    //   6a02                 | push                2
    //   e8????????           |                     
    //   83c410               | add                 esp, 0x10
    //   83c40c               | add                 esp, 0xc
    //   c3                   | ret                 
    //   83ec0c               | sub                 esp, 0xc
    //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
    $sequence_3 = { e8 ?? ?? ?? ?? 83 c4 0c 57 8d 44 24 3c 50 56 e8 ?? ?? ?? ?? }
    // n = 7, score = 100
    //   e8????????           |                     
    //   83c40c               | add                 esp, 0xc
    //   57                   | push                edi
    //   8d44243c             | lea                 eax, [esp + 0x3c]
    //   50                   | push                eax
    //   56                   | push                esi
    //   e8????????           |                     
    $sequence_4 = { 5f 5d c3 a1 ?? ?? ?? ?? 53 89 c3 8b 15 ?? ?? ?? ?? }
    // n = 7, score = 100
    //   5f                   | pop                 edi
    //   5d                   | pop                 ebp
    //   c3                   | ret                 
    //   a1????????           |                     
    //   53                   | push                ebx
    //   89c3                 | mov                 ebx, eax
    //   8b15????????         |                     
    $sequence_5 = { 50 6a 02 e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 5f ff 70 18 e8 ?? ?? ?? ?? }
    // n = 7, score = 100
    //   50                   | push                eax
    //   6a02                 | push                2
    //   e8????????           |                     
    //   a1????????           |                     
    //   5f                   | pop                 edi
    //   ff7018               | push                dword ptr [eax + 0x18]
    //   e8????????           |                     
    $sequence_6 = { 83 ec 10 8b 5c 24 18 ff 74 24 1c 53 e8 ?? ?? ?? ?? 83 c4 10 83 ca ff }
    // n = 7, score = 100
    //   83ec10               | sub                 esp, 0x10
    //   8b5c2418             | mov                 ebx, dword ptr [esp + 0x18]
    //   ff74241c             | push                dword ptr [esp + 0x1c]
    //   53                   | push                ebx
    //   e8????????           |                     
    //   83c410               | add                 esp, 0x10
    //   83caff               | or                  edx, 0xffffffff
    $sequence_7 = { 74 13 8d 43 10 89 74 24 10 89 44 24 14 59 5b 5e }
    // n = 7, score = 100
    //   7413                 | je                  0x15
    //   8d4310               | lea                 eax, [ebx + 0x10]
    //   89742410             | mov                 dword ptr [esp + 0x10], esi
    //   89442414             | mov                 dword ptr [esp + 0x14], eax
    //   59                   | pop                 ecx
    //   5b                   | pop                 ebx
    //   5e                   | pop                 esi
    $sequence_8 = { 85 c0 74 36 8d 43 04 51 51 50 }
    // n = 6, score = 100
    //   85c0                 | test                eax, eax
    //   7436                 | je                  0x38
    //   8d4304               | lea                 eax, [ebx + 4]
    //   51                   | push                ecx
    //   51                   | push                ecx
    //   50                   | push                eax
    $sequence_9 = { 50 e8 ?? ?? ?? ?? 89 5e 08 eb 0d 8d 46 10 51 51 }
  // n = 7, score = 100
  //   50                   | push                eax
  //   e8????????           |                     
  //   895e08               | mov                 dword ptr [esi + 8], ebx
  //   eb0d                 | jmp                 0xf
  //   8d4610               | lea                 eax, [esi + 0x10]
  //   51                   | push                ecx
  //   51                   | push                ecx

  condition:
    7 of them and filesize < 229376
}

rule elf_satori_auto {
  meta:
    author             = "Felix Bilstein - yara-signator at cocacoding dot com"
    date               = "2023-07-11"
    version            = "1"
    description        = "Detects elf.satori."
    info               = "autogenerated rule brought to you by yara-signator"
    tool               = "yara-signator v0.6.0"
    signator_config    = "callsandjumps;datarefs;binvalue"
    malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.satori"
    malpedia_rule_date = "20230705"
    malpedia_hash      = "42d0574f4405bd7d2b154d321d345acb18834a41"
    malpedia_version   = "20230715"
    malpedia_license   = "CC BY-SA 4.0"
    malpedia_sharing   = "TLP:WHITE"
  /* DISCLAIMER
   * The strings used in this rule have been automatically selected from the
   * disassembly of memory dumps and unpacked files, using YARA-Signator.
   * The code and documentation is published here:
   * https://github.com/fxb-cocacoding/yara-signator
   * As Malpedia is used as data source, please note that for a given
   * number of families, only single samples are documented.
   * This likely impacts the degree of generalization these rules will offer.
   * Take the described generation method also into consideration when you
   * apply the rules in your use cases and assign them confidence levels.
   */

  strings:
    $sequence_0 = { ba 01 00 00 00 eb bb 5b 5b 5e c3 55 }
    // n = 7, score = 100
    //   ba01000000           | mov                 edx, 1
    //   ebbb                 | jmp                 0xffffffbd
    //   5b                   | pop                 ebx
    //   5b                   | pop                 ebx
    //   5e                   | pop                 esi
    //   c3                   | ret                 
    //   55                   | push                ebp
    $sequence_1 = { e8 ?? ?? ?? ?? 89 1c 24 e8 ?? ?? ?? ?? 68 00 40 00 00 50 53 ff b5 1c 04 00 00 }
    // n = 7, score = 100
    //   e8????????           |                     
    //   891c24               | mov                 dword ptr [esp], ebx
    //   e8????????           |                     
    //   6800400000           | push                0x4000
    //   50                   | push                eax
    //   53                   | push                ebx
    //   ffb51c040000         | push                dword ptr [ebp + 0x41c]
    $sequence_2 = { 83 ec 0c 56 8b 10 e9 ?? ?? ?? ?? 80 f9 64 75 2b 8b 44 24 08 }
    // n = 7, score = 100
    //   83ec0c               | sub                 esp, 0xc
    //   56                   | push                esi
    //   8b10                 | mov                 edx, dword ptr [eax]
    //   e9????????           |                     
    //   80f964               | cmp                 cl, 0x64
    //   752b                 | jne                 0x2d
    //   8b442408             | mov                 eax, dword ptr [esp + 8]
    $sequence_3 = { 6a 03 56 53 e8 ?? ?? ?? ?? 0f b7 c0 }
    // n = 5, score = 100
    //   6a03                 | push                3
    //   56                   | push                esi
    //   53                   | push                ebx
    //   e8????????           |                     
    //   0fb7c0               | movzx               eax, ax
    $sequence_4 = { e8 ?? ?? ?? ?? c7 04 24 07 6c 00 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? eb 0f 50 50 }
    // n = 7, score = 100
    //   e8????????           |                     
    //   c70424076c0000       | mov                 dword ptr [esp], 0x6c07
    //   e8????????           |                     
    //   e8????????           |                     
    //   eb0f                 | jmp                 0x11
    //   50                   | push                eax
    //   50                   | push                eax
    $sequence_5 = { c7 44 24 50 00 00 00 00 88 44 24 17 6a 04 0f b6 44 24 1b }
    // n = 4, score = 100
    //   c744245000000000     | mov                 dword ptr [esp + 0x50], 0
    //   88442417             | mov                 byte ptr [esp + 0x17], al
    //   6a04                 | push                4
    //   0fb644241b           | movzx               eax, byte ptr [esp + 0x1b]
    $sequence_6 = { 85 c0 0f 8f ae 00 00 00 40 0f 84 a7 00 00 00 c7 84 24 3c 05 00 00 01 00 00 00 50 }
    // n = 6, score = 100
    //   85c0                 | test                eax, eax
    //   0f8fae000000         | jg                  0xb4
    //   40                   | inc                 eax
    //   0f84a7000000         | je                  0xad
    //   c784243c05000001000000     | mov    dword ptr [esp + 0x53c], 1
    //   50                   | push                eax
    $sequence_7 = { 89 54 24 08 74 0c 8b 10 8b 44 24 08 88 02 ff 01 }
    // n = 6, score = 100
    //   89542408             | mov                 dword ptr [esp + 8], edx
    //   740c                 | je                  0xe
    //   8b10                 | mov                 edx, dword ptr [eax]
    //   8b442408             | mov                 eax, dword ptr [esp + 8]
    //   8802                 | mov                 byte ptr [edx], al
    //   ff01                 | inc                 dword ptr [ecx]
    $sequence_8 = { 66 89 43 14 8b 44 24 2c 66 c1 c8 08 66 89 46 02 8b 44 24 10 }
    // n = 5, score = 100
    //   66894314             | mov                 word ptr [ebx + 0x14], ax
    //   8b44242c             | mov                 eax, dword ptr [esp + 0x2c]
    //   66c1c808             | ror                 ax, 8
    //   66894602             | mov                 word ptr [esi + 2], ax
    //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
    $sequence_9 = { c7 03 00 00 00 00 68 02 40 00 00 0f b7 84 24 4a 05 00 00 50 8d 74 24 18 56 }
  // n = 6, score = 100
  //   c70300000000         | mov                 dword ptr [ebx], 0
  //   6802400000           | push                0x4002
  //   0fb784244a050000     | movzx               eax, word ptr [esp + 0x54a]
  //   50                   | push                eax
  //   8d742418             | lea                 esi, [esp + 0x18]
  //   56                   | push                esi

  condition:
    7 of them and filesize < 122880
}

rule Hunting_qemu_plugin {
  meta:
    author      = "@captainGeech42"
    description = "Hunt for QEMU plugins"
    date        = "2024-01-13"
    version     = "1"
    DaysofYARA  = "13/100"

  condition:
    uint32be(0) == 0x7f454c46 and
    for 2 sym in elf.symtab: (
      (
        sym.name == "qemu_plugin_install" and
        sym.type == elf.STT_FUNC
      ) or (
        sym.name == "qemu_plugin_version" and
        sym.type == elf.STT_OBJECT
      )
    )
}

private rule elf_dyn {
  condition:
    file_elf_header and uint16(16) == 0x03
}

rule Mirai_Gen1 {
  strings:
    $s1 = ".symtab" fullword
    $s2 = ".shstrtab" fullword
    $s3 = ".note.gnu.property" fullword

  condition:
    file_elf_header and
    (
      $s1 and hash.md5(@s1[1], 0x64) == "cfea6ff0b826a05a3c24bd9b4da705c7"
    ) or
    (
      $s2 and hash.md5(@s2[1], 0x3C) == "6de76eb8aa868bf6751c01b7d120e909"
    ) or
    (
      $s3 and hash.md5(@s3[1], 0x74) == "5321a249df6dd47fabd3ca3dcc1ed7c9" or
      hash.md5(@s3[1], 0x74) == "5321a249df6dd47fabd3ca3dcc1ed7c9"
    )
}

rule Mirai_Gen2 {
  // meta:
  //   description = "Detect some Mirai's variants including Gafgyt and Tsunami variants (named by ClamAV) using section hash. File only"
  // file fa9878*95ec37, compiled Py

  strings:
    $ = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /" fullword ascii
    $ = "makeIPPacket" fullword ascii
    $ = "UDPRAW" fullword ascii
    $ = "sendRAW" fullword ascii
    $ = "HshrQjzbSjHs" fullword ascii

  condition:
    file_elf_header and any of them
}

rule Mirai_4c36 {
  // meta:
  //   md5 = "4c366b0552eac10a254ed2d177ba233d"

  strings:
    $ = "%9s %3hu %255[^\n]" fullword ascii
    $ = "oanacroane" fullword ascii

  condition:
    file_elf_header and any of them
}

rule Mirai_9c77 {
  // meta:
  //   md5 = "9c77a9f860f2643dc0cdbcd6bda65140"

  strings:
    $ = "31mip:%s" ascii

  condition:
    file_elf_header and any of them
}

rule Mirai_92a0 {
  // meta:
  //   md5 = "92a049c55539666bebc68c1a5d9d86ef"

  strings:
    $ = "4r3s b0tn3t" fullword ascii

  condition:
    file_elf_header and any of them
}

rule Rootkit_a669 {
  // meta:
  //   md5 = "1fccc4f70c2c800173b7c56558b74a95"
  //   md5 = "acf87e0165bc121eb384346d10c74997"
  //   descriptions = "Unknown Linux rootkit"

  strings:
    $ = "/proc/self/fd/%d" fullword ascii
    $ = "/proc/%s/stat" fullword ascii
    $ = "%d (%[^)]s" fullword ascii
    $ = "Error in dlsym: %s" fullword ascii

  condition:
    elf_dyn and all of them
}

rule Kinsing_ccef {
  // meta:
  //   md5 = "ccef46c7edf9131ccffc47bd69eb743b"
  //   sha256 = "c38c21120d8c17688f9aeb2af5bdafb6b75e1d2673b025b720e50232f888808a"
  //   description = "Kinsing rootkit from malwareBazaar"

  strings:
    $ = "is_hidden_file.c" fullword ascii
    $ = "%d (%[^)]s" fullword ascii
    $ = "chopN" fullword ascii

  condition:
    elf_dyn and
    (
      for 2 i in (0..elf.dynsym_entries):
      (
        elf.dynsym[i].type == elf.STT_FUNC and
        (
          elf.dynsym[i].name == "is_hidden_file" or
          elf.dynsym[i].name == "is_attacker" or
          elf.dynsym[i].name == "hide_tcp_ports"
        )
      ) or
      all of them
    )
}

rule Winnti_1acb {
  // meta:
  //   md5 = "1acb326773d6ba28d916871cb91af844"
  //   sha256 = "3b378846bc429fdf9bec08b9635885267d8d269f6d941ab1d6e526a03304331b"

  strings:
    $ = "Yi-!*" fullword ascii
    $ = { (7c | 3d) (42 | 43) 66 4b }
    $ = "get_our_sockets" fullword ascii
    $ = "cmdlineH" fullword ascii
    $ = "is_invisible_with_pids" fullword ascii

  condition:
    elf_dyn and
    (
      for 2 i in (0..elf.dynsym_entries):
      (
        elf.dynsym[i].type == elf.STT_FUNC and
        (
          elf.dynsym[i].name == "is_invisible_with_pids" or
          elf.dynsym[i].name == "get_our_pids" or
          elf.dynsym[i].name == "get_our_sockets" or
          elf.dynsym[i].name == "check_is_our_proc_dir"
        )
      ) or
      2 of them
    )
}

rule LDPreload_ImpFuncs {
  // meta:
  //   description = "Find DYN ELF bins that imports common function LD_PRELOAD rootkits hook"

  condition:
    // The limitation of dynsym_entries number is to avoid false positive detecting libc
    elf_dyn and elf.dynsym_entries < 300 and (
      for 7 i in (0..elf.dynsym_entries):
      (
        elf.dynsym[i].type == elf.STT_FUNC and
        (
          elf.dynsym[i].name == "access" or
          elf.dynsym[i].name == "dlsym" or
          elf.dynsym[i].name == "fopen" or
          elf.dynsym[i].name == "lstat" or
          elf.dynsym[i].name == "strstr" or
          elf.dynsym[i].name == "tmpfile" or
          elf.dynsym[i].name == "unlink"
        )
      )
    )
}

rule SSHDoor_Generic {
  strings:
    // TODO need to test runtime
    $ = "backdoor.h" fullword ascii
    $ = "backdoor_active" fullword ascii

  condition:
    file_elf_header and
    (
      for 1 i in (0..elf.symtab_entries):
      (
        elf.symtab[i].name == "backdoor_active" and elf.symtab[i].type == elf.STT_OBJECT
      ) or
      all of them
    )
}

rule Keylog_Xspy {
  // meta:
  //   descriptions = "Rule to detect X11 Keylogger"
  // Yara failed to detect running process because it can't load elf information such as elf.type

  strings:
    $ = "DISPLAY" fullword ascii
    $ = "for snoopng" fullword ascii

  condition:
    file_elf_header and all of them
}

rule Exploit_DirtyCow {
  // meta:
  //   hash = "0b22cdc1b1b1f944e4ca8fced2e234d14aeeef830970e8ae7491cbdcb3e11460"
  //   reference = "https://www.virustotal.com/gui/file/0b22cdc1b1b1f944e4ca8fced2e234d14aeeef830970e8ae7491cbdcb3e11460"

  strings:
    $ = "/tmp/passwd.bak" ascii
    $ = "madvise %d" fullword ascii
    $ = "ptrace %d" fullword ascii
    $ = "DON'T FORGET TO RESTORE!" ascii

  condition:
    elf.type == elf.ET_EXEC and
    (
      for 6 i in (0..elf.dynsym_entries):
      (
        elf.dynsym[i].type == elf.STT_FUNC and (
          elf.dynsym[i].name == "crypt" or
          elf.dynsym[i].name == "madvise" or
          elf.dynsym[i].name == "ptrace" or
          elf.dynsym[i].name == "waitpid" or
          elf.dynsym[i].name == "getpass" or
          elf.dynsym[i].name == "pthread_create"
        )
      ) or
      all of them
    )
}

rule HUNT_ELF_FREEBSD_GOLANG_KERNEL_MODULE_1 {
  meta:
    author      = "@qutluch@infosec.exchange"
    description = "Rule to surface FreeBSD kernel modules built with Golang."
    DaysofYARA  = "30/100"
    license     = "BSD-2-Clause"
    date        = "2024-01-31"
    version     = "1.0"

  strings:
    // Thanks to captainGeech42 for his Golang rule.
    // https://github.com/100DaysofYARA/2024/blob/main/captainGeech/day002_golang.yara
    $golang1 = " Go build ID: "
    $golang2 = "CGO_ENABLED"
    $golang3 = "GOOS"
    $golang4 = "GOARCH"
    $golang5 = "runtime.morestack_noctxt"
    $golang6 = "gopkg.in"
    $f1      = "module_register_init"

  condition:
    uint32(0) == 0x464c457f
    and uint16(0x7) == 0x9
    and
    (
      for any section in elf.sections: (
        section.name == ".gopclntab" or section.name == ".go.buildinfo"
      ) or
      4 of ($golang*)
    )
    and $f1
}

rule REVERSINGLABS_Linux_Trojan_Bibiwiper: TC_DETECTION MALICIOUS MALWARE FILE {
  meta:
    description         = "Yara rule that detects BiBiWiper trojan."
    author              = "ReversingLabs"
    id                  = "c370dde0-71ff-5832-b131-6d61beb02b9b"
    date                = "2023-11-28"
    modified            = "2023-11-28"
    reference           = "ReversingLabs"
    source_url          = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/d35a6845dcd00f2840f690611612b04dda6d195d/yara/trojan/Linux.Trojan.BiBiWiper.yara#L1-L76"
    license_url         = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/d35a6845dcd00f2840f690611612b04dda6d195d/LICENSE"
    logic_hash          = "8f290141d5da660463dede6df571d774448e136e2993a0a4c706245464e1239e"
    score               = 75
    quality             = 90
    tags                = "TC_DETECTION, MALICIOUS, MALWARE, FILE"
    status              = "RELEASED"
    sharing             = "TLP:WHITE"
    category            = "MALWARE"
    tc_detection_type   = "Trojan"
    tc_detection_name   = "BiBiWiper"
    tc_detection_factor = 5
    importance          = 25

  strings:
    $destroy_files_p1 = {
      55 48 89 E5 53 48 81 EC ?? ?? ?? ?? 48 89 BD ?? ?? ?? ?? 48 89 B5 ?? ?? ?? ?? 48 89
      95 ?? ?? ?? ?? 48 89 8D ?? ?? ?? ?? 4C 89 85 ?? ?? ?? ?? 44 89 8D ?? ?? ?? ?? 48 8B
      05 ?? ?? ?? ?? 48 83 C0 ?? 48 89 05 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 48 BA ?? ?? ??
      ?? ?? ?? ?? ?? 48 89 C8 48 F7 EA 48 89 D0 48 C1 F8 ?? 48 89 CA 48 C1 FA ?? 48 29 D0
      48 69 D0 ?? ?? ?? ?? 48 89 C8 48 29 D0 48 85 C0 0F 94 C0 84 C0 74 ?? E8 ?? ?? ?? ??
      48 8B 85 ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 89
      D6 48 89 C7 E8 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ??
      ?? 48 8D 85 ?? ?? ?? ?? 48 8D 8D ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 89 CE 48 89 C7
      E8 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 48 8D 95 ?? ?? ?? ?? 48 8D 8D ?? ?? ?? ?? 48 89
      CE 48 89 C7 E8 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 8D 85 ??
      ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 8D
      8D ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 CE 48 89 C7 E8 ?? ?? ?? ??
      48 8D 8D ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 CE 48 89 C7 E8 ?? ??
      ?? ?? 48 8D 95 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 48 89 D6 48 89 C7 E8 ?? ?? ?? ?? 48
      89 C3 48 8D 8D ?? ?? ?? ?? 48 8D 45 ?? BA ?? ?? ?? ?? 48 89 CE 48 89 C7 E8 ?? ?? ??
      ?? 48 8D 45 ?? 48 89 DE 48 89 C7 E8 ?? ?? ?? ?? 48 8D 45 ?? 48 89 C7 E8
    }
    $destroy_files_p2 = {
      48 8D 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ??
      ?? ?? 48 8B 85 ?? ?? ?? ?? 48 C1 E0 ?? 48 89 45 ?? 48 8B B5 ?? ?? ?? ?? 48 8B 85 ??
      ?? ?? ?? BA ?? ?? ?? ?? 48 F7 F6 48 8B 55 ?? 48 29 D0 48 89 45 ?? 83 BD ?? ?? ?? ??
      ?? 7E ?? 8B 85 ?? ?? ?? ?? 83 E8 ?? 48 98 48 0F AF 45 ?? BA ?? ?? ?? ?? 48 F7 B5 ??
      ?? ?? ?? 48 89 D0 48 89 C1 48 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 CE 48 89 C7 E8
      ?? ?? ?? ?? EB ?? 48 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 C7 E8 ??
      ?? ?? ?? 48 8B 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 48 8B 45 ?? 48 39
      85 ?? ?? ?? ?? 73 ?? BB ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 55 ?? 48 8B 85 ?? ?? ?? ??
      48 29 D0 48 89 45 ?? 48 8B 45 ?? 48 89 45 ?? 48 8D 55 ?? 48 8D 45 ?? 48 89 D6 48 89
      C7 E8 ?? ?? ?? ?? 48 8B 00 48 89 45 ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 45
      ?? 48 8B 45 ?? 89 C2 48 8D 85 ?? ?? ?? ?? 89 D6 48 89 C7 E8 ?? ?? ?? ?? C7 45 ?? ??
      ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 5D ?? 48 8D 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48
    }
    $destroy_files_p3 = {
      89 C7 48 8B 85 ?? ?? ?? ?? 48 89 C1 BA ?? ?? ?? ?? 48 89 DE E8 ?? ?? ?? ?? 48 8B 85
      ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 48 8B 55 ?? 48 8B 45 ?? 48 01 C2 48
      8B 45 ?? 48 01 D0 48 39 85 ?? ?? ?? ?? 73 ?? 48 8B 55 ?? 48 8B 85 ?? ?? ?? ?? 48 29
      D0 48 8B 55 ?? 48 29 D0 48 89 45 ?? 48 83 7D ?? ?? 7E ?? 48 8B 4D ?? 48 8B 85 ?? ??
      ?? ?? BA ?? ?? ?? ?? 48 89 CE 48 89 C7 E8 ?? ?? ?? ?? 83 45 ?? ?? 8B 45 ?? 48 98 48
      39 85 ?? ?? ?? ?? 0F 8F ?? ?? ?? ?? EB ?? 90 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48
      8D 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? BB ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 48 89
      C7 E8 ?? ?? ?? ?? 83 FB ?? E9 ?? ?? ?? ?? 48 89 C3 48 8D 85 ?? ?? ?? ?? 48 89 C7 E8
      ?? ?? ?? ?? EB ?? 48 89 C3 48 8D 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? EB ?? 48 89
      C3 48 8D 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 D8 48 89 C7 E8 ?? ?? ?? ?? 48
      89 C3 48 8D 45 ?? 48 89 C7 E8 ?? ?? ?? ?? EB ?? 48 89 C3 48 8D 85 ?? ?? ?? ?? 48 89
      C7 E8 ?? ?? ?? ?? EB ?? 48 89 C3 48 8D 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? EB ??
      48 89 C3 48 8D 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? EB ?? 48 89 C3 48 8D 85 ?? ??
      ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 D8 48 89 C7 E8 ?? ?? ?? ?? 48 8B 5D ?? C9 C3
    }

  condition:
    uint32(0) == 0x464C457F and (all of ($destroy_files_p*))
}

rule REVERSINGLABS_Linux_Trojan_Acidrain: TC_DETECTION MALICIOUS MALWARE FILE {
  meta:
    description         = "Yara rule that detects AcidRain trojan."
    author              = "ReversingLabs"
    id                  = "802c7eb7-d407-5b07-a6b4-4648d3ad80e9"
    date                = "2024-05-10"
    modified            = "2024-05-10"
    reference           = "ReversingLabs"
    source_url          = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/d35a6845dcd00f2840f690611612b04dda6d195d/yara/trojan/Linux.Trojan.AcidRain.yara#L1-L67"
    license_url         = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/d35a6845dcd00f2840f690611612b04dda6d195d/LICENSE"
    logic_hash          = "5b47a0de8bda09d217f8a148e561f3da7ce4945f011f4a9b5dbbca88157d3080"
    score               = 75
    quality             = 90
    tags                = "TC_DETECTION, MALICIOUS, MALWARE, FILE"
    status              = "RELEASED"
    sharing             = "TLP:WHITE"
    category            = "MALWARE"
    tc_detection_type   = "Trojan"
    tc_detection_name   = "AcidRain"
    tc_detection_factor = 5
    importance          = 25

  strings:
    $destroy_files_using_ioctls    = {
      55 89 E5 57 BF ?? ?? ?? ?? 56 53 81 EC ?? ?? ?? ?? 89 7C 24 ?? 8B 45 ?? 89 04 24 E8
      ?? ?? ?? ?? 85 C0 89 C3 78 ?? 8D 85 ?? ?? ?? ?? 89 44 24 ?? 89 1C 24 E8 ?? ?? ?? ??
      8B 85 ?? ?? ?? ?? 25 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 ?? 81 C4 ?? ?? ?? ?? 5B 5E 5F 5D
      C3 8D 45 ?? BE ?? ?? ?? ?? 89 44 24 ?? 89 74 24 ?? 89 1C 24 E8 ?? ?? ?? ?? 8B 4D ??
      8B 55 ?? C7 45 ?? ?? ?? ?? ?? 85 C9 89 55 ?? 74 ?? 8D 75 ?? 8D B6 ?? ?? ?? ?? 8D BF
      ?? ?? ?? ?? B8 ?? ?? ?? ?? 89 74 24 ?? 89 44 24 ?? 89 1C 24 E8 ?? ?? ?? ?? B8 ?? ??
      ?? ?? 89 74 24 ?? 89 44 24 ?? 89 1C 24 E8 ?? ?? ?? ?? 8B 45 ?? 8B 55 ?? 01 D0 39 45
      ?? 89 45 ?? 77 ?? 81 FA ?? ?? ?? ?? BF ?? ?? ?? ?? 0F 86 ?? ?? ?? ?? 8B 45 ?? C7 45
      ?? ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 75 ?? EB ?? 31 C9 89 4C 24 ?? 8B 45 ?? 89
      1C 24 89 44 24 ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 89 7C 24 ?? 89 1C 24 89 44 24 ?? E8
      ?? ?? ?? ?? 8B 55 ?? 8B 45 ?? 01 D0 39 45 ?? 89 45 ?? 76 ?? B8 ?? ?? ?? ?? 89 74 24
      ?? 89 44 24 ?? 89 1C 24 E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 89 74 24 ?? 89 44 24 ?? 89 1C
      24 E8 ?? ?? ?? ?? 80 7D ?? ?? 75 ?? A1 ?? ?? ?? ?? 89 7D ?? 89 45 ?? 8B 45 ?? 89 45
      ?? 8D 45 ?? 89 44 24 ?? B8 ?? ?? ?? ?? 89 44 24 ?? 89 1C 24 E8 ?? ?? ?? ?? 8B 55 ??
      8B 45 ?? 01 D0 39 45 ?? 89 45 ?? 77 ?? 8D 74 26 ?? 8D BC 27 ?? ?? ?? ?? 31 FF 89 1C
      24 E8 ?? ?? ?? ?? 31 C0 89 44 24 ?? 89 7C 24 ?? 89 1C 24 E8 ?? ?? ?? ?? 8B 75 ?? C7
      45 ?? ?? ?? ?? ?? 85 F6 74 ?? 8D 75 ?? 8D 76 ?? B9 ?? ?? ?? ?? 89 74 24 ?? 89 4C 24
      ?? 89 1C 24 E8 ?? ?? ?? ?? 8B 55 ?? 8B 45 ?? 01 D0 39 45 ?? 89 45 ?? 77 ?? 89 1C 24
      E8 ?? ?? ?? ?? 89 1C 24 E8 ?? ?? ?? ?? 81 C4 ?? ?? ?? ?? 5B 5E 5F 5D C3
    }
    $destroy_files_using_overwrite = {
      55 89 E5 83 EC ?? 89 5D ?? 8B 5D ?? 8D 45 ?? 89 75 ?? 89 7D ?? C7 45 ?? ?? ?? ?? ??
      C7 45 ?? ?? ?? ?? ?? 89 44 24 ?? 89 1C 24 E8 ?? ?? ?? ?? 85 C0 75 ?? 8B 5D ?? 8B 75
      ?? 8B 7D ?? 89 EC 5D C3
    }
    $redundant_reboot_attempts     = {
      C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 04 24 ??
      ?? ?? ?? E8 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 0F
      84 ?? ?? ?? ?? 8D B6 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 85 C0 0F
      84 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 8D 76 ?? 0F 84 ?? ?? ?? ?? A1 ?? ?? ?? ?? 89 04
      24 E8 ?? ?? ?? ?? 31 D2 83 C4 ?? 89 D0 59 5B 5E 5F 5D 8D 61 ?? C3
    }

  condition:
    uint32(0) == 0x464C457F and ($destroy_files_using_ioctls) and ($destroy_files_using_overwrite) and ($redundant_reboot_attempts)
}

rule REVERSINGLABS_Linux_Virus_Vit: TC_DETECTION MALICIOUS MALWARE FILE {
  meta:
    description         = "Yara rule that detects Vit virus."
    author              = "ReversingLabs"
    id                  = "4515fe43-4c5a-521d-82b7-273823f0c64e"
    date                = "2024-06-09"
    date                = "2024-06-09"
    modified            = "2023-06-07"
    reference           = "ReversingLabs"
    source_url          = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/d35a6845dcd00f2840f690611612b04dda6d195d/yara/virus/Linux.Virus.Vit.yara#L3-L36"
    license_url         = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/d35a6845dcd00f2840f690611612b04dda6d195d/LICENSE"
    logic_hash          = "2fba7a081dfca85aee5c7f3b33414b799ed52ca6aa5bbf031da040aaa75acde9"
    score               = 75
    quality             = 90
    tags                = "TC_DETECTION, MALICIOUS, MALWARE, FILE"
    status              = "RELEASED"
    sharing             = "TLP:WHITE"
    category            = "MALWARE"
    tc_detection_type   = "Virus"
    tc_detection_factor = 5
    importance          = 25

  strings:
    $vit_entry_point = {
      55 89 E5 81 EC 40 31 00 00 57 56 50 53 51 52 C7 85 D8 CE FF FF 00 00 00 00 C7 85 D4
      CE FF FF 00 00 00 00 C7 85 FC CF FF FF CA 08 00 00 C7 85 F8 CF FF FF B8 06 00 00 C7
      85 F4 CF FF FF AD 08 00 00 C7 85 F0 CF FF FF 50 06 00 00 6A 00 6A 00 8B 45 08 50 E8
      18 FA FF FF 89 C6 83 C4 0C 85 F6 0F 8C E6 01 00 00 6A 00 68 ?? ?? ?? ?? 56 E8 2E FA
      FF FF 83 C4 0C 85 C0 0F 8C C4 01 00 00 8B 85 FC CF FF FF 50 8D 85 00 D0 FF FF 50 56
      E8 2A FA FF FF 89 C2 8B 85 FC CF FF FF 83 C4 0C 39 C2 0F 85 9D 01 00 00 56 E8 E1 F9
      FF FF BE FF FF FF FF 6A 00 6A 00 E9
    }
    $vit_str         = "vi324.tmp"

  condition:
    uint32(0) == 0x464C457F and $vit_entry_point at elf.entry_point and $vit_str
}

rule REVERSINGLABS_Linux_Backdoor_Krasue: TC_DETECTION MALICIOUS MALWARE FILE {
  meta:
    description         = "Yara rule that detects Krasue backdoor."
    author              = "ReversingLabs"
    id                  = "3187eebf-ef70-585f-85cf-5813025c785e"
    date                = "2024-03-04"
    modified            = "2024-03-04"
    reference           = "ReversingLabs"
    source_url          = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/d35a6845dcd00f2840f690611612b04dda6d195d/yara/backdoor/Linux.Backdoor.Krasue.yara#L1-L127"
    license_url         = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/d35a6845dcd00f2840f690611612b04dda6d195d/LICENSE"
    logic_hash          = "e2daa35ef9e0793062c9fb3bd8e4838e1e81ee3d228d8117b1c3b0e72eb8e151"
    score               = 75
    quality             = 90
    tags                = "TC_DETECTION, MALICIOUS, MALWARE, FILE"
    status              = "RELEASED"
    sharing             = "TLP:WHITE"
    category            = "MALWARE"
    tc_detection_type   = "Backdoor"
    tc_detection_name   = "Krasue"
    tc_detection_factor = 5
    importance          = 25

  strings:
    $switch_server   = {
      8B 05 ?? ?? ?? ?? FF C0 3B 05 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? 7C ?? C7 05 ?? ?? ?? ??
      ?? ?? ?? ?? 48 63 05 ?? ?? ?? ?? 85 C0 75 ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? EB ?? 8B
      15 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? C6 05 ?? ?? ?? ?? ?? C6 05 ?? ?? ?? ??
      ?? 89 15 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? 66 89 15 ?? ?? 23 00 48 8B 04 C5 ?? ?? ?? ??
      66 C7 05 ?? ?? 23 00 ?? ?? 8B 10 89 15 ?? ?? ?? ?? 66 8B 40 ?? 66 89 05 ?? ?? 23 00
      C3
    }
    $get_hostname    = {
      41 55 41 54 31 F6 55 53 31 C0 BF ?? ?? ?? ?? 48 81 EC ?? ?? ?? ?? E8 ?? ?? ?? ?? 85
      C0 0F 88 ?? ?? ?? ?? 48 89 E6 89 C7 89 C3 E8 ?? ?? ?? ?? 48 8B 6C 24 ?? 45 31 C9 31
      FF 41 89 D8 B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 41 89 EC 48 63 ED 48 89 EE E8 ?? ?? ?? ??
      BE ?? ?? ?? ?? 48 89 C7 49 89 C5 E8 ?? ?? ?? ?? 83 F8 ?? 74 ?? 48 63 D0 49 8D 74 15
      ?? 8D 50 ?? 48 63 D2 44 39 E2 41 89 D0 7D ?? 48 FF C2 41 80 7C 15 ?? ?? 75 ?? 44 89
      C1 41 FF C8 BA ?? ?? ?? ?? 29 C1 4D 63 C0 48 89 D7 83 E9 ?? 48 63 C9 F3 A4 41 C6 80
      ?? ?? ?? ?? ?? 4C 89 EF 48 89 EE E8 ?? ?? ?? ?? 89 DF E8 ?? ?? ?? ?? 48 81 C4 ?? ??
      ?? ?? 5B 5D 41 5C 41 5D C3
    }
    $start_server_p1 = {
      41 57 41 56 31 D2 41 55 41 54 BE ?? ?? ?? ?? 55 53 89 FB BF ?? ?? ?? ?? 48 81 EC ??
      ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 89 05 ?? ?? ?? ?? 79 ?? 83 CF ?? E9 ?? ?? ?? ?? 48 8D
      4C 24 ?? 41 B8 ?? ?? ?? ?? BE ?? ?? ?? ?? BA ?? ?? ?? ?? 89 C7 C7 44 24 ?? ?? ?? ??
      ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 31 C0 B9 ?? ?? ?? ?? 48 89 D7 F3 AB 31 FF 66 C7 05
      ?? ?? 23 00 ?? ?? E8 ?? ?? ?? ?? 0F B7 FB 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 3D ??
      ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 66 89 05 ?? ?? 23 00 E8 ?? ?? ?? ?? 85 C0 78
      ?? 4C 8D A4 24 ?? ?? ?? ?? 4C 8D AC 24 ?? ?? ?? ?? 4C 8D 74 24 ?? C7 05 ?? ?? ?? ??
      ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 31 C9 41 B9 ?? ?? ?? ?? 41 B8 ?? ?? ?? ?? BA ?? ?? ??
      ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 48 89 C3 0F 88 ?? ?? ?? ?? 31 C0 B9 ?? ?? ??
      ?? 4C 89 E7 83 FB ?? F3 AB 7E ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ??
      ?? 85 C0 75 ?? B8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 41 B8 ?? ?? ?? ?? 44 8D 08 31 C9 BA
      ?? ?? ?? ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? EB ?? 83 FB ?? 75 ?? BE ?? ?? ?? ?? 4C 89
      E7 E8 ?? ?? ?? ?? 85 C0 75 ?? 8B 05 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 05
      ?? ?? ?? ?? E9 ?? ?? ?? ?? 89 DA BE ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ?? 4C 89 E6 89
      C2 8A 06 89 F5 44 29 E5 3C ?? 75 ?? 80 7E ?? ?? 75 ?? 48 83 C6 ?? EB ?? 3C ?? 75 ??
      80 7E ?? ?? 75 ?? 41 B8 ?? ?? ?? ?? 31 C0 B9 ?? ?? ?? ?? 4C 89 C7 4C 8B 05 ?? ?? ??
      ?? F3 AB 8B 7E ?? 66 8B 4E ?? 4C 89 06 C6 06 ?? 45 31 C0 C6 46 ?? ?? BE
    }
    $start_server_p2 = {
      66 C7 05 ?? ?? 23 00 ?? ?? 89 3D ?? ?? ?? ?? 66 89 0D ?? ?? 23 00 89 3D ?? ?? ?? ??
      66 89 0D ?? ?? 23 00 48 89 F7 B9 ?? ?? ?? ?? 4C 89 E6 F3 AB E9 ?? ?? ?? ?? 85 ED 75
      ?? 48 63 DD BA ?? ?? ?? ?? BE ?? ?? ?? ?? 4C 01 E3 48 89 DF E8 ?? ?? ?? ?? 85 C0 75
      ?? 48 8D 7B ?? E8 ?? ?? ?? ?? 6B C0 ?? B9 ?? ?? ?? ?? BE ?? ?? ?? ?? 4C 89 EF 99 F7
      F9 31 C0 E8 ?? ?? ?? ?? EB ?? 8D 45 ?? 48 8D 54 24 ?? 48 98 85 C0 78 ?? 49 8B 0C 04
      48 83 C2 ?? 48 83 E8 ?? 48 89 4A ?? C6 42 ?? ?? C6 42 ?? ?? EB ?? BA ?? ?? ?? ?? BE
      ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 85 C0 75 ?? 48 8B 05 ?? ?? ?? ?? 89 E9 4C 89 F6
      89 2D ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? B8 ?? ?? ?? ??
      48 89 C7 F3 A4 BE ?? ?? ?? ?? 4C 89 EF E8 ?? ?? ?? ?? 31 C0 48 83 C9 ?? 4C 89 EF F2
      AE 48 89 C8 48 F7 D0 48 8D 50 ?? E9 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89
      DF E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 44 8B 0D ?? ?? ?? ?? 44
      8B 3D ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 89 4C 24 ?? 44 89 4C 24 ?? E8 ?? ?? ?? ?? 48 83
      EC ?? 41 89 C0 BA ?? ?? ?? ?? 8B 4C 24 ?? 4C 89 EF BE ?? ?? ?? ?? 31 C0 51 8B 0D ??
      ?? ?? ?? 41 57 53 44 8B 4C 24 ?? E8 ?? ?? ?? ?? 31 C0 48 83 C9 ?? 4C 89 EF F2 AE 48
      83 C4 ?? 48 89 C8 48 F7 D0 48 8D 50 ?? 41 89 E8 4C 89 F1 4C 89 EE 8B 3D ?? ?? ?? ??
      E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 DF E8
    }
    $start_server_p3 = {
      85 C0 75 ?? 31 FF E8 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 DF E8 ?? ?? ??
      ?? 85 C0 75 ?? BF ?? ?? ?? ?? EB ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 DF E8 ?? ??
      ?? ?? 85 C0 75 ?? BF ?? ?? ?? ?? EB ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 DF E8 ??
      ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? E8 ?? ?? ?? ?? 41 89 C7 E8 ?? ?? ?? ?? 45 85 FF 0F
      85 ?? ?? ?? ?? 48 8D 7C 24 ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 41 89 C4 75 ?? 8B
      7C 24 ?? E8 ?? ?? ?? ?? 8B 7C 24 ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 7C 24 ?? BE ??
      ?? ?? ?? E8 ?? ?? ?? ?? 8B 7C 24 ?? E8 ?? ?? ?? ?? 48 8D 4B ?? 45 31 C0 BA ?? ?? ??
      ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? 31 C0 E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B 7C 24 ?? E8
      ?? ?? ?? ?? 8B 7C 24 ?? 48 8D B4 24 ?? ?? ?? ?? BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0
      89 C3 7E ?? 4C 8D AC 24 ?? ?? ?? ?? 8D 04 2B 3D ?? ?? ?? ?? 7E ?? 8B 3D ?? ?? ?? ??
      BA ?? ?? ?? ?? 48 8D 4C 24 ?? 4C 89 EE 29 EA 41 89 E8 49 81 C5 ?? ?? ?? ?? 81 EB ??
      ?? ?? ?? E8 ?? ?? ?? ?? EB ?? 8B 3D ?? ?? ?? ?? 48 8D 4C 24 ?? 41 89 E8 89 DA 4C 89
      EE E8 ?? ?? ?? ?? EB ?? 31 F6 BA ?? ?? ?? ?? 44 89 E7 E8 ?? ?? ?? ?? 85 C0 0F 85
    }
    $send_encrypt    = {
      E8 ?? ?? ?? ?? 41 8D 7E ?? 49 89 C5 48 63 FF E8 ?? ?? ?? ?? 48 63 54 24 ?? 48 89 C7
      4C 89 FE 48 8D 0C 13 C6 04 08 ?? 89 D1 48 01 C2 F3 A4 48 89 D7 48 89 EE 48 89 D9 44
      89 F2 F3 A4 48 89 C6 EB ?? 8D 7B ?? 48 63 FF E8 ?? ?? ?? ?? 89 DA 49 89 C5 48 89 EE
      4C 89 EF E8 ?? ?? ?? ?? 44 8B 0D ?? ?? ?? ?? 4C 89 EE 44 89 E7 48 63 D0 41 B8 ?? ??
      ?? ?? 31 C9 E8 ?? ?? ?? ?? 48 83 C4 ?? 5B 5D 41 5C 41 5D 41 5E 41 5F C3
    }
    $notify_server   = {
      48 81 EC ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? 48 89 E0 85 D2 7E ?? BE ?? ?? ?? ?? 89 D1 48
      89 E7 F3 A4 48 63 D2 BE ?? ?? ?? ?? B9 ?? ?? ?? ?? 4C 8D 04 10 41 B9 ?? ?? ?? ?? 48
      83 C2 ?? 4C 89 C7 41 B8 ?? ?? ?? ?? F3 A4 8B 3D ?? ?? ?? ?? 48 89 C6 E8 ?? ?? ?? ??
      8B 05 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? 48 81 C4 ?? ?? ?? ?? C3
    }

  condition:
    uint32(0) == 0x464C457F and ($switch_server) and ($get_hostname) and (all of ($start_server_p*)) and ($send_encrypt) and ($notify_server)
}

rule REVERSINGLABS_Linux_Backdoor_Linodas: TC_DETECTION MALICIOUS MALWARE FILE {
  meta:
    description         = "Yara rule that detects Linodas backdoor."
    author              = "ReversingLabs"
    id                  = "2b197346-abce-5cff-938f-bb8742e03168"
    date                = "2024-05-22"
    modified            = "2024-05-22"
    reference           = "ReversingLabs"
    source_url          = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/d35a6845dcd00f2840f690611612b04dda6d195d/yara/backdoor/Linux.Backdoor.Linodas.yara#L1-L216"
    license_url         = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/d35a6845dcd00f2840f690611612b04dda6d195d/LICENSE"
    logic_hash          = "12445771106e36b74b1ea292a8a25cab66bcaf0a08cf88d39a9f1bb13c6f525b"
    score               = 75
    quality             = 90
    tags                = "TC_DETECTION, MALICIOUS, MALWARE, FILE"
    status              = "RELEASED"
    sharing             = "TLP:WHITE"
    category            = "MALWARE"
    tc_detection_type   = "Backdoor"
    tc_detection_name   = "Linodas"
    tc_detection_factor = 5
    importance          = 25

  strings:
    $persistence_mechanism_ubuntu         = {
      41 54 BE ?? ?? ?? ?? 55 53 48 81 EC ?? ?? ?? ?? 48 8D 6C 24 ?? 48 8D 54 24 ?? 48 89
      EF E8 ?? ?? ?? ?? 48 8B 7C 24 ?? 31 F6 E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8D 5C 24 ?? 48
      89 EE 48 89 DF E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 8B 5C 24 ?? 48 83 EB ?? 48
      81 FB ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 48 8D 6C 24 ?? 48 8D 54 24 ?? BE ?? ?? ?? ?? 48
      89 EF E8 ?? ?? ?? ?? 48 8B 7C 24 ?? 31 F6 E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8D 5C 24 ??
      48 89 EE 48 89 DF E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 8B 5C 24 ?? 48 83 EB ??
      48 81 FB ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 48 8D 5C 24 ?? 48 89 EE 48 89 DF E8 ?? ?? ??
      ?? 48 89 DF E8 ?? ?? ?? ?? 48 8B 5C 24 ?? 41 BC ?? ?? ?? ?? 48 83 EB ?? 4C 39 E3 0F
      85 ?? ?? ?? ?? 4C 8B 44 24 ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 E7
      E8 ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? 85 C0
      74 ?? 48 8B 4C 24 ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48
      8D 5C 24 ?? 4C 8B 44 24 ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 DF E8
      ?? ?? ?? ?? 48 89 DE 48 89 E7 E8 ?? ?? ?? ?? 48 8B 5C 24 ?? 48 83 EB ?? 49 39 DC 0F
      85 ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 E7 E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 ?? BA
      ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 5C 24 ?? 4C 8B 44 24
      ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 DE 48
      89 E7 E8 ?? ?? ?? ?? 48 8B 5C 24 ?? 48 83 EB ?? 49 39 DC 0F 85 ?? ?? ?? ?? BE ?? ??
      ?? ?? 48 89 E7 E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 ?? BA ?? ?? ?? ?? BE ?? ?? ??
      ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 1C 24 48 83 EB ?? 49 39 DC 0F 85 ?? ?? ?? ??
      48 8B 5C 24 ?? 48 83 EB ?? 49 39 DC 0F 85 ?? ?? ?? ?? 48 8B 5C 24 ?? 48 83 EB ?? 49
      39 DC 0F 85 ?? ?? ?? ?? 48 81 C4 ?? ?? ?? ?? 5B 5D 41 5C C3
    }
    $network_communication_1              = {
      48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 F3 4C 89 64 24 ?? 4C 89 6C 24 ?? 48 81 EC ?? ??
      ?? ?? 48 8B 06 48 89 FD 89 54 24 ?? 45 89 C4 48 83 78 ?? ?? 0F 84 ?? ?? ?? ?? 4C 8D
      6C 24 ?? 48 8B 33 4C 89 EF E8 ?? ?? ?? ?? 48 8B 44 24 ?? 48 83 78 ?? ?? 0F 84 ?? ??
      ?? ?? 45 84 E4 0F 85 ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 88 45
      ?? 80 7D ?? ?? 0F 84 ?? ?? ?? ?? C6 45 ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ??
      ?? ?? E8 ?? ?? ?? ?? 83 F8 ?? 89 C5 0F 84 ?? ?? ?? ?? 48 8D 4C 24 ?? 41 B8 ?? ?? ??
      ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 89 C7 48 C7 44 24 ?? ?? ?? ?? ?? 48 C7 44 24 ?? ??
      ?? ?? ?? 48 8D 5C 24 ?? E8 ?? ?? ?? ?? 48 8D 4C 24 ?? BA ?? ?? ?? ?? BE ?? ?? ?? ??
      41 B8 ?? ?? ?? ?? 89 EF 48 C7 44 24 ?? ?? ?? ?? ?? 48 C7 44 24 ?? ?? ?? ?? ?? E8 ??
      ?? ?? ?? 48 8B 7C 24 ?? 48 C7 44 24 ?? ?? ?? ?? ?? 8B 44 24 ?? 48 C7 44 24 ?? ?? ??
      ?? ?? 66 C1 C8 ?? 66 C7 44 24 ?? ?? ?? 66 89 44 24 ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ??
      89 44 24 ?? 48 89 DE 89 EF E8 ?? ?? ?? ?? 83 C0 ?? 0F 84 ?? ?? ?? ?? 0F 1F 44 00 ??
      48 8B 5C 24 ?? 48 83 EB ?? 48 81 FB ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 89 E8 48 8B 5C 24
      ?? 48 8B 6C 24 ?? 4C 8B 64 24 ?? 4C 8B AC 24 ?? ?? ?? ?? 48 81 C4 ?? ?? ?? ?? C3
    }
    $network_communication_2              = {
      48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 FB 4C 89 64 24 ?? BE ?? ?? ?? ?? 48 83 EC ?? BF
      ?? ?? ?? ?? E8 ?? ?? ?? ?? 84 C0 74 ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 84 C0 0F 84 ??
      ?? ?? ?? 48 8D 73 ?? 48 8D 53 ?? BF ?? ?? ?? ?? 48 8D 6C 24 ?? 45 31 E4 E8 ?? ?? ??
      ?? 48 89 DF E8 ?? ?? ?? ?? 48 8B 73 ?? 48 89 EF E8 ?? ?? ?? ?? 48 8B 44 24 ?? 48 83
      78 ?? ?? 74 ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 84 C0 0F 84 ?? ?? ?? ??
      4C 8D 64 24 ?? 48 89 EE 4C 89 E7 E8 ?? ?? ?? ?? 4C 89 E6 48 89 DF E8 ?? ?? ?? ?? 48
      8B 6C 24 ?? 41 89 C4 48 83 ED ?? 48 81 FD ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 45 84 E4 74
      ?? 80 7B ?? ?? 0F 84 ?? ?? ?? ?? 90 48 89 DF E8 ?? ?? ?? ?? 48 8B 5C 24 ?? 41 0F B6
      EC 48 83 EB ?? 48 81 FB ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 89 E8 48 8B 5C 24 ?? 48 8B 6C
      24 ?? 4C 8B 64 24 ?? 48 83 C4 ?? C3
    }
    $persistence_mechanism_redhat_v11     = {
      41 57 41 56 41 55 41 54 55 53 48 83 EC ?? 48 8D 7C 24 ?? E8 ?? ?? ?? ?? 48 8B 6C 24
      ?? 8B 7D ?? 4C 8D 7D ?? 81 C7 ?? ?? ?? ?? 48 63 FF E8 ?? ?? ?? ?? 48 89 C3 48 8D 7C
      24 ?? 48 89 EE E8 ?? ?? ?? ?? 4C 8B 6C 24 ?? BE ?? ?? ?? ?? 48 89 DF 31 C0 4C 8D 74
      24 ?? 4C 89 EA E8 ?? ?? ?? ?? 48 98 48 8D 54 24 ?? 48 89 DE C6 04 18 ?? 4C 89 F7 E8
      ?? ?? ?? ?? 48 8B 7C 24 ?? 31 F6 E8 ?? ?? ?? ?? 85 C0 74 ?? 4C 89 E9 4C 89 EA BE ??
      ?? ?? ?? 48 89 DF 49 89 E9 4D 89 E8 31 C0 E8 ?? ?? ?? ?? 48 8B 7C 24 ?? 41 89 C4 B9
      ?? ?? ?? ?? 89 C2 48 89 DE E8 ?? ?? ?? ?? 48 8B 7C 24 ?? 31 F6 E8 ?? ?? ?? ?? 85 C0
      0F 85 ?? ?? ?? ?? 48 8B 54 24 ?? 48 89 DF BE ?? ?? ?? ?? 31 C0 E8 ?? ?? ?? ?? 48 89
      DF E8 ?? ?? ?? ?? 4C 89 EA BE ?? ?? ?? ?? 48 89 DF 31 C0 48 8D 6C 24 ?? E8 ?? ?? ??
      ?? 48 98 48 8D 54 24 ?? 48 89 DE C6 04 18 ?? 48 89 EF E8 ?? ?? ?? ?? 48 89 E7 31 C9
      BA ?? ?? ?? ?? 48 89 EE E8 ?? ?? ?? ?? 48 8B 6C 24 ?? 41 BE ?? ?? ?? ?? 4C 8B 24 24
      48 83 ED ?? 4C 39 F5 0F 85 ?? ?? ?? ?? BE ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ?? 48 85
      C0 0F 84 ?? ?? ?? ?? 48 89 DF 49 8D 5C 24 ?? E8 ?? ?? ?? ?? 49 39 DE 0F 85 ?? ?? ??
      ?? 48 8B 5C 24 ?? 48 83 EB ?? 49 39 DE 0F 85 ?? ?? ?? ?? 49 8D 5D ?? 49 39 DE 0F 85
      ?? ?? ?? ?? 49 81 FF ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 48 83 C4 ?? 5B 5D 41 5C 41 5D 41
      5E 41 5F C3
    }
    $change_timestamp_and_read_config_v11 = {
      55 53 48 83 EC ?? 48 8D 5C 24 ?? 48 89 E7 E8 ?? ?? ?? ?? 48 89 E6 48 89 DF E8 ?? ??
      ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 8B 5C 24 ?? 48 83 EB ?? 48 81 FB ?? ?? ?? ?? 0F 85
      ?? ?? ?? ?? 48 89 E6 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 1C 24 BE ?? ?? ?? ?? 48 89
      DF E8 ?? ?? ?? ?? 48 85 C0 74 ?? 48 83 C0 ?? 89 C5 29 DD 8D 7D ?? 48 63 FF E8 ?? ??
      ?? ?? 48 63 D5 48 89 C3 48 89 C7 C6 04 02 ?? 48 8B 34 24 E8 ?? ?? ?? ?? 48 89 DF E8
      ?? ?? ?? ?? 48 89 DE 48 89 C2 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ??
      BA ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 1C 24 B8 ?? ?? ??
      ?? 48 83 EB ?? 48 39 D8 75 ?? 48 83 C4 ?? 5B 5D C3
    }
    $generate_machine_id_v11              = {
      41 57 BE ?? ?? ?? ?? 49 89 FF 41 56 41 55 41 54 55 53 48 81 EC ?? ?? ?? ?? 48 8D 9C
      24 ?? ?? ?? ?? 48 8D 94 24 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 4C 8D AC 24 ?? ?? ??
      ?? 31 C9 BA ?? ?? ?? ?? 48 89 DE 4C 89 EF E8 ?? ?? ?? ?? 48 8B 9C 24 ?? ?? ?? ?? 41
      BE ?? ?? ?? ?? 48 83 EB ?? 4C 39 F3 0F 85 ?? ?? ?? ?? 4C 8D A4 24 ?? ?? ?? ?? 48 8B
      B4 24 ?? ?? ?? ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ?? 48 8B 84 24
      ?? ?? ?? ?? 48 83 78 ?? ?? 0F 84 ?? ?? ?? ?? 48 8D 9C 24 ?? ?? ?? ?? 48 8D 94 24 ??
      ?? ?? ?? BE ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 8D AC 24 ?? ?? ?? ?? 31 C9 BA ??
      ?? ?? ?? 48 89 DE 48 89 EF E8 ?? ?? ?? ?? 48 8B 9C 24 ?? ?? ?? ?? 48 83 EB ?? 49 39
      DE 0F 85 ?? ?? ?? ?? 48 89 EE 4C 89 E7 E8 ?? ?? ?? ?? 48 8B B4 24 ?? ?? ?? ?? 48 8D
      BC 24 ?? ?? ?? ?? 48 8B 56 ?? E8 ?? ?? ?? ?? 31 FF 4C 8B AC 24 ?? ?? ?? ?? E8 ?? ??
      ?? ?? 89 C7 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 89 C6 48 8D BC 24 ?? ?? ??
      ?? F7 EA 89 F1 89 F5 C1 F9 ?? C1 FA ?? 29 CA 69 D2 ?? ?? ?? ?? 29 D5 E8 ?? ?? ?? ??
      48 8B 9C 24 ?? ?? ?? ?? 41 89 E8 31 C0 4C 89 E9 BE ?? ?? ?? ?? 48 89 E7 48 89 DA 48
      83 EB ?? E8 ?? ?? ?? ?? 49 39 DE 89 C5 0F 85 ?? ?? ?? ?? 48 63 C5 48 8D 94 24 ?? ??
      ?? ?? 48 8D BC 24 ?? ?? ?? ?? C6 04 04 ?? 48 89 E6 E8 ?? ?? ?? ?? 48 8D 94 24 ?? ??
      ?? ?? 48 89 E6 4C 89 FF E8 ?? ?? ?? ?? 48 8B 9C 24 ?? ?? ?? ?? 48 83 EB ?? 49 39 DE
      0F 85 ?? ?? ?? ?? 49 8D 5D ?? 49 39 DE 0F 85 ?? ?? ?? ?? 48 8B 9C 24 ?? ?? ?? ?? 48
      83 EB ?? 49 39 DE 0F 85 ?? ?? ?? ?? 48 8B 9C 24 ?? ?? ?? ?? 48 83 EB ?? 49 39 DE 0F
      85 ?? ?? ?? ?? 48 8B 9C 24 ?? ?? ?? ?? 48 83 EB ?? 49 39 DE 0F 85 ?? ?? ?? ?? 48 81
      C4 ?? ?? ?? ?? 4C 89 F8 5B 5D 41 5C 41 5D 41 5E 41 5F C3
    }
    $persistence_mechanism_redhat_v7      = {
      48 89 6C 24 ?? 4C 89 7C 24 ?? 48 89 5C 24 ?? 4C 89 64 24 ?? 4C 89 6C 24 ?? 4C 89 74
      24 ?? 48 81 EC ?? ?? ?? ?? 48 8D 7C 24 ?? E8 ?? ?? ?? ?? 48 8B 6C 24 ?? 8B 7D ?? 4C
      8D 7D ?? 81 C7 ?? ?? ?? ?? 48 63 FF E8 ?? ?? ?? ?? 48 89 C3 48 8D 7C 24 ?? 48 89 EE
      E8 ?? ?? ?? ?? 4C 8B 64 24 ?? BE ?? ?? ?? ?? 48 89 DF 31 C0 4C 8D 74 24 ?? 4C 89 E2
      E8 ?? ?? ?? ?? 48 98 48 8D 54 24 ?? 48 89 DE C6 04 18 ?? 4C 89 F7 E8 ?? ?? ?? ?? 48
      8B 7C 24 ?? 31 F6 E8 ?? ?? ?? ?? 85 C0 74 ?? 4C 89 E1 4C 89 E2 BE ?? ?? ?? ?? 48 89
      DF 49 89 E9 4D 89 E0 31 C0 E8 ?? ?? ?? ?? 48 8B 7C 24 ?? 41 89 C5 B9 ?? ?? ?? ?? 89
      C2 48 89 DE E8 ?? ?? ?? ?? 48 8B 7C 24 ?? 31 F6 E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ??
      ?? 48 8B 54 24 ?? 48 89 DF BE ?? ?? ?? ?? 31 C0 E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ??
      ?? 4C 89 E2 BE ?? ?? ?? ?? 48 89 DF 31 C0 E8 ?? ?? ?? ?? 48 98 48 89 E7 31 C9 C6 04
      18 ?? BA ?? ?? ?? ?? 48 89 DE E8 ?? ?? ?? ?? 48 8B 2C 24 BE ?? ?? ?? ?? 48 89 EF E8
      ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 89 DF 48 8D 5D ?? BD ?? ?? ?? ?? E8 ?? ??
      ?? ?? 48 39 EB 0F 85 ?? ?? ?? ?? 48 8B 5C 24 ?? 48 83 EB ?? 48 39 DD 0F 85 ?? ?? ??
      ?? 49 8D 5C 24 ?? 48 39 DD 0F 85 ?? ?? ?? ?? 49 81 FF ?? ?? ?? ?? 0F 85 ?? ?? ?? ??
      48 8B 5C 24 ?? 48 8B 6C 24 ?? 4C 8B 64 24 ?? 4C 8B AC 24 ?? ?? ?? ?? 4C 8B B4 24 ??
      ?? ?? ?? 4C 8B BC 24 ?? ?? ?? ?? 48 81 C4 ?? ?? ?? ?? C3
    }
    $get_device_name_v7                   = {
      48 89 5C 24 ?? 48 89 6C 24 ?? BE ?? ?? ?? ?? 4C 89 64 24 ?? 4C 89 6C 24 ?? B9 ?? ??
      ?? ?? 4C 89 74 24 ?? 48 81 EC ?? ?? ?? ?? 4C 8B 05 ?? ?? ?? ?? 48 8D 5C 24 ?? BA ??
      ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 DE BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 5C 24
      ?? 41 BD ?? ?? ?? ?? 48 83 EB ?? 4C 39 EB 0F 85 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48
      83 78 ?? ?? 75 ?? 48 8D 5C 24 ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 DE BF ?? ?? ?? ?? E8
      ?? ?? ?? ?? 48 8B 5C 24 ?? 48 83 EB ?? 49 39 DD 0F 85 ?? ?? ?? ?? 48 8B 0D ?? ?? ??
      ?? 48 8B 15 ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 7C 24 ??
      E8 ?? ?? ?? ?? 4C 8B 64 24 ?? 48 89 E7 E8 ?? ?? ?? ?? 48 8B 2C 24 48 8D 5C 24 ?? 41
      B8 ?? ?? ?? ?? 4C 89 E2 BE ?? ?? ?? ?? 31 C0 48 89 DF 48 89 E9 E8 ?? ?? ?? ?? 48 89
      DE BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 5C 24 ?? 48 83 EB ?? 49 39 DD 0F 85 ?? ?? ??
      ?? E8 ?? ?? ?? ?? 48 8D 5D ?? 49 39 DD 0F 85 ?? ?? ?? ?? 49 8D 5C 24 ?? 49 39 DD 0F
      85 ?? ?? ?? ?? 48 8B 5C 24 ?? 48 8B 6C 24 ?? 4C 8B 64 24 ?? 4C 8B 6C 24 ?? 4C 8B B4
      24 ?? ?? ?? ?? 48 81 C4 ?? ?? ?? ?? C3
    }
    $generate_machine_id_v7               = {
      41 57 31 C9 BA ?? ?? ?? ?? BE ?? ?? ?? ?? 49 89 FF 41 56 41 55 41 54 55 53 48 81 EC
      ?? ?? ?? ?? 4C 8D A4 24 ?? ?? ?? ?? 48 8D AC 24 ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ??
      48 8B B4 24 ?? ?? ?? ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 48 8B
      84 24 ?? ?? ?? ?? 48 83 78 ?? ?? 0F 84 ?? ?? ?? ?? 48 8D 9C 24 ?? ?? ?? ?? 31 C9 BA
      ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 DE 48 89 EF E8 ?? ?? ?? ??
      48 8B B4 24 ?? ?? ?? ?? 48 8D BC 24 ?? ?? ?? ?? 48 8B 56 ?? E8 ?? ?? ?? ?? 31 FF 4C
      8B B4 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 C7 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ??
      ?? 89 C6 48 8D BC 24 ?? ?? ?? ?? F7 EA 89 F1 89 F5 C1 F9 ?? C1 FA ?? 29 CA 69 D2 ??
      ?? ?? ?? 29 D5 E8 ?? ?? ?? ?? 48 8B 9C 24 ?? ?? ?? ?? 41 89 E8 31 C0 4C 89 F1 BE ??
      ?? ?? ?? 48 89 E7 41 BD ?? ?? ?? ?? 48 89 DA 48 83 EB ?? E8 ?? ?? ?? ?? 4C 39 EB 89
      C5 0F 85 ?? ?? ?? ?? 48 63 C5 48 8D 94 24 ?? ?? ?? ?? 48 8D BC 24 ?? ?? ?? ?? C6 04
      04 ?? 48 89 E6 E8 ?? ?? ?? ?? 48 8D 94 24 ?? ?? ?? ?? 48 89 E6 4C 89 FF E8 ?? ?? ??
      ?? 48 8B 9C 24 ?? ?? ?? ?? 48 83 EB ?? 49 39 DD 0F 85 ?? ?? ?? ?? 49 8D 5E ?? 49 39
      DD 0F 85 ?? ?? ?? ?? 48 8B 9C 24 ?? ?? ?? ?? 48 83 EB ?? 49 39 DD 0F 85 ?? ?? ?? ??
      48 8B 9C 24 ?? ?? ?? ?? 48 83 EB ?? 49 39 DD 0F 85 ?? ?? ?? ?? 48 8B 9C 24 ?? ?? ??
      ?? 48 83 EB ?? 49 39 DD 0F 85 ?? ?? ?? ?? 48 81 C4 ?? ?? ?? ?? 4C 89 F8 5B 5D 41 5C
      41 5D 41 5E 41 5F C3
    }

  condition:
    uint32(0) == 0x464C457F and (($persistence_mechanism_ubuntu) and (all of ($network_communication_*)) and ((($change_timestamp_and_read_config_v11) and ($persistence_mechanism_redhat_v11) and ($generate_machine_id_v11)) or (($persistence_mechanism_redhat_v7) and ($get_device_name_v7) and ($generate_machine_id_v7))))
}

rule REVERSINGLABS_Linux_Ransomware_Redalert: TC_DETECTION MALICIOUS MALWARE FILE {
  meta:
    description         = "Yara rule that detects RedAlert ransomware."
    author              = "ReversingLabs"
    id                  = "ec7567bf-2c39-529f-ae93-74270a161827"
    date                = "2022-09-01"
    modified            = "2022-09-01"
    reference           = "ReversingLabs"
    source_url          = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/d35a6845dcd00f2840f690611612b04dda6d195d/yara/ransomware/Linux.Ransomware.RedAlert.yara#L1-L146"
    license_url         = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/d35a6845dcd00f2840f690611612b04dda6d195d/LICENSE"
    logic_hash          = "fe0d10c2ef1dacdb5374f319e470274b91f4f171db49de8c89e8aaa9aa75a45c"
    score               = 75
    quality             = 90
    tags                = "TC_DETECTION, MALICIOUS, MALWARE, FILE"
    status              = "RELEASED"
    sharing             = "TLP:WHITE"
    category            = "MALWARE"
    tc_detection_type   = "Ransomware"
    tc_detection_name   = "RedAlert"
    tc_detection_factor = 5
    importance          = 25

  strings:
    $encrypt_files_p1   = {
      41 57 41 56 41 55 41 54 55 53 48 81 EC ?? ?? ?? ?? 48 89 74 24 ?? BE ?? ?? ?? ?? 48
      89 54 24 ?? 48 89 4C 24 ?? 4C 89 44 24 ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 75 ?? BF
      ?? ?? ?? ?? E8 ?? ?? ?? ?? EB ?? 48 89 C7 E8 ?? ?? ?? ?? 83 F8 ?? 89 C3 75 ?? BF ??
      ?? ?? ?? E8 ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 31 C0 E9 ?? ?? ?? ?? 48 8D 54 24 ??
      89 C6 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? FF C0 75 ?? BF ?? ?? ?? ?? EB ?? 4C 8B B4 24 ??
      ?? ?? ?? 4D 85 F6 7F ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 DF E8 ?? ?? ?? ?? EB ?? 49
      81 FE ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 0F 97 44 24 ?? 49 81 FE ?? ?? ?? ?? 0F 97
      44 24 ?? 80 7C 24 ?? ?? 74 ?? BA ?? ?? ?? ?? 4C 89 F0 C7 44 24 ?? ?? ?? ?? ?? 48 89
      D3 31 D2 48 F7 F3 48 6B C8 ?? 48 89 4C 24 ?? 49 81 FE ?? ?? ?? ?? 77 ?? 4D 89 F4 41
      BD ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? EB ?? 41 BC ?? ?? ?? ?? 45 31 ED C7 44 24 ??
      ?? ?? ?? ?? 4D 63 FD C7 44 24 ?? ?? ?? ?? ?? 4C 0F AF 7C 24 ?? E9 ?? ?? ?? ?? 80 7C
      24 ?? ?? 74 ?? 45 85 ED 74 ?? 80 7C 24 ?? ?? 74 ?? 41 8D 45 ?? 3B 44 24 ?? 4C 89 FE
      75 ?? 49 8D B6 ?? ?? ?? ?? EB ?? 31 F6 31 D2 48 89 EF E8 ?? ?? ?? ?? 48 63 7C 24 ??
      48 89 E9 4C 89 E2 48 03 7C 24 ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 39 E0 74 ?? BF ??
      ?? ?? ?? EB ?? 44 01 64 24 ?? 41 FF C5 44 3B 6C 24 ?? 0F 85 ?? ?? ?? ?? 48 8D 9C 24
      ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 84 C0 74 ?? BF ??
      ?? ?? ?? EB ?? 48 8D BC 24 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 DE E8 ?? ?? ?? ?? 85 C0
      74 ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 63 6C 24 ?? 45 89 E7 44 89 64 24 ?? 4C 0F AF
      6C 24 ?? C6 44 24 ?? ?? C7 44 24 ?? ?? ?? ?? ?? E9 ?? ?? ?? ?? 4C 8B 4C 24 ?? 41 B8
      ?? ?? ?? ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 84
    }
    $encrypt_files_p2   = {
      C0 75 ?? 48 8B 54 24 ?? 48 8B 7C 24 ?? 48 89 E9 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B7
      15 ?? ?? ?? ?? 48 39 D0 75 ?? 48 8B 44 24 ?? 48 89 E9 BE ?? ?? ?? ?? 0F B7 50 ?? 48
      8B 38 E8 ?? ?? ?? ?? 48 8B 4C 24 ?? 0F B7 51 ?? 48 39 D0 74 ?? BF ?? ?? ?? ?? E9 ??
      ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 4C 03 7C 24 ?? 44 3B 6C 24 ?? 0F 8C ?? ?? ?? ?? E9
      ?? ?? ?? ?? BF ?? ?? ?? ?? EB ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 80 7C
      24 ?? ?? 74 ?? 83 7C 24 ?? ?? 74 ?? 80 7C 24 ?? ?? 74 ?? 8B 44 24 ?? 4C 89 EE FF C0
      3B 44 24 ?? 75 ?? 49 8D B6 ?? ?? ?? ?? EB ?? 31 F6 31 D2 48 89 EF E8 ?? ?? ?? ?? 48
      63 44 24 ?? 48 8B 5C 24 ?? 48 8D B4 24 ?? ?? ?? ?? 48 8D BC 24 ?? ?? ?? ?? 31 C9 31
      D2 45 89 E1 C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 48 01 C3 48 8D 84 24 ??
      ?? ?? ?? 49 89 D8 48 89 1C 24 48 89 44 24 ?? E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ??
      48 89 E9 4C 89 E2 BE ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 4C 39 E0 0F 85 ?? ?? ?? ??
      FF 44 24 ?? 8B 54 24 ?? 8B 4C 24 ?? 01 54 24 ?? 39 4C 24 ?? 75 ?? 31 F6 BA ?? ?? ??
      ?? 48 89 EF E8 ?? ?? ?? ?? 48 8D BC 24 ?? ?? ?? ?? 48 89 E9 BA ?? ?? ?? ?? BE ?? ??
      ?? ?? E8 ?? ?? ?? ?? 8A 5C 24 ?? 48 83 F8 ?? B0 ?? 0F 44 D8 44 3B 7C 24 ?? 88 5C 24
      ?? 74 ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 44 03 7C 24 ?? 4C 03 6C 24 ?? 8B 44 24 ?? 39
      44 24 ?? 0F 8C ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 0F B6 44 24 ?? 48 81 C4 ?? ?? ??
      ?? 5B 5D 41 5C 41 5D 41 5E 41 5F C3
    }
    $find_files_p1      = {
      41 57 FC 41 56 41 55 41 54 49 89 FC 55 53 48 83 EC ?? 48 8B 84 24 ?? ?? ?? ?? 48 89
      4C 24 ?? 48 83 C9 ?? 48 89 74 24 ?? 4C 89 44 24 ?? 4C 89 4C 24 ?? 88 54 24 ?? 48 89
      44 24 ?? 48 8B 84 24 ?? ?? ?? ?? 44 8A BC 24 ?? ?? ?? ?? 48 89 44 24 ?? 48 8B 84 24
      ?? ?? ?? ?? 48 89 44 24 ?? 48 8B 84 24 ?? ?? ?? ?? 48 89 44 24 ?? 31 C0 F2 AE 4C 89
      E7 48 F7 D1 4C 8D 71 ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 44 24 ?? 0F 85 ?? ?? ?? ?? E8
      ?? ?? ?? ?? 8B 38 E8 ?? ?? ?? ?? 48 83 C4 ?? 4C 89 E6 48 89 C2 5B 5D 41 5C 41 5D 41
      5E 41 5F BF ?? ?? ?? ?? 31 C0 E9 ?? ?? ?? ?? 45 84 FF 48 8D 6B ?? 74 ?? 0F B6 4B ??
      48 89 EA 4C 89 E6 BF ?? ?? ?? ?? 31 C0 E8 ?? ?? ?? ?? 80 7B ?? ?? 0F 85 ?? ?? ?? ??
      80 7C 24 ?? ?? 0F 84 ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 85 C0 0F 84
      ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? BE ?? ??
      ?? ?? 48 89 EF E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? FC 31 C0 48 83 C9 ?? 48 89 EF
      F2 AE 4C 89 F0 48 29 C8 48 3B 44 24 ?? 76 ?? 48 8B 3D ?? ?? ?? ?? 48 89 E9 4C 89 E2
      BE ?? ?? ?? ?? 31 C0 E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 4B 8D 1C 34 48 89 EE 48 8D 7B ??
      C6 03 ?? E8 ?? ?? ?? ?? 41 0F B6 C7 4C 8B 4C 24 ?? 4C 8B 44 24 ?? 89 44 24 ?? 48 8B
      44 24 ?? BA ?? ?? ?? ?? 48 8B 4C 24 ?? 48 8B 74 24 ?? 4C 89 E7 48 89 44 24 ?? 48 8B
    }
    $find_files_p2      = {
      44 24 ?? 48 89 44 24 ?? 48 8B 44 24 ?? 48 89 44 24 ?? 48 8B 44 24 ?? 48 89 04 24 E8
      ?? ?? ?? ?? E9 ?? ?? ?? ?? 45 84 FF 0F 85 ?? ?? ?? ?? FC 48 83 C9 ?? 48 89 EF 44 88
      F8 F2 AE 48 8B 54 24 ?? 48 89 EF 48 89 CB 48 8B 4C 24 ?? 48 F7 D3 48 89 DE 4C 8D 6B
      ?? E8 ?? ?? ?? ?? 84 C0 74 ?? 48 89 EA 4C 89 E6 BF ?? ?? ?? ?? 31 C0 E8 ?? ?? ?? ??
      E9 ?? ?? ?? ?? 4C 89 EA BE ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ??
      ?? 48 89 DE 48 89 EF E8 ?? ?? ?? ?? 84 C0 0F 84 ?? ?? ?? ?? 4B 8D 1C 34 48 89 EA 4C
      89 E6 BF ?? ?? ?? ?? 31 C0 E8 ?? ?? ?? ?? 48 8D 7B ?? 48 89 EE C6 03 ?? E8 ?? ?? ??
      ?? 0F B7 0D ?? ?? ?? ?? 4C 89 E7 4C 8B 44 24 ?? 48 8B 54 24 ?? 48 8B 74 24 ?? FF 15
      ?? ?? ?? ?? 84 C0 BF ?? ?? ?? ?? 74 ?? 48 8B 7C 24 ?? B9 ?? ?? ?? ?? 4C 89 E2 BE ??
      ?? ?? ?? 31 C0 E8 ?? ?? ?? ?? 48 8B 74 24 ?? 4C 89 E7 E8 ?? ?? ?? ?? 85 C0 74 ?? BF
      ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 7C 24 ?? 41 8D 56 ??
      4C 89 E6 E8 ?? ?? ?? ?? C6 03 ?? 48 8B 7C 24 ?? E8 ?? ?? ?? ?? 48 85 C0 48 89 C3 0F
      85 ?? ?? ?? ?? 48 8B 7C 24 ?? 48 83 C4 ?? 5B 5D 41 5C 41 5D 41 5E 41 5F E9
    }
    $setup_environment  = {
      55 48 89 E5 41 56 49 89 F6 BE ?? ?? ?? ?? 41 55 41 54 53 48 89 FB 48 83 EC ?? E8 ??
      ?? ?? ?? 48 85 C0 49 89 C4 75 ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 7D ?? E8 ?? ??
      ?? ?? 84 C0 BF ?? ?? ?? ?? 74 ?? BE ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 85 C0 49
      89 C4 74 ?? 0F B7 55 ?? 48 8B 7D ?? 48 89 C1 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B7 55
      ?? 48 8B 7D ?? 4C 89 E1 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B7 55 ?? 31 C9 39 C2 0F 85
      ?? ?? ?? ?? E9 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? BF ?? ?? ??
      ?? 49 89 E5 E8 ?? ?? ?? ?? 66 8B 3D ?? ?? 22 00 66 03 3D ?? ?? 22 00 66 8B 05 ?? ??
      22 00 66 89 7D ?? 0F B7 FF 66 89 45 ?? E8 ?? ?? ?? ?? 0F B7 7D ?? 48 89 45 ?? E8 ??
      ?? ?? ?? 0F B7 55 ?? 48 8B 7D ?? 4C 89 E1 BE ?? ?? ?? ?? 48 89 45 ?? E8 ?? ?? ?? ??
      0F B7 55 ?? 48 8B 7D ?? 4C 89 E1 BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 75 ?? BF ?? ??
      ?? ?? 31 C0 E8 ?? ?? ?? ?? 0F B7 45 ?? 0F B7 35 ?? ?? ?? ?? 31 C9 48 8B 7D ?? 48 83
      C0 ?? 25 ?? ?? ?? ?? 48 29 C4 48 8D 5C 24 ?? 48 83 E3 ?? 48 89 DA E8 ?? ?? ?? ?? 48
      89 DE BF ?? ?? ?? ?? 31 C0 E8 ?? ?? ?? ?? 0F B7 3D ?? ?? ?? ?? BE ?? ?? ?? ?? 48 03
      7D ?? E8 ?? ?? ?? ?? 66 39 05 ?? ?? 22 00 74 ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 89
      EC 31 C9 EB ?? 4C 89 E7 E8 ?? ?? ?? ?? 48 8D 75 ?? B9 ?? ?? ?? ?? 4C 89 F7 FC F3 A5
      B1 ?? EB ?? 4C 89 EC EB ?? 48 8D 65 ?? 89 C8 5B 41 5C 41 5D 41 5E C9 C3
    }
    $make_configuration = {
      41 56 BE ?? ?? ?? ?? 49 89 FE BF ?? ?? ?? ?? 41 55 41 54 55 53 48 83 EC ?? E8 ?? ??
      ?? ?? 84 C0 88 C3 74 ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 FF EB ?? BF ?? ?? ?? ?? E8
      ?? ?? ?? ?? BA ?? ?? ?? ?? 0F B7 F0 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8
      ?? ?? ?? ?? B9 ?? ?? ?? ?? 49 89 C4 48 89 C2 BE ?? ?? ?? ?? BF ?? ?? ?? ?? 66 C7 00
      ?? ?? C6 40 ?? ?? E8 ?? ?? ?? ?? 4C 89 E6 BF ?? ?? ?? ?? 31 C0 E8 ?? ?? ?? ?? 48 89
      E6 4C 89 E7 E8 ?? ?? ?? ?? 84 C0 75 ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ??
      E8 ?? ?? ?? ?? FC 88 D8 BF ?? ?? ?? ?? 48 83 C9 ?? F2 AE 48 F7 D1 48 FF C9 8D 59 ??
      83 C1 ?? 48 63 F9 E8 ?? ?? ?? ?? 48 85 C0 48 89 C5 0F 84 ?? ?? ?? ?? 48 8D 78 ?? 48
      63 D3 BE ?? ?? ?? ?? C6 00 ?? E8 ?? ?? ?? ?? 48 89 EF BE ?? ?? ?? ?? E8 ?? ?? ?? ??
      48 85 C0 48 89 C3 BF ?? ?? ?? ?? 74 ?? 0F B7 54 24 ?? 48 8B 7C 24 ?? 48 89 C1 BE ??
      ?? ?? ?? E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 EF E8 ?? ?? ?? ?? BF ?? ?? ??
      ?? E8 ?? ?? ?? ?? 4C 89 E7 E8 ?? ?? ?? ?? 4C 89 F7 48 89 E6 B9 ?? ?? ?? ?? FC F3 A5
      48 83 C4 ?? 5B 5D 41 5C 41 5D 41 5E C3 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? E9
    }

  condition:
    uint32(0) == 0x464C457F and ($setup_environment) and (all of ($find_files_p*)) and (all of ($encrypt_files_p*)) and ($make_configuration)
}

rule REVERSINGLABS_Linux_Ransomware_Gwisinlocker: TC_DETECTION MALICIOUS MALWARE FILE {
  meta:
    description         = "Yara rule that detects GwisinLocker ransomware."
    author              = "ReversingLabs"
    id                  = "9f00e1b4-3692-5824-b614-724073532c1f"
    date                = "2022-10-11"
    modified            = "2022-10-11"
    reference           = "ReversingLabs"
    source_url          = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/d35a6845dcd00f2840f690611612b04dda6d195d/yara/ransomware/Linux.Ransomware.GwisinLocker.yara#L1-L354"
    license_url         = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/d35a6845dcd00f2840f690611612b04dda6d195d/LICENSE"
    logic_hash          = "c23c0b73bbefbd644ffe1398e1f14eec3a89945cb3c3ccbc6f46c57046b53505"
    score               = 75
    quality             = 90
    tags                = "TC_DETECTION, MALICIOUS, MALWARE, FILE"
    status              = "RELEASED"
    sharing             = "TLP:WHITE"
    category            = "MALWARE"
    tc_detection_type   = "Ransomware"
    tc_detection_name   = "GwisinLocker"
    tc_detection_factor = 5
    importance          = 25

  strings:
    $init_key_v1          = {
      55 57 56 53 E8 ?? ?? ?? ?? 81 C3 ?? ?? ?? ?? 81 EC ?? ?? ?? ?? 8D 74 24 ?? 56 E8 ??
      ?? ?? ?? 83 C4 ?? 85 C0 74 ?? 31 FF 83 EC ?? 56 E8 ?? ?? ?? ?? 81 C4 ?? ?? ?? ?? 89
      F8 5B 5E 5F 5D C3 66 90 31 D2 31 C0 89 54 04 ?? 83 C0 ?? 83 F8 ?? 72 ?? 83 EC ?? 8D
      83 ?? ?? ?? ?? 50 8D 83 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 89 C5 8D 7C 24 ?? 85
      C0 74 ?? 50 6A ?? 6A ?? 57 E8 ?? ?? ?? ?? 89 2C 24 E8 ?? ?? ?? ?? 83 C4 ?? 83 EC ??
      6A ?? 57 56 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? C7 04 24 ?? ?? ?? ?? 83 EC ?? 8D 44
      24 ?? 50 FF B4 24 ?? ?? ?? ?? FF B4 24 ?? ?? ?? ?? FF B4 24 ?? ?? ?? ?? 6A ?? FF B3
      ?? ?? ?? ?? FF B4 24 ?? ?? ?? ?? 56 FF B3 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0
      0F 94 C0 0F B6 C0 89 C7 E9
    }
    $encrypt_files_v1_p1  = {
      55 B9 ?? ?? ?? ?? 57 56 53 E8 ?? ?? ?? ?? 81 C3 ?? ?? ?? ?? 81 EC ?? ?? ?? ?? 8B 84
      24 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 89 44 24 ?? 8B 84 24
      ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 89 44 24 ?? 8D 44 24 ?? 83 EC ?? 89 44 24 ?? 89
      C7 31 C0 F3 AB C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ??
      ?? 6A ?? FF 74 24 ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? 8D 84 24 ?? ?? ?? ?? 89 44
      24 ?? 8D 84 24 ?? ?? ?? ?? 89 44 24 ?? 31 FF 83 EC ?? 68 ?? ?? ?? ?? FF 74 24 ?? E8
      ?? ?? ?? ?? 58 5A 6A ?? FF 74 24 ?? E8 ?? ?? ?? ?? 59 5E 6A ?? FF 74 24 ?? E8 ?? ??
      ?? ?? 81 C4 ?? ?? ?? ?? 89 F8 5B 5E 5F 5D C3 8D 74 26 ?? 90 83 EC ?? 6A ?? 8D 84 24
      ?? ?? ?? ?? 89 44 24 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D B4 24 ?? ?? ?? ?? 89 74 24 ??
      85 C0 74 ?? 83 EC ?? 6A ?? FF 74 24 ?? 56 E8 ?? ?? ?? ?? 8D 83 ?? ?? ?? ?? 59 5E 50
      89 C5 FF B4 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 44 24 ?? 89 C6 83 C4 ?? 85 C0 0F 84 ??
      ?? ?? ?? 83 EC ?? FF B4 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 50 89 C7 FF B4 24 ??
      ?? ?? ?? FF B4 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 94 24 ?? ?? ?? ?? 01 FA 89 D0 8B 54
      24 ?? 89 10 0F B7 54 24 ?? 66 89 50 ?? 0F B6 54 24 ?? 88 50 ?? 8B 94 24 ?? ?? ?? ??
      C6 44 3A ?? ?? BF ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 56 E8 ?? ?? ?? ?? 83 C4 ?? 56 E8 ??
      ?? ?? ?? B9 ?? ?? ?? ?? 83 C4 ?? 39 C1 B9 ?? ?? ?? ?? 19 D1 7D ?? 83 EC ?? FF B4 24
      ?? ?? ?? ?? FF B4 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 ?? 83 EC ?? FF 74
      24 ?? E8 ?? ?? ?? ?? 83 C4 ?? E9 ?? ?? ?? ?? 8D 74 26 ?? 90 83 EC ?? 56 E8 ?? ?? ??
      ?? 58 5A 55 FF B4 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 44 24 ?? 89 C6 83 C4 ?? 85 C0 0F
    }
    $encrypt_files_v1_p2  = {
      84 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 50 E8 ?? ?? ?? ?? 89 34 24 E8 ?? ?? ?? ?? 8B 74 24
      ?? 8B 7C 24 ?? 89 D1 89 74 24 ?? 89 7C 24 ?? 83 C4 ?? 39 F0 19 F9 7D ?? 89 44 24 ??
      89 54 24 ?? 8B 7C 24 ?? 8B 74 24 ?? 89 F9 89 F5 C1 F9 ?? 89 C8 89 4C 24 ?? 31 CD 8B
      74 24 ?? C1 F8 ?? 89 44 24 ?? 89 E8 29 F0 8B 74 24 ?? 89 C7 83 E7 ?? 31 CF 89 F8 8B
      7C 24 ?? 29 F0 8B 74 24 ?? 89 FA 19 FA 8B 7C 24 ?? 29 C6 89 74 24 ?? 19 D7 83 EC ??
      89 7C 24 ?? 8D 44 24 ?? 50 E8 ?? ?? ?? ?? 8D BC 24 ?? ?? ?? ?? 8D B4 24 ?? ?? ?? ??
      B9 ?? ?? ?? ?? 89 84 24 ?? ?? ?? ?? 31 C0 F3 AB 89 94 24 ?? ?? ?? ?? 56 6A ?? FF 74
      24 ?? FF B4 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 C7 85 C0 0F 84 ?? ?? ?? ?? 83
      EC ?? FF 74 24 ?? E8 ?? ?? ?? ?? 5F 5D FF B4 24 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4
      ?? 89 C7 85 C0 0F 84 ?? ?? ?? ?? 8B B4 24 ?? ?? ?? ?? 8B 54 24 ?? 31 FF 8B 44 24 ??
      89 7C 24 ?? 89 74 24 ?? 8D 74 24 ?? 89 D7 89 74 24 ?? 8D B3 ?? ?? ?? ?? 09 C7 89 74
    }
    $encrypt_files_v1_p3  = {
      24 ?? 0F 84 ?? ?? ?? ?? 8B 4C 24 ?? 8B 6C 24 ?? 89 4C 24 ?? EB ?? 66 90 83 EC ?? 31
      ED FF B4 24 ?? ?? ?? ?? FF B4 24 ?? ?? ?? ?? FF B4 24 ?? ?? ?? ?? FF 74 24 ?? FF 74
      24 ?? FF 74 24 ?? E8 ?? ?? ?? ?? 83 C4 ?? 31 D2 6A ?? 8B 84 24 ?? ?? ?? ?? 52 F7 D8
      50 57 E8 ?? ?? ?? ?? 57 FF B4 24 ?? ?? ?? ?? 6A ?? FF B4 24 ?? ?? ?? ?? E8 ?? ?? ??
      ?? 8B 44 24 ?? 8B BC 24 ?? ?? ?? ?? 8B 54 24 ?? 29 F8 19 EA 89 44 24 ?? 89 D6 89 54
      24 ?? 83 C4 ?? 09 C6 74 ?? 39 84 24 ?? ?? ?? ?? 89 E9 8B 7C 24 ?? 19 D1 0F 4C 84 24
      ?? ?? ?? ?? 89 84 24 ?? ?? ?? ?? 8B 84 24 ?? ?? ?? ?? 89 44 24 ?? 8B 84 24 ?? ?? ??
      ?? 89 44 24 ?? 8B 84 24 ?? ?? ?? ?? 89 44 24 ?? 8B 84 24 ?? ?? ?? ?? 89 44 24 ?? 57
      FF B4 24 ?? ?? ?? ?? 6A ?? FF B4 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 39 84 24 ??
      ?? ?? ?? 0F 84 ?? ?? ?? ?? 83 EC ?? BF ?? ?? ?? ?? FF 74 24 ?? E8 ?? ?? ?? ?? 83 C4
      ?? E9 ?? ?? ?? ?? 83 EC ?? FF B4 24 ?? ?? ?? ?? FF B4 24 ?? ?? ?? ?? E8 ?? ?? ?? ??
      83 C4 ?? E9
    }
    $find_files_v1_p1     = {
      55 89 C5 57 E8 ?? ?? ?? ?? 81 C7 ?? ?? ?? ?? 56 53 81 EC ?? ?? ?? ?? 89 54 24 ?? 8B
      B4 24 ?? ?? ?? ?? 89 7C 24 ?? 89 FB 89 4C 24 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 89 44 24
      ?? C7 44 24 ?? ?? ?? ?? ?? 85 C0 74 ?? 8D 58 ?? 80 7C 05 ?? ?? 0F 45 D8 89 5C 24 ??
      8B BC 24 ?? ?? ?? ?? 83 E7 ?? 74 ?? 83 EC ?? 8D 44 24 ?? 89 44 24 ?? 50 55 6A ?? 8B
      5C 24 ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 ?? 8B 5C 24 ?? E8 ?? ?? ?? ?? 8B 00 83 F8
      ?? 0F 85 ?? ?? ?? ?? BF ?? ?? ?? ?? C6 44 24 ?? ?? C7 44 24 ?? ?? ?? ?? ?? EB ?? 8D
      B4 26 ?? ?? ?? ?? 66 90 83 EC ?? 8D 44 24 ?? 89 44 24 ?? 50 55 6A ?? 8B 5C 24 ?? E8
      ?? ?? ?? ?? 83 C4 ?? 85 C0 78 ?? 8B 84 24 ?? ?? ?? ?? 25 ?? ?? ?? ?? 3D ?? ?? ?? ??
      0F 84 ?? ?? ?? ?? 3D ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? C6 44 24 ?? ?? 31 FF C7 44 24 ??
      ?? ?? ?? ?? 8B 54 24 ?? 8B 44 24 ?? F6 84 24 ?? ?? ?? ?? ?? 74 ?? 85 F6 0F 84 ?? ??
      ?? ?? 8B 4E ?? 8B 5E ?? 31 D1 31 C3 09 CB 0F 84 ?? ?? ?? ?? 31 FF 81 C4 ?? ?? ?? ??
      89 F8 5B 5E 5F 5D C3 8D 74 26 ?? 90 8B 5C 24 ?? E8 ?? ?? ?? ?? 89 C7 8B 00 83 F8 ??
      0F 85 ?? ?? ?? ?? 83 EC ?? FF 74 24 ?? 55 6A ?? 8B 5C 24 ?? E8 ?? ?? ?? ?? 83 C4 ??
      85 C0 0F 85 ?? ?? ?? ?? BF ?? ?? ?? ?? C6 44 24 ?? ?? C7 44 24 ?? ?? ?? ?? ?? E9 ??
      ?? ?? ?? 8D 74 26 ?? 90 89 54 24 ?? 8B 94 24 ?? ?? ?? ?? 89 44 24 ?? 8B 84 24 ?? ??
      ?? ?? 89 74 24 ?? 89 44 24 ?? 89 54 24 ?? 85 F6 0F 84 ?? ?? ?? ?? 8B 46 ?? 8B 4C 24
      ?? 83 C0 ?? 83 C1 ?? 89 44 24 ?? 89 44 24 ?? 8B 46 ?? 89 4C 24 ?? 89 4C 24 ?? 89 44
    }
    $find_files_v1_p2     = {
      24 ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 83 FF ?? 0F 84 ?? ?? ?? ?? 8B
      84 24 ?? ?? ?? ?? 83 E0 ?? 89 44 24 ?? 75 ?? 8D 44 24 ?? 50 FF 74 24 ?? FF 74 24 ??
      55 8B 44 24 ?? FF D0 89 C7 83 C4 ?? 85 C0 0F 85 ?? ?? ?? ?? 85 F6 74 ?? 8B 84 24 ??
      ?? ?? ?? 8B 5C 24 ?? 89 6C 24 ?? 8B 4C 24 ?? 8B BC 24 ?? ?? ?? ?? 89 C5 EB ?? 8D B6
      ?? ?? ?? ?? 8B 36 85 F6 74 ?? 8B 46 ?? 8B 56 ?? 31 D8 31 CA 09 C2 75 ?? 8B 46 ?? 8B
      56 ?? 31 E8 31 FA 09 C2 0F 84 ?? ?? ?? ?? 8B 36 85 F6 75 ?? 8B 6C 24 ?? 8B 7C 24 ??
      85 FF 74 ?? 80 7C 24 ?? ?? 0F 85 ?? ?? ?? ?? 8B 44 24 ?? C6 44 05 ?? ?? 8B 44 24 ??
      85 C0 0F 84 ?? ?? ?? ?? 8D 44 24 ?? 50 FF 74 24 ?? FF 74 24 ?? 55 8B 44 24 ?? FF D0
      83 C4 ?? 89 C7 81 C4 ?? ?? ?? ?? 89 F8 5B 5E 5F 5D C3 66 90 83 EC ?? 6A ?? 55 8B 5C
      24 ?? E8 ?? ?? ?? ?? 8B 5C 24 ?? 89 44 24 ?? 89 C7 E8 ?? ?? ?? ?? 8B 00 89 44 24 ??
      83 C4 ?? 85 FF 79 ?? 83 F8 ?? 0F B6 4C 24 ?? BA ?? ?? ?? ?? 0F 94 C0 84 C0 B8 ?? ??
      ?? ?? 0F 44 44 24 ?? 0F 45 CA 89 44 24 ?? 88 4C 24 ?? 8B 44 24 ?? 85 C0 0F 85 ?? ??
      ?? ?? 83 EC ?? FF 74 24 ?? 8B 5C 24 ?? E8 ?? ?? ?? ?? 83 C4 ?? E9 ?? ?? ?? ?? 8D B4
      26 ?? ?? ?? ?? 8D 76 ?? 89 54 24 ?? 8B 94 24 ?? ?? ?? ?? 89 44 24 ?? 8B 84 24 ?? ??
      ?? ?? C7 44 24 ?? ?? ?? ?? ?? 89 44 24 ?? 89 54 24 ?? 8B 44 24 ?? C7 44 24 ?? ?? ??
      ?? ?? C7 44 24 ?? ?? ?? ?? ?? 8D 48 ?? 89 4C 24 ?? 89 4C 24 ?? 85 C0 74 ?? 80 7C 05
      ?? ?? 74 ?? E9 ?? ?? ?? ?? 8D 76 ?? 80 7C 05 ?? ?? 0F 85 ?? ?? ?? ?? 83 E8 ?? 75 ??
      31 D2 89 54 24 ?? E9 ?? ?? ?? ?? 8D 74 26 ?? 90 89 54 24 ?? 8B 94 24 ?? ?? ?? ?? 89
    }
    $find_files_v1_p3     = {
      44 24 ?? 8B 84 24 ?? ?? ?? ?? 89 74 24 ?? 89 44 24 ?? 89 54 24 ?? E9 ?? ?? ?? ?? 90
      8B 84 24 ?? ?? ?? ?? BF ?? ?? ?? ?? C6 44 24 ?? ?? 83 E0 ?? 83 F8 ?? 19 C0 83 E0 ??
      83 C0 ?? 89 44 24 ?? E9 ?? ?? ?? ?? 8D B4 26 ?? ?? ?? ?? 90 8B 74 24 ?? 85 F6 0F 88
      ?? ?? ?? ?? 83 EC ?? FF 74 24 ?? 8B 5C 24 ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 C6 85 C0 0F
      84 ?? ?? ?? ?? B8 ?? ?? ?? ?? 2B 44 24 ?? 89 44 24 ?? 8D B4 26 ?? ?? ?? ?? 8D 76 ??
      83 EC ?? 56 8B 5C 24 ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? 80 78 ?? ??
      0F 84 ?? ?? ?? ?? 83 EC ?? 8D 78 ?? 57 8B 5C 24 ?? E8 ?? ?? ?? ?? 83 C4 ?? 3B 44 24
      ?? 0F 83 ?? ?? ?? ?? 8B 44 24 ?? 83 EC ?? C6 44 05 ?? ?? 57 8B 44 24 ?? 01 E8 50 8B
      5C 24 ?? E8 ?? ?? ?? ?? 8B 44 24 ?? 5A 5B 8D 48 ?? 8D 44 24 ?? 50 89 E8 FF B4 24 ??
      ?? ?? ?? 8B 54 24 ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? 83 EC ?? 89 C7
      56 8B 5C 24 ?? E8 ?? ?? ?? ?? 83 C4 ?? E9 ?? ?? ?? ?? 66 90 80 78 ?? ?? 0F 84 ?? ??
      ?? ?? 66 83 78 ?? ?? 0F 85 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8D B6 ?? ?? ?? ?? 80 7C 05 ??
      ?? 8D 48 ?? 89 C2 0F 84 ?? ?? ?? ?? 85 C9 0F 84 ?? ?? ?? ?? 80 7C 05 ?? ?? 8D 50 ??
      75 ?? E9 ?? ?? ?? ?? 8D B4 26 ?? ?? ?? ?? 66 90 89 C2 85 D2 0F 84 ?? ?? ?? ?? 80 7C
      15 ?? ?? 8D 42 ?? 75 ?? E9 ?? ?? ?? ?? 8D B4 26 ?? ?? ?? ?? 85 FF 0F 84 ?? ?? ?? ??
      31 FF C6 44 24 ?? ?? C7 44 24 ?? ?? ?? ?? ?? E9 ?? ?? ?? ?? 83 EC ?? 56 8B 5C 24 ??
      E8 ?? ?? ?? ?? 83 C4 ?? E9 ?? ?? ?? ?? 8B 07 E9 ?? ?? ?? ?? 8B 7C 24 ?? 89 FB BF ??
      ?? ?? ?? E8 ?? ?? ?? ?? 83 EC ?? C7 00 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 ?? E9 ??
      ?? ?? ?? BF
    }
    $kill_processes_v1_p1 = {
      55 BA ?? ?? ?? ?? B8 ?? ?? ?? ?? BD ?? ?? ?? ?? 57 89 E9 56 53 E8 ?? ?? ?? ?? 81 C3
      ?? ?? ?? ?? 81 EC ?? ?? ?? ?? 66 89 54 24 ?? 8D 7C 24 ?? C7 44 24 ?? ?? ?? ?? ?? C7
      44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 8D B3 ?? ?? ?? ?? C7 44 24 ?? ?? ?? ??
      ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C6 44 24
      ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44
      24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C6 44 24 ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7
      44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 66 89 44 24 ??
      C6 44 24 ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ??
      ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C6 44 24 ?? ?? 8B 83 ?? ?? ?? ??
      89 44 24 ?? 8B 83 ?? ?? ?? ?? 89 84 24 ?? ?? ?? ?? F3 A5 8D B4 24 ?? ?? ?? ?? C6 44
    }
    $kill_processes_v1_p2 = {
      24 ?? ?? 83 EC ?? C7 44 24 ?? ?? ?? ?? ?? 89 F7 C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ??
      ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? 89 CD C7 44 24 ?? ?? ??
      ?? ?? B9 ?? ?? ?? ?? 89 E8 F3 AB FF B4 24 ?? ?? ?? ?? 89 F7 8D 44 24 ?? 50 56 E8 ??
      ?? ?? ?? 89 34 24 E8 ?? ?? ?? ?? 83 C4 ?? 89 E8 B9 ?? ?? ?? ?? F3 AB FF B4 24 ?? ??
      ?? ?? 89 F7 8D 44 24 ?? 50 56 E8 ?? ?? ?? ?? 89 34 24 E8 ?? ?? ?? ?? 83 C4 ?? 89 E8
      B9 ?? ?? ?? ?? F3 AB FF B4 24 ?? ?? ?? ?? 89 F7 8D 44 24 ?? 50 56 E8 ?? ?? ?? ?? 89
      34 24 E8 ?? ?? ?? ?? 83 C4 ?? 89 E8 B9 ?? ?? ?? ?? F3 AB FF B4 24 ?? ?? ?? ?? 89 F7
      8D 44 24 ?? 50 56 E8 ?? ?? ?? ?? 89 34 24 E8 ?? ?? ?? ?? 83 C4 ?? 89 E8 B9 ?? ?? ??
      ?? F3 AB FF B4 24 ?? ?? ?? ?? 89 F7 8D 84 24 ?? ?? ?? ?? 50 56 E8 ?? ?? ?? ?? 89 34
      24 E8 ?? ?? ?? ?? 83 C4 ?? 89 E8 B9 ?? ?? ?? ?? F3 AB FF B4 24 ?? ?? ?? ?? 89 F7 8D
      44 24 ?? 50 56 E8 ?? ?? ?? ?? 89 34 24 E8 ?? ?? ?? ?? 83 C4 ?? 89 E8 B9 ?? ?? ?? ??
      F3 AB FF B4 24 ?? ?? ?? ?? 8D 44 24 ?? 50 56 E8 ?? ?? ?? ?? 89 34 24 E8 ?? ?? ?? ??
      81 C4 ?? ?? ?? ?? 5B 5E 5F 5D C3
    }
    $shut_down_esxi_v1    = {
      55 B8 ?? ?? ?? ?? BD ?? ?? ?? ?? 57 89 C1 56 53 E8 ?? ?? ?? ?? 81 C3 ?? ?? ?? ?? 81
      EC ?? ?? ?? ?? 8D 7C 24 ?? C7 44 24 ?? 65 73 78 63 C7 44 24 ?? 6C 69 20 76 C7 44 24
      ?? 6D 20 70 72 8D B3 ?? ?? ?? ?? C7 44 24 ?? 6F 63 65 73 F3 A5 8D B4 24 ?? ?? ?? ??
      C7 44 24 ?? 73 20 6B 69 83 EC ?? 89 F7 C7 44 24 ?? 6C 6C 20 2D C7 44 24 ?? 2D 74 79
      70 C7 44 24 ?? 65 3D 66 6F C7 44 24 ?? 72 63 65 20 C7 44 24 ?? 2D 2D 77 6F 89 C8 B9
      ?? ?? ?? ?? C7 44 24 ?? 72 6C 64 2D C7 44 24 ?? 69 64 3D 22 C7 84 24 ?? ?? ?? ?? 25
      73 22 00 C7 44 24 ?? 5B 45 53 58 C7 44 24 ?? 69 5D 20 53 C7 44 24 ?? 68 75 74 74 C7
      44 24 ?? 69 6E 67 20 C7 44 24 ?? 64 6F 77 6E F3 AB C7 44 24 ?? 20 2D 20 25 8D 83 ??
      ?? ?? ?? 66 89 6C 24 ?? C6 44 24 ?? ?? 50 8D 84 24 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83
      C4 ?? 85 C0 0F 84 ?? ?? ?? ?? BF ?? ?? ?? ?? 89 C5 8D 44 24 ?? 66 89 7C 24 ?? 31 FF
    }
    $kill_processes_v2_p1 = {
      41 54 BA ?? ?? ?? ?? B9 ?? ?? ?? ?? 45 31 E4 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 55 48 89
      FD 53 48 81 EC ?? ?? ?? ?? 66 0F 6F 05 ?? ?? 00 00 48 89 84 24 ?? ?? ?? ?? B8 ?? ??
      ?? ?? 48 8D 9C 24 ?? ?? ?? ?? 48 8D B4 24 ?? ?? ?? ?? 0F 29 84 24 ?? ?? ?? ?? 66 0F
      6F 05 ?? ?? 00 00 48 89 DF 66 89 44 24 ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 0F 29 44 24
      ?? 66 0F 6F 05 ?? ?? 00 00 66 89 54 24 ?? 48 89 EA 0F 29 44 24 ?? 66 0F 6F 05 ?? ??
      00 00 66 89 8C 24 ?? ?? 00 00 B9 ?? ?? ?? ?? 0F 29 44 24 ?? 66 0F 6F 05 ?? ?? 00 00
      C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 0F 29 84 24 ?? ?? ?? ?? 66 0F 6F 05 ?? ?? 00 00 C6
      84 24 ?? ?? ?? ?? ?? 0F 29 84 24 ?? ?? ?? ?? 66 0F 6F 05 ?? ?? 00 00 C7 44 24 ?? ??
      ?? ?? ?? 0F 29 84 24 ?? ?? ?? ?? 66 0F 6F 05 ?? ?? 00 00 C6 44 24 ?? ?? 0F 29 84 24
      ?? ?? ?? ?? C6 44 24 ?? ?? C7 44 24 ?? ?? ?? ?? ?? C6 44 24 ?? ?? C7 84 24 ?? ?? ??
      ?? ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? ?? 48 89 44 24 ?? 48 B8
    }
    $kill_processes_v2_p2 = {
      48 89 44 24 ?? 4C 89 E0 F3 48 AB 48 89 DF C6 44 24 ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7
      44 24 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 4C 89 E0 48 89 DF B9 ??
      ?? ?? ?? F3 48 AB 48 8D 74 24 ?? 48 89 EA 48 89 DF E8 ?? ?? ?? ?? 48 89 DF E8 ?? ??
      ?? ?? 4C 89 E0 48 89 DF B9 ?? ?? ?? ?? F3 48 AB 48 8D 74 24 ?? 48 89 EA 48 89 DF E8
      ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 4C 89 E0 48 89 DF B9 ?? ?? ?? ?? F3 48 AB 48 8D
      74 24 ?? 48 89 EA 48 89 DF E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 4C 89 E0 48 89 DF
      B9 ?? ?? ?? ?? F3 48 AB 48 8D B4 24 ?? ?? ?? ?? 48 89 EA 48 89 DF E8 ?? ?? ?? ?? 48
      89 DF E8 ?? ?? ?? ?? 4C 89 E0 48 89 DF B9 ?? ?? ?? ?? F3 48 AB 48 8D 74 24 ?? 48 89
      EA 48 89 DF E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 4C 89 E0 48 89 DF B9 ?? ?? ?? ??
      F3 48 AB 48 8D 74 24 ?? 48 89 EA 48 89 DF E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48
      81 C4 ?? ?? ?? ?? 5B 5D 41 5C C3
    }
    $encrypt_files_v2_p1  = {
      48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 41 57 66 0F EF C0 49 89 FF 41 56 49 89 D6 41 55 49 89
      F5 BE ?? ?? ?? ?? 41 54 55 53 48 81 EC ?? ?? ?? ?? 48 8D 5C 24 ?? 48 89 4C 24 ?? 48
      8D AC 24 ?? ?? ?? ?? 48 89 DF 4C 89 04 24 0F 29 44 24 ?? 0F 29 44 24 ?? 0F 29 44 24
      ?? 48 C7 44 24 ?? ?? ?? ?? ?? 0F 29 44 24 ?? 48 89 44 24 ?? E8 ?? ?? ?? ?? 85 C0 75
      ?? 45 31 E4 48 89 EF BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 DF BE ?? ?? ?? ?? E8 ?? ??
      ?? ?? 48 8D 7B ?? BE ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 81 C4 ?? ?? ?? ?? 44 89 E0 5B 5D
      41 5C 41 5D 41 5E 41 5F C3 0F 1F 80 ?? ?? ?? ?? 48 8D 7B ?? BE ?? ?? ?? ?? E8 ?? ??
      ?? ?? 85 C0 74 ?? BA ?? ?? ?? ?? 48 89 DE 48 89 EF E8 ?? ?? ?? ?? 48 8D 35 ?? ?? ??
      ?? 4C 89 FF E8 ?? ?? ?? ?? 48 89 44 24 ?? 48 85 C0 0F 84 ?? ?? ?? ?? 4C 89 FF E8 ??
      ?? ?? ?? 4C 89 FE 4C 89 EF 48 89 C2 49 89 C4 E8 ?? ?? ?? ?? 8B 54 24 ?? 4B 8D 44 25
      ?? 31 F6 89 10 0F B7 54 24 ?? 66 89 50 ?? 0F B6 54 24 ?? 88 50 ?? BA ?? ?? ?? ?? 43
      C6 44 25 ?? ?? 4C 8B 64 24 ?? 4C 89 E7 E8 ?? ?? ?? ?? 4C 89 E7 4C 89 64 24 ?? 45 31
      E4 E8 ?? ?? ?? ?? 48 83 F8 ?? 7E ?? 4C 89 EE 4C 89 FF E8 ?? ?? ?? ?? 85 C0 74 ?? 48
      8B 7C 24 ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 66 0F 1F 44 00 ?? 48 8B 7C 24 ?? E8 ?? ??
      ?? ?? 48 8D 35 ?? ?? ?? ?? 4C 89 EF E8 ?? ?? ?? ?? 48 89 44 24 ?? 49 89 C4 48 85 C0
    }
    $encrypt_files_v2_p2  = {
      0F 84 ?? ?? ?? ?? 31 F6 BA ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 4C 89 E7 4C 89 64 24
      ?? E8 ?? ?? ?? ?? 48 39 44 24 ?? 48 0F 4E 44 24 ?? 48 8D 7C 24 ?? 48 89 C1 48 C1 F9
      ?? 48 C1 E9 ?? 48 8D 14 08 83 E2 ?? 48 29 CA 48 29 D0 48 89 44 24 ?? E8 ?? ?? ?? ??
      48 8D BC 24 ?? ?? ?? ?? B9 ?? ?? ?? ?? 48 89 DE 48 89 44 24 ?? 31 C0 BA ?? ?? ?? ??
      F3 48 AB 48 8D 84 24 ?? ?? ?? ?? 48 8B 3C 24 48 89 C1 48 89 44 24 ?? E8 ?? ?? ?? ??
      41 89 C4 85 C0 0F 84 ?? ?? ?? ?? 48 8B 7C 24 ?? E8 ?? ?? ?? ?? 48 8B 7C 24 ?? 4C 89
      EE E8 ?? ?? ?? ?? 41 89 C4 85 C0 0F 84 ?? ?? ?? ?? 48 8B 44 24 ?? 4C 8D 64 24 ?? 48
      85 C0 75 ?? E9 ?? ?? ?? ?? 0F 1F 80 ?? ?? ?? ?? 4D 89 F1 4D 89 E8 4C 89 E9 4C 89 E2
      48 89 EE 48 8D 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 89 F6 BA ?? ?? ?? ?? 4C 89 FF 48 F7
      DE E8 ?? ?? ?? ?? 4C 89 F9 4C 89 F2 BE ?? ?? ?? ?? 4C 89 EF E8 ?? ?? ?? ?? 48 8B 44
      24 ?? 4C 29 F0 48 89 44 24 ?? 74 ?? 49 39 C6 4C 8B 7C 24 ?? BE ?? ?? ?? ?? 4C 89 EF
      4C 0F 47 F0 66 0F 6F 4C 24 ?? 4C 89 F9 4C 89 F2 0F 29 4C 24 ?? E8 ?? ?? ?? ?? 4C 39
      F0 74 ?? 48 8B 7C 24 ?? 41 BC ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 4C 89 FE 4C
      89 EF E8 ?? ?? ?? ?? E9
    }
    $find_files_v2_p1     = {
      41 57 4D 89 C7 41 56 49 89 FE 41 55 49 89 FD 41 54 55 53 89 CB 48 81 EC ?? ?? ?? ??
      48 89 34 24 89 54 24 ?? 41 8B 55 ?? 49 83 C5 ?? 8D 82 ?? ?? ?? ?? F7 D2 21 D0 25 ??
      ?? ?? ?? 74 ?? 89 C2 C1 EA ?? A9 ?? ?? ?? ?? 0F 44 C2 49 8D 55 ?? 4C 0F 44 EA 89 C6
      40 00 C6 49 83 DD ?? 31 ED 4D 29 F5 74 ?? 49 8D 6D ?? 43 80 7C 2E ?? ?? 49 0F 45 ED
      48 8D 44 24 ?? 41 89 DC 4C 89 F6 48 89 44 24 ?? 48 89 C2 BF ?? ?? ?? ?? 41 83 E4 ??
      0F 84 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 00 83 F8
      ?? 0F 85 ?? ?? ?? ?? B9 ?? ?? ?? ?? 45 31 DB 41 BC ?? ?? ?? ?? 48 8B 44 24 ?? F6 C3
      ?? 0F 85 ?? ?? ?? ?? 48 89 44 24 ?? 48 8B 44 24 ?? 4C 89 7C 24 ?? 48 89 44 24 ?? 4D
      85 FF 0F 84 ?? ?? ?? ?? 41 8B 47 ?? 8D 55 ?? 89 54 24 ?? 83 C0 ?? 89 44 24 ?? 89 44
      24 ?? 41 8B 47 ?? 89 44 24 ?? 45 31 C0 C7 44 24 ?? ?? ?? ?? ?? 83 F9 ?? 0F 84 ?? ??
      ?? ?? 89 D8 83 E0 ?? 89 44 24 ?? 75 ?? 44 88 5C 24 ?? 44 89 E2 48 8D 4C 24 ?? 4C 89
      F7 48 8B 74 24 ?? 48 8B 04 24 44 89 44 24 ?? FF D0 44 8B 44 24 ?? 44 0F B6 5C 24 ??
      85 C0 89 C2 75 ?? 4D 85 FF 0F 84 ?? ?? ?? ?? 48 8B 44 24 ?? 48 8B 54 24 ?? EB ?? 0F
      1F 44 00 ?? 4D 8B 3F 4D 85 FF 0F 84 ?? ?? ?? ?? 49 39 47 ?? 75 ?? 49 39 57 ?? 75 ??
      31 D2 48 81 C4 ?? ?? ?? ?? 89 D0 5B 5D 41 5C 41 5D 41 5E 41 5F C3 66 90 E8 ?? ?? ??
      ?? 85 C0 78 ?? 8B 44 24 ?? 25 ?? ?? ?? ?? 3D ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 3D ?? ??
      ?? ?? 0F 84 ?? ?? ?? ?? 31 C9 45 31 DB 45 31 E4 48 8B 44 24 ?? F6 C3 ?? 0F 84 ?? ??
      ?? ?? 4D 85 FF 0F 84 ?? ?? ?? ?? 49 39 47 ?? 75 ?? 48 89 44 24 ?? 48 8B 44 24 ?? 4C
    }
    $find_files_v2_p2     = {
      89 7C 24 ?? 48 89 44 24 ?? E9 ?? ?? ?? ?? 66 2E 0F 1F 84 00 ?? ?? 00 00 E8 ?? ?? ??
      ?? 49 89 C4 8B 00 83 F8 ?? 0F 85 ?? ?? ?? ?? 48 8B 54 24 ?? 4C 89 F6 BF ?? ?? ?? ??
      E8 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? B9 ?? ?? ?? ?? 45 31 DB 41 BC ?? ?? ?? ?? EB
      ?? 0F 1F 00 8B 4C 24 ?? 85 C9 74 ?? 45 84 DB 0F 85 ?? ?? ?? ?? 8B 44 24 ?? 43 C6 04
      2E ?? 85 C0 0F 84 ?? ?? ?? ?? 44 89 E2 48 8D 4C 24 ?? 48 8B 74 24 ?? 4C 89 F7 48 8B
      04 24 FF D0 89 C2 E9 ?? ?? ?? ?? 90 31 F6 4C 89 F7 31 C0 44 88 5C 24 ?? E8 ?? ?? ??
      ?? 89 44 24 ?? E8 ?? ?? ?? ?? 8B 7C 24 ?? 44 0F B6 5C 24 ?? 44 8B 00 85 FF 79 ?? 41
      83 F8 ?? BA ?? ?? ?? ?? 0F 94 C0 84 C0 B8 ?? ?? ?? ?? 44 0F 45 DA 44 0F 45 E0 8B 74
      24 ?? 85 F6 0F 85 ?? ?? ?? ?? 8B 7C 24 ?? 44 88 5C 24 ?? 44 89 44 24 ?? E8 ?? ?? ??
      ?? 44 0F B6 5C 24 ?? 44 8B 44 24 ?? E9 ?? ?? ?? ?? 0F 1F 00 48 89 44 24 ?? 48 8B 44
      24 ?? 48 C7 44 24 ?? ?? ?? ?? ?? 48 89 44 24 ?? 8D 45 ?? C7 44 24 ?? ?? ?? ?? ?? 89
      44 24 ?? C7 44 24 ?? ?? ?? ?? ?? 48 85 ED 74 ?? 41 80 3C 2E ?? 48 89 E8 74 ?? E9 ??
      ?? ?? ?? 0F 1F 44 00 ?? 41 80 3C 06 ?? 0F 85 ?? ?? ?? ?? 48 83 E8 ?? 75 ?? 31 D2 89
    }
    $find_files_v2_p3     = {
      54 24 ?? E9 ?? ?? ?? ?? 0F 1F 40 ?? 89 D8 B9 ?? ?? ?? ?? 41 BB ?? ?? ?? ?? 83 E0 ??
      83 F8 ?? 45 19 E4 41 83 E4 ?? 41 83 C4 ?? E9 ?? ?? ?? ?? 0F 1F 44 00 ?? 8B 54 24 ??
      85 D2 0F 88 ?? ?? ?? ?? 8B 7C 24 ?? E8 ?? ?? ?? ?? 49 89 C7 48 85 C0 0F 84 ?? ?? ??
      ?? B8 ?? ?? ?? ?? 44 89 64 24 ?? 4C 29 E8 48 89 44 24 ?? 48 8D 44 24 ?? 48 89 44 24
      ?? 8B 44 24 ?? 83 E8 ?? 89 44 24 ?? 4C 89 FF E8 ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ??
      ?? 80 78 ?? ?? 74 ?? 4C 8D 60 ?? 4C 89 E7 E8 ?? ?? ?? ?? 48 3B 44 24 ?? 0F 83 ?? ??
      ?? ?? 41 C6 04 2E ?? 49 8D 7C 2E ?? 4C 89 E6 E8 ?? ?? ?? ?? 4C 8B 44 24 ?? 8B 54 24
      ?? 89 D9 48 8B 34 24 4C 89 F7 E8 ?? ?? ?? ?? 85 C0 74 ?? 4C 89 FF 89 04 24 E8 ?? ??
      ?? ?? 8B 14 24 E9 ?? ?? ?? ?? 66 90 80 78 ?? ?? 74 ?? 66 83 78 ?? ?? 75 ?? EB ?? 90
      41 80 7C 06 ?? ?? 48 8D 70 ?? 89 C2 0F 84 ?? ?? ?? ?? 48 85 F6 0F 84 ?? ?? ?? ?? 41
      80 7C 06 ?? ?? 48 8D 50 ?? 75 ?? E9 ?? ?? ?? ?? 0F 1F 40 ?? 48 89 C2 48 85 D2 0F 84
      ?? ?? ?? ?? 41 80 7C 16 ?? ?? 48 8D 42 ?? 75 ?? E9 ?? ?? ?? ?? 0F 1F 00 45 85 E4 0F
      84 ?? ?? ?? ?? 31 C9 45 31 DB 41 BC ?? ?? ?? ?? E9 ?? ?? ?? ?? 4C 89 FF 44 8B 64 24
      ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 41 8B 04 24 E9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 89 FF
      C7 00 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? E9 ?? ?? ?? ?? BA ?? ?? ?? ?? E9 ??
      ?? ?? ?? 48 89 F2 E9 ?? ?? ?? ?? 44 89 04 24 E8 ?? ?? ?? ?? 44 8B 04 24 BA ?? ?? ??
      ?? 44 89 00 E9 ?? ?? ?? ?? 8B 7C 24 ?? E8 ?? ?? ?? ?? 83 CA ?? E9
    }
    $init_key_v2          = {
      48 85 FF 0F 84 ?? ?? ?? ?? 48 85 F6 0F 84 ?? ?? ?? ?? 41 56 41 55 41 54 55 48 89 F5
      53 48 89 FB 48 81 EC ?? ?? ?? ?? 4C 8D 64 24 ?? 4C 89 E7 E8 ?? ?? ?? ?? 85 C0 75 ??
      66 0F EF C0 48 8D 35 ?? ?? ?? ?? 48 8D 3D ?? ?? ?? ?? 49 89 E6 0F 29 04 24 0F 29 44
      24 ?? E8 ?? ?? ?? ?? 49 89 C5 48 85 C0 74 ?? 4C 89 F7 48 89 C1 BA ?? ?? ?? ?? BE ??
      ?? ?? ?? E8 ?? ?? ?? ?? 4C 89 EF E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 4C 89 F6 4C 89 E7 E8
      ?? ?? ?? ?? 85 C0 74 ?? 31 C0 48 81 C4 ?? ?? ?? ?? 5B 5D 41 5C 41 5D 41 5E C3 66 2E
      0F 1F 84 00 ?? ?? 00 00 31 C0 C3 0F 1F 44 00 ?? 48 89 EA 48 89 DE 4C 89 E7 E8 ?? ??
      ?? ?? 85 C0 75 ?? 4C 89 E7 E8 ?? ?? ?? ?? 89 E8 EB
    }

  condition:
    uint32(0) == 0x464C457F and (((all of ($find_files_v1_p*)) and (all of ($kill_processes_v1_p*)) and ($init_key_v1) and (all of ($encrypt_files_v1_p*)) and ($shut_down_esxi_v1)) or ((all of ($find_files_v2_p*)) and (all of ($kill_processes_v2_p*)) and ($init_key_v2) and (all of ($encrypt_files_v2_p*))))
}

rule REVERSINGLABS_Linux_Ransomware_Killdisk: TC_DETECTION MALICIOUS MALWARE FILE {
  meta:
    description         = "Yara rule that detects KillDisk ransomware."
    author              = "ReversingLabs"
    id                  = "af6652dd-c668-5ae1-b51b-e272cb440c20"
    date                = "2020-07-15"
    modified            = "2020-07-15"
    reference           = "ReversingLabs"
    source_url          = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/d35a6845dcd00f2840f690611612b04dda6d195d/yara/ransomware/Linux.Ransomware.KillDisk.yara#L1-L144"
    license_url         = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/d35a6845dcd00f2840f690611612b04dda6d195d/LICENSE"
    logic_hash          = "3ed1fb2b7b24cd4d5100d93ed53a9ab28e1482bd0998a0538d8710a962ee839f"
    score               = 75
    quality             = 90
    tags                = "TC_DETECTION, MALICIOUS, MALWARE, FILE"
    status              = "RELEASED"
    sharing             = "TLP:WHITE"
    category            = "MALWARE"
    tc_detection_type   = "Ransomware"
    tc_detection_name   = "KillDisk"
    tc_detection_factor = 5
    importance          = 25

  strings:
    $encrypt_files_1 = {
      55 48 89 E5 48 81 EC ?? ?? ?? ?? 48 89 BD ?? ?? ?? ?? 64 48 8B 04 25 ?? ?? ?? ?? 48
      89 45 ?? 31 C0 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 48 C7 85
      ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 48 8D 95 ?? ?? ?? ?? 48 8B 85
      ?? ?? ?? ?? 48 89 D6 48 89 C7 E8 ?? ?? ?? ?? 85 C0 74 ?? BF ?? ?? ?? ?? E8 ?? ?? ??
      ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ??
      ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 85 ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 C7
      B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 85 C0 79 ?? 48 8B
      85 ?? ?? ?? ?? 48 89 C6 BF ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 85 ?? ??
      ?? ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 85 C0 78 ?? 48 8B 85 ?? ?? ?? ?? BE ??
      ?? ?? ?? 48 89 C7 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? 8B 05 ?? ?? ?? ??
      85 C0 79 ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 45 ?? 48 8D 90 ?? ?? ?? ?? 48 85 C0
      48 0F 48 C2 48 C1 F8 ?? 48 89 85 ?? ?? ?? ?? 48 8B 45 ?? 48 85 C0 7E ?? 48 83 BD ??
      ?? ?? ?? ?? 7F ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ??
      ?? 75 ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 83 BD ?? ?? ?? ?? ?? 0F 8E ?? ?? ?? ?? 48
      83 BD ?? ?? ?? ?? ?? 7F ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ??
      ?? ?? ?? ?? 75 ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 85 ?? ?? ?? ?? 48 89 C2 48 C1
    }
    $encrypt_files_2 = {
      EA ?? 48 01 D0 48 D1 F8 48 C1 E0 ?? 48 89 C1 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89
      CE 89 C7 E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ??
      ?? ?? ?? 75 ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 83 BD ?? ?? ?? ?? ?? 0F 8E ?? ?? ??
      ?? 48 81 BD ?? ?? ?? ?? ?? ?? ?? ?? 0F 8F ?? ?? ?? ?? 48 8B 8D ?? ?? ?? ?? 48 BA ??
      ?? ?? ?? ?? ?? ?? ?? 48 89 C8 48 F7 EA 48 8D 04 0A 48 C1 F8 ?? 48 89 C2 48 89 C8 48
      C1 F8 ?? 48 29 C2 48 89 D0 89 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? EB ?? 8B
      85 ?? ?? ?? ?? C1 E0 ?? 48 63 C8 8B 85 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 CE 89 C7 E8
      ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 75
      ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 83 85 ?? ?? ?? ?? ?? 83 85 ?? ?? ?? ?? ?? 8B 85 ??
      ?? ?? ?? 3B 85 ?? ?? ?? ?? 7C ?? 48 81 BD ?? ?? ?? ?? ?? ?? ?? ?? 0F 8E ?? ?? ?? ??
      48 8B 8D ?? ?? ?? ?? 48 BA ?? ?? ?? ?? ?? ?? ?? ?? 48 89 C8 48 F7 EA 48 8D 04 0A 48
      C1 F8 ?? 48 89 C2 48 89 C8 48 C1 F8 ?? 48 29 C2 48 89 D0 89 85 ?? ?? ?? ?? C7 85 ??
      ?? ?? ?? ?? ?? ?? ?? EB ?? 8B 85 ?? ?? ?? ?? C1 E0 ?? 48 63 C8 8B 85 ?? ?? ?? ?? BA
      ?? ?? ?? ?? 48 89 CE 89 C7 E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 85 ?? ??
      ?? ?? 83 BD ?? ?? ?? ?? ?? 75 ?? B8 ?? ?? ?? ?? EB ?? 83 85 ?? ?? ?? ?? ?? 83 85 ??
      ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 3B 85 ?? ?? ?? ?? 7C ?? 8B 05 ?? ?? ?? ?? 89 C7 E8 ??
      ?? ?? ?? 8B 05 ?? ?? ?? ?? 89 C7 E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 48 8B 75 ?? 64 48 33
      34 25 ?? ?? ?? ?? 74 ?? E8 ?? ?? ?? ?? C9 C3
    }
    $search_files    = {
      55 48 89 E5 48 81 EC ?? ?? ?? ?? 48 89 BD ?? ?? ?? ?? 64 48 8B 04 25 ?? ?? ?? ?? 48
      89 45 ?? 31 C0 8B 05 ?? ?? ?? ?? 83 C0 ?? 89 05 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 83 F8
      ?? 75 ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ??
      48 89 85 ?? ?? ?? ?? 48 83 BD ?? ?? ?? ?? ?? 75 ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? C7
      85 ?? ?? ?? ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 85 ??
      ?? ?? ?? 48 83 C0 ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ??
      48 8B 85 ?? ?? ?? ?? 48 83 C0 ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 85 C0 75 ??
      E9 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 48 8B 85 ?? ?? ?? ?? 48 83 C0
      ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 85 C0 75 ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ??
      E9 ?? ?? ?? ?? 48 8B 85 ?? ?? ?? ?? 48 83 C0 ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ??
      ?? 85 C0 74 ?? 48 8B 85 ?? ?? ?? ?? 48 83 C0 ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ??
      ?? 85 C0 75 ?? 83 85 ?? ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? C7 85 ??
      ?? ?? ?? ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 95 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 48 89
      D6 48 89 C7 E8 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 48 C7 C1 ?? ?? ?? ?? 48 89 C2 B8 ??
      ?? ?? ?? 48 89 D7 F2 AE 48 89 C8 48 F7 D0 48 8D 50 ?? 48 8D 85 ?? ?? ?? ?? 48 01 D0
      66 C7 00 ?? ?? 48 8B 85 ?? ?? ?? ?? 48 8D 50 ?? 48 8D 85 ?? ?? ?? ?? 48 89 D6 48 89
      C7 E8 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 83 F8 ?? 75 ?? 48 8D
      85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 83 E8 ?? 89 05 ?? ?? ?? ??
      48 8B 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 83 BD ?? ?? ??
      ?? ?? 0F 85 ?? ?? ?? ?? 48 8B 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? B8 ?? ?? ?? ??
      48 8B 4D ?? 64 48 33 0C 25 ?? ?? ?? ?? 74 ?? E8 ?? ?? ?? ?? C9 C3
    }
    $subvert_grub_1  = {
      55 48 89 E5 48 81 EC ?? ?? ?? ?? 64 48 8B 04 25 ?? ?? ?? ?? 48 89 45 ?? 31 C0 48 B8
      ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85
      ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ??
      ?? ?? ?? 48 89 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ??
      ?? ?? 48 89 85 ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 B8
      ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85
      ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ??
      ?? ?? ?? 66 C7 85 ?? ?? FF FF ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? ??
      ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ??
      48 89 85 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 48 B8 ?? ??
      ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 ?? ??
      ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ??
      ?? 48 89 85 ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 B8
    }
    $subvert_grub_2  = {
      48 89 85 ?? ?? ?? ?? 66 C7 85 ?? ?? FF FF ?? ?? 48 B8 ?? ?? ??
      ?? ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? ??
      ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ??
      48 89 85 ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 B8 ?? ??
      ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 ?? ??
      ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ??
      ?? E8 ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 83 BD ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 48
      8B 85 ?? ?? ?? ?? 48 89 C1 BA ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ??
      ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 4C 8D 85 ?? ??
      ?? ?? 48 8D BD ?? ?? ?? ?? 48 8D 8D ?? ?? ?? ?? 48 8D 95 ?? ?? ?? ?? 48 8B 85 ?? ??
      ?? ?? 48 8D B5 ?? ?? ?? ?? 56 48 8D B5 ?? ?? ?? ?? 56 4D 89 C1 49 89 F8 BE ?? ?? ??
      ?? 48 89 C7 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 C4 ?? 48 8B 85 ?? ?? ?? ?? 48 89 C7
      E8 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 85 ?? ?? ?? ?? 48 83 BD ?? ?? ??
      ?? ?? 0F 85 ?? ?? ?? ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 48 B9 ??
      ?? ?? ?? ?? ?? ?? ?? 48 89 08 C7 40 ?? ?? ?? ?? ?? C6 40 ?? ?? 48 8B 85
    }
    $subvert_grub_3  = {
      48 8D 50 ?? 48 8D 85 ?? ?? ?? ?? 48 89 D6 48 89 C7 E8 ?? ?? ?? ?? 48 8B 85 ?? ?? ??
      ?? 48 83 C0 ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 85 ?? ?? ??
      ?? 48 83 C0 ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 85 ?? ?? ??
      ?? 48 83 C0 ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 85 C0 75 ?? EB ?? 48 8D 85 ??
      ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 8B 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89
      85 ?? ?? ?? ?? 48 83 BD ?? ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ??
      ?? E9 ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 85 ?? ?? ?? ??
      48 83 BD ?? ?? ?? ?? ?? 74 ?? 4C 8D 85 ?? ?? ?? ?? 48 8D BD ?? ?? ?? ?? 48 8D 8D ??
      ?? ?? ?? 48 8D 95 ?? ?? ?? ?? 48 8B 85 ?? ?? ?? ?? 48 8D B5 ?? ?? ?? ?? 56 48 8D B5
      ?? ?? ?? ?? 56 4D 89 C1 49 89 F8 BE ?? ?? ?? ?? 48 89 C7 B8 ?? ?? ?? ?? E8 ?? ?? ??
      ?? 48 83 C4 ?? EB ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 85 ?? ?? ??
      ?? 48 83 BD ?? ?? ?? ?? ?? 74 ?? 4C 8D 85 ?? ?? ?? ?? 48 8D BD ?? ?? ?? ?? 48 8D 8D
      ?? ?? ?? ?? 48 8D 95 ?? ?? ?? ?? 48 8B 85 ?? ?? ?? ?? 48 8D B5 ?? ?? ?? ?? 56 48 8D
      B5 ?? ?? ?? ?? 56 4D 89 C1 49 89 F8 BE ?? ?? ?? ?? 48 89 C7 B8 ?? ?? ?? ?? E8 ?? ??
      ?? ?? 48 83 C4 ?? 48 8B 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 48 8B
      55 ?? 64 48 33 14 25 ?? ?? ?? ?? 74 ?? E8 ?? ?? ?? ?? C9 C3
    }

  condition:
    uint32(0) == 0x464C457F and ($search_files and (all of ($encrypt_files_*)) and (all of ($subvert_grub_*)))
}

rule REVERSINGLABS_Linux_Ransomware_Luckyjoe: TC_DETECTION MALICIOUS MALWARE FILE {
  meta:
    description         = "Yara rule that detects LuckyJoe ransomware."
    author              = "ReversingLabs"
    id                  = "8dc98d71-b79d-5b09-9383-11f2b57baeb5"
    date                = "2020-07-15"
    modified            = "2020-07-15"
    reference           = "ReversingLabs"
    source_url          = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/d35a6845dcd00f2840f690611612b04dda6d195d/yara/ransomware/Linux.Ransomware.LuckyJoe.yara#L1-L146"
    license_url         = "https://github.com/reversinglabs/reversinglabs-yara-rules//blob/d35a6845dcd00f2840f690611612b04dda6d195d/LICENSE"
    logic_hash          = "1e7df2c45bee072af233cf8f355a84ec931fe96afa3fbdcd225dded1b75ea961"
    score               = 75
    quality             = 90
    tags                = "TC_DETECTION, MALICIOUS, MALWARE, FILE"
    status              = "RELEASED"
    sharing             = "TLP:WHITE"
    category            = "MALWARE"
    tc_detection_type   = "Ransomware"
    tc_detection_name   = "LuckyJoe"
    tc_detection_factor = 5
    importance          = 25

  strings:
    $main_call_p1                = {
      55 48 89 E5 48 81 EC ?? ?? ?? ?? 48 C7 45 ?? ?? ?? ?? ?? 48 C7 45 ?? ?? ?? ?? ?? 48
      C7 45 ?? ?? ?? ?? ?? 48 C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ??
      48 89 45 ?? 48 8B 55 ?? 48 8B 45 ?? 48 89 D6 48 89 C7 E8 ?? ?? ?? ?? 48 8D 75 ?? 48
      8B 45 ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? BE ?? ??
      ?? ?? BF ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 89 C7 E8
      ?? ?? ?? ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ??
      ?? 48 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? E8 ?? ??
      ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 48 8B 35 ?? ?? ?? ?? 48 83 EC ?? 48 8B 45
      ?? 6A ?? 41 B9 ?? ?? ?? ?? 41 B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? 48 89 C7
      E8 ?? ?? ?? ?? 48 83 C4 ?? 48 8B 15 ?? ?? ?? ?? 48 8B 45 ?? 48 89 D6 48 89 C7 E8 ??
      ?? ?? ?? 48 8B 45 ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ??
      ?? ?? 48 98 48 89 45 ?? 48 8B 45 ?? B9 ?? ?? ?? ?? BA ?? ?? ?? ?? BE ?? ?? ?? ?? 48
    }
    $main_call_p2                = {
      89 C7 E8 ?? ?? ?? ?? 48 98 48 89 45 ?? 48 8B 45 ?? 48 83 C0 ?? 48 89 C7 E8 ?? ?? ??
      ?? 48 89 45 ?? 48 8B 45 ?? 48 83 C0 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 48 8B 45
      ?? 89 C2 48 8B 4D ?? 48 8B 45 ?? 48 89 CE 48 89 C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 89 C2
      48 8B 4D ?? 48 8B 45 ?? 48 89 CE 48 89 C7 E8 ?? ?? ?? ?? 48 8B 55 ?? 48 8B 45 ?? 48
      01 D0 C6 00 ?? 48 8B 55 ?? 48 8B 45 ?? 48 01 D0 C6 00 ?? 48 8B 45 ?? 48 8B 55 ?? 48
      89 D6 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 48 83 7D ?? ?? 75 ?? BF ?? ?? ?? ?? E8 ??
      ?? ?? ?? B8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C6 BF ?? ?? ?? ?? B8 ?? ??
      ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 ?? 74 ?? B8
      ?? ?? ?? ?? E9 ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 45 ??
      48 83 7D ?? ?? 74 ?? 48 8B 55 ?? 48 8B 45 ?? BE ?? ?? ?? ?? 48 89 C7 B8
    }
    $main_call_p3                = {
      E8 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 79 ?? 48 8B 45 ?? 89 C7 E8 ?? ?? ?? ?? B8 ?? ??
      ?? ?? E9 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 89 C7 E8 ?? ??
      ?? ?? 48 C7 45 ?? ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 45
      ?? 48 83 7D ?? ?? 74 ?? EB ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? E9 ?? ??
      ?? ?? 48 8B 55 ?? 48 8B 45 ?? BE ?? ?? ?? ?? 48 89 C7 B8 ?? ?? ?? ?? E8 ?? ?? ?? ??
      89 45 ?? 83 7D ?? ?? 79 ?? 48 8B 45 ?? 89 C7 E8 ?? ?? ?? ?? EB ?? 48 8B 45 ?? 48 89
      C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 89 C7 E8 ?? ?? ?? ?? EB ?? BF ?? ?? ?? ?? E8 ?? ?? ??
      ?? 48 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ??
      ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? EB ?? 8B 45 ?? 48 98 48 8B 84
      C5 ?? ?? ?? ?? 48 89 C6 BF ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? 48 98
      48 8B 84 C5 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 83 45 ?? ?? 83 7D ?? ?? 74 ?? BF ??
      ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8
      ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? C9 C3
    }
    $encrypt_files_p1            = {
      55 48 89 E5 53 48 81 EC ?? ?? ?? ?? 48 89 BD ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? BA ??
      ?? ?? ?? B9 ?? ?? ?? ?? 48 89 C7 48 89 D6 F3 48 A5 48 89 F2 48 89 F8 0F B7 0A 66 89
      08 48 8D 40 ?? 48 8D 52 ?? 48 C7 45 ?? ?? ?? ?? ?? 48 C7 85 ?? ?? ?? ?? ?? ?? ?? ??
      48 C7 45 ?? ?? ?? ?? ?? 48 8D 95 ?? ?? ?? ?? B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 48 89 D7
      F3 48 AB 48 8B 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 48 83 7D ?? ?? 75
      ?? 48 8B 85 ?? ?? ?? ?? 48 89 C6 BF ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ??
      ?? ?? ?? E9 ?? ?? ?? ?? 48 8D 95 ?? ?? ?? ?? 48 8D 85 ?? ?? ?? ?? 48 89 D6 48 89 C7
      E8 ?? ?? ?? ?? 48 8B 45 ?? 0F B6 40 ?? 3C ?? 0F 85 ?? ?? ?? ?? 48 8B 85 ?? ?? ?? ??
      48 89 C7 E8 ?? ?? ?? ?? 48 89 C3 48 8B 45 ?? 48 83 C0 ?? 48 89 C7 E8 ?? ?? ?? ?? 48
      01 D8 48 83 C0 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 48 8B 85 ?? ?? ?? ?? BE ?? ??
      ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 84 C0 74 ?? 48 8B 45 ?? 48 8D 48 ?? 48 8B 95 ?? ?? ??
      ?? 48 8B 45 ?? BE ?? ?? ?? ?? 48 89 C7 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB ?? 48 8B 45
      ?? 48 8D 48 ?? 48 8B 95 ?? ?? ?? ?? 48 8B 45 ?? BE ?? ?? ?? ?? 48 89 C7 B8 ?? ?? ??
      ?? E8 ?? ?? ?? ?? 48 8D 95 ?? ?? ?? ?? 48 8B 4D ?? 48 8D 85 ?? ?? ?? ?? 48 89 CE 48
      89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? EB ?? 48 8B 45 ?? 48 83 C0 ?? 48 89 C7 E8 ?? ?? ??
      ?? 48 89 C2 48 8B 45 ?? 48 89 C6 48 89 D7 E8 ?? ?? ?? ?? 85 C0 75 ?? 48 8B 45 ?? 48
    }
    $encrypt_files_p2            = {
      89 C6 BF ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ??
      ?? EB ?? 48 8D 95 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C6 BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 48
      89 45 ?? 48 83 7D ?? ?? 75 ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48
      8B 45 ?? 0F B6 40 ?? 3C ?? 0F 85 ?? ?? ?? ?? 48 8B 45 ?? 48 83 C0 ?? BE ?? ?? ?? ??
      48 89 C7 E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 45 ?? 48 83 C0 ?? BE ?? ?? ??
      ?? 48 89 C7 E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8B 45 ?? 48 83 C0 ?? 48 89 45
      ?? 48 8B 85 ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 C3 48 8B 45 ?? 48 89 C7 E8 ??
      ?? ?? ?? 48 01 D8 48 83 C0 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 48 8B 85 ?? ?? ??
      ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 84 C0 74 ?? 48 8B 45 ?? 48 8D 48 ?? 48 8B
      95 ?? ?? ?? ?? 48 8B 45 ?? BE ?? ?? ?? ?? 48 89 C7 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB
      ?? 48 8B 45 ?? 48 8D 48 ?? 48 8B 95 ?? ?? ?? ?? 48 8B 45 ?? BE ?? ?? ?? ?? 48 89 C7
      B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89
      C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 48 83 7D ?? ?? 0F
      85 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 81 C4 ?? ?? ?? ?? 5B 5D C3
    }
    $encrypt_internal_message_p1 = {
      55 48 89 E5 53 48 83 EC ?? 48 89 7D ?? 48 89 75 ?? 48 C7 45 ?? ?? ?? ?? ?? BF ?? ??
      ?? ?? E8 ?? ?? ?? ?? 48 89 45 ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 89 45 ?? 48 8B
      45 ?? 48 89 C7 E8 ?? ?? ?? ?? 89 45 ?? 8B 45 ?? 83 C0 ?? 48 98 48 89 C7 E8 ?? ?? ??
      ?? 48 89 45 ?? 8B 45 ?? 83 C0 ?? 48 63 D0 48 8B 45 ?? BE ?? ?? ?? ?? 48 89 C7 E8 ??
      ?? ?? ?? 8B 45 ?? 48 63 D0 48 8B 4D ?? 48 8B 45 ?? 48 89 CE 48 89 C7 E8 ?? ?? ?? ??
      8B 45 ?? 48 98 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ??
      ?? ?? ?? 8B 45 ?? 83 E8 ?? 89 45 ?? C7 45 ?? ?? ?? ?? ?? 66 0F EF C0 F2 0F 2A 45 ??
      66 0F EF C9 F2 0F 2A 4D ?? F2 0F 5E C1 E8 ?? ?? ?? ?? F2 0F 2C C0 89 45 ?? 8B 45 ??
      0F AF 45 ?? 48 98 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 8B 45 ?? 0F AF 45 ?? 48 63 D0
      48 8B 45 ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 8B 45 ?? 0F AF 45 ?? 89 C3 48 8B
      45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 C6 8B 45 ?? 89 C1 89 DA BF ?? ?? ?? ?? B8 ?? ??
      ?? ?? E8 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 48 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ??
      ?? E9 ?? ?? ?? ?? 8B 45 ?? 2B 45 ?? 3B 45 ?? 7D ?? 8B 45 ?? 2B 45 ?? 89 45 ?? 8B 45
      ?? 48 63 D0 48 8B 45 ?? BE ?? ?? ?? ?? 48 89 C7 E8 ?? ?? ?? ?? 8B 45 ?? 2B 45 ?? 89
    }
    $encrypt_internal_message_p2 = {
      C6 BF ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? 48 63 D0 48 8B 45 ?? 48 8D
      34 02 48 8B 4D ?? 48 8B 55 ?? 8B 45 ?? 41 B8 ?? ?? ?? ?? 89 C7 E8 ?? ?? ?? ?? 89 45
      ?? 8B 45 ?? 89 C6 BF ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 7D ?? ?? 75 ?? E8
      ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 C2 48 8B 45 ?? 48 89 C6 48 89 D7 E8 ?? ?? ?? ?? 48
      8B 05 ?? ?? ?? ?? 48 8B 55 ?? BE ?? ?? ?? ?? 48 89 C7 B8 ?? ?? ?? ?? E8 ?? ?? ?? ??
      48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 8B 45 ??
      48 89 C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? B8 ?? ?? ?? ?? E9 ?? ??
      ?? ?? 8B 45 ?? 48 63 D0 8B 45 ?? 48 63 C8 48 8B 45 ?? 48 01 C1 48 8B 45 ?? 48 89 C6
      48 89 CF E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 48 89 C6 BF ?? ?? ?? ??
      B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 ?? 01 45 ?? 8B 45 ?? 01 45 ?? 48 8B 45 ?? 48 89
      C7 E8 ?? ?? ?? ?? 83 45 ?? ?? 8B 45 ?? 3B 45 ?? 0F 8E ?? ?? ?? ?? 48 8B 45 ?? 48 89
      C7 E8 ?? ?? ?? ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ?? 8B 4D ?? 48 8B 45 ?? BA ?? ??
      ?? ?? 89 CE 48 89 C7 E8 ?? ?? ?? ?? 48 89 45 ?? 48 8B 45 ?? 48 89 C7 E8 ?? ?? ?? ??
      48 89 C6 BF ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 45 ?? 48 83 C4 ?? 5B 5D
      C3
    }

  condition:
    uint32(0) == 0x464C457F and (all of ($main_call_p*)) and (all of ($encrypt_files_p*)) and (all of ($encrypt_internal_message_p*))
}

rule ESET_Linux_Rakos {
  meta:
    description = "Linux/Rakos.A executable"
    author      = "Peter Kálnai"
    id          = "3c15401a-22c1-59e2-a979-1f9a6a990ae0"
    date        = "2016-12-13"
    modified    = "2016-12-19"
    reference   = "http://www.welivesecurity.com/2016/12/20/new-linuxrakos-threat-devices-servers-ssh-scan/"
    source_url  = "https://github.com/eset/malware-ioc/blob/21381c70ad030105cf9edb092dfd1cae29753286/rakos/rakos.yar#L33-L53"
    license_url = "https://github.com/eset/malware-ioc/blob/21381c70ad030105cf9edb092dfd1cae29753286/LICENSE"
    logic_hash  = "79a02ada56bf75c5f178b58822eb905977cace3483453ea8cf4dfc32f6b6c30d"
    score       = 75
    quality     = 80
    tags        = ""
    version     = "1"
    contact     = "threatintel@eset.com"
    license     = "BSD 2-Clause"

  strings:
    $ = "upgrade/vars.yaml"
    $ = "MUTTER"
    $ = "/tmp/.javaxxx"
    $ = "uckmydi"

  condition:
    3 of them
}

rule ESET_Libkeyutils_With_Ctor {
  meta:
    description = "This rule detects if a libkeyutils.so shared library has a potentially malicious function to be called when loaded, either via a glibc constructor (DT_INIT + .ctors) or an initializer function in DT_INIT_ARRAY."
    author      = "ESET, spol. s r.o."
    id          = "7b466bf7-f895-569d-99b0-eca95a6ebc83"
    date        = "2024-02-01"
    modified    = "2024-04-29"
    reference   = "https://github.com/eset/malware-ioc/"
    source_url  = "https://github.com/eset/malware-ioc/blob/21381c70ad030105cf9edb092dfd1cae29753286/windigo/ebury.yar#L3-L54"
    license_url = "https://github.com/eset/malware-ioc/blob/21381c70ad030105cf9edb092dfd1cae29753286/LICENSE"
    hash        = "e7debd6e453192ad8376db5bab03ed0d87566591"
    logic_hash  = "c6172aebc67a05fb044b0450aafcc71c7d1fd2831985587d1a9ad53f59e14214"
    score       = 75
    quality     = 80
    tags        = ""
    license     = "BSD 2-Clause"
    version     = 2

  strings:
    $libname = "libkeyutils.so.1"

  condition:
    for any ptr_size in (4, 8): (((ptr_size == 4 and elf.machine == elf.EM_386) or (ptr_size == 8 and elf.machine == elf.EM_X86_64)) and for any d in elf.dynamic: (d.type == elf.DT_SONAME and (for any s in elf.sections: (s.name == ".dynstr" and $libname at (s.offset + d.val)) or for any s in elf.dynamic: (s.type == elf.DT_STRTAB and $libname at (s.val + d.val)))) and (for any s in elf.sections: (s.name == ".ctors" and s.size > 2 * ptr_size) or for any d in elf.dynamic: (d.type == elf.DT_INIT_ARRAYSZ and d.val > ptr_size)))
}

rule ESET_Onimiki: LINUX_ONIMIKI {
  meta:
    description = "Linux/Onimiki malicious DNS server"
    author      = "Olivier Bilodeau <bilodeau@eset.com>"
    id          = "3a99799f-fbb4-5fee-a796-3310acd10e17"
    date        = "2014-02-06"
    modified    = "2014-04-04"
    reference   = "https://github.com/eset/malware-ioc/"
    source_url  = "https://github.com/eset/malware-ioc/blob/21381c70ad030105cf9edb092dfd1cae29753286/windigo/windigo-onimiki.yar#L32-L59"
    license_url = "https://github.com/eset/malware-ioc/blob/21381c70ad030105cf9edb092dfd1cae29753286/LICENSE"
    logic_hash  = "eac30f5c9a9606d1d0e14c55e0532c54976fbb0d2e4f5cd2d9f719b77e07161a"
    score       = 75
    quality     = 80
    tags        = "LINUX/ONIMIKI"
    malware     = "Linux/Onimiki"
    operation   = "Windigo"
    contact     = "windigo@eset.sk"
    license     = "BSD 2-Clause"

  strings:
    $a1 = { 43 0F B6 74 2A 0E 43 0F B6 0C 2A 8D 7C 3D 00 8D }
    $a2 = { 74 35 00 8D 4C 0D 00 89 F8 41 F7 E3 89 F8 29 D0 }
    $a3 = { D1 E8 01 C2 89 F0 C1 EA 04 44 8D 0C 92 46 8D 0C }
    $a4 = { 8A 41 F7 E3 89 F0 44 29 CF 29 D0 D1 E8 01 C2 89 }
    $a5 = { C8 C1 EA 04 44 8D 04 92 46 8D 04 82 41 F7 E3 89 }
    $a6 = { C8 44 29 C6 29 D0 D1 E8 01 C2 C1 EA 04 8D 04 92 }
    $a7 = { 8D 04 82 29 C1 42 0F B6 04 21 42 88 84 14 C0 01 }
    $a8 = { 00 00 42 0F B6 04 27 43 88 04 32 42 0F B6 04 26 }
    $a9 = { 42 88 84 14 A0 01 00 00 49 83 C2 01 49 83 FA 07 }

  condition:
    all of them
}

rule MALPEDIA_Elf_Mirai_Auto: FILE {
  meta:
    description        = "autogenerated rule brought to you by yara-signator"
    author             = "Felix Bilstein - yara-signator at cocacoding dot com"
    id                 = "99bf67bb-d881-5d1d-9ccf-8805d4c126fc"
    date               = "2023-12-06"
    modified           = "2023-12-08"
    reference          = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.mirai"
    source_url         = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/elf.mirai_auto.yar#L1-L92"
    license_url        = "N/A"
    logic_hash         = "53d684afadf5b7afddedfe71964fc5273146fef2945717259a3274aa2e1d04ee"
    score              = 75
    quality            = 75
    tags               = "FILE"
    version            = "1"
    tool               = "yara-signator v0.6.0"
    signator_config    = "callsandjumps;datarefs;binvalue"
    malpedia_rule_date = "20231130"
    malpedia_hash      = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
    malpedia_version   = "20230808"
    malpedia_license   = "CC BY-SA 4.0"
    malpedia_sharing   = "TLP:WHITE"

  strings:
    $sequence_0 = { 66 89 43 2a e8 ?? ?? ?? ?? c7 43 34 00 00 00 00 89 43 30 }
    $sequence_1 = { 89 d0 c1 e0 05 01 d0 89 ca }
    $sequence_2 = { 89 43 30 c6 43 38 01 c6 43 39 03 c6 43 3a 03 c6 43 3b 06 }
    $sequence_3 = { 66 c1 e8 08 d0 e8 8d 04 c0 28 c2 }
    $sequence_4 = { 3c 19 77 05 8d 42 e0 88 01 }
    $sequence_5 = { 80 7c 24 2b 00 66 89 43 04 74 06 66 c7 43 06 40 00 c6 43 09 2f }
    $sequence_6 = { 66 89 41 04 74 06 66 c7 41 06 40 00 c6 41 09 11 }
    $sequence_7 = { 8b 14 08 89 53 10 8b 54 08 0c 66 89 53 14 }

  condition:
    7 of them and filesize < 2228224
}

rule MALPEDIA_Elf_Blackcat_Auto: FILE {
  meta:
    description        = "autogenerated rule brought to you by yara-signator"
    author             = "Felix Bilstein - yara-signator at cocacoding dot com"
    id                 = "8a7e13ba-9ed1-59ed-8fb9-9aaa610fbd94"
    date               = "2023-12-06"
    modified           = "2023-12-08"
    reference          = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.blackcat"
    source_url         = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/elf.blackcat_auto.yar#L1-L113"
    license_url        = "N/A"
    logic_hash         = "1ac97428ed273512eef4209d87a29f49ce26e88d11cb15b15e2f2687ea017381"
    score              = 60
    quality            = 45
    tags               = "FILE"
    version            = "1"
    tool               = "yara-signator v0.6.0"
    signator_config    = "callsandjumps;datarefs;binvalue"
    malpedia_rule_date = "20231130"
    malpedia_hash      = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
    malpedia_version   = "20230808"
    malpedia_license   = "CC BY-SA 4.0"
    malpedia_sharing   = "TLP:WHITE"

  strings:
    $sequence_0 = { e8 ?? ?? ?? ?? 0f 0b 90 90 90 90 53 }
    $sequence_1 = { 69 c0 ?? ?? ?? ?? c1 e8 11 6b f0 64 29 f2 0f b7 d2 }
    $sequence_2 = { e8 ?? ?? ?? ?? 0f 0b 90 53 }
    $sequence_3 = { 89 c1 3d ?? ?? ?? ?? 73 19 c1 e9 06 }
    $sequence_4 = { 66 0f 7f 84 24 f0 01 00 00 66 0f 7f 84 24 e0 01 00 00 66 0f 7f 84 24 d0 01 00 00 66 0f 7f 84 24 c0 01 00 00 66 0f 7f 84 24 b0 01 00 00 }
    $sequence_5 = { d1 e9 01 d1 c1 e9 02 8d 14 cd 00 00 00 00 }
    $sequence_6 = { b8 01 00 00 00 81 f9 ?? ?? ?? ?? 0f 82 3f ff ff ff b8 02 00 00 00 }
    $sequence_7 = { 69 c0 ?? ?? ?? ?? c1 e8 10 29 c2 0f b7 d2 d1 ea }
    $sequence_8 = { 76 2a 0f b6 c8 8d 14 89 8d 0c d1 }
    $sequence_9 = { e8 ?? ?? ?? ?? 0f 0b e8 ?? ?? ?? ?? 0f 0b 90 90 90 }

  condition:
    7 of them and filesize < 8011776
}

rule MALPEDIA_Elf_Bashlite_Auto: FILE {
  meta:
    description        = "autogenerated rule brought to you by yara-signator"
    author             = "Felix Bilstein - yara-signator at cocacoding dot com"
    id                 = "ca6414ba-2b9c-5f1f-bb06-5810c9d01c02"
    date               = "2023-12-06"
    modified           = "2023-12-08"
    reference          = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.bashlite"
    source_url         = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/elf.bashlite_auto.yar#L1-L113"
    license_url        = "N/A"
    logic_hash         = "38a010b68cee7bf4f221088e2245d1e5d0f927b085c409c35c3789c20373d434"
    score              = 75
    quality            = 75
    tags               = "FILE"
    version            = "1"
    tool               = "yara-signator v0.6.0"
    signator_config    = "callsandjumps;datarefs;binvalue"
    malpedia_rule_date = "20231130"
    malpedia_hash      = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
    malpedia_version   = "20230808"
    malpedia_license   = "CC BY-SA 4.0"
    malpedia_sharing   = "TLP:WHITE"

  strings:
    $sequence_0 = { eb 19 e8 ?? ?? ?? ?? c7 00 16 00 00 00 e8 ?? ?? ?? ?? c7 00 16 00 00 00 }
    $sequence_1 = { 21 d0 33 45 fc c9 c3 55 }
    $sequence_2 = { 75 0c e8 ?? ?? ?? ?? 8b 00 83 f8 73 }
    $sequence_3 = { 8b 85 ec ef ff ff c9 c3 55 }
    $sequence_4 = { 76 0f e8 ?? ?? ?? ?? c7 00 1c 00 00 00 31 c0 }
    $sequence_5 = { 31 c0 eb 19 e8 ?? ?? ?? ?? c7 00 16 00 00 00 }
    $sequence_6 = { e8 ?? ?? ?? ?? 89 c2 89 d0 c1 e8 1f 01 d0 d1 f8 }
    $sequence_7 = { 85 c0 75 0c c7 85 ec ef ff ff 01 00 00 00 eb 0a c7 85 ec ef ff ff 00 00 00 00 }
    $sequence_8 = { 85 c0 75 0c c7 85 ec ef ff ff 01 00 00 00 eb 0a c7 85 ec ef ff ff 00 00 00 00 8b 85 ec ef ff ff }
    $sequence_9 = { c7 85 ec ef ff ff 01 00 00 00 eb 0a c7 85 ec ef ff ff 00 00 00 00 8b 85 ec ef ff ff c9 c3 }

  condition:
    7 of them and filesize < 2310144
}

rule MALPEDIA_Elf_Persirai_Auto: FILE {
  meta:
    description        = "autogenerated rule brought to you by yara-signator"
    author             = "Felix Bilstein - yara-signator at cocacoding dot com"
    id                 = "a8d888a8-efae-5fcd-8298-ba3399d89281"
    date               = "2023-12-06"
    modified           = "2023-12-08"
    reference          = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.persirai"
    source_url         = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/elf.persirai_auto.yar#L1-L132"
    license_url        = "N/A"
    logic_hash         = "091433f152a0a1932173079b7afa5457b62363ecd6425f8d1d7de8df73a8fbb4"
    score              = 75
    quality            = 75
    tags               = "FILE"
    version            = "1"
    tool               = "yara-signator v0.6.0"
    signator_config    = "callsandjumps;datarefs;binvalue"
    malpedia_rule_date = "20231130"
    malpedia_hash      = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
    malpedia_version   = "20230808"
    malpedia_license   = "CC BY-SA 4.0"
    malpedia_sharing   = "TLP:WHITE"

  strings:
    $sequence_0 = { c3 c3 53 83 ec 08 e8 ?? ?? ?? ?? 31 d2 8b 5c 24 14 }
    $sequence_1 = { 8b 5c 24 10 83 7c 24 14 00 74 0b 83 ec 0c ff 73 04 ff 13 83 c4 10 }
    $sequence_2 = { 50 52 e8 ?? ?? ?? ?? 58 8d 84 24 d8 17 00 00 50 e8 ?? ?? ?? ?? }
    $sequence_3 = { 8d 44 00 e0 50 e8 ?? ?? ?? ?? 89 c2 a3 ?? ?? ?? ?? 83 c4 10 83 c8 ff }
    $sequence_4 = { 81 7c 24 14 ff 03 00 00 0f 87 70 03 00 00 8b 44 24 14 c1 e0 04 83 b8 88 a2 05 08 00 0f 85 df 00 00 00 8b 0d ?? ?? ?? ?? }
    $sequence_5 = { c7 04 24 08 00 00 00 50 a1 ?? ?? ?? ?? 6a 1a 6a 01 50 e8 ?? ?? ?? ?? }
    $sequence_6 = { 83 c4 18 5b c3 81 ec ac 00 00 00 31 d2 a1 ?? ?? ?? ?? }
    $sequence_7 = { 85 c0 74 cb e8 ?? ?? ?? ?? 52 52 8b 00 }
    $sequence_8 = { c6 80 b9 01 00 00 00 8b 45 f0 e8 ?? ?? ?? ?? 89 f0 8b 55 f0 e8 ?? ?? ?? ?? 8b 45 f0 }
    $sequence_9 = { 83 c0 04 89 44 24 18 e9 ?? ?? ?? ?? bf 0a 00 00 00 e9 ?? ?? ?? ?? bf 10 00 00 00 e9 ?? ?? ?? ?? }

  condition:
    7 of them and filesize < 229376
}

rule MALPEDIA_Elf_Satori_Auto: FILE {
  meta:
    description        = "autogenerated rule brought to you by yara-signator"
    author             = "Felix Bilstein - yara-signator at cocacoding dot com"
    id                 = "ef9a3def-11bf-57c1-9abe-eaf3ea87bbf4"
    date               = "2023-12-06"
    modified           = "2023-12-08"
    reference          = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.satori"
    source_url         = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/elf.satori_auto.yar#L1-L128"
    license_url        = "N/A"
    logic_hash         = "acc91f43f84cb8d9ebcbacb4d453867e5ba0d238d6255f05df970cd0ecb540bb"
    score              = 75
    quality            = 75
    tags               = "FILE"
    version            = "1"
    tool               = "yara-signator v0.6.0"
    signator_config    = "callsandjumps;datarefs;binvalue"
    malpedia_rule_date = "20231130"
    malpedia_hash      = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
    malpedia_version   = "20230808"
    malpedia_license   = "CC BY-SA 4.0"
    malpedia_sharing   = "TLP:WHITE"

  strings:
    $sequence_0 = { 85 c0 78 04 8b 54 24 14 89 d0 83 c4 1c }
    $sequence_1 = { e8 ?? ?? ?? ?? b9 ?? ?? ?? ?? b8 02 00 00 00 89 ca e8 ?? ?? ?? ?? }
    $sequence_2 = { 89 c6 53 89 d3 83 ec 10 52 e8 ?? ?? ?? ?? }
    $sequence_3 = { b8 02 00 00 00 e8 ?? ?? ?? ?? b9 05 00 00 00 ba ?? ?? ?? ?? b8 02 00 00 00 e8 ?? ?? ?? ?? b9 08 00 00 00 }
    $sequence_4 = { c7 44 24 48 00 00 00 00 e9 ?? ?? ?? ?? 8b 54 24 04 8b 34 82 6b c0 18 03 44 24 64 }
    $sequence_5 = { e8 ?? ?? ?? ?? 83 c4 14 6a 1f e8 ?? ?? ?? ?? c7 04 24 20 00 00 00 e8 ?? ?? ?? ?? c7 85 28 04 00 00 1e 00 00 00 }
    $sequence_6 = { 85 c0 74 16 83 ec 0c ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 59 6a 00 }
    $sequence_7 = { 3b 41 0c 74 7c 8b 45 bc 83 ec 0c 8b 55 cc 8d 5d ef 89 45 e0 }
    $sequence_8 = { 6a 04 56 53 e8 ?? ?? ?? ?? 88 44 24 3a 83 c4 20 6a 00 }
    $sequence_9 = { 6a 15 68 ?? ?? ?? ?? 6a 1d e8 ?? ?? ?? ?? 83 c4 0c 6a 15 68 ?? ?? ?? ?? }

  condition:
    7 of them and filesize < 122880
}

rule MALPEDIA_Elf_Gobrat_Auto: FILE {
  meta:
    description        = "autogenerated rule brought to you by yara-signator"
    author             = "Felix Bilstein - yara-signator at cocacoding dot com"
    id                 = "4556c50c-642d-5e08-a37f-0bca17aca318"
    date               = "2023-12-06"
    modified           = "2023-12-08"
    reference          = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.gobrat"
    source_url         = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/elf.gobrat_auto.yar#L1-L134"
    license_url        = "N/A"
    logic_hash         = "d983e645d32d0df64baf254a8f8a69a3323d191b1dd7ae64a36bbf4746335d3e"
    score              = 60
    quality            = 35
    tags               = "FILE"
    version            = "1"
    tool               = "yara-signator v0.6.0"
    signator_config    = "callsandjumps;datarefs;binvalue"
    malpedia_rule_date = "20231130"
    malpedia_hash      = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
    malpedia_version   = "20230808"
    malpedia_license   = "CC BY-SA 4.0"
    malpedia_sharing   = "TLP:WHITE"

  strings:
    $sequence_0 = { e8 ?? ?? ?? ?? 48 83 38 00 0f 8f 28 02 00 00 48 8b 94 24 28 01 00 00 48 85 d2 75 08 e8 ?? ?? ?? ?? }
    $sequence_1 = { 84 c0 74 5c 48 8b 54 24 30 48 8b 5a 30 48 8b 74 24 28 48 8b 46 30 48 8b 4e 38 }
    $sequence_2 = { c6 44 24 29 03 48 8d 05 5a ca 32 00 48 8d 5c 24 18 e8 ?? ?? ?? ?? 48 89 c3 48 8d 05 46 ca 32 00 e8 ?? ?? ?? ?? }
    $sequence_3 = { eb 41 48 8d 05 9c 31 1e 00 e8 ?? ?? ?? ?? 48 c7 40 08 1c 00 00 00 48 8d 0d 39 a6 23 00 48 89 08 31 db }
    $sequence_4 = { e8 ?? ?? ?? ?? 48 8b 94 24 60 02 00 00 48 8b 72 18 48 89 70 20 48 83 7a 70 00 75 42 48 8d 1d f7 fc 32 00 }
    $sequence_5 = { c3 31 c0 48 8b 6c 24 78 48 83 ec 80 c3 48 8b 8c 24 88 00 00 00 48 8b 41 10 }
    $sequence_6 = { f7 da 41 0f af d1 89 d2 48 0f af d3 48 c1 ea 2f 44 89 c6 41 c1 e0 08 }
    $sequence_7 = { ff d2 b9 1a 00 00 00 48 89 c7 48 89 de 31 c0 48 8d 1d d7 ce 2d 00 e8 ?? ?? ?? ?? }
    $sequence_8 = { b8 25 01 00 00 e8 ?? ?? ?? ?? 48 85 c9 74 5d 48 83 f9 02 77 12 75 3c }
    $sequence_9 = { e8 ?? ?? ?? ?? 48 c7 40 08 22 00 00 00 48 8d 0d e4 21 22 00 48 89 08 31 db 48 89 d9 48 8d 3d 24 4d 2a 00 }

  condition:
    7 of them and filesize < 12853248
}

rule MALPEDIA_Elf_Hideandseek_Auto: FILE {
  meta:
    description        = "autogenerated rule brought to you by yara-signator"
    author             = "Felix Bilstein - yara-signator at cocacoding dot com"
    id                 = "8886e955-536d-56f5-a630-bf2b9ef8b07e"
    date               = "2023-12-06"
    modified           = "2023-12-08"
    reference          = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.hideandseek"
    source_url         = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/elf.hideandseek_auto.yar#L1-L133"
    license_url        = "N/A"
    logic_hash         = "c312d2a4b534a00f51e15be6e1572c868a1bf84ffb4d93cf13ce0449e347f5bb"
    score              = 75
    quality            = 75
    tags               = "FILE"
    version            = "1"
    tool               = "yara-signator v0.6.0"
    signator_config    = "callsandjumps;datarefs;binvalue"
    malpedia_rule_date = "20231130"
    malpedia_hash      = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
    malpedia_version   = "20230808"
    malpedia_license   = "CC BY-SA 4.0"
    malpedia_sharing   = "TLP:WHITE"

  strings:
    $sequence_0 = { 53 83 ec 14 8b 44 24 2c 8a 5c 24 30 ff 70 04 ff 74 24 2c e8 ?? ?? ?? ?? }
    $sequence_1 = { e8 ?? ?? ?? ?? 83 c4 10 84 c0 75 2e 83 ec 0c 8d 84 24 1c 12 00 00 50 }
    $sequence_2 = { 8d 44 24 4c 50 e8 ?? ?? ?? ?? 5b 8d 44 24 40 50 e8 ?? ?? ?? ?? }
    $sequence_3 = { 89 ca 8b 04 24 0f a4 d9 1e 31 c8 8b 4c 24 30 0f a4 d3 1e 8b 54 24 04 }
    $sequence_4 = { 74 11 0f 82 1e 04 00 00 83 f8 02 0f 85 08 04 00 00 eb 04 50 50 }
    $sequence_5 = { be 00 00 00 00 b8 00 00 00 00 c1 e2 10 09 c6 c1 e7 18 31 db 0f b6 45 04 }
    $sequence_6 = { 50 e8 ?? ?? ?? ?? 83 c4 10 84 c0 74 1a 8b 54 24 14 c7 43 44 03 00 00 00 }
    $sequence_7 = { 81 7e 0c 00 01 00 00 75 1a 8d 56 10 8d 46 50 53 68 c0 00 00 00 50 }
    $sequence_8 = { 56 53 8b 7c 24 10 80 3d ?? ?? ?? ?? 00 75 61 83 ec 0c 68 00 00 00 11 }
    $sequence_9 = { 50 8b 84 24 ec 00 00 00 ff 70 08 e8 ?? ?? ?? ?? 89 f2 8b 84 24 f0 00 00 00 }

  condition:
    7 of them and filesize < 196608
}

rule MALPEDIA_Elf_Babuk_Auto: FILE {
  meta:
    description        = "autogenerated rule brought to you by yara-signator"
    author             = "Felix Bilstein - yara-signator at cocacoding dot com"
    id                 = "0f03a128-b2bf-587f-bb2c-939b9b8a07cd"
    date               = "2023-12-06"
    modified           = "2023-12-08"
    reference          = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.babuk"
    source_url         = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/elf.babuk_auto.yar#L1-L133"
    license_url        = "N/A"
    logic_hash         = "1ffac28a8690c44fcc8b3792df7481d8deebcbe27a55524336d71b5e562fe261"
    score              = 75
    quality            = 75
    tags               = "FILE"
    version            = "1"
    tool               = "yara-signator v0.6.0"
    signator_config    = "callsandjumps;datarefs;binvalue"
    malpedia_rule_date = "20231130"
    malpedia_hash      = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
    malpedia_version   = "20230808"
    malpedia_license   = "CC BY-SA 4.0"
    malpedia_sharing   = "TLP:WHITE"

  strings:
    $sequence_0 = { f7 e2 89 94 24 88 02 00 00 89 84 24 a4 00 00 00 89 e8 f7 e1 89 94 24 84 02 00 00 89 84 24 a0 00 00 00 }
    $sequence_1 = { 89 5c 24 04 e8 ?? ?? ?? ?? eb a0 0f b6 c1 3d 88 00 00 00 0f 83 74 02 00 00 c1 e0 07 }
    $sequence_2 = { e8 ?? ?? ?? ?? 31 c0 eb 08 89 8c 84 90 00 00 00 40 83 f8 06 7d 5a }
    $sequence_3 = { 8b 9c 24 90 00 00 00 8d 2c 18 8d 4c 03 14 8b 94 24 00 01 00 00 8b 84 24 fc 00 00 00 8b 9c 24 f8 00 00 00 39 c1 }
    $sequence_4 = { e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 44 24 58 8b 40 18 c6 80 b5 00 00 00 02 8b 44 24 7c 8b 4c 24 78 }
    $sequence_5 = { e8 ?? ?? ?? ?? 0f b6 44 24 0c 84 c0 75 39 90 65 8b 05 00 00 00 00 8b 80 fc ff ff ff }
    $sequence_6 = { 8b 49 2c 8b 5c 24 14 01 d3 89 59 04 8b 48 18 8b 49 2c }
    $sequence_7 = { e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 65 8b 05 00 00 00 00 8b 80 fc ff ff ff 8b 40 18 8b 0c 24 89 48 24 }
    $sequence_8 = { c1 fd 1f 21 dd 8d 3c 2e 89 bc 24 f8 00 00 00 8b 6c 24 50 e9 ?? ?? ?? ?? 39 f5 }
    $sequence_9 = { 89 44 24 08 e8 ?? ?? ?? ?? 8b 44 24 0c 8b 4c 24 10 89 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? }

  condition:
    7 of them and filesize < 4186112
}

rule TRELLIX_ARC_MALW_Fritzfrog: BOTNET FILE {
  meta:
    description    = "Rule to detect Fritzfrog"
    author         = "Marc Rivero | McAfee ATR Team"
    id             = "4c553279-7e0c-5602-944d-ad8a47edf4ea"
    date           = "2020-08-20"
    modified       = "2020-08-20"
    reference      = "https://github.com/advanced-threat-research/Yara-Rules/"
    source_url     = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_fritzfrog.yar#L1-L26"
    license_url    = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
    logic_hash     = "488c807ecf0a9e981b2c1f2f5bb2e3072952d11f7cbf3a354bc85dc8e88b8b09"
    score          = 75
    quality        = 70
    tags           = "BOTNET, FILE"
    rule_version   = "v1"
    malware_type   = "botnet"
    malware_family = "Botnet:W32/Fritzfrog"
    actor_type     = "Cybercrime"
    hash1          = "103b8404dc64c9a44511675981a09fd01395ee837452d114f1350c295357c046"
    actor_type     = "Cybercrime"
    actor_group    = "Unknown"

  strings:
    $pattern = { 7F 45 4C 46 02 01 01 00 00 00 00 00 00 00 00 00 02 00 3E 00 01 00 00 00 90 D3 45 00 00 00 00 00 40 00 00 00 00 00 00 00 C8 01 00 00 00 00 00 00 00 00 00 00 40 00 38 00 07 00 40 00 0D 00 03 00 06 00 00 00 04 00 00 00 40 00 00 00 00 00 00 00 40 00 40 00 00 00 00 00 40 00 40 00 00 00 00 00 88 01 00 00 00 00 00 00 88 01 00 00 00 00 00 00 00 10 00 00 00 00 00 00 04 00 00 00 04 00 00 00 9C 0F 00 00 00 00 00 00 9C 0F 40 00 00 00 00 00 9C 0F 40 00 00 00 00 00 64 00 00 00 00 00 00 00 64 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 01 00 00 00 05 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 40 00 00 00 00 00 83 F2 3E 00 00 00 00 00 83 F2 3E 00 00 00 00 00 00 10 00 00 00 00 00 00 01 00 00 00 04 00 00 00 00 00 3F 00 00 00 00 00 00 00 7F 00 00 00 00 00 00 00 7F 00 00 00 00 00 6C 83 45 00 00 00 00 00 6C 83 45 00 00 00 00 00 00 10 00 00 00 00 00 00 01 00 00 00 06 00 00 00 00 90 84 00 00 00 00 00 00 90 C4 00 00 00 00 00 00 90 C4 00 00 00 00 00 60 EC 04 00 00 00 00 00 58 09 07 00 00 00 00 00 00 10 00 00 00 00 00 00 51 E5 74 64 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00 80 15 04 65 00 2A 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 01 00 00 00 06 00 00 00 00 00 00 00 00 10 40 00 00 00 00 00 00 10 00 00 00 00 00 00 83 E2 3E 00 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 00 00 00 01 00 00 00 02 00 00 00 00 00 00 00 00 00 7F 00 00 00 00 00 00 00 3F 00 00 00 00 00 C0 27 1B 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 72 00 00 00 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 C0 27 5A 00 00 00 00 00 7C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 49 00 00 00 01 00 00 00 02 00 00 00 00 00 00 00 40 28 9A 00 00 00 00 00 40 28 5A 00 00 00 00 00 D8 36 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 53 00 00 00 01 00 00 00 02 00 00 00 00 00 00 00 18 5F 9A 00 00 00 00 00 18 5F 5A 00 00 00 00 00 38 0D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 5D 00 00 00 01 00 00 00 02 00 00 00 00 00 00 00 50 6C 9A 00 00 00 00 00 50 6C 5A 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 67 00 00 00 01 00 00 00 02 00 00 00 00 00 00 00 60 6C 9A 00 00 00 00 00 60 6C 5A 00 00 00 00 00 0C 17 2A 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 07 00 00 00 01 00 00 00 03 00 00 00 00 00 00 00 00 90 C4 00 00 00 00 00 00 90 84 00 00 00 00 00 00 4B 03 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 12 00 00 00 01 00 00 00 03 00 00 00 00 00 00 00 00 DB C7 00 00 00 00 00 00 DB 87 00 00 00 00 00 50 A1 01 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 18 00 00 00 08 00 00 00 03 00 00 00 00 00 00 00 60 7C C9 00 00 00 00 00 60 7C 89 00 00 00 00 00 D0 E8 01 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1D 00 00 00 08 00 00 00 03 00 00 00 00 00 00 00 40 65 CB 00 00 00 00 00 40 65 8B 00 00 00 00 00 18 34 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 27 00 00 00 07 00 00 00 02 00 00 00 00 00 00 00 9C 0F 40 00 00 00 00 00 9C 0F 00 00 00 00 00 00 64 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    uint16(0) == 0x457f and filesize < 26000KB and all of them
}

rule TRELLIX_ARC_MALW_Liquorbot: MALWARE FILE {
  meta:
    description    = "Rule to detect LiquorBot malware"
    author         = "Marc Rivero | McAfee ATR Team"
    id             = "73898df8-b5eb-50ac-a2fe-ef9233c251c5"
    date           = "2020-08-19"
    modified       = "2020-08-19"
    reference      = "https://github.com/advanced-threat-research/Yara-Rules/"
    source_url     = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_liquorbot.yar#L1-L23"
    license_url    = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
    logic_hash     = "2448e3ede809331b2370fe9d42d603ad6508be6531a1a8764e0e0621867b6e89"
    score          = 75
    quality        = 70
    tags           = "MALWARE, FILE"
    rule_version   = "v1"
    malware_type   = "malware"
    malware_family = "Botnet:W32/LiquorBot"
    actor_type     = "Cybercrime"
    actor_group    = "Unknown"
    hash1          = "5b2a9cbda99ed903f75c3b37f0a6b1b9f6c39671a76ed652f3ddba117fd43bc9"

  strings:
    $pattern = { 7F 45 4C 46 02 01 01 00 00 00 00 00 00 00 00 00 02 00 3E 00 01 00 00 00 60 5A 46 00 00 00 00 00 40 00 00 00 00 00 00 00 70 02 00 00 00 00 00 00 00 00 00 00 40 00 38 00 0A 00 40 00 1B 00 09 00 06 00 00 00 04 00 00 00 40 00 00 00 00 00 00 00 40 00 40 00 00 00 00 00 40 00 40 00 00 00 00 00 30 02 00 00 00 00 00 00 30 02 00 00 00 00 00 00 00 10 00 00 00 00 00 00 03 00 00 00 04 00 00 00 E0 0F 00 00 00 00 00 00 E0 0F 40 00 00 00 00 00 E0 0F 40 00 00 00 00 00 20 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 04 00 00 00 04 00 00 00 7C 0F 00 00 00 00 00 00 7C 0F 40 00 00 00 00 00 7C 0F 40 00 00 00 00 00 64 00 00 00 00 00 00 00 64 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 01 00 00 00 05 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 40 00 00 00 00 00 40 FB 29 00 00 00 00 00 40 FB 29 00 00 00 00 00 00 10 00 00 00 00 00 00 01 00 00 00 04 00 00 00 00 00 2A 00 00 00 00 00 00 00 6A 00 00 00 00 00 00 00 6A 00 00 00 00 00 E4 49 2C 00 00 00 00 00 E4 49 2C 00 00 00 00 00 00 10 00 00 00 00 00 00 01 00 00 00 06 00 00 00 00 50 56 00 00 00 00 00 00 50 96 00 00 00 00 00 00 50 96 00 00 00 00 00 E0 14 04 00 00 00 00 00 68 13 07 00 00 00 00 00 00 10 00 00 00 00 00 00 02 00 00 00 06 00 00 00 40 51 56 00 00 00 00 00 40 51 96 00 00 00 00 00 40 51 96 00 00 00 00 00 30 01 00 00 00 00 00 00 30 01 00 00 00 00 00 00 08 00 00 00 00 00 00 00 07 00 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00 51 E5 74 64 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00 80 15 04 65 00 2A 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 01 00 00 00 06 00 00 00 00 00 00 00 00 10 40 00 00 00 00 00 00 10 00 00 00 00 00 00 1F E9 29 00 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 F0 00 00 00 01 00 00 00 06 00 00 00 00 00 00 00 20 F9 69 00 00 00 00 00 20 F9 29 00 00 00 00 00 20 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 00 10 00 00 00 00 00 00 00 70 00 00 00 01 00 00 00 02 00 00 00 00 00 00 00 00 00 6A 00 00 00 00 00 00 00 2A 00 00 00 00 00 A6 78 11 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 00 00 04 00 00 00 02 00 00 00 00 00 00 00 A8 78 7B 00 00 00 00 00 A8 78 3B 00 00 00 00 00 18 00 00 00 00 00 00 00 0B 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00 18 00 00 00 00 00 00 00 E6 00 00 00 04 00 00 00 02 00 00 00 00 00 00 00 C0 78 7B 00 00 00 00 00 C0 78 3B 00 00 00 00 00 18 03 00 00 00 00 00 00 0B 00 00 00 02 00 00 00 08 00 00 00 00 00 00 00 18 00 00 00 00 00 00 00 F5 00 00 00 FF }

  condition:
    uint16(0) == 0x457f and all of them
}

rule TRELLIX_ARC_Ransom_Linux_Hellokitty_0721: RANSOMWARE FILE {
  meta:
    description    = "rule to detect Linux variant of the Hello Kitty Ransomware"
    author         = "Christiaan @ ATR"
    id             = "097b02e7-93d8-5d4f-9964-7b660b3cd7b9"
    date           = "2021-07-19"
    modified       = "2021-07-19"
    reference      = "https://github.com/advanced-threat-research/Yara-Rules/"
    source_url     = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_Linux_HelloKitty0721.yar#L1-L28"
    license_url    = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
    logic_hash     = "77a3809df4c7c591a855aaecd702af62935952937bb81661aa7f68e64dcf4fb4"
    score          = 75
    quality        = 70
    tags           = "RANSOMWARE, FILE"
    Rule_Version   = "v1"
    malware_type   = "ransomware"
    malware_family = "Ransom:Linux/HelloKitty"
    hash1          = "ca607e431062ee49a21d69d722750e5edbd8ffabcb54fa92b231814101756041"
    hash2          = "556e5cb5e4e77678110961c8d9260a726a363e00bf8d278e5302cb4bfccc3eed"

  strings:
    $v1  = "esxcli vm process kill -t=force -w=%d" fullword ascii
    $v2  = "esxcli vm process kill -t=hard -w=%d" fullword ascii
    $v3  = "esxcli vm process kill -t=soft -w=%d" fullword ascii
    $v4  = "error encrypt: %s rename back:%s" fullword ascii
    $v5  = "esxcli vm process list" fullword ascii
    $v6  = "Total VM run on host:" fullword ascii
    $v7  = "error lock_exclusively:%s owner pid:%d" fullword ascii
    $v8  = "Error open %s in try_lock_exclusively" fullword ascii
    $v9  = "Mode:%d  Verbose:%d Daemon:%d AESNI:%d RDRAND:%d " fullword ascii
    $v10 = "pthread_cond_signal() error" fullword ascii
    $v11 = "ChaCha20 for x86_64, CRYPTOGAMS by <appro@openssl.org>" fullword ascii

  condition:
    (uint16(0) == 0x457f and filesize < 200KB and (8 of them)) or (all of them)
}

rule ARKBIRD_SOLG_Ran_ELF_EXX_Nov_2020_1: FILE {
  meta:
    description = "Detect EXX variant ELF ransomware"
    author      = "Arkbird_SOLG"
    id          = "fe85d480-317a-51c3-a817-fc9034e2944f"
    date        = "2020-12-09"
    modified    = "2020-12-09"
    reference   = "Internal Research"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-12-09/EXX/Ran_ELF_EXX_Nov_2020_1.yar#L1-L28"
    license_url = "N/A"
    logic_hash  = "4508a0cf79d0d85959009f59e1471cbf123fa24f5c21da5801e91ed0bbe8a085"
    score       = 50
    quality     = 73
    tags        = "FILE"
    level       = "experimental"
    hash1       = "cb408d45762a628872fa782109e8fcfc3a5bf456074b007de21e9331bb3c5849"

  strings:
    $dbg1 = "Unexpected error, return code = %08X\n"
    $dbg2 = { 47 72 65 65 74 69 6e 67 73 20 [3-10] 21 }
    $dbg3 = "cycles=%lu ratio=%lu millisecs=%lu secs=%lu hardfail=%d a=%lu b=%lu\n"
    $dbg4 = "SHA-%d test #%d:"
    $lib1 = "pthread_mutex_unlock@@GLIBC_2.2.5" fullword ascii
    $lib2 = "pthread_mutex_lock@@GLIBC_2.2.5" fullword ascii
    $lib3 = "mbedtls_rsa_import" fullword ascii
    $lib4 = "mbedtls_rsa_export" fullword ascii
    $lib5 = "mbedtls_oid_get_extended_key_usage" fullword ascii
    $lib6 = "mbedtls_sha256_process" fullword ascii
    $seq1 = { 48 83 ec 20 89 7d ec 48 89 75 e0 b8 00 00 00 00 e8 77 00 00 00 48 8d 45 f0 b9 00 00 00 00 48 8d 15 b5 ff ff ff be 00 00 00 00 48 89 c7 e8 d6 fb ff ff c7 45 fc 01 00 00 00 eb }
    $seq2 = { 00 00 00 00 e8 b2 fe ff ff 48 8b 45 e8 48 89 c7 e8 92 ed ff ff 48 83 c0 01 48 89 c7 e8 c6 ee ff ff 48 89 45 f8 48 83 7d f8 00 74 3a 48 8b 55 e8 48 8b 45 f8 48 89 d6 48 89 c7 e8 f8 ec ff ff 48 8b 45 f8 48 89 c7 e8 12 fd ff ff 48 8b 45 f8 48 89 c7 e8 90 ec ff ff b8 00 00 00 00 e8 95 fc ff ff }
    $seq3 = { e5 41 55 41 54 53 48 81 ec 18 18 00 00 c7 45 dc 00 00 00 00 48 c7 45 d0 00 00 00 00 bf 00 00 00 00 e8 13 fd ff ff 89 c7 e8 7c fc ff ff e8 d7 fd ff ff 41 89 c5 e8 cf fd ff ff 41 89 c4 e8 c7 fd ff ff 89 c3 e8 c0 fd ff ff 89 c2 48 8d 85 d0 e7 ff ff 4d 89 e9 4d 89 e0 48 89 d9 48 8d 35 bf 0a 02 00 48 89 }

  condition:
    uint16(0) == 0x457f and filesize > 80KB and 3 of ($dbg*) and 4 of ($lib*) and 2 of ($seq*)
}

rule TELEKOM_SECURITY_Android_Teabot: FILE {
  meta:
    description = "matches on dumped, decrypted V/DEX files of Teabot"
    author      = "Thomas Barabosch, Telekom Security"
    id          = "9db701bf-be84-5236-97f7-67043cf3ea93"
    date        = "2021-09-14"
    modified    = "2021-09-14"
    reference   = "https://github.com/telekom-security/malware_analysis/"
    source_url  = "https://github.com/telekom-security/malware_analysis//blob/bf832d97e8fd292ec5e095e35bde992a6462e71c/flubot/teabot.yar#L1-L23"
    license_url = "N/A"
    hash        = "37be18494cd03ea70a1fdd6270cef6e3"
    logic_hash  = "5aa7fdb191c36510c7698f3eae40c0b7f15c944b8f60113bbb4e40fc926579b8"
    score       = 75
    quality     = 45
    tags        = "FILE"
    version     = "20210819"

  strings:
    $dex  = "dex"
    $vdex = "vdex"
    $s1   = "ERR 404: Unsupported device"
    $s2   = "Opening inject"
    $s3   = "Prevented samsung power off"
    $s4   = "com.huawei.appmarket"
    $s5   = "kill_bot"
    $s6   = "kloger:"
    $s7   = "logged_sms"
    $s8   = "xiaomi_autostart"

  condition:
    ($dex at 0 or $vdex at 0) and 6 of ($s*)
}

rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Ransomwareexx {
  meta:
    description = "Detects files referencing identities associated with RansomwareEXX Linux ransomware"
    author      = "ditekShen"
    id          = "dfcff8cb-c50c-559e-b5b9-8c2cdac7a3dc"
    date        = "2024-01-23"
    modified    = "2024-01-23"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_knownbad_id.yar#L142-L150"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "a83ada5d29c6d62a292c4b3a1379558cddcaf63d97dbdfc6afd27cc52f6f656d"
    score       = 75
    quality     = 73
    tags        = ""

  strings:
    $s1 = "france.eigs@protonmail.com" ascii wide nocase

  condition:
    any of them
}

rule DITEKSHEN_MALWARE_Linux_Chachaddos: FILE {
  meta:
    description = "ChaChaDDoS variant of XorDDoS payload"
    author      = "ditekSHen"
    id          = "78a5cf3a-0e84-59bd-a936-bd335647e3d0"
    date        = "2024-05-28"
    modified    = "2024-05-28"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/malware.yar#L403-L418"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "2bf99771046650820f02a24d5bd825afeacd03d1e865b05d8563a3ef74d521fb"
    score       = 75
    quality     = 75
    tags        = "FILE"

  strings:
    $x1 = "[kworker/1:1]" ascii
    $x2 = "-- LuaSocket toolkit." ascii
    $x3 = "/etc/resolv.conf" ascii
    $x4 = "\"macaddress=\" .. DEVICE_MAC .. \"&device=\" .." ascii
    $x5 = "easy_attack_dns" ascii
    $x6 = "easy_attack_udp" ascii
    $x7 = "easy_attack_syn" ascii
    $x8 = "syn_probe" ascii

  condition:
    uint16(0) == 0x457f and 6 of them
}

rule DITEKSHEN_MALWARE_Linux_Ransomexx: FILE {
  meta:
    description = "Detects RansomEXX ransomware"
    author      = "ditekshen"
    id          = "b449afc7-9055-55ed-a876-316d1aea8fee"
    date        = "2024-05-28"
    modified    = "2024-05-28"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/malware.yar#L3834-L3858"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "c233ccc3e741cb2c53f182c48093e41595a82a3f4e5bdb1dc0204f1f57b96c2a"
    score       = 75
    quality     = 75
    tags        = "FILE"
    clamav_sig  = "MALWARE.Linux.Ransomware.RansomEXX"

  strings:
    $c1 = "crtstuff.c" fullword ascii
    $c2 = "cryptor.c" fullword ascii
    $c3 = "ransomware.c" fullword ascii
    $c4 = "logic.c" fullword ascii
    $c5 = "enum_files.c" fullword ascii
    $c6 = "readme.c" fullword ascii
    $c7 = "ctr_drbg.c" fullword ascii
    $s1 = "regenerate_pre_data" fullword ascii
    $s2 = "g_RansomHeader" fullword ascii
    $s3 = "CryptOneBlock" fullword ascii
    $s4 = "RansomLogic" fullword ascii
    $s5 = "CryptOneFile" fullword ascii
    $s6 = "encrypt_worker" fullword ascii
    $s7 = "list_dir" fullword ascii
    $s8 = "ctr_drbg_update_internal" fullword ascii

  condition:
    uint16(0) == 0x457f and (5 of ($c*) or 6 of ($s*) or (3 of ($c*) and 3 of ($s*)))
}

rule DITEKSHEN_MALWARE_Linux_Buhti: FILE {
  meta:
    description = "Detects Buhti Ransomware"
    author      = "ditekSHen"
    id          = "a50b8c34-e9e2-5466-80a1-b0ab805c68be"
    date        = "2024-05-28"
    modified    = "2024-05-28"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/malware.yar#L9648-L9661"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "1bab3202dbeaf088b233c3ab1056c357d156b7eef3111bea997b1c610a27f561"
    score       = 75
    quality     = 75
    tags        = "FILE"

  strings:
    $x1 = "buhtiRansom" ascii
    $x2 = "://satoshidisk.com/pay/" ascii
    $s1 = "main.encrypt_file" fullword ascii
    $s2 = "/path/to/be/encrypted" ascii
    $s3 = "Restore-My-Files.txt" ascii
    $s4 = ".buhti390625" ascii

  condition:
    uint16(0) == 0x457f and (all of ($x*) or (1 of ($x*) and 3 of ($s*)) or 5 of them)
}

rule DITEKSHEN_MALWARE_Linux_Gobrat: FILE {
  meta:
    description = "Detects GobRAT"
    author      = "ditekSHen"
    id          = "0561fa99-24ee-5e02-ba54-17a1dd81daa4"
    date        = "2024-05-28"
    modified    = "2024-05-28"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/malware.yar#L10062-L10080"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "070687c909b066e38f72b6421b77670e87476d7e1eb1ed8d41d027836629eb71"
    score       = 75
    quality     = 75
    tags        = "FILE"

  strings:
    $x1 = "BotList" ascii
    $x2 = "BotCount" ascii
    $x3 = "/etc/services/zone/bot.log" ascii
    $x4 = "aaa.com/bbb/me" ascii
    $s1 = "encoding/gob." ascii
    $s2 = ".GetMacAddress" ascii
    $s3 = ".IpString2Uint32" ascii
    $s4 = ".RegisterLogFile" ascii
    $s5 = ".UniqueAppendString" ascii
    $s6 = ".NewDaemon" ascii
    $s7 = ".SimpleCommand" ascii

  condition:
    uint16(0) == 0x457f and (3 of ($x*) or (2 of ($x*) and 3 of ($s*)) or (1 of ($x*) and 5 of ($s*)) or all of ($s*))
}

rule DITEKSHEN_MALWARE_Linux_Akira: FILE {
  meta:
    description = "Detects Akira Ransomware Linux"
    author      = "ditekSHen"
    id          = "3ac144b3-c747-58e5-bc75-b3f90786f404"
    date        = "2024-05-28"
    modified    = "2024-05-28"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/malware.yar#L10263-L10282"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "3a00154e1cfc442718e753641d3706ffd4dd8465525d0bb2854f74dfb1cf5dd0"
    score       = 75
    quality     = 75
    tags        = "FILE"

  strings:
    $x1 = "https://akira" ascii
    $x2 = ":\\akira\\" ascii
    $x3 = ".akira" ascii
    $x4 = "akira_readme.txt" ascii
    $s1 = "--encryption_" ascii
    $s2 = "--share_file" ascii
    $s3 = { 00 24 52 65 63 79 63 6c 65 2e 42 69 6e 00 24 52 45 43 59 43 4c 45 2e 42 49 4e 00 }
    $s4 = " PUBLIC KEY-----" ascii
    $s5 = ".onion" ascii
    $s6 = "/Esxi_Build_Esxi6/./" ascii nocase
    $s7 = "No path to encrypt" ascii
    $s8 = "-fork" fullword ascii

  condition:
    uint16(0) == 0x457f and (3 of ($x*) or (1 of ($x*) and 4 of ($s*)) or 6 of ($s*))
}

rule HARFANGLAB_Samecoin_Campaign_Nativewiper: FILE {
  meta:
    description = "Matches the native Android library used in the SameCoin campaign"
    author      = "HarfangLab"
    id          = "9c77c26e-50f7-5ee4-bc6b-c0333e268b2c"
    date        = "2024-02-13"
    modified    = "2024-04-05"
    reference   = "TRR240201"
    source_url  = "https://github.com/HarfangLab/iocs/blob/f679751df7994790f9f79629d60b3f2623148255/TRR240201/trr240201_yara.yar#L82-L102"
    license_url = "N/A"
    hash        = "248054658277e6971eb0b29e2f44d7c3c8d7c5abc7eafd16a3df6c4ca555e817"
    logic_hash  = "2779664830df3b5be72b7fe7d4da3d27e2a86b289ee3974596abf1df12317cd8"
    score       = 75
    quality     = 80
    tags        = "FILE"
    context     = "file"

  strings:
    $native_export = "Java_com_example_exampleone_MainActivity_deleteInCHunks" ascii
    $f1            = "_Z9chunkMainv" ascii
    $f2            = "_Z18deleteFilesInChunkRKNSt6__" ascii
    $f3            = "_Z18overwriteWithZerosPKc" ascii
    $s1            = "/storage/emulated/0/" ascii
    $s2            = "FileLister" ascii
    $s3            = "Directory chunks deleted."
    $s4            = "Current Chunk Size is:  %dl\n" ascii

  condition:
    filesize < 500KB and uint32(0) == 0x464C457F and ($native_export or all of ($f*) or all of ($s*))
}

rule SIGNATURE_BASE_APT_MAL_LNX_Hunting_Linux_WHIRLPOOL_1: FILE {
  meta:
    description = "Hunting rule looking for strings observed in WHIRLPOOL samples."
    author      = "Mandiant"
    id          = "a997bd65-c502-53a0-8bb8-62daaa916f0d"
    date        = "2023-06-15"
    modified    = "2023-12-05"
    reference   = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_barracuda_esg_unc4841_jun23.yar#L154-L173"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    hash        = "177add288b289d43236d2dba33e65956"
    logic_hash  = "d03c0e292b9b97bbf76585fc74208e4263d753807b8e4a445be80d41264d5432"
    score       = 70
    quality     = 85
    tags        = "FILE"

  strings:
    $s1 = "error -1 exit" fullword
    $s2 = "create socket error: %s(error: %d)\n" fullword
    $s3 = "connect error: %s(error: %d)\n" fullword
    $s4 = { C7 00 20 32 3E 26 66 C7 40 04 31 00 }
    $c1 = "plain_connect" fullword
    $c2 = "ssl_connect" fullword
    $c3 = "SSLShell.c" fullword

  condition:
    uint32(0) == 0x464c457f and filesize < 15MB and (all of ($s*) or all of ($c*))
}

rule SIGNATURE_BASE_APT_LNX_Academic_Camp_May20_Eraser_1: FILE {
  meta:
    description = "Detects malware used in attack on academic data centers"
    author      = "Florian Roth (Nextron Systems)"
    id          = "36d17887-9844-5fa4-8a0d-89cc41b2d876"
    date        = "2020-05-16"
    modified    = "2023-12-05"
    reference   = "https://csirt.egi.eu/academic-data-centers-abused-for-crypto-currency-mining/"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_academic_data_centers_camp_may20.yar#L1-L18"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "9a0410e86fa8fb8b599e5b8a6508d6889eb6e26600f0ecf222561ac4a169676d"
    score       = 75
    quality     = 85
    tags        = "FILE"
    hash1       = "552245645cc49087dfbc827d069fa678626b946f4b71cb35fa4a49becd971363"

  strings:
    $sc2 = {
      E6 FF FF 48 89 45 D0 8B 45 E0 BA 00 00 00 00 BE
      00 00 00 00 89 C7 E8
    }
    $sc3 = {
      E6 FF FF 89 45 DC 8B 45 DC 83 C0 01 48 98 BE 01
      00 00 00 48 89 C7 E8
    }

  condition:
    uint16(0) == 0x457f and filesize < 60KB and all of them
}

rule SIGNATURE_BASE_APT_LNX_Academic_Camp_May20_Loader_1: FILE {
  meta:
    description = "Detects malware used in attack on academic data centers"
    author      = "Florian Roth (Nextron Systems)"
    id          = "cda65abd-d918-5ee6-8f4a-554d47532d76"
    date        = "2020-05-16"
    modified    = "2023-12-05"
    reference   = "https://csirt.egi.eu/academic-data-centers-abused-for-crypto-currency-mining/"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_academic_data_centers_camp_may20.yar#L20-L35"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "a73883f9fdf3d53694d9f9efec5f8f15994c5fd80c5f2a87b1741db6b954a023"
    score       = 75
    quality     = 85
    tags        = "FILE"
    hash1       = "0efdd382872f0ff0866e5f68f0c66c01fcf4f9836a78ddaa5bbb349f20353897"

  strings:
    $sc1 = {
      C6 45 F1 00 C6 45 F2 0A C6 45 F3 0A C6 45 F4 4A
      C6 45 F5 04 C6 45 F6 06 C6 45 F7 1B C6 45 F8 01
    }
    $sc2 = { 01 48 39 EB 75 EA 48 83 C4 08 5B 5D 41 5C 41 5D }

  condition:
    uint16(0) == 0x457f and filesize < 10KB and all of them
}

rule SIGNATURE_BASE_CN_Honker_Linux_Bin: FILE {
  meta:
    description = "Script from disclosed CN Honker Pentest Toolset - file linux_bin"
    author      = "Florian Roth (Nextron Systems)"
    id          = "3c56a4a8-6392-517c-a16e-63785799acb9"
    date        = "2015-06-23"
    modified    = "2023-12-05"
    reference   = "Disclosed CN Honker Pentest Toolset"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/cn_pentestset_scripts.yar#L239-L254"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    hash        = "26e71e6ebc6a3bdda9467ce929610c94de8a7ca0"
    logic_hash  = "d02fcf23e46a0b6d44c382e34d73ef6239b6a1afc690e417aa0e6b0898e277c0"
    score       = 70
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

  strings:
    $s1 = "client.sin_port = htons(atoi(argv[3]));" fullword ascii
    $s2 = "printf(\"\\n\\n*********Waiting Client connect*****\\n\\n\");" fullword ascii

  condition:
    filesize < 20KB and all of them
}

rule SIGNATURE_BASE_APT_MAL_LNX_Turla_Apr202004_1: FILE {
  meta:
    description = "Detects Turla Linux malware x64 x32"
    author      = "Leonardo S.p.A."
    id          = "2da75433-b1c1-51b3-8f7a-a4442ca3de96"
    date        = "2020-04-24"
    modified    = "2023-12-05"
    reference   = "https://www.leonardocompany.com/en/news-and-stories-detail/-/detail/knowledge-the-basis-of-protection"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_turla_penquin.yar#L2-L33"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "1e07963c492f1e6264f01ee292e40b188ca325b76005d9d48e6dc198cb9bdcf4"
    score       = 75
    quality     = 85
    tags        = "FILE"
    hash1       = "67d9556c695ef6c51abf6fbab17acb3466e3149cf4d20cb64d6d34dc969b6502"
    hash2       = "8ccc081d4940c5d8aa6b782c16ed82528c0885bbb08210a8d0a8c519c54215bc"
    hash3       = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667"
    hash4       = "1d5e4466a6c5723cd30caf8b1c3d33d1a3d4c94c25e2ebe186c02b8b41daf905"
    hash5       = "2dabb2c5c04da560a6b56dbaa565d1eab8189d1fa4a85557a22157877065ea08"
    hash6       = "3e138e4e34c6eed3506efc7c805fce19af13bd62aeb35544f81f111e83b5d0d4"
    hash7       = "5a204263cac112318cd162f1c372437abf7f2092902b05e943e8784869629dd8"
    hash8       = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667"
    hash9       = "d49690ccb82ff9d42d3ee9d7da693fd7d302734562de088e9298413d56b86ed0"

  strings:
    $ = "/root/.hsperfdata" ascii fullword
    $ = "Desc| Filename | size |state|" ascii fullword
    $ = "VS filesystem: %s" ascii fullword
    $ = "File already exist on remote filesystem !" ascii fullword
    $ = "/tmp/.sync.pid" ascii fullword
    $ = "rem_fd: ssl " ascii fullword
    $ = "TREX_PID=%u" ascii fullword
    $ = "/tmp/.xdfg" ascii fullword
    $ = "__we_are_happy__" ascii
    $ = "/root/.sess" ascii fullword

  condition:
    uint16(0) == 0x457f and filesize < 5000KB and 4 of them
}

rule SIGNATURE_BASE_APT_MAL_LNX_Turla_Apr202004_1_Opcode: FILE {
  meta:
    description = "Detects Turla Linux malware x64 x32"
    author      = "Leonardo S.p.A."
    id          = "03043f59-c81a-5423-bec1-6cd88f6e3c52"
    date        = "2020-04-24"
    modified    = "2023-12-05"
    reference   = "https://www.leonardocompany.com/en/news-and-stories-detail/-/detail/knowledge-the-basis-of-protection"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_turla_penquin.yar#L35-L66"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "19524e6ec3b0d49ff9c85ce361ef1922b92e4f7876ddb7d6c9b209b5357080e3"
    score       = 75
    quality     = 85
    tags        = "FILE"
    hash1       = "67d9556c695ef6c51abf6fbab17acb3466e3149cf4d20cb64d6d34dc969b6502"
    hash2       = "8ccc081d4940c5d8aa6b782c16ed82528c0885bbb08210a8d0a8c519c54215bc"
    hash3       = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667"
    hash4       = "1d5e4466a6c5723cd30caf8b1c3d33d1a3d4c94c25e2ebe186c02b8b41daf905"
    hash5       = "2dabb2c5c04da560a6b56dbaa565d1eab8189d1fa4a85557a22157877065ea08"
    hash6       = "3e138e4e34c6eed3506efc7c805fce19af13bd62aeb35544f81f111e83b5d0d4"
    hash7       = "5a204263cac112318cd162f1c372437abf7f2092902b05e943e8784869629dd8"
    hash8       = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667"
    hash9       = "d49690ccb82ff9d42d3ee9d7da693fd7d302734562de088e9298413d56b86ed0"

  strings:
    $op0 = { 8D 41 05 32 06 48 FF C6 88 81 E0 80 69 00 }
    $op1 = { 48 FF C1 48 83 F9 49 75 E9 }
    $op2 = { C7 05 9B 7D 29 00 1D 00 00 00 C7 05 2D 7B 29 00 65 74 68 30 C6 05 2A 7B 29 00 00 E8 }
    $op3 = { BF FF FF FF FF E8 96 9D 0A 00 90 90 90 90 90 90 90 90 90 90 89 F0 }
    $op4 = { 88 D3 80 C3 05 32 9A C1 D6 0C 08 88 9A 60 A1 0F 08 42 83 FA 08 76 E9 }
    $op5 = { 8B 8D 50 DF FF FF B8 09 00 00 00 89 44 24 04 89 0C 24 E8 DD E5 02 00 }
    $op6 = { 8D 5A 05 32 9A 60 26 0C 08 88 9A 20 F4 0E 08 42 83 FA 48 76 EB }
    $op7 = { 8D 4A 05 32 8A 25 26 0C 08 88 8A 20 F4 0E 08 42 83 FA 08 76 EB }

  condition:
    uint16(0) == 0x457f and filesize < 5000KB and 2 of them
}

rule SIGNATURE_BASE_APT_MAL_LNX_Kobalos: FILE {
  meta:
    description = "Kobalos malware"
    author      = "Marc-Etienne M.Leveille"
    id          = "dfa47e30-c093-57f6-af01-72a2534cc6f4"
    date        = "2020-11-02"
    modified    = "2023-12-05"
    reference   = "https://github.com/eset/malware-ioc/"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_lnx_kobalos.yar#L32-L57"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "48aec47b70633d4c8cb55d90a2e168f3c2027ef27cfe1cd5d30dcdc08a2ff717"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "BSD 2-Clause"
    version     = "1"

  strings:
    $encrypted_strings_sizes = {
      05 00 00 00 09 00 00 00 04 00 00 00 06 00 00 00
      08 00 00 00 08 00 00 00 02 00 00 00 02 00 00 00
      01 00 00 00 01 00 00 00 05 00 00 00 07 00 00 00
      05 00 00 00 05 00 00 00 05 00 00 00 0A 00 00 00
    }
    $password_md5_digest     = { 3A DD 48 19 26 54 BD 55 8A 4A 4C ED 9C 25 5C 4C }
    $rsa_512_mod_header      = { 10 11 02 00 09 02 00 }
    $strings_rc4_key         = { AE 0E 05 09 0F 3A C2 B5 0B 1B C6 E9 1D 2F E3 CE }

  condition:
    uint16(0) == 0x457f and any of them
}

rule SIGNATURE_BASE_APT_MAL_LNX_Kobalos_SSH_Credential_Stealer: FILE {
  meta:
    description = "Kobalos SSH credential stealer seen in OpenSSH client"
    author      = "Marc-Etienne M.Leveille"
    id          = "0f923f92-c5d8-500d-9a2e-634ca7945c5c"
    date        = "2020-11-02"
    modified    = "2023-12-05"
    reference   = "https://github.com/eset/malware-ioc/"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_lnx_kobalos.yar#L59-L76"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "fdabaea0c838e43b8716bcd102bdeebf2f08fc041b0b909333e3d9d6f94391fc"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "BSD 2-Clause"
    version     = "1"

  strings:
    $ = "user: %.128s host: %.128s port %05d user: %.128s password: %.128s"

  condition:
    uint16(0) == 0x457f and any of them
}

rule SIGNATURE_BASE_MAL_RANSOM_ELF_Esxi_Attacks_Feb23_1: FILE {
  meta:
    description = "Detects ransomware exploiting and encrypting ESXi servers"
    author      = "Florian Roth"
    id          = "d0a813aa-41f8-57df-b708-18ccb0d7a3e5"
    date        = "2023-02-04"
    modified    = "2023-12-05"
    reference   = "https://www.bleepingcomputer.com/forums/t/782193/esxi-ransomware-help-and-support-topic-esxiargs-args-extension/page-14"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/mal_ransom_esxi_attacks_feb23.yar#L30-L56"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "27ff018574323c10821993c30cf74de15121caa92a308fbcae4eceae954e63b6"
    score       = 85
    quality     = 85
    tags        = "FILE"
    hash1       = "11b1b2375d9d840912cfd1f0d0d04d93ed0cddb0ae4ddb550a5b62cd044d6b66"

  strings:
    $x1  = "usage: encrypt <public_key> <file_to_encrypt> [<enc_step>] [<enc_size>] [<file_size>]" ascii fullword
    $x2  = "[ %s ] - FAIL { Errno: %d }" ascii fullword
    $s1  = "lPEM_read_bio_RSAPrivateKey" ascii fullword
    $s2  = "lERR_get_error" ascii fullword
    $s3  = "get_pk_data: key file is empty!" ascii fullword
    $op1 = { 8b 45 a8 03 45 d0 89 45 d4 8b 45 a4 69 c0 07 53 65 54 89 45 a8 8b 45 a8 c1 c8 19 }
    $op2 = { 48 89 95 40 fd ff ff 48 83 bd 40 fd ff ff 00 0f 85 2e 01 00 00 48 8b 9d 50 ff ff ff 48 89 9d 30 fd ff ff 48 83 bd 30 fd ff ff 00 78 13 f2 48 0f 2a 85 30 fd ff ff }
    $op3 = { 31 55 b4 f7 55 b8 8b 4d ac 09 4d b8 8b 45 b8 31 45 bc c1 4d bc 13 c1 4d b4 1d }

  condition:
    uint16(0) == 0x457f and filesize < 200KB and (1 of ($x*) or 3 of them) or 4 of them
}

rule SIGNATURE_BASE_Apt_Nix_Elf_Derusbi_Linux_Sharedmemcreation_1: FILE {
  meta:
    description = "Detects Derusbi Backdoor ELF Shared Memory Creation"
    author      = "Fidelis Cybersecurity"
    id          = "068b7bea-853d-57e8-a9fe-8b451dbc7582"
    date        = "2016-02-29"
    modified    = "2023-12-05"
    reference   = "https://github.com/fideliscyber/indicators/tree/master/FTA-1021"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_turbo_campaign.yar#L85-L96"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "adbdccea9ea7aefcca18d659c027a49e7e2e053873b77ddaf369203b3e301033"
    score       = 75
    quality     = 85
    tags        = "FILE"

  strings:
    $byte1 = { B6 03 00 00 ?? 40 00 00 00 ?? 0D 5F 01 82 }

  condition:
    uint32(0) == 0x464C457F and any of them
}

rule SIGNATURE_BASE_CN_Honker_Webshell_Linux_2_6_Exploit: FILE {
  meta:
    description = "Webshell from CN Honker Pentest Toolset - file 2.6.9"
    author      = "Florian Roth (Nextron Systems)"
    id          = "22e2aca7-418f-598f-af0c-99942aaf3278"
    date        = "2015-06-23"
    modified    = "2023-12-05"
    reference   = "Disclosed CN Honker Pentest Toolset"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/cn_pentestset_webshells.yar#L977-L991"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    hash        = "ec22fac0510d0dc2c29d56c55ff7135239b0aeee"
    logic_hash  = "7f3e2937796358a949ce980210ddeb1a606a7b9c2b4d9c4a4acad49bb556dfc8"
    score       = 70
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

  strings:
    $s0 = "[+] Failed to get root :( Something's wrong.  Maybe the kernel isn't vulnerable?" fullword ascii

  condition:
    filesize < 56KB and all of them
}

rule SIGNATURE_BASE_MAL_LNX_Camarodragon_Sheel_Oct23: FILE {
  meta:
    description = "Detects CamaroDragon's tool named sheel"
    author      = "Florian Roth"
    id          = "f6f08c0e-236c-5194-9369-da8fdef4aa21"
    date        = "2023-10-06"
    modified    = "2023-12-05"
    reference   = "https://research.checkpoint.com/2023/the-dragon-who-sold-his-camaro-analyzing-custom-router-implant/"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_camaro_dragon_oct23.yar#L2-L25"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "b06f645b766a099adb71c144bdced70c130735e75d5be6451f71077c7d3a5d19"
    score       = 85
    quality     = 85
    tags        = "FILE"
    hash1       = "7985f992dcc6fcce76ee2892700c8538af075bd991625156bf2482dbfebd5a5a"

  strings:
    $x1 = "-h server_ip -p server_port -i update_index[0-4] [-r]" ascii fullword
    $s1 = "read_ip" ascii fullword
    $s2 = "open fail.%m" ascii fullword
    $s3 = "ri:h:p:" ascii fullword
    $s4 = "update server list success!" ascii fullword

  condition:
    uint16(0) == 0x457f and filesize < 30KB and (1 of ($x*) or 3 of them) or 4 of them
}

rule SIGNATURE_BASE_Equationgroup_Crypttool: FILE {
  meta:
    description = "Equation Group hack tool leaked by ShadowBrokers- file cryptTool"
    author      = "Florian Roth (Nextron Systems)"
    id          = "e1f4e010-9c42-5b8a-8feb-2885b99307fe"
    date        = "2017-04-08"
    modified    = "2023-12-05"
    reference   = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp_apr17.yar#L50-L64"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "ae2d5eda038326376511450e1f5bd2bbf6264d23df013b005b322d70eb6266a0"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    hash1       = "96947ad30a2ab15ca5ef53ba8969b9d9a89c48a403e8b22dd5698145ac6695d2"

  strings:
    $s1 = "The encryption key is " fullword ascii
    $s2 = "___tempFile2.out" ascii

  condition:
    (uint16(0) == 0x457f and filesize < 200KB and all of them)
}

rule SIGNATURE_BASE_Equationgroup_Tnmunger: FILE {
  meta:
    description = "Equation Group hack tool leaked by ShadowBrokers- file tnmunger"
    author      = "Florian Roth (Nextron Systems)"
    id          = "c95dd24f-ffc9-5e58-aed7-205daa001b8c"
    date        = "2017-04-08"
    modified    = "2023-12-05"
    reference   = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp_apr17.yar#L120-L134"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "ddb957ca9350288d0fa98ba20847a99dcba931b5a03d0ae94cd3409f82f728eb"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    hash1       = "1ab985d84871c54d36ba4d2abd9168c2a468f1ba06994459db06be13ee3ae0d2"

  strings:
    $s1 = "TEST: mungedport=%6d  pp=%d  unmunged=%6d" fullword ascii
    $s2 = "mungedport=%6d  pp=%d  unmunged=%6d" fullword ascii

  condition:
    (uint16(0) == 0x457f and filesize < 10KB and 1 of them)
}

rule SIGNATURE_BASE_Equationgroup_Eh_1_1_0: FILE {
  meta:
    description = "Equation Group hack tool leaked by ShadowBrokers- file eh.1.1.0.0"
    author      = "Florian Roth (Nextron Systems)"
    id          = "a6f0ec1f-b0e5-5913-970d-9cdadf647c44"
    date        = "2017-04-08"
    modified    = "2023-12-05"
    reference   = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp_apr17.yar#L153-L168"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "d0972bb57076606b3c84f3cbbb0be85cd5663c7cd6f6d9f09a2991cb6532bfa9"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    hash1       = "0f8dd094516f1be96da5f9addc0f97bcac8f2a348374bd9631aa912344559628"

  strings:
    $x1 = "usage: %s -e -v -i target IP [-c Cert File] [-k Key File]" fullword ascii
    $x2 = "TYPE=licxfer&ftp=%s&source=/var/home/ftp/pub&version=NA&licfile=" ascii
    $x3 = "[-l Log File] [-m save MAC time file(s)] [-p Server Port]" fullword ascii

  condition:
    (uint16(0) == 0x457f and filesize < 100KB and 1 of them)
}

rule SIGNATURE_BASE_Equationgroup_Sshobo: FILE {
  meta:
    description = "Equation Group hack tool leaked by ShadowBrokers- file sshobo"
    author      = "Florian Roth (Nextron Systems)"
    id          = "b9392aec-34a8-5ad2-b3fd-eea907d19701"
    date        = "2017-04-08"
    modified    = "2023-12-05"
    reference   = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp_apr17.yar#L207-L223"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "90c892e06ccedb6a3208d728e9f3c27c14bbe1b4c13b63d4a350bbbf38efbe9d"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    hash1       = "c7491898a0a77981c44847eb00fb0b186aa79a219a35ebbca944d627eefa7d45"

  strings:
    $x1 = "Requested forwarding of port %d but user is not root." fullword ascii
    $x2 = "internal error: we do not read, but chan_read_failed for istate" fullword ascii
    $x3 = "~#  - list forwarded connections" fullword ascii
    $x4 = "packet_inject_ignore: block" fullword ascii

  condition:
    (uint16(0) == 0x457f and filesize < 600KB and all of them)
}

rule SIGNATURE_BASE_Equationgroup_Electricslide: FILE {
  meta:
    description = "Equation Group hack tool leaked by ShadowBrokers- file electricslide"
    author      = "Florian Roth (Nextron Systems)"
    id          = "5b1e5293-806a-58e6-b865-66025c8d8c32"
    date        = "2017-04-08"
    modified    = "2023-12-05"
    reference   = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp_apr17.yar#L310-L326"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "0803b61afc592d4fba523dc54d8f856a557b916a9f6e256efccd50178e8e024c"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    hash1       = "d27814b725568fa73641e86fa51850a17e54905c045b8b31a9a5b6d2bdc6f014"

  strings:
    $x1 = "Firing with the same hosts, on altername ports (target is on 8080, listener on 443)" fullword ascii
    $x2 = "Recieved Unknown Command Payload: 0x%x" fullword ascii
    $x3 = "Usage: eslide   [options] <-t profile> <-l listenerip> <targetip>" fullword ascii
    $x4 = "-------- Delete Key - Remove a *closed* tab" fullword ascii

  condition:
    (uint16(0) == 0x457f and filesize < 2000KB and 1 of them)
}

rule SIGNATURE_BASE_Equationgroup_Cmsd: FILE {
  meta:
    description = "Equation Group hack tool leaked by ShadowBrokers- file cmsd"
    author      = "Florian Roth (Nextron Systems)"
    id          = "9cdd3562-fed4-5b79-b056-049279404eeb"
    date        = "2017-04-08"
    modified    = "2023-12-05"
    reference   = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp_apr17.yar#L380-L397"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "2b9c7ef750c2e45df7839395db51c93204bc9855f5de05bd59c50bb6a964bc8b"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    hash1       = "634c50614e1f5f132f49ae204c4a28f62a32a39a3446084db5b0b49b564034b8"

  strings:
    $x1 = "usage: %s address [-t][-s|-c command] [-p port] [-v 5|6|7]" fullword ascii
    $x2 = "error: not vulnerable" fullword ascii
    $s1 = "port=%d connected! " fullword ascii
    $s2 = "xxx.XXXXXX" fullword ascii

  condition:
    (uint16(0) == 0x457f and filesize < 30KB and 1 of ($x*)) or (2 of them)
}

rule SIGNATURE_BASE_Equationgroup_Eggbasket: FILE {
  meta:
    description = "Equation Group hack tool leaked by ShadowBrokers- file eggbasket"
    author      = "Florian Roth (Nextron Systems)"
    id          = "3fb1388a-e6b8-5c7a-ad23-ddbfc9d33d56"
    date        = "2017-04-08"
    modified    = "2023-12-05"
    reference   = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp_apr17.yar#L417-L432"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "e4800d5c820a18d3483dc5c055c0e2f5374ce3b160ecb4d940a00ec4a90ca50d"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    hash1       = "b078a02963610475217682e6e1d6ae0b30935273ed98743e47cc2553fbfd068f"

  strings:
    $x1 = "# Building Shellcode into exploit." fullword ascii
    $x2 = "%s -w /index.html -v 3.5 -t 10 -c \"/usr/openwin/bin/xterm -d 555.1.2.2:0&\"  -d 10.0.0.1 -p 80" fullword ascii
    $x3 = "# STARTING EXHAUSTIVE ATTACK AGAINST " fullword ascii

  condition:
    (uint16(0) == 0x457f and filesize < 90KB and 1 of them) or (2 of them)
}

rule SIGNATURE_BASE_Equationgroup_Exze: FILE {
  meta:
    description = "Equation Group hack tool leaked by ShadowBrokers- file exze"
    author      = "Florian Roth (Nextron Systems)"
    id          = "d452b952-0c4a-501b-93f5-064d13f2c08e"
    date        = "2017-04-08"
    modified    = "2023-12-05"
    reference   = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp_apr17.yar#L522-L537"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "b8678f58da689be9507a345b6b80ece6cdb7a78d73db339bdc15ad0a66b4a2e6"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    hash1       = "1af6dde6d956db26c8072bf5ff26759f1a7fa792dd1c3498ba1af06426664876"

  strings:
    $s1 = "shellFile" fullword ascii
    $s2 = "completed.1" fullword ascii
    $s3 = "zeke_remove" fullword ascii

  condition:
    (uint16(0) == 0x457f and filesize < 80KB and all of them)
}

rule SIGNATURE_BASE_Equationgroup_DUL: FILE {
  meta:
    description = "Equation Group hack tool leaked by ShadowBrokers- file DUL"
    author      = "Florian Roth (Nextron Systems)"
    id          = "6dd90b30-30cb-531c-b8e2-fc208b21e8e6"
    date        = "2017-04-08"
    modified    = "2023-12-05"
    reference   = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp_apr17.yar#L539-L553"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "55df9a844352babf0c30075139e2a62cbf9db898280546d27b172e4d611ce1c0"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    hash1       = "24d1d50960d4ebf348b48b4db4a15e50f328ab2c0e24db805b106d527fc5fe8e"

  strings:
    $x1 = "?Usage: %s <shellcode> <output_file>" fullword ascii
    $x2 = "Here is the decoder+(encoded-decoder)+payload" fullword ascii

  condition:
    (uint16(0) == 0x457f and filesize < 80KB and 1 of them) or (all of them)
}

rule SIGNATURE_BASE_Equationgroup_Slugger2: FILE {
  meta:
    description = "Equation Group hack tool leaked by ShadowBrokers- file slugger2"
    author      = "Florian Roth (Nextron Systems)"
    id          = "3787a39e-0123-5b46-90c9-6b772b1fd96c"
    date        = "2017-04-08"
    modified    = "2023-12-05"
    reference   = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp_apr17.yar#L555-L574"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "3c736fdfa96d5e99bc4d093c03a81b8a4f58501ec8c03a2891f9f694d88b5284"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    hash1       = "a6a9ab66d73e4b443a80a69ef55a64da7f0af08dfaa7e17eb19c327301a70bdf"

  strings:
    $x1 = "usage: %s hostip port cmd [printer_name]" fullword ascii
    $x2 = "command must be less than 61 chars" fullword ascii
    $s1 = "__rw_read_waiting" ascii
    $s2 = "completed.1" fullword ascii
    $s3 = "__mutexkind" ascii
    $s4 = "__rw_pshared" ascii

  condition:
    (uint16(0) == 0x457f and filesize < 50KB and (4 of them and 1 of ($x*))) or (all of them)
}

rule SIGNATURE_BASE_Equationgroup_Jackpop: FILE {
  meta:
    description = "Equation Group hack tool leaked by ShadowBrokers- file jackpop"
    author      = "Florian Roth (Nextron Systems)"
    id          = "7c650752-200b-51e7-95c2-4d385bfd5844"
    date        = "2017-04-08"
    modified    = "2023-12-05"
    reference   = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp_apr17.yar#L596-L614"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "6efc4ccd2727f93713ad35dc1f054fa25e976e8c3d95f00226fbd56d7f1ce30b"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    hash1       = "0b208af860bb2c7ef6b1ae1fcef604c2c3d15fc558ad8ea241160bf4cbac1519"

  strings:
    $x1 = "%x:%d  --> %x:%d %d bytes" fullword ascii
    $s1 = "client: can't bind to local address, are you root?" fullword ascii
    $s2 = "Unable to register port" fullword ascii
    $s3 = "Could not resolve destination" fullword ascii
    $s4 = "raw troubles" fullword ascii

  condition:
    (uint16(0) == 0x457f and filesize < 30KB and 3 of them) or (all of them)
}

rule SIGNATURE_BASE_Equationgroup_Epoxyresin_V1_0_0: FILE {
  meta:
    description = "Equation Group hack tool leaked by ShadowBrokers- file epoxyresin.v1.0.0.1"
    author      = "Florian Roth (Nextron Systems)"
    id          = "390a13b0-3246-5bf7-8841-775a43045172"
    date        = "2017-04-08"
    modified    = "2023-12-05"
    reference   = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp_apr17.yar#L664-L681"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "c1cbc18f05b299837463aa27a9c47ea0355ca5974b2c6ab1e0a18cc9ad1b26a1"
    score       = 75
    quality     = 83
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    hash1       = "eea8a6a674d5063d7d6fc9fe07060f35b16172de6d273748d70576b01bf01c73"

  strings:
    $x1 = "[-] kernel not vulnerable" fullword ascii
    $s1 = ".tmp.%d.XXXXXX" fullword ascii
    $s2 = "[-] couldn't create temp file" fullword ascii
    $s3 = "/boot/System.map-%s" fullword ascii

  condition:
    (uint16(0) == 0x457f and filesize < 30KB and $x1) or (all of them)
}

rule SIGNATURE_BASE_Equationgroup_Ewok: FILE {
  meta:
    description = "Equation Group hack tool leaked by ShadowBrokers- file ewok"
    author      = "Florian Roth (Nextron Systems)"
    id          = "379c233f-86f8-5116-a15c-8a80b27daea6"
    date        = "2017-04-08"
    modified    = "2023-12-05"
    reference   = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp_apr17.yar#L768-L784"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "d10d75885daa8cd20e5d7d7e142d1e7a2dbc10a50debf7892629f67b948bbdbe"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    hash1       = "567da502d7709b7814ede9c7954ccc13d67fc573f3011db04cf212f8e8a95d72"

  strings:
    $x1 = "Example: ewok -t target public" fullword ascii
    $x2 = "Usage:  cleaner host community fake_prog" fullword ascii
    $x3 = "-g  - Subset of -m that Green Spirit hits " fullword ascii
    $x4 = "--- ewok version" fullword ascii

  condition:
    (uint16(0) == 0x457f and filesize < 80KB and 1 of them)
}

rule SIGNATURE_BASE_Equationgroup_Xspy: FILE {
  meta:
    description = "Equation Group hack tool leaked by ShadowBrokers- file xspy"
    author      = "Florian Roth (Nextron Systems)"
    id          = "fcb7246a-d613-51d7-a4f7-f767fa5f79e1"
    date        = "2017-04-08"
    modified    = "2023-12-05"
    reference   = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp_apr17.yar#L786-L799"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "94ab45d6c94c63c5c9c68ee3d509143af4eb574058c0cd4f26eed8058dbd9213"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    hash1       = "841e065c9c340a1e522b281a39753af8b6a3db5d9e7d8f3d69e02fdbd662f4cf"

  strings:
    $s1 = "USAGE: xspy -display <display> -delay <usecs> -up" fullword ascii

  condition:
    (uint16(0) == 0x457f and filesize < 60KB and all of them)
}

rule SIGNATURE_BASE_Equationgroup__Scanner_Scanner_V2_1_2: FILE {
  meta:
    description = "Equation Group hack tool leaked by ShadowBrokers- from files scanner, scanner.v2.1.2"
    author      = "Florian Roth (Nextron Systems)"
    id          = "bf1f2119-f742-5106-96f0-de88755275ef"
    date        = "2017-04-08"
    modified    = "2023-12-05"
    reference   = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp_apr17.yar#L873-L892"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "3c42aaacea1347fd64d7f91421f692e77e33e273d4c2e71806ef7f5f086aba11"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    super_rule  = 1
    hash1       = "dcbcd8a98ec93a4e877507058aa26f0c865b35b46b8e6de809ed2c4b3db7e222"
    hash2       = "9807aaa7208ed6c5da91c7c30ca13d58d16336ebf9753a5cea513bcb59de2cff"

  strings:
    $s1 = "Welcome to the network scanning tool" fullword ascii
    $s2 = "Scanning port %d" fullword ascii
    $s3 = "/current/down/cmdout/scans" fullword ascii
    $s4 = "Scan for SSH version" fullword ascii
    $s5 = "program vers proto   port  service" fullword ascii

  condition:
    (uint16(0) == 0x457f and filesize < 100KB and 2 of them) or (all of them)
}

rule SIGNATURE_BASE_Equationgroup__Ghost_Sparc_Ghost_X86_3: FILE {
  meta:
    description = "Equation Group hack tool leaked by ShadowBrokers- from files ghost_sparc, ghost_x86"
    author      = "Florian Roth (Nextron Systems)"
    id          = "ccc9c9be-8f78-5071-a11e-47f994cf8f08"
    date        = "2017-04-08"
    modified    = "2023-12-05"
    reference   = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp_apr17.yar#L894-L912"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "c4ad8e06934c1ece520863951f14cbf86d1bc4bba97aede1d58def1e5c7df4eb"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    super_rule  = 1
    hash1       = "d5ff0208d9532fc0c6716bd57297397c8151a01bf4f21311f24e7a72551f9bf1"
    hash2       = "82c899d1f05b50a85646a782cddb774d194ef85b74e1be642a8be2c7119f4e33"

  strings:
    $x1 = "Usage: %s [-v os] [-p] [-r] [-c command] [-a attacker] target" fullword ascii
    $x2 = "Sending shellcode as part of an open command..." fullword ascii
    $x3 = "cmdshellcode" fullword ascii
    $x4 = "You will not be able to run the shellcode. Exiting..." fullword ascii

  condition:
    (uint16(0) == 0x457f and filesize < 70KB and 1 of them) or (2 of them)
}

rule SIGNATURE_BASE_BKDR_Xzutil_Binary_CVE_2024_3094_Mar24_1: CVE_2024_3094 FILE {
  meta:
    description = "Detects injected code used by the backdoored XZ library (xzutil) CVE-2024-3094."
    author      = "Florian Roth"
    id          = "6ccdeb6d-67c4-5358-a76b-aef7f047c997"
    date        = "2024-03-30"
    modified    = "2024-04-24"
    reference   = "https://www.openwall.com/lists/oss-security/2024/03/29/4"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/bkdr_xz_util_cve_2024_3094.yar#L19-L46"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "ed364484ff598b0818f9b3249673e684b52394c25b14e47fbca25a5f96ecc970"
    score       = 75
    quality     = 85
    tags        = "CVE-2024-3094, FILE"
    hash1       = "319feb5a9cddd81955d915b5632b4a5f8f9080281fb46e2f6d69d53f693c23ae"
    hash2       = "605861f833fc181c7cdcabd5577ddb8989bea332648a8f498b4eef89b8f85ad4"
    hash3       = "8fa641c454c3e0f76de73b7cc3446096b9c8b9d33d406d38b8ac76090b0344fd"
    hash4       = "b418bfd34aa246b2e7b5cb5d263a640e5d080810f767370c4d2c24662a274963"
    hash5       = "cbeef92e67bf41ca9c015557d81f39adaba67ca9fb3574139754999030b83537"
    hash6       = "5448850cdc3a7ae41ff53b433c2adbd0ff492515012412ee63a40d2685db3049"

  strings:
    $op1 = { 48 8d 7c 24 08 f3 ab 48 8d 44 24 08 48 89 d1 4c 89 c7 48 89 c2 e8 ?? ?? ?? ?? 89 c2 }
    $op2 = { 31 c0 49 89 ff b9 16 00 00 00 4d 89 c5 48 8d 7c 24 48 4d 89 ce f3 ab 48 8d 44 24 48 }
    $op3 = { 4d 8b 6c 24 08 45 8b 3c 24 4c 8b 63 10 89 85 78 f1 ff ff 31 c0 83 bd 78 f1 ff ff 00 f3 ab 79 07 }
    $xc1 = { F3 0F 1E FA 55 48 89 F5 4C 89 CE 53 89 FB 81 E7 00 00 00 80 48 83 EC 28 48 89 54 24 18 48 89 4C 24 10 }

  condition:
    uint16(0) == 0x457f and (all of ($op*) or $xc1)
}

rule SIGNATURE_BASE_VULN_LNX_OMI_RCE_CVE_2021_386471_Sep21: CVE_2021_38647 FILE {
  meta:
    description = "Detects a Linux OMI version vulnerable to CVE-2021-38647 (OMIGOD) which enables an unauthenticated RCE"
    author      = "Christian Burkard"
    id          = "ca49f0cc-ea33-559c-bd4f-306a01315fce"
    date        = "2021-09-16"
    modified    = "2023-12-05"
    reference   = "https://www.wiz.io/blog/secret-agent-exposes-azure-customers-to-unauthorized-code-execution"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/vul_cve_2021_386471_omi.yar#L1-L37"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "99fddcf763f41a08a8ef8240d544ef67b840a1b5ae709bd7efbcbcad8268e8a5"
    score       = 50
    quality     = 85
    tags        = "CVE-2021-38647, FILE"

  strings:
    $a1  = "/opt/omi/bin/omiagent" ascii fullword
    $s1  = "OMI-1.6.8-0 - " ascii
    $s2  = "OMI-1.6.6-0 - " ascii
    $s3  = "OMI-1.6.4-1 - " ascii
    $s4  = "OMI-1.6.4-0 - " ascii
    $s5  = "OMI-1.6.2-0 - " ascii
    $s6  = "OMI-1.6.1-0 - " ascii
    $s7  = "OMI-1.5.0-0 - " ascii
    $s8  = "OMI-1.4.4-0 - " ascii
    $s9  = "OMI-1.4.3-2 - " ascii
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
    uint32be(0) == 0x7f454c46 and $a1 and 1 of ($s*)
}

rule SIGNATURE_BASE_APT_MAL_LNX_Redmenshen_Bpfdoor_Controller_May22_2: FILE {
  meta:
    description = "Detects BPFDoor implants used by Chinese actor Red Menshen"
    author      = "Florian Roth (Nextron Systems)"
    id          = "d5c3d530-ed6f-563e-a3b0-55d4c82e4899"
    date        = "2022-05-07"
    modified    = "2023-12-05"
    reference   = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/mal_lnx_implant_may22.yar#L78-L100"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "7525c675dbba6eb480f1d28fc6db05bd9907725c291e64ee6dc2453fd42892a0"
    score       = 85
    quality     = 85
    tags        = "FILE"
    hash1       = "76bf736b25d5c9aaf6a84edd4e615796fffc338a893b49c120c0b4941ce37925"
    hash2       = "96e906128095dead57fdc9ce8688bb889166b67c9a1b8fdb93d7cff7f3836bb9"
    hash3       = "c80bd1c4a796b4d3944a097e96f384c85687daeedcdcf05cc885c8c9b279b09c"
    hash4       = "f47de978da1dbfc5e0f195745e3368d3ceef034e964817c66ba01396a1953d72"

  strings:
    $opx1 = { 48 83 c0 0c 48 8b 95 e8 fe ff ff 48 83 c2 0c 8b 0a 8b 55 f0 01 ca 89 10 c9 }
    $opx2 = { 48 01 45 e0 83 45 f4 01 8b 45 f4 3b 45 dc 7c cd c7 45 f4 00 00 00 00 eb 2? 48 8b 05 ?? ?? 20 00 }
    $op1  = { 48 8d 14 c5 00 00 00 00 48 8b 45 d0 48 01 d0 48 8b 00 48 89 c7 e8 ?? ?? ff ff 48 83 c0 01 48 01 45 e0 }
    $op2  = { 89 c2 8b 85 fc fe ff ff 01 c2 8b 45 f4 01 d0 2d 7b cf 10 2b 89 45 f4 c1 4d f4 10 }
    $op3  = { e8 ?? d? ff ff 8b 45 f0 eb 12 8b 85 3c ff ff ff 89 c7 e8 ?? d? ff ff b8 ff ff ff ff c9 }

  condition:
    uint16(0) == 0x457f and filesize < 100KB and 2 of ($opx*) or 4 of them
}

rule SIGNATURE_BASE_APT_MAL_LNX_Redmenshen_Bpfdoor_Controller_May22_3: FILE {
  meta:
    description = "Detects BPFDoor implants used by Chinese actor Red Menshen"
    author      = "Florian Roth (Nextron Systems)"
    id          = "91c2153a-a6e0-529e-852c-61f799838798"
    date        = "2022-05-08"
    modified    = "2023-12-05"
    reference   = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/mal_lnx_implant_may22.yar#L102-L119"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "afec0bfeddf5c5c2abc1a3173f636c385437e5d7c0b68665f6274011113a6a9c"
    score       = 85
    quality     = 85
    tags        = "FILE"
    hash1       = "144526d30ae747982079d5d340d1ff116a7963aba2e3ed589e7ebc297ba0c1b3"
    hash2       = "fa0defdabd9fd43fe2ef1ec33574ea1af1290bd3d763fdb2bed443f2bd996d73"

  strings:
    $s1 = "hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event" ascii fullword
    $s2 = "/sbin/mingetty /dev" ascii fullword
    $s3 = "pickup -l -t fifo -u" ascii fullword

  condition:
    uint16(0) == 0x457f and filesize < 200KB and 2 of them or all of them
}

rule SIGNATURE_BASE_APT_MAL_LNX_Redmenshen_Bpfdoor_Controller_Generic_May22_1: FILE {
  meta:
    description = "Detects BPFDoor malware"
    author      = "Florian Roth (Nextron Systems)"
    id          = "d30df2ae-7008-53c0-9a61-8346a9c9f465"
    date        = "2022-05-09"
    modified    = "2023-12-05"
    reference   = "https://doublepulsar.com/bpfdoor-an-active-chinese-global-surveillance-tool-54b078f1a896"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/mal_lnx_implant_may22.yar#L121-L156"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "57ae5f7dc1d202fe66d6626ef2bf2278b92bec0310449ce049bdaeaec5657c77"
    score       = 90
    quality     = 85
    tags        = "FILE"
    hash1       = "07ecb1f2d9ffbd20a46cd36cd06b022db3cc8e45b1ecab62cd11f9ca7a26ab6d"
    hash2       = "1925e3cd8a1b0bba0d297830636cdb9ebf002698c8fa71e0063581204f4e8345"
    hash3       = "4c5cf8f977fc7c368a8e095700a44be36c8332462c0b1e41bff03238b2bf2a2d"
    hash4       = "591198c234416c6ccbcea6967963ca2ca0f17050be7eed1602198308d9127c78"
    hash5       = "599ae527f10ddb4625687748b7d3734ee51673b664f2e5d0346e64f85e185683"
    hash6       = "5b2a079690efb5f4e0944353dd883303ffd6bab4aad1f0c88b49a76ddcb28ee9"
    hash7       = "5faab159397964e630c4156f8852bcc6ee46df1cdd8be2a8d3f3d8e5980f3bb3"
    hash8       = "76bf736b25d5c9aaf6a84edd4e615796fffc338a893b49c120c0b4941ce37925"
    hash9       = "93f4262fce8c6b4f8e239c35a0679fbbbb722141b95a5f2af53a2bcafe4edd1c"
    hash10      = "96e906128095dead57fdc9ce8688bb889166b67c9a1b8fdb93d7cff7f3836bb9"
    hash11      = "97a546c7d08ad34dfab74c9c8a96986c54768c592a8dae521ddcf612a84fb8cc"
    hash12      = "c796fc66b655f6107eacbe78a37f0e8a2926f01fecebd9e68a66f0e261f91276"
    hash13      = "c80bd1c4a796b4d3944a097e96f384c85687daeedcdcf05cc885c8c9b279b09c"
    hash14      = "f47de978da1dbfc5e0f195745e3368d3ceef034e964817c66ba01396a1953d72"
    hash15      = "f8a5e735d6e79eb587954a371515a82a15883cf2eda9d7ddb8938b86e714ea27"
    hash16      = "fa0defdabd9fd43fe2ef1ec33574ea1af1290bd3d763fdb2bed443f2bd996d73"
    hash17      = "fd1b20ee5bd429046d3c04e9c675c41e9095bea70e0329bd32d7edd17ebaf68a"

  strings:
    $op1 = { c6 80 01 01 00 00 00 48 8b 45 ?8 0f b6 90 01 01 00 00 48 8b 45 ?8 88 90 00 01 00 00 c6 45 ?? 00 0f b6 45 ?? 88 45 }
    $op2 = { 48 89 55 c8 48 8b 45 c8 48 89 45 ?? 48 8b 45 c8 0f b6 80 00 01 00 00 88 45 f? 48 8b 45 c8 0f b6 80 01 01 00 00 }
    $op3 = { 48 89 45 ?? 48 8b 45 c8 0f b6 80 00 01 00 00 88 45 f? 48 8b 45 c8 0f b6 80 01 01 00 00 88 45 f? c7 45 f8 00 00 00 00 }
    $op4 = { 48 89 7d d8 89 75 d4 48 89 55 c8 48 8b 45 c8 48 89 45 ?? 48 8b 45 c8 0f b6 80 00 01 00 00 88 45 f? }
    $op5 = { 48 8b 45 ?8 c6 80 01 01 00 00 00 48 8b 45 ?8 0f b6 90 01 01 00 00 48 8b 45 ?8 88 90 00 01 00 00 c6 45 ?? 00 0f b6 45 }
    $op6 = { 89 75 d4 48 89 55 c8 48 8b 45 c8 48 89 45 ?? 48 8b 45 c8 0f b6 80 00 01 00 00 88 45 f? 48 8b 45 c8 }

  condition:
    uint16(0) == 0x457f and filesize < 200KB and 2 of them or 4 of them
}

rule SIGNATURE_BASE_Mirai_Botnet_Malware: FILE {
  meta:
    description = "Detects Mirai Botnet Malware"
    author      = "Florian Roth (Nextron Systems)"
    id          = "a678e9f7-d516-5bdb-962e-b9d39d8a64bb"
    date        = "2016-10-04"
    modified    = "2023-01-27"
    reference   = "Internal Research"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_mirai.yar#L10-L50"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "384f8377ca05296da1177a8939f526069fbad0bb73769bd282d81ea4d876003c"
    score       = 75
    quality     = 83
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    hash1       = "05c78c3052b390435e53a87e3d31e9fb17f7c76bb4df2814313bca24735ce81c"
    hash2       = "05c78c3052b390435e53a87e3d31e9fb17f7c76bb4df2814313bca24735ce81c"
    hash3       = "20683ff7a5fec1237fc09224af40be029b9548c62c693844624089af568c89d4"
    hash4       = "2efa09c124f277be2199bee58f49fc0ce6c64c0bef30079dfb3d94a6de492a69"
    hash5       = "420bf9215dfb04e5008c5e522eee9946599e2b323b17f17919cd802ebb012175"
    hash6       = "62cdc8b7fffbaf5683a466f6503c03e68a15413a90f6afd5a13ba027631460c6"
    hash7       = "70bb0ec35dd9afcfd52ec4e1d920e7045dc51dca0573cd4c753987c9d79405c0"
    hash8       = "89570ae59462e6472b6769545a999bde8457e47ae0d385caaa3499ab735b8147"
    hash9       = "bf0471b37dba7939524a30d7d5afc8fcfb8d4a7c9954343196737e72ea4e2dc4"
    hash10      = "c61bf95146c68bfbbe01d7695337ed0e93ea759f59f651799f07eecdb339f83f"
    hash11      = "d9573c3850e2ae35f371dff977fc3e5282a5e67db8e3274fd7818e8273fd5c89"
    hash12      = "f1100c84abff05e0501e77781160d9815628e7fd2de9e53f5454dbcac7c84ca5"
    hash13      = "fb713ccf839362bf0fbe01aedd6796f4d74521b133011b408e42c1fd9ab8246b"

  strings:
    $x1 = "POST /cdn-cgi/" ascii
    $x2 = "/dev/misc/watchdog" fullword ascii
    $x3 = "/dev/watchdog" ascii
    $x5 = ".mdebug.abi32" fullword ascii
    $s1 = "LCOGQGPTGP" fullword ascii
    $s2 = "QUKLEKLUKVJOG" fullword ascii
    $s3 = "CFOKLKQVPCVMP" fullword ascii
    $s4 = "QWRGPTKQMP" fullword ascii
    $s5 = "HWCLVGAJ" fullword ascii
    $s6 = "NKQVGLKLE" fullword ascii

  condition:
    uint16(0) == 0x457f and filesize < 200KB and ((1 of ($x*) and 1 of ($s*)) or 4 of ($s*))
}

rule SIGNATURE_BASE_Mirai_1_May17: FILE {
  meta:
    description = "Detects Mirai Malware"
    author      = "Florian Roth (Nextron Systems)"
    id          = "ac85ee28-a01f-5c3d-a534-0c19a3dc92e7"
    date        = "2017-05-12"
    modified    = "2023-12-05"
    reference   = "Internal Research"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_mirai.yar#L62-L78"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "6816ab3b455bbde6c4bb43bff162615d7fc24b9d5828faa190600387c38978e1"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    super_rule  = 1
    hash1       = "172d050cf0d4e4f5407469998857b51261c80209d9fa5a2f5f037f8ca14e85d2"
    hash2       = "9ba8def84a0bf14f682b3751b8f7a453da2cea47099734a72859028155b2d39c"
    hash3       = "a393449a5f19109160384b13d60bb40601af2ef5f08839b5223f020f1f83e990"

  strings:
    $s1 = "GET /bins/mirai.x86 HTTP/1.0" fullword ascii

  condition:
    (uint16(0) == 0x457f and filesize < 5000KB and all of them)
}

rule SIGNATURE_BASE_MAL_ELF_LNX_Mirai_Oct10_2: FILE {
  meta:
    description = "Detects ELF malware Mirai related"
    author      = "Florian Roth (Nextron Systems)"
    id          = "421b7708-030e-50d1-bf2e-e91758a48c00"
    date        = "2018-10-27"
    modified    = "2023-12-05"
    reference   = "Internal Research"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_mirai.yar#L124-L138"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "47d20bdf64c18c925dc1391b022278f913b7fbce13988a7b5de2e9d135c5a265"
    score       = 75
    quality     = 85
    tags        = "FILE"
    hash1       = "fa0018e75f503f9748a5de0d14d4358db234f65e28c31c8d5878cc58807081c9"

  strings:
    $c01 = {
      50 4F 53 54 20 2F 63 64 6E 2D 63 67 69 2F 00 00
      20 48 54 54 50 2F 31 2E 31 0D 0A 55 73 65 72 2D
      41 67 65 6E 74 3A 20 00 0D 0A 48 6F 73 74 3A
    }

  condition:
    uint16(0) == 0x457f and filesize < 200KB and all of them
}

rule SIGNATURE_BASE_MAL_Mirai_Nov19_1: FILE {
  meta:
    description = "Detects Mirai malware"
    author      = "Florian Roth (Nextron Systems)"
    id          = "40edcb29-9e10-5b87-ba79-8e3f629829e5"
    date        = "2019-11-13"
    modified    = "2023-12-05"
    reference   = "https://twitter.com/bad_packets/status/1194049104533282816"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_mirai.yar#L140-L157"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "e1202a9cd445c590c359a9c93e635292f8cf7f09291f4d8504ad9ce6679f6a47"
    score       = 75
    quality     = 85
    tags        = "FILE"
    hash1       = "bbb83da15d4dabd395996ed120435e276a6ddfbadafb9a7f096597c869c6c739"
    hash2       = "fadbbe439f80cc33da0222f01973f27cce9f5ab0709f1bfbf1a954ceac5a579b"

  strings:
    $s1  = "SERVZUXO" fullword ascii
    $s2  = "-loldongs" fullword ascii
    $s3  = "/dev/null" fullword ascii
    $s4  = "/bin/busybox" fullword ascii
    $sc1 = "Groups:\t0"

  condition:
    uint16(0) == 0x457f and filesize <= 100KB and 4 of them
}

rule SIGNATURE_BASE_MAL_ARM_LNX_Mirai_Mar13_2022: FILE {
  meta:
    description = "Detects new ARM Mirai variant"
    author      = "Mehmet Ali Kerimoglu a.k.a. CYB3RMX"
    id          = "54d8860e-fc45-5571-b68c-66590c67a705"
    date        = "2022-03-16"
    modified    = "2023-12-05"
    reference   = "https://github.com/Neo23x0/signature-base"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_mirai.yar#L159-L181"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "a44a6174a198a658c8a5e2da50192da20bae7f8ed4e4f212c9eebb29fa4b0dd0"
    score       = 75
    quality     = 85
    tags        = "FILE"
    hash1       = "0283b72913b8a78b2a594b2d40ebc3c873e4823299833a1ff6854421378f5a68"

  strings:
    $str1   = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/lib1funcs.asm"
    $str2   = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/lib1funcs.asm"
    $str3   = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm"
    $str4   = "/home/landley/aboriginal/aboriginal/build/simple-cross-compiler-armv6l/bin/../cc/include"
    $attck1 = "attack.c"
    $attck2 = "attacks.c"
    $attck3 = "anti_gdb_entry"
    $attck4 = "resolve_cnc_addr"
    $attck5 = "attack_gre_eth"
    $attck6 = "attack_udp_generic"
    $attck7 = "attack_get_opt_ip"
    $attck8 = "attack_icmpecho"

  condition:
    uint16(0) == 0x457f and (3 of ($str*) or 4 of ($attck*))
}

rule SIGNATURE_BASE_MAL_ELF_Vpnfilter_1: FILE {
  meta:
    description = "Detects VPNFilter malware"
    author      = "Florian Roth (Nextron Systems)"
    id          = "dc50cb37-a6e7-5eb5-9581-31d7fd005e47"
    date        = "2018-05-24"
    modified    = "2023-12-05"
    reference   = "Internal Research"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_vpnfilter.yar#L11-L31"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "aff7b1f3d4afaf883c2702287ef7d6e13e01e80222ba336978d13deb21a93614"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    hash1       = "f8286e29faa67ec765ae0244862f6b7914fcdde10423f96595cb84ad5cc6b344"

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
    uint16(0) == 0x457f and filesize < 100KB and all of them
}

rule SIGNATURE_BASE_HKTL_EXPL_POC_Libssh_Auth_Bypass_CVE_2023_2283_Jun23_1: CVE_2023_2283 FILE {
  meta:
    description = "Detects POC code used in attacks against libssh vulnerability CVE-2023-2283"
    author      = "Florian Roth"
    id          = "e72eba33-686f-5fca-bca3-2b875d1ec224"
    date        = "2023-06-08"
    modified    = "2023-12-05"
    reference   = "https://github.com/github/securitylab/tree/1786eaae7f90d87ce633c46bbaa0691d2f9bf449/SecurityExploits/libssh/pubkey-auth-bypass-CVE-2023-2283"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/expl_libssh_cve_2023_2283_jun23.yar#L2-L15"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "4c3d54d7f4902c1da664e41096b5931e6534aaaf63243f12e05b81af63d8b28f"
    score       = 85
    quality     = 85
    tags        = "CVE-2023-2283, FILE"

  strings:
    $s1 = "nprocs = %d" ascii fullword
    $s2 = "fork failed: %s" ascii fullword

  condition:
    uint16(0) == 0x457f and all of them
}

rule SIGNATURE_BASE_APT_MAL_LNX_Turla_Apr20_1: FILE {
  meta:
    description = "Detects Turla Linux malware"
    author      = "Florian Roth (Nextron Systems)"
    id          = "f21e7793-a7dd-5195-805d-963827b35808"
    date        = "2020-04-05"
    modified    = "2023-12-05"
    reference   = "https://twitter.com/Int2e_/status/1246115636331319309"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_turla.yar#L252-L272"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "d463f5a151bb0c3440d719b4c7c0d1ca34de1e0bed7fb9167ecf396607abd3ff"
    score       = 75
    quality     = 85
    tags        = "FILE"
    hash1       = "67d9556c695ef6c51abf6fbab17acb3466e3149cf4d20cb64d6d34dc969b6502"
    hash2       = "8ccc081d4940c5d8aa6b782c16ed82528c0885bbb08210a8d0a8c519c54215bc"

  strings:
    $s1 = "/root/.hsperfdata" ascii fullword
    $s2 = "Desc|     Filename     |  size  |state|" ascii fullword
    $s3 = "IPv6 address %s not supported" ascii fullword
    $s4 = "File already exist on remote filesystem !" ascii fullword
    $s5 = "/tmp/.sync.pid" ascii fullword
    $s6 = "'gateway' supported only on ethernet/FDDI/token ring/802.11/ATM LANE/Fibre Channel" ascii fullword

  condition:
    uint16(0) == 0x457f and filesize < 5000KB and 4 of them
}

rule SIGNATURE_BASE_APT_MAL_Winntilinux_Dropper_Azazelfork_May19: AZAZEL_FORK FILE {
  meta:
    description = "Detection of Linux variant of Winnti"
    author      = "Silas Cutler (havex [@] chronicle.security), Chronicle Security"
    id          = "d641de9a-e563-5067-b7e4-0aa83a087ed4"
    date        = "2019-05-15"
    modified    = "2023-12-05"
    reference   = "https://github.com/Neo23x0/signature-base"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_winnti_linux.yar#L1-L16"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    hash        = "4741c2884d1ca3a40dadd3f3f61cb95a59b11f99a0f980dbadc663b85eb77a2a"
    logic_hash  = "0af32675dccfd0ad0c7919683fddced6ad49c65800ffa523773b7342b431379f"
    score       = 75
    quality     = 85
    tags        = "AZAZEL_FORK, FILE"
    version     = "1.0"
    TLP         = "White"

  strings:
    $config_decr = { 48 89 45 F0 C7 45 EC 08 01 00 00 C7 45 FC 28 00 00 00 EB 31 8B 45 FC 48 63 D0 48 8B 45 F0 48 01 C2 8B 45 FC 48 63 C8 48 8B 45 F0 48 01 C8 0F B6 00 89 C1 8B 45 F8 89 C6 8B 45 FC 01 F0 31 C8 88 02 83 45 FC 01 }
    $export1     = "our_sockets"
    $export2     = "get_our_pids"

  condition:
    uint16(0) == 0x457f and all of them
}

rule SIGNATURE_BASE_MAL_ELF_SALTWATER_Jun23_1: CVE_2023_2868 FILE {
  meta:
    description = "Detects SALTWATER malware used in Barracuda ESG exploitations (CVE-2023-2868)"
    author      = "Florian Roth"
    id          = "10a038f6-6096-5d3a-aaf5-db441685102b"
    date        = "2023-06-07"
    modified    = "2023-12-05"
    reference   = "https://www.barracuda.com/company/legal/esg-vulnerability"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/mal_lnx_barracuda_cve_2023_2868.yar#L21-L46"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "cb35898c0ee726170da93b4364920ac065f083f9f02db8eb5d293b1ce127cb78"
    score       = 80
    quality     = 85
    tags        = "CVE-2023-2868, FILE"
    hash1       = "601f44cc102ae5a113c0b5fe5d18350db8a24d780c0ff289880cc45de28e2b80"

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
    uint16(0) == 0x457f and filesize < 6000KB and ((1 of ($x*) and 2 of them) or 3 of them) or all of them
}

rule SIGNATURE_BASE_APT_APT41_CN_ELF_Speculoos_Backdoor: FILE {
  meta:
    description = "Detects Speculoos Backdoor used by APT41"
    author      = "Florian Roth (Nextron Systems)"
    id          = "efe2b368-33af-5382-a5f0-0e7dd7f4dea4"
    date        = "2020-04-14"
    modified    = "2023-12-05"
    reference   = "https://unit42.paloaltonetworks.com/apt41-using-new-speculoos-backdoor-to-target-organizations-globally/"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt41.yar#L233-L267"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "ee4cbbc5fc51fb24cbf6017dfb4763ac72a0b23a3b6e794b909e678ebfbabc03"
    score       = 90
    quality     = 85
    tags        = "FILE"
    hash1       = "6943fbb194317d344ca9911b7abb11b684d3dca4c29adcbcff39291822902167"
    hash2       = "99c5dbeb545af3ef1f0f9643449015988c4e02bf8a7164b5d6c86f67e6dc2d28"

  strings:
    $xc1 = {
      2F 70 72 69 76 61 74 65 2F 76 61 72 00 68 77 2E
      70 68 79 73 6D 65 6D 00 68 77 2E 75 73 65 72 6D
      65 6D 00 4E 41 2D 4E 41 2D 4E 41 2D 4E 41 2D 4E
      41 2D 4E 41 00 6C 6F 30 00 00 00 00 25 30 32 78
      2D 25 30 32 78 2D 25 30 32 78 2D 25 30 32 78 2D
      25 30 32 78 2D 25 30 32 78 0A 00 72 00 4E 41 00
      75 6E 61 6D 65 20 2D 76
    }
    $s1  = "badshell" ascii fullword
    $s2  = "hw.physmem" ascii fullword
    $s3  = "uname -v" ascii fullword
    $s4  = "uname -s" ascii fullword
    $s5  = "machdep.tsc_freq" ascii fullword
    $s6  = "/usr/sbin/config.bak" ascii fullword
    $s7  = "enter MessageLoop..." ascii fullword
    $s8  = "exit StartCBProcess..." ascii fullword
    $sc1 = {
      72 6D 20 2D 72 66 20 22 25 73 22 00 2F 70 72 6F
      63 2F
    }

  condition:
    uint16(0) == 0x457f and filesize < 600KB and 1 of ($x*) or 4 of them
}

rule SIGNATURE_BASE_EQGRP_Durablenapkin_Solaris_2_0_1: FILE {
  meta:
    description = "Detects tool from EQGRP toolset - file durablenapkin.solaris.2.0.1.1"
    author      = "Florian Roth (Nextron Systems)"
    id          = "7b49a26d-9ee3-5aff-93fc-509239daef28"
    date        = "2016-08-15"
    modified    = "2023-12-05"
    reference   = "Research"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp.yar#L75-L92"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "113f9451d6792511baa168957c643de02f37826b32944ef882f49b68496ec596"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

  strings:
    $s1 = "recv_ack: %s: Service not supplied by provider" fullword ascii
    $s2 = "send_request: putmsg \"%s\": %s" fullword ascii
    $s3 = "port undefined" fullword ascii
    $s4 = "recv_ack: %s getmsg: %s" fullword ascii
    $s5 = ">> %d -- %d" fullword ascii

  condition:
    (uint16(0) == 0x457f and filesize < 40KB and 2 of them)
}

rule SIGNATURE_BASE_EQGRP_Bc_Parser: FILE {
  meta:
    description = "Detects tool from EQGRP toolset - file bc-parser"
    author      = "Florian Roth (Nextron Systems)"
    id          = "ed4523de-b126-503a-83bd-aafd8533b0e5"
    date        = "2016-08-15"
    modified    = "2023-12-05"
    reference   = "Research"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp.yar#L172-L187"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "e8911acc1173e1149fd11dd795b72ba26bc654cbc7f9d95053ce420663fcafe9"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    hash1       = "879f2f1ae5d18a3a5310aeeafec22484607649644e5ecb7d8a72f0877ac19cee"

  strings:
    $s1 = "*** Target may be susceptible to FALSEMOREL      ***" fullword ascii
    $s2 = "*** Target is susceptible to FALSEMOREL          ***" fullword ascii

  condition:
    uint16(0) == 0x457f and 1 of them
}

rule SIGNATURE_BASE_Install_Get_Persistent_Filenames: FILE {
  meta:
    description = "EQGRP Toolset Firewall - file install_get_persistent_filenames"
    author      = "Florian Roth (Nextron Systems)"
    id          = "cf74b479-4b78-537a-878c-2f3ce004b775"
    date        = "2016-08-16"
    modified    = "2023-12-05"
    reference   = "Research"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp.yar#L237-L250"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "be07e3e3e96dd4676a76b32eb8fc47b2ab1f66ebbd6c2a3f1c88fc224f9f39ef"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    hash1       = "4a50ec4bf42087e932e9e67e0ea4c09e52a475d351981bb4c9851fda02b35291"

  strings:
    $s1 = "Generates the persistence file name and prints it out." fullword ascii

  condition:
    (uint16(0) == 0x457f and all of them)
}

rule SIGNATURE_BASE_EQGRP_Bo: FILE {
  meta:
    description = "EQGRP Toolset Firewall - file bo"
    author      = "Florian Roth (Nextron Systems)"
    id          = "6aa71528-3ce6-5597-bb1a-e44cff3856d6"
    date        = "2016-08-16"
    modified    = "2023-12-05"
    reference   = "Research"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp.yar#L435-L452"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "48c2d3f13283d2a1b7e1010c724f1e68e6002dd9a9779025dfc3a4952bec95bc"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    hash1       = "aa8b363073e8ae754b1836c30f440d7619890ded92fb5b97c73294b15d22441d"

  strings:
    $s1 = "ERROR: failed to open %s: %d" fullword ascii
    $s2 = "__libc_start_main@@GLIBC_2.0" ascii
    $s3 = "serial number: %s" fullword ascii
    $s4 = "strerror@@GLIBC_2.0" fullword ascii
    $s5 = "ERROR: mmap failed: %d" fullword ascii

  condition:
    (uint16(0) == 0x457f and filesize < 20KB and all of them)
}

rule SIGNATURE_BASE_EQGRP_Bpfcreator_RHEL4: FILE {
  meta:
    description = "EQGRP Toolset Firewall - file BpfCreator-RHEL4"
    author      = "Florian Roth (Nextron Systems)"
    id          = "476185f2-b093-5fb9-8604-891e96fe52a9"
    date        = "2016-08-16"
    modified    = "2023-12-05"
    reference   = "Research"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp.yar#L825-L842"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "8586425b13355170137d66fe8d52ed98982d7c5699b26a8c0132f107b4af43d8"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    hash1       = "bd7303393409623cabf0fcf2127a0b81fae52fe40a0d2b8db0f9f092902bbd92"

  strings:
    $s1 = "usage %s \"<tcpdump pcap string>\" <outfile>" fullword ascii
    $s2 = "error reading dump file: %s" fullword ascii
    $s3 = "truncated dump file; tried to read %u captured bytes, only got %lu" fullword ascii
    $s4 = "%s: link-layer type %d isn't supported in savefiles" fullword ascii
    $s5 = "DLT %d is not one of the DLTs supported by this device" fullword ascii

  condition:
    (uint16(0) == 0x457f and filesize < 2000KB and all of them)
}

rule SIGNATURE_BASE_EQGRP_BARPUNCH_BPICKER: FILE {
  meta:
    description = "EQGRP Toolset Firewall - from files BARPUNCH-3110, BPICKER-3100"
    author      = "Florian Roth (Nextron Systems)"
    id          = "7e88ba9d-1f15-533a-b388-a2a027ddb07c"
    date        = "2016-08-16"
    modified    = "2023-12-05"
    reference   = "Research"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp.yar#L902-L921"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "f5d0cc881bedad736a90109933da8dbd32c4435aa255676c68ae3541bbb61e74"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    super_rule  = 1
    hash1       = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
    hash2       = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"

  strings:
    $x1 = "--cmd %x --idkey %s --sport %i --dport %i --lp %s --implant %s --bsize %hu --logdir %s --lptimeout %u" fullword ascii
    $x2 = "%s -c <cmdtype> -l <lp> -i <implant> -k <ikey> -s <port> -d <port> [operation] [options]" fullword ascii
    $x3 = "* [%lu] 0x%x is marked as stateless (the module will be persisted without its configuration)" fullword ascii
    $x4 = "%s version %s already has persistence installed. If you want to uninstall," fullword ascii
    $x5 = "The active module(s) on the target are not meant to be persisted" fullword ascii

  condition:
    (uint16(0) == 0x457f and filesize < 6000KB and 1 of them) or (3 of them)
}

rule SIGNATURE_BASE_EQGRP_Implants_Gen6: FILE {
  meta:
    description = "EQGRP Toolset Firewall"
    author      = "Florian Roth (Nextron Systems)"
    id          = "1b1c6426-7274-5fd4-9ea2-ef10bda769d4"
    date        = "2016-08-16"
    modified    = "2023-12-05"
    reference   = "Research"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp.yar#L923-L951"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "9f0aa1994199c8cef543b7602b574726171dd96df159a0c496db0c60c339c4d0"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    super_rule  = 1
    hash1       = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
    hash2       = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
    hash3       = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
    hash4       = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
    hash5       = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
    hash6       = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"
    hash7       = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"

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
    (uint16(0) == 0x457f and filesize < 6000KB and all of them)
}

rule SIGNATURE_BASE_EQGRP_Implants_Gen5: FILE {
  meta:
    description = "EQGRP Toolset Firewall"
    author      = "Florian Roth (Nextron Systems)"
    id          = "e35748ee-d530-5e73-a74d-5675d05725e9"
    date        = "2016-08-16"
    modified    = "2023-12-05"
    reference   = "Research"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp.yar#L953-L978"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "d4bbd9dbde4ca1da80d49157363ade3ec47d55828529ec7e1a46b64d07c991f0"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    super_rule  = 1
    hash1       = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
    hash2       = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
    hash3       = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
    hash4       = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
    hash5       = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
    hash6       = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
    hash7       = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"
    hash8       = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"

  strings:
    $x1 = "Module and Implant versions do not match.  This module is not compatible with the target implant" fullword ascii
    $s1 = "%s/BF_READ_%08x_%04d%02d%02d_%02d%02d%02d.log" fullword ascii
    $s2 = "%s/BF_%04d%02d%02d.log" fullword ascii
    $s3 = "%s/BF_READ_%08x_%04d%02d%02d_%02d%02d%02d.bin" fullword ascii

  condition:
    (uint16(0) == 0x457f and 1 of ($x*)) or (all of them)
}

rule SIGNATURE_BASE_EQGRP_Bananausurper_Writejetplow: FILE {
  meta:
    description = "EQGRP Toolset Firewall - from files BananaUsurper-2120, writeJetPlow-2130"
    author      = "Florian Roth (Nextron Systems)"
    id          = "901af182-cbfa-533a-a055-565d95005d62"
    date        = "2016-08-16"
    modified    = "2023-12-05"
    reference   = "Research"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp.yar#L1009-L1028"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "101e75800291a7603e03145bff298d7587c9b5f19102e7ba9ed3bf2b544fa5cf"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    super_rule  = 1
    hash1       = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
    hash2       = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"

  strings:
    $x1 = "Implant Version-Specific Values:" fullword ascii
    $x2 = "This function should not be used with a Netscreen, something has gone horribly wrong" fullword ascii
    $s1 = "createSendRecv: recv'd an error from the target." fullword ascii
    $s2 = "Error: WatchDogTimeout read returned %d instead of 4" fullword ascii

  condition:
    (uint16(0) == 0x457f and filesize < 2000KB and 1 of ($x*)) or (3 of them)
}

rule SIGNATURE_BASE_EQGRP_Implants_Gen4: FILE {
  meta:
    description = "EQGRP Toolset Firewall - from files BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120"
    author      = "Florian Roth (Nextron Systems)"
    id          = "8b2061f0-862d-51de-a7d0-7a36d3e71d61"
    date        = "2016-08-16"
    modified    = "2023-12-05"
    reference   = "Research"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp.yar#L1030-L1051"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "3bfcef33e9a0a1753fd21458ee3173284f98942d30a496c5183c79a7df960208"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    super_rule  = 1
    hash1       = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
    hash2       = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
    hash3       = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
    hash4       = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"

  strings:
    $s1 = "Command has not yet been coded" fullword ascii
    $s2 = "Beacon Domain  : www.%s.com" fullword ascii
    $s3 = "This command can only be run on a PIX/ASA" fullword ascii
    $s4 = "Warning! Bad or missing Flash values (in section 2 of .dat file)" fullword ascii
    $s5 = "Printing the interface info and security levels. PIX ONLY." fullword ascii

  condition:
    (uint16(0) == 0x457f and filesize < 3000KB and 3 of them) or (all of them)
}

rule SIGNATURE_BASE_EQGRP_Implants_Gen3: FILE {
  meta:
    description = "EQGRP Toolset Firewall"
    author      = "Florian Roth (Nextron Systems)"
    id          = "ec64bb2b-566b-50b6-a518-222afc88d400"
    date        = "2016-08-16"
    modified    = "2023-12-05"
    reference   = "Research"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp.yar#L1053-L1076"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "32d4dd0e35ea480199f5b2032145326c3eef73243783c580605a4de6877df982"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    super_rule  = 1
    hash1       = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
    hash2       = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
    hash3       = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
    hash4       = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
    hash5       = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
    hash6       = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"

  strings:
    $x1 = "incomplete and must be removed manually.)" fullword ascii
    $s1 = "%s: recv'd an error from the target." fullword ascii
    $s2 = "Unable to fetch the address to the get_uptime_secs function for this OS version" fullword ascii
    $s3 = "upload/activate/de-activate/remove/cmd function failed" fullword ascii

  condition:
    (uint16(0) == 0x457f and filesize < 6000KB and 2 of them) or (all of them)
}

rule SIGNATURE_BASE_EQGRP_Implants_Gen2: FILE {
  meta:
    description = "EQGRP Toolset Firewall"
    author      = "Florian Roth (Nextron Systems)"
    id          = "58b0b51d-d1f8-5ee2-a4af-491c49dd0573"
    date        = "2016-08-16"
    modified    = "2023-12-05"
    reference   = "Research"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_eqgrp.yar#L1137-L1168"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    logic_hash  = "c3cbe11ae38f5affffab247cdc618d0afb5a0feda6ea4b2f43dd8edb2fbf2b11"
    score       = 75
    quality     = 85
    tags        = "FILE"
    license     = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
    super_rule  = 1
    hash1       = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
    hash2       = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
    hash3       = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
    hash4       = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
    hash5       = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
    hash6       = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"

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
    (uint16(0) == 0x457f and filesize < 3000KB and 1 of ($x*)) or (5 of them)
}

rule android_rat_androidTester: Android RAT {
  meta:
    author      = "@_lubiedo"
    date        = "2020-12-02"
    description = "Android Tester"
    malver      = "v.6.4.6"
    version     = "1.0"

  strings:
    $str00 = "Android Tester" fullword
    $str01 = "6.4.4" fullword
    $str02 = "device_admin" fullword
    $res03 = "res/drawable/abc_"
    $res04 = "res/layout/abc_"

  condition:
    uint32be(0) == 0x504B0304  // APK file signature
    and filesize < 1MB and (
      all of ($str*) and any of ($res*)
    )
}

rule linux_miner_doki {
  meta:
    author      = "@_lubiedo"
    description = "Doki Miner"
    reference0  = "https://www.intezer.com/container-security/watch-your-containers-doki-infecting-docker-servers-in-the-cloud/"
    hash0       = "4aadb47706f0fe1734ee514e79c93eed65e1a0a9f61b63f3e7b6367bd9a3e63b"
    date        = "2020-07-31"

  strings:
    $s0 = "/api/v1/address/sent/DP9S4V3TeqRES3Zp7dmD7frAsNExCFKCbx"
    $s1 = "dogechain.info"
    $s2 = "cfltwf\n"
    $s3 = "update.sh"
    $s4 = ".ddns.ne"  // .ddns.ne

  condition:
    uint32(0) == 0x464c457f and filesize < 1MB and all of them
}

rule apt_apt31_rekoobe {
  meta:
    id             = "b1461a72-76ce-4cc5-ac84-3cc87454d288"
    version        = "1.0"
    description    = "Find Rekoobe sample via Trend Elf Hash (telfhash)"
    author         = "Sekoia.io"
    creation_date  = "2023-07-10"
    classification = "TLP:CLEAR"

  condition:
    uint32be(0) == 0x7f454c46 and
    filesize < 100KB and elf.telfhash() == "T18FC080C7C6B56A34A7F32538AC7C407982035E1581561B207F50C955D93B408404C5EF"
}

rule apt_spynote_android_dex_strings {
  meta:
    id             = "87fb8b7a-bfac-4003-b618-50b4a7863928"
    version        = "1.0"
    description    = "Detects Android SpyNote DEX file"
    author         = "Sekoia.io"
    creation_date  = "2022-08-22"
    classification = "TLP:CLEAR"

  strings:
    $ = "is not file found"
    $ = "Can not access"
    $ = "PANG !!"
    $ = "On Start!!"

  condition:
    uint32be(0) == 0x6465780A and
    filesize < 1MB and
    all of them
}

rule exploit_linux_eop_cve202121974_exploit_strings {
  meta:
    id             = "8e1fbbe5-7d51-48b4-80d5-90abff8cab9e"
    version        = "1.0"
    description    = "Detects CVE-2021-21974 Local Privesc exploit"
    author         = "Sekoia.io"
    creation_date  = "2023-12-08"
    classification = "TLP:CLEAR"

  strings:
    $ = ".name.replace('Thread','SLP Client'"
    $ = "print('[' + name + '] recv: ', d)"
    $ = "requests[28].put(connect())"
    $ = "[+] stack enviorn address:"

  condition:
    uint32be(0) == 0x7f454c46 and filesize < 1MB and all of them
}

rule exploit_linux_eop_dirtyc0w_strings {
  meta:
    id             = "f0551e56-b08f-4f6f-81df-f30fbb8ee7b8"
    version        = "1.0"
    description    = "Detects DirtyCow exploit"
    author         = "Sekoia.io"
    creation_date  = "2023-12-08"
    classification = "TLP:CLEAR"

  strings:
    $ = "DirtyCow root privilege escalation"
    $ = "Backing up %s to /tmp/bak"
    $ = "(o o)_____/"

  condition:
    uint32be(0) == 0x7f454c46 and filesize < 1MB and all of them
}

rule exploit_linux_eop_rationallove_strings {
  meta:
    id             = "e71e026e-ca2c-42b7-b552-b3fd013676db"
    version        = "1.0"
    description    = "Detects RationalLove Local Privesc exploit"
    author         = "Sekoia.io"
    creation_date  = "2023-12-08"
    classification = "TLP:CLEAR"

  strings:
    $ = "../x/../../AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/"
    $ = "Detected OS version: %s"
    $ = "Content-Type: text/plain; charset=UTF-8"

  condition:
    uint32be(0) == 0x7f454c46 and filesize < 1MB and all of them
}

rule merlin_linux_elf {
  meta:
    id             = "d9c57f5e-26c3-43be-b2cf-10f5129d3be6"
    author         = "Sekoia.io"
    creation_date  = "2022-01-03"
    description    = "Detects Merling agent (ELF)"
    version        = "1.0"
    classification = "TLP:CLEAR"

  strings:
    $s1 = "github.com/Ne0nd0g/merlin" ascii
    $s2 = "github.com/refraction-networking" ascii
    $s3 = "SendMerlinMessage" ascii

  condition:
    uint32(0) == 0x464c457f
    and for any i in (0..elf.sections.len() - 1): (
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "80199718ff1821a3fe914cd2279ab3a0"
    )
    and for any i in (0..elf.sections.len() - 1): (
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "7dea362b3fac8e00956a4952a3d4f474"
    )
    and for any i in (0..elf.sections.len() - 1): (
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "d41d8cd98f00b204e9800998ecf8427e"
    )
    and for any i in (0..elf.sections.len() - 1): (
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "91476dafa5ef669483350538fa6ec4cb"
    )
    and all of them
    and filesize < 15MB
}

rule ransomware_linux_icefire_2023 {
  meta:
    id             = "b04964f4-3fdc-4745-9f4a-95a5a79bc7e1"
    version        = "1.0"
    description    = "Rule to detect Linux IceFire ransomware samples."
    author         = "Sekoia.io"
    creation_date  = "2023-02-13"
    classification = "TLP:CLEAR"
    hash1          = "e9cc7fdfa3cf40ff9c3db0248a79f4817b170f2660aa2b2ed6c551eae1c38e0b"

  strings:
    $string01 = "********************Your network has been infected!!!********************"
    $string02 = "IMPORTANT : DO NOT DELETE THIS FILE UNTIL ALL YOUR DATA HAVE BEEN RECOVERED!!!"
    $string03 = "username:"
    $string04 = "password:"
    $string05 = ".cfg.o.sh.img.txt.xml.jar.pid.ini.pyc.a.so.run.env.cache.xmlb"
    $string06 = "./boot./dev./etc./lib./proc./srv./sys./usr./var./run"
    $string07 = "/iFire-readme.txt"
    $string08 = ".iFire"
    $string09 = "iFire.pid"

  condition:
    uint32be(0) == 0x7F454C46 and all of them
}

rule ransomware_lin_avoslocker_sections {
  meta:
    id             = "3a7bf14d-24fb-47c9-b073-dd734f808983"
    version        = "1.0"
    description    = "Detect AvosLocker ransomware for Linux by using its section hashes"
    author         = "Sekoia.io"
    creation_date  = "2022-02-21"
    classification = "TLP:CLEAR"
    hash1          = "0cd7b6ea8857ce827180342a1c955e79c3336a6cf2000244e5cfd4279c5fc1b6"
    hash2          = "7c935dcd672c4854495f41008120288e8e1c144089f1f06a23bd0a0f52a544b1"
    hash3          = "10ab76cd6d6b50d26fde5fe54e8d80fceeb744de8dbafddff470939fac6a98c4"

  condition:
    uint32(0) == 0x464c457f and
    for any i in (0..elf.sections.len() - 1): (hash.md5(elf.sections[i].offset, elf.sections[i].size) == "91476dafa5ef669483350538fa6ec4cb")
    and for any i in (0..elf.sections.len() - 1): (hash.md5(elf.sections[i].offset, elf.sections[i].size) == "c2b21b2556c9d751e203965c825f8a81")
    and for any i in (0..elf.sections.len() - 1): (hash.md5(elf.sections[i].offset, elf.sections[i].size) == "f858d36231ba743ad8c898d86a67a864")
    and for any i in (0..elf.sections.len() - 1): (hash.md5(elf.sections[i].offset, elf.sections[i].size) == "7dea362b3fac8e00956a4952a3d4f474")
    and for any i in (0..elf.sections.len() - 1): (hash.md5(elf.sections[i].offset, elf.sections[i].size) == "489c87d7b1a694980587dfb413fb2afc")
    and for any i in (0..elf.sections.len() - 1): (hash.md5(elf.sections[i].offset, elf.sections[i].size) == "972e27e9f115278244f5e4ae89dd412a")
    and for any i in (0..elf.sections.len() - 1): (hash.md5(elf.sections[i].offset, elf.sections[i].size) == "d1f5b688a92b611e1363945fa552a9d7")
}

rule ransomware_lin_avoslocker_strings {
  meta:
    version        = "1.0"
    description    = "Detect AvosLocker ransomware for Linux by using strings from its ransom note and the onion domains"
    author         = "Sekoia.io"
    creation_date  = "2022-02-21"
    classification = "TLP:CLEAR"
    hash1          = "0cd7b6ea8857ce827180342a1c955e79c3336a6cf2000244e5cfd4279c5fc1b6"
    hash2          = "7c935dcd672c4854495f41008120288e8e1c144089f1f06a23bd0a0f52a544b1"
    hash3          = "10ab76cd6d6b50d26fde5fe54e8d80fceeb744de8dbafddff470939fac6a98c4"
    id             = "6056e15c-d656-41cb-bea0-704776c52c92"

  strings:
    $s1 = "The corporations whom don't pay or fail to respond in a swift manner can be found in our blog, accessible at" ascii
    $s2 = "http://avosqxh72b5ia23dl5fgwcpndkctuzqvh2iefk5imp3pi5gfhel5klad.onion" ascii
    $s3 = "http://avosjon4pfh3y7ew3jdwz6ofw7lljcxlbk7hcxxmnxlh5kvf2akcqjad.onion" ascii

  condition:
    uint32(0) == 0x464c457f and all of them
}

rule rootkit_lin_winnti {
  meta:
    id             = "c800038e-7f8a-4f24-bf0b-06aba6a828cb"
    version        = "1.0"
    description    = "Rootkit used by Winnti"
    author         = "Sekoia.io"
    creation_date  = "2024-05-22"
    classification = "TLP:CLEAR"
    reference      = "https://x.com/naumovax/status/1792902386295394629"
    hash1          = "161344ae61278e09eacb1c76508cda45555eee109e6d6a031716a096ab5c84f3"
    hash2          = "bb56e088739b281c9f56b4fa3fa4d285e45b32c4f9f06b647d7e8cb916054e1a"
    hash3          = "777c1fda4008f122ff3aef9e80b5b5720c9f2dbc3d7e708277e2ccad1afd8cc5"
    hash4          = "9c770b12a2da76c41f921f49a22d7bc6b5a1166875b9dc732bc7c05b6ae39241"

  strings:
    $ = "[CDATA[%s]]></name><type>%o</type><perm>%o</perm><user>%s:%s</user><size>%llu</size><time>%s</time></LIST>"
    $ = "HideFile"
    $ = "DownThread"
    $ = "PortforwardThread"
    $ = "HidePidPort"
    $ = "DownFile"
    $ = "ReadReConnConf"
    $ = "DecRemotePort"
    $ = "DecRemoteIP"

  condition:
    uint32(0) == 0x464c457f
    and 6 of them
    and for any i in (0..elf.sections.len() - 1): (
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "7dea362b3fac8e00956a4952a3d4f474"
    )
}

rule spyware_and_bahamut {
  meta:
    id             = "d416997e-baf1-412c-bf39-905a6e19b65e"
    version        = "1.0"
    description    = "Detect Bahamut's spyware based on common information gathering function names"
    author         = "Sekoia.io"
    creation_date  = "2022-11-23"
    classification = "TLP:CLEAR"
    reference      = "https://www.welivesecurity.com/2022/11/23/bahamut-cybermercenary-group-targets-android-users-fake-vpn-apps/"
    hash1          = "c51dc2132c830c560aaeae4bf48e5f0d28c84b36d27840b5c2ba170d87f4afa5"
    hash2          = "d7e2cf642b236dba9ba0cbe5a9dc28baf22477973d5ce163e21ec40f5f26e078"

  strings:
    $ = "FbDao"
    $ = "SignalDao"
    $ = "conionDao"

  condition:
    all of them
}

rule tool_enum4linux_strings {
  meta:
    id             = "6b3094fe-1292-4da3-a1ed-9e255be531da"
    version        = "1.0"
    description    = "Detects enum4linux based on strings"
    author         = "Sekoia.io"
    creation_date  = "2024-02-02"
    classification = "TLP:CLEAR"

  strings:
    $ = "my $os_info = `$command`;"
    $ = "($global_workgroup) = $os_info =~"
    $ = "sub enum_groups {"
    $ = "if ($shares =~ /NT_STATUS_ACCESS_DENIED/) {"
    $ = "Can't open share list file $shares_file"
    $ = "my $users = `$command`;"
    $ = "my @shares = <SHARES>;"
    $ = "foreach my $grouptype (\"builtin\", \"domain\") {"

  condition:
    6 of them
}

rule trojan_android_brata {
  meta:
    id             = "fde9b82e-c677-44ed-b512-b225a3aba201"
    author         = "Sekoia.io"
    creation_date  = "2022-01-27"
    description    = "Detect samples of the Android banking trojan BRATA"
    version        = "1.0"
    classification = "TLP:CLEAR"

  strings:
    $goo0 = "Google Play services error"
    $goo1 = "Error de Serveis de Google Play"
    $goo2 = "Fehler bei Zugriff auf Google Play-Dienste"
    $goo3 = "Erro nos servizos de Google Play"
    $goo4 = "Fout met Google Play-services"
    $goo5 = "Virhe Google Play -palveluissa"
    $goo6 = "Erro do Google Play Services"
    $goo7 = "Error de Google Play Services"

    $res0 = "res/xml/device_admin.xml"
    $res1 = "res/xml/windowchangedetectingservice.xml"
    $res2 = "res/xml-v22/windowchangedetectingservice.xml"

  condition:
    uint32be(0) == 0x504B0304
    and filesize > 2MB
    and filesize < 6MB
    and 7 of ($goo*) and 2 of ($res*)
}

rule trojan_android_cerberus {
  meta:
    id             = "3ea398bd-a80c-40f4-ad52-73b528add4ad"
    author         = "Sekoia.io"
    creation_date  = "2022-01-24"
    description    = "Detect samples of the Android banking trojan Cerberus, or its family"
    version        = "1.0"
    classification = "TLP:CLEAR"

  strings:
    $str0 = "assets/neurax.txt"
    $str1 = "assets/Card_UpPotency_UI.json"
    $str2 = "assets/Card_SignetFoster_UI.json"
    $str3 = "assets/Gene_EmpathyTrainer.png"

    $bin0 = "assets/180417.bin"
    $bin1 = "assets/180513.bin"
    $bin2 = "assets/180527.bin"
    $bin3 = "assets/180528.bin"

  condition:
    uint32be(0) == 0x504B0304
    and filesize > 1MB
    and filesize < 4MB
    and 3 of ($str*) and 3 of ($bin*)
}

rule trojan_android_xenomorph {
  meta:
    id             = "ec65ca1b-e71f-4772-8be0-2a2b6a690987"
    author         = "Sekoia.io"
    creation_date  = "2022-02-25"
    description    = "Detect samples of the Android banking trojan Xenomorph"
    version        = "1.0"
    classification = "TLP:CLEAR"

  strings:
    $ass0 = "assets/shadows/knife_shadow_"
    $ass1 = "assets/knife_"
    $ass2 = "okhttp3"

  condition:
    uint32be(0) == 0x504B0304
    and filesize > 1MB
    and filesize < 4MB
    and #ass0 > 10 and #ass1 > 10 and $ass2
}

rule trojan_and_keepspy {
  meta:
    id             = "9390e7c8-a996-45cc-b642-c23d4b7dcf34"
    version        = "1.0"
    description    = "Finds KeepSpy samples based on specific strings"
    author         = "Sekoia.io"
    creation_date  = "2023-06-28"
    classification = "TLP:CLEAR"

  strings:
    $str01 = "Characters entered %1$d of %2$d" ascii
    $str02 = "com.google.android.material.behavior.HideBottomViewOnScrollBehavior" ascii
    $str03 = "com/j256/ormlite/core/VERSION.txt" ascii
    $str04 = "res/raw/empty.wav" ascii
    $str05 = "res/mipmap/ic_launcher.png" ascii
    $str06 = "res/interpolator/fast_out_slow_in.xml" ascii
    $str07 = "OnePixelActivity" ascii

  condition:
    uint32be(0) == 0x504B0304 and 6 of them
    and filesize > 2MB
}

rule dropper_ren: realshell android {
  meta:
    author    = "https://twitter.com/plutec_net"
    reference = "https://koodous.com/"
    source    = "https://blog.malwarebytes.org/mobile-2/2015/06/complex-method-of-obfuscation-found-in-dropper-realshell/"

  strings:
    $b = "Decrypt.malloc.memset.free.pluginSMS_encrypt.Java_com_skymobi_pay_common_util_LocalDataDecrpty_Encrypt.strcpy"

  condition:
    $b
}





rule marcher3 {
  meta:
    author  = "Antonio S. <asanchez@koodous.com>"
    source  = "https://analyst.koodous.com/rulesets/890"
    sample1 = "087710b944c09c3905a5a9c94337a75ad88706587c10c632b78fad52ec8dfcbe"
    sample2 = "fa7a9145b8fc32e3ac16fa4a4cf681b2fa5405fc154327f879eaf71dd42595c2"

  strings:
    $a = "certificado # 73828394"
    $b = "A compania TMN informa que o vosso sistema Android tem vulnerabilidade"

  condition:
    all of them
}

rule android_metasploit: android {
  meta:
    author      = "https://twitter.com/plutec_net"
    description = "This rule detects apps made with metasploit framework"
    sample      = "cb9a217032620c63b85a58dde0f9493f69e4bda1e12b180047407c15ee491b41"

  strings:
    $a = "*Lcom/metasploit/stage/PayloadTrustManager;"
    $b = "(com.metasploit.stage.PayloadTrustManager"
    $c = "Lcom/metasploit/stage/Payload$1;"
    $d = "Lcom/metasploit/stage/Payload;"

  condition:
    all of them

}

rule SlemBunk: android {
  meta:
    description = "Rule to detect trojans imitating banks of North America, Eurpope and Asia"
    author      = "@plutec_net"
    sample      = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
    source      = "https://www.fireeye.com/blog/threat-research/2015/12/slembunk_an_evolvin.html"

  strings:
    $a = "#intercept_sms_start"
    $b = "#intercept_sms_stop"
    $c = "#block_numbers"
    $d = "#wipe_data"
    $e = "Visa Electron"

  condition:
    all of them

}

rule smsfraud1: android {
  meta:
    author      = "Antonio Sánchez https://twitter.com/plutec_net"
    reference   = "https://koodous.com/"
    description = "This rule detects a kind of SMSFraud trojan"
    sample      = "265890c3765d9698091e347f5fcdcf1aba24c605613916820cc62011a5423df2"
    sample2     = "112b61c778d014088b89ace5e561eb75631a35b21c64254e32d506379afc344c"

  strings:
    $a = "E!QQAZXS"
    $b = "__exidx_end"
    $c = "res/layout/notify_apkinstall.xmlPK"

  condition:
    all of them

}

rule smsfraud2: android {
  meta:
    author    = "Antonio Sánchez https://twitter.com/plutec_net"
    reference = "https://koodous.com/"
    sample    = "0200a454f0de2574db0b58421ea83f0f340bc6e0b0a051fe943fdfc55fea305b"
    sample2   = "bff3881a8096398b2ded8717b6ce1b86a823e307c919916ab792a13f2f5333b6"

  strings:
    $a = "pluginSMS_decrypt"
    $b = "pluginSMS_encrypt"
    $c = "__dso_handle"
    $d = "lib/armeabi/libmylib.soUT"
    $e = "]Diok\"3|"

  condition:
    all of them
}

rule tachi: android {
  meta:
    author      = "https://twitter.com/plutec_net"
    source      = "https://analyst.koodous.com/rulesets/1332"
    description = "This rule detects tachi apps (not all malware)"
    sample      = "10acdf7db989c3acf36be814df4a95f00d370fe5b5fda142f9fd94acf46149ec"

  strings:
    $a      = "svcdownload"
    $xml_1  = "<config>"
    $xml_2  = "<apptitle>"
    $xml_3  = "<txinicio>"
    $xml_4  = "<txiniciotitulo>"
    $xml_5  = "<txnored>"
    $xml_6  = "<txnoredtitulo>"
    $xml_7  = "<txnoredretry>"
    $xml_8  = "<txnoredsalir>"
    $xml_9  = "<laurl>"
    $xml_10 = "<txquieresalir>"
    $xml_11 = "<txquieresalirtitulo>"
    $xml_12 = "<txquieresalirsi>"
    $xml_13 = "<txquieresalirno>"
    $xml_14 = "<txfiltro>"
    $xml_15 = "<txfiltrourl>"
    $xml_16 = "<posicion>"

  condition:
    $a and 4 of ($xml_*)
}

rule MAL_ARM_LNX_Mirai_Mar13_2022 {
  meta:
    description = "Detects new ARM Mirai variant"
    author      = "Mehmet Ali Kerimoglu a.k.a. CYB3RMX"
    date        = "2022-03-13"
    hash1       = "0283b72913b8a78b2a594b2d40ebc3c873e4823299833a1ff6854421378f5a68"

  strings:
    $str1   = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/lib1funcs.asm"
    $str2   = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/lib1funcs.asm"
    $str3   = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm"
    $str4   = "/home/landley/aboriginal/aboriginal/build/simple-cross-compiler-armv6l/bin/../cc/include"
    $attck1 = "attack.c"
    $attck2 = "attacks.c"
    $attck3 = "anti_gdb_entry"
    $attck4 = "resolve_cnc_addr"
    $attck5 = "attack_gre_eth"
    $attck6 = "attack_udp_generic"
    $attck7 = "attack_get_opt_ip"
    $attck8 = "attack_icmpecho"

  condition:
    uint16(0) == 0x457f and ((3 or all of ($str*)) or (4 or all of ($attck*)))
}

rule Linux_x86_64_Mirai_shellcode_Variant_2022_03_17 {
  meta:
    description = "Detects new x86_64 Mirai variant"
    author      = "Mehmet Ali Kerimoglu a.k.a. CYB3RMX"
    date        = "2022-03-17"
    hash1       = "220935a9c5f6de63ef0d7c63e6f9ba3033e962854ca1911e770de2578d3d7e35"

  strings:
    $mstr1 = "142.93.140.12:23" wide ascii
    $mstr2 = "[Shelling]-->[%s]-->[%s]-->[%s]-->[%s]-->[%s]" wide ascii
    $mstr3 = "been_there_done_that.3160" wide ascii
    $mstr4 = "Sending TCP Packets To: %s:%d for %d seconds" wide ascii
    $ppp1  = "/etc/apt/apt.conf" wide ascii
    $ppp2  = "/etc/yum.conf" wide ascii

  condition:
    uint16(0) == 0x457f and ((3 or all of ($mstr*)) and (all of ($ppp*)))
}

rule Kaiten {
  meta:
    description = "Linux IRC DDoS Malware"
    family      = "Linux.Backdoor.Kaiten"
    filetype    = "ELF"
    hash        = "6b5386d96b90a4cb811c5ddd6f35f6b0d4c65c69c8160216077e7a0f43a8888d"
    hash        = "965a9594ef80e7134e1a9e5a4cce0a3dce98636107d1f6410224386dfccb9d5b"
    hash        = "2c772242de272bff1bb940b0687445739ec544aceec1bc5591a374a57cd652b5"

  strings:
    $irc     = /(PING)|(PONG)|(NOTICE)|(PRIVMSG)/
    $kill    = "Killing pid %d" nocase
    $subnet  = "What kind of subnet address is that" nocase
    $version = /(Helel mod)|(Kaiten wa goraku)/
    $flood   = "UDP <target> <port> <secs>" nocase

  condition:
    elf.type == elf.ET_EXEC and $irc and
    2 of ($kill, $subnet, $version, $flood)
}

rule apt_CN_31_sowat_code {
  meta:
    author      = "@imp0rtp3"
    description = "Apt31 router implant (SoWaT) unique code (relevant only for MIPS)"
    reference   = "https://imp0rtp3.wordpress.com/2021/11/25/sowat/"

  strings:
    $c1 = { 25 38 00 00 [8] 38 00 1? 9A 09 F8 20 03 2? 20 A0 02 10 40 92 8E }
    $c2 = { 06 00 30 12 25 20 00 02 04 00 70 12 00 00 00 00 09 F8 20 03 00 00 00 00 ?? 00 BC 8F 01 00 10 26 }
    $c3 = { 00 01 02 24 25 38 00 00 02 00 06 24 ?? 00 A2 A7 09 F8 20 03 ?? 00 A5 27 }
    $c4 = { 09 F8 20 03 25 20 ?0 02 0B 00 02 24 0? 00 22 12 ?? 00 BC 8F }
    $c5 = { ?5 26 ?? 00 BC 8F ?? ?? 99 8F 09 F8 20 03 10 00 04 24 ?? ?? ?5 26 ?? 00 BC 8F ?? ?? 99 8F 09 F8 20 03 0F 00 04 24 01 00 05 24 ?? 00 BC 8F ?? ?? 99 8F 09 F8 20 03 0D 00 04 24 ?? ?? ?5 26 ?? 00 BC 8F ?? ?? 99 8F 09 F8 20 03 0A 00 04 24 }
    $c6 = { 08 00 03 3C ?? ?? 99 8F 04 00 05 24 80 00 63 24 25 20 00 0? 09 F8 20 03 25 30 43 00 ?? 00 40 04 ?? 00 BC 8F ?? ?? 99 8F 01 00 05 24 09 F8 20 03 0D 00 04 24 }

  condition:
    uint32(0) == 0x464c457f and
    filesize < 2MB and
    (
      elf.machine == elf.EM_MIPS_RS3_LE or
      elf.machine == elf.EM_MIPS
    ) and 4 of ($c*)

}

rule ELF_RANSOMWARE_BLACKCAT: LinuxMalware {
  meta:
    description               = "Detect Linux version of BlackCat Ransomware"
    author                    = "Jesper Mikkelsen"
    reference                 = "https://www.virustotal.com/gui/file/056d28621dca8990caf159f8e14069a2343b48146473d2ac586ca9a51dfbbba7"
    date                      = "2022-05-10"
    yarahub_reference_md5     = "c7e39ead7df59e09be30f8c3ffbf4d28"
    yarahub_uuid              = "4354fe5a-ee0c-47e3-a595-2824dd82928d"
    yarahub_license           = "CC0 1.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp  = "TLP:WHITE"
    techniques                = "File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification"
    tactic                    = "Defense Evasion"
    mitre_att                 = "T1222.002"
    sharing                   = "TLP:WHITE"
    dname                     = "Ransom.Linux.BLACKCAT.YXCDFZ"
    score                     = 75

  strings:
    $pattern0 = "sbin*/cdrom*/dev*/etc*/lib**lost+found*/proc*/run*/snap*/tmp*/sys*/usr*/bi"
    $pattern1 = "n `vim-cmd vmsvc/getallvms| awk '{print$1}'`;do vim-cmd vmsvc/sn"
    $pattern2 = {
      BB 6C EA 3F AA 84 31 C4 13 19 F2
      4C 47 F1 29 B7 FE 88 43 CA EF 60
      98 31 56 7A 97 30 CD 92 4C CB 74
      EB 26 B6 65 03 FD 4D DC D1 A1 A7
      CC 39 7A 5C 75 40 10 21 64 A8 CB
      DA DD B2 C4 DB 46 5A 1F 20
    }
    $pattern3 = {
      78 15 58 9C 99 1A C5 47 BC 7B B9
      31 5D 74 24 C7 E9 E0 72 B1 08 EF
      EF 6A 2D 8E 93 1C CC 81 0E DC 66
      4C 6B AA 87 43 F6 71 A2 22 8A 07
      43 2D 17 9D CB 0B 27 EB 2A 04 BA
      30 0F 65 C6 46 EE 6A 5B 86
    }
    $pattern4 = {
      72 78 B3 93 0F 69 5B 48 F4 D0 89
      14 1E C0 61 CF E5 79 18 A5 98 68
      F0 7E 63 D1 EA 71 62 4A 02 AA 99
      F3 7B C0 E4 E2 93 1B 1F 5B 0E D8
      97 0F E6 03 6C B6 9F 69 11 A7 77
      B2 EA 1E 6D BD EB 85 85 66
    }
    $pattern5 = {
      39 67 68 97 DB 59 03 55 34 5A B8
      62 DF 64 D3 A0 30 D1 0A 58 A9 EF
      61 9A 46 EC DA AD AD D2 B1 6F 42
      AB AA B3 A0 95 C1 71 4F 96 7A 46
      A4 A8 11 84 4B 25 4A 8F BA 1B 21
      4D 55 18 9A 7A BE 26 F1 B8 51
    }
    $pattern6 = {
      4B 35 35 C4 3D D4 3A 59 A7 5C 1C
      69 D1 BD 13 F4 0A 98 72 88 7C 79
      7D 15 BC D3 B0 70 CA 32 BF ED 11
      17 DE 91 67 F6 D1 0C 91 42 45 5A
      E7 A3 4A C7 3C 86 2B BB 4A 67 24
      26 8A CD E9 43 FC 2C E6 DE 27 09
      87 A2 51 E8 88 3F
    }
    $pattern7 = {
      6B DA AE D5 B0 21 17 CF BF 20 8C
      27 64 DB 35 5E 0E A6 24 B6 D5 5D
      9D 2B 16 D5 C9 C3 CD 2E 70 BA A7
      53 61 52 7C A8 D8 48 73 A9 43 A0
      A8 52 FA D9 C2 2F EB 31 19 D4 52
      BB F0 87 4E 53 2B 7C F7 2A 41 01
      E6 C2 9A FA 5F D8 95 FB C4
    }

  condition:
    all of them
}

rule elf_rekoobe_b3_06c9 {
  meta:
    author                    = "Johannes Bader"
    date                      = "2022-09-02"
    description               = "detects the Rekoobe Linux backdoor"
    hash1_md5                 = "55ab7e652976d25997875f678c935de7"
    hash1_sha1                = "dc6beb5019ee21ab207c146ece5080d00f20a103"
    hash1_sha256              = "a89ebd7157336141eb14ed9084491cc5bdfce103b4db065e433dff47a1803731"
    tlp                       = "TLP:WHITE"
    version                   = "v1.0"
    yarahub_author_email      = "yara@bin.re"
    yarahub_author_twitter    = "@viql"
    yarahub_license           = "CC BY-SA 4.0"
    yarahub_reference_md5     = "55ab7e652976d25997875f678c935de7"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp  = "TLP:WHITE"
    yarahub_uuid              = "06c95657-8897-443c-bc8e-f0f5cf6cf055"

  strings:
    $sha_1 = { 01 23 45 67 [0-10] 89 AB CD EF [0-10] FE DC BA 98 [0-10] 76 54 32 10 [0-10] F0 E1 D2 C3 }

    $hmac_1 = "66666666"
    $hmac_2 = "\\\\\\\\\\\\\\\\"

    $str_term_1 = { C6 00 54 }
    $str_term_2 = { C6 40 03 4D }
    $str_term_3 = { C6 40 01 45 }
    $str_term_4 = { C6 40 04 3D }
    $str_term_5 = { C6 40 02 52 }
    $str_term_6 = { C6 40 02 52 }

    $str_histfile_1 = { C6 00 48 }
    $str_histfile_2 = { C6 40 05 49 }
    $str_histfile_3 = { C6 40 01 49 }
    $str_histfile_4 = { C6 40 06 4C }
    $str_histfile_5 = { C6 40 02 53 }
    $str_histfile_6 = { C6 40 07 45 }
    $str_histfile_7 = { C6 40 03 54 }
    $str_histfile_8 = { C6 40 08 3D }
    $str_histfile_9 = { C6 40 04 46 }

  condition:
    uint32(0) == 0x464C457F and
    (
      all of them
    )
}

rule IOC_MIRAI_elf {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_MIRAI_LAB"
    date_IOC   = "2023-11-14 06:10:22"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "MIRAI"
    file_type  = "elf"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "c8112fddbfed0adfa62343a770dc09984c306063cfe01e4989f8a96893fdb908" or
    hash.sha256(0, filesize) == "0e9ec7fffe192bb53a79d9a71ba74884bc9493cc55c6e363e7ad952c53da25fe" or
    hash.sha256(0, filesize) == "eec68e0190cb6b7683556b3fde3922936b0b0a70d0efd2062c53c87f2adfdb1f" or
    hash.sha256(0, filesize) == "0433abed1161da8a9c18a8855f9a65d9dd2ce66392107e989e058e510033f26e" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}

private rule IRC {
  strings:
    $ = "USER" fullword nocase
    $ = "PASS" fullword nocase
    $ = "PRIVMSG" fullword nocase
    $ = "MODE" fullword nocase
    $ = "PING" fullword nocase
    $ = "PONG" fullword nocase
    $ = "JOIN" fullword nocase
    $ = "PART" fullword nocase

  condition:
    5 of them
}

rule GodLua_Linux: linuxmalware {
  meta:
    Author  = "Adam M. Swanda"
    Website = "https://www.deadbits.org"
    Repo    = "https://github.com/deadbits/yara-rules"
    Date    = "2019-07-18"

  strings:
    $tmp0 = "/tmp" ascii fullword
    $tmp1 = "TMPDIR" ascii

    $str1  = "\"description\": \"" ascii fullword
    $str2  = "searchers" ascii fullword
    $str3  = "/dev/misc/watchdog" ascii fullword
    $str4  = "/dev/wdt" ascii fullword
    $str5  = "/dev/misc/wdt"
    $str6  = "lcurl.safe" ascii fullword
    $str7  = "luachild" ascii fullword
    $str8  = "cjson.safe" ascii fullword
    $str9  = "HostUrl" ascii fullword
    $str10 = "HostConnect" ascii fullword
    $str11 = "LUABOX" ascii fullword
    $str12 = "Infinity" ascii fullword
    $str13 = "/bin/sh" ascii fullword
    $str14 = /\.onion(\.)?/ ascii fullword
    $str15 = "/etc/resolv.conf" ascii fullword
    $str16 = "hosts:" ascii fullword

    $resolvers = /([0-9]{1,3}\.){3}[0-9]{1,3}:53,([0-9]{1,3}\.){3}[0-9]{1,3},([0-9]{1,3}\.){3}[0-9]{1,3}:5353,([0-9]{1,3}\.){3}[0-9]{1,3}:443/ ascii

    $identifier0 = "$LuaVersion: God " ascii
    $identifier1 = /fbi\/d\.\/d.\/d/ ascii
    $identifier2 = "Copyright (C) FBI Systems, 2012-2019, https://fbi.gov" fullword ascii
    $identifier3 = "God 5.1"

  condition:
    uint16(0) == 0x457f
    and
    (
      all of them
      or
      (
        any of ($identifier*)
        and $resolvers
        and any of ($tmp*)
        and 4 of ($str*)
      )
      or
      (
        any of ($identifier*)
        and any of ($tmp*)
        and 4 of ($str*)
      )
    )
}

rule apt_malware_apk_badsignal_Jun23_c: EvilBamboo {
  meta:
    author        = "threatintel@volexity.com"
    description   = "Detection of the android variant of the BADSIGNAL malware."
    date          = "2023-06-15"
    hash1         = "f0bf154d1e90491199b66ab95c1a4071669f3322c55f3643e36c20a9fb63eb56"
    scan_context  = "file"
    last_modified = "2023-06-15T14:50Z"
    license       = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

  strings:
    $s1 = "clientlogin" fullword
    $s2 = "TibetOne" fullword
    $s3 = "Success,picture saved at" fullword
    $s4 = "Failed,please try again" fullword
    $s5 = ":4432"
    $s6 = "DeviceInfo" fullword
    $s7 = "com.holy.tibetone"

    $info1  = "imeiinfo" fullword
    $info2  = "raimei" fullword
    $info3  = "imei" fullword
    $info4  = "latitude" fullword
    $info5  = "longitude" fullword
    $info6  = "altitude" fullword
    $info7  = "wifiinfo" fullword
    $info8  = "dns1" fullword
    $info9  = "dns2" fullword
    $info10 = "wifi not open " fullword  //space intentional
    $info11 = "bssid" fullword
    $info12 = "CHINA MOBILE" fullword

  condition:
    (
      // dex
      uint32be(0) == 0x6465780a or
      // pk
      uint16be(0) == 0x504b
    )
    and 3 of ($s*)
    and 6 of ($info*)
}

rule apt_malware_apk_badsignal_Jun23_b: EvilBamboo {
  meta:
    author        = "threatintel@volexity.com"
    date          = "2023-06-08"
    description   = "Detect the BADSIGNAL Android malware."
    hash1         = "549d726fe2b775cfdd1304c2d689dfd779731336a3143225dc3c095440f69ed0"
    scan_context  = "file"
    last_modified = "2023-06-13T12:06Z"
    license       = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

  strings:
    $api1 = "Location?imei="
    $api2 = "clientLogin?imei="
    $api3 = "QRCode?imei="

  condition:
    (
      // dex
      uint32be(0) == 0x6465780a or
      // pk
      uint16be(0) == 0x504b
    )
    and all of them
}

rule HackingTeam_Android: Android Implant {
  meta:
    description = "HackingTeam Android implant, known to detect version v4 - v7"
    author      = "Tim 'diff' Strazzere <strazz@gmail.com>"
    reference   = "http://rednaga.io/2016/11/14/hackingteam_back_for_your_androids/"
    date        = "2016-11-14"
    version     = "1.0"

  strings:
    $decryptor          = {
      12 01              // const/4 v1, 0x0
      D8 00 ?? ??        // add-int/lit8 ??, ??, ??
      6E 10 ?? ?? ?? 00  // invoke-virtual {??} -> String.toCharArray()
      0C 04              // move-result-object v4
      21 45              // array-length v5, v4
      01 02              // move v2, v0
      01 10              // move v0, v1
      32 50 11 00        // if-eq v0, v5, 0xb
      49 03 04 00        // aget-char v3, v4, v0
      DD 06 02 5F        // and-int/lit8 v6, v2, 0x5f <- potentially change the hardcoded xor bit to ??
      B7 36              // xor-int/2addr v6, v3
      D8 03 02 ??        // and-int/lit8 v3, v2, ??
      D8 02 00 01        // and-int/lit8 v2, v0, 0x1
      8E 66              // int-to-char v6, v6
      50 06 04 00        // aput-char v6, v4, v0
      01 20              // move v0, v2
      01 32              // move v2, v3
      28 F0              // goto 0xa
      71 30 ?? ?? 14 05  // invoke-static {v4, v1, v5}, ?? -> String.valueOf()
      0C 00              // move-result-object v0
      6E 10 ?? ?? 00 00  // invoke-virtual {v0} ?? -> String.intern()
      0C 00              // move-result-object v0
      11 00              // return-object v0
    }
    // Below is the following string, however encoded as it would appear in the string table (length encoded, null byte padded)
    // Lcom/google/android/global/Settings;
    $settings           = {
      00 24 4C 63 6F 6D 2F 67 6F 6F 67 6C 65 2F 61 6E
      64 72 6F 69 64 2F 67 6C 6F 62 61 6C 2F 53 65 74
      74 69 6E 67 73 3B 00
    }
    // getSmsInputNumbers (Same encoded described above)
    $getSmsInputNumbers = {
      00 12 67 65 74 53 6D 73 49 6E 70 75 74 4E 75 6D
      62 65 72 73 00
    }

  condition:
    $decryptor and ($settings and $getSmsInputNumbers)
}

rule Linux_Worm_ORCSHRED {
  meta:
    description = "Detects ORCSHRED worm used in attacks on Ukrainian ICS"
    reference   = "https://github.com/cado-security/DFIR_Resources_Industroyer2"
    author      = "mmuir@cadosecurity.com"
    date        = "2022-04-12"
    license     = "Apache License 2.0"
    hash        = "43d07f28b7b699f43abd4f695596c15a90d772bfbd6029c8ee7bc5859c2b0861"

  strings:
    $a = "is_owner" ascii
    $b = "Start most security mode!" ascii
    $c = "check_solaris" ascii
    $d = "wsol.sh" ascii
    $e = "wobf.sh" ascii
    $f = "disown" ascii
    $g = "/var/log/tasks" ascii

  condition:
    4 of them
}

rule FE_APT_Tool_Linux32_BLOODBANK_1 {
  meta:
    author        = "Mandiant"
    date_created  = "2021-05-17"
    sha256        = "8bd504ac5fb342d3533fbe0febe7de5c2adcf74a13942c073de6a9db810f9936"
    reference_url = "https://www.fireeye.com/blog/threat-research/2021/05/updates-on-chinese-apt-compromising-pulse-secure-vpn-devices.html"

  strings:
    $sb1 = { 0f b6 00 3c 75 [2-6] 8b 85 [4] 8d ?? 01 8b 85 [4] 01 ?? 0f b6 00 3c 73 [2-6] 8b 85 [4] 8d ?? 02 8b 85 [4] 01 ?? 0f b6 00 3c 65 [2-6] 8b 85 [4] 8d ?? 03 8b 85 [4] 01 ?? 0f b6 00 3c 72 [2-6] 8b 85 [4] 8d ?? 04 8b 85 [4] 01 ?? 0f b6 00 3c 40 }
    $sb2 = { 0f b6 00 3c 70 [2-6] 8b 85 [4] 8d ?? 01 8b 85 [4] 01 ?? 0f b6 00 3c 61 [2-6] 8b 85 [4] 8d ?? 02 8b 85 [4] 01 ?? 0f b6 00 3c 73 [2-6] 8b 85 [4] 8d ?? 03 8b 85 [4] 01 ?? 0f b6 00 3c 73 [2-6] 8b 85 [4] 8d ?? 04 8b 85 [4] 01 ?? 0f b6 00 3c 77 [2-6] 8b 85 [4] 8d ?? 08 8b 85 [4] 01 ?? 0f b6 00 3c 40 }
    $ss1 = "\x00:%4d-%02d-%02d %02d:%02d:%02d  \x00"

  condition:
    ((uint32(0) == 0x464c457f) and (uint8(4) == 1)) and all of them
}

rule FE_APT_Tool_Linux_BLOODBANK_2 {
  meta:
    author        = "Mandiant"
    date_created  = "2021-05-17"
    sha256        = "8bd504ac5fb342d3533fbe0febe7de5c2adcf74a13942c073de6a9db810f9936"
    reference_url = "https://www.fireeye.com/blog/threat-research/2021/05/updates-on-chinese-apt-compromising-pulse-secure-vpn-devices.html"

  strings:
    $ss1 = "\x00:%4d-%02d-%02d %02d:%02d:%02d  \x00"
    $ss2 = "\x00ok!\x00"
    $ss3 = "\x00\x0a\x0a%s:%s   \x00"
    $ss4 = "\x00PRIMARY!%s   \x00"

  condition:
    (uint32(0) == 0x464c457f) and all of them
}

rule FE_APT_Tool_Linux32_BLOODMINE_1 {
  meta:
    author        = "Mandiant"
    date_created  = "2021-05-17"
    sha256        = "38705184975684c826be28302f5e998cdb3726139aad9f8a6889af34eb2b0385"
    reference_url = "https://www.fireeye.com/blog/threat-research/2021/05/updates-on-chinese-apt-compromising-pulse-secure-vpn-devices.html"

  strings:
    $sb1 = { 6A 01 6A 03 68 [4] E8 [4-32] 50 E8 [4-32] 6A 01 5? 50 E8 [4-32] 50 E8 [4-32] 6A 01 5? 50 E8 [4-32] 6A 01 6A 01 68 [4] E8 [4-32] 8? [0-2] 01 A1 [4] 39 [2] 0F 8? }
    $sb2 = { 68 [4] FF B5 [4] E8 [4-16] 85 C0 7? ?? C7 05 [4] 01 00 00 00 E9 [4-32] 68 [4] FF B5 [4] E8 [4-16] 85 C0 7? ?? C7 05 [4] 02 00 00 00 E9 [4-32] 68 [4] FF B5 [4] E8 [4-16] 85 C0 7? ?? C7 05 [4] 03 00 00 00 E9 }

  condition:
    ((uint32(0) == 0x464c457f) and (uint8(4) == 1)) and all of them
}

rule FE_APT_Tool_Linux_BLOODMINE_2 {
  meta:
    author        = "Mandiant"
    date_created  = "2021-05-17"
    sha256        = "38705184975684c826be28302f5e998cdb3726139aad9f8a6889af34eb2b0385"
    reference_url = "https://www.fireeye.com/blog/threat-research/2021/05/updates-on-chinese-apt-compromising-pulse-secure-vpn-devices.html"

  strings:
    $ss1 = "\x00[+]\x00"
    $ss2 = "\x00%d-%d-%d-%d-%d-%d\x0a\x00"
    $ss3 = "\x00[+]The count of saved logs: %d\x0a\x00"
    $ss4 = "\x00[+]Remember to clear \"%s\", good luck!\x0a\x00"

  condition:
    (uint32(0) == 0x464c457f) and all of them
}

rule FE_APT_Tool_Linux32_CLEANPULSE_1 {
  meta:
    author        = "Mandiant"
    date_created  = "2021-05-17"
    sha256        = "9308cfbd697e4bf76fcc8ff71429fbdfe375441e8c8c10519b6a73a776801ba7"
    reference_url = "https://www.fireeye.com/blog/threat-research/2021/05/updates-on-chinese-apt-compromising-pulse-secure-vpn-devices.html"

  strings:
    $sb1 = { A1 [4] 8B [5] 50 68 [4] 5? FF 75 ?? E8 [4] 83 C4 10 A1 [4] 8B [5] 50 68 [4] 5? FF 75 ?? E8 [4] 83 C4 10 A1 [4] 8B [5] 50 68 [4] 5? FF 75 ?? E8 [4] 83 C4 10 A1 [4] 8B [5] 50 68 [4] 5? FF 75 ?? E8 [4] 83 C4 10 8B ?? 04 }
    $sb2 = { 8B 00 0F B6 00 3C ?? 74 0F 8B ?? 04 83 C0 10 8B 00 0F B6 00 3C ?? 75 }
    $ss1 = "\x00OK!\x00"
    $ss2 = "\x00argv %d error!\x00"
    $ss3 = "\x00ptrace_write\x00"
    $ss4 = "\x00ptrace_attach\x00"

  condition:
    ((uint32(0) == 0x464c457f) and (uint8(4) == 1)) and all of them
}

rule FE_APT_Tool_Linux_CLEANPULSE_2 {
  meta:
    author        = "Mandiant"
    date_created  = "2021-05-17"
    sha256        = "9308cfbd697e4bf76fcc8ff71429fbdfe375441e8c8c10519b6a73a776801ba7"
    reference_url = "https://www.fireeye.com/blog/threat-research/2021/05/updates-on-chinese-apt-compromising-pulse-secure-vpn-devices.html"

  strings:
    $sb1 = { 00 89 4C 24 08 FF 52 04 8D 00 }
    $ss1 = "\x00OK!\x00"
    $ss2 = "\x00argv %d error!\x00"
    $ss3 = "\x00ptrace_write\x00"
    $ss4 = "\x00ptrace_attach\x00"

  condition:
    (uint32(0) == 0x464c457f) and all of them
}

rule MAL_AbyssLocker_Lin_strings {
  meta:
    description   = "Matches strings found in SentinelOne analysis of Linux variant of the Abyss Locker ransomware."
    last_modified = "2024-02-16"
    author        = "@petermstewart"
    DaysofYara    = "47/100"
    ref           = "https://www.sentinelone.com/anthology/abyss-locker/"

  strings:
    $a1 = "Usage:%s [-m (5-10-20-25-33-50) -v -d] Start Path"
    $b1 = "esxcli vm process list"
    $b2 = "esxcli vm process kill -t=force -w=%d"
    $b3 = "esxcli vm process kill -t=hard -w=%d"
    $b4 = "esxcli vm process kill -t=soft -w=%d"
    $c1 = ".crypt" fullword
    $c2 = "README_TO_RESTORE"

  condition:
    uint32(0) == 0x464c457f and
    all of them
}

rule BYL_bank_trojan: Android {
  meta:
    author = "loopher"

  strings:
    // $str = "http://ksjajsxccb.com" wide ascii
    $str       = "http://ksjajsxccb.com/api/index/information"
    $shellcode = {
      22 00 ee 08 70 20 84 4a 40 00 12 41 23 11 54 0c 12 02 1a 03 bd 53 4d 03 01 02 12 12 4d 05 01 02 12 25 1a 02 5b 53 4d 02 01 05 12 35 4d 06 01 05 1a 05 83 40 71 30 59 4b 05 01 0e
      00
    }

  condition:
    $str and $shellcode
}

rule Trojan {
  meta:
    author      = "loopher"
    description = "This rule is for scanning Trojan Android.Kmin.a[org]"

  strings:
    $shelle_code = { 12 1c 12 0b 12 02 1a 01 1a 06 1a 03 6a 05 71 20 c2 01 31 00 6e 10 2e 00 0d 00 0c 00 22 01 8f 00 1a 03 63 04 70 20 a5 02 31 00 6e 20 aa 02 f1 00 0c 01 1a 03 24 00 6e 20 aa 02 31 00 0c 01 6e 10 ac 02 01 00 0c 01 71 10 6e 00 01 00 0c 01 07 23 07 24 07 25 74 06 26 00 00 00 0c 07 38 07 6f 00 72 10 53 00 07 00 0c 0a 1a 01 1f 00 22 02 8f 00 1a 03 73 04 70 20 a5 02 32 00 72 10 54 00 07 00 0a 03 6e 20 a7 02 32 00 0c 02 6e 10 ac 02 02 00 0c 02 71 20 c2 01 21 00 72 10 54 00 07 00 0a 01 3c 01 04 00 01 b1 0f 01 72 10 5a 00 07 00 1a 06 00 00 12 08 21 a1 34 18 0d 00 71 10 e7 01 06 00 0c 09 38 0e 05 00 21 e1 39 01 28 00 01 c1 28 ec 46 01 0a 08 72 20 58 00 87 00 0c 02 39 02 16 00 1a 02 54 06 71 20 c2 01 21 00 46 01 0a 08 1a 02 b8 03 6e 20 8c 02 21 00 0a 01 38 01 0c 00 72 20 58 00 87 00 0c 06 28 da 72 20 58 00 87 00 0c 02 28 ea d8 08 08 01 28 cf 12 08 21 e1 34 18 11 00 1a 01 1e 00 1a 02 20 00 71 20 c2 01 21 00 72 10 59 00 07 00 0a 01 38 01 11 00 01 b1 28 b5 46 01 0e 08 6e 20 8c 02 19 00 0a 01 38 01 04 00 01 c1 28 ab d8 08 08 01 28 e2 72 10 5b 00 07 00 28 a8 }
    $string      = "http://su.5k3g.com/portal/m/c5/0.ashx?"

  condition:
    any of them
}

rule esxi_commands_ransomware {
  meta:
    author      = "Marius 'f0wL' Genheimer <hello@dissectingmalwa.re>"
    description = "Detects commands issued by Ransomware to interact with ESXi VMs"
    date        = "2021-12-20"
    tlp         = "WHITE"

    // AvosLocker
    hash0 = "e9a7b43acdddc3d2101995a2e2072381449054a7d8d381e6dc6ed64153c9c96a"
    // BlackCat
    hash1 = "f8c08d00ff6e8c6adb1a93cd133b19302d0b651afd73ccb54e3b6ac6c60d99c6"
    // BlackMatter 
    hash2 = "d4645d2c29505cf10d1b201826c777b62cbf9d752cb1008bef1192e0dd545a82"
    // HelloKitty  
    hash3 = "ca607e431062ee49a21d69d722750e5edbd8ffabcb54fa92b231814101756041"
    // Hive
    hash4 = "822d89e7917d41a90f5f65bee75cad31fe13995e43f47ea9ea536862884efc25"
    // REvil
    hash5 = "ea1872b2835128e3cb49a0bc27e4727ca33c4e6eba1e80422db19b505f965bc4"

  strings:
    $keyword0 = "esxi" ascii nocase
    $keyword1 = "vm" ascii nocase
    $keyword2 = "process" ascii nocase
    $keyword3 = "kill" ascii nocase
    $keyword4 = "list" ascii nocase
    $keyword5 = "stop" ascii nocase

    // observed in: BlackMatter
    $keyword6 = "firewall" ascii nocase

    // VMware commandline tools
    $command0 = "esxcli" ascii
    $command1 = "esxcfg" ascii
    $command2 = "vicfg" ascii
    $command3 = "vmware-cmd" ascii
    $command4 = "vim-cmd" ascii

    // observed in: Hive, Python ESXi Ransomware, BlackCat
    $command5 = "vmsvc/getallvms" ascii
    $command6 = "vmsvc/power.off" ascii

    // observed in: BlackCat
    $command7 = "vmsvc/snapshot.removeall" ascii

    // observed in: BlackMatter, AvosLocker, REvil
    $argument0 = "--type=force" ascii
    $argument1 = "--world-id=" ascii

    // observed in: AvosLocker, Revil
    $argument2 = "--formatter=csv" ascii
    $argument3 = "--format-param=fields==\"WorldID,DisplayName\"" ascii

    // observed in: HelloKitty
    $argument4 = "-t=soft" ascii
    $argument5 = "-t=hard" ascii
    $argument6 = "-t=force" ascii

    $path0 = "/vmfs"

    // common VMware related file extensions
    $extension0 = "vmx"
    $extension1 = "vmdk"
    $extension2 = "vmsd"
    $extension3 = "vmsn"
    $extension5 = "vmem"
    $extension6 = "vswp"

  condition:
    uint16(0) == 0x457F
    and filesize < 10MB
    and any of ($keyword*)
    and any of ($command*)
    and (any of ($argument*) or (any of ($path*)) or (any of ($extension*)))
}

rule EzuriLoader_revised: LinuxMalware {
  meta:
    author      = "Marius 'f0wL' Genheimer <hello@dissectingmalwa.re>"
    description = "Detects Ezuri Golang Loader/Crypter"
    reference   = "https://cybersecurity.att.com/blogs/labs-research/malware-using-new-ezuri-memory-loader"
    date        = "2021-01-09"
    tlp         = "WHITE"
    hash1       = "ddbb714157f2ef91c1ec350cdf1d1f545290967f61491404c81b4e6e52f5c41f"
    hash2       = "751014e0154d219dea8c2e999714c32fd98f817782588cd7af355d2488eb1c80"

  strings:
    // This is a revised rule originally created by AT&T alien labs
    $a1 = "main.runFromMemory"
    $a2 = "main.aesDec"
    $a3 = "crypto/cipher.NewCFBDecrypter"
    $a4 = "/proc/self/fd/%d"
    $a5 = "/dev/null"

    // Additionally match on AES constants/SBox as proposed by @DuchyRE
    // https://en.wikipedia.org/wiki/Rijndael_S-box
    $aes  = { A5 63 63 C6 84 7C 7C F8 }
    $sbox = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }

  condition:
    uint32(0) == 0x464c457f
    and filesize < 20MB
    and all of ($a*)
    and $aes and $sbox
}

