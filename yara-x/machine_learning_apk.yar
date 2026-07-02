/*
   YARA Rule Set
   Author: HydraDragonAntivirus
   Date: 2026-06-28
   Identifier: apk
   Reference: https://github.com/HydraDragonAntivirus
   License: GPLv2
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_17372844a0ecb548c70275a5e06f522a2445f2781410a246130757e0b7bc {
   meta:
      description = "apk - file 17372844a0ecb548c70275a5e06f522a2445f2781410a246130757e0b7bc5396.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "17372844a0ecb548c70275a5e06f522a2445f2781410a246130757e0b7bc5396"
   strings:
      $s1 = "Meta@android.com1" fullword ascii
      $s2 = "Android System" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_888d3156f5cc5ae3de8861eb097197b4939b4f5b2e7f1ff88c558fd64dcd {
   meta:
      description = "apk - file 888d3156f5cc5ae3de8861eb097197b4939b4f5b2e7f1ff88c558fd64dcdeecb.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "888d3156f5cc5ae3de8861eb097197b4939b4f5b2e7f1ff88c558fd64dcdeecb"
   strings:
      $s1 = "Android System" fullword ascii
      $s2 = "8Fp+$HAYz" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_06f7dfdfbff03719082750fb11ca1f1fe720daa57f11c7d30d3b3277bfec {
   meta:
      description = "apk - file 06f7dfdfbff03719082750fb11ca1f1fe720daa57f11c7d30d3b3277bfeceb13.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "06f7dfdfbff03719082750fb11ca1f1fe720daa57f11c7d30d3b3277bfeceb13"
   strings:
      $s1 = "##Evil Bunny Neighbor Android Edition" fullword ascii
      $s2 = "bINg!P" fullword ascii
      $s3 = "YesO%Xr" fullword ascii
      $s4 = "HaMi 8Q]" fullword ascii
      $s5 = "U*LAME" fullword ascii
      $s6 = "x`RipA" fullword ascii
      $s7 = "';selE" fullword ascii
      $s8 = "WeaR)J" fullword ascii
      $s9 = "Y,>:LAME" fullword ascii
      $s10 = "B09{guRl" fullword ascii
      $s11 = "beaT#p" fullword ascii
      $s12 = "eMIR[n" fullword ascii
      $s13 = "U$i#LAME" fullword ascii
      $s14 = "A:LAME" fullword ascii
      $s15 = "GoNG>Q" fullword ascii
      $s16 = "<#sImP" fullword ascii
      $s17 = "o]LAME" fullword ascii
      $s18 = ")MAdE&" fullword ascii
      $s19 = ")HeAP@" fullword ascii
      $s20 = "d*LAME" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_5948a349b534156f5734b3a99e761ec6d84e527ab729b1f28242049b3afa {
   meta:
      description = "apk - file 5948a349b534156f5734b3a99e761ec6d84e527ab729b1f28242049b3afab2e6.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "5948a349b534156f5734b3a99e761ec6d84e527ab729b1f28242049b3afab2e6"
   strings:
      $s1 = "n&GINK%" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_836f2b13d8481e9461925303d5295908efbf0a58cd7307c851082ed5e1a0 {
   meta:
      description = "apk - file 836f2b13d8481e9461925303d5295908efbf0a58cd7307c851082ed5e1a074a2.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "836f2b13d8481e9461925303d5295908efbf0a58cd7307c851082ed5e1a074a2"
   strings:
      $s1 = "Brawl Stars Pro" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_76b8569eff05ce94ba580e10fb1161af6537d931f8c9d07edba20e93a4a3 {
   meta:
      description = "apk - file 76b8569eff05ce94ba580e10fb1161af6537d931f8c9d07edba20e93a4a34bb6.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "76b8569eff05ce94ba580e10fb1161af6537d931f8c9d07edba20e93a4a34bb6"
   strings:
      $s1 = "Marc van der Meulen -" fullword wide
      $s2 = "#TUFF@T$" fullword ascii
      $s3 = "SUNE#&<" fullword ascii
      $s4 = "Before The Invasion" fullword wide
      $s5 = "haaF(6" fullword ascii
      $s6 = "3\"(NEti" fullword ascii
      $s7 = "},nagA" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_8e7b0e8d2d82a7fcc696919f7bcd16d5d8008b68d7ff692f592a4dbb5cb0 {
   meta:
      description = "apk - file 8e7b0e8d2d82a7fcc696919f7bcd16d5d8008b68d7ff692f592a4dbb5cb083f3.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "8e7b0e8d2d82a7fcc696919f7bcd16d5d8008b68d7ff692f592a4dbb5cb083f3"
   strings:
      $s1 = "FileDownloader is running." fullword ascii
      $s2 = "??File download successful,save in %s,do you want to open it now?" fullword ascii
      $s3 = "We attach great importance to user privacy and strictly comply with relevant legal regulations. Please carefully read the User S" ascii
      $s4 = "++File has Downloaded completely, saved at:%s" fullword ascii
      $s5 = "22The type of file is not supported for downloading!" fullword ascii
      $s6 = "We attach great importance to user privacy and strictly comply with relevant legal regulations. Please carefully read the User S" ascii
      $s7 = "User Service Terms" fullword ascii
      $s8 = "\"Are you sure to download " fullword ascii
      $s9 = "It is downloading,please wait!" fullword ascii
      $s10 = "Not allow to download" fullword ascii
      $s11 = "\"\"File Size:%s,Progress:%s,Rate:%s/s" fullword ascii
      $s12 = "QR code scanning" fullword ascii
      $s13 = "ead and understood the entire content of the agreement." fullword ascii
      $s14 = "hhPlease carefully read and agree to the User Service Terms and Privacy Statement before continuing to use" fullword ascii
      $s15 = "Operation tips" fullword ascii
      $s16 = "Share to Weichat" fullword ascii
      $s17 = "User Privacy Agreement" fullword ascii
      $s18 = "Welcome to use " fullword ascii
      $s19 = "Share to Weichat Group" fullword ascii
      $s20 = "ervice Terms and Privacy Statement before continuing to use. If you continue to use our services, it means that you have fully r" ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_9afa8c36ee47fbbe6e14472385f86b0984f082ed3247be26b57dae59dd62 {
   meta:
      description = "apk - file 9afa8c36ee47fbbe6e14472385f86b0984f082ed3247be26b57dae59dd62718b.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "9afa8c36ee47fbbe6e14472385f86b0984f082ed3247be26b57dae59dd62718b"
   strings:
      $s1 = "See https://youtrack.jetbrains.com/issue/KT-46465 for details about the migration" fullword ascii
      $s2 = "Service onCreate - Device: " fullword ascii
      $s3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii
      $s4 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" fullword ascii
      $s5 = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safar" ascii
      $s6 = "no support for error strings built in" fullword ascii
      $s7 = "onStartCommand$lambda$1" fullword ascii
      $s8 = "~~R8{\"backend\":\"dex\",\"compilation-mode\":\"release\",\"has-checksums\":false,\"min-api\":19,\"pg-map-id\":\"4eef14f15631381" ascii
      $s9 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15" fullword ascii
      $s10 = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safar" ascii
      $s11 = "System Background Service" fullword ascii
      $s12 = "ddEnsures system services are up to date and improves device performance by managing background tasks." fullword ascii
      $s13 = "Google Play Services Core" fullword wide
      $s14 = "If you override toChar() function in your Number inheritor, it's recommended to gradually deprecate the overriding function and " ascii
      $s15 = "If you override toChar() function in your Number inheritor, it's recommended to gradually deprecate the overriding function and " ascii
      $s16 = "ZUnclear conversion. To achieve the same result convert to Int explicitly and then to Byte." fullword ascii
      $s17 = "Google Play Services Update" fullword wide
      $s18 = "~~R8{\"backend\":\"dex\",\"compilation-mode\":\"release\",\"has-checksums\":false,\"min-api\":19,\"pg-map-id\":\"4eef14f15631381" ascii
      $s19 = "E. It's recommended to use 'endInclusive' property that doesn't throw." fullword ascii
      $s20 = "[Unclear conversion. To achieve the same result convert to Int explicitly and then to Short." fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule f2559c75597cd7ab5ad85ff689191d0f8fd91f0c1e2af541c341baf6db8d32d7 {
   meta:
      description = "apk - file f2559c75597cd7ab5ad85ff689191d0f8fd91f0c1e2af541c341baf6db8d32d7.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "f2559c75597cd7ab5ad85ff689191d0f8fd91f0c1e2af541c341baf6db8d32d7"
   strings:
      $s1 = "GYpS?@" fullword ascii
      $s2 = "Please wait pdh" fullword ascii
      $s3 = "QuiZ]zT" fullword ascii
      $s4 = "Continue sf4" fullword ascii
      $s5 = "Please wait gfp" fullword ascii
      $s6 = "pRoD{C" fullword ascii
      $s7 = "e_`MADE" fullword ascii
      $s8 = " ,NuLL;`" fullword ascii
      $s9 = "R fUlL" fullword ascii
      $s10 = "cOrD`;" fullword ascii
      $s11 = "Froe}<" fullword ascii
      $s12 = "Y}FUMy" fullword ascii
      $s13 = "#:B]ReNk" fullword ascii
      $s14 = "e*LEeD" fullword ascii
      $s15 = "}]gYne" fullword ascii
      $s16 = "Cancel btn" fullword ascii
      $s17 = "Cancel blj" fullword ascii
      $s18 = "Cancel qpz" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_595355daaa6aad284090210cd55c4a2e276c5263c83d2b202e1486d347af {
   meta:
      description = "apk - file 595355daaa6aad284090210cd55c4a2e276c5263c83d2b202e1486d347af3701.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "595355daaa6aad284090210cd55c4a2e276c5263c83d2b202e1486d347af3701"
   strings:
      $s1 = ")Z&rOaD" fullword ascii
      $s2 = "SNED$;" fullword ascii
      $s3 = "<CuIr}" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_926d3c5cc0c4f93cd63e1dd0cb7fb7a2da96fce980fce4cf77cdcf69ccca {
   meta:
      description = "apk - file 926d3c5cc0c4f93cd63e1dd0cb7fb7a2da96fce980fce4cf77cdcf69ccca4e6b.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "926d3c5cc0c4f93cd63e1dd0cb7fb7a2da96fce980fce4cf77cdcf69ccca4e6b"
   strings:
      $s1 = "{jLAME3.101 (beta 3)" fullword ascii
      $s2 = "LAME3.101 (beta 3)UUUUUUUUUUUUUUUUUU" fullword ascii
      $s3 = "LAME3.101 (beta 3)" fullword ascii
      $s4 = "LAME3.101 (beta 3)UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" fullword ascii
      $s5 = "LAME3.101 (beta 3)UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" fullword ascii
      $s6 = "LAME3.101 (beta 3)UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUULAME3.101 (beta 3)UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" ascii
      $s7 = "LAME3.101 (beta 3)UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUULAME3.101 (beta 3)UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_906896b11849040c03a0260dd290320c08b1df19d0bc5e885abf2f99de0d {
   meta:
      description = "apk - file 906896b11849040c03a0260dd290320c08b1df19d0bc5e885abf2f99de0daebc.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "906896b11849040c03a0260dd290320c08b1df19d0bc5e885abf2f99de0daebc"
   strings:
      $s1 = "Stealer" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_50d8632433d3954b14af9ce7da67f030f1d3dadc2d0be6fc9a0615531468 {
   meta:
      description = "apk - file 50d8632433d3954b14af9ce7da67f030f1d3dadc2d0be6fc9a06155314682701.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "50d8632433d3954b14af9ce7da67f030f1d3dadc2d0be6fc9a06155314682701"
   strings:
      $s1 = "iR`:lIMY" fullword ascii
      $s2 = "ByrE#0" fullword ascii
      $s3 = ":Fono>" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule a571605812fbd816070e09fce86c2f010673dab8f8a33f8e7de7a89f3ed3ce74 {
   meta:
      description = "apk - file a571605812fbd816070e09fce86c2f010673dab8f8a33f8e7de7a89f3ed3ce74.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "a571605812fbd816070e09fce86c2f010673dab8f8a33f8e7de7a89f3ed3ce74"
   strings:
      $s1 = "E]thIr" fullword ascii
      $s2 = "CHAP@B" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule fbfab254dc250f89c58a5eed9c0233d0a0afdb029da1bba9537cfe359e2e4794 {
   meta:
      description = "apk - file fbfab254dc250f89c58a5eed9c0233d0a0afdb029da1bba9537cfe359e2e4794.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "fbfab254dc250f89c58a5eed9c0233d0a0afdb029da1bba9537cfe359e2e4794"
   strings:
      $s1 = "ISO Media file produced by Google Inc." fullword ascii
      $s2 = "I<dOcK?R" fullword ascii
      $s3 = "Sheet Cryptograph" fullword ascii
      $s4 = "Sb#?yerk" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_3f4c9b68876000a2cf20ba8804cbb7fa74064a8dd39253733371486d2a8f {
   meta:
      description = "apk - file 3f4c9b68876000a2cf20ba8804cbb7fa74064a8dd39253733371486d2a8fc83a.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "3f4c9b68876000a2cf20ba8804cbb7fa74064a8dd39253733371486d2a8fc83a"
   strings:
      $s1 = "/:LAME" fullword ascii
      $s2 = "LAME F" fullword ascii
      $s3 = "h LAME" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule b68e96cf67fd740c164dc3b90634b10e1b7a20ca5b741cf66885f5ec3be09d74 {
   meta:
      description = "apk - file b68e96cf67fd740c164dc3b90634b10e1b7a20ca5b741cf66885f5ec3be09d74.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "b68e96cf67fd740c164dc3b90634b10e1b7a20ca5b741cf66885f5ec3be09d74"
   strings:
      $s1 = "Voice changer with effects - https://thevoicechanger.comTPE1" fullword ascii
      $s2 = "Voice changer with effects - https://thevoicechanger.comTSSE" fullword ascii
      $s3 = "TAGVoice changer with effects - hVoice changer with effects - h" fullword ascii
      $s4 = "**LAME" fullword ascii
      $s5 = "<*LAME" fullword ascii
      $s6 = "J*LAME" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule c4f51ccde0525887b61fb919eefc5830b24ec35fdcb2af2aa3893e5f56957c40 {
   meta:
      description = "apk - file c4f51ccde0525887b61fb919eefc5830b24ec35fdcb2af2aa3893e5f56957c40.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "c4f51ccde0525887b61fb919eefc5830b24ec35fdcb2af2aa3893e5f56957c40"
   strings:
      $s1 = "Tom and Angela-You Get Me (From " fullword ascii
      $s2 = "Talking Friends" fullword ascii
      $s3 = ")#nostalgia #shorts #talkingtom #fyp #ttf" fullword ascii
      $s4 = "SLaB*5$" fullword ascii
      $s5 = "YE]&loRn" fullword ascii
      $s6 = "*=Z0@`c@`ecHE" fullword ascii
      $s7 = "UAnG$l" fullword ascii
      $s8 = "y\"LAME" fullword ascii
      $s9 = "cAFh?`G" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_8159c79c8a9b54ad363516f9b53c7cada3ea4afa0b2d0f6e7dc66fe147d0 {
   meta:
      description = "apk - file 8159c79c8a9b54ad363516f9b53c7cada3ea4afa0b2d0f6e7dc66fe147d03a93.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "8159c79c8a9b54ad363516f9b53c7cada3ea4afa0b2d0f6e7dc66fe147d03a93"
   strings:
      $s1 = "2018 Epic Stock Media (Horror Game) https://epicstockmedia.com" fullword ascii
      $s2 = "All files are Copyright Epic Stock Media - All Rights Reserved " fullword ascii
      $s3 = "<BWFXML><IXML_VERSION>1.61</IXML_VERSION><STEINBERG><ATTR_LIST><ATTR><TYPE>string</TYPE><NAME>MediaLibrary</NAME><VALUE>Horror G" ascii
      $s4 = "Logic Pro X" fullword ascii
      $s5 = "<BWFXML><IXML_VERSION>1.61</IXML_VERSION><STEINBERG><ATTR_LIST><ATTR><TYPE>string</TYPE><NAME>MediaLibrary</NAME><VALUE>Horror G" ascii
      $s6 = " 2018 Epic Stock MediaCOMM" fullword ascii
      $s7 = "><VALUE>Epic Stock Media</VALUE></ATTR><ATTR><TYPE>string</TYPE><NAME>MediaComment</NAME><VALUE>This is a sound effect created b" ascii
      $s8 = "         <dc:description>" fullword ascii
      $s9 = "         </dc:description>" fullword ascii
      $s10 = "ame</VALUE></ATTR><ATTR><TYPE>string</TYPE><NAME>MediaCategoryPost</NAME><VALUE>Game</VALUE></ATTR><ATTR><TYPE>string</TYPE><NAM" ascii
      $s11 = "Epic Stock Media" fullword ascii
      $s12 = "My Horror Domlopez 4" fullword ascii
      $s13 = "data@XE" fullword ascii
      $s14 = "ENCODER=FL Studio Mobile v4.8.0" fullword ascii
      $s15 = "Epic Stock MediaTORY" fullword ascii
      $s16 = "Horror GameTYER" fullword ascii
      $s17 = "This is a sound effect created by Epic Stock Media for horror games." fullword ascii
      $s18 = "Horror Game" fullword ascii
      $s19 = "E>MediaLibraryManufacturerName</NAME><VALUE>Epic Stock Media</VALUE></ATTR><ATTR><TYPE>string</TYPE><NAME>AudioSoundEditor</NAME" ascii
      $s20 = "This is a sound effect created by Epic Stock Media for horror games.TOWN" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_89d492b7539b5552445764907a96b517d08d448f8ff0e3e7a93958df82d3 {
   meta:
      description = "apk - file 89d492b7539b5552445764907a96b517d08d448f8ff0e3e7a93958df82d3df58.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "89d492b7539b5552445764907a96b517d08d448f8ff0e3e7a93958df82d3df58"
   strings:
      $s1 = "!oXEA:" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_9fb8a940492ee6095a24b4a34ecfa252a515fb681f16636a8f00b1e0e7d4 {
   meta:
      description = "apk - file 9fb8a940492ee6095a24b4a34ecfa252a515fb681f16636a8f00b1e0e7d47fe2.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "9fb8a940492ee6095a24b4a34ecfa252a515fb681f16636a8f00b1e0e7d47fe2"
   strings:
      $s1 = "Tite;B" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule d5b6c048a278c06e2625c47a3a57f5ce2e4d6d73d830051a84de1768e0445882 {
   meta:
      description = "apk - file d5b6c048a278c06e2625c47a3a57f5ce2e4d6d73d830051a84de1768e0445882.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "d5b6c048a278c06e2625c47a3a57f5ce2e4d6d73d830051a84de1768e0445882"
   strings:
      $s1 = "Squeaky background soundTPE1" fullword ascii
      $s2 = "TAGSqueaky background sound" fullword ascii
      $s3 = "Squeaky background sound" fullword ascii
      $s4 = "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUULAME3.92 (alpha)UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" ascii
      $s5 = "LAME?B" fullword ascii
      $s6 = "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" ascii
      $s7 = "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" ascii
      $s8 = "LAME3.92 (alpha)UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" fullword ascii
      $s9 = "w;piKA" fullword ascii
      $s10 = "4>LAME" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule d7362ff697a5cae24b4b084d0436ccde7060524a24c34f37f185f64597930514 {
   meta:
      description = "apk - file d7362ff697a5cae24b4b084d0436ccde7060524a24c34f37f185f64597930514.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "d7362ff697a5cae24b4b084d0436ccde7060524a24c34f37f185f64597930514"
   strings:
      $s1 = "$FOrd[AL" fullword ascii
      $s2 = "Robux Cheat" fullword ascii
      $s3 = "|$CiNe" fullword ascii
      $s4 = ":LAME " fullword ascii
      $s5 = "x*LAME" fullword ascii
      $s6 = "H}LAME" fullword ascii
      $s7 = "^[SYnE" fullword ascii
      $s8 = "%fLAME" fullword ascii
      $s9 = "2^~oo<LAME" fullword ascii
      $s10 = "scUn,#" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule fd263056adfe6cb5596a11612440fa5d851b3b9bed34a481139c2206a6c570b1 {
   meta:
      description = "apk - file fd263056adfe6cb5596a11612440fa5d851b3b9bed34a481139c2206a6c570b1.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "fd263056adfe6cb5596a11612440fa5d851b3b9bed34a481139c2206a6c570b1"
   strings:
      $s1 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description rdf:ab" ascii
      $s2 = "\"uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\"><xmp:CreatorTool>Microsoft Windows Phot" ascii
      $s3 = "ewer 6.1.7600.16385</xmp:CreatorTool></rdf:Description></rdf:RDF></x:xmpmeta>" fullword ascii
      $s4 = "Microsoft Windows Photo Viewer 6.1.7600.16385" fullword ascii
      $s5 = "LAME% T" fullword ascii
      $s6 = "COPYRIGHT, 2011" fullword ascii
      $s7 = "YAGi!N" fullword ascii
      $s8 = "LAME in FL Studio 10 " fullword ascii
      $s9 = "GOli`l0" fullword ascii
      $s10 = "U*LAME" fullword ascii
      $s11 = "pOON;~" fullword ascii
      $s12 = "%*LAME" fullword ascii
      $s13 = "u*LAME" fullword ascii
      $s14 = "sb*LAME" fullword ascii
      $s15 = "y@buRP" fullword ascii
      $s16 = "&[cURl" fullword ascii
      $s17 = "R& uRAn" fullword ascii
      $s18 = "zj5&LAME" fullword ascii
      $s19 = "(BLAME" fullword ascii
      $s20 = "(para r" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_92871cbed3b8b6a65b0e50df893c015e6508572d7cde49b0a99ec61449a1 {
   meta:
      description = "apk - file 92871cbed3b8b6a65b0e50df893c015e6508572d7cde49b0a99ec61449a11d1e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "92871cbed3b8b6a65b0e50df893c015e6508572d7cde49b0a99ec61449a11d1e"
   strings:
      $s1 = "targetSdkVersion does not support the current path on Android10+ system devices after setting >=29. Please change to the applica" ascii
      $s2 = "targetSdkVersion does not support the current path on Android10+ system devices after setting >=29. Please change to the applica" ascii
      $s3 = "%%, configuration file download failed!" fullword ascii
      $s4 = "FFthe Authentication Service operation to obtain authorized logon failed" fullword ascii
      $s5 = "failed to get token" fullword ascii
      $s6 = "Configuration get failed" fullword ascii
      $s7 = "FFfailed to obtain authorization to log in to the authentication service" fullword ascii
      $s8 = "==The webview has not been created yet, please execute it later" fullword ascii
      $s9 = "tion run path! Please see:https://ask.dcloud.net.cn/article/36199" fullword ascii
      $s10 = "KKPlease upload after compressing and cutting, the largest file only supports" fullword ascii
      $s11 = "orage (the system prompts to access photos, media content and files on the device), please allow." fullword ascii
      $s12 = "XXWGTU installation package www under contents manifest.json file version version mismatch" fullword ascii
      $s13 = "LLWGTU installation package www under contents manifest.json file format error" fullword ascii
      $s14 = "??the get address is empty, get a new URI through getShortCutUri?" fullword ascii
      $s15 = "not logged in or logged out" fullword ascii
      $s16 = "SSplease check whether %s related nodes are added in assets/data/properties.xml file." fullword ascii
      $s17 = "\"%s\" modules are configured in manifest.json of WGT, but these modules are not configured when the app is packaged. After upgr" ascii
      $s18 = "KKCurrently on a non-WiFi network, is the x5 module allowed to be downloaded?" fullword ascii
      $s19 = "\"%s\" modules are configured in manifest.json of WGT, but these modules are not configured when the app is packaged. After upgr" ascii
      $s20 = "22the current system does not support AAC recording!" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_9a778fbb730ee653f45b36700a369c81792509f855c2529aca73de1443c6 {
   meta:
      description = "apk - file 9a778fbb730ee653f45b36700a369c81792509f855c2529aca73de1443c62de8.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "9a778fbb730ee653f45b36700a369c81792509f855c2529aca73de1443c62de8"
   strings:
      $s1 = "wiNG&v" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_23d668f31429fe38195087c3f7d9d68ef32fbb7bfa947be3589c08f09751 {
   meta:
      description = "apk - file 23d668f31429fe38195087c3f7d9d68ef32fbb7bfa947be3589c08f0975193f7.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "23d668f31429fe38195087c3f7d9d68ef32fbb7bfa947be3589c08f0975193f7"
   strings:
      $s1 = "tasH @6" fullword ascii
      $s2 = "BREi!,l" fullword ascii
      $s3 = "HuTcH!*F" fullword ascii
      $s4 = "t#dAFt" fullword ascii
      $s5 = "HS#BAiL" fullword ascii
      $s6 = "k34#pUFF" fullword ascii
      $s7 = "d]LeAM" fullword ascii
      $s8 = "\"lITeR," fullword ascii
      $s9 = "BEtH{j" fullword ascii
      $s10 = "\":flAm" fullword ascii
      $s11 = "pL)KITh," fullword ascii
      $s12 = "Axis::" fullword ascii
      $s13 = "dEnT@#" fullword ascii
      $s14 = "]*LAME" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule b115b04b197b112eecf668fa549f65189e683cb87050708a72fcca268c9258e2 {
   meta:
      description = "apk - file b115b04b197b112eecf668fa549f65189e683cb87050708a72fcca268c9258e2.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "b115b04b197b112eecf668fa549f65189e683cb87050708a72fcca268c9258e2"
   strings:
      $s1 = "Forward UDP packets to badvpn-udpgw via SOCKS5. This needs badvpn-udpgw running on the remote server (normally listening on 127." ascii
      $s2 = "sglobal { perm_cache=1024; cache_dir={DIR}; server_port = 8091; server_ip = 0.0.0.0; query_method=tcp_only; min_ttl=15m; max_ttl" ascii
      $s3 = "CCEnable this option to bypass selected apps instead of proxying them" fullword ascii
      $s4 = "Bypass Mode" fullword ascii
      $s5 = "Forward UDP packets to badvpn-udpgw via SOCKS5. This needs badvpn-udpgw running on the remote server (normally listening on 127." ascii
      $s6 = "=1w; timeout=10; daemon=on; pid_file={DIR}/pdnsd.pid; } server { label= upstream; ip = {IP}; port = {PORT}; uptest = none; } rr " ascii
      $s7 = "UDP Forwarding" fullword ascii
      $s8 = "vvEnable IPv6 forwarding. If the server supports IPv6, you can access IPv6 contents from IPv4 network with this enabled." fullword ascii
      $s9 = "\"\"Username & Password Authentication" fullword ascii
      $s10 = "YYEnter one app's package name in one line. See Settings -> Apps for package names of apps." fullword ascii
      $s11 = "Delete profile %s?" fullword ascii
      $s12 = "Failed to add profile %s" fullword ascii
      $s13 = "Switch on / off the proxy" fullword ascii
      $s14 = "Error deleting profile %s" fullword ascii
      $s15 = "DNS Port (TCP)" fullword ascii
      $s16 = "UDP Gateway (Remote)" fullword ascii
      $s17 = "Server IP" fullword ascii
      $s18 = "About Bot" fullword ascii
      $s19 = "RaND(D," fullword ascii
      $s20 = "SHADOW BOT" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_0bcdf887e6bd21ea4073385a8b2e59025768be3131a92e9940886e05c748 {
   meta:
      description = "apk - file 0bcdf887e6bd21ea4073385a8b2e59025768be3131a92e9940886e05c748e1cc.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "0bcdf887e6bd21ea4073385a8b2e59025768be3131a92e9940886e05c748e1cc"
   strings:
      $s1 = "Squeaky background soundTPE1" fullword ascii
      $s2 = "TAGSqueaky background sound" fullword ascii
      $s3 = "Squeaky background sound" fullword ascii
      $s4 = "w;piKA" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_1f29ad9ef32cea0d462fd3d74d7bf439757b6de28039ee7c3fcd75b122a0 {
   meta:
      description = "apk - file 1f29ad9ef32cea0d462fd3d74d7bf439757b6de28039ee7c3fcd75b122a03043.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "1f29ad9ef32cea0d462fd3d74d7bf439757b6de28039ee7c3fcd75b122a03043"
   strings:
      $s1 = "sExfid)V" fullword ascii
      $s2 = ":FuZe@" fullword ascii
      $s3 = "`!BadE" fullword ascii
      $s4 = "JuDO>~" fullword ascii
      $s5 = "C;?atIS" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_4b9a92bc2ba87c302fa3fc5090d588d9c2dc86a35b3caf61bba460a81b65 {
   meta:
      description = "apk - file 4b9a92bc2ba87c302fa3fc5090d588d9c2dc86a35b3caf61bba460a81b65dc9a.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "4b9a92bc2ba87c302fa3fc5090d588d9c2dc86a35b3caf61bba460a81b65dc9a"
   strings:
      $s1 = "Android (10552028, +pgo, +bolt, +lto, -mlgo, based on r487747d) clang version 17.0.2 (https://android.googlesource.com/toolchain" ascii
      $s2 = "Android (10552028, +pgo, +bolt, +lto, -mlgo, based on r487747d) clang version 17.0.2 (https://android.googlesource.com/toolchain" ascii
      $s3 = "Linker: LLD 17.0.2" fullword ascii
      $s4 = "SUrA'W," fullword ascii
      $s5 = "y'Q@OiNT" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule c295c55aa803cfd0e92ba47a233a3c200e7eb003468b2a5a8ca0d95f110f0c86 {
   meta:
      description = "apk - file c295c55aa803cfd0e92ba47a233a3c200e7eb003468b2a5a8ca0d95f110f0c86.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "c295c55aa803cfd0e92ba47a233a3c200e7eb003468b2a5a8ca0d95f110f0c86"
   strings:
      $s1 = "Android (10552028, +pgo, +bolt, +lto, -mlgo, based on r487747d) clang version 17.0.2 (https://android.googlesource.com/toolchain" ascii
      $s2 = "Android (10552028, +pgo, +bolt, +lto, -mlgo, based on r487747d) clang version 17.0.2 (https://android.googlesource.com/toolchain" ascii
      $s3 = "Linker: LLD 17.0.2" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_1389e203ecaebc0b44365ebcc95c05789367e896e862f1a2f614e29ded7d {
   meta:
      description = "apk - file 1389e203ecaebc0b44365ebcc95c05789367e896e862f1a2f614e29ded7d6c01.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "1389e203ecaebc0b44365ebcc95c05789367e896e862f1a2f614e29ded7d6c01"
   strings:
      $s1 = "2VI{duRo" fullword ascii
      $s2 = "Yelk'y" fullword ascii
      $s3 = "O,\"maRT" fullword ascii
      $s4 = "%:HaeC" fullword ascii
      $s5 = "bAST'0" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule d6e87fb3a6f6bc2527c16a768ab517aec705666f3e8540f21b47e9747ff67e9c {
   meta:
      description = "apk - file d6e87fb3a6f6bc2527c16a768ab517aec705666f3e8540f21b47e9747ff67e9c.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "d6e87fb3a6f6bc2527c16a768ab517aec705666f3e8540f21b47e9747ff67e9c"
   strings:
      $s1 = "nasI[?>" fullword ascii
      $s2 = "ikra!%" fullword ascii
      $s3 = "/%sAhh" fullword ascii
      $s4 = "^[}cOpY" fullword ascii
      $s5 = "sisHaX" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule df384f9aaa8c3a194e2225d9f3b577d9bbda92f390ad15f3f812c3770909f9e8 {
   meta:
      description = "apk - file df384f9aaa8c3a194e2225d9f3b577d9bbda92f390ad15f3f812c3770909f9e8.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "df384f9aaa8c3a194e2225d9f3b577d9bbda92f390ad15f3f812c3770909f9e8"
   strings:
      $s1 = "PeLL@HV" fullword ascii
      $s2 = "x`NOTe" fullword ascii
      $s3 = "!bOCE<" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_364983d2dbff85f4b9b2bac2beba40ad29ac85f2a16bdbc8fd65896ef03c {
   meta:
      description = "apk - file 364983d2dbff85f4b9b2bac2beba40ad29ac85f2a16bdbc8fd65896ef03cddb2.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "364983d2dbff85f4b9b2bac2beba40ad29ac85f2a16bdbc8fd65896ef03cddb2"
   strings:
      $s1 = "--To use this app, download the latest version." fullword ascii
      $s2 = "~~D8{\"backend\":\"dex\",\"compilation-mode\":\"debug\",\"has-checksums\":false,\"min-api\":21,\"sha-1\":\"abaab469b5ebd4dd2bb91" ascii
      $s3 = "~~D8{\"backend\":\"dex\",\"compilation-mode\":\"debug\",\"has-checksums\":false,\"min-api\":21,\"sha-1\":\"abaab469b5ebd4dd2bb91" ascii
      $s4 = "Video System" fullword ascii
      $s5 = "Ready to check for updates." fullword ascii
      $s6 = "@@To enjoy all matches without interruptions, please activate VPN." fullword ascii
      $s7 = "AjaR@\\M8" fullword ascii
      $s8 = "Bug fixes and general stability improvements." fullword ascii
      $s9 = "Enable VPN" fullword ascii
      $s10 = "Refreshed interface with a cleaner design." fullword ascii
      $s11 = "`NoBS:H)RG" fullword ascii
      $s12 = "Improved overall performance and faster loading times." fullword ascii
      $s13 = "Updated links with more options." fullword ascii
      $s14 = "Everyone 1.5 MB" fullword ascii
      $s15 = "VPN protection is required" fullword ascii
      $s16 = "Optimized video player with greater stability." fullword ascii
      $s17 = "Open App" fullword ascii
      $s18 = "val$suffix" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_793b9d915d2f412ad32d3aac486f17dd7b5014b86469b6a4540d559ee70a {
   meta:
      description = "apk - file 793b9d915d2f412ad32d3aac486f17dd7b5014b86469b6a4540d559ee70a4d7b.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "793b9d915d2f412ad32d3aac486f17dd7b5014b86469b6a4540d559ee70a4d7b"
   strings:
      $s1 = "r&0xFindClassExceptionCheckJNIEnv*JNIEnvNewStringUTFNewStringUTF resultDeleteLocalRefGetObjectClassNewObjectANewObjectA resultCa" ascii
      $s2 = "r&0xFindClassExceptionCheckJNIEnv*JNIEnvNewStringUTFNewStringUTF resultDeleteLocalRefGetObjectClassNewObjectANewObjectA resultCa" ascii
      $s3 = "SetLongFieldSetBooleanFieldSetFloatFieldSetDoubleFieldset_field_typed obj argumentGetByteArrayRegionget_byte_array_region array " ascii
      $s4 = "ssfailed to write whole bufferdescription() is deprecated; use Display" fullword ascii
      $s5 = "argumentSetByteArrayRegionset_byte_array_region array argumentRegisterNativesGetObjectArrayElementget_object_array_element array" ascii
      $s6 = "5rustc version 1.95.0-nightly (a33907a7a 2026-02-14)" fullword ascii
      $s7 = "rustc version 1.95.0-nightly (a33907a7a 2026-02-14)" fullword ascii
      $s8 = " of read, write, or append accesscreating or truncating a file requires write or append accessfailed to write whole bufferdescri" ascii
      $s9 = "call_method obj argumentNewGlobalRefGetBooleanFieldGetByteFieldGetCharFieldGetDoubleFieldGetFloatFieldGetIntFieldGetLongFieldGet" ascii
      $s10 = "GetStaticFieldIDFindClass result" fullword ascii
      $s11 = "ir:fail" fullword ascii
      $s12 = "i:done pkg=" fullword ascii
      $s13 = "ir:ok:launch:" fullword ascii
      $s14 = ">PrimitiveObjectArrayMethodTypeSignatureretfile name contained an unexpected NUL byteinvalid stack sizemust specify at least one" ascii
      $s15 = " stack sizemust specify at least one of read, write, or append accesscreating or truncating a file requires write or append acce" ascii
      $s16 = "etThrowFailedParseFailedJniCall<init>PrimitiveObjectArrayMethodTypeSignatureretfile name contained an unexpected NUL byteinvalid" ascii
      $s17 = ";)char" fullword ascii
      $s18 = "ption() is deprecated; use Display" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_61ac11961911a76b3752982592e7903d621bf6c9cf51853cbdea3b18f7ff {
   meta:
      description = "apk - file 61ac11961911a76b3752982592e7903d621bf6c9cf51853cbdea3b18f7ff63fd.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "61ac11961911a76b3752982592e7903d621bf6c9cf51853cbdea3b18f7ff63fd"
   strings:
      $s1 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://" fullword ascii
      $s2 = "/bin/busybox echo -ne " fullword ascii
      $s3 = "usage: busybox" fullword ascii
      $s4 = "/bin/busybox echo > " fullword ascii
      $s5 = "ping ;sh" fullword ascii
      $s6 = "netman" fullword ascii
      $s7 = "expand 32-byte kp@-" fullword ascii
      $s8 = "1234@root" fullword ascii
      $s9 = "olt!pass" fullword ascii
      $s10 = "Saint Helens1" fullword ascii
      $s11 = "!manage" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_2fcc2db37c0c78d06a71002c1ac287fd68f024ec0717306629166c9b2225 {
   meta:
      description = "apk - file 2fcc2db37c0c78d06a71002c1ac287fd68f024ec0717306629166c9b2225756e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "2fcc2db37c0c78d06a71002c1ac287fd68f024ec0717306629166c9b2225756e"
   strings:
      $s1 = "<Command xmlns=\"http://spss.com/spss/extension\" Name=\"RunScript\">" fullword ascii
      $s2 = "<Command xmlns=\"http://spss.com/spss/extension\" Name=\"ImportData\">" fullword ascii
      $s3 = "<Command xmlns=\"http://spss.com/spss/extension\" Name=\"ExportData\">" fullword ascii
      $s4 = "<Command xmlns=\"http://spss.com/spss/extension\" Name=\"RunAnalysis\">" fullword ascii
      $s5 = "<Command xmlns=\"http://spss.com/spss/extension\" Name=\"CustomAction\">" fullword ascii
      $s6 = "* Custom SPSS Script." fullword ascii
      $s7 = "<Extension xmlns=\"http://spss.com/spss/extension\" version=\"1.0\">" fullword ascii
      $s8 = "* Compute." fullword ascii
      $s9 = "* Report." fullword ascii
      $s10 = "EXECUTE." fullword ascii
      $s11 = "* Regression." fullword ascii
      $s12 = "* Aggregate." fullword ascii
      $s13 = "* Filter." fullword ascii
      $s14 = "AGGREGATE /OUTFILE=* /x=MEAN(x)." fullword ascii
      $s15 = "REPORT /x." fullword ascii
      $s16 = "* Sort." fullword ascii
      $s17 = "* Save." fullword ascii
      $s18 = "REGRESSION /x." fullword ascii
      $s19 = "SAVE OUTFILE='out.sav'." fullword ascii
      $s20 = "COMPUTE x=1." fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_5fc08b4c4197d94016ec27e3cf09d4943891921519b489ade3c9494d71fe {
   meta:
      description = "apk - file 5fc08b4c4197d94016ec27e3cf09d4943891921519b489ade3c9494d71fe4715.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "5fc08b4c4197d94016ec27e3cf09d4943891921519b489ade3c9494d71fe4715"
   strings:
      $s1 = " per cercare i virus e bloccarli)." fullword ascii
      $s2 = " per cercare i virus e bloccarli. (Consente al sistema di proteggere il dispositivo, utilizza gli eventi di accessibilit" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_603d89c5a2883ab2ed68e12517212bd0b74760f1ef755a61d059440aeba0 {
   meta:
      description = "apk - file 603d89c5a2883ab2ed68e12517212bd0b74760f1ef755a61d059440aeba045fd.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "603d89c5a2883ab2ed68e12517212bd0b74760f1ef755a61d059440aeba045fd"
   strings:
      $s1 = "TUfF&UE_" fullword ascii
      $s2 = "FuZe$jx," fullword ascii
      $s3 = "X{pUAN<d" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_038ddeb937e70aa8e1321f55c5d43b18f4cea9dd6abe63f43141ec22ccbe {
   meta:
      description = "apk - file 038ddeb937e70aa8e1321f55c5d43b18f4cea9dd6abe63f43141ec22ccbe9825.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "038ddeb937e70aa8e1321f55c5d43b18f4cea9dd6abe63f43141ec22ccbe9825"
   strings:
      $s1 = "h$TuZA" fullword ascii
      $s2 = "imo-International Calls & Chat" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_4064f42a30b85220545e4a43672e374ba879b36b3d79c4a5e2324a3ca1f6 {
   meta:
      description = "apk - file 4064f42a30b85220545e4a43672e374ba879b36b3d79c4a5e2324a3ca1f6df8a.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "4064f42a30b85220545e4a43672e374ba879b36b3d79c4a5e2324a3ca1f6df8a"
   strings:
      $s1 = "beaK!w" fullword ascii
      $s2 = "z>veaL" fullword ascii
      $s3 = "LUNE)1" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule d0a79f28baec2beaae749a8d64dcc4d1a79cde6982a72ede58945a843b563955 {
   meta:
      description = "apk - file d0a79f28baec2beaae749a8d64dcc4d1a79cde6982a72ede58945a843b563955.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "d0a79f28baec2beaae749a8d64dcc4d1a79cde6982a72ede58945a843b563955"
   strings:
      $s1 = "Spotify: Music and Podcasts" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule a4c267819d38e8c1e85e1764115032db61bf8985711d4a5a3384891404a176fe {
   meta:
      description = "apk - file a4c267819d38e8c1e85e1764115032db61bf8985711d4a5a3384891404a176fe.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "a4c267819d38e8c1e85e1764115032db61bf8985711d4a5a3384891404a176fe"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s2 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s3 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s4 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s5 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s6 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s7 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s8 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s9 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s10 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s11 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s12 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s13 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s14 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s15 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s16 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s17 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s18 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s19 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s20 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_3a659f0eea60ca2388eda4ea3989c15f8e5d29c54b51fc74efb599474ba9 {
   meta:
      description = "apk - file 3a659f0eea60ca2388eda4ea3989c15f8e5d29c54b51fc74efb599474ba943ea.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "3a659f0eea60ca2388eda4ea3989c15f8e5d29c54b51fc74efb599474ba943ea"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s2 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 4.2.2-c063 53.352624, 2008/0" ascii
      $s3 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s4 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s5 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s6 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s7 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s8 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s9 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s10 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s11 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s12 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s13 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s14 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s15 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s16 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s17 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s18 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s19 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s20 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_87def7f445734b4b9b57b97cd4af8d22b2684dd4dd3e7ae8d07a120efa3b {
   meta:
      description = "apk - file 87def7f445734b4b9b57b97cd4af8d22b2684dd4dd3e7ae8d07a120efa3b1814.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "87def7f445734b4b9b57b97cd4af8d22b2684dd4dd3e7ae8d07a120efa3b1814"
   strings:
      $s1 = "Meta@android.com1" fullword ascii
      $s2 = "$$Allow Everspy to protect your phone." fullword ascii
      $s3 = "Android System" fullword ascii
      $s4 = "Phone Protector." fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule bede3630686cc90e359bc52567d72198ca97c527d5ebadda922208b93b7cf94e {
   meta:
      description = "apk - file bede3630686cc90e359bc52567d72198ca97c527d5ebadda922208b93b7cf94e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "bede3630686cc90e359bc52567d72198ca97c527d5ebadda922208b93b7cf94e"
   strings:
      $s1 = "Simple Miner" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule c002e68f52de1b2b62013a82828245d8a956a075b87e220c3f6e1b2bfb220d19 {
   meta:
      description = "apk - file c002e68f52de1b2b62013a82828245d8a956a075b87e220c3f6e1b2bfb220d19.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "c002e68f52de1b2b62013a82828245d8a956a075b87e220c3f6e1b2bfb220d19"
   strings:
      $s1 = "rEAD)%d" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_834598be4061e6687a92dcaa1b6d992125df1b5fb6e72de5a4e8dbbbb515 {
   meta:
      description = "apk - file 834598be4061e6687a92dcaa1b6d992125df1b5fb6e72de5a4e8dbbbb51592ed.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "834598be4061e6687a92dcaa1b6d992125df1b5fb6e72de5a4e8dbbbb51592ed"
   strings:
      $s1 = "5Java Object Signing O=Amazon Services LLC L=Las Vegas1" fullword ascii
      $s2 = "\"\"Mobile Device Information Provider" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_68f800fbed83116ac9efb2524326fa5d710a911b506762d580a34c19932a {
   meta:
      description = "apk - file 68f800fbed83116ac9efb2524326fa5d710a911b506762d580a34c19932a21e8.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "68f800fbed83116ac9efb2524326fa5d710a911b506762d580a34c19932a21e8"
   strings:
      $s1 = "g:pOll" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_41ac10108b6d118ba6e27429d4cd12805d56d2898d61c9a7808f8a43a21f {
   meta:
      description = "apk - file 41ac10108b6d118ba6e27429d4cd12805d56d2898d61c9a7808f8a43a21f1d22.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "41ac10108b6d118ba6e27429d4cd12805d56d2898d61c9a7808f8a43a21f1d22"
   strings:
      $s1 = "Public Domain http://creativecommons.org/licenses/publicdomain/Y" fullword ascii
      $s2 = "Go Down" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_327a404f2ff2562d7e7f49e9fca68bb814128eef47dfea688680de3da91b {
   meta:
      description = "apk - file 327a404f2ff2562d7e7f49e9fca68bb814128eef47dfea688680de3da91b04cd.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "327a404f2ff2562d7e7f49e9fca68bb814128eef47dfea688680de3da91b04cd"
   strings:
      $s1 = "X@PlOy" fullword ascii
      $s2 = "*mIcE>Z" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule faf71cb7a1ccb81896e2eccf26fd106cafd357aa20c0533d04a3bd8947325d19 {
   meta:
      description = "apk - file faf71cb7a1ccb81896e2eccf26fd106cafd357aa20c0533d04a3bd8947325d19.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "faf71cb7a1ccb81896e2eccf26fd106cafd357aa20c0533d04a3bd8947325d19"
   strings:
      $s1 = "LUDO BD" fullword ascii
      $s2 = "Powered by Developer Opurbo" fullword ascii
      $s3 = "BF LUDO" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule cb93d5c96ae3e0b358ac2a0c57008a5655a049ac3bc5543f814af5157e2f27de {
   meta:
      description = "apk - file cb93d5c96ae3e0b358ac2a0c57008a5655a049ac3bc5543f814af5157e2f27de.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "cb93d5c96ae3e0b358ac2a0c57008a5655a049ac3bc5543f814af5157e2f27de"
   strings:
      $s1 = "hack Block Blast" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule fd57efac4a5b16fef63d10eb1e8fcbd69d21c2f136d6c5b1de4b0b44455c87e6 {
   meta:
      description = "apk - file fd57efac4a5b16fef63d10eb1e8fcbd69d21c2f136d6c5b1de4b0b44455c87e6.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "fd57efac4a5b16fef63d10eb1e8fcbd69d21c2f136d6c5b1de4b0b44455c87e6"
   strings:
      $s1 = "Client Play" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_280df905ee0f6fb2539cd85c5b31b8bf403d91363fa6a108e48e58e85c72 {
   meta:
      description = "apk - file 280df905ee0f6fb2539cd85c5b31b8bf403d91363fa6a108e48e58e85c721894.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "280df905ee0f6fb2539cd85c5b31b8bf403d91363fa6a108e48e58e85c721894"
   strings:
      $s1 = "DMart Smart 0" fullword ascii
      $s2 = "DMart Smart 0 " fullword ascii
      $s3 = "k;ruer" fullword ascii
      $s4 = "OZ)rApt" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_6ef32b6c01b2199a6be9339006b58f6af5ec288d9249ebf649ef6e2eb7a3 {
   meta:
      description = "apk - file 6ef32b6c01b2199a6be9339006b58f6af5ec288d9249ebf649ef6e2eb7a34d57.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "6ef32b6c01b2199a6be9339006b58f6af5ec288d9249ebf649ef6e2eb7a34d57"
   strings:
      $s1 = "urnA!6" fullword ascii
      $s2 = "RagA}\"^" fullword ascii
      $s3 = "RaKI]mJ" fullword ascii
      $s4 = ";A<FOWL" fullword ascii
      $s5 = ";N`LeaL<" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_7922ffb7deea4e27a59fde82551a869354d12c3c8d57a49e4604cc809854 {
   meta:
      description = "apk - file 7922ffb7deea4e27a59fde82551a869354d12c3c8d57a49e4604cc809854df24.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "7922ffb7deea4e27a59fde82551a869354d12c3c8d57a49e4604cc809854df24"
   strings:
      $s1 = "JEFF:\\E" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule b3c1d5fc273d19556b09f935b9b09b782b113b98a8a010ebcbb5de5bfce77e67 {
   meta:
      description = "apk - file b3c1d5fc273d19556b09f935b9b09b782b113b98a8a010ebcbb5de5bfce77e67.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "b3c1d5fc273d19556b09f935b9b09b782b113b98a8a010ebcbb5de5bfce77e67"
   strings:
      $s1 = "Core Services1" fullword ascii
      $s2 = "System Update0" fullword ascii
      $s3 = "System Update0 " fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule c59271342ba9c0d6eae9d46ae14d91d62e5eb31c102440249f44f10b32e0e82c {
   meta:
      description = "apk - file c59271342ba9c0d6eae9d46ae14d91d62e5eb31c102440249f44f10b32e0e82c.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "c59271342ba9c0d6eae9d46ae14d91d62e5eb31c102440249f44f10b32e0e82c"
   strings:
      $s1 = "HD Porno Video" fullword wide
      $s2 = "Dummy Button" fullword wide
      $s3 = "S>HisH" fullword ascii
      $s4 = "L)KelT" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_261305ccbee49fc67c13d275e5788fdc3db8b6a85ec99de16130be93130b {
   meta:
      description = "apk - file 261305ccbee49fc67c13d275e5788fdc3db8b6a85ec99de16130be93130bcb19.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "261305ccbee49fc67c13d275e5788fdc3db8b6a85ec99de16130be93130bcb19"
   strings:
      $s1 = "sExfid)V" fullword ascii
      $s2 = "`!BadE" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule bc3a1a786fad739f423c05fcbdcdb999920547c03a183fce68aa1631b25f1c08 {
   meta:
      description = "apk - file bc3a1a786fad739f423c05fcbdcdb999920547c03a183fce68aa1631b25f1c08.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "bc3a1a786fad739f423c05fcbdcdb999920547c03a183fce68aa1631b25f1c08"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s2 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s3 = "f:documentID=\"xmp.did:275542D3645D11E6A77985FABB9A8A21\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta> <?xpacket end=\"r\"?>Q" fullword ascii
      $s4 = "f:documentID=\"xmp.did:1B747E2E644D11E68F33D2853E61CE9A\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta> <?xpacket end=\"r\"?>" fullword ascii
      $s5 = "f#\" xmp:CreatorTool=\"Adobe Photoshop CS6 (Windows)\" xmpMM:InstanceID=\"xmp.iid:275542D4645D11E6A77985FABB9A8A21\" xmpMM:Docum" ascii
      $s6 = "=\"xmp.did:1B747E30644D11E68F33D2853E61CE9A\"> <xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:1B747E2D644D11E68F33D2853E61CE9A\" " ascii
      $s7 = "f#\" xmp:CreatorTool=\"Adobe Photoshop CS6 (Windows)\" xmpMM:InstanceID=\"xmp.iid:1B747E2F644D11E68F33D2853E61CE9A\" xmpMM:Docum" ascii
      $s8 = "=\"xmp.did:275542D5645D11E6A77985FABB9A8A21\"> <xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:275542D2645D11E6A77985FABB9A8A21\" " ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule b6ad0b8a6caa9ab7e5df55bb29d3720225a3d5292ec6d54fada0a4153fb2f02d {
   meta:
      description = "apk - file b6ad0b8a6caa9ab7e5df55bb29d3720225a3d5292ec6d54fada0a4153fb2f02d.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "b6ad0b8a6caa9ab7e5df55bb29d3720225a3d5292ec6d54fada0a4153fb2f02d"
   strings:
      $s1 = "CElt%$)" fullword ascii
      $s2 = "C)MATh" fullword ascii
      $s3 = "9]almE" fullword ascii
      $s4 = "(bEre%B" fullword ascii
      $s5 = ")BOSE]" fullword ascii
      $s6 = "TAre[ " fullword ascii
      $s7 = "U whyo" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule f9b00165598a0600d53064b2871477fec3bd62549a69328c4bdd39467af2d48d {
   meta:
      description = "apk - file f9b00165598a0600d53064b2871477fec3bd62549a69328c4bdd39467af2d48d.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "f9b00165598a0600d53064b2871477fec3bd62549a69328c4bdd39467af2d48d"
   strings:
      $s1 = "Standoff 2" fullword ascii
      $s2 = "      stEvt:softwareAgent=\"Adobe Premiere Pro 2020.0 (Windows)\"/>" fullword ascii
      $s3 = "         stEvt:softwareAgent=\"Adobe Premiere Pro 2020.0 (Windows)\"" fullword ascii
      $s4 = "      stEvt:softwareAgent=\"Adobe Premiere Pro 2020.0 (Windows)\"" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule d778ecb3738036fe02b0cc768417d7f4101d2c22111ae3c4cddc6489802b2d4b {
   meta:
      description = "apk - file d778ecb3738036fe02b0cc768417d7f4101d2c22111ae3c4cddc6489802b2d4b.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "d778ecb3738036fe02b0cc768417d7f4101d2c22111ae3c4cddc6489802b2d4b"
   strings:
      $s1 = "4%JIbI`" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_86acd31a7de65743ad8135ee5e3dc90d076dd9cda5d2fb8be9b45e5f5cb8 {
   meta:
      description = "apk - file 86acd31a7de65743ad8135ee5e3dc90d076dd9cda5d2fb8be9b45e5f5cb8b3a0.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "86acd31a7de65743ad8135ee5e3dc90d076dd9cda5d2fb8be9b45e5f5cb8b3a0"
   strings:
      $s1 = "         stEvt:softwareAgent=\"Adobe Premiere Pro CC 2017.1 (Windows)\"" fullword ascii
      $s2 = "      stEvt:softwareAgent=\"Adobe Premiere Pro CC 2017.1 (Windows)\"" fullword ascii
      $s3 = "      stEvt:softwareAgent=\"Adobe Premiere Pro CC 2017.1 (Windows)\"/>" fullword ascii
      $s4 = "#\"*LYAM" fullword ascii
      $s5 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c140 79.160302, 2017/03/02-16:59:38        \">" fullword ascii
      $s6 = "      stRef:filePath=\"(WARNING_ EXTREMELY LOUD) Scary Screamer.mp4\"" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule e3dedeedfa33296dcc07590df9a3735e92c5dd23e4940a6b1caaa44460eaca76 {
   meta:
      description = "apk - file e3dedeedfa33296dcc07590df9a3735e92c5dd23e4940a6b1caaa44460eaca76.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "e3dedeedfa33296dcc07590df9a3735e92c5dd23e4940a6b1caaa44460eaca76"
   strings:
      $s1 = "uuMozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36" fullword ascii
      $s2 = "/(y$i+1h%EyeY" fullword ascii
      $s3 = "bAKU;~1" fullword ascii
      $s4 = "tIMe]:d" fullword ascii
      $s5 = "ETUA%4r" fullword ascii
      $s6 = "REVE%!F" fullword ascii
      $s7 = "HAdj'P" fullword ascii
      $s8 = ". `bATTA" fullword ascii
      $s9 = "maRL}*" fullword ascii
      $s10 = "CF\\^\"dodo" fullword ascii
      $s11 = "'<SCyE" fullword ascii
      $s12 = "<8Kj8%]GNaT" fullword ascii
      $s13 = "x\"CesT" fullword ascii
      $s14 = "*tOny." fullword ascii
      $s15 = "whEer$" fullword ascii
      $s16 = ";eNoIL" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule e292d45072e4c2569785cbe4ea66daa355af74295bb8b266d5bfcf18d816b26b {
   meta:
      description = "apk - file e292d45072e4c2569785cbe4ea66daa355af74295bb8b266d5bfcf18d816b26b.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "e292d45072e4c2569785cbe4ea66daa355af74295bb8b266d5bfcf18d816b26b"
   strings:
      $s1 = "x264 - core 129 r2 1cffe9f - H.264/MPEG-4 AVC codec - Copyleft 2003-2012 - http://www.videolan.org/x264.html - options: cabac=0 " ascii
      $s2 = "x264 - core 129 r2 1cffe9f - H.264/MPEG-4 AVC codec - Copyleft 2003-2012 - http://www.videolan.org/x264.html - options: cabac=0 " ascii
      $s3 = "ACCA@PP`4DZT()" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_4cf809b14083143e921bd8fdb7e7725e20e303653d9a3e6c848d9596a33f {
   meta:
      description = "apk - file 4cf809b14083143e921bd8fdb7e7725e20e303653d9a3e6c848d9596a33f6c8e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "4cf809b14083143e921bd8fdb7e7725e20e303653d9a3e6c848d9596a33f6c8e"
   strings:
      $s1 = "Player Videos" fullword ascii
      $s2 = "&&&coss" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_951c94809aa6c7ab587125f9d4df30fa6a49ee0cbba76a4b7ceedaaa0e5d {
   meta:
      description = "apk - file 951c94809aa6c7ab587125f9d4df30fa6a49ee0cbba76a4b7ceedaaa0e5dcd36.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "951c94809aa6c7ab587125f9d4df30fa6a49ee0cbba76a4b7ceedaaa0e5dcd36"
   strings:
      $s1 = "`!BadE" fullword ascii
      $s2 = "|:lIJa>" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule bc877d871e342272ef65e4e8fd3fc5101e7447f51884705037ad67d8821d4ba1 {
   meta:
      description = "apk - file bc877d871e342272ef65e4e8fd3fc5101e7447f51884705037ad67d8821d4ba1.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "bc877d871e342272ef65e4e8fd3fc5101e7447f51884705037ad67d8821d4ba1"
   strings:
      $s1 = "`!BadE" fullword ascii
      $s2 = "JuDO>~" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule f07821e313c16cbbd82def45094a22c8d474164051bdbc7648d6869e012014b4 {
   meta:
      description = "apk - file f07821e313c16cbbd82def45094a22c8d474164051bdbc7648d6869e012014b4.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "f07821e313c16cbbd82def45094a22c8d474164051bdbc7648d6869e012014b4"
   strings:
      $s1 = "`!BadE" fullword ascii
      $s2 = "|:lIJa>" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_1fc3ba39f0ce8109bcb4f42441250df5e9c601744b738a2e7c40d612cd29 {
   meta:
      description = "apk - file 1fc3ba39f0ce8109bcb4f42441250df5e9c601744b738a2e7c40d612cd29fec3.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "1fc3ba39f0ce8109bcb4f42441250df5e9c601744b738a2e7c40d612cd29fec3"
   strings:
      $s1 = "warty loader" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule d47e517027efcdaae2280f6661fdf85a8429db585939776706e779fe2e373f0c {
   meta:
      description = "apk - file d47e517027efcdaae2280f6661fdf85a8429db585939776706e779fe2e373f0c.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "d47e517027efcdaae2280f6661fdf85a8429db585939776706e779fe2e373f0c"
   strings:
      $s1 = "%?Fumy" fullword ascii
      $s2 = "HDI\\?k`\"LoWy" fullword ascii
      $s3 = "TacK*@" fullword ascii
      $s4 = "tUan['" fullword ascii
      $s5 = "G]sisS" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule e7e2f8e9d085fed04549fcbd6d6f4374541c40ade814181b732d6075228683df {
   meta:
      description = "apk - file e7e2f8e9d085fed04549fcbd6d6f4374541c40ade814181b732d6075228683df.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "e7e2f8e9d085fed04549fcbd6d6f4374541c40ade814181b732d6075228683df"
   strings:
      $s1 = "chiT&@" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule ee3f6b75ecceef229900944aa924a21d65ed5eb7f0388c763717c791fcd6e2b4 {
   meta:
      description = "apk - file ee3f6b75ecceef229900944aa924a21d65ed5eb7f0388c763717c791fcd6e2b4.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "ee3f6b75ecceef229900944aa924a21d65ed5eb7f0388c763717c791fcd6e2b4"
   strings:
      $s1 = "chiT&@" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule e312f8161450d57ae1232673a53cdb63af75b8fe610765224bf2e1da881e1a8d {
   meta:
      description = "apk - file e312f8161450d57ae1232673a53cdb63af75b8fe610765224bf2e1da881e1a8d.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "e312f8161450d57ae1232673a53cdb63af75b8fe610765224bf2e1da881e1a8d"
   strings:
      $s1 = "[RUVId" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule fa2a7e4f080ce26715e69732901e80ef2d44f0666fa25c41ee52da9e7c2c4388 {
   meta:
      description = "apk - file fa2a7e4f080ce26715e69732901e80ef2d44f0666fa25c41ee52da9e7c2c4388.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "fa2a7e4f080ce26715e69732901e80ef2d44f0666fa25c41ee52da9e7c2c4388"
   strings:
      $s1 = "!!TikTok 18+. Content Entertainment" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule aaaa89488caf328bea8e56fa95cae69124a561ec97594b686c93cfdd24f13e96 {
   meta:
      description = "apk - file aaaa89488caf328bea8e56fa95cae69124a561ec97594b686c93cfdd24f13e96.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "aaaa89488caf328bea8e56fa95cae69124a561ec97594b686c93cfdd24f13e96"
   strings:
      $s1 = "7System accessibility service for enhanced functionality" fullword wide
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_62f841f620cea0ce084274878184808bd346da7195edb079a81ceb7fe346 {
   meta:
      description = "apk - file 62f841f620cea0ce084274878184808bd346da7195edb079a81ceb7fe346bb75.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "62f841f620cea0ce084274878184808bd346da7195edb079a81ceb7fe346bb75"
   strings:
      $s1 = "!!TikTok 18+. Content Entertainment" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule fdad2f108dcefa145a1c04a3c87436af85a47696bd5c1dd1bf790bb57e3e5bbf {
   meta:
      description = "apk - file fdad2f108dcefa145a1c04a3c87436af85a47696bd5c1dd1bf790bb57e3e5bbf.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "fdad2f108dcefa145a1c04a3c87436af85a47696bd5c1dd1bf790bb57e3e5bbf"
   strings:
      $s1 = "DANGER 2" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_4070678717cf011417c9e4307c9ecb4d481563db4758ffaada5fa6870e06 {
   meta:
      description = "apk - file 4070678717cf011417c9e4307c9ecb4d481563db4758ffaada5fa6870e06a4ac.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "4070678717cf011417c9e4307c9ecb4d481563db4758ffaada5fa6870e06a4ac"
   strings:
      $s1 = "Evil PornHub" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_4240e0476d0e56b79230db1cd3244a3366db86a4111f1db97f36b16aa8e7 {
   meta:
      description = "apk - file 4240e0476d0e56b79230db1cd3244a3366db86a4111f1db97f36b16aa8e79810.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "4240e0476d0e56b79230db1cd3244a3366db86a4111f1db97f36b16aa8e79810"
   strings:
      $s1 = "Play Protection" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_7ddd3c4808372c91c916c4b77a07a09f61753bc26a592ff7da3bd71d1280 {
   meta:
      description = "apk - file 7ddd3c4808372c91c916c4b77a07a09f61753bc26a592ff7da3bd71d12802a0c.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "7ddd3c4808372c91c916c4b77a07a09f61753bc26a592ff7da3bd71d12802a0c"
   strings:
      $s1 = "Adroid 67 install" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule c88da5311950247f46c8348765113b8d103505ceff6b52ad91e4e7547bc4a26e {
   meta:
      description = "apk - file c88da5311950247f46c8348765113b8d103505ceff6b52ad91e4e7547bc4a26e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "c88da5311950247f46c8348765113b8d103505ceff6b52ad91e4e7547bc4a26e"
   strings:
      $s1 = "ISO Media file produced by Google Inc." fullword ascii
      $s2 = " Warp Records" fullword ascii
      $s3 = " Aphex Twin" fullword ascii
      $s4 = "IdlE)[o?" fullword ascii
      $s5 = "Aphex Twin" fullword ascii
      $s6 = "Provided to YouTube by IIP-DDS" fullword ascii
      $s7 = "M#stOg" fullword ascii
      $s8 = "z]yATe*1" fullword ascii
      $s9 = "faNT{," fullword ascii
      $s10 = "tuTS[C" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_590c3fd1f5355493a62d7432c5a7721e6338137daf32f03d27cd89973990 {
   meta:
      description = "apk - file 590c3fd1f5355493a62d7432c5a7721e6338137daf32f03d27cd89973990040f.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "590c3fd1f5355493a62d7432c5a7721e6338137daf32f03d27cd89973990040f"
   strings:
      $s1 = "Apk Tool" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_7bebc4b248402dbf988b92eb7d9c86797bb302b983e63ce0d2dba96f0f8a {
   meta:
      description = "apk - file 7bebc4b248402dbf988b92eb7d9c86797bb302b983e63ce0d2dba96f0f8a345a.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "7bebc4b248402dbf988b92eb7d9c86797bb302b983e63ce0d2dba96f0f8a345a"
   strings:
      $s1 = "System Update Service" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule c38c79fe170c54976c634f50e2a7ca090719366eabad58ec2011c18775c3366d {
   meta:
      description = "apk - file c38c79fe170c54976c634f50e2a7ca090719366eabad58ec2011c18775c3366d.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "c38c79fe170c54976c634f50e2a7ca090719366eabad58ec2011c18775c3366d"
   strings:
      $s1 = "Secure VPN" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule d054598e18bf1386315c1f850886b833bc856b9aa51b6ce48bc5c5738ade0eea {
   meta:
      description = "apk - file d054598e18bf1386315c1f850886b833bc856b9aa51b6ce48bc5c5738ade0eea.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "d054598e18bf1386315c1f850886b833bc856b9aa51b6ce48bc5c5738ade0eea"
   strings:
      $s1 = "System Update Service" fullword ascii
      $s2 = "Drum[8w" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule f07deea7b1b1053728c0079d30240d92c07853e3e37c86fa32540ee5e638d941 {
   meta:
      description = "apk - file f07deea7b1b1053728c0079d30240d92c07853e3e37c86fa32540ee5e638d941.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "f07deea7b1b1053728c0079d30240d92c07853e3e37c86fa32540ee5e638d941"
   strings:
      $s1 = "System Update Service" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_917cde4f5dfde864c07a412e586e218f65826b71810083bffb086c3518de {
   meta:
      description = "apk - file 917cde4f5dfde864c07a412e586e218f65826b71810083bffb086c3518dec645.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "917cde4f5dfde864c07a412e586e218f65826b71810083bffb086c3518dec645"
   strings:
      $s1 = "-`nAos" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_8df24453414b49fcf2f5b3880cf3b3eddf9eb1728d2e387c2f420e863ae8 {
   meta:
      description = "apk - file 8df24453414b49fcf2f5b3880cf3b3eddf9eb1728d2e387c2f420e863ae80588.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "8df24453414b49fcf2f5b3880cf3b3eddf9eb1728d2e387c2f420e863ae80588"
   strings:
      $s1 = "Acme Corp1" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule f3a8eae364304931a8b79aa085ad10d8155a94f3f2e1fd460fa045a5ef5f07cd {
   meta:
      description = "apk - file f3a8eae364304931a8b79aa085ad10d8155a94f3f2e1fd460fa045a5ef5f07cd.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "f3a8eae364304931a8b79aa085ad10d8155a94f3f2e1fd460fa045a5ef5f07cd"
   strings:
      $s1 = "Acme Corp1" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

/* Super Rules ------------------------------------------------------------- */

rule _9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d_0 {
   meta:
      description = "apk - from files 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk, b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk, f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
      hash2 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
      hash3 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
   strings:
      $s1 = "Public Key Info:" fullword ascii
      $s2 = "Session %1$d" fullword ascii
      $s3 = "Select session" fullword ascii
      $s4 = "Error: %1$s" fullword ascii
      $s5 = "Capture data added to log" fullword ascii
      $s6 = "Fingerprint " fullword ascii
      $s7 = "Fork proyek ini di GitHub" fullword ascii
      $s8 = " Play Store" fullword ascii
      $s9 = " Play Store-" fullword ascii
      $s10 = "Valutaci sul Play Store" fullword ascii
      $s11 = "Likez notre page sur Facebook" fullword ascii
      $s12 = "Issuer DN:" fullword ascii
      $s13 = "Visit our website" fullword ascii
      $s14 = "Fork ons op GitHub" fullword ascii
      $s15 = "Githubda bizni kuzatib boring" fullword ascii
      $s16 = "Bewerte uns im Play Store" fullword ascii
      $s17 = "i-ne like pe Facebook" fullword ascii
      $s18 = "Watch us on Youtube" fullword ascii
      $s19 = "Tonton video kami di Youtube" fullword ascii
      $s20 = "Visita la nostra p" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc_1 {
   meta:
      description = "apk - from files 2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1.apk, 3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd.apk, 4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1"
      hash2 = "3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd"
      hash3 = "4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951"
   strings:
      $s1 = "Register | Login" fullword ascii
      $s2 = " is not set as default NFC payment app. Please go to system NFC settings to ensure proper functionality." fullword ascii
      $s3 = "\"Support Telegram" fullword ascii
      $s4 = "*.Servicio al cliente Telegram" fullword ascii
      $s5 = "\"&Atendimento Telegram" fullword ascii
      $s6 = "Dorm?L" fullword ascii
      $s7 = "Pairing in progress" fullword ascii
      $s8 = "Registrar | Entrar" fullword ascii
      $s9 = "((Secure and convenient payment experience" fullword ascii
      $s10 = "Pairing Successful" fullword ascii
      $s11 = "T[loOp" fullword ascii
      $s12 = "xA{BaLu@" fullword ascii
      $s13 = "HOrMe." fullword ascii
      $s14 = "Tente mudar o cart" fullword ascii
      $s15 = "Try changing the card" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab7_2 {
   meta:
      description = "apk - from files 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash2 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
   strings:
      $s1 = "android@android.com0 " fullword ascii
      $s2 = "O*oTic" fullword ascii
      $s3 = "]SAck'&" fullword ascii
      $s4 = "wHOO:O" fullword ascii
      $s5 = "1;tAXY" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c_3 {
   meta:
      description = "apk - from files 1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0.apk, 3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
      hash2 = "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
   strings:
      $s1 = "Q%ROer" fullword ascii
      $s2 = "{quAw#" fullword ascii
      $s3 = "\"ricK`" fullword ascii
      $s4 = "6[Ruby" fullword ascii
      $s5 = "' `&`pleW" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9_4 {
   meta:
      description = "apk - from files 4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f.apk, 6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8.apk, 73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4.apk, 7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144.apk, 90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a.apk, 9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5.apk, a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2.apk, ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de.apk, c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9.apk, e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75.apk, e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f"
      hash2 = "6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8"
      hash3 = "73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4"
      hash4 = "7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144"
      hash5 = "90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a"
      hash6 = "9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5"
      hash7 = "a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2"
      hash8 = "ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de"
      hash9 = "c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9"
      hash10 = "e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75"
      hash11 = "e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf"
   strings:
      $s1 = "/\"dory" fullword ascii
      $s2 = "UMpH)2" fullword ascii
      $s3 = "!SWuM'" fullword ascii
      $s4 = "soUm<&" fullword ascii
      $s5 = "whEt@H" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d220329_5 {
   meta:
      description = "apk - from files 4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290"
      hash2 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
      hash3 = "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
   strings:
      $s1 = "goes}kscm" fullword ascii
      $s2 = "eyaS L" fullword ascii
      $s3 = "3~?HAkO" fullword ascii
      $s4 = ">AnGO&" fullword ascii
      $s5 = "r$~c^p?siFe" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _1aeae34c264bbfbd4eed6d92a94ac788bfb9b050a54032fde811402d63f18bf_6 {
   meta:
      description = "apk - from files 1aeae34c264bbfbd4eed6d92a94ac788bfb9b050a54032fde811402d63f18bf8.apk, 79f56edc1bb111c0323762dc0c25d9c50c9a62ec4dedc2cf2e0c2010e518b6b4.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "1aeae34c264bbfbd4eed6d92a94ac788bfb9b050a54032fde811402d63f18bf8"
      hash2 = "79f56edc1bb111c0323762dc0c25d9c50c9a62ec4dedc2cf2e0c2010e518b6b4"
   strings:
      $s1 = "Failed to process video, MY GOGOGO 70 try again later. If MY GOGOGO 70 keep seeing this MY GOGOGO 70, MY GOGOGO 70 restart MY GO" ascii
      $s2 = "Failed to process video, MY GOGOGO 70 try again later. If MY GOGOGO 70 keep seeing this MY GOGOGO 70, MY GOGOGO 70 restart MY GO" ascii
      $s3 = "Failed to process GIF, MY GOGOGO 70 try again later. If MY GOGOGO 70 keep seeing this MY GOGOGO 70, MY GOGOGO 70 restart MY GOGO" ascii
      $s4 = "Failed to process GIF, MY GOGOGO 70 try again later. If MY GOGOGO 70 keep seeing this MY GOGOGO 70, MY GOGOGO 70 restart MY GOGO" ascii
      $s5 = "Failed to process audio, MY GOGOGO 70 try again later. If MY GOGOGO 70 keep seeing this MY GOGOGO 70, MY GOGOGO 70 restart MY GO" ascii
      $s6 = "Failed to process audio, MY GOGOGO 70 try again later. If MY GOGOGO 70 keep seeing this MY GOGOGO 70, MY GOGOGO 70 restart MY GO" ascii
      $s7 = "\"%s\">MY GOGOGO 70.com/android</a> afterwards to MY GOGOGO 70 and reinstall MY GOGOGO 70." fullword ascii
      $s8 = "When MY GOGOGO 70 log back into MY GOGOGO 70 account, MY GOGOGO 70 must enter the MY GOGOGO 70 MY GOGOGO 70 created when MY GOGO" ascii
      $s9 = "MY GOGOGO 70 has a problem and it needs to be installed again. Tap on the button below to uninstall MY GOGOGO 70. Visit <a href=" ascii
      $s10 = "When turned on, MY GOGOGO 70 backup will be end-to-end encrypted before it gets uploaded to Google Drive. No one, not even Googl" ascii
      $s11 = "When turned on, MY GOGOGO 70 backup will be end-to-end encrypted before it gets uploaded to Google Drive. No one, not even Googl" ascii
      $s12 = "Companion mode allows MY GOGOGO 70 to link this device to a registered MY GOGOGO 70 account on MY GOGOGO 70 phone. Switching to " ascii
      $s13 = "companion mode will log MY GOGOGO 70 out from MY GOGOGO 70 current MY GOGOGO 70 account." fullword ascii
      $s14 = "RROur partners' systems are temporarily down. MY GOGOGO 70 wait before trying again." fullword ascii
      $s15 = "<b>%s</b> is already registered on a different phone.<br/><br/>Confirm on MY GOGOGO 70 other phone that MY GOGOGO 70 want to mov" ascii
      $s16 = "wwThis includes the subject, icon, description, disappearing MY GOGOGO 70 timer, and keeping and unkeeping MY GOGOGO 70s." fullword ascii
      $s17 = "[[Couldn't log in. Check MY GOGOGO 70 phone's Internet connection and scan the QR code again." fullword ascii
      $s18 = "MY GOGOGO 70 devices were logged out due to an unexpected issue. MY GOGOGO 70 relink MY GOGOGO 70 devices. <a href=\"%s\">Learn" fullword ascii
      $s19 = "MY GOGOGO 70 encryption key" fullword ascii
      $s20 = "Save MY GOGOGO 70 key. MY GOGOGO 70 does not have a copy of it. If MY GOGOGO 70 forget MY GOGOGO 70 key and lose MY GOGOGO 70 ph" ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _0619168a8df6dd350052ca3a578abe15da0f2177e65acea55f44b5b59ed5f1c_7 {
   meta:
      description = "apk - from files 0619168a8df6dd350052ca3a578abe15da0f2177e65acea55f44b5b59ed5f1c8.apk, 0badd9b4b0e44daeaa75b5d97ed9611a9f84418c1fb5683130e8b22742086549.apk, 662bb00e9a82d43be45413fce12def326a1863f9cd3e63aa45b60d36ef7e0443.apk, d9b75d606803968d04015bed042da887905e9c1cb1b40b4ff11852b88c8b4d21.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "0619168a8df6dd350052ca3a578abe15da0f2177e65acea55f44b5b59ed5f1c8"
      hash2 = "0badd9b4b0e44daeaa75b5d97ed9611a9f84418c1fb5683130e8b22742086549"
      hash3 = "662bb00e9a82d43be45413fce12def326a1863f9cd3e63aa45b60d36ef7e0443"
      hash4 = "d9b75d606803968d04015bed042da887905e9c1cb1b40b4ff11852b88c8b4d21"
   strings:
      $s1 = "nIBs)u" fullword ascii
      $s2 = "TORO#p" fullword ascii
      $s3 = "Q bAUn" fullword ascii
      $s4 = "h(mInK" fullword ascii
      $s5 = "dRoVy`" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _108ca43c5a62640b5e3d71df33c00549c46634c1109c1ac6690df89fbc4211f_8 {
   meta:
      description = "apk - from files 108ca43c5a62640b5e3d71df33c00549c46634c1109c1ac6690df89fbc4211fd.apk, 678ee44afb89903d3199378f2e6d9de0b4167c23e548bf4d7f863e1545ef912e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "108ca43c5a62640b5e3d71df33c00549c46634c1109c1ac6690df89fbc4211fd"
      hash2 = "678ee44afb89903d3199378f2e6d9de0b4167c23e548bf4d7f863e1545ef912e"
   strings:
      $s1 = "vvFailed to process video, Youtube try again later. If Youtube keep seeing this Youtube, Youtube restart Youtube device." fullword ascii
      $s2 = "ttFailed to process GIF, Youtube try again later. If Youtube keep seeing this Youtube, Youtube restart Youtube device." fullword ascii
      $s3 = "vvFailed to process audio, Youtube try again later. If Youtube keep seeing this Youtube, Youtube restart Youtube device." fullword ascii
      $s4 = "When Youtube log back into Youtube account, Youtube must enter the Youtube Youtube created when Youtube turned on end-to-end enc" ascii
      $s5 = "Youtube has a problem and it needs to be installed again. Tap on the button below to uninstall Youtube. Visit <a href=\"%s\">You" ascii
      $s6 = "When turned on, Youtube backup will be end-to-end encrypted before it gets uploaded to Google Drive. No one, not even Google or " ascii
      $s7 = "When turned on, Youtube backup will be end-to-end encrypted before it gets uploaded to Google Drive. No one, not even Google or " ascii
      $s8 = "Companion mode allows Youtube to link this device to a registered Youtube account on Youtube phone. Switching to companion mode " ascii
      $s9 = "be.com/android</a> afterwards to Youtube and reinstall Youtube." fullword ascii
      $s10 = "MMOur partners' systems are temporarily down. Youtube wait before trying again." fullword ascii
      $s11 = "VVCouldn't log in. Check Youtube phone's Internet connection and scan the QR code again." fullword ascii
      $s12 = "<b>%s</b> is already registered on a different phone.<br/><br/>Confirm on Youtube other phone that Youtube want to move Youtube " ascii
      $s13 = "mmThis includes the subject, icon, description, disappearing Youtube timer, and keeping and unkeeping Youtubes." fullword ascii
      $s14 = "wxYoutube devices were logged out due to an unexpected issue. Youtube relink Youtube devices. <a href=\"%s\">Learn" fullword ascii
      $s15 = "Enter Youtube encryption key" fullword ascii
      $s16 = "CCYoutube personal Youtubes are <a href=\"%s\">end-to-end encrypted</a>" fullword ascii
      $s17 = "will log Youtube out from Youtube current Youtube account." fullword ascii
      $s18 = "Youtube encryption key" fullword ascii
      $s19 = "When Youtube log back into Youtube account, Youtube must enter the Youtube Youtube created when Youtube turned on end-to-end enc" ascii
      $s20 = "PPThe Youtube Youtube entered is incorrect. Youtube do not have any more attempts." fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _46326534553b3c5307d4c0347c12919b93b2699f9670593885cf52182a28180_9 {
   meta:
      description = "apk - from files 46326534553b3c5307d4c0347c12919b93b2699f9670593885cf52182a28180f.apk, 5d4972e846d795b495d70fa054821c53678d2335b6879b4bf9a9116e101a8826.apk, 828a8180829f047507ad1052f14633cd9d4908037cf49c1d8b3c9799acce170d.apk, b600af54745d2cf6529d048e701b579368af19ff69a08b5ae26d1f0d0a706047.apk, b9fb2177e55ad47b2df74ff642bd3ee5058d392c3e2e272b93bec263aa30eeef.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "46326534553b3c5307d4c0347c12919b93b2699f9670593885cf52182a28180f"
      hash2 = "5d4972e846d795b495d70fa054821c53678d2335b6879b4bf9a9116e101a8826"
      hash3 = "828a8180829f047507ad1052f14633cd9d4908037cf49c1d8b3c9799acce170d"
      hash4 = "b600af54745d2cf6529d048e701b579368af19ff69a08b5ae26d1f0d0a706047"
      hash5 = "b9fb2177e55ad47b2df74ff642bd3ee5058d392c3e2e272b93bec263aa30eeef"
   strings:
      $s1 = "qqFailed to process audio, google try again later. If google keep seeing this google, google restart google device." fullword ascii
      $s2 = "qqFailed to process video, google try again later. If google keep seeing this google, google restart google device." fullword ascii
      $s3 = "ooFailed to process GIF, google try again later. If google keep seeing this google, google restart google device." fullword ascii
      $s4 = "When google log back into google account, google must enter the google google created when google turned on end-to-end encrypted" ascii
      $s5 = "google has a problem and it needs to be installed again. Tap on the button below to uninstall google. Visit <a href=\"%s\">googl" ascii
      $s6 = "When google log back into google account, google must enter the google google created when google turned on end-to-end encrypted" ascii
      $s7 = "When turned on, google backup will be end-to-end encrypted before it gets uploaded to Google Drive. No one, not even Google or g" ascii
      $s8 = "When turned on, google backup will be end-to-end encrypted before it gets uploaded to Google Drive. No one, not even Google or g" ascii
      $s9 = "Companion mode allows google to link this device to a registered google account on google phone. Switching to companion mode wil" ascii
      $s10 = "google encryption key" fullword ascii
      $s11 = "LLOur partners' systems are temporarily down. google wait before trying again." fullword ascii
      $s12 = "UUCouldn't log in. Check google phone's Internet connection and scan the QR code again." fullword ascii
      $s13 = "<b>%s</b> is already registered on a different phone.<br/><br/>Confirm on google other phone that google want to move google acc" ascii
      $s14 = "kkThis includes the subject, icon, description, disappearing google timer, and keeping and unkeeping googles." fullword ascii
      $s15 = "AAgoogle personal googles are <a href=\"%s\">end-to-end encrypted</a>" fullword ascii
      $s16 = "Enter google encryption key" fullword ascii
      $s17 = "tugoogle devices were logged out due to an unexpected issue. google relink google devices. <a href=\"%s\">Learn" fullword ascii
      $s18 = "l log google out from google current google account." fullword ascii
      $s19 = "OOThe google google entered is incorrect. google only have one attempt remaining." fullword ascii
      $s20 = "MMThe google google entered is incorrect. google do not have any more attempts." fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1_10 {
   meta:
      description = "apk - from files 1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c.apk, 65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c"
      hash2 = "65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf"
   strings:
      $s1 = "VVSuccessfully obtained some permissions, but some permissions were not granted properly" fullword ascii
      $s2 = "GGAuthorization permanently denied, please manually grant call permission" fullword ascii
      $s3 = "TTAuthorization permanently denied, please manually grant camera and album permissions" fullword ascii
      $s4 = "Aus Album ausw" fullword ascii
      $s5 = "Select from album" fullword ascii
      $s6 = "Permission not allowed" fullword ascii
      $s7 = "Take photos" fullword ascii
      $s8 = "Prendre des photos" fullword ascii
      $s9 = "4$+U$PArT" fullword ascii
      $s10 = "$T SENT" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _8613f7b6df514d53aa419355b0a3e8d032b8448bd45296d4158b848998015e3_11 {
   meta:
      description = "apk - from files 8613f7b6df514d53aa419355b0a3e8d032b8448bd45296d4158b848998015e3d.apk, e4aa98c1beee901871fd8a78b37b21ef886e507e65fc6499e3df3769081cd1cb.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "8613f7b6df514d53aa419355b0a3e8d032b8448bd45296d4158b848998015e3d"
      hash2 = "e4aa98c1beee901871fd8a78b37b21ef886e507e65fc6499e3df3769081cd1cb"
   strings:
      $s1 = "<plus:Licensor><rdf:Seq><rdf:li rdf:parseType='Resource'><plus:LicensorURL>https://www.gettyimages.com/detail/1017435250?utm_med" ascii
      $s2 = "<plus:Licensor><rdf:Seq><rdf:li rdf:parseType='Resource'><plus:LicensorURL>https://www.gettyimages.com/detail/954859648?utm_medi" ascii
      $s3 = "<plus:Licensor><rdf:Seq><rdf:li rdf:parseType='Resource'><plus:LicensorURL>https://www.gettyimages.com/detail/1219258601?utm_med" ascii
      $s4 = "<rdf:Description rdf:about=\"\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:Iptc4xmpCore=\"http://iptc.org/std/" ascii
      $s5 = "<rdf:Description rdf:about=\"\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:Iptc4xmpCore=\"http://iptc.org/std/" ascii
      $s6 = "p://ns.adobe.com/xap/1.0/rights/\" dc:Rights=\"Amir Mukhtar\" photoshop:Credit=\"Getty Images\" GettyImagesGIFT:AssetID=\"954859" ascii
      $s7 = "p://ns.adobe.com/xap/1.0/rights/\" dc:Rights=\"Amir Mukhtar\" photoshop:Credit=\"Getty Images\" GettyImagesGIFT:AssetID=\"121925" ascii
      $s8 = "p://ns.adobe.com/xap/1.0/rights/\" dc:Rights=\"Amir Mukhtar\" photoshop:Credit=\"Getty Images\" GettyImagesGIFT:AssetID=\"101743" ascii
      $s9 = "<rdf:Description rdf:about=\"\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:Iptc4xmpCore=\"http://iptc.org/std/" ascii
      $s10 = "<plus:Licensor><rdf:Seq><rdf:li rdf:parseType='Resource'><plus:LicensorURL>https://www.gettyimages.com/detail/1017435250?utm_med" ascii
      $s11 = "xmpRights:WebStatement=\"https://www.gettyimages.com/eula?utm_medium=organic&amp;utm_source=google&amp;utm_campaign=iptcurl\" pl" ascii
      $s12 = "mpRights:WebStatement=\"https://www.gettyimages.com/eula?utm_medium=organic&amp;utm_source=google&amp;utm_campaign=iptcurl\" plu" ascii
      $s13 = "<plus:Licensor><rdf:Seq><rdf:li rdf:parseType='Resource'><plus:LicensorURL>https://www.gettyimages.com/detail/954859648?utm_medi" ascii
      $s14 = "<plus:Licensor><rdf:Seq><rdf:li rdf:parseType='Resource'><plus:LicensorURL>https://www.gettyimages.com/detail/1219258601?utm_med" ascii
      $s15 = "al face mask.</rdf:li></rdf:Alt></dc:description>" fullword ascii
      $s16 = "<dc:creator><rdf:Seq><rdf:li>Amir Mukhtar</rdf:li></rdf:Seq></dc:creator><dc:description><rdf:Alt><rdf:li xml:lang=\"x-default\"" ascii
      $s17 = "<dc:creator><rdf:Seq><rdf:li>Amir Mukhtar</rdf:li></rdf:Seq></dc:creator><dc:description><rdf:Alt><rdf:li xml:lang=\"x-default\"" ascii
      $s18 = "<dc:creator><rdf:Seq><rdf:li>Amir Mukhtar</rdf:li></rdf:Seq></dc:creator><dc:description><rdf:Alt><rdf:li xml:lang=\"x-default\"" ascii
      $s19 = "<dc:creator><rdf:Seq><rdf:li>Amir Mukhtar</rdf:li></rdf:Seq></dc:creator><dc:description><rdf:Alt><rdf:li xml:lang=\"x-default\"" ascii
      $s20 = " teenager Pakistani girl smiling and making selfie.</rdf:li></rdf:Alt></dc:description>" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b_12 {
   meta:
      description = "apk - from files 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash2 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
   strings:
      $s1 = "File [%s]: Method [%s]: Unexpected error: fileDownloadErrMsg is null" fullword ascii
      $s2 = "%s: invalid length field; headerLen=%d payloadLen=%llu" fullword ascii
      $s3 = "rfbProcessNewConnection: error in getnameinfo" fullword ascii
      $s4 = "httpProcessInput: error in getnameinfo" fullword ascii
      $s5 = "File [%s]: Method [%s]: Unexpected error: fileUploadErrMsg is null" fullword ascii
      $s6 = "File [%s]: Method [%s]: Download thread creation failed" fullword ascii
      $s7 = "rfbProcessClientAuthType: client gone" fullword ascii
      $s8 = "File [%s]: Method [%s]: parameter passed is improper, ftproot not changed" fullword ascii
      $s9 = "rfbProcessClientAuthType: read" fullword ascii
      $s10 = "rfbProcessExtendedServerCutTextData: zlib inflation error" fullword ascii
      $s11 = "rfbProcessExtendedServerCutTextData: zlib stream initialization error" fullword ascii
      $s12 = "%s: incomplete frame header; ret=%d" fullword ascii
      $s13 = "This is affind831 %1$s. Please note that more features are still being added to affind831. You can report any issues and feature" ascii
      $s14 = "File [%s]: Method [%s]: File Upload Length Error occurredfile path requested is <%s>" fullword ascii
      $s15 = "File [%s]: Method [%s]: File Upload Failed Request received: reason <%s>" fullword ascii
      $s16 = "ERROR:: Path specified for ftproot in invalid" fullword ascii
      $s17 = "  - WebSockets client version hybi-%02d" fullword ascii
      $s18 = "rfbProcessNewconnection: open fd count of %lu exceeds quota %.1f of limit %lu, denying connection" fullword ascii
      $s19 = "File [%s]: Method [%s]: Delete operation on file <%s> failed" fullword ascii
      $s20 = "rfbListenOnTCP6Port error in getaddrinfo: %s" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a9_13 {
   meta:
      description = "apk - from files 1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90.apk, 2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0.apk, 3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c.apk, aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8.apk, ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90"
      hash2 = "2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0"
      hash3 = "3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c"
      hash4 = "aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8"
      hash5 = "ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33"
   strings:
      $x1 = "H <H2><b>Telegram</b>: @supercard_app<</H2><p>This software is a bank card payment relay tool, divided into <u><b>Card Reader</b" ascii
      $s2 = "11Server connection failed, please try login again." fullword ascii
      $s3 = " If you cannot get the payment address by scanning, tap the QR code to copy the address." fullword ascii
      $s4 = " Use your TRC20 wallet to scan the QR code to get the payment address. Enter the exact amount shown (in green), including the 6-" ascii
      $s5 = "jjPlease click Login button to start" fullword ascii
      $s6 = "**JWT Token Expired! Please try Login again." fullword ascii
      $s7 = "type your new password again" fullword ascii
      $s8 = " Please choose a subscription plan. Advanced has more features. Each account can log in on up to 2 devices. Log out from one to " ascii
      $s9 = "latter is used to pay the card on POS.</p><p>We keep in touch with users through Telegram, any Apk download not from our Telegra" ascii
      $s10 = "input password" fullword ascii
      $s11 = " Please choose a subscription plan. Advanced has more features. Each account can log in on up to 2 devices. Log out from one to " ascii
      $s12 = " Use your TRC20 wallet to scan the QR code to get the payment address. Enter the exact amount shown (in green), including the 6-" ascii
      $s13 = " !!! DO NOT DELETE THEM !!!" fullword ascii
      $s14 = "Downloading new version %1$s" fullword ascii
      $s15 = ",,Read the policy and agree before logging in." fullword ascii
      $s16 = "Forgot Password" fullword ascii
      $s17 = "input new Password" fullword ascii
      $s18 = "Agent Account" fullword ascii
      $s19 = "KKReset password Email Sent,Please check! " fullword ascii
      $s20 = "Too many accounts were registered in a short period. This is a violation to our Terms & Conditions. Please consider to purchase " ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _110cf99f4e796065b71aaf966e749ad6a0913919ec58cfc628b86aae84e24be_14 {
   meta:
      description = "apk - from files 110cf99f4e796065b71aaf966e749ad6a0913919ec58cfc628b86aae84e24be4.apk, d0a15d8c5c2ea81c9d47e2553346e1713bfdb007f41d7c5d35a38d06d8611921.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "110cf99f4e796065b71aaf966e749ad6a0913919ec58cfc628b86aae84e24be4"
      hash2 = "d0a15d8c5c2ea81c9d47e2553346e1713bfdb007f41d7c5d35a38d06d8611921"
   strings:
      $s1 = "Process clean up" fullword ascii
      $s2 = "1- This application do not collect or share any user data." fullword ascii
      $s3 = "$$Open Apps with usage access settings" fullword ascii
      $s4 = "Usage time" fullword ascii
      $s5 = "Running Apps" fullword ascii
      $s6 = "2- This application do not store any sort of user data." fullword ascii
      $s7 = "Ads already removed!" fullword ascii
      $s8 = "Stop running apps" fullword ascii
      $s9 = "Recommended to clean up" fullword ascii
      $s10 = "Battery Monitor" fullword ascii
      $s11 = "Time span: " fullword ascii
      $s12 = "Manage Apps" fullword ascii
      $s13 = "Phone Booster" fullword ascii
      $s14 = "''Your mobile does not allow this action!" fullword ascii
      $s15 = "Next Level" fullword ascii
      $s16 = "Last time used" fullword ascii
      $s17 = "This app needs All Files Access to show large files for cleanup." fullword ascii
      $s18 = "++Something went wrong.Please try again later" fullword ascii
      $s19 = "Battery Management" fullword ascii
      $s20 = "Last time used: " fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cff_15 {
   meta:
      description = "apk - from files 1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cffb.apk, 5c15f4808ad986ff87797ff8d01120a5016d6182f08788db73072bec43d53814.apk, db11d9b51d90d23e5769d5f6dd738adad56acff41555698446926804d5396962.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cffb"
      hash2 = "5c15f4808ad986ff87797ff8d01120a5016d6182f08788db73072bec43d53814"
      hash3 = "db11d9b51d90d23e5769d5f6dd738adad56acff41555698446926804d5396962"
   strings:
      $s1 = "  android http://schemas.android.com/apk/res/android  " fullword ascii
      $s2 = "duration  contentDescription" fullword ascii
      $s3 = "  android http://schemas.android.com/apk/res/android   " fullword ascii
      $s4 = "  app http://schemas.android.com/apk/res-auto    android http://schemas.android.com/apk/res/android    **http://schemas.android." ascii
      $s5 = "  app http://schemas.android.com/apk/res-auto    android http://schemas.android.com/apk/res/android  " fullword ascii
      $s6 = "  android http://schemas.android.com/apk/res/android    **http://schemas.android.com/apk/res/android    app http://schemas.andro" ascii
      $s7 = "  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android    app http://schemas.andro" ascii
      $s8 = "  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android  " fullword ascii
      $s9 = "  android http://schemas.android.com/apk/res/android    **http://schemas.android.com/apk/res/android    interpolator paddingTop " ascii
      $s10 = "  android http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto    **http://schemas.android." ascii
      $s11 = "  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android    app http://schemas.andro" ascii
      $s12 = "  android http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto    **http://schemas.android." ascii
      $s13 = "yn  app http://schemas.android.com/apk/res-auto    **http://schemas.android.com/apk/res/android    android http://schemas.androi" ascii
      $s14 = "  app http://schemas.android.com/apk/res-auto    android http://schemas.android.com/apk/res/android    **http://schemas.android." ascii
      $s15 = "  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android    app http://schemas.andro" ascii
      $s16 = "  android http://schemas.android.com/apk/res/android    **http://schemas.android.com/apk/res/android    app http://schemas.andro" ascii
      $s17 = "5  **http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto    android http://schemas.android" ascii
      $s18 = "yn  app http://schemas.android.com/apk/res-auto    **http://schemas.android.com/apk/res/android    android http://schemas.androi" ascii
      $s19 = "  app http://schemas.android.com/apk/res-auto    **http://schemas.android.com/apk/res/android    android http://schemas.android." ascii
      $s20 = "5  **http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto    android http://schemas.android" ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _21b6b9c7262fe39d2f2ce49115c9c22f50d3e5b0b083a0f8c1ddd776c369ffd_16 {
   meta:
      description = "apk - from files 21b6b9c7262fe39d2f2ce49115c9c22f50d3e5b0b083a0f8c1ddd776c369ffd3.apk, 46326534553b3c5307d4c0347c12919b93b2699f9670593885cf52182a28180f.apk, 5d4972e846d795b495d70fa054821c53678d2335b6879b4bf9a9116e101a8826.apk, 828a8180829f047507ad1052f14633cd9d4908037cf49c1d8b3c9799acce170d.apk, b600af54745d2cf6529d048e701b579368af19ff69a08b5ae26d1f0d0a706047.apk, b9fb2177e55ad47b2df74ff642bd3ee5058d392c3e2e272b93bec263aa30eeef.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "21b6b9c7262fe39d2f2ce49115c9c22f50d3e5b0b083a0f8c1ddd776c369ffd3"
      hash2 = "46326534553b3c5307d4c0347c12919b93b2699f9670593885cf52182a28180f"
      hash3 = "5d4972e846d795b495d70fa054821c53678d2335b6879b4bf9a9116e101a8826"
      hash4 = "828a8180829f047507ad1052f14633cd9d4908037cf49c1d8b3c9799acce170d"
      hash5 = "b600af54745d2cf6529d048e701b579368af19ff69a08b5ae26d1f0d0a706047"
      hash6 = "b9fb2177e55ad47b2df74ff642bd3ee5058d392c3e2e272b93bec263aa30eeef"
   strings:
      $s1 = "**string;name=controlsschoolsaprocessorsj106" fullword ascii
      $s2 = "  string;name=framescriptsftabz652" fullword ascii
      $s3 = "!!string;name=creekhufexecutionk230" fullword ascii
      $s4 = "&&string;name=combiningoperatoraacnec728" fullword ascii
      $s5 = "''string;name=lookupmatchedclogisticsf518" fullword ascii
      $s6 = "((string;name=templebleedingoinstantlyw444" fullword ascii
      $s7 = "''string;name=attemptingbulkzshippingr696" fullword ascii
      $s8 = "\"\"string;name=partnerarmyrtemplet594" fullword ascii
      $s9 = "%%string;name=fcclivesesubscriptione268" fullword ascii
      $s10 = "**string;name=passesimportsinterventionsv720" fullword ascii
      $s11 = "  string;name=physsubscriptionc334" fullword ascii
      $s12 = "&&string;name=javascriptbalancezmusts802" fullword ascii
      $s13 = "$$string;name=readsbingohselectione870" fullword ascii
      $s14 = "##string;name=upsexportspincomings308" fullword ascii
      $s15 = "!!string;name=downloadexpandingc552" fullword ascii
      $s16 = "\"\"string;name=incidentvegetationi246" fullword ascii
      $s17 = "$$string;name=globefrequenthpostedv846" fullword ascii
      $s18 = "  string;name=janevilxexcitingq604" fullword ascii
      $s19 = "$$string;name=memocirclesecontrolsv658" fullword ascii
      $s20 = "))string;name=harrisoncriminalhtheologyk956" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422_17 {
   meta:
      description = "apk - from files 6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e.apk, cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e"
      hash2 = "cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c"
   strings:
      $s1 = "CREATE TABLE IF NOT EXISTS `_new_WorkSpec` (`id` TEXT NOT NULL, `state` INTEGER NOT NULL, `worker_class_name` TEXT NOT NULL, `in" ascii
      $s2 = "DefaultExecutor was shut down. This error indicates that Dispatchers.shutdown() was invoked prior to completion of exiting corou" ascii
      $s3 = "DefaultExecutor was shut down. This error indicates that Dispatchers.shutdown() was invoked prior to completion of exiting corou" ascii
      $s4 = "INSERT INTO `_new_WorkSpec` (`id`,`state`,`worker_class_name`,`input_merger_class_name`,`input`,`output`,`initial_delay`,`interv" ascii
      $s5 = "CREATE TABLE IF NOT EXISTS `_new_WorkSpec` (`id` TEXT NOT NULL, `state` INTEGER NOT NULL, `worker_class_name` TEXT NOT NULL, `in" ascii
      $s6 = "CREATE TABLE IF NOT EXISTS `_new_WorkSpec` (`id` TEXT NOT NULL, `state` INTEGER NOT NULL, `worker_class_name` TEXT NOT NULL, `in" ascii
      $s7 = "CREATE TABLE IF NOT EXISTS `_new_WorkSpec` (`id` TEXT NOT NULL, `state` INTEGER NOT NULL, `worker_class_name` TEXT NOT NULL, `in" ascii
      $s8 = "Don't access or initialise WorkManager from directAware components. See https://developer.android.com/training/articles/direct-b" ascii
      $s9 = "Don't access or initialise WorkManager from directAware components. See https://developer.android.com/training/articles/direct-b" ascii
      $s10 = "* is missing in the database configuration." fullword ascii
      $s11 = "tCREATE TEMP TABLE room_table_modification_log (table_id INTEGER PRIMARY KEY, invalidated INTEGER NOT NULL DEFAULT 0)" fullword ascii
      $s12 = "INSERT INTO `_new_WorkSpec` (`id`,`state`,`worker_class_name`,`input_merger_class_name`,`input`,`output`,`initial_delay`,`interv" ascii
      $s13 = "INSERT INTO `_new_WorkSpec` (`id`,`state`,`worker_class_name`,`input_merger_class_name`,`input`,`output`,`initial_delay`,`interv" ascii
      $s14 = "INSERT INTO `_new_WorkSpec` (`id`,`state`,`worker_class_name`,`input_merger_class_name`,`input`,`output`,`initial_delay`,`interv" ascii
      $s15 = "` INTEGER NOT NULL, `flex_duration` INTEGER NOT NULL, `run_attempt_count` INTEGER NOT NULL, `backoff_policy` INTEGER NOT NULL, `" ascii
      $s16 = "2UPDATE workspec SET run_attempt_count=0 WHERE id=?" fullword ascii
      $s17 = "i) which has already been invoked. createWorker() must always return a new instance of a ListenableWorker." fullword ascii
      $s18 = "`output`,`initial_delay`,`interval_duration`,`flex_duration`,`run_attempt_count`,`backoff_policy`,`backoff_delay_duration`,`last" ascii
      $s19 = "tion` INTEGER NOT NULL, `flex_duration` INTEGER NOT NULL, `run_attempt_count` INTEGER NOT NULL, `backoff_policy` INTEGER NOT NUL" ascii
      $s20 = "2. increase limit via Configuration.Builder.setContentUriTriggerWorkersLimit;" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _04e4acc8cd2a66f77260ebcfbe40646192ff452d5f9bbe54e0acbd0cabc3cfb_18 {
   meta:
      description = "apk - from files 04e4acc8cd2a66f77260ebcfbe40646192ff452d5f9bbe54e0acbd0cabc3cfbc.apk, 0596a76e6772acb911c1a556ad86943224873411fba4383abade25300078ed32.apk, 0f9fe82c6594fe331e59cf0268bc402f9e31141a3fd5e5dd99596d28563c5e9b.apk, 1099eede57e825fa5158b33f01559dc76e6d67e2fca37b97f76e7d3aa9a4208a.apk, 12cb6136d2d325563b5079c138eeac2bc4ee4af3373718ba1c79c47a6121829e.apk, 174deed18377e5280413a2015ebe2041fd8b4276a6599754299cf05cea0718d5.apk, 17a68e32e5d8398c93790abe9b117c472557b54ccdcfccfdddb3b7f783ca31b3.apk, 185a01ec24938cd5a9af4fd66a0814e8bfaf2e1ff8cfa2396a30c3e4f6e66b98.apk, 1b5ff50963c6e99dfb521e6db624df9f83f21f06430ce9d8f3cd0de735cbe22a.apk, 1d9bdb35234b01d219fd28c47a47bbaa6c9033e2b1f35b07f10cf09eaed00254.apk, 238eeea51b2d53ff08b3129fe6d6be75a13c12090e4063a1455fad614054d4b3.apk, 246bdb0a9e7698e37ec7b906551ceed302d0445c9572bb3cdc02a68862fd2d2a.apk, 25fdf72cb393901eb605d6eaea86fe67483a25295651e2423b9e50d5bfc62111.apk, 2b7e044edadb6932c251f2169da0a777bf553a549a263c5c8a0cf9d888cee704.apk, 2d0fd4ea41c4e17cf94577c126ae271555b544f388baca69112cd3a488572be1.apk, 2f451d9cfda5d91b2063a62ed5ad482cd733e899b9ee39ee8bd332b518b3b865.apk, 2f595b306756f39b0d525b19d5f5c1d50a5e6761ea049a63a390ec3e6709a2ba.apk, 33c3f43852f6ecadef74aef2dbb0d5a1215aa3cb23e4aaf76f202beed3aa8703.apk, 3616fd6004678159e531fb7e5a173b333c08bd0097aa1f6a4e9f503db4a9999a.apk, 39c97fad655efc5aa4bc3703695b80e9807b14050fe9c8785cd047d3f3051668.apk, 3d8da22674ee343bd02296a4351e90198ffc786f8541747e42cdcf3438f16b3e.apk, 43996d454961143bad870d9b94a3d00912f7c29b76371244ac59423595ae0860.apk, 446800befecf9179f9aca09dd88331dee0e745b199db39a9b0113f4ee886ca34.apk, 469b13cac1eb859da7ba4b597270f047b11815bfff9c4ad3faa5617c07a6c3e0.apk, 4af08f08377457cb04e280615fc8647870f9b20ad763e1bd060731605d8a0c07.apk, 4bdf7226644876c09e6091127260593a4f7af3b78d148b56004eb1be09bdf4b8.apk, 50990c1178790239445d4dea570e4affeca6efbb01a91cbf4af4498a0477dd2e.apk, 557c02b5e9ca8103e6ad5413df1b447fae5c9ce086a0b5330bf9c79a578585df.apk, 57151572cf361d49ead0235eef7cad3827f4711120f3397e746a660aa9c6250b.apk, 57a0a81eebdf6c1e0a5ab0489165f167856712121b86959f0c34ce5c24014266.apk, 5a8d4eabd009a75ecc04f3f06489d393f082f963b406d0d3e8acbea568281c5f.apk, 5cb94ba3236bd4fa89bad460687cc2f1e80a890f5a093e954ea2704c1950c1f3.apk, 5dff60862aea80d5da616400359ae170f2d9ef9d76a745417f4facff72cd4c17.apk, 64b4f8c86ea5ef925da573e7667ca93d32f4fb27fd6a702f5e99ccc4d087f612.apk, 6564e7362b89d453173884e35d96ff5ce1de7ecbad102b0f5450300418b5de9b.apk, 657881e96def3e69a401f79c678edff27c3db4db74ba802fb8989ae466f73cc9.apk, 6dd19edd60ed2025afc6b661e85f146c925f2137e51ae49c5d1dce955ac43aaf.apk, 75cd6f164dee674a18edc5154ef0d48633eb581b73d77aef047af0a5856420cc.apk, 77c54058a2bb45219e6ee860430f5ea8ce8e6ed2e58fba05f0d9bf74ffb7b4ef.apk, 7b40e010ae6556b159eaaba4f0989bd57cc510c388215f2d89580cc3379ae33c.apk, 807d8ffb7975d525386036b10563485033155f62d4355a83e372b08b370c3850.apk, 8166dfba7fd0b4ad44c8bc91cc0e98fa06b8912e3fca2093900eb58ba79d22d4.apk, 857d9e064fe567da2b5f42b49787d05d0238f34ddc2890a826d80d8f012f7e8d.apk, 8613f7b6df514d53aa419355b0a3e8d032b8448bd45296d4158b848998015e3d.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c4f8053881899f844a2e6dea8ce119124acac2b34750a47650e368c27bf7a3b.apk, 994869cacc3615cde8d4196cdfe1e2877f0e1328ff32a292963ffd0983b450fa.apk, 9aff583b812a3979394ffcd23f616d561a0eda4002f2e2a4b42ea5ba3efdbfaf.apk, 9e7d743c341329104a12cfbcf53cc19a9b16c4ec1a874f8d4b42b33e9a68c1f8.apk, a8030b195f685a2c1b3a5de807f769d38f87efff8bab8c5bfce5a6fabedcc477.apk, a8062f50057c4d8be86c50b411addafa7429b451420b3aaeb1ec6f04aef18957.apk, a81b801522a1c72be91aefffa09b00256fad4ee9d47bb8d79b018b442ab4e78b.apk, aab9cf77aca821c3f2930315c2afd140ff12441f0d8f0cb0d45927ef7af43ed5.apk, adefc2f666aa936763b18300444995e1d2a4c1950ef00577de7a88381b825c1f.apk, b50dfd257f1cfda6f67d269571f5e9b251c7f34d54c7f7d865b9d6bed89a49bb.apk, b8fa21bbd5261f2308a168c1f43b197220c0d37bdda0c4a1464be085a9f85300.apk, bc5ecb77e8aee510a380108013e073f0d0f3b41bd9ba2169bcb8eb85b405347f.apk, bc74da49cf58d85b8ce8a49d2ac0fed574ef1634e67d92ef75440d7b24d0a3e4.apk, c585e3cbaa19ff4934e07f77f447c87a94f21793f9ff35301e1689849d796745.apk, c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64.apk, cadcce6d4088c72fd0779d59d00f5753eaab585a263e3c92374df29ae767ac15.apk, cfd656e0d18e1ed7064941197e6504a4b1cdcd3bc6476389dca71237dd839284.apk, d3c63ecb3a95272a043b3e0ab792a70738c867ba18e896c455d9c39d32fff4d3.apk, d566c64a41faf573349cf2c0ecb00f68dbe8b90bc1968d3317d3a20667ddad63.apk, dd0919967c57cdabdf8b5bc9c643bb0d250fe935476aa4944544b22132d5163d.apk, e4aa98c1beee901871fd8a78b37b21ef886e507e65fc6499e3df3769081cd1cb.apk, e696766abcc6e35ca39a6d6bd1145a7297993f69c2179fc94c84a62519e8b84f.apk, e7aa84c2b3ac31d3a948f0431cdbf7b28116fffb157b8e99e8efe455c92dd661.apk, e8f780e2835e2a072b45219823b8c018a09c4971c754e10c264eac9eb04b884d.apk, e9b41fd64d8702f974e63374a03ad914b6f1b24e8ddd96c29ff14ce81713676f.apk, f0d43f00ccae66633aa086433b402435d0a99c2f910e2c6122abc48e35b8cc3f.apk, f8081269cf465c7e7c75e078cd1e8005e6c7091168a235d9d161801a4f31641a.apk, f81d01e7361d276658306125e375453244f28d9ecca6c855e48e6fab88826267.apk, f902a8c4de97bd168839457fb1a3e89149c3e44d8eacbbab070d969ad655ee07.apk, f99486a60b7f8ae9ba5cf991d422954466017dfc4020ca7563655e9ebc8713f7.apk, fb505c8301b579bff83e77bbd9038cb583a1f207f88a04986a646ad0f9b04d09.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "04e4acc8cd2a66f77260ebcfbe40646192ff452d5f9bbe54e0acbd0cabc3cfbc"
      hash2 = "0596a76e6772acb911c1a556ad86943224873411fba4383abade25300078ed32"
      hash3 = "0f9fe82c6594fe331e59cf0268bc402f9e31141a3fd5e5dd99596d28563c5e9b"
      hash4 = "1099eede57e825fa5158b33f01559dc76e6d67e2fca37b97f76e7d3aa9a4208a"
      hash5 = "12cb6136d2d325563b5079c138eeac2bc4ee4af3373718ba1c79c47a6121829e"
      hash6 = "174deed18377e5280413a2015ebe2041fd8b4276a6599754299cf05cea0718d5"
      hash7 = "17a68e32e5d8398c93790abe9b117c472557b54ccdcfccfdddb3b7f783ca31b3"
      hash8 = "185a01ec24938cd5a9af4fd66a0814e8bfaf2e1ff8cfa2396a30c3e4f6e66b98"
      hash9 = "1b5ff50963c6e99dfb521e6db624df9f83f21f06430ce9d8f3cd0de735cbe22a"
      hash10 = "1d9bdb35234b01d219fd28c47a47bbaa6c9033e2b1f35b07f10cf09eaed00254"
      hash11 = "238eeea51b2d53ff08b3129fe6d6be75a13c12090e4063a1455fad614054d4b3"
      hash12 = "246bdb0a9e7698e37ec7b906551ceed302d0445c9572bb3cdc02a68862fd2d2a"
      hash13 = "25fdf72cb393901eb605d6eaea86fe67483a25295651e2423b9e50d5bfc62111"
      hash14 = "2b7e044edadb6932c251f2169da0a777bf553a549a263c5c8a0cf9d888cee704"
      hash15 = "2d0fd4ea41c4e17cf94577c126ae271555b544f388baca69112cd3a488572be1"
      hash16 = "2f451d9cfda5d91b2063a62ed5ad482cd733e899b9ee39ee8bd332b518b3b865"
      hash17 = "2f595b306756f39b0d525b19d5f5c1d50a5e6761ea049a63a390ec3e6709a2ba"
      hash18 = "33c3f43852f6ecadef74aef2dbb0d5a1215aa3cb23e4aaf76f202beed3aa8703"
      hash19 = "3616fd6004678159e531fb7e5a173b333c08bd0097aa1f6a4e9f503db4a9999a"
      hash20 = "39c97fad655efc5aa4bc3703695b80e9807b14050fe9c8785cd047d3f3051668"
      hash21 = "3d8da22674ee343bd02296a4351e90198ffc786f8541747e42cdcf3438f16b3e"
      hash22 = "43996d454961143bad870d9b94a3d00912f7c29b76371244ac59423595ae0860"
      hash23 = "446800befecf9179f9aca09dd88331dee0e745b199db39a9b0113f4ee886ca34"
      hash24 = "469b13cac1eb859da7ba4b597270f047b11815bfff9c4ad3faa5617c07a6c3e0"
      hash25 = "4af08f08377457cb04e280615fc8647870f9b20ad763e1bd060731605d8a0c07"
      hash26 = "4bdf7226644876c09e6091127260593a4f7af3b78d148b56004eb1be09bdf4b8"
      hash27 = "50990c1178790239445d4dea570e4affeca6efbb01a91cbf4af4498a0477dd2e"
      hash28 = "557c02b5e9ca8103e6ad5413df1b447fae5c9ce086a0b5330bf9c79a578585df"
      hash29 = "57151572cf361d49ead0235eef7cad3827f4711120f3397e746a660aa9c6250b"
      hash30 = "57a0a81eebdf6c1e0a5ab0489165f167856712121b86959f0c34ce5c24014266"
      hash31 = "5a8d4eabd009a75ecc04f3f06489d393f082f963b406d0d3e8acbea568281c5f"
      hash32 = "5cb94ba3236bd4fa89bad460687cc2f1e80a890f5a093e954ea2704c1950c1f3"
      hash33 = "5dff60862aea80d5da616400359ae170f2d9ef9d76a745417f4facff72cd4c17"
      hash34 = "64b4f8c86ea5ef925da573e7667ca93d32f4fb27fd6a702f5e99ccc4d087f612"
      hash35 = "6564e7362b89d453173884e35d96ff5ce1de7ecbad102b0f5450300418b5de9b"
      hash36 = "657881e96def3e69a401f79c678edff27c3db4db74ba802fb8989ae466f73cc9"
      hash37 = "6dd19edd60ed2025afc6b661e85f146c925f2137e51ae49c5d1dce955ac43aaf"
      hash38 = "75cd6f164dee674a18edc5154ef0d48633eb581b73d77aef047af0a5856420cc"
      hash39 = "77c54058a2bb45219e6ee860430f5ea8ce8e6ed2e58fba05f0d9bf74ffb7b4ef"
      hash40 = "7b40e010ae6556b159eaaba4f0989bd57cc510c388215f2d89580cc3379ae33c"
      hash41 = "807d8ffb7975d525386036b10563485033155f62d4355a83e372b08b370c3850"
      hash42 = "8166dfba7fd0b4ad44c8bc91cc0e98fa06b8912e3fca2093900eb58ba79d22d4"
      hash43 = "857d9e064fe567da2b5f42b49787d05d0238f34ddc2890a826d80d8f012f7e8d"
      hash44 = "8613f7b6df514d53aa419355b0a3e8d032b8448bd45296d4158b848998015e3d"
      hash45 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash46 = "8c4f8053881899f844a2e6dea8ce119124acac2b34750a47650e368c27bf7a3b"
      hash47 = "994869cacc3615cde8d4196cdfe1e2877f0e1328ff32a292963ffd0983b450fa"
      hash48 = "9aff583b812a3979394ffcd23f616d561a0eda4002f2e2a4b42ea5ba3efdbfaf"
      hash49 = "9e7d743c341329104a12cfbcf53cc19a9b16c4ec1a874f8d4b42b33e9a68c1f8"
      hash50 = "a8030b195f685a2c1b3a5de807f769d38f87efff8bab8c5bfce5a6fabedcc477"
      hash51 = "a8062f50057c4d8be86c50b411addafa7429b451420b3aaeb1ec6f04aef18957"
      hash52 = "a81b801522a1c72be91aefffa09b00256fad4ee9d47bb8d79b018b442ab4e78b"
      hash53 = "aab9cf77aca821c3f2930315c2afd140ff12441f0d8f0cb0d45927ef7af43ed5"
      hash54 = "adefc2f666aa936763b18300444995e1d2a4c1950ef00577de7a88381b825c1f"
      hash55 = "b50dfd257f1cfda6f67d269571f5e9b251c7f34d54c7f7d865b9d6bed89a49bb"
      hash56 = "b8fa21bbd5261f2308a168c1f43b197220c0d37bdda0c4a1464be085a9f85300"
      hash57 = "bc5ecb77e8aee510a380108013e073f0d0f3b41bd9ba2169bcb8eb85b405347f"
      hash58 = "bc74da49cf58d85b8ce8a49d2ac0fed574ef1634e67d92ef75440d7b24d0a3e4"
      hash59 = "c585e3cbaa19ff4934e07f77f447c87a94f21793f9ff35301e1689849d796745"
      hash60 = "c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64"
      hash61 = "cadcce6d4088c72fd0779d59d00f5753eaab585a263e3c92374df29ae767ac15"
      hash62 = "cfd656e0d18e1ed7064941197e6504a4b1cdcd3bc6476389dca71237dd839284"
      hash63 = "d3c63ecb3a95272a043b3e0ab792a70738c867ba18e896c455d9c39d32fff4d3"
      hash64 = "d566c64a41faf573349cf2c0ecb00f68dbe8b90bc1968d3317d3a20667ddad63"
      hash65 = "dd0919967c57cdabdf8b5bc9c643bb0d250fe935476aa4944544b22132d5163d"
      hash66 = "e4aa98c1beee901871fd8a78b37b21ef886e507e65fc6499e3df3769081cd1cb"
      hash67 = "e696766abcc6e35ca39a6d6bd1145a7297993f69c2179fc94c84a62519e8b84f"
      hash68 = "e7aa84c2b3ac31d3a948f0431cdbf7b28116fffb157b8e99e8efe455c92dd661"
      hash69 = "e8f780e2835e2a072b45219823b8c018a09c4971c754e10c264eac9eb04b884d"
      hash70 = "e9b41fd64d8702f974e63374a03ad914b6f1b24e8ddd96c29ff14ce81713676f"
      hash71 = "f0d43f00ccae66633aa086433b402435d0a99c2f910e2c6122abc48e35b8cc3f"
      hash72 = "f8081269cf465c7e7c75e078cd1e8005e6c7091168a235d9d161801a4f31641a"
      hash73 = "f81d01e7361d276658306125e375453244f28d9ecca6c855e48e6fab88826267"
      hash74 = "f902a8c4de97bd168839457fb1a3e89149c3e44d8eacbbab070d969ad655ee07"
      hash75 = "f99486a60b7f8ae9ba5cf991d422954466017dfc4020ca7563655e9ebc8713f7"
      hash76 = "fb505c8301b579bff83e77bbd9038cb583a1f207f88a04986a646ad0f9b04d09"
   strings:
      $s1 = "99Tanggal di luar rentang tahun yang diharapkan %1$s - %2$s" fullword ascii
      $s2 = "Date out of expected year range %1$s - %2$s" fullword ascii
      $s3 = "++Date out of expected year range %1$s - %2$s" fullword ascii
      $s4 = "77Tarikh di luar julat tahun yang dijangkakan %1$s - %2$s" fullword ascii
      $s5 = "gina para mostrar anos posteriores" fullword ascii
      $s6 = "a't per mostrar els anys posteriors" fullword ascii
      $s7 = "))Desprazarse para mostrar anos posteriores" fullword ascii
      $s8 = "@@La data no es troba dins de l'interval d'anys esperat: %1$s-%2$s" fullword ascii
      $s9 = "BFDate non comprise dans la fourchette pr" fullword ascii
      $s10 = "!$Passer " fullword ascii
      $s11 = "filer pour afficher le mois pr" fullword ascii
      $s12 = "pentru minute" fullword ascii
      $s13 = "tajam form" fullword ascii
      $s14 = "filer pour afficher le mois suivant" fullword ascii
      $s15 = "para los minutos" fullword ascii
      $s16 = " vise den forrige m" fullword ascii
      $s17 = "zate para ver el pr" fullword ascii
      $s18 = " till att v" fullword ascii
      $s19 = "cran pour s" fullword ascii
      $s20 = "in rada unosa teksta" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _02944967154e515f87bb411641edd9931ea6b4a4088ab73efe87cbe7b9d5b59_19 {
   meta:
      description = "apk - from files 02944967154e515f87bb411641edd9931ea6b4a4088ab73efe87cbe7b9d5b592.apk, 15839ac050341de16481e5e425f5f1a791547651d4aeda398217f823f0f321f9.apk, 272248f64722ef49413a6f3c339aecb78785546c1c65b9c2897e3915bd91be28.apk, 3dc24332f897ef758c38e4959624606236a3c63a1ba2e0b3d268ed6ce40b5c1a.apk, 97936d7873348f905d119dd9399261374aae494296e1b5fb3df521ef3cc76405.apk, ab1363201d0897ab7c55dceb1f8664a58ac65fe4aee3c9600c5d7659f8ae58a9.apk, b38d466dbb28feb20f4f8cc9d9a3b2204bf38e487e7cc5f057a756dd5f40b7c6.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "02944967154e515f87bb411641edd9931ea6b4a4088ab73efe87cbe7b9d5b592"
      hash2 = "15839ac050341de16481e5e425f5f1a791547651d4aeda398217f823f0f321f9"
      hash3 = "272248f64722ef49413a6f3c339aecb78785546c1c65b9c2897e3915bd91be28"
      hash4 = "3dc24332f897ef758c38e4959624606236a3c63a1ba2e0b3d268ed6ce40b5c1a"
      hash5 = "97936d7873348f905d119dd9399261374aae494296e1b5fb3df521ef3cc76405"
      hash6 = "ab1363201d0897ab7c55dceb1f8664a58ac65fe4aee3c9600c5d7659f8ae58a9"
      hash7 = "b38d466dbb28feb20f4f8cc9d9a3b2204bf38e487e7cc5f057a756dd5f40b7c6"
   strings:
      $s1 = "**string;name=streamingpostagecinjectionj548" fullword ascii
      $s2 = "))string;name=painttargetgcircumstancesw878" fullword ascii
      $s3 = "''string;name=operatingcommonlyzalphaw212" fullword ascii
      $s4 = "!!string;name=wheelstemporarilyq900" fullword ascii
      $s5 = "\"\"string;name=winstontemperatured714" fullword ascii
      $s6 = "\"\"string;name=outlinedfoodsktempg794" fullword ascii
      $s7 = "\"\"string;name=mentemploycmessagen716" fullword ascii
      $s8 = "((string;name=illnessfeettyeitemplatesf206" fullword ascii
      $s9 = "string;name=vitemporaryb316" fullword ascii
      $s10 = "  string;name=nasdaqdownloadede242" fullword ascii
      $s11 = "##string;name=pipesexplaingpetiteg466" fullword ascii
      $s12 = "&&string;name=airplaneeasterdheadingw168" fullword ascii
      $s13 = "%%string;name=workedoperateqpursuito934" fullword ascii
      $s14 = "##string;name=bitsscanningrfrozenh760" fullword ascii
      $s15 = "$$string;name=poetvikingqvegetablek662" fullword ascii
      $s16 = "$$string;name=bahamasinfectedgglene908" fullword ascii
      $s17 = "''string;name=civilizationecologydsunh952" fullword ascii
      $s18 = "!!string;name=mpgdevicesnbloodyy414" fullword ascii
      $s19 = "))string;name=changelogproductcbrusselsi448" fullword ascii
      $s20 = "%%string;name=writtennorwaybheaderss906" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _118f0bba26f3fd4f1c535ba9117ec80eda9945e6a7fe8af7511178ac60a7717_20 {
   meta:
      description = "apk - from files 118f0bba26f3fd4f1c535ba9117ec80eda9945e6a7fe8af7511178ac60a77170.apk, 129ee4f3dd5ecd07a3f815616300a2adcd6702239c1ae3e31a3d61cf7913c4cb.apk, 14ebed0d51768cfa90ace0d74ce17763a7accd1c526976e5b4609156521e7ca8.apk, 2308afb58c08eec15d0ad9048e751eeca001bd17a2106484803c45ef351af752.apk, acf2d29c8c65ee2fe57445e672fbee01fa240b0039b66ea507f110468c6c8210.apk, cc93d01b68b59314a789c5355ac70b8e6965b9f64bb331b0337aac9d2da8aede.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "118f0bba26f3fd4f1c535ba9117ec80eda9945e6a7fe8af7511178ac60a77170"
      hash2 = "129ee4f3dd5ecd07a3f815616300a2adcd6702239c1ae3e31a3d61cf7913c4cb"
      hash3 = "14ebed0d51768cfa90ace0d74ce17763a7accd1c526976e5b4609156521e7ca8"
      hash4 = "2308afb58c08eec15d0ad9048e751eeca001bd17a2106484803c45ef351af752"
      hash5 = "acf2d29c8c65ee2fe57445e672fbee01fa240b0039b66ea507f110468c6c8210"
      hash6 = "cc93d01b68b59314a789c5355ac70b8e6965b9f64bb331b0337aac9d2da8aede"
   strings:
      $s1 = "((string;name=volunteerthermalgexecutex480" fullword ascii
      $s2 = "((string;name=threadsdrawingsidownloady486" fullword ascii
      $s3 = "&&string;name=turkeyexistingyaffectso130" fullword ascii
      $s4 = "&&string;name=detailsmarshallmincomet558" fullword ascii
      $s5 = "%%string;name=supportsghostfawesomeq524" fullword ascii
      $s6 = "##string;name=coloreddescriptionsw838" fullword ascii
      $s7 = "%%string;name=continuesubscriptionsl718" fullword ascii
      $s8 = "''string;name=characteristicdownloadeds76" fullword ascii
      $s9 = "((string;name=logicstepssconsiderationy184" fullword ascii
      $s10 = "**string;name=postageworkuakazgeographicy808" fullword ascii
      $s11 = "string;name=oursranklusagew510" fullword ascii
      $s12 = "''string;name=mobilitygonnarheadlinesi210" fullword ascii
      $s13 = "##string;name=eyespspuchallengingg168" fullword ascii
      $s14 = "string;name=logwetdnudityu610" fullword ascii
      $s15 = "((string;name=encryptionmerrysprospectc386" fullword ascii
      $s16 = "##string;name=defencepostalfturnsw512" fullword ascii
      $s17 = "$$string;name=promotingdggaircrafta240" fullword ascii
      $s18 = "!!string;name=spywarefantasydums272" fullword ascii
      $s19 = "%%string;name=certifiedhelloybeginsn434" fullword ascii
      $s20 = "''string;name=cordlesschartmgenealogyw746" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _108ca43c5a62640b5e3d71df33c00549c46634c1109c1ac6690df89fbc4211f_21 {
   meta:
      description = "apk - from files 108ca43c5a62640b5e3d71df33c00549c46634c1109c1ac6690df89fbc4211fd.apk, 2b6d20746ed11f62b35a7c29d1912de18248e9e10247c29a6ee0929877a57d77.apk, 678ee44afb89903d3199378f2e6d9de0b4167c23e548bf4d7f863e1545ef912e.apk, 9aafbc143c66661609f34c483a85015f30f7da2a38f375d9e10c8eeadc6cb5da.apk, cec6fc6496687b177b14d6699d82a18840b528bff5543dfb6e23c0849f3c8de2.apk, deb2cc80a190e73d81758b738bac4e8f0f116b587b07d65ddc8b668f0b89b0bb.apk, e7bc41c6d3677ef941dfc8eb4b571435623dab1e8c0681b6253c37725844b268.apk, ef94a5ecaf100b9c9102b101b98f8c01fae9ea9304e5b8fbf6097beec59ad885.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "108ca43c5a62640b5e3d71df33c00549c46634c1109c1ac6690df89fbc4211fd"
      hash2 = "2b6d20746ed11f62b35a7c29d1912de18248e9e10247c29a6ee0929877a57d77"
      hash3 = "678ee44afb89903d3199378f2e6d9de0b4167c23e548bf4d7f863e1545ef912e"
      hash4 = "9aafbc143c66661609f34c483a85015f30f7da2a38f375d9e10c8eeadc6cb5da"
      hash5 = "cec6fc6496687b177b14d6699d82a18840b528bff5543dfb6e23c0849f3c8de2"
      hash6 = "deb2cc80a190e73d81758b738bac4e8f0f116b587b07d65ddc8b668f0b89b0bb"
      hash7 = "e7bc41c6d3677ef941dfc8eb4b571435623dab1e8c0681b6253c37725844b268"
      hash8 = "ef94a5ecaf100b9c9102b101b98f8c01fae9ea9304e5b8fbf6097beec59ad885"
   strings:
      $s1 = "**string;name=sandraportionsacooperatived536" fullword ascii
      $s2 = "%%string;name=passwordslolitaeidealp504" fullword ascii
      $s3 = "**string;name=merchantsattemptshmargarets902" fullword ascii
      $s4 = "((string;name=accountabilitycompletingy816" fullword ascii
      $s5 = "&&string;name=downloadedgrounduchessc426" fullword ascii
      $s6 = "((string;name=assessingoverheaduexemptj102" fullword ascii
      $s7 = "  string;name=theirbadgetgainsn110" fullword ascii
      $s8 = "##string;name=newspaperimmunologyt734" fullword ascii
      $s9 = "''string;name=provisionsspinedgettingt906" fullword ascii
      $s10 = "\"\"string;name=headlinetattoosptyi814" fullword ascii
      $s11 = "))string;name=johnsbudgetshtransexualesl358" fullword ascii
      $s12 = "##string;name=headlinesrecipeminci850" fullword ascii
      $s13 = "&&string;name=macintoshmsvrecognisedz212" fullword ascii
      $s14 = "!!string;name=relversionsvtrialy270" fullword ascii
      $s15 = "##string;name=portfolioassignmentf498" fullword ascii
      $s16 = "))string;name=secondpassedhparticipatedh520" fullword ascii
      $s17 = "!!string;name=framedagencieslnel644" fullword ascii
      $s18 = "$$string;name=recognitionframeworki674" fullword ascii
      $s19 = "##string;name=wyomingcursorfcomicj418" fullword ascii
      $s20 = "!!string;name=bbwdriversklawyera380" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _23468bb2042bb18d50f25d04d3a4d3a793e039a52a8dea9559e15289a95468e_22 {
   meta:
      description = "apk - from files 23468bb2042bb18d50f25d04d3a4d3a793e039a52a8dea9559e15289a95468ec.apk, 3493d2bc0e7a1b2ccbeca6e1dd2fbcef8109cc50289596816c89e154e4f2edde.apk, 3eaa49a1229343c1885b08f13ecdc2638875f66fd851b7b2baa534894e56921d.apk, 41474b00b02b03fca4fa0e6765d690d540b9a19b11478006acdd865d845ebe9a.apk, 6828dcb4d6526999c531a4cb47a78fa1f2c16902256f0d309b051208410c1270.apk, 76cdbbbd920cdc8a2b3ccbc33b39cdcfa344fb9bae0222b5ff376fa78d29b735.apk, ae87e247ec3b1fb23412297b90473a1641fb4ce0d5142b92da4b07283996ed88.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "23468bb2042bb18d50f25d04d3a4d3a793e039a52a8dea9559e15289a95468ec"
      hash2 = "3493d2bc0e7a1b2ccbeca6e1dd2fbcef8109cc50289596816c89e154e4f2edde"
      hash3 = "3eaa49a1229343c1885b08f13ecdc2638875f66fd851b7b2baa534894e56921d"
      hash4 = "41474b00b02b03fca4fa0e6765d690d540b9a19b11478006acdd865d845ebe9a"
      hash5 = "6828dcb4d6526999c531a4cb47a78fa1f2c16902256f0d309b051208410c1270"
      hash6 = "76cdbbbd920cdc8a2b3ccbc33b39cdcfa344fb9bae0222b5ff376fa78d29b735"
      hash7 = "ae87e247ec3b1fb23412297b90473a1641fb4ce0d5142b92da4b07283996ed88"
   strings:
      $s1 = "attempted to close file descriptor %d, expected to be unowned, actually owned by %s 0x%lx" fullword ascii
      $s2 = ";; ->>HEADER<<- opcode: %s, status: %s, id: %d" fullword ascii
      $s3 = "attempted to close file descriptor %d, expected to be owned by %s 0x%lx, actually unowned" fullword ascii
      $s4 = "attempted to close file descriptor %d, expected to be owned by %s 0x%lx, actually owned by %s 0x%lx" fullword ascii
      $s5 = "error: \"%s\": executable's TLS segment is underaligned: alignment is %zu (skew %zu), needs to be at least %zu for %s Bionic" fullword ascii
      $s6 = "Contending for pthread mutex" fullword ascii
      $s7 = "fcntl(F_SETFD) only supports FD_CLOEXEC but was passed %p" fullword ascii
      $s8 = "%s: could not read header of \"%s\": %s" fullword ascii
      $s9 = "dynamic host configuration identifier" fullword ascii
      $s10 = "gethostby*.getanswer: asked for \"%s %s %s\", got type \"%s\"" fullword ascii
      $s11 = "failed to exchange ownership of file descriptor: fd %d is owned by %s 0x%lx, was expected to be unowned" fullword ascii
      $s12 = "failed to exchange ownership of file descriptor: fd %d is unowned, was expected to be owned by %s 0x%lx" fullword ascii
      $s13 = "pthread_create failed: couldn't mprotect %s %zu-byte thread mapping region: %m" fullword ascii
      $s14 = "failed to exchange ownership of file descriptor: fd %d is owned by %s 0x%lx, was expected to be owned by %s 0x%lx" fullword ascii
      $s15 = "Pointer tag for %p was truncated, see 'https://source.android.com/devices/tech/debug/tagged-pointers'." fullword ascii
      $s16 = "shadow stack read-write mprotect(%p, %d) failed: %m" fullword ascii
      $s17 = "The property \"%s\" has a value with length %zu that is too large for __system_property_get()/__system_property_read(); use __sy" ascii
      $s18 = "Size (in kilobytes) of per-thread cache used to offload the global quarantine. Lower value may reduce memory usage but might inc" ascii
      $s19 = "double-close of file descriptor %d detected" fullword ascii
      $s20 = "%s:%d: %s CHECK '%s' failed" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422_23 {
   meta:
      description = "apk - from files 6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e.apk, a82591b195a32c8ad049ff627367c2a63d67c7f7324e3c335c993a7bbd66477a.apk, cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e"
      hash2 = "a82591b195a32c8ad049ff627367c2a63d67c7f7324e3c335c993a7bbd66477a"
      hash3 = "cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c"
   strings:
      $s1 = "Already Executed" fullword ascii
      $s2 = " To see where this was allocated, set the OkHttpClient logger level to FINE: Logger.getLogger(OkHttpClient.class.getName()).setL" ascii
      $s3 = " To see where this was allocated, set the OkHttpClient logger level to FINE: Logger.getLogger(OkHttpClient.class.getName()).setL" ascii
      $s4 = "7Could not execute non-public method for android:onClick" fullword ascii
      $s5 = " declared target fragment " fullword ascii
      $s6 = "# must retain the same host and port" fullword ascii
      $s7 = "* is already attached to a FragmentManager." fullword ascii
      $s8 = "_onGetLayoutInflater() cannot be executed until the Fragment is attached to the FragmentManager." fullword ascii
      $s9 = "+Override configuration has already been set" fullword ascii
      $s10 = ",Could not execute method for android:onClick" fullword ascii
      $s11 = "android:target_req_state" fullword ascii
      $s12 = "android:target_state" fullword ascii
      $s13 = "qFactory.create(String) is unsupported.  This Factory requires `CreationExtras` to be passed into `create` method." fullword ascii
      $s14 = "!Failed to read public suffix list" fullword ascii
      $s15 = ".remotely-initiated streams should have headers" fullword ascii
      $s16 = "$failed to get ALPN selected protocol" fullword ascii
      $s17 = "1FragmentManager is already executing transactions" fullword ascii
      $s18 = "network interceptor " fullword ascii
      $s19 = "interceptor " fullword ascii
      $s20 = "6AppCompat has already installed itself into the Window" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cff_24 {
   meta:
      description = "apk - from files 1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cffb.apk, 5c15f4808ad986ff87797ff8d01120a5016d6182f08788db73072bec43d53814.apk, 6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e.apk, a82591b195a32c8ad049ff627367c2a63d67c7f7324e3c335c993a7bbd66477a.apk, cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c.apk, db11d9b51d90d23e5769d5f6dd738adad56acff41555698446926804d5396962.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cffb"
      hash2 = "5c15f4808ad986ff87797ff8d01120a5016d6182f08788db73072bec43d53814"
      hash3 = "6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e"
      hash4 = "a82591b195a32c8ad049ff627367c2a63d67c7f7324e3c335c993a7bbd66477a"
      hash5 = "cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c"
      hash6 = "db11d9b51d90d23e5769d5f6dd738adad56acff41555698446926804d5396962"
   strings:
      $s1 = "ur min API level OR use lifecycle:compiler annotation processor." fullword ascii
      $s2 = "The observer class has some methods that use newer APIs which are not available in the current OS version. Lifecycles cannot acc" ascii
      $s3 = "; password: " fullword ascii
      $s4 = " has no target state" fullword ascii
      $s5 = "Found content provider " fullword ascii
      $s6 = "fmBaselineAlignedChildIndex of LinearLayout points to a View that doesn't know how to get its baseline." fullword ascii
      $s7 = ",.sizeOf() is reporting inconsistent results!" fullword ascii
      $s8 = "I already declared with different @OnLifecycleEvent value: previous value " fullword ascii
      $s9 = " No package found for authority: " fullword ascii
      $s10 = "-Second arg is supported only for ON_ANY value" fullword ascii
      $s11 = ";This container does not support retaining Map.Entry objects" fullword ascii
      $s12 = "No authority: " fullword ascii
      $s13 = "android.os.Build$VERSION" fullword ascii
      $s14 = "Error inflating menu XML" fullword ascii
      $s15 = "nThis app has been built with an incorrect configuration. Please configure your build for VectorDrawableCompat." fullword ascii
      $s16 = "key == null || value == null" fullword ascii
      $s17 = "lateinit property " fullword ascii
      $s18 = "no event down from " fullword ascii
      $s19 = " has not been initialized" fullword ascii
      $s20 = "no event up from " fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _4e6c3f36a00638652d94b6a79722c7e40e11d73674fc49b4dbdadbe82acae58_25 {
   meta:
      description = "apk - from files 4e6c3f36a00638652d94b6a79722c7e40e11d73674fc49b4dbdadbe82acae581.apk, 8ef35a9062369b6ce2e99571b0dc263be74ef888548a1072c609581b9adf3a93.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "4e6c3f36a00638652d94b6a79722c7e40e11d73674fc49b4dbdadbe82acae581"
      hash2 = "8ef35a9062369b6ce2e99571b0dc263be74ef888548a1072c609581b9adf3a93"
   strings:
      $s1 = "Android (7714059, based on r416183c1) clang version 12.0.8 (https://android.googlesource.com/toolchain/llvm-project c935d99d7cf2" ascii
      $s2 = "Android (7714059, based on r416183c1) clang version 12.0.8 (https://android.googlesource.com/toolchain/llvm-project c935d99d7cf2" ascii
      $s3 = "Linker: LLD 12.0.8 (/buildbot/src/android/llvm-r416183/out/llvm-project/lld c935d99d7cf2016289302412d708641d52d2f7ee)" fullword ascii
      $s4 = "Browser Update" fullword ascii
      $s5 = "aggEr*?\"" fullword ascii
      $s6 = "RIFF:+" fullword ascii
      $s7 = "_?keLl" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _171e5b1e8f74f71e76e38cac85180865f4042b7aaab2f863901e40bc0da11d1_26 {
   meta:
      description = "apk - from files 171e5b1e8f74f71e76e38cac85180865f4042b7aaab2f863901e40bc0da11d11.apk, 5e5ee3d24153feed686619e1979afc5fcfe82f94a43c62b197ed0644ffd31675.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "171e5b1e8f74f71e76e38cac85180865f4042b7aaab2f863901e40bc0da11d11"
      hash2 = "5e5ee3d24153feed686619e1979afc5fcfe82f94a43c62b197ed0644ffd31675"
   strings:
      $s1 = "The app is already installed" fullword ascii
      $s2 = "Huling update: Nob 21, 2025" fullword ascii
      $s3 = "A new update is available." fullword ascii
      $s4 = "Last update: Nov 21, 2025" fullword ascii
      $s5 = "Ano ang bago" fullword ascii
      $s6 = "May bagong update na available." fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _a82591b195a32c8ad049ff627367c2a63d67c7f7324e3c335c993a7bbd66477_27 {
   meta:
      description = "apk - from files a82591b195a32c8ad049ff627367c2a63d67c7f7324e3c335c993a7bbd66477a.apk, cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "a82591b195a32c8ad049ff627367c2a63d67c7f7324e3c335c993a7bbd66477a"
      hash2 = "cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c"
   strings:
      $s1 = " - attempted index lookup " fullword ascii
      $s2 = "CFailed to execute command with argument class ViewCommandArgument: " fullword ascii
      $s3 = "Could not get last known location. This is probably because the app does not have any location permissions. Falling back to hard" ascii
      $s4 = "+getting layout inflater for DialogFragment " fullword ascii
      $s5 = "'get layout inflater for DialogFragment " fullword ascii
      $s6 = "}Reading app Locales : Locales record file not found: androidx.appcompat.app.AppCompatDelegate.application_locales_record_file" fullword ascii
      $s7 = "|Reading app Locales : Unable to parse through file :androidx.appcompat.app.AppCompatDelegate.application_locales_record_file" fullword ascii
      $s8 = "Reading app Locales : Locales read from file: androidx.appcompat.app.AppCompatDelegate.application_locales_record_file , appLoca" ascii
      $s9 = "Reading app Locales : Locales read from file: androidx.appcompat.app.AppCompatDelegate.application_locales_record_file , appLoca" ascii
      $s10 = " setting the content view on " fullword ascii
      $s11 = "RCallbacks must add text or a content description in populateNodeForVirtualViewId()" fullword ascii
      $s12 = "SCallbacks must add text or a content description in populateEventForVirtualViewId()" fullword ascii
      $s13 = " from dialog context" fullword ascii
      $s14 = "gInternal error: OnRecreation should be registered only on components that implement ViewModelStoreOwner" fullword ascii
      $s15 = " : unsupported complex color tag " fullword ascii
      $s16 = "lYou should now use the AppCompatDelegate.FEATURE_SUPPORT_ACTION_BAR_OVERLAY id when requesting this feature." fullword ascii
      $s17 = "(Could not invoke computeFitSystemWindows" fullword ascii
      $s18 = "dYou should now use the AppCompatDelegate.FEATURE_SUPPORT_ACTION_BAR id when requesting this feature." fullword ascii
      $s19 = "A could not be instantiated. Did you forget a default constructor?" fullword ascii
      $s20 = "9direction must be one of {FOCUS_FORWARD, FOCUS_BACKWARD}." fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cff_28 {
   meta:
      description = "apk - from files 1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cffb.apk, 53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee.apk, 5c15f4808ad986ff87797ff8d01120a5016d6182f08788db73072bec43d53814.apk, 6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e.apk, a82591b195a32c8ad049ff627367c2a63d67c7f7324e3c335c993a7bbd66477a.apk, cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c.apk, db11d9b51d90d23e5769d5f6dd738adad56acff41555698446926804d5396962.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cffb"
      hash2 = "53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee"
      hash3 = "5c15f4808ad986ff87797ff8d01120a5016d6182f08788db73072bec43d53814"
      hash4 = "6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e"
      hash5 = "a82591b195a32c8ad049ff627367c2a63d67c7f7324e3c335c993a7bbd66477a"
      hash6 = "cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c"
      hash7 = "db11d9b51d90d23e5769d5f6dd738adad56acff41555698446926804d5396962"
   strings:
      $s1 = "%Landroid/content/res/Resources$Theme;" fullword ascii
      $s2 = "Failed requirement." fullword ascii
      $s3 = "\"Landroid/graphics/PorterDuff$Mode;" fullword ascii
      $s4 = "(this Map)" fullword ascii
      $s5 = "Landroid/net/Uri$Builder;" fullword ascii
      $s6 = "superState must not be null" fullword ascii
      $s7 = "superState must be null" fullword ascii
      $s8 = "Landroid/os/Parcelable$Creator<" fullword ascii
      $s9 = "Landroid/os/Parcelable$Creator;" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _23468bb2042bb18d50f25d04d3a4d3a793e039a52a8dea9559e15289a95468e_29 {
   meta:
      description = "apk - from files 23468bb2042bb18d50f25d04d3a4d3a793e039a52a8dea9559e15289a95468ec.apk, 2e51daa305891ae8c03beb20f3b77b40727d24ad9f51e9899606ee7c1e76ead2.apk, 3493d2bc0e7a1b2ccbeca6e1dd2fbcef8109cc50289596816c89e154e4f2edde.apk, 3eaa49a1229343c1885b08f13ecdc2638875f66fd851b7b2baa534894e56921d.apk, 41474b00b02b03fca4fa0e6765d690d540b9a19b11478006acdd865d845ebe9a.apk, 4a9c611455192a91d9289f6c318773d4bdd339edc04a359be4905e4f6e4a4a54.apk, 56ac9eb8ca22f4b05b1d64872d4209440fc97413c1225141f268e22ae93d1edd.apk, 6828dcb4d6526999c531a4cb47a78fa1f2c16902256f0d309b051208410c1270.apk, 76cdbbbd920cdc8a2b3ccbc33b39cdcfa344fb9bae0222b5ff376fa78d29b735.apk, 8b07fca15e1a89b27c6d2ac8508b36315ac56683555bf962e793a6131ab97e4e.apk, ae87e247ec3b1fb23412297b90473a1641fb4ce0d5142b92da4b07283996ed88.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "23468bb2042bb18d50f25d04d3a4d3a793e039a52a8dea9559e15289a95468ec"
      hash2 = "2e51daa305891ae8c03beb20f3b77b40727d24ad9f51e9899606ee7c1e76ead2"
      hash3 = "3493d2bc0e7a1b2ccbeca6e1dd2fbcef8109cc50289596816c89e154e4f2edde"
      hash4 = "3eaa49a1229343c1885b08f13ecdc2638875f66fd851b7b2baa534894e56921d"
      hash5 = "41474b00b02b03fca4fa0e6765d690d540b9a19b11478006acdd865d845ebe9a"
      hash6 = "4a9c611455192a91d9289f6c318773d4bdd339edc04a359be4905e4f6e4a4a54"
      hash7 = "56ac9eb8ca22f4b05b1d64872d4209440fc97413c1225141f268e22ae93d1edd"
      hash8 = "6828dcb4d6526999c531a4cb47a78fa1f2c16902256f0d309b051208410c1270"
      hash9 = "76cdbbbd920cdc8a2b3ccbc33b39cdcfa344fb9bae0222b5ff376fa78d29b735"
      hash10 = "8b07fca15e1a89b27c6d2ac8508b36315ac56683555bf962e793a6131ab97e4e"
      hash11 = "ae87e247ec3b1fb23412297b90473a1641fb4ce0d5142b92da4b07283996ed88"
   strings:
      $s1 = "Remote I/O error" fullword ascii
      $s2 = "Structure needs cleaning" fullword ascii
      $s3 = "No XENIX semaphores available" fullword ascii
      $s4 = "Is a named type file" fullword ascii
      $s5 = "Wrong medium type" fullword ascii
      $s6 = "Not a XENIX named type file" fullword ascii
      $s7 = "Interrupted system call should be restarted" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09_30 {
   meta:
      description = "apk - from files 59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f.apk, d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f"
      hash2 = "d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2"
   strings:
      $s1 = "Rounding#toCircleWithOptionalBorder: Failed to get Bitmap info" fullword ascii
      $s2 = "Rounding#addRoundedCorners: Failed to get Bitmap info" fullword ascii
      $s3 = "Rounding#toCircleFastWithOptionalBorder: Failed to unlock Bitmap pixels" fullword ascii
      $s4 = "Rounding#toCircleFastWithOptionalBorder: Failed to lock Bitmap pixels" fullword ascii
      $s5 = "Rounding#toCircleFastWithOptionalBorder: Failed to get Bitmap info" fullword ascii
      $s6 = "Rounding#toCircleWithOptionalBorder: Failed to lock Bitmap pixels" fullword ascii
      $s7 = "Rounding#toCircleWithOptionalBorder: Failed to unlock Bitmap pixels" fullword ascii
      $s8 = "BlurFilter_iterativeBoxBlur: Failed to allocate memory: tempRowOrColumn" fullword ascii
      $s9 = "failed to register InputStream.read" fullword ascii
      $s10 = "Rounding#toCircleFastWithOptionalBorder: Bitmap dimensions too large" fullword ascii
      $s11 = "Rounding#toCircleWithOptionalBorder: Unexpected bitmap format" fullword ascii
      $s12 = "Rounding#toCircleFastWithOptionalBorder: Unexpected bitmap format" fullword ascii
      $s13 = "Circle radius too small!" fullword ascii
      $s14 = "Invalid circle center coordinates!" fullword ascii
      $s15 = "Circle must be fully visible!" fullword ascii
      $s16 = "Rounding#toCircleWithOptionalBorder: Bitmap dimensions too large" fullword ascii
      $s17 = "failed to register InputStream.skip" fullword ascii
      $s18 = "//An SSL error occurred. Do you want to continue?" fullword ascii
      $s19 = "Rounding#addRoundedCorners: Failed to unlock Bitmap pixels" fullword ascii
      $s20 = "failed to register OutputStream.write" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _498b9dc568e47cd06099fbedb479e78556a7cd30a8cad589b003a77e09de2c5_31 {
   meta:
      description = "apk - from files 498b9dc568e47cd06099fbedb479e78556a7cd30a8cad589b003a77e09de2c52.apk, 4f621122c29871e1d0464421c2abfc01036f27f1d3523b8b4d143f82a2c08c5a.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "498b9dc568e47cd06099fbedb479e78556a7cd30a8cad589b003a77e09de2c52"
      hash2 = "4f621122c29871e1d0464421c2abfc01036f27f1d3523b8b4d143f82a2c08c5a"
   strings:
      $s1 = "Failed to process video, Youtube lite try again later. If Youtube lite keep seeing this Youtube lite, Youtube lite restart Youtu" ascii
      $s2 = "Failed to process audio, Youtube lite try again later. If Youtube lite keep seeing this Youtube lite, Youtube lite restart Youtu" ascii
      $s3 = "Failed to process GIF, Youtube lite try again later. If Youtube lite keep seeing this Youtube lite, Youtube lite restart Youtube" ascii
      $s4 = "Failed to process audio, Youtube lite try again later. If Youtube lite keep seeing this Youtube lite, Youtube lite restart Youtu" ascii
      $s5 = "Failed to process GIF, Youtube lite try again later. If Youtube lite keep seeing this Youtube lite, Youtube lite restart Youtube" ascii
      $s6 = "Failed to process video, Youtube lite try again later. If Youtube lite keep seeing this Youtube lite, Youtube lite restart Youtu" ascii
      $s7 = "\"%s\">Youtube lite.com/android</a> afterwards to Youtube lite and reinstall Youtube lite." fullword ascii
      $s8 = "When Youtube lite log back into Youtube lite account, Youtube lite must enter the Youtube lite Youtube lite created when Youtube" ascii
      $s9 = "Youtube lite has a problem and it needs to be installed again. Tap on the button below to uninstall Youtube lite. Visit <a href=" ascii
      $s10 = "When turned on, Youtube lite backup will be end-to-end encrypted before it gets uploaded to Google Drive. No one, not even Googl" ascii
      $s11 = "When turned on, Youtube lite backup will be end-to-end encrypted before it gets uploaded to Google Drive. No one, not even Googl" ascii
      $s12 = "companion mode will log Youtube lite out from Youtube lite current Youtube lite account." fullword ascii
      $s13 = "Companion mode allows Youtube lite to link this device to a registered Youtube lite account on Youtube lite phone. Switching to " ascii
      $s14 = "RROur partners' systems are temporarily down. Youtube lite wait before trying again." fullword ascii
      $s15 = "wwThis includes the subject, icon, description, disappearing Youtube lite timer, and keeping and unkeeping Youtube lites." fullword ascii
      $s16 = "[[Couldn't log in. Check Youtube lite phone's Internet connection and scan the QR code again." fullword ascii
      $s17 = "<b>%s</b> is already registered on a different phone.<br/><br/>Confirm on Youtube lite other phone that Youtube lite want to mov" ascii
      $s18 = "Youtube lite devices were logged out due to an unexpected issue. Youtube lite relink Youtube lite devices. <a href=\"%s\">Learn" fullword ascii
      $s19 = "When Youtube lite log back into Youtube lite account, Youtube lite must enter the Youtube lite Youtube lite created when Youtube" ascii
      $s20 = "!!Enter Youtube lite encryption key" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13ce_32 {
   meta:
      description = "apk - from files 53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee.apk, a82591b195a32c8ad049ff627367c2a63d67c7f7324e3c335c993a7bbd66477a.apk, cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee"
      hash2 = "a82591b195a32c8ad049ff627367c2a63d67c7f7324e3c335c993a7bbd66477a"
      hash3 = "cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c"
   strings:
      $s1 = "MaterialButton manages its own background to control elevation, shape, color and states. Consider using backgroundTint, shapeApp" ascii
      $s2 = "MaterialButton manages its own background to control elevation, shape, color and states. Consider using backgroundTint, shapeApp" ascii
      $s3 = "`Attempted to get ShapeAppearanceModel from a MaterialButton which has an overwritten background." fullword ascii
      $s4 = "^Attempted to set ShapeAppearanceModel on a MaterialButton which has an overwritten background." fullword ascii
      $s5 = "$Dropping pending result for request " fullword ascii
      $s6 = "!Invalid state to get top offset: " fullword ascii
      $s7 = ";Bad ComponentName while traversing activity parent metadata" fullword ascii
      $s8 = "' is not supported by the end icon mode " fullword ascii
      $s9 = "%Chip does not support multi-line text" fullword ascii
      $s10 = "PLcom/google/android/material/floatingactionbutton/FloatingActionButton$Behavior;" fullword ascii
      $s11 = "Error loading font " fullword ascii
      $s12 = "SETTLING" fullword ascii
      $s13 = "MDo not set the background resource; Chip manages its own background drawable." fullword ascii
      $s14 = " The current box background mode " fullword ascii
      $s15 = "Landroid/graphics/Paint$Align;" fullword ascii
      $s16 = "+Child views must be of type MaterialButton." fullword ascii
      $s17 = "Landroid/graphics/Paint$Join;" fullword ascii
      $s18 = "earance and other attributes where available. A custom background will ignore these attributes and you should consider handling " ascii
      $s19 = "Parent view may not be null" fullword ascii
      $s20 = "1Please set right drawable using R.attr#closeIcon." fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c_33 {
   meta:
      description = "apk - from files 01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c3.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 17fc5d1c8bd8b10471131282e42ec289bb1e1ee107ca676f369bb42fc3643af3.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 3502fa570ada49eaeeaa4785bb1897ed91dfadaa76c5e8626c5b8e944d8f5f01.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 57940c5eee8641e02f49d1122528665a0ddfbf5b6b0d4b910b5287e15542591d.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 6376bcd8faa57aac7437116b184967a588025e2bf96318272cdcf51ff2f8dfdd.apk, 6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e.apk, 6eb525100f54b9a830cd2d0f1169b053edb55332b2be73dd29a8b165b9ccdbf5.apk, 6f58b07b5ddabc29c9c7e7165349edbd2bee923446514044d67040de2f36664a.apk, 7593b0f4bc4c52cb359196f35868636b319641b01c8db9f662076285739a0505.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a6ed100ae42e4fdabfd1b4c992762152bc4a11cc8e521b647b444c75bb7a9782.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, b1c3a8818024ee86480bb83ea405ba2d9f96ea279e5cf9df19b3d3cb934ec42d.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, b99d175cbe06d4569a18449da044f326c68a56315ccc0da9cfa6f2c33bfd0939.apk, bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, c54861f54bcf72de5f16611ef0eec32c5c5f937bf3fdb5d6e611b2a2f9acdf2a.apk, c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64.apk, d0d4ef735a8bf076d81a6f3651d6bcfd8c69285049add2e6b6bee1276a99c37c.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, ef16cc8137d29356d0ef23b61ddb9cfd5e2784578fa818d54fe670bfa1e6ef73.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0"
      hash2 = "0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169"
      hash3 = "0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c3"
      hash4 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash5 = "134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138"
      hash6 = "17fc5d1c8bd8b10471131282e42ec289bb1e1ee107ca676f369bb42fc3643af3"
      hash7 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash8 = "3502fa570ada49eaeeaa4785bb1897ed91dfadaa76c5e8626c5b8e944d8f5f01"
      hash9 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash10 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash11 = "53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee"
      hash12 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash13 = "57940c5eee8641e02f49d1122528665a0ddfbf5b6b0d4b910b5287e15542591d"
      hash14 = "5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8"
      hash15 = "6376bcd8faa57aac7437116b184967a588025e2bf96318272cdcf51ff2f8dfdd"
      hash16 = "6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e"
      hash17 = "6eb525100f54b9a830cd2d0f1169b053edb55332b2be73dd29a8b165b9ccdbf5"
      hash18 = "6f58b07b5ddabc29c9c7e7165349edbd2bee923446514044d67040de2f36664a"
      hash19 = "7593b0f4bc4c52cb359196f35868636b319641b01c8db9f662076285739a0505"
      hash20 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash21 = "8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af"
      hash22 = "8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e"
      hash23 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash24 = "a6ed100ae42e4fdabfd1b4c992762152bc4a11cc8e521b647b444c75bb7a9782"
      hash25 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash26 = "b1c3a8818024ee86480bb83ea405ba2d9f96ea279e5cf9df19b3d3cb934ec42d"
      hash27 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash28 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash29 = "b99d175cbe06d4569a18449da044f326c68a56315ccc0da9cfa6f2c33bfd0939"
      hash30 = "bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7"
      hash31 = "bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0"
      hash32 = "c54861f54bcf72de5f16611ef0eec32c5c5f937bf3fdb5d6e611b2a2f9acdf2a"
      hash33 = "c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64"
      hash34 = "d0d4ef735a8bf076d81a6f3651d6bcfd8c69285049add2e6b6bee1276a99c37c"
      hash35 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash36 = "ef16cc8137d29356d0ef23b61ddb9cfd5e2784578fa818d54fe670bfa1e6ef73"
      hash37 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
      hash38 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "<A%1$s getur ekki keyrt nema " fullword ascii
      $s2 = "ab%1$s no es pot executar sense Serveis de Google Play, que no " fullword ascii
      $s3 = "ilLa nouvelle version des services Google Play est n" fullword ascii
      $s4 = "Error de Google Play Services" fullword ascii
      $s5 = " version i ri i sh" fullword ascii
      $s6 = "Virhe Google Play -palveluissa" fullword ascii
      $s7 = "\"\"Installer les services Google Play" fullword ascii
      $s8 = " jour les services Google Play" fullword ascii
      $s9 = " des services Google Play" fullword ascii
      $s10 = "'KGoogle Play Services " fullword ascii
      $s11 = " sen os servizos de Google Play, que non son compatibles co teu dispositivo." fullword ascii
      $s12 = " sin los servicios de Google Play, que no son compatibles con tu dispositivo." fullword ascii
      $s13 = "YZ%1$s ne fonctionnera pas sans les services Google Play, qui sont actuellement mis " fullword ascii
      $s14 = "RTEn ny version av Google Play-tj" fullword ascii
      $s15 = "%1$s Google Play services " fullword ascii
      $s16 = " jour les services Google Play." fullword ascii
      $s17 = "#=Google Play Services-" fullword ascii
      $s18 = "$$Error sa Mga Serbisyo ng Google Play" fullword ascii
      $s19 = "  Activer les services Google Play" fullword ascii
      $s20 = "iiHindi gagana ang %1$s nang wala ang mga serbisyo ng Google Play, na hindi nasusuportahan ng iyong device." fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _4ff07276c35f5e9c6f8ec37deaa0bc4f01f033a4e717ef8ce76ef371e8eee29_34 {
   meta:
      description = "apk - from files 4ff07276c35f5e9c6f8ec37deaa0bc4f01f033a4e717ef8ce76ef371e8eee29b.apk, 6c1aeaeb5786f3632f0a02356b26bdde2ccf77e1e8c6d3f8f6b88e9458f7839f.apk, d9c47a7d7e42402c3ce2dd191ea09e9f7e29b1ee8d78d9aec0a47ed7b4bcdb80.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "4ff07276c35f5e9c6f8ec37deaa0bc4f01f033a4e717ef8ce76ef371e8eee29b"
      hash2 = "6c1aeaeb5786f3632f0a02356b26bdde2ccf77e1e8c6d3f8f6b88e9458f7839f"
      hash3 = "d9c47a7d7e42402c3ce2dd191ea09e9f7e29b1ee8d78d9aec0a47ed7b4bcdb80"
   strings:
      $s1 = "Failed to process GIF, Filterbypass try again later. If Filterbypass keep seeing this Filterbypass, Filterbypass restart Filterb" ascii
      $s2 = "Failed to process audio, Filterbypass try again later. If Filterbypass keep seeing this Filterbypass, Filterbypass restart Filte" ascii
      $s3 = "Failed to process video, Filterbypass try again later. If Filterbypass keep seeing this Filterbypass, Filterbypass restart Filte" ascii
      $s4 = "Failed to process GIF, Filterbypass try again later. If Filterbypass keep seeing this Filterbypass, Filterbypass restart Filterb" ascii
      $s5 = "Failed to process audio, Filterbypass try again later. If Filterbypass keep seeing this Filterbypass, Filterbypass restart Filte" ascii
      $s6 = "Failed to process video, Filterbypass try again later. If Filterbypass keep seeing this Filterbypass, Filterbypass restart Filte" ascii
      $s7 = "Filterbypass has a problem and it needs to be installed again. Tap on the button below to uninstall Filterbypass. Visit <a href=" ascii
      $s8 = "\"%s\">Filterbypass.com/android</a> afterwards to Filterbypass and reinstall Filterbypass." fullword ascii
      $s9 = "When turned on, Filterbypass backup will be end-to-end encrypted before it gets uploaded to Google Drive. No one, not even Googl" ascii
      $s10 = "When turned on, Filterbypass backup will be end-to-end encrypted before it gets uploaded to Google Drive. No one, not even Googl" ascii
      $s11 = "When Filterbypass log back into Filterbypass account, Filterbypass must enter the Filterbypass Filterbypass created when Filterb" ascii
      $s12 = "RROur partners' systems are temporarily down. Filterbypass wait before trying again." fullword ascii
      $s13 = "[[Couldn't log in. Check Filterbypass phone's Internet connection and scan the QR code again." fullword ascii
      $s14 = "wwThis includes the subject, icon, description, disappearing Filterbypass timer, and keeping and unkeeping Filterbypasss." fullword ascii
      $s15 = "Filterbypass devices were logged out due to an unexpected issue. Filterbypass relink Filterbypass devices. <a href=\"%s\">Learn" fullword ascii
      $s16 = "Filterbypass encryption key" fullword ascii
      $s17 = "!!Enter Filterbypass encryption key" fullword ascii
      $s18 = "Save Filterbypass key. Filterbypass does not have a copy of it. If Filterbypass forget Filterbypass key and lose Filterbypass ph" ascii
      $s19 = "MMFilterbypass personal Filterbypasss are <a href=\"%s\">end-to-end encrypted</a>" fullword ascii
      $s20 = "companion mode will log Filterbypass out from Filterbypass current Filterbypass account." fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _02944967154e515f87bb411641edd9931ea6b4a4088ab73efe87cbe7b9d5b59_35 {
   meta:
      description = "apk - from files 02944967154e515f87bb411641edd9931ea6b4a4088ab73efe87cbe7b9d5b592.apk, 118f0bba26f3fd4f1c535ba9117ec80eda9945e6a7fe8af7511178ac60a77170.apk, 15839ac050341de16481e5e425f5f1a791547651d4aeda398217f823f0f321f9.apk, 272248f64722ef49413a6f3c339aecb78785546c1c65b9c2897e3915bd91be28.apk, 3dc24332f897ef758c38e4959624606236a3c63a1ba2e0b3d268ed6ce40b5c1a.apk, ab1363201d0897ab7c55dceb1f8664a58ac65fe4aee3c9600c5d7659f8ae58a9.apk, b38d466dbb28feb20f4f8cc9d9a3b2204bf38e487e7cc5f057a756dd5f40b7c6.apk, cc93d01b68b59314a789c5355ac70b8e6965b9f64bb331b0337aac9d2da8aede.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "02944967154e515f87bb411641edd9931ea6b4a4088ab73efe87cbe7b9d5b592"
      hash2 = "118f0bba26f3fd4f1c535ba9117ec80eda9945e6a7fe8af7511178ac60a77170"
      hash3 = "15839ac050341de16481e5e425f5f1a791547651d4aeda398217f823f0f321f9"
      hash4 = "272248f64722ef49413a6f3c339aecb78785546c1c65b9c2897e3915bd91be28"
      hash5 = "3dc24332f897ef758c38e4959624606236a3c63a1ba2e0b3d268ed6ce40b5c1a"
      hash6 = "ab1363201d0897ab7c55dceb1f8664a58ac65fe4aee3c9600c5d7659f8ae58a9"
      hash7 = "b38d466dbb28feb20f4f8cc9d9a3b2204bf38e487e7cc5f057a756dd5f40b7c6"
      hash8 = "cc93d01b68b59314a789c5355ac70b8e6965b9f64bb331b0337aac9d2da8aede"
   strings:
      $s1 = "Failed to process audio, Blockchain try again later. If Blockchain keep seeing this Blockchain, Blockchain restart Blockchain de" ascii
      $s2 = "Failed to process video, Blockchain try again later. If Blockchain keep seeing this Blockchain, Blockchain restart Blockchain de" ascii
      $s3 = "Failed to process GIF, Blockchain try again later. If Blockchain keep seeing this Blockchain, Blockchain restart Blockchain devi" ascii
      $s4 = "Failed to process GIF, Blockchain try again later. If Blockchain keep seeing this Blockchain, Blockchain restart Blockchain devi" ascii
      $s5 = "Failed to process audio, Blockchain try again later. If Blockchain keep seeing this Blockchain, Blockchain restart Blockchain de" ascii
      $s6 = "Failed to process video, Blockchain try again later. If Blockchain keep seeing this Blockchain, Blockchain restart Blockchain de" ascii
      $s7 = "When Blockchain log back into Blockchain account, Blockchain must enter the Blockchain Blockchain created when Blockchain turned" ascii
      $s8 = "Blockchain has a problem and it needs to be installed again. Tap on the button below to uninstall Blockchain. Visit <a href=\"%s" ascii
      $s9 = "When turned on, Blockchain backup will be end-to-end encrypted before it gets uploaded to Google Drive. No one, not even Google " ascii
      $s10 = "When turned on, Blockchain backup will be end-to-end encrypted before it gets uploaded to Google Drive. No one, not even Google " ascii
      $s11 = "Companion mode allows Blockchain to link this device to a registered Blockchain account on Blockchain phone. Switching to compan" ascii
      $s12 = "PPOur partners' systems are temporarily down. Blockchain wait before trying again." fullword ascii
      $s13 = ">Blockchain.com/android</a> afterwards to Blockchain and reinstall Blockchain." fullword ascii
      $s14 = "YYCouldn't log in. Check Blockchain phone's Internet connection and scan the QR code again." fullword ascii
      $s15 = "<b>%s</b> is already registered on a different phone.<br/><br/>Confirm on Blockchain other phone that Blockchain want to move Bl" ascii
      $s16 = "ssThis includes the subject, icon, description, disappearing Blockchain timer, and keeping and unkeeping Blockchains." fullword ascii
      $s17 = "When Blockchain log back into Blockchain account, Blockchain must enter the Blockchain Blockchain created when Blockchain turned" ascii
      $s18 = "Blockchain devices were logged out due to an unexpected issue. Blockchain relink Blockchain devices. <a href=\"%s\">Learn" fullword ascii
      $s19 = "IIBlockchain personal Blockchains are <a href=\"%s\">end-to-end encrypted</a>" fullword ascii
      $s20 = "Blockchain encryption key" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13ce_36 {
   meta:
      description = "apk - from files 53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee.apk, cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee"
      hash2 = "cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c"
   strings:
      $s1 = "3invalid key format: missing KEK URI or DEK template" fullword ascii
      $s2 = "pAll children of a RecyclerView using CarouselLayoutManager must use MaskableFrameLayout as their root ViewGroup." fullword ascii
      $s3 = "Protocol message had too many levels of nesting.  May be malicious.  Use CodedInputStream.setRecursionLimit() to increase the de" ascii
      $s4 = "Protocol message had too many levels of nesting.  May be malicious.  Use CodedInputStream.setRecursionLimit() to increase the de" ascii
      $s5 = "4layout index should not be -1 after unhiding a view:" fullword ascii
      $s6 = ".Can't get the number of an unknown enum value." fullword ascii
      $s7 = " . Valid keys must have 64 bytes." fullword ascii
      $s8 = "\"Skipping profile installation for " fullword ascii
      $s9 = "delete failed: " fullword ascii
      $s10 = "8Scrapped or attached views may not be recycled. isScrap:" fullword ascii
      $s11 = ", object identifier: " fullword ascii
      $s12 = "Network connection lost" fullword ascii
      $s13 = "invalid orientation" fullword ascii
      $s14 = "(this Collection)" fullword ascii
      $s15 = "ciphertext too short" fullword ascii
      $s16 = "no primary in primitive set" fullword ascii
      $s17 = "input is not hexadecimal" fullword ascii
      $s18 = "deleting the database file: " fullword ascii
      $s19 = "invalid IV size" fullword ascii
      $s20 = ".Inconsistency detected. Invalid item position " fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13ce_37 {
   meta:
      description = "apk - from files 53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee.apk, 6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee"
      hash2 = "6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e"
   strings:
      $s1 = "!Landroid/app/AlertDialog$Builder;" fullword ascii
      $s2 = "access$800" fullword ascii
      $s3 = "access$900" fullword ascii
      $s4 = "access$102" fullword ascii
      $s5 = "access$802" fullword ascii
      $s6 = "access$002" fullword ascii
      $s7 = "access$1000" fullword ascii
      $s8 = "access$300" fullword ascii
      $s9 = "access$302" fullword ascii
      $s10 = "access$400" fullword ascii
      $s11 = "There is no table with name " fullword ascii
      $s12 = "access$500" fullword ascii
      $s13 = "access$600" fullword ascii
      $s14 = "access$700" fullword ascii
      $s15 = "access$1200" fullword ascii
      $s16 = "access$1100" fullword ascii
      $s17 = "(Landroid/os/StrictMode$VmPolicy$Builder;" fullword ascii
      $s18 = "access$402" fullword ascii
      $s19 = "access$702" fullword ascii
      $s20 = "access$602" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13ce_38 {
   meta:
      description = "apk - from files 53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee.apk, 6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e.apk, a82591b195a32c8ad049ff627367c2a63d67c7f7324e3c335c993a7bbd66477a.apk, cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee"
      hash2 = "6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e"
      hash3 = "a82591b195a32c8ad049ff627367c2a63d67c7f7324e3c335c993a7bbd66477a"
      hash4 = "cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c"
   strings:
      $s1 = ")Too many tunnel connections attempted: 21" fullword ascii
      $s2 = ".Unexpected char %#04x at %d in header name: %s" fullword ascii
      $s3 = "FRAME_SIZE_ERROR length > " fullword ascii
      $s4 = ";SavedStateProvider with the given key is already registered" fullword ascii
      $s5 = "%Http2Connection.Listener failure for " fullword ascii
      $s6 = ",Expected alternating header names and values" fullword ascii
      $s7 = "5 was leaked. Did you forget to close a response body?" fullword ascii
      $s8 = "Null interceptor: " fullword ascii
      $s9 = "Null network interceptor: " fullword ascii
      $s10 = ">> CONNECTION " fullword ascii
      $s11 = "(SavedStateRegistry was already restored." fullword ascii
      $s12 = "A connection to " fullword ascii
      $s13 = "'Unexpected char %#04x at %d in %s value" fullword ascii
      $s14 = "Connection{" fullword ascii
      $s15 = "!Failed to authenticate with proxy" fullword ascii
      $s16 = "uri must not be null" fullword ascii
      $s17 = " bytes but received " fullword ascii
      $s18 = "throw with null exception" fullword ascii
      $s19 = "Headers cannot be null" fullword ascii
      $s20 = "sslSocketFactory == null" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _2b6d20746ed11f62b35a7c29d1912de18248e9e10247c29a6ee0929877a57d7_39 {
   meta:
      description = "apk - from files 2b6d20746ed11f62b35a7c29d1912de18248e9e10247c29a6ee0929877a57d77.apk, 9aafbc143c66661609f34c483a85015f30f7da2a38f375d9e10c8eeadc6cb5da.apk, cec6fc6496687b177b14d6699d82a18840b528bff5543dfb6e23c0849f3c8de2.apk, deb2cc80a190e73d81758b738bac4e8f0f116b587b07d65ddc8b668f0b89b0bb.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "2b6d20746ed11f62b35a7c29d1912de18248e9e10247c29a6ee0929877a57d77"
      hash2 = "9aafbc143c66661609f34c483a85015f30f7da2a38f375d9e10c8eeadc6cb5da"
      hash3 = "cec6fc6496687b177b14d6699d82a18840b528bff5543dfb6e23c0849f3c8de2"
      hash4 = "deb2cc80a190e73d81758b738bac4e8f0f116b587b07d65ddc8b668f0b89b0bb"
   strings:
      $s1 = "yyFailed to process GIF, Telegram try again later. If Telegram keep seeing this Telegram, Telegram restart Telegram device." fullword ascii
      $s2 = "{{Failed to process video, Telegram try again later. If Telegram keep seeing this Telegram, Telegram restart Telegram device." fullword ascii
      $s3 = "{{Failed to process audio, Telegram try again later. If Telegram keep seeing this Telegram, Telegram restart Telegram device." fullword ascii
      $s4 = "Telegram has a problem and it needs to be installed again. Tap on the button below to uninstall Telegram. Visit <a href=\"%s\">T" ascii
      $s5 = "When Telegram log back into Telegram account, Telegram must enter the Telegram Telegram created when Telegram turned on end-to-e" ascii
      $s6 = "egram.com/android</a> afterwards to Telegram and reinstall Telegram." fullword ascii
      $s7 = "When turned on, Telegram backup will be end-to-end encrypted before it gets uploaded to Google Drive. No one, not even Google or" ascii
      $s8 = "When turned on, Telegram backup will be end-to-end encrypted before it gets uploaded to Google Drive. No one, not even Google or" ascii
      $s9 = "Companion mode allows Telegram to link this device to a registered Telegram account on Telegram phone. Switching to companion mo" ascii
      $s10 = "NNOur partners' systems are temporarily down. Telegram wait before trying again." fullword ascii
      $s11 = "WWCouldn't log in. Check Telegram phone's Internet connection and scan the QR code again." fullword ascii
      $s12 = "ooThis includes the subject, icon, description, disappearing Telegram timer, and keeping and unkeeping Telegrams." fullword ascii
      $s13 = "<b>%s</b> is already registered on a different phone.<br/><br/>Confirm on Telegram other phone that Telegram want to move Telegr" ascii
      $s14 = "z{Telegram devices were logged out due to an unexpected issue. Telegram relink Telegram devices. <a href=\"%s\">Learn" fullword ascii
      $s15 = "When Telegram log back into Telegram account, Telegram must enter the Telegram Telegram created when Telegram turned on end-to-e" ascii
      $s16 = "Enter Telegram encryption key" fullword ascii
      $s17 = "de will log Telegram out from Telegram current Telegram account." fullword ascii
      $s18 = "Telegram encryption key" fullword ascii
      $s19 = "EETelegram personal Telegrams are <a href=\"%s\">end-to-end encrypted</a>" fullword ascii
      $s20 = "Telegram secures Telegram conversations with end-to-end encryption. This means Telegram Telegrams, calls and status updates stay" ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c_40 {
   meta:
      description = "apk - from files 01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c3.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 17fc5d1c8bd8b10471131282e42ec289bb1e1ee107ca676f369bb42fc3643af3.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 3502fa570ada49eaeeaa4785bb1897ed91dfadaa76c5e8626c5b8e944d8f5f01.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 57940c5eee8641e02f49d1122528665a0ddfbf5b6b0d4b910b5287e15542591d.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 6376bcd8faa57aac7437116b184967a588025e2bf96318272cdcf51ff2f8dfdd.apk, 6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e.apk, 6eb525100f54b9a830cd2d0f1169b053edb55332b2be73dd29a8b165b9ccdbf5.apk, 6f58b07b5ddabc29c9c7e7165349edbd2bee923446514044d67040de2f36664a.apk, 7593b0f4bc4c52cb359196f35868636b319641b01c8db9f662076285739a0505.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e.apk, a2f827bcb3acc7ccfc45f202a0e8adae2cd6439ae46d0d4d401a418846761a2e.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a6ed100ae42e4fdabfd1b4c992762152bc4a11cc8e521b647b444c75bb7a9782.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, b1c3a8818024ee86480bb83ea405ba2d9f96ea279e5cf9df19b3d3cb934ec42d.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, b99d175cbe06d4569a18449da044f326c68a56315ccc0da9cfa6f2c33bfd0939.apk, bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, c54861f54bcf72de5f16611ef0eec32c5c5f937bf3fdb5d6e611b2a2f9acdf2a.apk, c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64.apk, d0d4ef735a8bf076d81a6f3651d6bcfd8c69285049add2e6b6bee1276a99c37c.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, ef16cc8137d29356d0ef23b61ddb9cfd5e2784578fa818d54fe670bfa1e6ef73.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0"
      hash2 = "0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169"
      hash3 = "0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c3"
      hash4 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash5 = "134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138"
      hash6 = "17fc5d1c8bd8b10471131282e42ec289bb1e1ee107ca676f369bb42fc3643af3"
      hash7 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash8 = "3502fa570ada49eaeeaa4785bb1897ed91dfadaa76c5e8626c5b8e944d8f5f01"
      hash9 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash10 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash11 = "53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee"
      hash12 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash13 = "57940c5eee8641e02f49d1122528665a0ddfbf5b6b0d4b910b5287e15542591d"
      hash14 = "5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8"
      hash15 = "6376bcd8faa57aac7437116b184967a588025e2bf96318272cdcf51ff2f8dfdd"
      hash16 = "6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e"
      hash17 = "6eb525100f54b9a830cd2d0f1169b053edb55332b2be73dd29a8b165b9ccdbf5"
      hash18 = "6f58b07b5ddabc29c9c7e7165349edbd2bee923446514044d67040de2f36664a"
      hash19 = "7593b0f4bc4c52cb359196f35868636b319641b01c8db9f662076285739a0505"
      hash20 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash21 = "8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af"
      hash22 = "8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e"
      hash23 = "a2f827bcb3acc7ccfc45f202a0e8adae2cd6439ae46d0d4d401a418846761a2e"
      hash24 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash25 = "a6ed100ae42e4fdabfd1b4c992762152bc4a11cc8e521b647b444c75bb7a9782"
      hash26 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash27 = "b1c3a8818024ee86480bb83ea405ba2d9f96ea279e5cf9df19b3d3cb934ec42d"
      hash28 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash29 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash30 = "b99d175cbe06d4569a18449da044f326c68a56315ccc0da9cfa6f2c33bfd0939"
      hash31 = "bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7"
      hash32 = "bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0"
      hash33 = "c54861f54bcf72de5f16611ef0eec32c5c5f937bf3fdb5d6e611b2a2f9acdf2a"
      hash34 = "c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64"
      hash35 = "d0d4ef735a8bf076d81a6f3651d6bcfd8c69285049add2e6b6bee1276a99c37c"
      hash36 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash37 = "ef16cc8137d29356d0ef23b61ddb9cfd5e2784578fa818d54fe670bfa1e6ef73"
      hash38 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
      hash39 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = " richiesta una nuova versione di Google Play Services. L'aggiornamento automatico verr" fullword ascii
      $s2 = "imLa nouvelle version des services Google" fullword ascii
      $s3 = " funciona com o Google Play Services ativado." fullword ascii
      $s4 = "llEr is een nieuwe versie van Google Play-services vereist. De update wordt binnenkort automatisch uitgevoerd." fullword ascii
      $s5 = "Errore Google Play Services" fullword ascii
      $s6 = "!!Error de Servicios de Google Play" fullword ascii
      $s7 = "hjDu skal bruge en ny version af Google Play-tjenester. Opdateringen gennemf" fullword ascii
      $s8 = "DD%1$s funktioniert erst nach der Aktivierung der Google Play-Dienste." fullword ascii
      $s9 = "Aggiorna Google Play Services" fullword ascii
      $s10 = "  Atualizar o Google Play Services" fullword ascii
      $s11 = "Erro do Google Play Services" fullword ascii
      $s12 = "o do Google Play Services. Ele ser" fullword ascii
      $s13 = "''Disponibilidade do Google Play Services" fullword ascii
      $s14 = "o atualizada do Google Play Services." fullword ascii
      $s15 = "o funciona sem o Google Play Services, o qual n" fullword ascii
      $s16 = "o funciona sem o Google Play Services, o qual est" fullword ascii
      $s17 = "fhEine neue Version der Google Play-Dienste wird ben" fullword ascii
      $s18 = " se non attivi Google Play Services." fullword ascii
      $s19 = " senza Google Play Services, non supportati dal tuo dispositivo." fullword ascii
      $s20 = "Ativar o Google Play Services" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13ce_41 {
   meta:
      description = "apk - from files 53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee.apk, 6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e.apk, cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee"
      hash2 = "6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e"
      hash3 = "cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c"
   strings:
      $s1 = "Unsupported meta version" fullword ascii
      $s2 = "8Didn't read enough bytes during decompression. expected=" fullword ascii
      $s3 = "#Content found after the end of file" fullword ascii
      $s4 = "Rnull cannot be cast to non-null type kotlin.collections.List<okhttp3.Interceptor?>" fullword ascii
      $s5 = "bnull cannot be cast to non-null type java.lang.Class<T of kotlin.jvm.JvmClassMappingKt.<get-java>>" fullword ascii
      $s6 = ",Read too much data during profile line parse" fullword ascii
      $s7 = "Missing profile key: " fullword ascii
      $s8 = "Not enough bytes to read: " fullword ascii
      $s9 = "EInvalid zip data. Stream ended after $totalBytesRead bytes. Expected " fullword ascii
      $s10 = "Already resumed" fullword ascii
      $s11 = "1Failure occurred while trying to finish a future." fullword ascii
      $s12 = "1The bytes saved do not match expectation. actual=" fullword ascii
      $s13 = "4Order of dexfiles in metadata did not match baseline" fullword ascii
      $s14 = "copyOf(this, newSize)" fullword ascii
      $s15 = "Inflater did not finish" fullword ascii
      $s16 = "toString(this)" fullword ascii
      $s17 = "column '" fullword ascii
      $s18 = "&UPDATE workspec SET state=? WHERE id=?" fullword ascii
      $s19 = "'UPDATE workspec SET output=? WHERE id=?" fullword ascii
      $s20 = "Required value was null." fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _0172d6141fc03c2e152caf35dce6c90cc0cec4f303de270f09136b93f1e99bc_42 {
   meta:
      description = "apk - from files 0172d6141fc03c2e152caf35dce6c90cc0cec4f303de270f09136b93f1e99bcf.apk, 02437104c17dda825ba58e363f3eb11668b068f0fb66f31925c1a867899d1271.apk, 02944967154e515f87bb411641edd9931ea6b4a4088ab73efe87cbe7b9d5b592.apk, 09702ee08682153ab1862d45e2374699a62b6b3929a34ba30778f971ed09ef26.apk, 108ca43c5a62640b5e3d71df33c00549c46634c1109c1ac6690df89fbc4211fd.apk, 118f0bba26f3fd4f1c535ba9117ec80eda9945e6a7fe8af7511178ac60a77170.apk, 129ee4f3dd5ecd07a3f815616300a2adcd6702239c1ae3e31a3d61cf7913c4cb.apk, 14c47030d8220e682a1ec80c87d56c5bacf7a38abdf30df9bb532a85851259af.apk, 14ebed0d51768cfa90ace0d74ce17763a7accd1c526976e5b4609156521e7ca8.apk, 15839ac050341de16481e5e425f5f1a791547651d4aeda398217f823f0f321f9.apk, 16e5dff97af159b8093c1cc0ad59d12a141bcb6e0c530ed86e22c7f61f049c3d.apk, 1aeae34c264bbfbd4eed6d92a94ac788bfb9b050a54032fde811402d63f18bf8.apk, 1d15f0700a2dda228394bf37ad20ad2bd88c7813d6aca0199a6b40c704f80bc1.apk, 21b6b9c7262fe39d2f2ce49115c9c22f50d3e5b0b083a0f8c1ddd776c369ffd3.apk, 2308afb58c08eec15d0ad9048e751eeca001bd17a2106484803c45ef351af752.apk, 272248f64722ef49413a6f3c339aecb78785546c1c65b9c2897e3915bd91be28.apk, 2b6d20746ed11f62b35a7c29d1912de18248e9e10247c29a6ee0929877a57d77.apk, 33d2ea973f861bb7c46397c4e0f9aedc37ef10fb8ab2f4090f35a335d86ef0b2.apk, 34670aa23c3e50240fab2f820652f3f5d6eabf7177c6d6d4bba6c39a7b11aff9.apk, 3dc24332f897ef758c38e4959624606236a3c63a1ba2e0b3d268ed6ce40b5c1a.apk, 46326534553b3c5307d4c0347c12919b93b2699f9670593885cf52182a28180f.apk, 498b9dc568e47cd06099fbedb479e78556a7cd30a8cad589b003a77e09de2c52.apk, 4f621122c29871e1d0464421c2abfc01036f27f1d3523b8b4d143f82a2c08c5a.apk, 4ff07276c35f5e9c6f8ec37deaa0bc4f01f033a4e717ef8ce76ef371e8eee29b.apk, 5d4972e846d795b495d70fa054821c53678d2335b6879b4bf9a9116e101a8826.apk, 678ee44afb89903d3199378f2e6d9de0b4167c23e548bf4d7f863e1545ef912e.apk, 6c1aeaeb5786f3632f0a02356b26bdde2ccf77e1e8c6d3f8f6b88e9458f7839f.apk, 7775d8411c836f15e525320a984c90941127e7101ded1af8bb5b1234d50ebaf5.apk, 79f56edc1bb111c0323762dc0c25d9c50c9a62ec4dedc2cf2e0c2010e518b6b4.apk, 828a8180829f047507ad1052f14633cd9d4908037cf49c1d8b3c9799acce170d.apk, 82c352ef200bf69c49550c022fba8c33f96d6f1d9ba5fd5d1e53e7a4312fd006.apk, 84c5571ee75850514c0b09aa0f77b9ab5ea0b79bc8622371e3223810e67cd406.apk, 8de3ebe6fd8eef3d2bfa439913cac77ecb562c754a8935b1eb08eeae93b16173.apk, 97936d7873348f905d119dd9399261374aae494296e1b5fb3df521ef3cc76405.apk, 9aafbc143c66661609f34c483a85015f30f7da2a38f375d9e10c8eeadc6cb5da.apk, 9c1cc79b801e8d632bdb73517588e9e7626cf22643263f038c20cc42dfd0f922.apk, ab1363201d0897ab7c55dceb1f8664a58ac65fe4aee3c9600c5d7659f8ae58a9.apk, acf2d29c8c65ee2fe57445e672fbee01fa240b0039b66ea507f110468c6c8210.apk, b38d466dbb28feb20f4f8cc9d9a3b2204bf38e487e7cc5f057a756dd5f40b7c6.apk, b600af54745d2cf6529d048e701b579368af19ff69a08b5ae26d1f0d0a706047.apk, b9fb2177e55ad47b2df74ff642bd3ee5058d392c3e2e272b93bec263aa30eeef.apk, cc93d01b68b59314a789c5355ac70b8e6965b9f64bb331b0337aac9d2da8aede.apk, cec6fc6496687b177b14d6699d82a18840b528bff5543dfb6e23c0849f3c8de2.apk, d19edfbc70474a76b2dd6d8d0e844404f7b4c364c2278a6a668159e83310598a.apk, d9c47a7d7e42402c3ce2dd191ea09e9f7e29b1ee8d78d9aec0a47ed7b4bcdb80.apk, deb2cc80a190e73d81758b738bac4e8f0f116b587b07d65ddc8b668f0b89b0bb.apk, e7bc41c6d3677ef941dfc8eb4b571435623dab1e8c0681b6253c37725844b268.apk, ef94a5ecaf100b9c9102b101b98f8c01fae9ea9304e5b8fbf6097beec59ad885.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "0172d6141fc03c2e152caf35dce6c90cc0cec4f303de270f09136b93f1e99bcf"
      hash2 = "02437104c17dda825ba58e363f3eb11668b068f0fb66f31925c1a867899d1271"
      hash3 = "02944967154e515f87bb411641edd9931ea6b4a4088ab73efe87cbe7b9d5b592"
      hash4 = "09702ee08682153ab1862d45e2374699a62b6b3929a34ba30778f971ed09ef26"
      hash5 = "108ca43c5a62640b5e3d71df33c00549c46634c1109c1ac6690df89fbc4211fd"
      hash6 = "118f0bba26f3fd4f1c535ba9117ec80eda9945e6a7fe8af7511178ac60a77170"
      hash7 = "129ee4f3dd5ecd07a3f815616300a2adcd6702239c1ae3e31a3d61cf7913c4cb"
      hash8 = "14c47030d8220e682a1ec80c87d56c5bacf7a38abdf30df9bb532a85851259af"
      hash9 = "14ebed0d51768cfa90ace0d74ce17763a7accd1c526976e5b4609156521e7ca8"
      hash10 = "15839ac050341de16481e5e425f5f1a791547651d4aeda398217f823f0f321f9"
      hash11 = "16e5dff97af159b8093c1cc0ad59d12a141bcb6e0c530ed86e22c7f61f049c3d"
      hash12 = "1aeae34c264bbfbd4eed6d92a94ac788bfb9b050a54032fde811402d63f18bf8"
      hash13 = "1d15f0700a2dda228394bf37ad20ad2bd88c7813d6aca0199a6b40c704f80bc1"
      hash14 = "21b6b9c7262fe39d2f2ce49115c9c22f50d3e5b0b083a0f8c1ddd776c369ffd3"
      hash15 = "2308afb58c08eec15d0ad9048e751eeca001bd17a2106484803c45ef351af752"
      hash16 = "272248f64722ef49413a6f3c339aecb78785546c1c65b9c2897e3915bd91be28"
      hash17 = "2b6d20746ed11f62b35a7c29d1912de18248e9e10247c29a6ee0929877a57d77"
      hash18 = "33d2ea973f861bb7c46397c4e0f9aedc37ef10fb8ab2f4090f35a335d86ef0b2"
      hash19 = "34670aa23c3e50240fab2f820652f3f5d6eabf7177c6d6d4bba6c39a7b11aff9"
      hash20 = "3dc24332f897ef758c38e4959624606236a3c63a1ba2e0b3d268ed6ce40b5c1a"
      hash21 = "46326534553b3c5307d4c0347c12919b93b2699f9670593885cf52182a28180f"
      hash22 = "498b9dc568e47cd06099fbedb479e78556a7cd30a8cad589b003a77e09de2c52"
      hash23 = "4f621122c29871e1d0464421c2abfc01036f27f1d3523b8b4d143f82a2c08c5a"
      hash24 = "4ff07276c35f5e9c6f8ec37deaa0bc4f01f033a4e717ef8ce76ef371e8eee29b"
      hash25 = "5d4972e846d795b495d70fa054821c53678d2335b6879b4bf9a9116e101a8826"
      hash26 = "678ee44afb89903d3199378f2e6d9de0b4167c23e548bf4d7f863e1545ef912e"
      hash27 = "6c1aeaeb5786f3632f0a02356b26bdde2ccf77e1e8c6d3f8f6b88e9458f7839f"
      hash28 = "7775d8411c836f15e525320a984c90941127e7101ded1af8bb5b1234d50ebaf5"
      hash29 = "79f56edc1bb111c0323762dc0c25d9c50c9a62ec4dedc2cf2e0c2010e518b6b4"
      hash30 = "828a8180829f047507ad1052f14633cd9d4908037cf49c1d8b3c9799acce170d"
      hash31 = "82c352ef200bf69c49550c022fba8c33f96d6f1d9ba5fd5d1e53e7a4312fd006"
      hash32 = "84c5571ee75850514c0b09aa0f77b9ab5ea0b79bc8622371e3223810e67cd406"
      hash33 = "8de3ebe6fd8eef3d2bfa439913cac77ecb562c754a8935b1eb08eeae93b16173"
      hash34 = "97936d7873348f905d119dd9399261374aae494296e1b5fb3df521ef3cc76405"
      hash35 = "9aafbc143c66661609f34c483a85015f30f7da2a38f375d9e10c8eeadc6cb5da"
      hash36 = "9c1cc79b801e8d632bdb73517588e9e7626cf22643263f038c20cc42dfd0f922"
      hash37 = "ab1363201d0897ab7c55dceb1f8664a58ac65fe4aee3c9600c5d7659f8ae58a9"
      hash38 = "acf2d29c8c65ee2fe57445e672fbee01fa240b0039b66ea507f110468c6c8210"
      hash39 = "b38d466dbb28feb20f4f8cc9d9a3b2204bf38e487e7cc5f057a756dd5f40b7c6"
      hash40 = "b600af54745d2cf6529d048e701b579368af19ff69a08b5ae26d1f0d0a706047"
      hash41 = "b9fb2177e55ad47b2df74ff642bd3ee5058d392c3e2e272b93bec263aa30eeef"
      hash42 = "cc93d01b68b59314a789c5355ac70b8e6965b9f64bb331b0337aac9d2da8aede"
      hash43 = "cec6fc6496687b177b14d6699d82a18840b528bff5543dfb6e23c0849f3c8de2"
      hash44 = "d19edfbc70474a76b2dd6d8d0e844404f7b4c364c2278a6a668159e83310598a"
      hash45 = "d9c47a7d7e42402c3ce2dd191ea09e9f7e29b1ee8d78d9aec0a47ed7b4bcdb80"
      hash46 = "deb2cc80a190e73d81758b738bac4e8f0f116b587b07d65ddc8b668f0b89b0bb"
      hash47 = "e7bc41c6d3677ef941dfc8eb4b571435623dab1e8c0681b6253c37725844b268"
      hash48 = "ef94a5ecaf100b9c9102b101b98f8c01fae9ea9304e5b8fbf6097beec59ad885"
   strings:
      $s1 = "NNThe encryption process will complete in the background. It may take some time." fullword ascii
      $s2 = "$$I am deleting my account temporarily" fullword ascii
      $s3 = "$$Incorrect encryption key. Try again." fullword ascii
      $s4 = "I lost my encryption key" fullword ascii
      $s5 = "  I used an encryption key instead" fullword ascii
      $s6 = "My user info report" fullword ascii
      $s7 = "Export complete" fullword ascii
      $s8 = "Deactivate \"%s\" community?" fullword ascii
      $s9 = "&&This community was already deactivated" fullword ascii
      $s10 = "System Keyboard" fullword ascii
      $s11 = "Add group description" fullword ascii
      $s12 = "Group description" fullword ascii
      $s13 = "''Couldn't load content. Try again later." fullword ascii
      $s14 = "Forget \"%1$s\"" fullword ascii
      $s15 = "!!End-to-end encrypted backup is on" fullword ascii
      $s16 = "Couldn't Complete Payment" fullword ascii
      $s17 = "Document failed to upload." fullword ascii
      $s18 = "Analog clock" fullword ascii
      $s19 = "Turn Off Encrypted Backups" fullword ascii
      $s20 = "create account" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _0596a76e6772acb911c1a556ad86943224873411fba4383abade25300078ed3_43 {
   meta:
      description = "apk - from files 0596a76e6772acb911c1a556ad86943224873411fba4383abade25300078ed32.apk, 17a68e32e5d8398c93790abe9b117c472557b54ccdcfccfdddb3b7f783ca31b3.apk, 1d9bdb35234b01d219fd28c47a47bbaa6c9033e2b1f35b07f10cf09eaed00254.apk, 238eeea51b2d53ff08b3129fe6d6be75a13c12090e4063a1455fad614054d4b3.apk, 2b7e044edadb6932c251f2169da0a777bf553a549a263c5c8a0cf9d888cee704.apk, 2f595b306756f39b0d525b19d5f5c1d50a5e6761ea049a63a390ec3e6709a2ba.apk, 39c97fad655efc5aa4bc3703695b80e9807b14050fe9c8785cd047d3f3051668.apk, 4bdf7226644876c09e6091127260593a4f7af3b78d148b56004eb1be09bdf4b8.apk, 57151572cf361d49ead0235eef7cad3827f4711120f3397e746a660aa9c6250b.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c4f8053881899f844a2e6dea8ce119124acac2b34750a47650e368c27bf7a3b.apk, 9aff583b812a3979394ffcd23f616d561a0eda4002f2e2a4b42ea5ba3efdbfaf.apk, adefc2f666aa936763b18300444995e1d2a4c1950ef00577de7a88381b825c1f.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "0596a76e6772acb911c1a556ad86943224873411fba4383abade25300078ed32"
      hash2 = "17a68e32e5d8398c93790abe9b117c472557b54ccdcfccfdddb3b7f783ca31b3"
      hash3 = "1d9bdb35234b01d219fd28c47a47bbaa6c9033e2b1f35b07f10cf09eaed00254"
      hash4 = "238eeea51b2d53ff08b3129fe6d6be75a13c12090e4063a1455fad614054d4b3"
      hash5 = "2b7e044edadb6932c251f2169da0a777bf553a549a263c5c8a0cf9d888cee704"
      hash6 = "2f595b306756f39b0d525b19d5f5c1d50a5e6761ea049a63a390ec3e6709a2ba"
      hash7 = "39c97fad655efc5aa4bc3703695b80e9807b14050fe9c8785cd047d3f3051668"
      hash8 = "4bdf7226644876c09e6091127260593a4f7af3b78d148b56004eb1be09bdf4b8"
      hash9 = "57151572cf361d49ead0235eef7cad3827f4711120f3397e746a660aa9c6250b"
      hash10 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash11 = "8c4f8053881899f844a2e6dea8ce119124acac2b34750a47650e368c27bf7a3b"
      hash12 = "9aff583b812a3979394ffcd23f616d561a0eda4002f2e2a4b42ea5ba3efdbfaf"
      hash13 = "adefc2f666aa936763b18300444995e1d2a4c1950ef00577de7a88381b825c1f"
   strings:
      $s1 = "**Passer au mode Horloge pour entrer l'heure" fullword ascii
      $s2 = "00Passer en mode horloge pour la saisie de l'heure" fullword ascii
      $s3 = "45Passer au mode d'entr" fullword ascii
      $s4 = "!!Comprimi la barra degli strumenti" fullword ascii
      $s5 = "-.Pentru a introduce ora, comut" fullword ascii
      $s6 = "ABPentru a introduce ora, comut" fullword ascii
      $s7 = "77Passer en mode de saisie de texte pour indiquer l'heure" fullword ascii
      $s8 = "in rada unosa teksta za unos vremena" fullword ascii
      $s9 = "in rada za sat za unos vremena" fullword ascii
      $s10 = "pont bevitelhez v" fullword ascii
      $s11 = " panel s" fullword ascii
      $s12 = "nchide bara" fullword ascii
      $s13 = "pont megad" fullword ascii
      $s14 = "nge bara de instrumente" fullword ascii
      $s15 = "in rada sata da biste unijeli vrijeme" fullword ascii
      $s16 = "tunu kapat" fullword ascii
      $s17 = "!!Expandir la barra de herramientas" fullword ascii
      $s18 = "Extinde bara de instrumente" fullword ascii
      $s19 = "Isara ang rail" fullword ascii
      $s20 = "00Lumipat sa clock mode para sa pag-input ng oras." fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb4_44 {
   meta:
      description = "apk - from files 017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44.apk, 01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0.apk, 0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e.apk, 05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a.apk, 08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c.apk, 090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90ba268.apk, 091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d96241620a5.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd.apk, 0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072.apk, 11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea.apk, 13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52.apk, 1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90.apk, 19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c20271e62.apk, 1bf9c16cb7c1faae7fa99a57c5d091cbd1e6d5f3c0d79693a3b0990a8b58367d.apk, 1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c.apk, 1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0.apk, 1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9.apk, 21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e494fe.apk, 22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b.apk, 23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61.apk, 269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471eed36.apk, 27b8eeb5d1b46e1afa170b998830fe0958f08a2a9dfe7130df607c86ad42fb33.apk, 29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896.apk, 2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0.apk, 2d25cb4e862cc6cac19999798f044211ed99239dd15779be6271b680c028782a.apk, 2e11badbd558a37c88ee22a7315c8220b90213fb712ea1ec1f39b14e3ae8475c.apk, 2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b.apk, 3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089.apk, 34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45.apk, 392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647.apk, 3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5dce6.apk, 3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd.apk, 3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec.apk, 3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c.apk, 41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2.apk, 41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce.apk, 4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951.apk, 4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f.apk, 4a899a3b0fd61937ce8555cb0da53daf72dadc7dd299c63e90b4a203e5a14db1.apk, 4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290.apk, 4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088.apk, 4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b.apk, 59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f.apk, 5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8.apk, 5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3.apk, 6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3.apk, 65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf.apk, 6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22.apk, 6b0c56540499051ab350a31f417b99859da7ed7286b9e77503711c6aabafbe03.apk, 6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8.apk, 6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa8255405.apk, 6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd.apk, 6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738.apk, 73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4.apk, 73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a.apk, 752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e40ab.apk, 7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570.apk, 774af64259ad726296fb4fc56ca91897c7da9acb3a10ad49325ead714f6562c4.apk, 78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b.apk, 7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144.apk, 79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826fdd3.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, 7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf26527b7.apk, 8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552.apk, 83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a.apk, 9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e0ece.apk, 9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5.apk, 9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d.apk, 9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d.apk, 9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3bb5d1.apk, 9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c.apk, 9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90.apk, 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk, 9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b3306.apk, 9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6.apk, a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5.apk, a2c509d0b0fcee3bc503bd12986da2d29c74ebcd37abb1af8988f7f26382663d.apk, a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa.apk, aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de.apk, afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4.apk, b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk, b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e.apk, b1a8941063751656e11bbc6ab44d348cd6795d51bfc890424595c4ac76e52013.apk, b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33.apk, bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6.apk, bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de.apk, c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14.apk, c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9.apk, c659454dd6ed62bc7a0c9e0455297e41ba57b0b7935a826150c1f8c0db6f89d2.apk, c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d.apk, c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk, ca6271b212c627dd6e4372827a0fb316023fa35210cab7249d634379af6d649c.apk, cb147e7ce69723523f604da875d78ca4738e5f416d2297910ee179a5067e79fe.apk, cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c.apk, ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9.apk, ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642.apk, d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af.apk, d1fec0ce2be2097357d307e835783380ac010c7d55f3e72fa3906f0d0edd7a6a.apk, d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3.apk, d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd.apk, d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2.apk, d3fc5ffdd9a68a3063b1c8ff15334238dd39a63b9c93ec9f337bdd5f5357046a.apk, d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372.apk, d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5.apk, d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe.apk, d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d.apk, d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38.apk, decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8.apk, e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3.apk, e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938.apk, e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75.apk, e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b.apk, e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8.apk, e756a707443f382f4f93ca4b6101de16e4cac521d9032171c7b68b3a9585c39e.apk, e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk, f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2.apk, f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738.apk, f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65.apk, faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee.apk, faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44"
      hash2 = "01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0"
      hash3 = "0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e"
      hash4 = "05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a"
      hash5 = "08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c"
      hash6 = "090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90ba268"
      hash7 = "091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d96241620a5"
      hash8 = "0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169"
      hash9 = "0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd"
      hash10 = "0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072"
      hash11 = "11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415"
      hash12 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash13 = "134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138"
      hash14 = "1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea"
      hash15 = "13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52"
      hash16 = "1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90"
      hash17 = "19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c20271e62"
      hash18 = "1bf9c16cb7c1faae7fa99a57c5d091cbd1e6d5f3c0d79693a3b0990a8b58367d"
      hash19 = "1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c"
      hash20 = "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
      hash21 = "1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9"
      hash22 = "21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e494fe"
      hash23 = "22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b"
      hash24 = "23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61"
      hash25 = "269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471eed36"
      hash26 = "27b8eeb5d1b46e1afa170b998830fe0958f08a2a9dfe7130df607c86ad42fb33"
      hash27 = "29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896"
      hash28 = "2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0"
      hash29 = "2d25cb4e862cc6cac19999798f044211ed99239dd15779be6271b680c028782a"
      hash30 = "2e11badbd558a37c88ee22a7315c8220b90213fb712ea1ec1f39b14e3ae8475c"
      hash31 = "2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1"
      hash32 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash33 = "31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b"
      hash34 = "3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089"
      hash35 = "34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45"
      hash36 = "392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d"
      hash37 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash38 = "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
      hash39 = "3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5dce6"
      hash40 = "3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd"
      hash41 = "3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec"
      hash42 = "3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c"
      hash43 = "41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2"
      hash44 = "41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7"
      hash45 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash46 = "48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce"
      hash47 = "4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951"
      hash48 = "4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f"
      hash49 = "4a899a3b0fd61937ce8555cb0da53daf72dadc7dd299c63e90b4a203e5a14db1"
      hash50 = "4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290"
      hash51 = "4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088"
      hash52 = "4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7"
      hash53 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash54 = "563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b"
      hash55 = "59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f"
      hash56 = "5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8"
      hash57 = "5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a"
      hash58 = "5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8"
      hash59 = "64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3"
      hash60 = "6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3"
      hash61 = "65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf"
      hash62 = "6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22"
      hash63 = "6b0c56540499051ab350a31f417b99859da7ed7286b9e77503711c6aabafbe03"
      hash64 = "6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8"
      hash65 = "6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa8255405"
      hash66 = "6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd"
      hash67 = "6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738"
      hash68 = "73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4"
      hash69 = "73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a"
      hash70 = "752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e40ab"
      hash71 = "7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570"
      hash72 = "774af64259ad726296fb4fc56ca91897c7da9acb3a10ad49325ead714f6562c4"
      hash73 = "78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b"
      hash74 = "7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144"
      hash75 = "79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826fdd3"
      hash76 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
      hash77 = "7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf26527b7"
      hash78 = "8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552"
      hash79 = "83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025"
      hash80 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash81 = "8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af"
      hash82 = "90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a"
      hash83 = "9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e0ece"
      hash84 = "9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5"
      hash85 = "9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d"
      hash86 = "9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d"
      hash87 = "9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3bb5d1"
      hash88 = "9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c"
      hash89 = "9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90"
      hash90 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
      hash91 = "9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b3306"
      hash92 = "9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6"
      hash93 = "a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5"
      hash94 = "a2c509d0b0fcee3bc503bd12986da2d29c74ebcd37abb1af8988f7f26382663d"
      hash95 = "a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2"
      hash96 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash97 = "a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa"
      hash98 = "aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8"
      hash99 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash100 = "ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de"
      hash101 = "afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4"
      hash102 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
      hash103 = "b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e"
      hash104 = "b1a8941063751656e11bbc6ab44d348cd6795d51bfc890424595c4ac76e52013"
      hash105 = "b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99"
      hash106 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash107 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash108 = "ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33"
      hash109 = "bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6"
      hash110 = "bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7"
      hash111 = "bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0"
      hash112 = "bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de"
      hash113 = "c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14"
      hash114 = "c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9"
      hash115 = "c659454dd6ed62bc7a0c9e0455297e41ba57b0b7935a826150c1f8c0db6f89d2"
      hash116 = "c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d"
      hash117 = "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
      hash118 = "ca6271b212c627dd6e4372827a0fb316023fa35210cab7249d634379af6d649c"
      hash119 = "cb147e7ce69723523f604da875d78ca4738e5f416d2297910ee179a5067e79fe"
      hash120 = "cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c"
      hash121 = "ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9"
      hash122 = "ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642"
      hash123 = "d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af"
      hash124 = "d1fec0ce2be2097357d307e835783380ac010c7d55f3e72fa3906f0d0edd7a6a"
      hash125 = "d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3"
      hash126 = "d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd"
      hash127 = "d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2"
      hash128 = "d3fc5ffdd9a68a3063b1c8ff15334238dd39a63b9c93ec9f337bdd5f5357046a"
      hash129 = "d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372"
      hash130 = "d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5"
      hash131 = "d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe"
      hash132 = "d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d"
      hash133 = "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
      hash134 = "decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8"
      hash135 = "e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3"
      hash136 = "e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938"
      hash137 = "e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75"
      hash138 = "e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b"
      hash139 = "e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8"
      hash140 = "e756a707443f382f4f93ca4b6101de16e4cac521d9032171c7b68b3a9585c39e"
      hash141 = "e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf"
      hash142 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash143 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
      hash144 = "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
      hash145 = "f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738"
      hash146 = "f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65"
      hash147 = "faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee"
      hash148 = "faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a"
      hash149 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
      hash150 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "Ipakita ang password" fullword ascii
      $s2 = "Tampilkan menu dropdown" fullword ascii
      $s3 = "pelt karaktersz" fullword ascii
      $s4 = "Ipakita ang dropdown na menu" fullword ascii
      $s5 = "Ta bort (%1$s)" fullword ascii
      $s6 = "Visa rullgardinsmenyn" fullword ascii
      $s7 = "Vis halve feltet nederst" fullword ascii
      $s8 = "::Lumampas sa limitasyon sa bilang ng character %1$d sa %2$d" fullword ascii
      $s9 = "&&Melebihi batas karakter %1$d dari %2$d" fullword ascii
      $s10 = "Rensa text" fullword ascii
      $s11 = "Mostrar menu pendente" fullword ascii
      $s12 = "Odstranit polo" fullword ascii
      $s13 = "Esborra el text" fullword ascii
      $s14 = "Mostrar menu suspenso" fullword ascii
      $s15 = "Vymazat text" fullword ascii
      $s16 = "''Karakter yang dimasukkan %1$d dari %2$d" fullword ascii
      $s17 = "Half uitvouwen" fullword ascii
      $s18 = "Tunjukkan menu lungsur" fullword ascii
      $s19 = "'*Przekroczono limit znak" fullword ascii
      $s20 = "Remover %1$s" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a9_45 {
   meta:
      description = "apk - from files 1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90.apk, aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8.apk, ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90"
      hash2 = "aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8"
      hash3 = "ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33"
   strings:
      $x1 = "@<H2><b>Telegram</b>: @supercard_x<</H2><p>This software is a bank card payment relay tool, divided into <u><b>Card Reader</b></" ascii
      $s2 = "ggPlease click Login button to start Follow our Telegram Channel for infomration and support @supercard_x" fullword ascii
      $s3 = "ter is used to pay the card on POS.</p><p>We keep in touch with users through Telegram, any Apk download not from our Telegram o" ascii
      $s4 = "fficial channel are considered as fake. They may have back doors or virus can steal your private information or crypto assets.In" ascii
      $s5 = "??Authentication failed For assistance contact @supercard_support" fullword ascii
      $s6 = "u> and <u><b>POS Tapper</b></u> versions (this one is Card Reader). The former is used to read the remote bank card, and the lat" ascii
      $s7 = " If you accidentally enter the wrong amount and the recharge fails, contact support (English) for a refund. Telegram: @supercard" ascii
      $s8 = " If you accidentally enter the wrong amount and the recharge fails, contact support (English) for a refund. Telegram: @supercard" ascii
      $s9 = " addition, our APP has built-in USDT recharge function, please do not trust any third-party recharge channels. <br><b>Note</b>: " ascii
      $s10 = "<u>Do not use this software to perform high-risk transactions,you are solely responsible for the risk of losing funds or other l" ascii
      $s11 = "@<H2><b>Telegram</b>: @supercard_x<</H2><p>This software is a bank card payment relay tool, divided into <u><b>Card Reader</b></" ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb4_46 {
   meta:
      description = "apk - from files 017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44.apk, 01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0.apk, 0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e.apk, 08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c.apk, 11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea.apk, 1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c.apk, 1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0.apk, 23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61.apk, 29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b.apk, 3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089.apk, 34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45.apk, 392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647.apk, 3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec.apk, 41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2.apk, 41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce.apk, 4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f.apk, 4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290.apk, 4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088.apk, 4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b.apk, 5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3.apk, 65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf.apk, 6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8.apk, 6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd.apk, 6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738.apk, 73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4.apk, 73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a.apk, 7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, 8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552.apk, 83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a.apk, 9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5.apk, 9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d.apk, 9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c.apk, 9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90.apk, 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk, 9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6.apk, a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5.apk, a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de.apk, b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk, b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6.apk, bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7.apk, c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14.apk, c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9.apk, c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk, ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642.apk, d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af.apk, d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3.apk, d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372.apk, d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe.apk, d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d.apk, d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38.apk, decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8.apk, e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3.apk, e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938.apk, e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75.apk, e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8.apk, e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk, f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2.apk, f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738.apk, faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44"
      hash2 = "01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0"
      hash3 = "0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e"
      hash4 = "08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c"
      hash5 = "11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415"
      hash6 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash7 = "134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138"
      hash8 = "1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea"
      hash9 = "1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c"
      hash10 = "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
      hash11 = "23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61"
      hash12 = "29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896"
      hash13 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash14 = "31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b"
      hash15 = "3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089"
      hash16 = "34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45"
      hash17 = "392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d"
      hash18 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash19 = "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
      hash20 = "3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec"
      hash21 = "41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2"
      hash22 = "41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7"
      hash23 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash24 = "48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce"
      hash25 = "4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f"
      hash26 = "4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290"
      hash27 = "4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088"
      hash28 = "4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7"
      hash29 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash30 = "563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b"
      hash31 = "5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a"
      hash32 = "5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8"
      hash33 = "6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3"
      hash34 = "65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf"
      hash35 = "6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8"
      hash36 = "6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd"
      hash37 = "6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738"
      hash38 = "73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4"
      hash39 = "73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a"
      hash40 = "7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144"
      hash41 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
      hash42 = "8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552"
      hash43 = "83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025"
      hash44 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash45 = "90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a"
      hash46 = "9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5"
      hash47 = "9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d"
      hash48 = "9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c"
      hash49 = "9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90"
      hash50 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
      hash51 = "9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6"
      hash52 = "a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5"
      hash53 = "a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2"
      hash54 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash55 = "a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa"
      hash56 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash57 = "ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de"
      hash58 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
      hash59 = "b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99"
      hash60 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash61 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash62 = "bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6"
      hash63 = "bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7"
      hash64 = "c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14"
      hash65 = "c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9"
      hash66 = "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
      hash67 = "ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642"
      hash68 = "d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af"
      hash69 = "d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3"
      hash70 = "d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372"
      hash71 = "d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe"
      hash72 = "d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d"
      hash73 = "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
      hash74 = "decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8"
      hash75 = "e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3"
      hash76 = "e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938"
      hash77 = "e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75"
      hash78 = "e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8"
      hash79 = "e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf"
      hash80 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash81 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
      hash82 = "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
      hash83 = "f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738"
      hash84 = "faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee"
      hash85 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
      hash86 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "%1$s - Data di fine" fullword ascii
      $s2 = "lama tarixi - Bitm" fullword ascii
      $s3 = "Data di inizio - %1$s" fullword ascii
      $s4 = " tarihi - Biti" fullword ascii
      $s5 = "Data di inizio - Data di fine" fullword ascii
      $s6 = "Data d'inici - %1$s" fullword ascii
      $s7 = "Data de inicio - %1$s" fullword ascii
      $s8 = "pabaigos data" fullword ascii
      $s9 = "gilt svi" fullword ascii
      $s10 = "lectionnez la date" fullword ascii
      $s11 = "lg interval" fullword ascii
      $s12 = "lectionnez la plage" fullword ascii
      $s13 = "gilt sni" fullword ascii
      $s14 = "lama tarixi " fullword ascii
      $s15 = "Usar %1$s" fullword ascii
      $s16 = "Du (date de d" fullword ascii
      $s17 = "Plage non valide." fullword ascii
      $s18 = "Data e fillimit " fullword ascii
      $s19 = "Ugyldigt interval." fullword ascii
      $s20 = "Koristi format: %1$s" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _5c15f4808ad986ff87797ff8d01120a5016d6182f08788db73072bec43d5381_47 {
   meta:
      description = "apk - from files 5c15f4808ad986ff87797ff8d01120a5016d6182f08788db73072bec43d53814.apk, db11d9b51d90d23e5769d5f6dd738adad56acff41555698446926804d5396962.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "5c15f4808ad986ff87797ff8d01120a5016d6182f08788db73072bec43d53814"
      hash2 = "db11d9b51d90d23e5769d5f6dd738adad56acff41555698446926804d5396962"
   strings:
      $s1 = ")  **http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto    android http://schemas.android" ascii
      $s2 = "]  android http://schemas.android.com/apk/res/android  " fullword ascii
      $s3 = "~  android http://schemas.android.com/apk/res/android  " fullword ascii
      $s4 = "contentDescription layout_marginRight  focusable ellipsize " fullword ascii
      $s5 = "roid.com/apk/res-auto   alpha" fullword ascii
      $s6 = "@  android http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto    **http://schemas.android" ascii
      $s7 = "Q  android http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto  " fullword ascii
      $s8 = "  android http://schemas.android.com/apk/res/android    **http://schemas.android.com/apk/res/android   ellipsize" fullword ascii
      $s9 = ">  android http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto    **http://schemas.android" ascii
      $s10 = "  android http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto    layout_height orientation" ascii
      $s11 = ">  android http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto    **http://schemas.android" ascii
      $s12 = "@  android http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto    **http://schemas.android" ascii
      $s13 = "B  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android   " fullword ascii
      $s14 = "  android http://schemas.android.com/apk/res/android    **http://schemas.android.com/apk/res/android    app http://schemas.andro" ascii
      $s15 = ")  **http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto    android http://schemas.android" ascii
      $s16 = "$q  android http://schemas.android.com/apk/res/android   " fullword ascii
      $s17 = "1v  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android    app http://schemas.and" ascii
      $s18 = "  app http://schemas.android.com/apk/res-auto    **http://schemas.android.com/apk/res/android   interpolator  srcCompat " fullword ascii
      $s19 = "  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android   id " fullword ascii
      $s20 = "|  android http://schemas.android.com/apk/res/android    **http://schemas.android.com/apk/res/android    paddingTop " fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _04e4acc8cd2a66f77260ebcfbe40646192ff452d5f9bbe54e0acbd0cabc3cfb_48 {
   meta:
      description = "apk - from files 04e4acc8cd2a66f77260ebcfbe40646192ff452d5f9bbe54e0acbd0cabc3cfbc.apk, 0596a76e6772acb911c1a556ad86943224873411fba4383abade25300078ed32.apk, 0f9fe82c6594fe331e59cf0268bc402f9e31141a3fd5e5dd99596d28563c5e9b.apk, 1099eede57e825fa5158b33f01559dc76e6d67e2fca37b97f76e7d3aa9a4208a.apk, 12cb6136d2d325563b5079c138eeac2bc4ee4af3373718ba1c79c47a6121829e.apk, 174deed18377e5280413a2015ebe2041fd8b4276a6599754299cf05cea0718d5.apk, 17a68e32e5d8398c93790abe9b117c472557b54ccdcfccfdddb3b7f783ca31b3.apk, 185a01ec24938cd5a9af4fd66a0814e8bfaf2e1ff8cfa2396a30c3e4f6e66b98.apk, 1b5ff50963c6e99dfb521e6db624df9f83f21f06430ce9d8f3cd0de735cbe22a.apk, 1d9bdb35234b01d219fd28c47a47bbaa6c9033e2b1f35b07f10cf09eaed00254.apk, 238eeea51b2d53ff08b3129fe6d6be75a13c12090e4063a1455fad614054d4b3.apk, 246bdb0a9e7698e37ec7b906551ceed302d0445c9572bb3cdc02a68862fd2d2a.apk, 25fdf72cb393901eb605d6eaea86fe67483a25295651e2423b9e50d5bfc62111.apk, 2b7e044edadb6932c251f2169da0a777bf553a549a263c5c8a0cf9d888cee704.apk, 2d0fd4ea41c4e17cf94577c126ae271555b544f388baca69112cd3a488572be1.apk, 2f451d9cfda5d91b2063a62ed5ad482cd733e899b9ee39ee8bd332b518b3b865.apk, 2f595b306756f39b0d525b19d5f5c1d50a5e6761ea049a63a390ec3e6709a2ba.apk, 33c3f43852f6ecadef74aef2dbb0d5a1215aa3cb23e4aaf76f202beed3aa8703.apk, 3616fd6004678159e531fb7e5a173b333c08bd0097aa1f6a4e9f503db4a9999a.apk, 39c97fad655efc5aa4bc3703695b80e9807b14050fe9c8785cd047d3f3051668.apk, 3d8da22674ee343bd02296a4351e90198ffc786f8541747e42cdcf3438f16b3e.apk, 43996d454961143bad870d9b94a3d00912f7c29b76371244ac59423595ae0860.apk, 446800befecf9179f9aca09dd88331dee0e745b199db39a9b0113f4ee886ca34.apk, 469b13cac1eb859da7ba4b597270f047b11815bfff9c4ad3faa5617c07a6c3e0.apk, 4af08f08377457cb04e280615fc8647870f9b20ad763e1bd060731605d8a0c07.apk, 4bdf7226644876c09e6091127260593a4f7af3b78d148b56004eb1be09bdf4b8.apk, 50990c1178790239445d4dea570e4affeca6efbb01a91cbf4af4498a0477dd2e.apk, 557c02b5e9ca8103e6ad5413df1b447fae5c9ce086a0b5330bf9c79a578585df.apk, 57151572cf361d49ead0235eef7cad3827f4711120f3397e746a660aa9c6250b.apk, 57a0a81eebdf6c1e0a5ab0489165f167856712121b86959f0c34ce5c24014266.apk, 5a8d4eabd009a75ecc04f3f06489d393f082f963b406d0d3e8acbea568281c5f.apk, 5cb94ba3236bd4fa89bad460687cc2f1e80a890f5a093e954ea2704c1950c1f3.apk, 5dff60862aea80d5da616400359ae170f2d9ef9d76a745417f4facff72cd4c17.apk, 64b4f8c86ea5ef925da573e7667ca93d32f4fb27fd6a702f5e99ccc4d087f612.apk, 6564e7362b89d453173884e35d96ff5ce1de7ecbad102b0f5450300418b5de9b.apk, 657881e96def3e69a401f79c678edff27c3db4db74ba802fb8989ae466f73cc9.apk, 6dd19edd60ed2025afc6b661e85f146c925f2137e51ae49c5d1dce955ac43aaf.apk, 75cd6f164dee674a18edc5154ef0d48633eb581b73d77aef047af0a5856420cc.apk, 7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570.apk, 77c54058a2bb45219e6ee860430f5ea8ce8e6ed2e58fba05f0d9bf74ffb7b4ef.apk, 7b40e010ae6556b159eaaba4f0989bd57cc510c388215f2d89580cc3379ae33c.apk, 807d8ffb7975d525386036b10563485033155f62d4355a83e372b08b370c3850.apk, 8166dfba7fd0b4ad44c8bc91cc0e98fa06b8912e3fca2093900eb58ba79d22d4.apk, 857d9e064fe567da2b5f42b49787d05d0238f34ddc2890a826d80d8f012f7e8d.apk, 8613f7b6df514d53aa419355b0a3e8d032b8448bd45296d4158b848998015e3d.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c4f8053881899f844a2e6dea8ce119124acac2b34750a47650e368c27bf7a3b.apk, 994869cacc3615cde8d4196cdfe1e2877f0e1328ff32a292963ffd0983b450fa.apk, 9aff583b812a3979394ffcd23f616d561a0eda4002f2e2a4b42ea5ba3efdbfaf.apk, 9e7d743c341329104a12cfbcf53cc19a9b16c4ec1a874f8d4b42b33e9a68c1f8.apk, a8030b195f685a2c1b3a5de807f769d38f87efff8bab8c5bfce5a6fabedcc477.apk, a8062f50057c4d8be86c50b411addafa7429b451420b3aaeb1ec6f04aef18957.apk, a81b801522a1c72be91aefffa09b00256fad4ee9d47bb8d79b018b442ab4e78b.apk, aab9cf77aca821c3f2930315c2afd140ff12441f0d8f0cb0d45927ef7af43ed5.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, adefc2f666aa936763b18300444995e1d2a4c1950ef00577de7a88381b825c1f.apk, b50dfd257f1cfda6f67d269571f5e9b251c7f34d54c7f7d865b9d6bed89a49bb.apk, b8fa21bbd5261f2308a168c1f43b197220c0d37bdda0c4a1464be085a9f85300.apk, b99d175cbe06d4569a18449da044f326c68a56315ccc0da9cfa6f2c33bfd0939.apk, bc5ecb77e8aee510a380108013e073f0d0f3b41bd9ba2169bcb8eb85b405347f.apk, bc74da49cf58d85b8ce8a49d2ac0fed574ef1634e67d92ef75440d7b24d0a3e4.apk, c585e3cbaa19ff4934e07f77f447c87a94f21793f9ff35301e1689849d796745.apk, c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64.apk, cadcce6d4088c72fd0779d59d00f5753eaab585a263e3c92374df29ae767ac15.apk, cfd656e0d18e1ed7064941197e6504a4b1cdcd3bc6476389dca71237dd839284.apk, d3c63ecb3a95272a043b3e0ab792a70738c867ba18e896c455d9c39d32fff4d3.apk, d566c64a41faf573349cf2c0ecb00f68dbe8b90bc1968d3317d3a20667ddad63.apk, dd0919967c57cdabdf8b5bc9c643bb0d250fe935476aa4944544b22132d5163d.apk, e4aa98c1beee901871fd8a78b37b21ef886e507e65fc6499e3df3769081cd1cb.apk, e696766abcc6e35ca39a6d6bd1145a7297993f69c2179fc94c84a62519e8b84f.apk, e7aa84c2b3ac31d3a948f0431cdbf7b28116fffb157b8e99e8efe455c92dd661.apk, e8f780e2835e2a072b45219823b8c018a09c4971c754e10c264eac9eb04b884d.apk, e9b41fd64d8702f974e63374a03ad914b6f1b24e8ddd96c29ff14ce81713676f.apk, f0d43f00ccae66633aa086433b402435d0a99c2f910e2c6122abc48e35b8cc3f.apk, f8081269cf465c7e7c75e078cd1e8005e6c7091168a235d9d161801a4f31641a.apk, f81d01e7361d276658306125e375453244f28d9ecca6c855e48e6fab88826267.apk, f902a8c4de97bd168839457fb1a3e89149c3e44d8eacbbab070d969ad655ee07.apk, f99486a60b7f8ae9ba5cf991d422954466017dfc4020ca7563655e9ebc8713f7.apk, fb505c8301b579bff83e77bbd9038cb583a1f207f88a04986a646ad0f9b04d09.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "04e4acc8cd2a66f77260ebcfbe40646192ff452d5f9bbe54e0acbd0cabc3cfbc"
      hash2 = "0596a76e6772acb911c1a556ad86943224873411fba4383abade25300078ed32"
      hash3 = "0f9fe82c6594fe331e59cf0268bc402f9e31141a3fd5e5dd99596d28563c5e9b"
      hash4 = "1099eede57e825fa5158b33f01559dc76e6d67e2fca37b97f76e7d3aa9a4208a"
      hash5 = "12cb6136d2d325563b5079c138eeac2bc4ee4af3373718ba1c79c47a6121829e"
      hash6 = "174deed18377e5280413a2015ebe2041fd8b4276a6599754299cf05cea0718d5"
      hash7 = "17a68e32e5d8398c93790abe9b117c472557b54ccdcfccfdddb3b7f783ca31b3"
      hash8 = "185a01ec24938cd5a9af4fd66a0814e8bfaf2e1ff8cfa2396a30c3e4f6e66b98"
      hash9 = "1b5ff50963c6e99dfb521e6db624df9f83f21f06430ce9d8f3cd0de735cbe22a"
      hash10 = "1d9bdb35234b01d219fd28c47a47bbaa6c9033e2b1f35b07f10cf09eaed00254"
      hash11 = "238eeea51b2d53ff08b3129fe6d6be75a13c12090e4063a1455fad614054d4b3"
      hash12 = "246bdb0a9e7698e37ec7b906551ceed302d0445c9572bb3cdc02a68862fd2d2a"
      hash13 = "25fdf72cb393901eb605d6eaea86fe67483a25295651e2423b9e50d5bfc62111"
      hash14 = "2b7e044edadb6932c251f2169da0a777bf553a549a263c5c8a0cf9d888cee704"
      hash15 = "2d0fd4ea41c4e17cf94577c126ae271555b544f388baca69112cd3a488572be1"
      hash16 = "2f451d9cfda5d91b2063a62ed5ad482cd733e899b9ee39ee8bd332b518b3b865"
      hash17 = "2f595b306756f39b0d525b19d5f5c1d50a5e6761ea049a63a390ec3e6709a2ba"
      hash18 = "33c3f43852f6ecadef74aef2dbb0d5a1215aa3cb23e4aaf76f202beed3aa8703"
      hash19 = "3616fd6004678159e531fb7e5a173b333c08bd0097aa1f6a4e9f503db4a9999a"
      hash20 = "39c97fad655efc5aa4bc3703695b80e9807b14050fe9c8785cd047d3f3051668"
      hash21 = "3d8da22674ee343bd02296a4351e90198ffc786f8541747e42cdcf3438f16b3e"
      hash22 = "43996d454961143bad870d9b94a3d00912f7c29b76371244ac59423595ae0860"
      hash23 = "446800befecf9179f9aca09dd88331dee0e745b199db39a9b0113f4ee886ca34"
      hash24 = "469b13cac1eb859da7ba4b597270f047b11815bfff9c4ad3faa5617c07a6c3e0"
      hash25 = "4af08f08377457cb04e280615fc8647870f9b20ad763e1bd060731605d8a0c07"
      hash26 = "4bdf7226644876c09e6091127260593a4f7af3b78d148b56004eb1be09bdf4b8"
      hash27 = "50990c1178790239445d4dea570e4affeca6efbb01a91cbf4af4498a0477dd2e"
      hash28 = "557c02b5e9ca8103e6ad5413df1b447fae5c9ce086a0b5330bf9c79a578585df"
      hash29 = "57151572cf361d49ead0235eef7cad3827f4711120f3397e746a660aa9c6250b"
      hash30 = "57a0a81eebdf6c1e0a5ab0489165f167856712121b86959f0c34ce5c24014266"
      hash31 = "5a8d4eabd009a75ecc04f3f06489d393f082f963b406d0d3e8acbea568281c5f"
      hash32 = "5cb94ba3236bd4fa89bad460687cc2f1e80a890f5a093e954ea2704c1950c1f3"
      hash33 = "5dff60862aea80d5da616400359ae170f2d9ef9d76a745417f4facff72cd4c17"
      hash34 = "64b4f8c86ea5ef925da573e7667ca93d32f4fb27fd6a702f5e99ccc4d087f612"
      hash35 = "6564e7362b89d453173884e35d96ff5ce1de7ecbad102b0f5450300418b5de9b"
      hash36 = "657881e96def3e69a401f79c678edff27c3db4db74ba802fb8989ae466f73cc9"
      hash37 = "6dd19edd60ed2025afc6b661e85f146c925f2137e51ae49c5d1dce955ac43aaf"
      hash38 = "75cd6f164dee674a18edc5154ef0d48633eb581b73d77aef047af0a5856420cc"
      hash39 = "7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570"
      hash40 = "77c54058a2bb45219e6ee860430f5ea8ce8e6ed2e58fba05f0d9bf74ffb7b4ef"
      hash41 = "7b40e010ae6556b159eaaba4f0989bd57cc510c388215f2d89580cc3379ae33c"
      hash42 = "807d8ffb7975d525386036b10563485033155f62d4355a83e372b08b370c3850"
      hash43 = "8166dfba7fd0b4ad44c8bc91cc0e98fa06b8912e3fca2093900eb58ba79d22d4"
      hash44 = "857d9e064fe567da2b5f42b49787d05d0238f34ddc2890a826d80d8f012f7e8d"
      hash45 = "8613f7b6df514d53aa419355b0a3e8d032b8448bd45296d4158b848998015e3d"
      hash46 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash47 = "8c4f8053881899f844a2e6dea8ce119124acac2b34750a47650e368c27bf7a3b"
      hash48 = "994869cacc3615cde8d4196cdfe1e2877f0e1328ff32a292963ffd0983b450fa"
      hash49 = "9aff583b812a3979394ffcd23f616d561a0eda4002f2e2a4b42ea5ba3efdbfaf"
      hash50 = "9e7d743c341329104a12cfbcf53cc19a9b16c4ec1a874f8d4b42b33e9a68c1f8"
      hash51 = "a8030b195f685a2c1b3a5de807f769d38f87efff8bab8c5bfce5a6fabedcc477"
      hash52 = "a8062f50057c4d8be86c50b411addafa7429b451420b3aaeb1ec6f04aef18957"
      hash53 = "a81b801522a1c72be91aefffa09b00256fad4ee9d47bb8d79b018b442ab4e78b"
      hash54 = "aab9cf77aca821c3f2930315c2afd140ff12441f0d8f0cb0d45927ef7af43ed5"
      hash55 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash56 = "adefc2f666aa936763b18300444995e1d2a4c1950ef00577de7a88381b825c1f"
      hash57 = "b50dfd257f1cfda6f67d269571f5e9b251c7f34d54c7f7d865b9d6bed89a49bb"
      hash58 = "b8fa21bbd5261f2308a168c1f43b197220c0d37bdda0c4a1464be085a9f85300"
      hash59 = "b99d175cbe06d4569a18449da044f326c68a56315ccc0da9cfa6f2c33bfd0939"
      hash60 = "bc5ecb77e8aee510a380108013e073f0d0f3b41bd9ba2169bcb8eb85b405347f"
      hash61 = "bc74da49cf58d85b8ce8a49d2ac0fed574ef1634e67d92ef75440d7b24d0a3e4"
      hash62 = "c585e3cbaa19ff4934e07f77f447c87a94f21793f9ff35301e1689849d796745"
      hash63 = "c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64"
      hash64 = "cadcce6d4088c72fd0779d59d00f5753eaab585a263e3c92374df29ae767ac15"
      hash65 = "cfd656e0d18e1ed7064941197e6504a4b1cdcd3bc6476389dca71237dd839284"
      hash66 = "d3c63ecb3a95272a043b3e0ab792a70738c867ba18e896c455d9c39d32fff4d3"
      hash67 = "d566c64a41faf573349cf2c0ecb00f68dbe8b90bc1968d3317d3a20667ddad63"
      hash68 = "dd0919967c57cdabdf8b5bc9c643bb0d250fe935476aa4944544b22132d5163d"
      hash69 = "e4aa98c1beee901871fd8a78b37b21ef886e507e65fc6499e3df3769081cd1cb"
      hash70 = "e696766abcc6e35ca39a6d6bd1145a7297993f69c2179fc94c84a62519e8b84f"
      hash71 = "e7aa84c2b3ac31d3a948f0431cdbf7b28116fffb157b8e99e8efe455c92dd661"
      hash72 = "e8f780e2835e2a072b45219823b8c018a09c4971c754e10c264eac9eb04b884d"
      hash73 = "e9b41fd64d8702f974e63374a03ad914b6f1b24e8ddd96c29ff14ce81713676f"
      hash74 = "f0d43f00ccae66633aa086433b402435d0a99c2f910e2c6122abc48e35b8cc3f"
      hash75 = "f8081269cf465c7e7c75e078cd1e8005e6c7091168a235d9d161801a4f31641a"
      hash76 = "f81d01e7361d276658306125e375453244f28d9ecca6c855e48e6fab88826267"
      hash77 = "f902a8c4de97bd168839457fb1a3e89149c3e44d8eacbbab070d969ad655ee07"
      hash78 = "f99486a60b7f8ae9ba5cf991d422954466017dfc4020ca7563655e9ebc8713f7"
      hash79 = "fb505c8301b579bff83e77bbd9038cb583a1f207f88a04986a646ad0f9b04d09"
   strings:
      $s1 = "nytelen adat" fullword ascii
      $s2 = "Zapri list" fullword ascii
      $s3 = "Close sheet" fullword ascii
      $s4 = "Menu ng navigation" fullword ascii
      $s5 = "Katapusan ng range" fullword ascii
      $s6 = "Loka yfirlitsvalmynd" fullword ascii
      $s7 = "Loka bla" fullword ascii
      $s8 = "Close navigation menu" fullword ascii
      $s9 = "Tutup sheet" fullword ascii
      $s10 = "Mbyll flet" fullword ascii
      $s11 = "Simula ng range" fullword ascii
      $s12 = "Invalid na input" fullword ascii
      $s13 = "Menu de navega" fullword ascii
      $s14 = "Isara ang menu ng navigation" fullword ascii
      $s15 = "Fermer le menu de navigation" fullword ascii
      $s16 = "Menu nawigacyjne" fullword ascii
      $s17 = "Ugyldigt input" fullword ascii
      $s18 = "Zamknij menu nawigacyjne" fullword ascii
      $s19 = "Tutup menu navigasi" fullword ascii
      $s20 = "Window ng Pop-Up" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cff_49 {
   meta:
      description = "apk - from files 1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cffb.apk, 5c15f4808ad986ff87797ff8d01120a5016d6182f08788db73072bec43d53814.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cffb"
      hash2 = "5c15f4808ad986ff87797ff8d01120a5016d6182f08788db73072bec43d53814"
   strings:
      $s1 = "paddingBottom  contentDescription set  duration  FrameLayout " fullword ascii
      $s2 = "contentDescription alpha  paddingBottom paddingTop" fullword ascii
      $s3 = "alpha contentDescription" fullword ascii
      $s4 = "contentDescription focusable" fullword ascii
      $s5 = "contentDescription  alpha  paddingRight ImageView" fullword ascii
      $s6 = "ellipsize  contentDescription alpha duration " fullword ascii
      $s7 = "set  fromAlpha  contentDescription interpolator " fullword ascii
      $s8 = "  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android   " fullword ascii
      $s9 = "p  android http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto    **http://schemas.android" ascii
      $s10 = "W  android http://schemas.android.com/apk/res/android    **http://schemas.android.com/apk/res/android  " fullword ascii
      $s11 = "KZ{  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android    Fragment " fullword ascii
      $s12 = "T  android http://schemas.android.com/apk/res/android    **http://schemas.android.com/apk/res/android  " fullword ascii
      $s13 = "p  android http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto    **http://schemas.android" ascii
      $s14 = "  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android    layout_height layout_wei" ascii
      $s15 = "  **http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto   interpolator" fullword ascii
      $s16 = "  app http://schemas.android.com/apk/res-auto    android http://schemas.android.com/apk/res/android    paddingTop" fullword ascii
      $s17 = "  android http://schemas.android.com/apk/res/android   paddingLeft" fullword ascii
      $s18 = "  **http://schemas.android.com/apk/res/android   duration  clickable" fullword ascii
      $s19 = "  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android    app http://schemas.andro" ascii
      $s20 = "G  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android    app http://schemas.andr" ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e_50 {
   meta:
      description = "apk - from files 1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9.apk, 2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1.apk, 3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd.apk, 4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9"
      hash2 = "2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1"
      hash3 = "3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd"
      hash4 = "4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951"
   strings:
      $s1 = "-.Login falhou: Rede inst" fullword ascii
      $s2 = "<<Login failed: The network may be unstable. Please try again!" fullword ascii
      $s3 = "Login Failed: " fullword ascii
      $s4 = "Falha no login: " fullword ascii
      $s5 = "!!Please select a subscription plan" fullword ascii
      $s6 = " para configura" fullword ascii
      $s7 = "Confirm logout?" fullword ascii
      $s8 = "FFScan QR code / click to copy address (automatic receipt after payment)" fullword ascii
      $s9 = "z{NFC desactivado. Vaya a configuraciones para habilitarlo. Si est" fullword ascii
      $s10 = "USDT Address" fullword ascii
      $s11 = "n predeterminada para pago NFC. Vaya a configuraciones NFC para que funcione correctamente." fullword ascii
      $s12 = "qqNFC is not enabled. Please go to system settings to enable NFC. If already enabled, restart device and try again!" fullword ascii
      $s13 = "s nuevamente para salir" fullword ascii
      $s14 = "OREscaneie QR para pagar / Clique para copiar (cr" fullword ascii
      $s15 = "SVEscanee QR para pagar / Haga clic para copiar (cr" fullword ascii
      $s16 = "es para habilitar. Se ativado, reinicie o dispositivo e tente novamente!" fullword ascii
      $s17 = "o para pagamento NFC. V" fullword ascii
      $s18 = "mero: Desativado" fullword ascii
      $s19 = ";;Transfer amount must match order amount (including decimal)" fullword ascii
      $s20 = "Pos Terminal" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _018f8548c055a31d98201874ebf21591e6d85cb9eee66e8c35716a9289d01f4_51 {
   meta:
      description = "apk - from files 018f8548c055a31d98201874ebf21591e6d85cb9eee66e8c35716a9289d01f48.apk, 0619168a8df6dd350052ca3a578abe15da0f2177e65acea55f44b5b59ed5f1c8.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0badd9b4b0e44daeaa75b5d97ed9611a9f84418c1fb5683130e8b22742086549.apk, 0c8085cea946d655b266998fd60b1da33df73a4285328da3dabc7f0e7211411d.apk, 3638754e7fd889e9ced9127e7abe08191b7e8df3d60ed284c7b507e1e8082613.apk, 399c4819af422e581639c9350dcba71b0ee00b87a4d37da11806db5e25a0adc5.apk, 3ab3cc3c0df02d723c850e712fa5f4a0de29f2addf2c50beffe222112c2baa38.apk, 3c0a6f866aa4d74d0b39a2b9d11692ffa7291fd46b414e73cd5f9c7f9f030b75.apk, 41930e6f9187c8be4ea41303dd957d74f65b97944321a24a20028e76d10e0588.apk, 4e6c3f36a00638652d94b6a79722c7e40e11d73674fc49b4dbdadbe82acae581.apk, 4f0508904ec488ea7767e9d124b78097aefa8f43cc1713e81a7c4f45e1ba77f0.apk, 53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee.apk, 59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f.apk, 662bb00e9a82d43be45413fce12def326a1863f9cd3e63aa45b60d36ef7e0443.apk, 6a702c55f4ee54eeb35a991d7413328da1e56dde6e719babec23682423bec23f.apk, 75b4d9eb26ed9e20009c9a55a58e66457d7ec4d7d060179f09f6522e96c62e2e.apk, 7b167d362a9282adb176095be2e5bd4692b4158b7bdf4c6c20870daed5b04665.apk, 8ef35a9062369b6ce2e99571b0dc263be74ef888548a1072c609581b9adf3a93.apk, 904e4153d2026380dc42297173192e72de7e5d9ea50f16bf8df2e2fa6922cdc3.apk, 95236ef71738807ce60ef7d042699decb7156931931682cf46e6adc991dc9ecb.apk, b4b2197c5a8f0e9b9766fa39e9b538568284ec8a0099811b8b54fe6a1402545b.apk, bca248d31bf87b605e8cca7587a9753d58a9ad9a8f7e6f7f882d03150d72869f.apk, ca5b40e938f68321dfa3a7f1ad2a03db4ff6ba27fdae5e230654cd5c30090692.apk, d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2.apk, d5a84c85508c444743d055be354a464eb22dc5b33cba41e4b149829d182f4dca.apk, d9b75d606803968d04015bed042da887905e9c1cb1b40b4ff11852b88c8b4d21.apk, e0f530acc605475dc38c1bae9ecf9f7c94c80b8f24b695e3f8025dba1e8d5c22.apk, e163a088d174d4eb41479b53e6df04831dc40899b893a0b183d080d2dfe52cd7.apk, faab917444988b9a2e8d5d5bc06a0423c53718f92cbb8840cc6632f464c89130.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "018f8548c055a31d98201874ebf21591e6d85cb9eee66e8c35716a9289d01f48"
      hash2 = "0619168a8df6dd350052ca3a578abe15da0f2177e65acea55f44b5b59ed5f1c8"
      hash3 = "0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169"
      hash4 = "0badd9b4b0e44daeaa75b5d97ed9611a9f84418c1fb5683130e8b22742086549"
      hash5 = "0c8085cea946d655b266998fd60b1da33df73a4285328da3dabc7f0e7211411d"
      hash6 = "3638754e7fd889e9ced9127e7abe08191b7e8df3d60ed284c7b507e1e8082613"
      hash7 = "399c4819af422e581639c9350dcba71b0ee00b87a4d37da11806db5e25a0adc5"
      hash8 = "3ab3cc3c0df02d723c850e712fa5f4a0de29f2addf2c50beffe222112c2baa38"
      hash9 = "3c0a6f866aa4d74d0b39a2b9d11692ffa7291fd46b414e73cd5f9c7f9f030b75"
      hash10 = "41930e6f9187c8be4ea41303dd957d74f65b97944321a24a20028e76d10e0588"
      hash11 = "4e6c3f36a00638652d94b6a79722c7e40e11d73674fc49b4dbdadbe82acae581"
      hash12 = "4f0508904ec488ea7767e9d124b78097aefa8f43cc1713e81a7c4f45e1ba77f0"
      hash13 = "53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee"
      hash14 = "59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f"
      hash15 = "662bb00e9a82d43be45413fce12def326a1863f9cd3e63aa45b60d36ef7e0443"
      hash16 = "6a702c55f4ee54eeb35a991d7413328da1e56dde6e719babec23682423bec23f"
      hash17 = "75b4d9eb26ed9e20009c9a55a58e66457d7ec4d7d060179f09f6522e96c62e2e"
      hash18 = "7b167d362a9282adb176095be2e5bd4692b4158b7bdf4c6c20870daed5b04665"
      hash19 = "8ef35a9062369b6ce2e99571b0dc263be74ef888548a1072c609581b9adf3a93"
      hash20 = "904e4153d2026380dc42297173192e72de7e5d9ea50f16bf8df2e2fa6922cdc3"
      hash21 = "95236ef71738807ce60ef7d042699decb7156931931682cf46e6adc991dc9ecb"
      hash22 = "b4b2197c5a8f0e9b9766fa39e9b538568284ec8a0099811b8b54fe6a1402545b"
      hash23 = "bca248d31bf87b605e8cca7587a9753d58a9ad9a8f7e6f7f882d03150d72869f"
      hash24 = "ca5b40e938f68321dfa3a7f1ad2a03db4ff6ba27fdae5e230654cd5c30090692"
      hash25 = "d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2"
      hash26 = "d5a84c85508c444743d055be354a464eb22dc5b33cba41e4b149829d182f4dca"
      hash27 = "d9b75d606803968d04015bed042da887905e9c1cb1b40b4ff11852b88c8b4d21"
      hash28 = "e0f530acc605475dc38c1bae9ecf9f7c94c80b8f24b695e3f8025dba1e8d5c22"
      hash29 = "e163a088d174d4eb41479b53e6df04831dc40899b893a0b183d080d2dfe52cd7"
      hash30 = "faab917444988b9a2e8d5d5bc06a0423c53718f92cbb8840cc6632f464c89130"
   strings:
      $s1 = "Can't binary search on variable length encoded data." fullword ascii
      $s2 = "DW_EH_PE_aligned pointer encoding not supported" fullword ascii
      $s3 = "CIE version is not 1 or 3" fullword ascii
      $s4 = "DW_EH_PE_funcrel pointer encoding not supported" fullword ascii
      $s5 = "unsupported arm64 register" fullword ascii
      $s6 = "DW_EH_PE_textrel pointer encoding not supported" fullword ascii
      $s7 = "unknown pointer encoding" fullword ascii
      $s8 = "unsupported restore location for float register" fullword ascii
      $s9 = "unsupported restore location for register" fullword ascii
      $s10 = "libunwind: malformed DW_CFA_offset_extended_sf DWARF unwind, reg too big" fullword ascii
      $s11 = "libunwind: malformed DW_CFA_expression DWARF unwind, reg too big" fullword ascii
      $s12 = "FDE is really a CIE" fullword ascii
      $s13 = "FDE has zero length" fullword ascii
      $s14 = "libunwind: malformed DW_CFA_def_cfa_register DWARF unwind, reg too big" fullword ascii
      $s15 = "DWARF opcode not implemented" fullword ascii
      $s16 = "libunwind: malformed DW_CFA_offset_extended DWARF unwind, reg too big" fullword ascii
      $s17 = "libunwind: malformed DW_CFA_val_offset DWARF unwind, reg (%lu) out of range" fullword ascii
      $s18 = "libunwind: malformed DW_CFA_same_value DWARF unwind, reg too big" fullword ascii
      $s19 = "libunwind: malformed DW_CFA_def_cfa DWARF unwind, reg too big" fullword ascii
      $s20 = "DW_OP_deref_size with bad size" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cff_52 {
   meta:
      description = "apk - from files 1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cffb.apk, db11d9b51d90d23e5769d5f6dd738adad56acff41555698446926804d5396962.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cffb"
      hash2 = "db11d9b51d90d23e5769d5f6dd738adad56acff41555698446926804d5396962"
   strings:
      $s1 = "interpolator  app  contentDescription FrameLayout " fullword ascii
      $s2 = "2  android http://schemas.android.com/apk/res/android  " fullword ascii
      $s3 = "android contentDescription" fullword ascii
      $s4 = "  app http://schemas.android.com/apk/res-auto    **http://schemas.android.com/apk/res/android    android http://schemas.android." ascii
      $s5 = "contentDescription interpolator" fullword ascii
      $s6 = "style  RecyclerView FrameLayout" fullword ascii
      $s7 = "s  android http://schemas.android.com/apk/res/android    **http://schemas.android.com/apk/res/android   paddingBottom layout_mar" ascii
      $s8 = "7  android http://schemas.android.com/apk/res/android    **http://schemas.android.com/apk/res/android    app http://schemas.andr" ascii
      $s9 = "  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android    app http://schemas.andro" ascii
      $s10 = "!  app http://schemas.android.com/apk/res-auto    android http://schemas.android.com/apk/res/android    **http://schemas.android" ascii
      $s11 = "yj  android http://schemas.android.com/apk/res/android   interpolator " fullword ascii
      $s12 = "oid.com/apk/res-auto   layout_margin app  android layout_marginStart " fullword ascii
      $s13 = "V  android http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto  " fullword ascii
      $s14 = "  app http://schemas.android.com/apk/res-auto    android http://schemas.android.com/apk/res/android   " fullword ascii
      $s15 = "  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android    app http://schemas.andro" ascii
      $s16 = "s  android http://schemas.android.com/apk/res/android    **http://schemas.android.com/apk/res/android   paddingBottom layout_mar" ascii
      $s17 = "  android http://schemas.android.com/apk/res/android    **http://schemas.android.com/apk/res/android    app http://schemas.andro" ascii
      $s18 = "!  app http://schemas.android.com/apk/res-auto    android http://schemas.android.com/apk/res/android    **http://schemas.android" ascii
      $s19 = "P(  android http://schemas.android.com/apk/res/android    **http://schemas.android.com/apk/res/android   " fullword ascii
      $s20 = "p7^V  android http://schemas.android.com/apk/res/android    **http://schemas.android.com/apk/res/android    LinearLayout " fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _0619168a8df6dd350052ca3a578abe15da0f2177e65acea55f44b5b59ed5f1c_53 {
   meta:
      description = "apk - from files 0619168a8df6dd350052ca3a578abe15da0f2177e65acea55f44b5b59ed5f1c8.apk, 0badd9b4b0e44daeaa75b5d97ed9611a9f84418c1fb5683130e8b22742086549.apk, 0c8085cea946d655b266998fd60b1da33df73a4285328da3dabc7f0e7211411d.apk, 2117f4f448674fb5fafa5dd581777d35255253a4b82c9d0be2aac917efec8ae8.apk, 2a5f808f305334a0cfec1daa7290ace649079ab9c6dbed43f77ffdccb55c6e31.apk, 3638754e7fd889e9ced9127e7abe08191b7e8df3d60ed284c7b507e1e8082613.apk, 399c4819af422e581639c9350dcba71b0ee00b87a4d37da11806db5e25a0adc5.apk, 3ab3cc3c0df02d723c850e712fa5f4a0de29f2addf2c50beffe222112c2baa38.apk, 3c0a6f866aa4d74d0b39a2b9d11692ffa7291fd46b414e73cd5f9c7f9f030b75.apk, 41930e6f9187c8be4ea41303dd957d74f65b97944321a24a20028e76d10e0588.apk, 4845bbe3b1f17da3783db71b6a471b9dc073c8459fe2981004fbbcd70144ec01.apk, 4f0508904ec488ea7767e9d124b78097aefa8f43cc1713e81a7c4f45e1ba77f0.apk, 51863351193ab67148e3e47255cad4927eb13939292c7854121ebedb4de28590.apk, 58cc948bd809292143e604c3e03735c9517f94b37dd35299ca5e81d7b902d620.apk, 63a19cd37e5f23ba982d004e587472bdc30d64af04e1b321419d8173a16c60cc.apk, 662bb00e9a82d43be45413fce12def326a1863f9cd3e63aa45b60d36ef7e0443.apk, 6a702c55f4ee54eeb35a991d7413328da1e56dde6e719babec23682423bec23f.apk, 6e87157051e31528627d600f310e0b7252f85fcaf9607b34e5a4156b2d14cdec.apk, 75b4d9eb26ed9e20009c9a55a58e66457d7ec4d7d060179f09f6522e96c62e2e.apk, 7b167d362a9282adb176095be2e5bd4692b4158b7bdf4c6c20870daed5b04665.apk, 904e4153d2026380dc42297173192e72de7e5d9ea50f16bf8df2e2fa6922cdc3.apk, 95e88ec3ceb56c7f3679c45b837f931d0b38269a2e275628f2bc1a9f5c77a19f.apk, 9904bb103fae65ab3dd712f6b9ff361d3f3cb3a4cc814b69f0af3e2f1a837ecd.apk, 9ae895cd6474d1928bbbd68e240679c9de3c0ca327ac4e4b83845878b72322be.apk, a0edfa97344c870ee24aa7c008cec40e85e616c21e86522b8f6fce0324b356f7.apk, a97c8523696f6ef8f30cc6cf4b60a7a46fcb8716176741e09dfa81d5eacd8334.apk, b4b2197c5a8f0e9b9766fa39e9b538568284ec8a0099811b8b54fe6a1402545b.apk, be8adc196213154b10bd4209098ff94083d5ade71abeeacbf9d4cf30e3403234.apk, c5544517f1be9d5a721a951d906b26f9ad11adf4a06c3660a75e89f07dabb8aa.apk, c5dc6d8f325c125fba0a9ceea0cac957642fbf0a38bd4da867a82f6f06962d45.apk, ca5b40e938f68321dfa3a7f1ad2a03db4ff6ba27fdae5e230654cd5c30090692.apk, d5a84c85508c444743d055be354a464eb22dc5b33cba41e4b149829d182f4dca.apk, d69108a94a9a81e07a05d456dc997cbf5b5a8cc8f0869eae7904fac1da60f335.apk, d9b75d606803968d04015bed042da887905e9c1cb1b40b4ff11852b88c8b4d21.apk, ddeb13abf09d096f821ee657c3479f799f2a236b49f46c80a0afb2676a8f55ab.apk, dfa3539353b89089a3599f4775a296b270751738186af515bf3e630dc054bc7d.apk, e163a088d174d4eb41479b53e6df04831dc40899b893a0b183d080d2dfe52cd7.apk, e3d0cbffe67561de432b5b0e912328ed7c32c5fcfb3a5002515e34b517d7296b.apk, ee9eceda9522ae4c5ff3e07aefa523c61d50ebb9aca2808e0f4494a8c53498ea.apk, faab917444988b9a2e8d5d5bc06a0423c53718f92cbb8840cc6632f464c89130.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "0619168a8df6dd350052ca3a578abe15da0f2177e65acea55f44b5b59ed5f1c8"
      hash2 = "0badd9b4b0e44daeaa75b5d97ed9611a9f84418c1fb5683130e8b22742086549"
      hash3 = "0c8085cea946d655b266998fd60b1da33df73a4285328da3dabc7f0e7211411d"
      hash4 = "2117f4f448674fb5fafa5dd581777d35255253a4b82c9d0be2aac917efec8ae8"
      hash5 = "2a5f808f305334a0cfec1daa7290ace649079ab9c6dbed43f77ffdccb55c6e31"
      hash6 = "3638754e7fd889e9ced9127e7abe08191b7e8df3d60ed284c7b507e1e8082613"
      hash7 = "399c4819af422e581639c9350dcba71b0ee00b87a4d37da11806db5e25a0adc5"
      hash8 = "3ab3cc3c0df02d723c850e712fa5f4a0de29f2addf2c50beffe222112c2baa38"
      hash9 = "3c0a6f866aa4d74d0b39a2b9d11692ffa7291fd46b414e73cd5f9c7f9f030b75"
      hash10 = "41930e6f9187c8be4ea41303dd957d74f65b97944321a24a20028e76d10e0588"
      hash11 = "4845bbe3b1f17da3783db71b6a471b9dc073c8459fe2981004fbbcd70144ec01"
      hash12 = "4f0508904ec488ea7767e9d124b78097aefa8f43cc1713e81a7c4f45e1ba77f0"
      hash13 = "51863351193ab67148e3e47255cad4927eb13939292c7854121ebedb4de28590"
      hash14 = "58cc948bd809292143e604c3e03735c9517f94b37dd35299ca5e81d7b902d620"
      hash15 = "63a19cd37e5f23ba982d004e587472bdc30d64af04e1b321419d8173a16c60cc"
      hash16 = "662bb00e9a82d43be45413fce12def326a1863f9cd3e63aa45b60d36ef7e0443"
      hash17 = "6a702c55f4ee54eeb35a991d7413328da1e56dde6e719babec23682423bec23f"
      hash18 = "6e87157051e31528627d600f310e0b7252f85fcaf9607b34e5a4156b2d14cdec"
      hash19 = "75b4d9eb26ed9e20009c9a55a58e66457d7ec4d7d060179f09f6522e96c62e2e"
      hash20 = "7b167d362a9282adb176095be2e5bd4692b4158b7bdf4c6c20870daed5b04665"
      hash21 = "904e4153d2026380dc42297173192e72de7e5d9ea50f16bf8df2e2fa6922cdc3"
      hash22 = "95e88ec3ceb56c7f3679c45b837f931d0b38269a2e275628f2bc1a9f5c77a19f"
      hash23 = "9904bb103fae65ab3dd712f6b9ff361d3f3cb3a4cc814b69f0af3e2f1a837ecd"
      hash24 = "9ae895cd6474d1928bbbd68e240679c9de3c0ca327ac4e4b83845878b72322be"
      hash25 = "a0edfa97344c870ee24aa7c008cec40e85e616c21e86522b8f6fce0324b356f7"
      hash26 = "a97c8523696f6ef8f30cc6cf4b60a7a46fcb8716176741e09dfa81d5eacd8334"
      hash27 = "b4b2197c5a8f0e9b9766fa39e9b538568284ec8a0099811b8b54fe6a1402545b"
      hash28 = "be8adc196213154b10bd4209098ff94083d5ade71abeeacbf9d4cf30e3403234"
      hash29 = "c5544517f1be9d5a721a951d906b26f9ad11adf4a06c3660a75e89f07dabb8aa"
      hash30 = "c5dc6d8f325c125fba0a9ceea0cac957642fbf0a38bd4da867a82f6f06962d45"
      hash31 = "ca5b40e938f68321dfa3a7f1ad2a03db4ff6ba27fdae5e230654cd5c30090692"
      hash32 = "d5a84c85508c444743d055be354a464eb22dc5b33cba41e4b149829d182f4dca"
      hash33 = "d69108a94a9a81e07a05d456dc997cbf5b5a8cc8f0869eae7904fac1da60f335"
      hash34 = "d9b75d606803968d04015bed042da887905e9c1cb1b40b4ff11852b88c8b4d21"
      hash35 = "ddeb13abf09d096f821ee657c3479f799f2a236b49f46c80a0afb2676a8f55ab"
      hash36 = "dfa3539353b89089a3599f4775a296b270751738186af515bf3e630dc054bc7d"
      hash37 = "e163a088d174d4eb41479b53e6df04831dc40899b893a0b183d080d2dfe52cd7"
      hash38 = "e3d0cbffe67561de432b5b0e912328ed7c32c5fcfb3a5002515e34b517d7296b"
      hash39 = "ee9eceda9522ae4c5ff3e07aefa523c61d50ebb9aca2808e0f4494a8c53498ea"
      hash40 = "faab917444988b9a2e8d5d5bc06a0423c53718f92cbb8840cc6632f464c89130"
   strings:
      $s1 = "Company logo" fullword ascii
      $s2 = "- Correction de bugs critiques." fullword ascii
      $s3 = "CC- Improved performance." fullword ascii
      $s4 = "- New feature added." fullword ascii
      $s5 = "##Error: installation file not found." fullword ascii
      $s6 = "**Errore: file di installazione non trovato." fullword ascii
      $s7 = "((Failed to prepare the installation file." fullword ascii
      $s8 = "- Yeni " fullword ascii
      $s9 = "Info icon" fullword ascii
      $s10 = "- Fixed critical bugs." fullword ascii
      $s11 = "Taille : 2.2 Mo" fullword ascii
      $s12 = "Size: 2.2 MB" fullword ascii
      $s13 = "//Impossibile preparare il file di installazione." fullword ascii
      $s14 = "n alma" fullword ascii
      $s15 = "n para usar la aplicaci" fullword ascii
      $s16 = "66You need to install the update to use the application." fullword ascii
      $s17 = "Application inconnue" fullword ascii
      $s18 = "!!Vous pouvez lancer l'application." fullword ascii
      $s19 = "Unknown application" fullword ascii
      $s20 = "ABPour utiliser l'application, vous devez installer la mise " fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb4_54 {
   meta:
      description = "apk - from files 017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44.apk, 01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0.apk, 0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e.apk, 08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c.apk, 11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea.apk, 1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c.apk, 1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0.apk, 23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61.apk, 29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b.apk, 3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089.apk, 34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45.apk, 392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647.apk, 3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec.apk, 41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2.apk, 41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce.apk, 4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f.apk, 4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290.apk, 4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088.apk, 4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b.apk, 5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3.apk, 65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf.apk, 6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8.apk, 6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd.apk, 6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738.apk, 73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4.apk, 73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a.apk, 7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570.apk, 7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, 8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552.apk, 83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a.apk, 9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5.apk, 9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d.apk, 9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c.apk, 9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90.apk, 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk, 9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6.apk, a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5.apk, a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de.apk, b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk, b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6.apk, bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7.apk, c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14.apk, c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9.apk, c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk, ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642.apk, d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af.apk, d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3.apk, d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372.apk, d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe.apk, d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d.apk, d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38.apk, decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8.apk, e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3.apk, e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938.apk, e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75.apk, e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8.apk, e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk, f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2.apk, f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738.apk, faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44"
      hash2 = "01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0"
      hash3 = "0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e"
      hash4 = "08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c"
      hash5 = "11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415"
      hash6 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash7 = "134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138"
      hash8 = "1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea"
      hash9 = "1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c"
      hash10 = "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
      hash11 = "23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61"
      hash12 = "29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896"
      hash13 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash14 = "31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b"
      hash15 = "3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089"
      hash16 = "34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45"
      hash17 = "392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d"
      hash18 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash19 = "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
      hash20 = "3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec"
      hash21 = "41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2"
      hash22 = "41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7"
      hash23 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash24 = "48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce"
      hash25 = "4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f"
      hash26 = "4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290"
      hash27 = "4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088"
      hash28 = "4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7"
      hash29 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash30 = "563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b"
      hash31 = "5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a"
      hash32 = "5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8"
      hash33 = "6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3"
      hash34 = "65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf"
      hash35 = "6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8"
      hash36 = "6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd"
      hash37 = "6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738"
      hash38 = "73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4"
      hash39 = "73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a"
      hash40 = "7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570"
      hash41 = "7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144"
      hash42 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
      hash43 = "8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552"
      hash44 = "83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025"
      hash45 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash46 = "90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a"
      hash47 = "9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5"
      hash48 = "9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d"
      hash49 = "9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c"
      hash50 = "9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90"
      hash51 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
      hash52 = "9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6"
      hash53 = "a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5"
      hash54 = "a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2"
      hash55 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash56 = "a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa"
      hash57 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash58 = "ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de"
      hash59 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
      hash60 = "b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99"
      hash61 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash62 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash63 = "bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6"
      hash64 = "bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7"
      hash65 = "c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14"
      hash66 = "c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9"
      hash67 = "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
      hash68 = "ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642"
      hash69 = "d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af"
      hash70 = "d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3"
      hash71 = "d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372"
      hash72 = "d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe"
      hash73 = "d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d"
      hash74 = "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
      hash75 = "decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8"
      hash76 = "e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3"
      hash77 = "e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938"
      hash78 = "e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75"
      hash79 = "e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8"
      hash80 = "e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf"
      hash81 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash82 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
      hash83 = "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
      hash84 = "f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738"
      hash85 = "faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee"
      hash86 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
      hash87 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "11Passer en mode horloge pour la saisie de l'heure." fullword ascii
      $s2 = "++Passer au mode Horloge pour entrer l'heure." fullword ascii
      $s3 = "34Passer au mode Entr" fullword ascii
      $s4 = "DEPentru a introduce ora, comuta" fullword ascii
      $s5 = "/0Pentru a introduce ora, comuta" fullword ascii
      $s6 = "99Passer en mode saisie de texte pour la saisie de l'heure." fullword ascii
      $s7 = "*+Byt till textinmatningsl" fullword ascii
      $s8 = "Valige tund" fullword ascii
      $s9 = "!\"Byt till klockl" fullword ascii
      $s10 = "$$Beralih ke mod jam untuk input masa." fullword ascii
      $s11 = "Izberite minute" fullword ascii
      $s12 = "%1$s minuter" fullword ascii
      $s13 = "Laika atlas" fullword ascii
      $s14 = "AALumipat sa pamamaraan ng pag-input ng text para sa input na oras." fullword ascii
      $s15 = "69Mude para o modo de rel" fullword ascii
      $s16 = "++Beralih ke mod input teks untuk input masa." fullword ascii
      $s17 = "Kell %1$s" fullword ascii
      $s18 = "e de texte pour entrer l'heure." fullword ascii
      $s19 = "in rada kao sat za unos vremena." fullword ascii
      $s20 = "79Alterne para o modo de rel" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a9_55 {
   meta:
      description = "apk - from files 1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90.apk, 2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0.apk, aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8.apk, ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90"
      hash2 = "2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0"
      hash3 = "aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8"
      hash4 = "ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33"
   strings:
      $s1 = " If you cannot get the payment address by scanning, tap the QR code to copy the address. " fullword ascii
      $s2 = " Use your TRC20 wallet to scan the QR code to get the payment address. Enter the exact amount shown (in green), including the 6-" ascii
      $s3 = " Please choose a subscription plan. Advanced has more features. Each account can log in on up to 2 devices. Log out from one to " ascii
      $s4 = "BBThe decimal is your payment verify code !!! DO NOT DELETE THEM !!!" fullword ascii
      $s5 = "IIReset password Email Sent,Please check! Only open the link in this phone." fullword ascii
      $s6 = "mmNew %s Server Found > Server Name: %s > IP Address: %s > Port: %d You can view this in user information later" fullword ascii
      $s7 = " In an emergency, you can get time from a friend via the Share Time feature. " fullword ascii
      $s8 = "((Enter a valid port number (keep default)" fullword ascii
      $s9 = "::Account is not Activated. Please confirm your Email first." fullword ascii
      $s10 = "@@Authentication failed" fullword ascii
      $s11 = "[[> Configuration applied automatically > Please go to settings to activate the configuration" fullword ascii
      $s12 = "EEPlease use your TRC20 wallet to Pay It will take 1 minute to recharge" fullword ascii
      $s13 = "Server is not responding. Please try again or choose another server in Settings. " fullword ascii
      $s14 = "switch to another. " fullword ascii
      $s15 = "Telegram @supercard_support" fullword ascii
      $s16 = "bbResetting NFC and APDU Services (%1$d Sec) please restart App manually later. SuperCard ForceReset" fullword ascii
      $s17 = "Telegram: @supercard_support" fullword ascii
      $s18 = "digit code after the decimal point. Input errors will cause the recharge to fail. " fullword ascii
      $s19 = "For assistance contact @supercard_support" fullword ascii
      $s20 = "&&Configuring the server, please wait..." fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb4_56 {
   meta:
      description = "apk - from files 017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44.apk, 01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0.apk, 0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e.apk, 08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c.apk, 11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea.apk, 1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c.apk, 1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0.apk, 23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61.apk, 29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b.apk, 3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089.apk, 34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45.apk, 392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647.apk, 3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec.apk, 41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2.apk, 41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce.apk, 4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f.apk, 4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290.apk, 4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088.apk, 4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b.apk, 5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3.apk, 65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf.apk, 6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8.apk, 6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd.apk, 6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738.apk, 73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4.apk, 73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a.apk, 7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, 8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552.apk, 83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a.apk, 9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5.apk, 9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d.apk, 9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c.apk, 9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90.apk, 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk, 9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6.apk, a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5.apk, a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de.apk, b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk, b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6.apk, bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14.apk, c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9.apk, c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk, ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642.apk, d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af.apk, d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3.apk, d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372.apk, d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe.apk, d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d.apk, d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38.apk, decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8.apk, e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3.apk, e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938.apk, e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75.apk, e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8.apk, e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk, f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2.apk, f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738.apk, faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44"
      hash2 = "01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0"
      hash3 = "0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e"
      hash4 = "08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c"
      hash5 = "11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415"
      hash6 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash7 = "134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138"
      hash8 = "1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea"
      hash9 = "1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c"
      hash10 = "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
      hash11 = "23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61"
      hash12 = "29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896"
      hash13 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash14 = "31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b"
      hash15 = "3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089"
      hash16 = "34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45"
      hash17 = "392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d"
      hash18 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash19 = "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
      hash20 = "3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec"
      hash21 = "41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2"
      hash22 = "41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7"
      hash23 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash24 = "48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce"
      hash25 = "4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f"
      hash26 = "4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290"
      hash27 = "4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088"
      hash28 = "4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7"
      hash29 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash30 = "563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b"
      hash31 = "5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a"
      hash32 = "5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8"
      hash33 = "6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3"
      hash34 = "65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf"
      hash35 = "6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8"
      hash36 = "6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd"
      hash37 = "6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738"
      hash38 = "73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4"
      hash39 = "73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a"
      hash40 = "7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144"
      hash41 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
      hash42 = "8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552"
      hash43 = "83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025"
      hash44 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash45 = "90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a"
      hash46 = "9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5"
      hash47 = "9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d"
      hash48 = "9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c"
      hash49 = "9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90"
      hash50 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
      hash51 = "9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6"
      hash52 = "a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5"
      hash53 = "a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2"
      hash54 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash55 = "a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa"
      hash56 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash57 = "ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de"
      hash58 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
      hash59 = "b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99"
      hash60 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash61 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash62 = "bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6"
      hash63 = "bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7"
      hash64 = "bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0"
      hash65 = "c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14"
      hash66 = "c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9"
      hash67 = "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
      hash68 = "ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642"
      hash69 = "d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af"
      hash70 = "d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3"
      hash71 = "d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372"
      hash72 = "d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe"
      hash73 = "d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d"
      hash74 = "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
      hash75 = "decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8"
      hash76 = "e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3"
      hash77 = "e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938"
      hash78 = "e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75"
      hash79 = "e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8"
      hash80 = "e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf"
      hash81 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash82 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
      hash83 = "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
      hash84 = "f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738"
      hash85 = "faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee"
      hash86 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
      hash87 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "Yeni bildirim" fullword ascii
      $s2 = "%d notifikasi baru" fullword ascii
      $s3 = "%d jakinarazpen berri" fullword ascii
      $s4 = "%d nova obvestila" fullword ascii
      $s5 = "%d nova obavje" fullword ascii
      $s6 = "%d yeni bildiri" fullword ascii
      $s7 = "%%%1$d jakinarazpen berri baino gehiago" fullword ascii
      $s8 = "%d nova obave" fullword ascii
      $s9 = "Minimum %1$d yeni bildiri" fullword ascii
      $s10 = "Nova obavijest" fullword ascii
      $s11 = "Yeni bildiri" fullword ascii
      $s12 = "  %1$d adetten fazla yeni bildirim" fullword ascii
      $s13 = "Peste %1$d notific" fullword ascii
      $s14 = "bb mint %1$d " fullword ascii
      $s15 = "%d nova obavijest" fullword ascii
      $s16 = "Notifikasi baru" fullword ascii
      $s17 = "%d yeni bildirim" fullword ascii
      $s18 = "$%Plus de %1$d" fullword ascii
      $s19 = "n nova" fullword ascii
      $s20 = "nouvelle notification" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _2117f4f448674fb5fafa5dd581777d35255253a4b82c9d0be2aac917efec8ae_57 {
   meta:
      description = "apk - from files 2117f4f448674fb5fafa5dd581777d35255253a4b82c9d0be2aac917efec8ae8.apk, 58cc948bd809292143e604c3e03735c9517f94b37dd35299ca5e81d7b902d620.apk, 6e87157051e31528627d600f310e0b7252f85fcaf9607b34e5a4156b2d14cdec.apk, 9904bb103fae65ab3dd712f6b9ff361d3f3cb3a4cc814b69f0af3e2f1a837ecd.apk, a97c8523696f6ef8f30cc6cf4b60a7a46fcb8716176741e09dfa81d5eacd8334.apk, c5544517f1be9d5a721a951d906b26f9ad11adf4a06c3660a75e89f07dabb8aa.apk, c5dc6d8f325c125fba0a9ceea0cac957642fbf0a38bd4da867a82f6f06962d45.apk, e3d0cbffe67561de432b5b0e912328ed7c32c5fcfb3a5002515e34b517d7296b.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "2117f4f448674fb5fafa5dd581777d35255253a4b82c9d0be2aac917efec8ae8"
      hash2 = "58cc948bd809292143e604c3e03735c9517f94b37dd35299ca5e81d7b902d620"
      hash3 = "6e87157051e31528627d600f310e0b7252f85fcaf9607b34e5a4156b2d14cdec"
      hash4 = "9904bb103fae65ab3dd712f6b9ff361d3f3cb3a4cc814b69f0af3e2f1a837ecd"
      hash5 = "a97c8523696f6ef8f30cc6cf4b60a7a46fcb8716176741e09dfa81d5eacd8334"
      hash6 = "c5544517f1be9d5a721a951d906b26f9ad11adf4a06c3660a75e89f07dabb8aa"
      hash7 = "c5dc6d8f325c125fba0a9ceea0cac957642fbf0a38bd4da867a82f6f06962d45"
      hash8 = "e3d0cbffe67561de432b5b0e912328ed7c32c5fcfb3a5002515e34b517d7296b"
   strings:
      $s1 = "Mozilla/5.0 (Linux; Android " fullword ascii
      $s2 = "sending report" fullword ascii
      $s3 = "- Performance optimization." fullword ascii
      $s4 = "- Minor fixes." fullword ascii
      $s5 = "~~D8{\"backend\":\"dex\",\"compilation-mode\":\"debug\",\"has-checksums\":false,\"min-api\":26,\"sha-1\":\"abaab469b5ebd4dd2bb91" ascii
      $s6 = "DD- Stability improvements." fullword ascii
      $s7 = "88A newer version is available. Please update to continue." fullword ascii
      $s8 = "decoy launch failed: " fullword ascii
      $s9 = "attachBaseContext error: " fullword ascii
      $s10 = "~~D8{\"backend\":\"dex\",\"compilation-mode\":\"debug\",\"has-checksums\":false,\"min-api\":26,\"sha-1\":\"abaab469b5ebd4dd2bb91" ascii
      $s11 = " Android: " fullword ascii
      $s12 = "Rated for 3+" fullword ascii
      $s13 = "%1$s is ready" fullword ascii
      $s14 = " Fingerprint: " fullword ascii
      $s15 = "blocked: " fullword ascii
      $s16 = "silent block: bot label=" fullword ascii
      $s17 = "Contains optional features" fullword ascii
      $s18 = "Para mayores de 3 a" fullword ascii
      $s19 = "silent block: liteResult=3" fullword ascii
      $s20 = " Provider missing in decoy mode: " fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13ce_58 {
   meta:
      description = "apk - from files 53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee.apk, 6376bcd8faa57aac7437116b184967a588025e2bf96318272cdcf51ff2f8dfdd.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee"
      hash2 = "6376bcd8faa57aac7437116b184967a588025e2bf96318272cdcf51ff2f8dfdd"
   strings:
      $s1 = " Lkotlin/time/Duration$Companion;" fullword ascii
      $s2 = "UNDISPATCHED" fullword ascii
      $s3 = "Horizontal(alignment=" fullword ascii
      $s4 = "3Landroid/view/inputmethod/CursorAnchorInfo$Builder;" fullword ascii
      $s5 = "contains$default" fullword ascii
      $s6 = "cancel$default" fullword ascii
      $s7 = "{ location = " fullword ascii
      $s8 = "*visitChildren called on an unattached node" fullword ascii
      $s9 = "3Landroid/view/textclassifier/TextSelection$Request;" fullword ascii
      $s10 = ";Landroid/view/textclassifier/TextSelection$Request$Builder;" fullword ascii
      $s11 = "Vertical(menuAlignment=" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb4_59 {
   meta:
      description = "apk - from files 017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44.apk, 01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0.apk, 0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e.apk, 04e4acc8cd2a66f77260ebcfbe40646192ff452d5f9bbe54e0acbd0cabc3cfbc.apk, 05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a.apk, 0596a76e6772acb911c1a556ad86943224873411fba4383abade25300078ed32.apk, 08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c.apk, 090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90ba268.apk, 091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d96241620a5.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd.apk, 0f9fe82c6594fe331e59cf0268bc402f9e31141a3fd5e5dd99596d28563c5e9b.apk, 0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072.apk, 1099eede57e825fa5158b33f01559dc76e6d67e2fca37b97f76e7d3aa9a4208a.apk, 11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 12cb6136d2d325563b5079c138eeac2bc4ee4af3373718ba1c79c47a6121829e.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea.apk, 13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52.apk, 1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90.apk, 174deed18377e5280413a2015ebe2041fd8b4276a6599754299cf05cea0718d5.apk, 17a68e32e5d8398c93790abe9b117c472557b54ccdcfccfdddb3b7f783ca31b3.apk, 185a01ec24938cd5a9af4fd66a0814e8bfaf2e1ff8cfa2396a30c3e4f6e66b98.apk, 19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c20271e62.apk, 1b5ff50963c6e99dfb521e6db624df9f83f21f06430ce9d8f3cd0de735cbe22a.apk, 1bf9c16cb7c1faae7fa99a57c5d091cbd1e6d5f3c0d79693a3b0990a8b58367d.apk, 1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c.apk, 1d9bdb35234b01d219fd28c47a47bbaa6c9033e2b1f35b07f10cf09eaed00254.apk, 1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0.apk, 1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9.apk, 21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e494fe.apk, 22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b.apk, 238eeea51b2d53ff08b3129fe6d6be75a13c12090e4063a1455fad614054d4b3.apk, 23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61.apk, 246bdb0a9e7698e37ec7b906551ceed302d0445c9572bb3cdc02a68862fd2d2a.apk, 25fdf72cb393901eb605d6eaea86fe67483a25295651e2423b9e50d5bfc62111.apk, 269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471eed36.apk, 27b8eeb5d1b46e1afa170b998830fe0958f08a2a9dfe7130df607c86ad42fb33.apk, 29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896.apk, 2b7e044edadb6932c251f2169da0a777bf553a549a263c5c8a0cf9d888cee704.apk, 2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0.apk, 2d0fd4ea41c4e17cf94577c126ae271555b544f388baca69112cd3a488572be1.apk, 2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1.apk, 2f451d9cfda5d91b2063a62ed5ad482cd733e899b9ee39ee8bd332b518b3b865.apk, 2f595b306756f39b0d525b19d5f5c1d50a5e6761ea049a63a390ec3e6709a2ba.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b.apk, 3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089.apk, 33c3f43852f6ecadef74aef2dbb0d5a1215aa3cb23e4aaf76f202beed3aa8703.apk, 34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45.apk, 3616fd6004678159e531fb7e5a173b333c08bd0097aa1f6a4e9f503db4a9999a.apk, 392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d.apk, 39c97fad655efc5aa4bc3703695b80e9807b14050fe9c8785cd047d3f3051668.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647.apk, 3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5dce6.apk, 3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd.apk, 3d8da22674ee343bd02296a4351e90198ffc786f8541747e42cdcf3438f16b3e.apk, 3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec.apk, 3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c.apk, 41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2.apk, 41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7.apk, 43996d454961143bad870d9b94a3d00912f7c29b76371244ac59423595ae0860.apk, 446800befecf9179f9aca09dd88331dee0e745b199db39a9b0113f4ee886ca34.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 469b13cac1eb859da7ba4b597270f047b11815bfff9c4ad3faa5617c07a6c3e0.apk, 48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce.apk, 4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951.apk, 4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f.apk, 4a899a3b0fd61937ce8555cb0da53daf72dadc7dd299c63e90b4a203e5a14db1.apk, 4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290.apk, 4af08f08377457cb04e280615fc8647870f9b20ad763e1bd060731605d8a0c07.apk, 4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088.apk, 4bdf7226644876c09e6091127260593a4f7af3b78d148b56004eb1be09bdf4b8.apk, 4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7.apk, 50990c1178790239445d4dea570e4affeca6efbb01a91cbf4af4498a0477dd2e.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 557c02b5e9ca8103e6ad5413df1b447fae5c9ce086a0b5330bf9c79a578585df.apk, 563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b.apk, 57151572cf361d49ead0235eef7cad3827f4711120f3397e746a660aa9c6250b.apk, 57a0a81eebdf6c1e0a5ab0489165f167856712121b86959f0c34ce5c24014266.apk, 59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f.apk, 5a8d4eabd009a75ecc04f3f06489d393f082f963b406d0d3e8acbea568281c5f.apk, 5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8.apk, 5cb94ba3236bd4fa89bad460687cc2f1e80a890f5a093e954ea2704c1950c1f3.apk, 5dff60862aea80d5da616400359ae170f2d9ef9d76a745417f4facff72cd4c17.apk, 5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3.apk, 64b4f8c86ea5ef925da573e7667ca93d32f4fb27fd6a702f5e99ccc4d087f612.apk, 6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3.apk, 6564e7362b89d453173884e35d96ff5ce1de7ecbad102b0f5450300418b5de9b.apk, 657881e96def3e69a401f79c678edff27c3db4db74ba802fb8989ae466f73cc9.apk, 65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf.apk, 6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22.apk, 6b0c56540499051ab350a31f417b99859da7ed7286b9e77503711c6aabafbe03.apk, 6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8.apk, 6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa8255405.apk, 6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd.apk, 6dd19edd60ed2025afc6b661e85f146c925f2137e51ae49c5d1dce955ac43aaf.apk, 6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738.apk, 73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4.apk, 73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a.apk, 752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e40ab.apk, 75cd6f164dee674a18edc5154ef0d48633eb581b73d77aef047af0a5856420cc.apk, 7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570.apk, 77c54058a2bb45219e6ee860430f5ea8ce8e6ed2e58fba05f0d9bf74ffb7b4ef.apk, 78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b.apk, 7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144.apk, 79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826fdd3.apk, 7b40e010ae6556b159eaaba4f0989bd57cc510c388215f2d89580cc3379ae33c.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, 7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf26527b7.apk, 807d8ffb7975d525386036b10563485033155f62d4355a83e372b08b370c3850.apk, 8166dfba7fd0b4ad44c8bc91cc0e98fa06b8912e3fca2093900eb58ba79d22d4.apk, 8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552.apk, 83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025.apk, 857d9e064fe567da2b5f42b49787d05d0238f34ddc2890a826d80d8f012f7e8d.apk, 8613f7b6df514d53aa419355b0a3e8d032b8448bd45296d4158b848998015e3d.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c4f8053881899f844a2e6dea8ce119124acac2b34750a47650e368c27bf7a3b.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a.apk, 9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e0ece.apk, 994869cacc3615cde8d4196cdfe1e2877f0e1328ff32a292963ffd0983b450fa.apk, 9aff583b812a3979394ffcd23f616d561a0eda4002f2e2a4b42ea5ba3efdbfaf.apk, 9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5.apk, 9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d.apk, 9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d.apk, 9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3bb5d1.apk, 9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c.apk, 9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90.apk, 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk, 9e7d743c341329104a12cfbcf53cc19a9b16c4ec1a874f8d4b42b33e9a68c1f8.apk, 9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b3306.apk, 9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6.apk, a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5.apk, a2c509d0b0fcee3bc503bd12986da2d29c74ebcd37abb1af8988f7f26382663d.apk, a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa.apk, a8030b195f685a2c1b3a5de807f769d38f87efff8bab8c5bfce5a6fabedcc477.apk, a8062f50057c4d8be86c50b411addafa7429b451420b3aaeb1ec6f04aef18957.apk, a81b801522a1c72be91aefffa09b00256fad4ee9d47bb8d79b018b442ab4e78b.apk, aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8.apk, aab9cf77aca821c3f2930315c2afd140ff12441f0d8f0cb0d45927ef7af43ed5.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de.apk, adefc2f666aa936763b18300444995e1d2a4c1950ef00577de7a88381b825c1f.apk, afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4.apk, b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk, b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e.apk, b1a8941063751656e11bbc6ab44d348cd6795d51bfc890424595c4ac76e52013.apk, b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, b50dfd257f1cfda6f67d269571f5e9b251c7f34d54c7f7d865b9d6bed89a49bb.apk, b8fa21bbd5261f2308a168c1f43b197220c0d37bdda0c4a1464be085a9f85300.apk, ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33.apk, bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6.apk, bc5ecb77e8aee510a380108013e073f0d0f3b41bd9ba2169bcb8eb85b405347f.apk, bc74da49cf58d85b8ce8a49d2ac0fed574ef1634e67d92ef75440d7b24d0a3e4.apk, bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de.apk, c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14.apk, c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9.apk, c585e3cbaa19ff4934e07f77f447c87a94f21793f9ff35301e1689849d796745.apk, c659454dd6ed62bc7a0c9e0455297e41ba57b0b7935a826150c1f8c0db6f89d2.apk, c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64.apk, c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d.apk, c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk, ca6271b212c627dd6e4372827a0fb316023fa35210cab7249d634379af6d649c.apk, cadcce6d4088c72fd0779d59d00f5753eaab585a263e3c92374df29ae767ac15.apk, cb147e7ce69723523f604da875d78ca4738e5f416d2297910ee179a5067e79fe.apk, cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c.apk, ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9.apk, ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642.apk, cfd656e0d18e1ed7064941197e6504a4b1cdcd3bc6476389dca71237dd839284.apk, d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af.apk, d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3.apk, d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd.apk, d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2.apk, d3c63ecb3a95272a043b3e0ab792a70738c867ba18e896c455d9c39d32fff4d3.apk, d3fc5ffdd9a68a3063b1c8ff15334238dd39a63b9c93ec9f337bdd5f5357046a.apk, d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372.apk, d566c64a41faf573349cf2c0ecb00f68dbe8b90bc1968d3317d3a20667ddad63.apk, d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5.apk, d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe.apk, d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d.apk, d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38.apk, dd0919967c57cdabdf8b5bc9c643bb0d250fe935476aa4944544b22132d5163d.apk, decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8.apk, e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3.apk, e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938.apk, e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75.apk, e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b.apk, e4aa98c1beee901871fd8a78b37b21ef886e507e65fc6499e3df3769081cd1cb.apk, e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8.apk, e696766abcc6e35ca39a6d6bd1145a7297993f69c2179fc94c84a62519e8b84f.apk, e7aa84c2b3ac31d3a948f0431cdbf7b28116fffb157b8e99e8efe455c92dd661.apk, e8f780e2835e2a072b45219823b8c018a09c4971c754e10c264eac9eb04b884d.apk, e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf.apk, e9b41fd64d8702f974e63374a03ad914b6f1b24e8ddd96c29ff14ce81713676f.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, f0d43f00ccae66633aa086433b402435d0a99c2f910e2c6122abc48e35b8cc3f.apk, f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk, f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2.apk, f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738.apk, f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65.apk, f8081269cf465c7e7c75e078cd1e8005e6c7091168a235d9d161801a4f31641a.apk, f81d01e7361d276658306125e375453244f28d9ecca6c855e48e6fab88826267.apk, f902a8c4de97bd168839457fb1a3e89149c3e44d8eacbbab070d969ad655ee07.apk, f99486a60b7f8ae9ba5cf991d422954466017dfc4020ca7563655e9ebc8713f7.apk, faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee.apk, faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a.apk, fb505c8301b579bff83e77bbd9038cb583a1f207f88a04986a646ad0f9b04d09.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44"
      hash2 = "01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0"
      hash3 = "0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e"
      hash4 = "04e4acc8cd2a66f77260ebcfbe40646192ff452d5f9bbe54e0acbd0cabc3cfbc"
      hash5 = "05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a"
      hash6 = "0596a76e6772acb911c1a556ad86943224873411fba4383abade25300078ed32"
      hash7 = "08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c"
      hash8 = "090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90ba268"
      hash9 = "091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d96241620a5"
      hash10 = "0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169"
      hash11 = "0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd"
      hash12 = "0f9fe82c6594fe331e59cf0268bc402f9e31141a3fd5e5dd99596d28563c5e9b"
      hash13 = "0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072"
      hash14 = "1099eede57e825fa5158b33f01559dc76e6d67e2fca37b97f76e7d3aa9a4208a"
      hash15 = "11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415"
      hash16 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash17 = "12cb6136d2d325563b5079c138eeac2bc4ee4af3373718ba1c79c47a6121829e"
      hash18 = "134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138"
      hash19 = "1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea"
      hash20 = "13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52"
      hash21 = "1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90"
      hash22 = "174deed18377e5280413a2015ebe2041fd8b4276a6599754299cf05cea0718d5"
      hash23 = "17a68e32e5d8398c93790abe9b117c472557b54ccdcfccfdddb3b7f783ca31b3"
      hash24 = "185a01ec24938cd5a9af4fd66a0814e8bfaf2e1ff8cfa2396a30c3e4f6e66b98"
      hash25 = "19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c20271e62"
      hash26 = "1b5ff50963c6e99dfb521e6db624df9f83f21f06430ce9d8f3cd0de735cbe22a"
      hash27 = "1bf9c16cb7c1faae7fa99a57c5d091cbd1e6d5f3c0d79693a3b0990a8b58367d"
      hash28 = "1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c"
      hash29 = "1d9bdb35234b01d219fd28c47a47bbaa6c9033e2b1f35b07f10cf09eaed00254"
      hash30 = "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
      hash31 = "1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9"
      hash32 = "21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e494fe"
      hash33 = "22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b"
      hash34 = "238eeea51b2d53ff08b3129fe6d6be75a13c12090e4063a1455fad614054d4b3"
      hash35 = "23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61"
      hash36 = "246bdb0a9e7698e37ec7b906551ceed302d0445c9572bb3cdc02a68862fd2d2a"
      hash37 = "25fdf72cb393901eb605d6eaea86fe67483a25295651e2423b9e50d5bfc62111"
      hash38 = "269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471eed36"
      hash39 = "27b8eeb5d1b46e1afa170b998830fe0958f08a2a9dfe7130df607c86ad42fb33"
      hash40 = "29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896"
      hash41 = "2b7e044edadb6932c251f2169da0a777bf553a549a263c5c8a0cf9d888cee704"
      hash42 = "2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0"
      hash43 = "2d0fd4ea41c4e17cf94577c126ae271555b544f388baca69112cd3a488572be1"
      hash44 = "2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1"
      hash45 = "2f451d9cfda5d91b2063a62ed5ad482cd733e899b9ee39ee8bd332b518b3b865"
      hash46 = "2f595b306756f39b0d525b19d5f5c1d50a5e6761ea049a63a390ec3e6709a2ba"
      hash47 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash48 = "31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b"
      hash49 = "3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089"
      hash50 = "33c3f43852f6ecadef74aef2dbb0d5a1215aa3cb23e4aaf76f202beed3aa8703"
      hash51 = "34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45"
      hash52 = "3616fd6004678159e531fb7e5a173b333c08bd0097aa1f6a4e9f503db4a9999a"
      hash53 = "392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d"
      hash54 = "39c97fad655efc5aa4bc3703695b80e9807b14050fe9c8785cd047d3f3051668"
      hash55 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash56 = "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
      hash57 = "3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5dce6"
      hash58 = "3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd"
      hash59 = "3d8da22674ee343bd02296a4351e90198ffc786f8541747e42cdcf3438f16b3e"
      hash60 = "3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec"
      hash61 = "3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c"
      hash62 = "41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2"
      hash63 = "41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7"
      hash64 = "43996d454961143bad870d9b94a3d00912f7c29b76371244ac59423595ae0860"
      hash65 = "446800befecf9179f9aca09dd88331dee0e745b199db39a9b0113f4ee886ca34"
      hash66 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash67 = "469b13cac1eb859da7ba4b597270f047b11815bfff9c4ad3faa5617c07a6c3e0"
      hash68 = "48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce"
      hash69 = "4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951"
      hash70 = "4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f"
      hash71 = "4a899a3b0fd61937ce8555cb0da53daf72dadc7dd299c63e90b4a203e5a14db1"
      hash72 = "4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290"
      hash73 = "4af08f08377457cb04e280615fc8647870f9b20ad763e1bd060731605d8a0c07"
      hash74 = "4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088"
      hash75 = "4bdf7226644876c09e6091127260593a4f7af3b78d148b56004eb1be09bdf4b8"
      hash76 = "4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7"
      hash77 = "50990c1178790239445d4dea570e4affeca6efbb01a91cbf4af4498a0477dd2e"
      hash78 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash79 = "557c02b5e9ca8103e6ad5413df1b447fae5c9ce086a0b5330bf9c79a578585df"
      hash80 = "563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b"
      hash81 = "57151572cf361d49ead0235eef7cad3827f4711120f3397e746a660aa9c6250b"
      hash82 = "57a0a81eebdf6c1e0a5ab0489165f167856712121b86959f0c34ce5c24014266"
      hash83 = "59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f"
      hash84 = "5a8d4eabd009a75ecc04f3f06489d393f082f963b406d0d3e8acbea568281c5f"
      hash85 = "5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8"
      hash86 = "5cb94ba3236bd4fa89bad460687cc2f1e80a890f5a093e954ea2704c1950c1f3"
      hash87 = "5dff60862aea80d5da616400359ae170f2d9ef9d76a745417f4facff72cd4c17"
      hash88 = "5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a"
      hash89 = "5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8"
      hash90 = "64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3"
      hash91 = "64b4f8c86ea5ef925da573e7667ca93d32f4fb27fd6a702f5e99ccc4d087f612"
      hash92 = "6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3"
      hash93 = "6564e7362b89d453173884e35d96ff5ce1de7ecbad102b0f5450300418b5de9b"
      hash94 = "657881e96def3e69a401f79c678edff27c3db4db74ba802fb8989ae466f73cc9"
      hash95 = "65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf"
      hash96 = "6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22"
      hash97 = "6b0c56540499051ab350a31f417b99859da7ed7286b9e77503711c6aabafbe03"
      hash98 = "6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8"
      hash99 = "6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa8255405"
      hash100 = "6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd"
      hash101 = "6dd19edd60ed2025afc6b661e85f146c925f2137e51ae49c5d1dce955ac43aaf"
      hash102 = "6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738"
      hash103 = "73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4"
      hash104 = "73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a"
      hash105 = "752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e40ab"
      hash106 = "75cd6f164dee674a18edc5154ef0d48633eb581b73d77aef047af0a5856420cc"
      hash107 = "7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570"
      hash108 = "77c54058a2bb45219e6ee860430f5ea8ce8e6ed2e58fba05f0d9bf74ffb7b4ef"
      hash109 = "78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b"
      hash110 = "7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144"
      hash111 = "79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826fdd3"
      hash112 = "7b40e010ae6556b159eaaba4f0989bd57cc510c388215f2d89580cc3379ae33c"
      hash113 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
      hash114 = "7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf26527b7"
      hash115 = "807d8ffb7975d525386036b10563485033155f62d4355a83e372b08b370c3850"
      hash116 = "8166dfba7fd0b4ad44c8bc91cc0e98fa06b8912e3fca2093900eb58ba79d22d4"
      hash117 = "8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552"
      hash118 = "83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025"
      hash119 = "857d9e064fe567da2b5f42b49787d05d0238f34ddc2890a826d80d8f012f7e8d"
      hash120 = "8613f7b6df514d53aa419355b0a3e8d032b8448bd45296d4158b848998015e3d"
      hash121 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash122 = "8c4f8053881899f844a2e6dea8ce119124acac2b34750a47650e368c27bf7a3b"
      hash123 = "8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af"
      hash124 = "90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a"
      hash125 = "9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e0ece"
      hash126 = "994869cacc3615cde8d4196cdfe1e2877f0e1328ff32a292963ffd0983b450fa"
      hash127 = "9aff583b812a3979394ffcd23f616d561a0eda4002f2e2a4b42ea5ba3efdbfaf"
      hash128 = "9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5"
      hash129 = "9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d"
      hash130 = "9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d"
      hash131 = "9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3bb5d1"
      hash132 = "9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c"
      hash133 = "9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90"
      hash134 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
      hash135 = "9e7d743c341329104a12cfbcf53cc19a9b16c4ec1a874f8d4b42b33e9a68c1f8"
      hash136 = "9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b3306"
      hash137 = "9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6"
      hash138 = "a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5"
      hash139 = "a2c509d0b0fcee3bc503bd12986da2d29c74ebcd37abb1af8988f7f26382663d"
      hash140 = "a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2"
      hash141 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash142 = "a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa"
      hash143 = "a8030b195f685a2c1b3a5de807f769d38f87efff8bab8c5bfce5a6fabedcc477"
      hash144 = "a8062f50057c4d8be86c50b411addafa7429b451420b3aaeb1ec6f04aef18957"
      hash145 = "a81b801522a1c72be91aefffa09b00256fad4ee9d47bb8d79b018b442ab4e78b"
      hash146 = "aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8"
      hash147 = "aab9cf77aca821c3f2930315c2afd140ff12441f0d8f0cb0d45927ef7af43ed5"
      hash148 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash149 = "ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de"
      hash150 = "adefc2f666aa936763b18300444995e1d2a4c1950ef00577de7a88381b825c1f"
      hash151 = "afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4"
      hash152 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
      hash153 = "b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e"
      hash154 = "b1a8941063751656e11bbc6ab44d348cd6795d51bfc890424595c4ac76e52013"
      hash155 = "b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99"
      hash156 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash157 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash158 = "b50dfd257f1cfda6f67d269571f5e9b251c7f34d54c7f7d865b9d6bed89a49bb"
      hash159 = "b8fa21bbd5261f2308a168c1f43b197220c0d37bdda0c4a1464be085a9f85300"
      hash160 = "ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33"
      hash161 = "bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6"
      hash162 = "bc5ecb77e8aee510a380108013e073f0d0f3b41bd9ba2169bcb8eb85b405347f"
      hash163 = "bc74da49cf58d85b8ce8a49d2ac0fed574ef1634e67d92ef75440d7b24d0a3e4"
      hash164 = "bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7"
      hash165 = "bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0"
      hash166 = "bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de"
      hash167 = "c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14"
      hash168 = "c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9"
      hash169 = "c585e3cbaa19ff4934e07f77f447c87a94f21793f9ff35301e1689849d796745"
      hash170 = "c659454dd6ed62bc7a0c9e0455297e41ba57b0b7935a826150c1f8c0db6f89d2"
      hash171 = "c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64"
      hash172 = "c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d"
      hash173 = "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
      hash174 = "ca6271b212c627dd6e4372827a0fb316023fa35210cab7249d634379af6d649c"
      hash175 = "cadcce6d4088c72fd0779d59d00f5753eaab585a263e3c92374df29ae767ac15"
      hash176 = "cb147e7ce69723523f604da875d78ca4738e5f416d2297910ee179a5067e79fe"
      hash177 = "cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c"
      hash178 = "ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9"
      hash179 = "ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642"
      hash180 = "cfd656e0d18e1ed7064941197e6504a4b1cdcd3bc6476389dca71237dd839284"
      hash181 = "d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af"
      hash182 = "d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3"
      hash183 = "d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd"
      hash184 = "d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2"
      hash185 = "d3c63ecb3a95272a043b3e0ab792a70738c867ba18e896c455d9c39d32fff4d3"
      hash186 = "d3fc5ffdd9a68a3063b1c8ff15334238dd39a63b9c93ec9f337bdd5f5357046a"
      hash187 = "d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372"
      hash188 = "d566c64a41faf573349cf2c0ecb00f68dbe8b90bc1968d3317d3a20667ddad63"
      hash189 = "d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5"
      hash190 = "d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe"
      hash191 = "d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d"
      hash192 = "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
      hash193 = "dd0919967c57cdabdf8b5bc9c643bb0d250fe935476aa4944544b22132d5163d"
      hash194 = "decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8"
      hash195 = "e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3"
      hash196 = "e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938"
      hash197 = "e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75"
      hash198 = "e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b"
      hash199 = "e4aa98c1beee901871fd8a78b37b21ef886e507e65fc6499e3df3769081cd1cb"
      hash200 = "e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8"
      hash201 = "e696766abcc6e35ca39a6d6bd1145a7297993f69c2179fc94c84a62519e8b84f"
      hash202 = "e7aa84c2b3ac31d3a948f0431cdbf7b28116fffb157b8e99e8efe455c92dd661"
      hash203 = "e8f780e2835e2a072b45219823b8c018a09c4971c754e10c264eac9eb04b884d"
      hash204 = "e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf"
      hash205 = "e9b41fd64d8702f974e63374a03ad914b6f1b24e8ddd96c29ff14ce81713676f"
      hash206 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash207 = "f0d43f00ccae66633aa086433b402435d0a99c2f910e2c6122abc48e35b8cc3f"
      hash208 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
      hash209 = "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
      hash210 = "f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738"
      hash211 = "f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65"
      hash212 = "f8081269cf465c7e7c75e078cd1e8005e6c7091168a235d9d161801a4f31641a"
      hash213 = "f81d01e7361d276658306125e375453244f28d9ecca6c855e48e6fab88826267"
      hash214 = "f902a8c4de97bd168839457fb1a3e89149c3e44d8eacbbab070d969ad655ee07"
      hash215 = "f99486a60b7f8ae9ba5cf991d422954466017dfc4020ca7563655e9ebc8713f7"
      hash216 = "faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee"
      hash217 = "faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a"
      hash218 = "fb505c8301b579bff83e77bbd9038cb583a1f207f88a04986a646ad0f9b04d09"
      hash219 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
      hash220 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "Passer au mode de saisie Texte" fullword ascii
      $s2 = "Passa al mese precedente" fullword ascii
      $s3 = "Passer au mois suivant" fullword ascii
      $s4 = "Passa al mese successivo" fullword ascii
      $s5 = "Passer au mois pr" fullword ascii
      $s6 = "ndra till f" fullword ascii
      $s7 = "ndra till n" fullword ascii
      $s8 = "s anterior" fullword ascii
      $s9 = " !Byt till text som inmatningsl" fullword ascii
      $s10 = "\"\"Skift til input-tilstand for tekst" fullword ascii
      $s11 = "()Kalo te modaliteti i \"Hyrjes s" fullword ascii
      $s12 = "Mudar para o m" fullword ascii
      $s13 = "Skift til n" fullword ascii
      $s14 = "Skift til forrige m" fullword ascii
      $s15 = "**Lumipat sa pamamaraan ng pag-input ng text" fullword ascii
      $s16 = "Beralih kepada mod input teks" fullword ascii
      $s17 = "$%Byt till kalender som inmatningsl" fullword ascii
      $s18 = "!!Beralih kepada mod input kalendar" fullword ascii
      $s19 = "%%Skift til input-tilstand for kalender" fullword ascii
      $s20 = "+,Kalo te modaliteti i \"Hyrjes s" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cff_60 {
   meta:
      description = "apk - from files 1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cffb.apk, 5c15f4808ad986ff87797ff8d01120a5016d6182f08788db73072bec43d53814.apk, 6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e.apk, cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c.apk, db11d9b51d90d23e5769d5f6dd738adad56acff41555698446926804d5396962.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cffb"
      hash2 = "5c15f4808ad986ff87797ff8d01120a5016d6182f08788db73072bec43d53814"
      hash3 = "6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e"
      hash4 = "cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c"
      hash5 = "db11d9b51d90d23e5769d5f6dd738adad56acff41555698446926804d5396962"
   strings:
      $s1 = "> should not exceed maximal supported number of threads 2097150" fullword ascii
      $s2 = "Module with the Main dispatcher is missing. Add dependency providing the Main dispatcher, e.g. 'kotlinx-coroutines-android' and " ascii
      $s3 = "Failure(" fullword ascii
      $s4 = "7EmojiCompat font provider not available on this device." fullword ascii
      $s5 = "ensure it has the same version as 'kotlinx-coroutines-core'" fullword ascii
      $s6 = "}, running workers queues = " fullword ascii
      $s7 = "System property '" fullword ascii
      $s8 = " fetchFonts failed (empty result)" fullword ascii
      $s9 = "\", Control State {created workers= " fullword ascii
      $s10 = "provider not found" fullword ascii
      $s11 = ". Cycle detected." fullword ascii
      $s12 = "4 should be greater than or equals to core pool size " fullword ascii
      $s13 = " The main looper is not available" fullword ascii
      $s14 = "!invalid metadata codepoint length" fullword ascii
      $s15 = "Idle worker keep alive time " fullword ascii
      $s16 = "[Pool Size {core = " fullword ascii
      $s17 = "-Expected positive parallelism level, but got " fullword ascii
      $s18 = ", dormant = " fullword ascii
      $s19 = "4Exception while trying to handle coroutine exception" fullword ascii
      $s20 = " should be at least 1" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb4_61 {
   meta:
      description = "apk - from files 017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44.apk, 01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0.apk, 0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e.apk, 04e4acc8cd2a66f77260ebcfbe40646192ff452d5f9bbe54e0acbd0cabc3cfbc.apk, 0596a76e6772acb911c1a556ad86943224873411fba4383abade25300078ed32.apk, 08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c.apk, 0f9fe82c6594fe331e59cf0268bc402f9e31141a3fd5e5dd99596d28563c5e9b.apk, 1099eede57e825fa5158b33f01559dc76e6d67e2fca37b97f76e7d3aa9a4208a.apk, 11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 12cb6136d2d325563b5079c138eeac2bc4ee4af3373718ba1c79c47a6121829e.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea.apk, 174deed18377e5280413a2015ebe2041fd8b4276a6599754299cf05cea0718d5.apk, 17a68e32e5d8398c93790abe9b117c472557b54ccdcfccfdddb3b7f783ca31b3.apk, 185a01ec24938cd5a9af4fd66a0814e8bfaf2e1ff8cfa2396a30c3e4f6e66b98.apk, 1b5ff50963c6e99dfb521e6db624df9f83f21f06430ce9d8f3cd0de735cbe22a.apk, 1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c.apk, 1d9bdb35234b01d219fd28c47a47bbaa6c9033e2b1f35b07f10cf09eaed00254.apk, 1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0.apk, 238eeea51b2d53ff08b3129fe6d6be75a13c12090e4063a1455fad614054d4b3.apk, 23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61.apk, 246bdb0a9e7698e37ec7b906551ceed302d0445c9572bb3cdc02a68862fd2d2a.apk, 25fdf72cb393901eb605d6eaea86fe67483a25295651e2423b9e50d5bfc62111.apk, 29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896.apk, 2b7e044edadb6932c251f2169da0a777bf553a549a263c5c8a0cf9d888cee704.apk, 2d0fd4ea41c4e17cf94577c126ae271555b544f388baca69112cd3a488572be1.apk, 2f451d9cfda5d91b2063a62ed5ad482cd733e899b9ee39ee8bd332b518b3b865.apk, 2f595b306756f39b0d525b19d5f5c1d50a5e6761ea049a63a390ec3e6709a2ba.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b.apk, 3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089.apk, 33c3f43852f6ecadef74aef2dbb0d5a1215aa3cb23e4aaf76f202beed3aa8703.apk, 34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45.apk, 3616fd6004678159e531fb7e5a173b333c08bd0097aa1f6a4e9f503db4a9999a.apk, 392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d.apk, 39c97fad655efc5aa4bc3703695b80e9807b14050fe9c8785cd047d3f3051668.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647.apk, 3d8da22674ee343bd02296a4351e90198ffc786f8541747e42cdcf3438f16b3e.apk, 3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec.apk, 41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2.apk, 41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7.apk, 43996d454961143bad870d9b94a3d00912f7c29b76371244ac59423595ae0860.apk, 446800befecf9179f9aca09dd88331dee0e745b199db39a9b0113f4ee886ca34.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 469b13cac1eb859da7ba4b597270f047b11815bfff9c4ad3faa5617c07a6c3e0.apk, 48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce.apk, 4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f.apk, 4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290.apk, 4af08f08377457cb04e280615fc8647870f9b20ad763e1bd060731605d8a0c07.apk, 4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088.apk, 4bdf7226644876c09e6091127260593a4f7af3b78d148b56004eb1be09bdf4b8.apk, 4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7.apk, 50990c1178790239445d4dea570e4affeca6efbb01a91cbf4af4498a0477dd2e.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 557c02b5e9ca8103e6ad5413df1b447fae5c9ce086a0b5330bf9c79a578585df.apk, 563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b.apk, 57151572cf361d49ead0235eef7cad3827f4711120f3397e746a660aa9c6250b.apk, 57a0a81eebdf6c1e0a5ab0489165f167856712121b86959f0c34ce5c24014266.apk, 5a8d4eabd009a75ecc04f3f06489d393f082f963b406d0d3e8acbea568281c5f.apk, 5cb94ba3236bd4fa89bad460687cc2f1e80a890f5a093e954ea2704c1950c1f3.apk, 5dff60862aea80d5da616400359ae170f2d9ef9d76a745417f4facff72cd4c17.apk, 5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 64b4f8c86ea5ef925da573e7667ca93d32f4fb27fd6a702f5e99ccc4d087f612.apk, 6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3.apk, 6564e7362b89d453173884e35d96ff5ce1de7ecbad102b0f5450300418b5de9b.apk, 657881e96def3e69a401f79c678edff27c3db4db74ba802fb8989ae466f73cc9.apk, 65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf.apk, 6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8.apk, 6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd.apk, 6dd19edd60ed2025afc6b661e85f146c925f2137e51ae49c5d1dce955ac43aaf.apk, 6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738.apk, 73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4.apk, 73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a.apk, 75cd6f164dee674a18edc5154ef0d48633eb581b73d77aef047af0a5856420cc.apk, 77c54058a2bb45219e6ee860430f5ea8ce8e6ed2e58fba05f0d9bf74ffb7b4ef.apk, 7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144.apk, 7b40e010ae6556b159eaaba4f0989bd57cc510c388215f2d89580cc3379ae33c.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, 807d8ffb7975d525386036b10563485033155f62d4355a83e372b08b370c3850.apk, 8166dfba7fd0b4ad44c8bc91cc0e98fa06b8912e3fca2093900eb58ba79d22d4.apk, 8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552.apk, 83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025.apk, 857d9e064fe567da2b5f42b49787d05d0238f34ddc2890a826d80d8f012f7e8d.apk, 8613f7b6df514d53aa419355b0a3e8d032b8448bd45296d4158b848998015e3d.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c4f8053881899f844a2e6dea8ce119124acac2b34750a47650e368c27bf7a3b.apk, 90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a.apk, 994869cacc3615cde8d4196cdfe1e2877f0e1328ff32a292963ffd0983b450fa.apk, 9aff583b812a3979394ffcd23f616d561a0eda4002f2e2a4b42ea5ba3efdbfaf.apk, 9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5.apk, 9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d.apk, 9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c.apk, 9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90.apk, 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk, 9e7d743c341329104a12cfbcf53cc19a9b16c4ec1a874f8d4b42b33e9a68c1f8.apk, 9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6.apk, a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5.apk, a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa.apk, a8030b195f685a2c1b3a5de807f769d38f87efff8bab8c5bfce5a6fabedcc477.apk, a8062f50057c4d8be86c50b411addafa7429b451420b3aaeb1ec6f04aef18957.apk, a81b801522a1c72be91aefffa09b00256fad4ee9d47bb8d79b018b442ab4e78b.apk, aab9cf77aca821c3f2930315c2afd140ff12441f0d8f0cb0d45927ef7af43ed5.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de.apk, adefc2f666aa936763b18300444995e1d2a4c1950ef00577de7a88381b825c1f.apk, b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk, b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, b50dfd257f1cfda6f67d269571f5e9b251c7f34d54c7f7d865b9d6bed89a49bb.apk, b8fa21bbd5261f2308a168c1f43b197220c0d37bdda0c4a1464be085a9f85300.apk, bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6.apk, bc5ecb77e8aee510a380108013e073f0d0f3b41bd9ba2169bcb8eb85b405347f.apk, bc74da49cf58d85b8ce8a49d2ac0fed574ef1634e67d92ef75440d7b24d0a3e4.apk, bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7.apk, c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14.apk, c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9.apk, c585e3cbaa19ff4934e07f77f447c87a94f21793f9ff35301e1689849d796745.apk, c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64.apk, c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk, cadcce6d4088c72fd0779d59d00f5753eaab585a263e3c92374df29ae767ac15.apk, ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642.apk, cfd656e0d18e1ed7064941197e6504a4b1cdcd3bc6476389dca71237dd839284.apk, d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af.apk, d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3.apk, d3c63ecb3a95272a043b3e0ab792a70738c867ba18e896c455d9c39d32fff4d3.apk, d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372.apk, d566c64a41faf573349cf2c0ecb00f68dbe8b90bc1968d3317d3a20667ddad63.apk, d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe.apk, d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d.apk, d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38.apk, dd0919967c57cdabdf8b5bc9c643bb0d250fe935476aa4944544b22132d5163d.apk, decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8.apk, e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3.apk, e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938.apk, e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75.apk, e4aa98c1beee901871fd8a78b37b21ef886e507e65fc6499e3df3769081cd1cb.apk, e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8.apk, e696766abcc6e35ca39a6d6bd1145a7297993f69c2179fc94c84a62519e8b84f.apk, e7aa84c2b3ac31d3a948f0431cdbf7b28116fffb157b8e99e8efe455c92dd661.apk, e8f780e2835e2a072b45219823b8c018a09c4971c754e10c264eac9eb04b884d.apk, e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf.apk, e9b41fd64d8702f974e63374a03ad914b6f1b24e8ddd96c29ff14ce81713676f.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, f0d43f00ccae66633aa086433b402435d0a99c2f910e2c6122abc48e35b8cc3f.apk, f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk, f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2.apk, f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738.apk, f8081269cf465c7e7c75e078cd1e8005e6c7091168a235d9d161801a4f31641a.apk, f81d01e7361d276658306125e375453244f28d9ecca6c855e48e6fab88826267.apk, f902a8c4de97bd168839457fb1a3e89149c3e44d8eacbbab070d969ad655ee07.apk, f99486a60b7f8ae9ba5cf991d422954466017dfc4020ca7563655e9ebc8713f7.apk, faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee.apk, fb505c8301b579bff83e77bbd9038cb583a1f207f88a04986a646ad0f9b04d09.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44"
      hash2 = "01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0"
      hash3 = "0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e"
      hash4 = "04e4acc8cd2a66f77260ebcfbe40646192ff452d5f9bbe54e0acbd0cabc3cfbc"
      hash5 = "0596a76e6772acb911c1a556ad86943224873411fba4383abade25300078ed32"
      hash6 = "08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c"
      hash7 = "0f9fe82c6594fe331e59cf0268bc402f9e31141a3fd5e5dd99596d28563c5e9b"
      hash8 = "1099eede57e825fa5158b33f01559dc76e6d67e2fca37b97f76e7d3aa9a4208a"
      hash9 = "11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415"
      hash10 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash11 = "12cb6136d2d325563b5079c138eeac2bc4ee4af3373718ba1c79c47a6121829e"
      hash12 = "134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138"
      hash13 = "1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea"
      hash14 = "174deed18377e5280413a2015ebe2041fd8b4276a6599754299cf05cea0718d5"
      hash15 = "17a68e32e5d8398c93790abe9b117c472557b54ccdcfccfdddb3b7f783ca31b3"
      hash16 = "185a01ec24938cd5a9af4fd66a0814e8bfaf2e1ff8cfa2396a30c3e4f6e66b98"
      hash17 = "1b5ff50963c6e99dfb521e6db624df9f83f21f06430ce9d8f3cd0de735cbe22a"
      hash18 = "1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c"
      hash19 = "1d9bdb35234b01d219fd28c47a47bbaa6c9033e2b1f35b07f10cf09eaed00254"
      hash20 = "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
      hash21 = "238eeea51b2d53ff08b3129fe6d6be75a13c12090e4063a1455fad614054d4b3"
      hash22 = "23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61"
      hash23 = "246bdb0a9e7698e37ec7b906551ceed302d0445c9572bb3cdc02a68862fd2d2a"
      hash24 = "25fdf72cb393901eb605d6eaea86fe67483a25295651e2423b9e50d5bfc62111"
      hash25 = "29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896"
      hash26 = "2b7e044edadb6932c251f2169da0a777bf553a549a263c5c8a0cf9d888cee704"
      hash27 = "2d0fd4ea41c4e17cf94577c126ae271555b544f388baca69112cd3a488572be1"
      hash28 = "2f451d9cfda5d91b2063a62ed5ad482cd733e899b9ee39ee8bd332b518b3b865"
      hash29 = "2f595b306756f39b0d525b19d5f5c1d50a5e6761ea049a63a390ec3e6709a2ba"
      hash30 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash31 = "31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b"
      hash32 = "3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089"
      hash33 = "33c3f43852f6ecadef74aef2dbb0d5a1215aa3cb23e4aaf76f202beed3aa8703"
      hash34 = "34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45"
      hash35 = "3616fd6004678159e531fb7e5a173b333c08bd0097aa1f6a4e9f503db4a9999a"
      hash36 = "392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d"
      hash37 = "39c97fad655efc5aa4bc3703695b80e9807b14050fe9c8785cd047d3f3051668"
      hash38 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash39 = "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
      hash40 = "3d8da22674ee343bd02296a4351e90198ffc786f8541747e42cdcf3438f16b3e"
      hash41 = "3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec"
      hash42 = "41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2"
      hash43 = "41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7"
      hash44 = "43996d454961143bad870d9b94a3d00912f7c29b76371244ac59423595ae0860"
      hash45 = "446800befecf9179f9aca09dd88331dee0e745b199db39a9b0113f4ee886ca34"
      hash46 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash47 = "469b13cac1eb859da7ba4b597270f047b11815bfff9c4ad3faa5617c07a6c3e0"
      hash48 = "48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce"
      hash49 = "4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f"
      hash50 = "4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290"
      hash51 = "4af08f08377457cb04e280615fc8647870f9b20ad763e1bd060731605d8a0c07"
      hash52 = "4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088"
      hash53 = "4bdf7226644876c09e6091127260593a4f7af3b78d148b56004eb1be09bdf4b8"
      hash54 = "4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7"
      hash55 = "50990c1178790239445d4dea570e4affeca6efbb01a91cbf4af4498a0477dd2e"
      hash56 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash57 = "557c02b5e9ca8103e6ad5413df1b447fae5c9ce086a0b5330bf9c79a578585df"
      hash58 = "563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b"
      hash59 = "57151572cf361d49ead0235eef7cad3827f4711120f3397e746a660aa9c6250b"
      hash60 = "57a0a81eebdf6c1e0a5ab0489165f167856712121b86959f0c34ce5c24014266"
      hash61 = "5a8d4eabd009a75ecc04f3f06489d393f082f963b406d0d3e8acbea568281c5f"
      hash62 = "5cb94ba3236bd4fa89bad460687cc2f1e80a890f5a093e954ea2704c1950c1f3"
      hash63 = "5dff60862aea80d5da616400359ae170f2d9ef9d76a745417f4facff72cd4c17"
      hash64 = "5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a"
      hash65 = "5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8"
      hash66 = "64b4f8c86ea5ef925da573e7667ca93d32f4fb27fd6a702f5e99ccc4d087f612"
      hash67 = "6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3"
      hash68 = "6564e7362b89d453173884e35d96ff5ce1de7ecbad102b0f5450300418b5de9b"
      hash69 = "657881e96def3e69a401f79c678edff27c3db4db74ba802fb8989ae466f73cc9"
      hash70 = "65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf"
      hash71 = "6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8"
      hash72 = "6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd"
      hash73 = "6dd19edd60ed2025afc6b661e85f146c925f2137e51ae49c5d1dce955ac43aaf"
      hash74 = "6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738"
      hash75 = "73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4"
      hash76 = "73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a"
      hash77 = "75cd6f164dee674a18edc5154ef0d48633eb581b73d77aef047af0a5856420cc"
      hash78 = "77c54058a2bb45219e6ee860430f5ea8ce8e6ed2e58fba05f0d9bf74ffb7b4ef"
      hash79 = "7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144"
      hash80 = "7b40e010ae6556b159eaaba4f0989bd57cc510c388215f2d89580cc3379ae33c"
      hash81 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
      hash82 = "807d8ffb7975d525386036b10563485033155f62d4355a83e372b08b370c3850"
      hash83 = "8166dfba7fd0b4ad44c8bc91cc0e98fa06b8912e3fca2093900eb58ba79d22d4"
      hash84 = "8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552"
      hash85 = "83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025"
      hash86 = "857d9e064fe567da2b5f42b49787d05d0238f34ddc2890a826d80d8f012f7e8d"
      hash87 = "8613f7b6df514d53aa419355b0a3e8d032b8448bd45296d4158b848998015e3d"
      hash88 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash89 = "8c4f8053881899f844a2e6dea8ce119124acac2b34750a47650e368c27bf7a3b"
      hash90 = "90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a"
      hash91 = "994869cacc3615cde8d4196cdfe1e2877f0e1328ff32a292963ffd0983b450fa"
      hash92 = "9aff583b812a3979394ffcd23f616d561a0eda4002f2e2a4b42ea5ba3efdbfaf"
      hash93 = "9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5"
      hash94 = "9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d"
      hash95 = "9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c"
      hash96 = "9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90"
      hash97 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
      hash98 = "9e7d743c341329104a12cfbcf53cc19a9b16c4ec1a874f8d4b42b33e9a68c1f8"
      hash99 = "9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6"
      hash100 = "a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5"
      hash101 = "a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2"
      hash102 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash103 = "a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa"
      hash104 = "a8030b195f685a2c1b3a5de807f769d38f87efff8bab8c5bfce5a6fabedcc477"
      hash105 = "a8062f50057c4d8be86c50b411addafa7429b451420b3aaeb1ec6f04aef18957"
      hash106 = "a81b801522a1c72be91aefffa09b00256fad4ee9d47bb8d79b018b442ab4e78b"
      hash107 = "aab9cf77aca821c3f2930315c2afd140ff12441f0d8f0cb0d45927ef7af43ed5"
      hash108 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash109 = "ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de"
      hash110 = "adefc2f666aa936763b18300444995e1d2a4c1950ef00577de7a88381b825c1f"
      hash111 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
      hash112 = "b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99"
      hash113 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash114 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash115 = "b50dfd257f1cfda6f67d269571f5e9b251c7f34d54c7f7d865b9d6bed89a49bb"
      hash116 = "b8fa21bbd5261f2308a168c1f43b197220c0d37bdda0c4a1464be085a9f85300"
      hash117 = "bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6"
      hash118 = "bc5ecb77e8aee510a380108013e073f0d0f3b41bd9ba2169bcb8eb85b405347f"
      hash119 = "bc74da49cf58d85b8ce8a49d2ac0fed574ef1634e67d92ef75440d7b24d0a3e4"
      hash120 = "bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7"
      hash121 = "c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14"
      hash122 = "c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9"
      hash123 = "c585e3cbaa19ff4934e07f77f447c87a94f21793f9ff35301e1689849d796745"
      hash124 = "c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64"
      hash125 = "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
      hash126 = "cadcce6d4088c72fd0779d59d00f5753eaab585a263e3c92374df29ae767ac15"
      hash127 = "ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642"
      hash128 = "cfd656e0d18e1ed7064941197e6504a4b1cdcd3bc6476389dca71237dd839284"
      hash129 = "d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af"
      hash130 = "d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3"
      hash131 = "d3c63ecb3a95272a043b3e0ab792a70738c867ba18e896c455d9c39d32fff4d3"
      hash132 = "d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372"
      hash133 = "d566c64a41faf573349cf2c0ecb00f68dbe8b90bc1968d3317d3a20667ddad63"
      hash134 = "d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe"
      hash135 = "d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d"
      hash136 = "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
      hash137 = "dd0919967c57cdabdf8b5bc9c643bb0d250fe935476aa4944544b22132d5163d"
      hash138 = "decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8"
      hash139 = "e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3"
      hash140 = "e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938"
      hash141 = "e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75"
      hash142 = "e4aa98c1beee901871fd8a78b37b21ef886e507e65fc6499e3df3769081cd1cb"
      hash143 = "e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8"
      hash144 = "e696766abcc6e35ca39a6d6bd1145a7297993f69c2179fc94c84a62519e8b84f"
      hash145 = "e7aa84c2b3ac31d3a948f0431cdbf7b28116fffb157b8e99e8efe455c92dd661"
      hash146 = "e8f780e2835e2a072b45219823b8c018a09c4971c754e10c264eac9eb04b884d"
      hash147 = "e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf"
      hash148 = "e9b41fd64d8702f974e63374a03ad914b6f1b24e8ddd96c29ff14ce81713676f"
      hash149 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash150 = "f0d43f00ccae66633aa086433b402435d0a99c2f910e2c6122abc48e35b8cc3f"
      hash151 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
      hash152 = "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
      hash153 = "f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738"
      hash154 = "f8081269cf465c7e7c75e078cd1e8005e6c7091168a235d9d161801a4f31641a"
      hash155 = "f81d01e7361d276658306125e375453244f28d9ecca6c855e48e6fab88826267"
      hash156 = "f902a8c4de97bd168839457fb1a3e89149c3e44d8eacbbab070d969ad655ee07"
      hash157 = "f99486a60b7f8ae9ba5cf991d422954466017dfc4020ca7563655e9ebc8713f7"
      hash158 = "faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee"
      hash159 = "fb505c8301b579bff83e77bbd9038cb583a1f207f88a04986a646ad0f9b04d09"
      hash160 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
      hash161 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "lama tarixi" fullword ascii
      $s2 = "etni datum" fullword ascii
      $s3 = "Data selectat" fullword ascii
      $s4 = "Gekose datum" fullword ascii
      $s5 = "Kies datum" fullword ascii
      $s6 = "Data di fine" fullword ascii
      $s7 = "Data e fillimit" fullword ascii
      $s8 = "Data e zgjedhur" fullword ascii
      $s9 = "Pabaigos data" fullword ascii
      $s10 = " actual: %1$s" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _0172d6141fc03c2e152caf35dce6c90cc0cec4f303de270f09136b93f1e99bc_62 {
   meta:
      description = "apk - from files 0172d6141fc03c2e152caf35dce6c90cc0cec4f303de270f09136b93f1e99bcf.apk, 02944967154e515f87bb411641edd9931ea6b4a4088ab73efe87cbe7b9d5b592.apk, 09eb87493c014406a0d83996a8b1894da5257fd6166921878a9bbd42b1e9390e.apk, 0bd64f2bfd3b3d5427adfeb8bb72d2522d9758c80995bcf09a60c8631e0f1d34.apk, 108ca43c5a62640b5e3d71df33c00549c46634c1109c1ac6690df89fbc4211fd.apk, 118f0bba26f3fd4f1c535ba9117ec80eda9945e6a7fe8af7511178ac60a77170.apk, 129ee4f3dd5ecd07a3f815616300a2adcd6702239c1ae3e31a3d61cf7913c4cb.apk, 1495da4ff455fceb8fc73f38b75d65be3435c649b2aaf014124e9c58da930c37.apk, 14c47030d8220e682a1ec80c87d56c5bacf7a38abdf30df9bb532a85851259af.apk, 14ebed0d51768cfa90ace0d74ce17763a7accd1c526976e5b4609156521e7ca8.apk, 15839ac050341de16481e5e425f5f1a791547651d4aeda398217f823f0f321f9.apk, 1aeae34c264bbfbd4eed6d92a94ac788bfb9b050a54032fde811402d63f18bf8.apk, 1c64737419a6cb1729ae42f232461a723a8b8b1e67fbcba32cacd151fcbaba7d.apk, 1d15f0700a2dda228394bf37ad20ad2bd88c7813d6aca0199a6b40c704f80bc1.apk, 21b6b9c7262fe39d2f2ce49115c9c22f50d3e5b0b083a0f8c1ddd776c369ffd3.apk, 2308afb58c08eec15d0ad9048e751eeca001bd17a2106484803c45ef351af752.apk, 272248f64722ef49413a6f3c339aecb78785546c1c65b9c2897e3915bd91be28.apk, 2b6d20746ed11f62b35a7c29d1912de18248e9e10247c29a6ee0929877a57d77.apk, 2b7af4d5fd24ce4daaa2aada2db239d0ec17510d17a55beb214b70b8edc54fb6.apk, 33d2ea973f861bb7c46397c4e0f9aedc37ef10fb8ab2f4090f35a335d86ef0b2.apk, 372607bbdf97e253a8970876a4bb1c9419859a9b0bd9d421750f17c28995017e.apk, 37aea8c8ed8ea55d23da37d997e82e6cc34bf80bce891378be7543adf6678ea1.apk, 3dc24332f897ef758c38e4959624606236a3c63a1ba2e0b3d268ed6ce40b5c1a.apk, 46326534553b3c5307d4c0347c12919b93b2699f9670593885cf52182a28180f.apk, 498b9dc568e47cd06099fbedb479e78556a7cd30a8cad589b003a77e09de2c52.apk, 49b40786a01886ad8e962bd74e5d2e3ede8472de5cabe7b060284c54e5941182.apk, 4f621122c29871e1d0464421c2abfc01036f27f1d3523b8b4d143f82a2c08c5a.apk, 4ff07276c35f5e9c6f8ec37deaa0bc4f01f033a4e717ef8ce76ef371e8eee29b.apk, 5294f5ff8d2190157b8a2c0863ee395764ad520ae397929f60756a6c810fb9ff.apk, 5a6eda5a51b8330bea4f79652927cefbb2aed857d60f71ea3b14e63db06dc1ad.apk, 5d4972e846d795b495d70fa054821c53678d2335b6879b4bf9a9116e101a8826.apk, 638fc69f1d2945d4a575154d019e503ef6e00a67317666fea3655262b474643a.apk, 678ee44afb89903d3199378f2e6d9de0b4167c23e548bf4d7f863e1545ef912e.apk, 6ace30c2832b85ef093f86c13b9920a528dc86c3d561148a7a641f2d2b80db00.apk, 6db892bb9921633415b73799421a00cea90d089960dcf2734f8722fb1bbfe210.apk, 73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a.apk, 7775d8411c836f15e525320a984c90941127e7101ded1af8bb5b1234d50ebaf5.apk, 79f56edc1bb111c0323762dc0c25d9c50c9a62ec4dedc2cf2e0c2010e518b6b4.apk, 7a449a292f2498734e22aa7f43857fda0d34f81910ffb8a85cd679eb9c3694de.apk, 7ad0ae4494675c5412b1abc00a527d8b568debc01b148d2d16e7a55367e28eb8.apk, 810926f89430144fd258ed4a95f1d77215f657a4e7dac2ce0c410bcffbdca99e.apk, 814cd115a30c5b4bfbb276524774a3ad2396e7f346c9f083983131b3e08200d2.apk, 828a8180829f047507ad1052f14633cd9d4908037cf49c1d8b3c9799acce170d.apk, 84c5571ee75850514c0b09aa0f77b9ab5ea0b79bc8622371e3223810e67cd406.apk, 8adce5e888db7e35a5731de025715c95961b459481edd19a2e7fb040c1218063.apk, 94b6a8c5a5a9569b073f56ccaf56bded9dd3f00ce619369142ce16a492f9ac9e.apk, 97936d7873348f905d119dd9399261374aae494296e1b5fb3df521ef3cc76405.apk, 99b3c2ceeeb0c5866baddd1eb0e53556514708a74b58324f4a742207ef781680.apk, 9aafbc143c66661609f34c483a85015f30f7da2a38f375d9e10c8eeadc6cb5da.apk, 9c1cc79b801e8d632bdb73517588e9e7626cf22643263f038c20cc42dfd0f922.apk, a140917183b3a1e51dca80b5a0f87dc5dc6eba21bc4d53d328f9ba24312d6075.apk, aa3b976475e375e92f09bf4b06db50693ad42dd7c0abfcbfd598f3e9d46f0744.apk, ab1363201d0897ab7c55dceb1f8664a58ac65fe4aee3c9600c5d7659f8ae58a9.apk, acf2d29c8c65ee2fe57445e672fbee01fa240b0039b66ea507f110468c6c8210.apk, b1c3a8818024ee86480bb83ea405ba2d9f96ea279e5cf9df19b3d3cb934ec42d.apk, b38d466dbb28feb20f4f8cc9d9a3b2204bf38e487e7cc5f057a756dd5f40b7c6.apk, b3c86606b1410cc558acef06d55c2a03d41ad85cb2b04e904640f58b23185db3.apk, b600af54745d2cf6529d048e701b579368af19ff69a08b5ae26d1f0d0a706047.apk, b8f7304f293daad9beb862a068f837a4426792656a3a2695b614dbe9ac920b3e.apk, b9fb2177e55ad47b2df74ff642bd3ee5058d392c3e2e272b93bec263aa30eeef.apk, ba4523e699d017cff49e9f725b6a5c279654dd8d91a55e68a4786f5d46ea771e.apk, c5ab0adaedf391a395387df33b0bf6854f1ccc9c5da937915ea86b5eec6e6103.apk, cc93d01b68b59314a789c5355ac70b8e6965b9f64bb331b0337aac9d2da8aede.apk, cec6fc6496687b177b14d6699d82a18840b528bff5543dfb6e23c0849f3c8de2.apk, cf3ac7265631cf1cb96f617addee7b4100f4e582e215a7e4a190c9730c49044f.apk, d19edfbc70474a76b2dd6d8d0e844404f7b4c364c2278a6a668159e83310598a.apk, d9c47a7d7e42402c3ce2dd191ea09e9f7e29b1ee8d78d9aec0a47ed7b4bcdb80.apk, deb2cc80a190e73d81758b738bac4e8f0f116b587b07d65ddc8b668f0b89b0bb.apk, e21f8722ab3d3557e7b0dda0faca39c517bbf0afd84bf4bbdc92687c9bd58aae.apk, e7bc41c6d3677ef941dfc8eb4b571435623dab1e8c0681b6253c37725844b268.apk, ef94a5ecaf100b9c9102b101b98f8c01fae9ea9304e5b8fbf6097beec59ad885.apk, f3fe34702fefe9dfb8bf50f2d2ca475a8a3150f3dee3c07b09994947d540b3a1.apk, fca04c73ad8c4626e4026faaac63fbe6c2a6404952e1c53d657b696480789553.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "0172d6141fc03c2e152caf35dce6c90cc0cec4f303de270f09136b93f1e99bcf"
      hash2 = "02944967154e515f87bb411641edd9931ea6b4a4088ab73efe87cbe7b9d5b592"
      hash3 = "09eb87493c014406a0d83996a8b1894da5257fd6166921878a9bbd42b1e9390e"
      hash4 = "0bd64f2bfd3b3d5427adfeb8bb72d2522d9758c80995bcf09a60c8631e0f1d34"
      hash5 = "108ca43c5a62640b5e3d71df33c00549c46634c1109c1ac6690df89fbc4211fd"
      hash6 = "118f0bba26f3fd4f1c535ba9117ec80eda9945e6a7fe8af7511178ac60a77170"
      hash7 = "129ee4f3dd5ecd07a3f815616300a2adcd6702239c1ae3e31a3d61cf7913c4cb"
      hash8 = "1495da4ff455fceb8fc73f38b75d65be3435c649b2aaf014124e9c58da930c37"
      hash9 = "14c47030d8220e682a1ec80c87d56c5bacf7a38abdf30df9bb532a85851259af"
      hash10 = "14ebed0d51768cfa90ace0d74ce17763a7accd1c526976e5b4609156521e7ca8"
      hash11 = "15839ac050341de16481e5e425f5f1a791547651d4aeda398217f823f0f321f9"
      hash12 = "1aeae34c264bbfbd4eed6d92a94ac788bfb9b050a54032fde811402d63f18bf8"
      hash13 = "1c64737419a6cb1729ae42f232461a723a8b8b1e67fbcba32cacd151fcbaba7d"
      hash14 = "1d15f0700a2dda228394bf37ad20ad2bd88c7813d6aca0199a6b40c704f80bc1"
      hash15 = "21b6b9c7262fe39d2f2ce49115c9c22f50d3e5b0b083a0f8c1ddd776c369ffd3"
      hash16 = "2308afb58c08eec15d0ad9048e751eeca001bd17a2106484803c45ef351af752"
      hash17 = "272248f64722ef49413a6f3c339aecb78785546c1c65b9c2897e3915bd91be28"
      hash18 = "2b6d20746ed11f62b35a7c29d1912de18248e9e10247c29a6ee0929877a57d77"
      hash19 = "2b7af4d5fd24ce4daaa2aada2db239d0ec17510d17a55beb214b70b8edc54fb6"
      hash20 = "33d2ea973f861bb7c46397c4e0f9aedc37ef10fb8ab2f4090f35a335d86ef0b2"
      hash21 = "372607bbdf97e253a8970876a4bb1c9419859a9b0bd9d421750f17c28995017e"
      hash22 = "37aea8c8ed8ea55d23da37d997e82e6cc34bf80bce891378be7543adf6678ea1"
      hash23 = "3dc24332f897ef758c38e4959624606236a3c63a1ba2e0b3d268ed6ce40b5c1a"
      hash24 = "46326534553b3c5307d4c0347c12919b93b2699f9670593885cf52182a28180f"
      hash25 = "498b9dc568e47cd06099fbedb479e78556a7cd30a8cad589b003a77e09de2c52"
      hash26 = "49b40786a01886ad8e962bd74e5d2e3ede8472de5cabe7b060284c54e5941182"
      hash27 = "4f621122c29871e1d0464421c2abfc01036f27f1d3523b8b4d143f82a2c08c5a"
      hash28 = "4ff07276c35f5e9c6f8ec37deaa0bc4f01f033a4e717ef8ce76ef371e8eee29b"
      hash29 = "5294f5ff8d2190157b8a2c0863ee395764ad520ae397929f60756a6c810fb9ff"
      hash30 = "5a6eda5a51b8330bea4f79652927cefbb2aed857d60f71ea3b14e63db06dc1ad"
      hash31 = "5d4972e846d795b495d70fa054821c53678d2335b6879b4bf9a9116e101a8826"
      hash32 = "638fc69f1d2945d4a575154d019e503ef6e00a67317666fea3655262b474643a"
      hash33 = "678ee44afb89903d3199378f2e6d9de0b4167c23e548bf4d7f863e1545ef912e"
      hash34 = "6ace30c2832b85ef093f86c13b9920a528dc86c3d561148a7a641f2d2b80db00"
      hash35 = "6db892bb9921633415b73799421a00cea90d089960dcf2734f8722fb1bbfe210"
      hash36 = "73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a"
      hash37 = "7775d8411c836f15e525320a984c90941127e7101ded1af8bb5b1234d50ebaf5"
      hash38 = "79f56edc1bb111c0323762dc0c25d9c50c9a62ec4dedc2cf2e0c2010e518b6b4"
      hash39 = "7a449a292f2498734e22aa7f43857fda0d34f81910ffb8a85cd679eb9c3694de"
      hash40 = "7ad0ae4494675c5412b1abc00a527d8b568debc01b148d2d16e7a55367e28eb8"
      hash41 = "810926f89430144fd258ed4a95f1d77215f657a4e7dac2ce0c410bcffbdca99e"
      hash42 = "814cd115a30c5b4bfbb276524774a3ad2396e7f346c9f083983131b3e08200d2"
      hash43 = "828a8180829f047507ad1052f14633cd9d4908037cf49c1d8b3c9799acce170d"
      hash44 = "84c5571ee75850514c0b09aa0f77b9ab5ea0b79bc8622371e3223810e67cd406"
      hash45 = "8adce5e888db7e35a5731de025715c95961b459481edd19a2e7fb040c1218063"
      hash46 = "94b6a8c5a5a9569b073f56ccaf56bded9dd3f00ce619369142ce16a492f9ac9e"
      hash47 = "97936d7873348f905d119dd9399261374aae494296e1b5fb3df521ef3cc76405"
      hash48 = "99b3c2ceeeb0c5866baddd1eb0e53556514708a74b58324f4a742207ef781680"
      hash49 = "9aafbc143c66661609f34c483a85015f30f7da2a38f375d9e10c8eeadc6cb5da"
      hash50 = "9c1cc79b801e8d632bdb73517588e9e7626cf22643263f038c20cc42dfd0f922"
      hash51 = "a140917183b3a1e51dca80b5a0f87dc5dc6eba21bc4d53d328f9ba24312d6075"
      hash52 = "aa3b976475e375e92f09bf4b06db50693ad42dd7c0abfcbfd598f3e9d46f0744"
      hash53 = "ab1363201d0897ab7c55dceb1f8664a58ac65fe4aee3c9600c5d7659f8ae58a9"
      hash54 = "acf2d29c8c65ee2fe57445e672fbee01fa240b0039b66ea507f110468c6c8210"
      hash55 = "b1c3a8818024ee86480bb83ea405ba2d9f96ea279e5cf9df19b3d3cb934ec42d"
      hash56 = "b38d466dbb28feb20f4f8cc9d9a3b2204bf38e487e7cc5f057a756dd5f40b7c6"
      hash57 = "b3c86606b1410cc558acef06d55c2a03d41ad85cb2b04e904640f58b23185db3"
      hash58 = "b600af54745d2cf6529d048e701b579368af19ff69a08b5ae26d1f0d0a706047"
      hash59 = "b8f7304f293daad9beb862a068f837a4426792656a3a2695b614dbe9ac920b3e"
      hash60 = "b9fb2177e55ad47b2df74ff642bd3ee5058d392c3e2e272b93bec263aa30eeef"
      hash61 = "ba4523e699d017cff49e9f725b6a5c279654dd8d91a55e68a4786f5d46ea771e"
      hash62 = "c5ab0adaedf391a395387df33b0bf6854f1ccc9c5da937915ea86b5eec6e6103"
      hash63 = "cc93d01b68b59314a789c5355ac70b8e6965b9f64bb331b0337aac9d2da8aede"
      hash64 = "cec6fc6496687b177b14d6699d82a18840b528bff5543dfb6e23c0849f3c8de2"
      hash65 = "cf3ac7265631cf1cb96f617addee7b4100f4e582e215a7e4a190c9730c49044f"
      hash66 = "d19edfbc70474a76b2dd6d8d0e844404f7b4c364c2278a6a668159e83310598a"
      hash67 = "d9c47a7d7e42402c3ce2dd191ea09e9f7e29b1ee8d78d9aec0a47ed7b4bcdb80"
      hash68 = "deb2cc80a190e73d81758b738bac4e8f0f116b587b07d65ddc8b668f0b89b0bb"
      hash69 = "e21f8722ab3d3557e7b0dda0faca39c517bbf0afd84bf4bbdc92687c9bd58aae"
      hash70 = "e7bc41c6d3677ef941dfc8eb4b571435623dab1e8c0681b6253c37725844b268"
      hash71 = "ef94a5ecaf100b9c9102b101b98f8c01fae9ea9304e5b8fbf6097beec59ad885"
      hash72 = "f3fe34702fefe9dfb8bf50f2d2ca475a8a3150f3dee3c07b09994947d540b3a1"
      hash73 = "fca04c73ad8c4626e4026faaac63fbe6c2a6404952e1c53d657b696480789553"
   strings:
      $s1 = "Higit pang mga opsyon" fullword ascii
      $s2 = "Pasirinkti program" fullword ascii
      $s3 = "Visa startsidan" fullword ascii
      $s4 = "Dastur tanlang" fullword ascii
      $s5 = "Vai alla home page" fullword ascii
      $s6 = "Navigasi naik" fullword ascii
      $s7 = "Mag-navigate patungo sa home" fullword ascii
      $s8 = "Navigiraj prema gore" fullword ascii
      $s9 = "lectionnez une application" fullword ascii
      $s10 = "Vai in alto" fullword ascii
      $s11 = "Navega cap a dalt" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _3aea0345c88f069d3a079c82571086adafb585137a86e277f4e5c9fb1b2190e_63 {
   meta:
      description = "apk - from files 3aea0345c88f069d3a079c82571086adafb585137a86e277f4e5c9fb1b2190e6.apk, b3c86606b1410cc558acef06d55c2a03d41ad85cb2b04e904640f58b23185db3.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "3aea0345c88f069d3a079c82571086adafb585137a86e277f4e5c9fb1b2190e6"
      hash2 = "b3c86606b1410cc558acef06d55c2a03d41ad85cb2b04e904640f58b23185db3"
   strings:
      $s1 = "\\\\The content view in SmartRefreshLayout is empty. Do you forget to add it in xml layout file?" fullword ascii
      $s2 = "``%s falsify area," fullword ascii
      $s3 = "'Last Update' M-d HH:mm" fullword ascii
      $s4 = "Refresh Failed" fullword ascii
      $s5 = " Represents the height[%.1fdp] of drag at run time," fullword ascii
      $s6 = "Pull Down To Refresh" fullword ascii
      $s7 = "Refresh Success" fullword ascii
      $s8 = "Wait For Loading" fullword ascii
      $s9 = "Release To Load More" fullword ascii
      $s10 = "Release To Second Floor" fullword ascii
      $s11 = " It does not show anything." fullword ascii
      $s12 = "Wait For Refreshing" fullword ascii
      $s13 = "Pull Up To Load More" fullword ascii
      $s14 = "Load Success" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb4_64 {
   meta:
      description = "apk - from files 017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44.apk, 08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea.apk, 1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0.apk, 23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61.apk, 29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089.apk, 34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45.apk, 392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce.apk, 4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f.apk, 4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290.apk, 4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7.apk, 563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b.apk, 5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a.apk, 6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3.apk, 6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8.apk, 73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4.apk, 73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a.apk, 7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a.apk, 9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5.apk, 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk, 9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6.apk, a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de.apk, b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk, b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14.apk, c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9.apk, c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk, ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642.apk, d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af.apk, d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3.apk, d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38.apk, e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3.apk, e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938.apk, e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75.apk, e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk, f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44"
      hash2 = "08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c"
      hash3 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash4 = "1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea"
      hash5 = "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
      hash6 = "23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61"
      hash7 = "29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896"
      hash8 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash9 = "3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089"
      hash10 = "34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45"
      hash11 = "392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d"
      hash12 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash13 = "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
      hash14 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash15 = "48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce"
      hash16 = "4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f"
      hash17 = "4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290"
      hash18 = "4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7"
      hash19 = "563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b"
      hash20 = "5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a"
      hash21 = "6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3"
      hash22 = "6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8"
      hash23 = "73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4"
      hash24 = "73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a"
      hash25 = "7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144"
      hash26 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
      hash27 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash28 = "90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a"
      hash29 = "9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5"
      hash30 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
      hash31 = "9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6"
      hash32 = "a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2"
      hash33 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash34 = "ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de"
      hash35 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
      hash36 = "b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99"
      hash37 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash38 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash39 = "c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14"
      hash40 = "c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9"
      hash41 = "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
      hash42 = "ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642"
      hash43 = "d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af"
      hash44 = "d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3"
      hash45 = "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
      hash46 = "e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3"
      hash47 = "e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938"
      hash48 = "e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75"
      hash49 = "e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf"
      hash50 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash51 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
      hash52 = "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
      hash53 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "n de data de inicio: %1$s - Selecci" fullword ascii
      $s2 = "r data zah" fullword ascii
      $s3 = "lection de la date de fin" fullword ascii
      $s4 = "hech qanday" fullword ascii
      $s5 = "n de data de finalizaci" fullword ascii
      $s6 = "r data ukon" fullword ascii
      $s7 = "o da data de in" fullword ascii
      $s8 = " de la data de finalitzaci" fullword ascii
      $s9 = "lama tarixi se" fullword ascii
      $s10 = " wybrana data zako" fullword ascii
      $s11 = "lection de la date de d" fullword ascii
      $s12 = " Date de fin s" fullword ascii
      $s13 = "?DWybrana data rozpocz" fullword ascii
      $s14 = " de la data d'inici: %1$s " fullword ascii
      $s15 = "cio: %1$s. Sele" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb4_65 {
   meta:
      description = "apk - from files 017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44.apk, 05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a.apk, 08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c.apk, 090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90ba268.apk, 091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d96241620a5.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd.apk, 0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea.apk, 13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52.apk, 1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90.apk, 19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c20271e62.apk, 1bf9c16cb7c1faae7fa99a57c5d091cbd1e6d5f3c0d79693a3b0990a8b58367d.apk, 1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0.apk, 1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9.apk, 21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e494fe.apk, 22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b.apk, 23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61.apk, 269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471eed36.apk, 27b8eeb5d1b46e1afa170b998830fe0958f08a2a9dfe7130df607c86ad42fb33.apk, 29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896.apk, 2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0.apk, 2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089.apk, 34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45.apk, 392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647.apk, 3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5dce6.apk, 3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd.apk, 3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce.apk, 4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951.apk, 4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f.apk, 4a899a3b0fd61937ce8555cb0da53daf72dadc7dd299c63e90b4a203e5a14db1.apk, 4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290.apk, 4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b.apk, 59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f.apk, 5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8.apk, 5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a.apk, 64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3.apk, 6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3.apk, 6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22.apk, 6b0c56540499051ab350a31f417b99859da7ed7286b9e77503711c6aabafbe03.apk, 6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8.apk, 6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa8255405.apk, 73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4.apk, 73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a.apk, 752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e40ab.apk, 7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570.apk, 78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b.apk, 7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144.apk, 79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826fdd3.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, 7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf26527b7.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a.apk, 9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e0ece.apk, 9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5.apk, 9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d.apk, 9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3bb5d1.apk, 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk, 9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b3306.apk, 9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6.apk, a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8.apk, ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de.apk, afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4.apk, b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk, b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e.apk, b1a8941063751656e11bbc6ab44d348cd6795d51bfc890424595c4ac76e52013.apk, b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de.apk, c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14.apk, c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9.apk, c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d.apk, c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk, ca6271b212c627dd6e4372827a0fb316023fa35210cab7249d634379af6d649c.apk, cb147e7ce69723523f604da875d78ca4738e5f416d2297910ee179a5067e79fe.apk, cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c.apk, ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9.apk, ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642.apk, d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af.apk, d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3.apk, d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd.apk, d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2.apk, d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5.apk, d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38.apk, e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3.apk, e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938.apk, e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75.apk, e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b.apk, e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk, f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2.apk, f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65.apk, faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44"
      hash2 = "05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a"
      hash3 = "08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c"
      hash4 = "090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90ba268"
      hash5 = "091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d96241620a5"
      hash6 = "0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169"
      hash7 = "0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd"
      hash8 = "0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072"
      hash9 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash10 = "1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea"
      hash11 = "13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52"
      hash12 = "1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90"
      hash13 = "19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c20271e62"
      hash14 = "1bf9c16cb7c1faae7fa99a57c5d091cbd1e6d5f3c0d79693a3b0990a8b58367d"
      hash15 = "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
      hash16 = "1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9"
      hash17 = "21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e494fe"
      hash18 = "22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b"
      hash19 = "23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61"
      hash20 = "269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471eed36"
      hash21 = "27b8eeb5d1b46e1afa170b998830fe0958f08a2a9dfe7130df607c86ad42fb33"
      hash22 = "29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896"
      hash23 = "2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0"
      hash24 = "2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1"
      hash25 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash26 = "3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089"
      hash27 = "34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45"
      hash28 = "392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d"
      hash29 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash30 = "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
      hash31 = "3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5dce6"
      hash32 = "3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd"
      hash33 = "3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c"
      hash34 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash35 = "48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce"
      hash36 = "4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951"
      hash37 = "4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f"
      hash38 = "4a899a3b0fd61937ce8555cb0da53daf72dadc7dd299c63e90b4a203e5a14db1"
      hash39 = "4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290"
      hash40 = "4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7"
      hash41 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash42 = "563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b"
      hash43 = "59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f"
      hash44 = "5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8"
      hash45 = "5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a"
      hash46 = "64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3"
      hash47 = "6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3"
      hash48 = "6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22"
      hash49 = "6b0c56540499051ab350a31f417b99859da7ed7286b9e77503711c6aabafbe03"
      hash50 = "6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8"
      hash51 = "6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa8255405"
      hash52 = "73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4"
      hash53 = "73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a"
      hash54 = "752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e40ab"
      hash55 = "7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570"
      hash56 = "78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b"
      hash57 = "7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144"
      hash58 = "79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826fdd3"
      hash59 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
      hash60 = "7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf26527b7"
      hash61 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash62 = "8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af"
      hash63 = "90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a"
      hash64 = "9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e0ece"
      hash65 = "9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5"
      hash66 = "9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d"
      hash67 = "9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3bb5d1"
      hash68 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
      hash69 = "9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b3306"
      hash70 = "9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6"
      hash71 = "a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2"
      hash72 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash73 = "aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8"
      hash74 = "ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de"
      hash75 = "afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4"
      hash76 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
      hash77 = "b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e"
      hash78 = "b1a8941063751656e11bbc6ab44d348cd6795d51bfc890424595c4ac76e52013"
      hash79 = "b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99"
      hash80 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash81 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash82 = "ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33"
      hash83 = "bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0"
      hash84 = "bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de"
      hash85 = "c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14"
      hash86 = "c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9"
      hash87 = "c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d"
      hash88 = "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
      hash89 = "ca6271b212c627dd6e4372827a0fb316023fa35210cab7249d634379af6d649c"
      hash90 = "cb147e7ce69723523f604da875d78ca4738e5f416d2297910ee179a5067e79fe"
      hash91 = "cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c"
      hash92 = "ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9"
      hash93 = "ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642"
      hash94 = "d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af"
      hash95 = "d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3"
      hash96 = "d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd"
      hash97 = "d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2"
      hash98 = "d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5"
      hash99 = "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
      hash100 = "e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3"
      hash101 = "e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938"
      hash102 = "e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75"
      hash103 = "e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b"
      hash104 = "e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf"
      hash105 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash106 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
      hash107 = "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
      hash108 = "f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65"
      hash109 = "faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a"
      hash110 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = " vista de ano" fullword ascii
      $s2 = "Ir ao ano actual (%1$d)" fullword ascii
      $s3 = "o actual (%1$d)" fullword ascii
      $s4 = "Navegue para o ano %1$d" fullword ascii
      $s5 = "i la anul actual %1$d" fullword ascii
      $s6 = "Idite na aktuelnu godinu %1$d" fullword ascii
      $s7 = "o actual, %1$d" fullword ascii
      $s8 = "Vai all'anno corrente %1$d" fullword ascii
      $s9 = "Ir para o ano %1$d" fullword ascii
      $s10 = "Idite na godinu %1$d" fullword ascii
      $s11 = "Navegar para o ano atual %1$d" fullword ascii
      $s12 = "Mine aastasse %1$d" fullword ascii
      $s13 = "Ir para o ano atual %1$d" fullword ascii
      $s14 = "!\"Navigera till innevarande " fullword ascii
      $s15 = " vista de calendario" fullword ascii
      $s16 = "Navega fins a l'any actual %1$d" fullword ascii
      $s17 = "area Calendar" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c_66 {
   meta:
      description = "apk - from files 01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0.apk, 0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e.apk, 11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c.apk, 31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b.apk, 3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec.apk, 41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2.apk, 41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7.apk, 4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf.apk, 6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd.apk, 6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738.apk, 8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552.apk, 83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025.apk, 9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d.apk, 9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c.apk, 9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90.apk, a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5.apk, a2c509d0b0fcee3bc503bd12986da2d29c74ebcd37abb1af8988f7f26382663d.apk, a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6.apk, bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7.apk, c659454dd6ed62bc7a0c9e0455297e41ba57b0b7935a826150c1f8c0db6f89d2.apk, d3fc5ffdd9a68a3063b1c8ff15334238dd39a63b9c93ec9f337bdd5f5357046a.apk, d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372.apk, d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe.apk, d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d.apk, decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8.apk, e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8.apk, f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738.apk, faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0"
      hash2 = "0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e"
      hash3 = "11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415"
      hash4 = "134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138"
      hash5 = "1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c"
      hash6 = "31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b"
      hash7 = "3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec"
      hash8 = "41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2"
      hash9 = "41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7"
      hash10 = "4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088"
      hash11 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash12 = "5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8"
      hash13 = "65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf"
      hash14 = "6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd"
      hash15 = "6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738"
      hash16 = "8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552"
      hash17 = "83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025"
      hash18 = "9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d"
      hash19 = "9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c"
      hash20 = "9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90"
      hash21 = "a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5"
      hash22 = "a2c509d0b0fcee3bc503bd12986da2d29c74ebcd37abb1af8988f7f26382663d"
      hash23 = "a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa"
      hash24 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash25 = "bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6"
      hash26 = "bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7"
      hash27 = "c659454dd6ed62bc7a0c9e0455297e41ba57b0b7935a826150c1f8c0db6f89d2"
      hash28 = "d3fc5ffdd9a68a3063b1c8ff15334238dd39a63b9c93ec9f337bdd5f5357046a"
      hash29 = "d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372"
      hash30 = "d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe"
      hash31 = "d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d"
      hash32 = "decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8"
      hash33 = "e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8"
      hash34 = "f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738"
      hash35 = "faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee"
      hash36 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
   strings:
      $s1 = "*-Touchez pour passer " fullword ascii
      $s2 = "%%I-tap para lumipat sa pagpili ng taon" fullword ascii
      $s3 = "*,Touchez pour passer " fullword ascii
      $s4 = "%%I-tap para lumipat sa pagpili ng araw" fullword ascii
      $s5 = "gtos uz gada atlas" fullword ascii
      $s6 = "r genom att trycka" fullword ascii
      $s7 = "gtos uz dienas atlas" fullword ascii
      $s8 = "lja en dag genom att trycka" fullword ascii
      $s9 = "lection de jour" fullword ascii
      $s10 = "!\"Appuyer pour s" fullword ascii
      $s11 = "Navegue para o ano %1$s" fullword ascii
      $s12 = "Ir para o ano %1$s" fullword ascii
      $s13 = "#%Appuyer pour s" fullword ascii
      $s14 = "*,Byt till att v" fullword ascii
      $s15 = "*+Byt till att v" fullword ascii
      $s16 = ",.Toque para alternar para a sele" fullword ascii
      $s17 = "&(Toque para mudar para a sele" fullword ascii
      $s18 = "lection d'ann" fullword ascii
      $s19 = "Idite na godinu %1$s" fullword ascii
      $s20 = "Mine aastasse %1$s" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _58cc948bd809292143e604c3e03735c9517f94b37dd35299ca5e81d7b902d62_67 {
   meta:
      description = "apk - from files 58cc948bd809292143e604c3e03735c9517f94b37dd35299ca5e81d7b902d620.apk, 9904bb103fae65ab3dd712f6b9ff361d3f3cb3a4cc814b69f0af3e2f1a837ecd.apk, c5544517f1be9d5a721a951d906b26f9ad11adf4a06c3660a75e89f07dabb8aa.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "58cc948bd809292143e604c3e03735c9517f94b37dd35299ca5e81d7b902d620"
      hash2 = "9904bb103fae65ab3dd712f6b9ff361d3f3cb3a4cc814b69f0af3e2f1a837ecd"
      hash3 = "c5544517f1be9d5a721a951d906b26f9ad11adf4a06c3660a75e89f07dabb8aa"
   strings:
      $s1 = ",Login failed. Please check your credentials." fullword ascii
      $s2 = "*Incorrect login details. Please try again." fullword ascii
      $s3 = "Login required" fullword ascii
      $s4 = "/To reset your password, please contact support." fullword ascii
      $s5 = ")Account recovery is temporarily disabled." fullword ascii
      $s6 = "3Authentication failed. Incorrect login or password." fullword ascii
      $s7 = "DPassword reset is currently unavailable. Contact your administrator." fullword ascii
      $s8 = ";Please contact your IT administrator for password recovery." fullword ascii
      $s9 = ",Authorization error. Please try again later." fullword ascii
      $s10 = "Enter your credentials" fullword ascii
      $s11 = "Trouble logging in?" fullword ascii
      $s12 = "&Invalid credentials. Please try again." fullword ascii
      $s13 = "SOC 2 Compliant" fullword ascii
      $s14 = "#Access denied. Invalid credentials." fullword ascii
      $s15 = "Your username" fullword ascii
      $s16 = "Company access code" fullword ascii
      $s17 = "Member access portal" fullword ascii
      $s18 = "Access your account" fullword ascii
      $s19 = "Enterprise Security" fullword ascii
      $s20 = "Remember me" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb4_68 {
   meta:
      description = "apk - from files 017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44.apk, 05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a.apk, 08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c.apk, 090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90ba268.apk, 091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d96241620a5.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd.apk, 0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52.apk, 1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90.apk, 19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c20271e62.apk, 1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9.apk, 21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e494fe.apk, 22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b.apk, 23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61.apk, 269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471eed36.apk, 29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896.apk, 2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0.apk, 2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1.apk, 3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089.apk, 34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45.apk, 392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5dce6.apk, 3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd.apk, 3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c.apk, 48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce.apk, 4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951.apk, 4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f.apk, 4a899a3b0fd61937ce8555cb0da53daf72dadc7dd299c63e90b4a203e5a14db1.apk, 4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b.apk, 59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f.apk, 5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8.apk, 5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a.apk, 64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3.apk, 6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3.apk, 6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22.apk, 6b0c56540499051ab350a31f417b99859da7ed7286b9e77503711c6aabafbe03.apk, 6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8.apk, 6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa8255405.apk, 73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4.apk, 752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e40ab.apk, 7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570.apk, 78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b.apk, 7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144.apk, 79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826fdd3.apk, 7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf26527b7.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a.apk, 9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e0ece.apk, 9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5.apk, 9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d.apk, 9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3bb5d1.apk, 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk, 9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b3306.apk, 9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6.apk, a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8.apk, ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de.apk, afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4.apk, b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk, b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33.apk, c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14.apk, c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9.apk, c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk, cb147e7ce69723523f604da875d78ca4738e5f416d2297910ee179a5067e79fe.apk, cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c.apk, ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9.apk, ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642.apk, d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af.apk, d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3.apk, d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd.apk, d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2.apk, d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5.apk, d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38.apk, e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3.apk, e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938.apk, e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75.apk, e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b.apk, e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk, f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65.apk, faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44"
      hash2 = "05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a"
      hash3 = "08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c"
      hash4 = "090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90ba268"
      hash5 = "091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d96241620a5"
      hash6 = "0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169"
      hash7 = "0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd"
      hash8 = "0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072"
      hash9 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash10 = "13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52"
      hash11 = "1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90"
      hash12 = "19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c20271e62"
      hash13 = "1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9"
      hash14 = "21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e494fe"
      hash15 = "22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b"
      hash16 = "23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61"
      hash17 = "269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471eed36"
      hash18 = "29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896"
      hash19 = "2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0"
      hash20 = "2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1"
      hash21 = "3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089"
      hash22 = "34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45"
      hash23 = "392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d"
      hash24 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash25 = "3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5dce6"
      hash26 = "3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd"
      hash27 = "3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c"
      hash28 = "48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce"
      hash29 = "4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951"
      hash30 = "4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f"
      hash31 = "4a899a3b0fd61937ce8555cb0da53daf72dadc7dd299c63e90b4a203e5a14db1"
      hash32 = "4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7"
      hash33 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash34 = "563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b"
      hash35 = "59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f"
      hash36 = "5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8"
      hash37 = "5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a"
      hash38 = "64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3"
      hash39 = "6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3"
      hash40 = "6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22"
      hash41 = "6b0c56540499051ab350a31f417b99859da7ed7286b9e77503711c6aabafbe03"
      hash42 = "6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8"
      hash43 = "6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa8255405"
      hash44 = "73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4"
      hash45 = "752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e40ab"
      hash46 = "7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570"
      hash47 = "78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b"
      hash48 = "7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144"
      hash49 = "79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826fdd3"
      hash50 = "7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf26527b7"
      hash51 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash52 = "8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af"
      hash53 = "90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a"
      hash54 = "9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e0ece"
      hash55 = "9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5"
      hash56 = "9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d"
      hash57 = "9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3bb5d1"
      hash58 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
      hash59 = "9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b3306"
      hash60 = "9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6"
      hash61 = "a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2"
      hash62 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash63 = "aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8"
      hash64 = "ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de"
      hash65 = "afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4"
      hash66 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
      hash67 = "b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e"
      hash68 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash69 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash70 = "ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33"
      hash71 = "c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14"
      hash72 = "c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9"
      hash73 = "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
      hash74 = "cb147e7ce69723523f604da875d78ca4738e5f416d2297910ee179a5067e79fe"
      hash75 = "cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c"
      hash76 = "ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9"
      hash77 = "ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642"
      hash78 = "d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af"
      hash79 = "d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3"
      hash80 = "d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd"
      hash81 = "d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2"
      hash82 = "d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5"
      hash83 = "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
      hash84 = "e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3"
      hash85 = "e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938"
      hash86 = "e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75"
      hash87 = "e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b"
      hash88 = "e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf"
      hash89 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash90 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
      hash91 = "f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65"
      hash92 = "faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a"
      hash93 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "%&Appuyer pour passer " fullword ascii
      $s2 = "*+Toucher pour passer " fullword ascii
      $s3 = "$&Appuyer pour passer " fullword ascii
      $s4 = "')Toucher pour passer " fullword ascii
      $s5 = "r att byta till " fullword ascii
      $s6 = "r att byta till kalendervy" fullword ascii
      $s7 = "\"\"I-tap para lumipat sa view ng taon" fullword ascii
      $s8 = "((I-tap para lumipat sa view ng Kalendaryo" fullword ascii
      $s9 = "$$Toque para mudar para a vista de ano" fullword ascii
      $s10 = ".0Toque para mudar para a visualiza" fullword ascii
      $s11 = "*,Toque para mudar para a visualiza" fullword ascii
      $s12 = "area An" fullword ascii
      $s13 = "//Tik om over te schakelen naar de agendaweergave" fullword ascii
      $s14 = "--Tik om over te schakelen naar de jaarweergave" fullword ascii
      $s15 = "o de agenda" fullword ascii
      $s16 = "'(Presiona para cambiar a la vista de a" fullword ascii
      $s17 = "!\"Tocar para cambiar " fullword ascii
      $s18 = "()Tocar para cambiar " fullword ascii
      $s19 = "(`Calendar " fullword ascii
      $s20 = "+,Toque para mudar para a vista do Calend" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210_69 {
   meta:
      description = "apk - from files 05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a.apk, 0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd.apk, 0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072.apk, 13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52.apk, 22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b.apk, 5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8.apk, 6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22.apk, 9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d.apk, 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk, b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk, b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e.apk, e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b.apk, f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk, f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a"
      hash2 = "0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd"
      hash3 = "0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072"
      hash4 = "13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52"
      hash5 = "22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b"
      hash6 = "5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8"
      hash7 = "6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22"
      hash8 = "9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d"
      hash9 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
      hash10 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
      hash11 = "b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e"
      hash12 = "e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b"
      hash13 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
      hash14 = "f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65"
   strings:
      $s1 = "$$Enter a valid hostname or IP address" fullword ascii
      $s2 = "Server Hostname or IP Address" fullword ascii
      $s3 = "Export config" fullword ascii
      $s4 = "Shared Session Number" fullword ascii
      $s5 = "iiYour device does not support HostCardEmulation and is not supported as Tag emulator in Relay/Replay mode." fullword ascii
      $s6 = "  Enter a two-digit session number" fullword ascii
      $s7 = "Copy config" fullword ascii
      $s8 = "OOA bug in Android 6.0.1 on the Nexus 5X prevents it from reading the hist bytes." fullword ascii
      $s9 = "Enter a valid port number" fullword ascii
      $s10 = "$$Network: Connected, wait for partner" fullword ascii
      $s11 = "Network: Connected to partner" fullword ascii
      $s12 = "Network: Connecting to network" fullword ascii
      $s13 = "Native Hook Enabled" fullword ascii
      $s14 = "$$Your NFC Chip could not be detected." fullword ascii
      $s15 = "WWNative hook could not be found. Cloning and relaying in Tag mode may not work properly." fullword ascii
      $s16 = "Presence Check Interval" fullword ascii
      $s17 = "SSChange the interval for Tags that do not like being presence-checked while relaying" fullword ascii
      $s18 = "Waiting for %1$s" fullword ascii
      $s19 = "!!Enter an interval in milliseconds" fullword ascii
      $s20 = "Network: Partner left" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cff_70 {
   meta:
      description = "apk - from files 1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cffb.apk, 5c15f4808ad986ff87797ff8d01120a5016d6182f08788db73072bec43d53814.apk, a82591b195a32c8ad049ff627367c2a63d67c7f7324e3c335c993a7bbd66477a.apk, db11d9b51d90d23e5769d5f6dd738adad56acff41555698446926804d5396962.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cffb"
      hash2 = "5c15f4808ad986ff87797ff8d01120a5016d6182f08788db73072bec43d53814"
      hash3 = "a82591b195a32c8ad049ff627367c2a63d67c7f7324e3c335c993a7bbd66477a"
      hash4 = "db11d9b51d90d23e5769d5f6dd738adad56acff41555698446926804d5396962"
   strings:
      $s1 = ".Error copying resource contents to temp file: " fullword ascii
      $s2 = "Failed to get visible insets. getViewRootImpl() returned null from the provided view. This means that the view is either not att" ascii
      $s3 = "Failed to get visible insets. getViewRootImpl() returned null from the provided view. This means that the view is either not att" ascii
      $s4 = "2Failed to get visible insets. (Reflection error). " fullword ascii
      $s5 = "4Could not get value from WindowInsets.CONSUMED field" fullword ascii
      $s6 = "Unable to get icon resource" fullword ascii
      $s7 = "-Landroid/text/PrecomputedText$Params$Builder;" fullword ascii
      $s8 = ".Failed to invoke TextView#nullLayouts() method" fullword ascii
      $s9 = "Failed to retrieve TextView#" fullword ascii
      $s10 = "Failed to invoke TextView#" fullword ascii
      $s11 = "OUnable to collect necessary private methods. Fallback to legacy implementation." fullword ascii
      $s12 = "oLifecycleOwner of this LifecycleRegistry is alreadygarbage collected. It is too late to change lifecycle state." fullword ascii
      $s13 = "CFailed to obtain TextDirectionHeuristic, auto size may be incorrect" fullword ascii
      $s14 = "ached or the method has been overridden" fullword ascii
      $s15 = "[getVisibleInsets() should not be called on API >= 30. Use WindowInsets.isVisible() instead." fullword ascii
      $s16 = "#None of the preset sizes is valid: " fullword ascii
      $s17 = "GCould not find method setClipToScreenEnabled() on PopupWindow. Oh well." fullword ascii
      $s18 = "2Could not invoke setEpicenterBounds on PopupWindow" fullword ascii
      $s19 = ",Do not use this function in API 29 or later." fullword ascii
      $s20 = "GCould not find method setEpicenterBounds(Rect) on PopupWindow. Oh well." fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb4_71 {
   meta:
      description = "apk - from files 017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44.apk, 08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea.apk, 1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90.apk, 1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0.apk, 23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61.apk, 29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896.apk, 2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089.apk, 34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45.apk, 392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647.apk, 3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce.apk, 4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f.apk, 4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290.apk, 4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7.apk, 563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b.apk, 5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a.apk, 6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3.apk, 6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8.apk, 73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4.apk, 73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a.apk, 7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570.apk, 7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a.apk, 9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5.apk, 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk, 9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6.apk, a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8.apk, ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de.apk, b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk, b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14.apk, c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9.apk, c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk, ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642.apk, d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af.apk, d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3.apk, d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38.apk, e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3.apk, e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938.apk, e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75.apk, e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk, f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44"
      hash2 = "08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c"
      hash3 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash4 = "1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea"
      hash5 = "1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90"
      hash6 = "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
      hash7 = "23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61"
      hash8 = "29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896"
      hash9 = "2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0"
      hash10 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash11 = "3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089"
      hash12 = "34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45"
      hash13 = "392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d"
      hash14 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash15 = "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
      hash16 = "3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c"
      hash17 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash18 = "48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce"
      hash19 = "4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f"
      hash20 = "4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290"
      hash21 = "4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7"
      hash22 = "563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b"
      hash23 = "5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a"
      hash24 = "6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3"
      hash25 = "6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8"
      hash26 = "73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4"
      hash27 = "73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a"
      hash28 = "7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570"
      hash29 = "7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144"
      hash30 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
      hash31 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash32 = "8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af"
      hash33 = "90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a"
      hash34 = "9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5"
      hash35 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
      hash36 = "9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6"
      hash37 = "a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2"
      hash38 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash39 = "aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8"
      hash40 = "ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de"
      hash41 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
      hash42 = "b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99"
      hash43 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash44 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash45 = "ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33"
      hash46 = "bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0"
      hash47 = "c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14"
      hash48 = "c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9"
      hash49 = "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
      hash50 = "ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642"
      hash51 = "d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af"
      hash52 = "d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3"
      hash53 = "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
      hash54 = "e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3"
      hash55 = "e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938"
      hash56 = "e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75"
      hash57 = "e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf"
      hash58 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash59 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
      hash60 = "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
      hash61 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "ni datum %1$s" fullword ascii
      $s2 = "Data di fine: %1$s" fullword ascii
      $s3 = "Gaur %1$s" fullword ascii
      $s4 = "Pabaigos data %1$s" fullword ascii
      $s5 = "etni datum %1$s" fullword ascii
      $s6 = "Data de fim: %1$s" fullword ascii
      $s7 = "Data e fillimit: %1$s" fullword ascii
      $s8 = "Data d'inici: %1$s" fullword ascii
      $s9 = "ios data %1$s" fullword ascii
      $s10 = "lama tarixi: %1$s" fullword ascii
      $s11 = "Data de inicio: %1$s" fullword ascii
      $s12 = "Data di inizio: %1$s" fullword ascii
      $s13 = "Data e mbarimit: %1$s" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b_72 {
   meta:
      description = "apk - from files 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash2 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash3 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash4 = "bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0"
      hash5 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
      hash6 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "pnij link" fullword ascii
      $s2 = "bn i browser" fullword ascii
      $s3 = "Salin link" fullword ascii
      $s4 = "Partilhar link" fullword ascii
      $s5 = "Buksan sa browser" fullword ascii
      $s6 = "Bagikan link" fullword ascii
      $s7 = "Kopiraj link" fullword ascii
      $s8 = "Kopeeri link" fullword ascii
      $s9 = "Deli link" fullword ascii
      $s10 = "Link delen" fullword ascii
      $s11 = "Ibahagi ang link" fullword ascii
      $s12 = "Buka di browser" fullword ascii
      $s13 = "Dijeli link" fullword ascii
      $s14 = "Link megoszt" fullword ascii
      $s15 = "Link kopi" fullword ascii
      $s16 = "Openen in browser" fullword ascii
      $s17 = "Kopyahin ang link" fullword ascii
      $s18 = "r link" fullword ascii
      $s19 = "Link m" fullword ascii
      $s20 = "Del link" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cff_73 {
   meta:
      description = "apk - from files 1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cffb.apk, 53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee.apk, 5c15f4808ad986ff87797ff8d01120a5016d6182f08788db73072bec43d53814.apk, 6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e.apk, cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c.apk, db11d9b51d90d23e5769d5f6dd738adad56acff41555698446926804d5396962.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cffb"
      hash2 = "53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee"
      hash3 = "5c15f4808ad986ff87797ff8d01120a5016d6182f08788db73072bec43d53814"
      hash4 = "6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e"
      hash5 = "cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c"
      hash6 = "db11d9b51d90d23e5769d5f6dd738adad56acff41555698446926804d5396962"
   strings:
      $s1 = "JSet metadataLoadStrategy to LOAD_STRATEGY_MANUAL to execute manual loading" fullword ascii
      $s2 = "configuration to help improve error message." fullword ascii
      $s3 = " AndroidManifest.xml. If it is missing or contains tools:node=\"remove\", and you" fullword ascii
      $s4 = "intend to use automatic configuration, verify:" fullword ascii
      $s5 = "You must initialize EmojiCompat prior to referencing the EmojiCompat instance." fullword ascii
      $s6 = "learn more in the documentation for BundledEmojiCompatConfig." fullword ascii
      $s7 = "EmojiCompatInitializer and InitializationProvider is present in" fullword ascii
      $s8 = "either explicitly in AndroidManifest.xml, or by including" fullword ascii
      $s9 = "The most likely cause of this error is disabling the EmojiCompatInitializer" fullword ascii
      $s10 = "EmojiCompat.init immediately on application startup." fullword ascii
      $s11 = "  2. All modules do not contain an exclusion manifest rule for" fullword ascii
      $s12 = "do this in Android Studio using Build > Analyze APK." fullword ascii
      $s13 = "start should be <= than end" fullword ascii
      $s14 = "In the APK Analyzer, ensure that the startup entry for" fullword ascii
      $s15 = "(end should be < than charSequence length" fullword ascii
      $s16 = "*start should be < than charSequence length" fullword ascii
      $s17 = "fetchFonts result is not OK. (" fullword ascii
      $s18 = "If you intended to perform manual configuration, it is recommended that you call" fullword ascii
      $s19 = "you are not expecting to initialize EmojiCompat manually in your application," fullword ascii
      $s20 = "Automatic initialization is typically performed by EmojiCompatInitializer. If" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210_74 {
   meta:
      description = "apk - from files 05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a.apk, 090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90ba268.apk, 091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d96241620a5.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd.apk, 0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea.apk, 13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52.apk, 1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90.apk, 19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c20271e62.apk, 1bf9c16cb7c1faae7fa99a57c5d091cbd1e6d5f3c0d79693a3b0990a8b58367d.apk, 1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0.apk, 1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9.apk, 21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e494fe.apk, 22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b.apk, 23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61.apk, 269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471eed36.apk, 27b8eeb5d1b46e1afa170b998830fe0958f08a2a9dfe7130df607c86ad42fb33.apk, 2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0.apk, 2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089.apk, 34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45.apk, 3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647.apk, 3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5dce6.apk, 3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd.apk, 3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951.apk, 4a899a3b0fd61937ce8555cb0da53daf72dadc7dd299c63e90b4a203e5a14db1.apk, 4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f.apk, 5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8.apk, 64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3.apk, 6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22.apk, 6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa8255405.apk, 73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a.apk, 752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e40ab.apk, 7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570.apk, 78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b.apk, 79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826fdd3.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, 7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf26527b7.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e0ece.apk, 9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d.apk, 9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3bb5d1.apk, 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk, 9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b3306.apk, 9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6.apk, aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8.apk, afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4.apk, b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk, b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e.apk, b1a8941063751656e11bbc6ab44d348cd6795d51bfc890424595c4ac76e52013.apk, b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de.apk, c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d.apk, c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk, ca6271b212c627dd6e4372827a0fb316023fa35210cab7249d634379af6d649c.apk, cb147e7ce69723523f604da875d78ca4738e5f416d2297910ee179a5067e79fe.apk, ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9.apk, d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd.apk, d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2.apk, d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5.apk, d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38.apk, e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3.apk, e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk, f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2.apk, f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65.apk, faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a"
      hash2 = "090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90ba268"
      hash3 = "091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d96241620a5"
      hash4 = "0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169"
      hash5 = "0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd"
      hash6 = "0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072"
      hash7 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash8 = "1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea"
      hash9 = "13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52"
      hash10 = "1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90"
      hash11 = "19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c20271e62"
      hash12 = "1bf9c16cb7c1faae7fa99a57c5d091cbd1e6d5f3c0d79693a3b0990a8b58367d"
      hash13 = "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
      hash14 = "1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9"
      hash15 = "21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e494fe"
      hash16 = "22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b"
      hash17 = "23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61"
      hash18 = "269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471eed36"
      hash19 = "27b8eeb5d1b46e1afa170b998830fe0958f08a2a9dfe7130df607c86ad42fb33"
      hash20 = "2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0"
      hash21 = "2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1"
      hash22 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash23 = "3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089"
      hash24 = "34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45"
      hash25 = "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
      hash26 = "3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5dce6"
      hash27 = "3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd"
      hash28 = "3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c"
      hash29 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash30 = "4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951"
      hash31 = "4a899a3b0fd61937ce8555cb0da53daf72dadc7dd299c63e90b4a203e5a14db1"
      hash32 = "4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290"
      hash33 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash34 = "59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f"
      hash35 = "5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8"
      hash36 = "64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3"
      hash37 = "6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22"
      hash38 = "6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa8255405"
      hash39 = "73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a"
      hash40 = "752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e40ab"
      hash41 = "7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570"
      hash42 = "78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b"
      hash43 = "79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826fdd3"
      hash44 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
      hash45 = "7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf26527b7"
      hash46 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash47 = "8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af"
      hash48 = "9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e0ece"
      hash49 = "9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d"
      hash50 = "9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3bb5d1"
      hash51 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
      hash52 = "9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b3306"
      hash53 = "9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6"
      hash54 = "aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8"
      hash55 = "afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4"
      hash56 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
      hash57 = "b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e"
      hash58 = "b1a8941063751656e11bbc6ab44d348cd6795d51bfc890424595c4ac76e52013"
      hash59 = "b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99"
      hash60 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash61 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash62 = "ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33"
      hash63 = "bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0"
      hash64 = "bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de"
      hash65 = "c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d"
      hash66 = "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
      hash67 = "ca6271b212c627dd6e4372827a0fb316023fa35210cab7249d634379af6d649c"
      hash68 = "cb147e7ce69723523f604da875d78ca4738e5f416d2297910ee179a5067e79fe"
      hash69 = "ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9"
      hash70 = "d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd"
      hash71 = "d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2"
      hash72 = "d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5"
      hash73 = "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
      hash74 = "e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3"
      hash75 = "e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b"
      hash76 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash77 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
      hash78 = "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
      hash79 = "f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65"
      hash80 = "faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a"
      hash81 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "gina lateral" fullword ascii
      $s2 = "szlegesen bejel" fullword ascii
      $s3 = "Stranski list" fullword ascii
      $s4 = "Walang check" fullword ascii
      $s5 = "Foaie lateral" fullword ascii
      $s6 = "Helaian Sisi" fullword ascii
      $s7 = "&&Mudar para o modo de entrada da agenda" fullword ascii
      $s8 = "%%Mudar para o modo de entrada de texto" fullword ascii
      $s9 = "Sheet Samping" fullword ascii
      $s10 = "Feuille lat" fullword ascii
      $s11 = "Hoja lateral" fullword ascii
      $s12 = "Felt i siden" fullword ascii
      $s13 = "Folla lateral" fullword ascii
      $s14 = "Panell lateral" fullword ascii
      $s15 = "ni list" fullword ascii
      $s16 = "May check" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288e_75 {
   meta:
      description = "apk - from files 1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea.apk, 1bf9c16cb7c1faae7fa99a57c5d091cbd1e6d5f3c0d79693a3b0990a8b58367d.apk, 1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0.apk, 27b8eeb5d1b46e1afa170b998830fe0958f08a2a9dfe7130df607c86ad42fb33.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290.apk, 73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, b1a8941063751656e11bbc6ab44d348cd6795d51bfc890424595c4ac76e52013.apk, b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99.apk, bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de.apk, c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d.apk, ca6271b212c627dd6e4372827a0fb316023fa35210cab7249d634379af6d649c.apk, f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea"
      hash2 = "1bf9c16cb7c1faae7fa99a57c5d091cbd1e6d5f3c0d79693a3b0990a8b58367d"
      hash3 = "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
      hash4 = "27b8eeb5d1b46e1afa170b998830fe0958f08a2a9dfe7130df607c86ad42fb33"
      hash5 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash6 = "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
      hash7 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash8 = "4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290"
      hash9 = "73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a"
      hash10 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
      hash11 = "b1a8941063751656e11bbc6ab44d348cd6795d51bfc890424595c4ac76e52013"
      hash12 = "b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99"
      hash13 = "bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de"
      hash14 = "c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d"
      hash15 = "ca6271b212c627dd6e4372827a0fb316023fa35210cab7249d634379af6d649c"
      hash16 = "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
   strings:
      $s1 = " a la vista de a" fullword ascii
      $s2 = "Kalenderansicht wird angezeigt" fullword ascii
      $s3 = "Mudou para a vista de ano" fullword ascii
      $s4 = "#%Mudou para a visualiza" fullword ascii
      $s5 = " \"Mudou para a visualiza" fullword ascii
      $s6 = "Du har bytt till " fullword ascii
      $s7 = "Jahresansicht wird angezeigt" fullword ascii
      $s8 = "Du har bytt till kalendervy" fullword ascii
      $s9 = "o de Agenda" fullword ascii
      $s10 = " !Se ha cambiado a la vista de a" fullword ascii
      $s11 = " a la vista de Calendario" fullword ascii
      $s12 = "''Se ha cambiado a la vista de calendario" fullword ascii
      $s13 = " !Mudou para a vista do Calend" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422_76 {
   meta:
      description = "apk - from files 6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e.apk, a82591b195a32c8ad049ff627367c2a63d67c7f7324e3c335c993a7bbd66477a.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e"
      hash2 = "a82591b195a32c8ad049ff627367c2a63d67c7f7324e3c335c993a7bbd66477a"
   strings:
      $s1 = "#Unable to find configured root for " fullword ascii
      $s2 = "+Resolved path jumped beyond configured root" fullword ascii
      $s3 = "=Failed to parse android.support.FILE_PROVIDER_PATHS meta-data" fullword ascii
      $s4 = "#Provider must grant uri permissions" fullword ascii
      $s5 = "Provider must not be exported" fullword ascii
      $s6 = "4Couldn't find meta-data for provider with authority " fullword ascii
      $s7 = "+source is out of range of [0, 5] (too high)" fullword ascii
      $s8 = "*source is out of range of [0, 5] (too low)" fullword ascii
      $s9 = "No external updates" fullword ascii
      $s10 = ", but only 0x" fullword ascii
      $s11 = "& must not contain null or empty values" fullword ascii
      $s12 = "No external inserts" fullword ascii
      $s13 = "permission must be non-null" fullword ascii
      $s14 = "Invalid mode: " fullword ascii
      $s15 = "#Permission request for permissions " fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb4_77 {
   meta:
      description = "apk - from files 017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44.apk, 0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e.apk, 04e4acc8cd2a66f77260ebcfbe40646192ff452d5f9bbe54e0acbd0cabc3cfbc.apk, 05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a.apk, 0596a76e6772acb911c1a556ad86943224873411fba4383abade25300078ed32.apk, 08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c.apk, 090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90ba268.apk, 091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d96241620a5.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd.apk, 0f9fe82c6594fe331e59cf0268bc402f9e31141a3fd5e5dd99596d28563c5e9b.apk, 0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072.apk, 1099eede57e825fa5158b33f01559dc76e6d67e2fca37b97f76e7d3aa9a4208a.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 12cb6136d2d325563b5079c138eeac2bc4ee4af3373718ba1c79c47a6121829e.apk, 1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea.apk, 13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52.apk, 1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90.apk, 174deed18377e5280413a2015ebe2041fd8b4276a6599754299cf05cea0718d5.apk, 17a68e32e5d8398c93790abe9b117c472557b54ccdcfccfdddb3b7f783ca31b3.apk, 185a01ec24938cd5a9af4fd66a0814e8bfaf2e1ff8cfa2396a30c3e4f6e66b98.apk, 19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c20271e62.apk, 1b5ff50963c6e99dfb521e6db624df9f83f21f06430ce9d8f3cd0de735cbe22a.apk, 1d9bdb35234b01d219fd28c47a47bbaa6c9033e2b1f35b07f10cf09eaed00254.apk, 1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0.apk, 1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9.apk, 21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e494fe.apk, 22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b.apk, 238eeea51b2d53ff08b3129fe6d6be75a13c12090e4063a1455fad614054d4b3.apk, 23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61.apk, 246bdb0a9e7698e37ec7b906551ceed302d0445c9572bb3cdc02a68862fd2d2a.apk, 25fdf72cb393901eb605d6eaea86fe67483a25295651e2423b9e50d5bfc62111.apk, 269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471eed36.apk, 29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896.apk, 2b7e044edadb6932c251f2169da0a777bf553a549a263c5c8a0cf9d888cee704.apk, 2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0.apk, 2d0fd4ea41c4e17cf94577c126ae271555b544f388baca69112cd3a488572be1.apk, 2e11badbd558a37c88ee22a7315c8220b90213fb712ea1ec1f39b14e3ae8475c.apk, 2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1.apk, 2f451d9cfda5d91b2063a62ed5ad482cd733e899b9ee39ee8bd332b518b3b865.apk, 2f595b306756f39b0d525b19d5f5c1d50a5e6761ea049a63a390ec3e6709a2ba.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b.apk, 3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089.apk, 33c3f43852f6ecadef74aef2dbb0d5a1215aa3cb23e4aaf76f202beed3aa8703.apk, 34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45.apk, 3616fd6004678159e531fb7e5a173b333c08bd0097aa1f6a4e9f503db4a9999a.apk, 392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d.apk, 39c97fad655efc5aa4bc3703695b80e9807b14050fe9c8785cd047d3f3051668.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647.apk, 3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5dce6.apk, 3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd.apk, 3d8da22674ee343bd02296a4351e90198ffc786f8541747e42cdcf3438f16b3e.apk, 3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec.apk, 3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c.apk, 41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2.apk, 43996d454961143bad870d9b94a3d00912f7c29b76371244ac59423595ae0860.apk, 446800befecf9179f9aca09dd88331dee0e745b199db39a9b0113f4ee886ca34.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 469b13cac1eb859da7ba4b597270f047b11815bfff9c4ad3faa5617c07a6c3e0.apk, 48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce.apk, 4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951.apk, 4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f.apk, 4a899a3b0fd61937ce8555cb0da53daf72dadc7dd299c63e90b4a203e5a14db1.apk, 4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290.apk, 4af08f08377457cb04e280615fc8647870f9b20ad763e1bd060731605d8a0c07.apk, 4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088.apk, 4bdf7226644876c09e6091127260593a4f7af3b78d148b56004eb1be09bdf4b8.apk, 4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7.apk, 50990c1178790239445d4dea570e4affeca6efbb01a91cbf4af4498a0477dd2e.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 557c02b5e9ca8103e6ad5413df1b447fae5c9ce086a0b5330bf9c79a578585df.apk, 563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b.apk, 57151572cf361d49ead0235eef7cad3827f4711120f3397e746a660aa9c6250b.apk, 57a0a81eebdf6c1e0a5ab0489165f167856712121b86959f0c34ce5c24014266.apk, 59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f.apk, 5a8d4eabd009a75ecc04f3f06489d393f082f963b406d0d3e8acbea568281c5f.apk, 5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8.apk, 5cb94ba3236bd4fa89bad460687cc2f1e80a890f5a093e954ea2704c1950c1f3.apk, 5dff60862aea80d5da616400359ae170f2d9ef9d76a745417f4facff72cd4c17.apk, 5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a.apk, 64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3.apk, 64b4f8c86ea5ef925da573e7667ca93d32f4fb27fd6a702f5e99ccc4d087f612.apk, 6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3.apk, 6564e7362b89d453173884e35d96ff5ce1de7ecbad102b0f5450300418b5de9b.apk, 657881e96def3e69a401f79c678edff27c3db4db74ba802fb8989ae466f73cc9.apk, 6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22.apk, 6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8.apk, 6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa8255405.apk, 6dd19edd60ed2025afc6b661e85f146c925f2137e51ae49c5d1dce955ac43aaf.apk, 6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738.apk, 73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4.apk, 73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a.apk, 752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e40ab.apk, 75cd6f164dee674a18edc5154ef0d48633eb581b73d77aef047af0a5856420cc.apk, 7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570.apk, 774af64259ad726296fb4fc56ca91897c7da9acb3a10ad49325ead714f6562c4.apk, 77c54058a2bb45219e6ee860430f5ea8ce8e6ed2e58fba05f0d9bf74ffb7b4ef.apk, 78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b.apk, 7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144.apk, 79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826fdd3.apk, 7b40e010ae6556b159eaaba4f0989bd57cc510c388215f2d89580cc3379ae33c.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, 7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf26527b7.apk, 807d8ffb7975d525386036b10563485033155f62d4355a83e372b08b370c3850.apk, 8166dfba7fd0b4ad44c8bc91cc0e98fa06b8912e3fca2093900eb58ba79d22d4.apk, 857d9e064fe567da2b5f42b49787d05d0238f34ddc2890a826d80d8f012f7e8d.apk, 8613f7b6df514d53aa419355b0a3e8d032b8448bd45296d4158b848998015e3d.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c4f8053881899f844a2e6dea8ce119124acac2b34750a47650e368c27bf7a3b.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a.apk, 9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e0ece.apk, 994869cacc3615cde8d4196cdfe1e2877f0e1328ff32a292963ffd0983b450fa.apk, 9aff583b812a3979394ffcd23f616d561a0eda4002f2e2a4b42ea5ba3efdbfaf.apk, 9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5.apk, 9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d.apk, 9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3bb5d1.apk, 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk, 9e7d743c341329104a12cfbcf53cc19a9b16c4ec1a874f8d4b42b33e9a68c1f8.apk, 9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b3306.apk, 9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6.apk, a2c509d0b0fcee3bc503bd12986da2d29c74ebcd37abb1af8988f7f26382663d.apk, a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a8030b195f685a2c1b3a5de807f769d38f87efff8bab8c5bfce5a6fabedcc477.apk, a8062f50057c4d8be86c50b411addafa7429b451420b3aaeb1ec6f04aef18957.apk, a81b801522a1c72be91aefffa09b00256fad4ee9d47bb8d79b018b442ab4e78b.apk, aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8.apk, aab9cf77aca821c3f2930315c2afd140ff12441f0d8f0cb0d45927ef7af43ed5.apk, ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de.apk, adefc2f666aa936763b18300444995e1d2a4c1950ef00577de7a88381b825c1f.apk, afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4.apk, b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk, b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e.apk, b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, b50dfd257f1cfda6f67d269571f5e9b251c7f34d54c7f7d865b9d6bed89a49bb.apk, b8fa21bbd5261f2308a168c1f43b197220c0d37bdda0c4a1464be085a9f85300.apk, ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33.apk, bc5ecb77e8aee510a380108013e073f0d0f3b41bd9ba2169bcb8eb85b405347f.apk, bc74da49cf58d85b8ce8a49d2ac0fed574ef1634e67d92ef75440d7b24d0a3e4.apk, bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de.apk, c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14.apk, c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9.apk, c585e3cbaa19ff4934e07f77f447c87a94f21793f9ff35301e1689849d796745.apk, c659454dd6ed62bc7a0c9e0455297e41ba57b0b7935a826150c1f8c0db6f89d2.apk, c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64.apk, c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d.apk, c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk, cadcce6d4088c72fd0779d59d00f5753eaab585a263e3c92374df29ae767ac15.apk, cb147e7ce69723523f604da875d78ca4738e5f416d2297910ee179a5067e79fe.apk, ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9.apk, ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642.apk, cfd656e0d18e1ed7064941197e6504a4b1cdcd3bc6476389dca71237dd839284.apk, d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af.apk, d1fec0ce2be2097357d307e835783380ac010c7d55f3e72fa3906f0d0edd7a6a.apk, d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3.apk, d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd.apk, d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2.apk, d3c63ecb3a95272a043b3e0ab792a70738c867ba18e896c455d9c39d32fff4d3.apk, d3fc5ffdd9a68a3063b1c8ff15334238dd39a63b9c93ec9f337bdd5f5357046a.apk, d566c64a41faf573349cf2c0ecb00f68dbe8b90bc1968d3317d3a20667ddad63.apk, d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5.apk, d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38.apk, dd0919967c57cdabdf8b5bc9c643bb0d250fe935476aa4944544b22132d5163d.apk, e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3.apk, e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938.apk, e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75.apk, e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b.apk, e4aa98c1beee901871fd8a78b37b21ef886e507e65fc6499e3df3769081cd1cb.apk, e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8.apk, e696766abcc6e35ca39a6d6bd1145a7297993f69c2179fc94c84a62519e8b84f.apk, e756a707443f382f4f93ca4b6101de16e4cac521d9032171c7b68b3a9585c39e.apk, e7aa84c2b3ac31d3a948f0431cdbf7b28116fffb157b8e99e8efe455c92dd661.apk, e8f780e2835e2a072b45219823b8c018a09c4971c754e10c264eac9eb04b884d.apk, e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf.apk, e9b41fd64d8702f974e63374a03ad914b6f1b24e8ddd96c29ff14ce81713676f.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, f0d43f00ccae66633aa086433b402435d0a99c2f910e2c6122abc48e35b8cc3f.apk, f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk, f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2.apk, f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65.apk, f8081269cf465c7e7c75e078cd1e8005e6c7091168a235d9d161801a4f31641a.apk, f81d01e7361d276658306125e375453244f28d9ecca6c855e48e6fab88826267.apk, f902a8c4de97bd168839457fb1a3e89149c3e44d8eacbbab070d969ad655ee07.apk, f99486a60b7f8ae9ba5cf991d422954466017dfc4020ca7563655e9ebc8713f7.apk, faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a.apk, fb505c8301b579bff83e77bbd9038cb583a1f207f88a04986a646ad0f9b04d09.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44"
      hash2 = "0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e"
      hash3 = "04e4acc8cd2a66f77260ebcfbe40646192ff452d5f9bbe54e0acbd0cabc3cfbc"
      hash4 = "05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a"
      hash5 = "0596a76e6772acb911c1a556ad86943224873411fba4383abade25300078ed32"
      hash6 = "08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c"
      hash7 = "090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90ba268"
      hash8 = "091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d96241620a5"
      hash9 = "0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169"
      hash10 = "0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd"
      hash11 = "0f9fe82c6594fe331e59cf0268bc402f9e31141a3fd5e5dd99596d28563c5e9b"
      hash12 = "0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072"
      hash13 = "1099eede57e825fa5158b33f01559dc76e6d67e2fca37b97f76e7d3aa9a4208a"
      hash14 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash15 = "12cb6136d2d325563b5079c138eeac2bc4ee4af3373718ba1c79c47a6121829e"
      hash16 = "1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea"
      hash17 = "13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52"
      hash18 = "1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90"
      hash19 = "174deed18377e5280413a2015ebe2041fd8b4276a6599754299cf05cea0718d5"
      hash20 = "17a68e32e5d8398c93790abe9b117c472557b54ccdcfccfdddb3b7f783ca31b3"
      hash21 = "185a01ec24938cd5a9af4fd66a0814e8bfaf2e1ff8cfa2396a30c3e4f6e66b98"
      hash22 = "19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c20271e62"
      hash23 = "1b5ff50963c6e99dfb521e6db624df9f83f21f06430ce9d8f3cd0de735cbe22a"
      hash24 = "1d9bdb35234b01d219fd28c47a47bbaa6c9033e2b1f35b07f10cf09eaed00254"
      hash25 = "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
      hash26 = "1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9"
      hash27 = "21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e494fe"
      hash28 = "22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b"
      hash29 = "238eeea51b2d53ff08b3129fe6d6be75a13c12090e4063a1455fad614054d4b3"
      hash30 = "23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61"
      hash31 = "246bdb0a9e7698e37ec7b906551ceed302d0445c9572bb3cdc02a68862fd2d2a"
      hash32 = "25fdf72cb393901eb605d6eaea86fe67483a25295651e2423b9e50d5bfc62111"
      hash33 = "269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471eed36"
      hash34 = "29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896"
      hash35 = "2b7e044edadb6932c251f2169da0a777bf553a549a263c5c8a0cf9d888cee704"
      hash36 = "2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0"
      hash37 = "2d0fd4ea41c4e17cf94577c126ae271555b544f388baca69112cd3a488572be1"
      hash38 = "2e11badbd558a37c88ee22a7315c8220b90213fb712ea1ec1f39b14e3ae8475c"
      hash39 = "2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1"
      hash40 = "2f451d9cfda5d91b2063a62ed5ad482cd733e899b9ee39ee8bd332b518b3b865"
      hash41 = "2f595b306756f39b0d525b19d5f5c1d50a5e6761ea049a63a390ec3e6709a2ba"
      hash42 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash43 = "31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b"
      hash44 = "3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089"
      hash45 = "33c3f43852f6ecadef74aef2dbb0d5a1215aa3cb23e4aaf76f202beed3aa8703"
      hash46 = "34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45"
      hash47 = "3616fd6004678159e531fb7e5a173b333c08bd0097aa1f6a4e9f503db4a9999a"
      hash48 = "392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d"
      hash49 = "39c97fad655efc5aa4bc3703695b80e9807b14050fe9c8785cd047d3f3051668"
      hash50 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash51 = "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
      hash52 = "3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5dce6"
      hash53 = "3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd"
      hash54 = "3d8da22674ee343bd02296a4351e90198ffc786f8541747e42cdcf3438f16b3e"
      hash55 = "3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec"
      hash56 = "3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c"
      hash57 = "41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2"
      hash58 = "43996d454961143bad870d9b94a3d00912f7c29b76371244ac59423595ae0860"
      hash59 = "446800befecf9179f9aca09dd88331dee0e745b199db39a9b0113f4ee886ca34"
      hash60 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash61 = "469b13cac1eb859da7ba4b597270f047b11815bfff9c4ad3faa5617c07a6c3e0"
      hash62 = "48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce"
      hash63 = "4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951"
      hash64 = "4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f"
      hash65 = "4a899a3b0fd61937ce8555cb0da53daf72dadc7dd299c63e90b4a203e5a14db1"
      hash66 = "4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290"
      hash67 = "4af08f08377457cb04e280615fc8647870f9b20ad763e1bd060731605d8a0c07"
      hash68 = "4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088"
      hash69 = "4bdf7226644876c09e6091127260593a4f7af3b78d148b56004eb1be09bdf4b8"
      hash70 = "4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7"
      hash71 = "50990c1178790239445d4dea570e4affeca6efbb01a91cbf4af4498a0477dd2e"
      hash72 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash73 = "557c02b5e9ca8103e6ad5413df1b447fae5c9ce086a0b5330bf9c79a578585df"
      hash74 = "563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b"
      hash75 = "57151572cf361d49ead0235eef7cad3827f4711120f3397e746a660aa9c6250b"
      hash76 = "57a0a81eebdf6c1e0a5ab0489165f167856712121b86959f0c34ce5c24014266"
      hash77 = "59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f"
      hash78 = "5a8d4eabd009a75ecc04f3f06489d393f082f963b406d0d3e8acbea568281c5f"
      hash79 = "5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8"
      hash80 = "5cb94ba3236bd4fa89bad460687cc2f1e80a890f5a093e954ea2704c1950c1f3"
      hash81 = "5dff60862aea80d5da616400359ae170f2d9ef9d76a745417f4facff72cd4c17"
      hash82 = "5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a"
      hash83 = "64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3"
      hash84 = "64b4f8c86ea5ef925da573e7667ca93d32f4fb27fd6a702f5e99ccc4d087f612"
      hash85 = "6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3"
      hash86 = "6564e7362b89d453173884e35d96ff5ce1de7ecbad102b0f5450300418b5de9b"
      hash87 = "657881e96def3e69a401f79c678edff27c3db4db74ba802fb8989ae466f73cc9"
      hash88 = "6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22"
      hash89 = "6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8"
      hash90 = "6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa8255405"
      hash91 = "6dd19edd60ed2025afc6b661e85f146c925f2137e51ae49c5d1dce955ac43aaf"
      hash92 = "6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738"
      hash93 = "73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4"
      hash94 = "73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a"
      hash95 = "752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e40ab"
      hash96 = "75cd6f164dee674a18edc5154ef0d48633eb581b73d77aef047af0a5856420cc"
      hash97 = "7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570"
      hash98 = "774af64259ad726296fb4fc56ca91897c7da9acb3a10ad49325ead714f6562c4"
      hash99 = "77c54058a2bb45219e6ee860430f5ea8ce8e6ed2e58fba05f0d9bf74ffb7b4ef"
      hash100 = "78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b"
      hash101 = "7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144"
      hash102 = "79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826fdd3"
      hash103 = "7b40e010ae6556b159eaaba4f0989bd57cc510c388215f2d89580cc3379ae33c"
      hash104 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
      hash105 = "7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf26527b7"
      hash106 = "807d8ffb7975d525386036b10563485033155f62d4355a83e372b08b370c3850"
      hash107 = "8166dfba7fd0b4ad44c8bc91cc0e98fa06b8912e3fca2093900eb58ba79d22d4"
      hash108 = "857d9e064fe567da2b5f42b49787d05d0238f34ddc2890a826d80d8f012f7e8d"
      hash109 = "8613f7b6df514d53aa419355b0a3e8d032b8448bd45296d4158b848998015e3d"
      hash110 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash111 = "8c4f8053881899f844a2e6dea8ce119124acac2b34750a47650e368c27bf7a3b"
      hash112 = "8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af"
      hash113 = "90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a"
      hash114 = "9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e0ece"
      hash115 = "994869cacc3615cde8d4196cdfe1e2877f0e1328ff32a292963ffd0983b450fa"
      hash116 = "9aff583b812a3979394ffcd23f616d561a0eda4002f2e2a4b42ea5ba3efdbfaf"
      hash117 = "9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5"
      hash118 = "9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d"
      hash119 = "9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3bb5d1"
      hash120 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
      hash121 = "9e7d743c341329104a12cfbcf53cc19a9b16c4ec1a874f8d4b42b33e9a68c1f8"
      hash122 = "9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b3306"
      hash123 = "9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6"
      hash124 = "a2c509d0b0fcee3bc503bd12986da2d29c74ebcd37abb1af8988f7f26382663d"
      hash125 = "a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2"
      hash126 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash127 = "a8030b195f685a2c1b3a5de807f769d38f87efff8bab8c5bfce5a6fabedcc477"
      hash128 = "a8062f50057c4d8be86c50b411addafa7429b451420b3aaeb1ec6f04aef18957"
      hash129 = "a81b801522a1c72be91aefffa09b00256fad4ee9d47bb8d79b018b442ab4e78b"
      hash130 = "aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8"
      hash131 = "aab9cf77aca821c3f2930315c2afd140ff12441f0d8f0cb0d45927ef7af43ed5"
      hash132 = "ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de"
      hash133 = "adefc2f666aa936763b18300444995e1d2a4c1950ef00577de7a88381b825c1f"
      hash134 = "afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4"
      hash135 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
      hash136 = "b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e"
      hash137 = "b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99"
      hash138 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash139 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash140 = "b50dfd257f1cfda6f67d269571f5e9b251c7f34d54c7f7d865b9d6bed89a49bb"
      hash141 = "b8fa21bbd5261f2308a168c1f43b197220c0d37bdda0c4a1464be085a9f85300"
      hash142 = "ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33"
      hash143 = "bc5ecb77e8aee510a380108013e073f0d0f3b41bd9ba2169bcb8eb85b405347f"
      hash144 = "bc74da49cf58d85b8ce8a49d2ac0fed574ef1634e67d92ef75440d7b24d0a3e4"
      hash145 = "bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7"
      hash146 = "bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0"
      hash147 = "bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de"
      hash148 = "c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14"
      hash149 = "c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9"
      hash150 = "c585e3cbaa19ff4934e07f77f447c87a94f21793f9ff35301e1689849d796745"
      hash151 = "c659454dd6ed62bc7a0c9e0455297e41ba57b0b7935a826150c1f8c0db6f89d2"
      hash152 = "c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64"
      hash153 = "c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d"
      hash154 = "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
      hash155 = "cadcce6d4088c72fd0779d59d00f5753eaab585a263e3c92374df29ae767ac15"
      hash156 = "cb147e7ce69723523f604da875d78ca4738e5f416d2297910ee179a5067e79fe"
      hash157 = "ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9"
      hash158 = "ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642"
      hash159 = "cfd656e0d18e1ed7064941197e6504a4b1cdcd3bc6476389dca71237dd839284"
      hash160 = "d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af"
      hash161 = "d1fec0ce2be2097357d307e835783380ac010c7d55f3e72fa3906f0d0edd7a6a"
      hash162 = "d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3"
      hash163 = "d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd"
      hash164 = "d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2"
      hash165 = "d3c63ecb3a95272a043b3e0ab792a70738c867ba18e896c455d9c39d32fff4d3"
      hash166 = "d3fc5ffdd9a68a3063b1c8ff15334238dd39a63b9c93ec9f337bdd5f5357046a"
      hash167 = "d566c64a41faf573349cf2c0ecb00f68dbe8b90bc1968d3317d3a20667ddad63"
      hash168 = "d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5"
      hash169 = "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
      hash170 = "dd0919967c57cdabdf8b5bc9c643bb0d250fe935476aa4944544b22132d5163d"
      hash171 = "e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3"
      hash172 = "e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938"
      hash173 = "e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75"
      hash174 = "e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b"
      hash175 = "e4aa98c1beee901871fd8a78b37b21ef886e507e65fc6499e3df3769081cd1cb"
      hash176 = "e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8"
      hash177 = "e696766abcc6e35ca39a6d6bd1145a7297993f69c2179fc94c84a62519e8b84f"
      hash178 = "e756a707443f382f4f93ca4b6101de16e4cac521d9032171c7b68b3a9585c39e"
      hash179 = "e7aa84c2b3ac31d3a948f0431cdbf7b28116fffb157b8e99e8efe455c92dd661"
      hash180 = "e8f780e2835e2a072b45219823b8c018a09c4971c754e10c264eac9eb04b884d"
      hash181 = "e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf"
      hash182 = "e9b41fd64d8702f974e63374a03ad914b6f1b24e8ddd96c29ff14ce81713676f"
      hash183 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash184 = "f0d43f00ccae66633aa086433b402435d0a99c2f910e2c6122abc48e35b8cc3f"
      hash185 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
      hash186 = "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
      hash187 = "f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65"
      hash188 = "f8081269cf465c7e7c75e078cd1e8005e6c7091168a235d9d161801a4f31641a"
      hash189 = "f81d01e7361d276658306125e375453244f28d9ecca6c855e48e6fab88826267"
      hash190 = "f902a8c4de97bd168839457fb1a3e89149c3e44d8eacbbab070d969ad655ee07"
      hash191 = "f99486a60b7f8ae9ba5cf991d422954466017dfc4020ca7563655e9ebc8713f7"
      hash192 = "faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a"
      hash193 = "fb505c8301b579bff83e77bbd9038cb583a1f207f88a04986a646ad0f9b04d09"
      hash194 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
      hash195 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "gina inferior" fullword ascii
      $s2 = "o inferior" fullword ascii
      $s3 = "velopper la bottom sheet" fullword ascii
      $s4 = "duire la bottom sheet" fullword ascii
      $s5 = "Contraer la hoja inferior" fullword ascii
      $s6 = "Replega el full inferior" fullword ascii
      $s7 = "Expandir la hoja inferior" fullword ascii
      $s8 = "velopper la zone de contenu dans le bas de l'" fullword ascii
      $s9 = "Marker za povla" fullword ascii
      $s10 = "\"\"Ansicht am unteren Rand minimieren" fullword ascii
      $s11 = "Zgjero flet" fullword ascii
      $s12 = "duire la zone de contenu dans le bas de l'" fullword ascii
      $s13 = "I-collapse ang bottom sheet" fullword ascii
      $s14 = " Bottom Sheet" fullword ascii
      $s15 = "Palos flet" fullword ascii
      $s16 = "\"\"Ansicht am unteren Rand maximieren" fullword ascii
      $s17 = "Desplega el full inferior" fullword ascii
      $s18 = "Indicador para arrastar" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _04e4acc8cd2a66f77260ebcfbe40646192ff452d5f9bbe54e0acbd0cabc3cfb_78 {
   meta:
      description = "apk - from files 04e4acc8cd2a66f77260ebcfbe40646192ff452d5f9bbe54e0acbd0cabc3cfbc.apk, 0596a76e6772acb911c1a556ad86943224873411fba4383abade25300078ed32.apk, 0f9fe82c6594fe331e59cf0268bc402f9e31141a3fd5e5dd99596d28563c5e9b.apk, 1099eede57e825fa5158b33f01559dc76e6d67e2fca37b97f76e7d3aa9a4208a.apk, 12cb6136d2d325563b5079c138eeac2bc4ee4af3373718ba1c79c47a6121829e.apk, 174deed18377e5280413a2015ebe2041fd8b4276a6599754299cf05cea0718d5.apk, 17a68e32e5d8398c93790abe9b117c472557b54ccdcfccfdddb3b7f783ca31b3.apk, 185a01ec24938cd5a9af4fd66a0814e8bfaf2e1ff8cfa2396a30c3e4f6e66b98.apk, 1b5ff50963c6e99dfb521e6db624df9f83f21f06430ce9d8f3cd0de735cbe22a.apk, 1d9bdb35234b01d219fd28c47a47bbaa6c9033e2b1f35b07f10cf09eaed00254.apk, 238eeea51b2d53ff08b3129fe6d6be75a13c12090e4063a1455fad614054d4b3.apk, 246bdb0a9e7698e37ec7b906551ceed302d0445c9572bb3cdc02a68862fd2d2a.apk, 25fdf72cb393901eb605d6eaea86fe67483a25295651e2423b9e50d5bfc62111.apk, 2b7e044edadb6932c251f2169da0a777bf553a549a263c5c8a0cf9d888cee704.apk, 2d0fd4ea41c4e17cf94577c126ae271555b544f388baca69112cd3a488572be1.apk, 2f451d9cfda5d91b2063a62ed5ad482cd733e899b9ee39ee8bd332b518b3b865.apk, 2f595b306756f39b0d525b19d5f5c1d50a5e6761ea049a63a390ec3e6709a2ba.apk, 33c3f43852f6ecadef74aef2dbb0d5a1215aa3cb23e4aaf76f202beed3aa8703.apk, 3616fd6004678159e531fb7e5a173b333c08bd0097aa1f6a4e9f503db4a9999a.apk, 39c97fad655efc5aa4bc3703695b80e9807b14050fe9c8785cd047d3f3051668.apk, 3d8da22674ee343bd02296a4351e90198ffc786f8541747e42cdcf3438f16b3e.apk, 43996d454961143bad870d9b94a3d00912f7c29b76371244ac59423595ae0860.apk, 446800befecf9179f9aca09dd88331dee0e745b199db39a9b0113f4ee886ca34.apk, 469b13cac1eb859da7ba4b597270f047b11815bfff9c4ad3faa5617c07a6c3e0.apk, 4af08f08377457cb04e280615fc8647870f9b20ad763e1bd060731605d8a0c07.apk, 4bdf7226644876c09e6091127260593a4f7af3b78d148b56004eb1be09bdf4b8.apk, 50990c1178790239445d4dea570e4affeca6efbb01a91cbf4af4498a0477dd2e.apk, 557c02b5e9ca8103e6ad5413df1b447fae5c9ce086a0b5330bf9c79a578585df.apk, 57151572cf361d49ead0235eef7cad3827f4711120f3397e746a660aa9c6250b.apk, 57a0a81eebdf6c1e0a5ab0489165f167856712121b86959f0c34ce5c24014266.apk, 5a8d4eabd009a75ecc04f3f06489d393f082f963b406d0d3e8acbea568281c5f.apk, 5cb94ba3236bd4fa89bad460687cc2f1e80a890f5a093e954ea2704c1950c1f3.apk, 5dff60862aea80d5da616400359ae170f2d9ef9d76a745417f4facff72cd4c17.apk, 64b4f8c86ea5ef925da573e7667ca93d32f4fb27fd6a702f5e99ccc4d087f612.apk, 6564e7362b89d453173884e35d96ff5ce1de7ecbad102b0f5450300418b5de9b.apk, 657881e96def3e69a401f79c678edff27c3db4db74ba802fb8989ae466f73cc9.apk, 6dd19edd60ed2025afc6b661e85f146c925f2137e51ae49c5d1dce955ac43aaf.apk, 75cd6f164dee674a18edc5154ef0d48633eb581b73d77aef047af0a5856420cc.apk, 77c54058a2bb45219e6ee860430f5ea8ce8e6ed2e58fba05f0d9bf74ffb7b4ef.apk, 7b40e010ae6556b159eaaba4f0989bd57cc510c388215f2d89580cc3379ae33c.apk, 807d8ffb7975d525386036b10563485033155f62d4355a83e372b08b370c3850.apk, 8166dfba7fd0b4ad44c8bc91cc0e98fa06b8912e3fca2093900eb58ba79d22d4.apk, 857d9e064fe567da2b5f42b49787d05d0238f34ddc2890a826d80d8f012f7e8d.apk, 8613f7b6df514d53aa419355b0a3e8d032b8448bd45296d4158b848998015e3d.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c4f8053881899f844a2e6dea8ce119124acac2b34750a47650e368c27bf7a3b.apk, 994869cacc3615cde8d4196cdfe1e2877f0e1328ff32a292963ffd0983b450fa.apk, 9aff583b812a3979394ffcd23f616d561a0eda4002f2e2a4b42ea5ba3efdbfaf.apk, 9e7d743c341329104a12cfbcf53cc19a9b16c4ec1a874f8d4b42b33e9a68c1f8.apk, a8030b195f685a2c1b3a5de807f769d38f87efff8bab8c5bfce5a6fabedcc477.apk, a8062f50057c4d8be86c50b411addafa7429b451420b3aaeb1ec6f04aef18957.apk, a81b801522a1c72be91aefffa09b00256fad4ee9d47bb8d79b018b442ab4e78b.apk, aab9cf77aca821c3f2930315c2afd140ff12441f0d8f0cb0d45927ef7af43ed5.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, adefc2f666aa936763b18300444995e1d2a4c1950ef00577de7a88381b825c1f.apk, b50dfd257f1cfda6f67d269571f5e9b251c7f34d54c7f7d865b9d6bed89a49bb.apk, b8fa21bbd5261f2308a168c1f43b197220c0d37bdda0c4a1464be085a9f85300.apk, b99d175cbe06d4569a18449da044f326c68a56315ccc0da9cfa6f2c33bfd0939.apk, bc5ecb77e8aee510a380108013e073f0d0f3b41bd9ba2169bcb8eb85b405347f.apk, bc74da49cf58d85b8ce8a49d2ac0fed574ef1634e67d92ef75440d7b24d0a3e4.apk, c585e3cbaa19ff4934e07f77f447c87a94f21793f9ff35301e1689849d796745.apk, c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64.apk, cadcce6d4088c72fd0779d59d00f5753eaab585a263e3c92374df29ae767ac15.apk, cfd656e0d18e1ed7064941197e6504a4b1cdcd3bc6476389dca71237dd839284.apk, d3c63ecb3a95272a043b3e0ab792a70738c867ba18e896c455d9c39d32fff4d3.apk, d566c64a41faf573349cf2c0ecb00f68dbe8b90bc1968d3317d3a20667ddad63.apk, dd0919967c57cdabdf8b5bc9c643bb0d250fe935476aa4944544b22132d5163d.apk, e4aa98c1beee901871fd8a78b37b21ef886e507e65fc6499e3df3769081cd1cb.apk, e696766abcc6e35ca39a6d6bd1145a7297993f69c2179fc94c84a62519e8b84f.apk, e7aa84c2b3ac31d3a948f0431cdbf7b28116fffb157b8e99e8efe455c92dd661.apk, e8f780e2835e2a072b45219823b8c018a09c4971c754e10c264eac9eb04b884d.apk, e9b41fd64d8702f974e63374a03ad914b6f1b24e8ddd96c29ff14ce81713676f.apk, f0d43f00ccae66633aa086433b402435d0a99c2f910e2c6122abc48e35b8cc3f.apk, f8081269cf465c7e7c75e078cd1e8005e6c7091168a235d9d161801a4f31641a.apk, f81d01e7361d276658306125e375453244f28d9ecca6c855e48e6fab88826267.apk, f902a8c4de97bd168839457fb1a3e89149c3e44d8eacbbab070d969ad655ee07.apk, f99486a60b7f8ae9ba5cf991d422954466017dfc4020ca7563655e9ebc8713f7.apk, fb505c8301b579bff83e77bbd9038cb583a1f207f88a04986a646ad0f9b04d09.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "04e4acc8cd2a66f77260ebcfbe40646192ff452d5f9bbe54e0acbd0cabc3cfbc"
      hash2 = "0596a76e6772acb911c1a556ad86943224873411fba4383abade25300078ed32"
      hash3 = "0f9fe82c6594fe331e59cf0268bc402f9e31141a3fd5e5dd99596d28563c5e9b"
      hash4 = "1099eede57e825fa5158b33f01559dc76e6d67e2fca37b97f76e7d3aa9a4208a"
      hash5 = "12cb6136d2d325563b5079c138eeac2bc4ee4af3373718ba1c79c47a6121829e"
      hash6 = "174deed18377e5280413a2015ebe2041fd8b4276a6599754299cf05cea0718d5"
      hash7 = "17a68e32e5d8398c93790abe9b117c472557b54ccdcfccfdddb3b7f783ca31b3"
      hash8 = "185a01ec24938cd5a9af4fd66a0814e8bfaf2e1ff8cfa2396a30c3e4f6e66b98"
      hash9 = "1b5ff50963c6e99dfb521e6db624df9f83f21f06430ce9d8f3cd0de735cbe22a"
      hash10 = "1d9bdb35234b01d219fd28c47a47bbaa6c9033e2b1f35b07f10cf09eaed00254"
      hash11 = "238eeea51b2d53ff08b3129fe6d6be75a13c12090e4063a1455fad614054d4b3"
      hash12 = "246bdb0a9e7698e37ec7b906551ceed302d0445c9572bb3cdc02a68862fd2d2a"
      hash13 = "25fdf72cb393901eb605d6eaea86fe67483a25295651e2423b9e50d5bfc62111"
      hash14 = "2b7e044edadb6932c251f2169da0a777bf553a549a263c5c8a0cf9d888cee704"
      hash15 = "2d0fd4ea41c4e17cf94577c126ae271555b544f388baca69112cd3a488572be1"
      hash16 = "2f451d9cfda5d91b2063a62ed5ad482cd733e899b9ee39ee8bd332b518b3b865"
      hash17 = "2f595b306756f39b0d525b19d5f5c1d50a5e6761ea049a63a390ec3e6709a2ba"
      hash18 = "33c3f43852f6ecadef74aef2dbb0d5a1215aa3cb23e4aaf76f202beed3aa8703"
      hash19 = "3616fd6004678159e531fb7e5a173b333c08bd0097aa1f6a4e9f503db4a9999a"
      hash20 = "39c97fad655efc5aa4bc3703695b80e9807b14050fe9c8785cd047d3f3051668"
      hash21 = "3d8da22674ee343bd02296a4351e90198ffc786f8541747e42cdcf3438f16b3e"
      hash22 = "43996d454961143bad870d9b94a3d00912f7c29b76371244ac59423595ae0860"
      hash23 = "446800befecf9179f9aca09dd88331dee0e745b199db39a9b0113f4ee886ca34"
      hash24 = "469b13cac1eb859da7ba4b597270f047b11815bfff9c4ad3faa5617c07a6c3e0"
      hash25 = "4af08f08377457cb04e280615fc8647870f9b20ad763e1bd060731605d8a0c07"
      hash26 = "4bdf7226644876c09e6091127260593a4f7af3b78d148b56004eb1be09bdf4b8"
      hash27 = "50990c1178790239445d4dea570e4affeca6efbb01a91cbf4af4498a0477dd2e"
      hash28 = "557c02b5e9ca8103e6ad5413df1b447fae5c9ce086a0b5330bf9c79a578585df"
      hash29 = "57151572cf361d49ead0235eef7cad3827f4711120f3397e746a660aa9c6250b"
      hash30 = "57a0a81eebdf6c1e0a5ab0489165f167856712121b86959f0c34ce5c24014266"
      hash31 = "5a8d4eabd009a75ecc04f3f06489d393f082f963b406d0d3e8acbea568281c5f"
      hash32 = "5cb94ba3236bd4fa89bad460687cc2f1e80a890f5a093e954ea2704c1950c1f3"
      hash33 = "5dff60862aea80d5da616400359ae170f2d9ef9d76a745417f4facff72cd4c17"
      hash34 = "64b4f8c86ea5ef925da573e7667ca93d32f4fb27fd6a702f5e99ccc4d087f612"
      hash35 = "6564e7362b89d453173884e35d96ff5ce1de7ecbad102b0f5450300418b5de9b"
      hash36 = "657881e96def3e69a401f79c678edff27c3db4db74ba802fb8989ae466f73cc9"
      hash37 = "6dd19edd60ed2025afc6b661e85f146c925f2137e51ae49c5d1dce955ac43aaf"
      hash38 = "75cd6f164dee674a18edc5154ef0d48633eb581b73d77aef047af0a5856420cc"
      hash39 = "77c54058a2bb45219e6ee860430f5ea8ce8e6ed2e58fba05f0d9bf74ffb7b4ef"
      hash40 = "7b40e010ae6556b159eaaba4f0989bd57cc510c388215f2d89580cc3379ae33c"
      hash41 = "807d8ffb7975d525386036b10563485033155f62d4355a83e372b08b370c3850"
      hash42 = "8166dfba7fd0b4ad44c8bc91cc0e98fa06b8912e3fca2093900eb58ba79d22d4"
      hash43 = "857d9e064fe567da2b5f42b49787d05d0238f34ddc2890a826d80d8f012f7e8d"
      hash44 = "8613f7b6df514d53aa419355b0a3e8d032b8448bd45296d4158b848998015e3d"
      hash45 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash46 = "8c4f8053881899f844a2e6dea8ce119124acac2b34750a47650e368c27bf7a3b"
      hash47 = "994869cacc3615cde8d4196cdfe1e2877f0e1328ff32a292963ffd0983b450fa"
      hash48 = "9aff583b812a3979394ffcd23f616d561a0eda4002f2e2a4b42ea5ba3efdbfaf"
      hash49 = "9e7d743c341329104a12cfbcf53cc19a9b16c4ec1a874f8d4b42b33e9a68c1f8"
      hash50 = "a8030b195f685a2c1b3a5de807f769d38f87efff8bab8c5bfce5a6fabedcc477"
      hash51 = "a8062f50057c4d8be86c50b411addafa7429b451420b3aaeb1ec6f04aef18957"
      hash52 = "a81b801522a1c72be91aefffa09b00256fad4ee9d47bb8d79b018b442ab4e78b"
      hash53 = "aab9cf77aca821c3f2930315c2afd140ff12441f0d8f0cb0d45927ef7af43ed5"
      hash54 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash55 = "adefc2f666aa936763b18300444995e1d2a4c1950ef00577de7a88381b825c1f"
      hash56 = "b50dfd257f1cfda6f67d269571f5e9b251c7f34d54c7f7d865b9d6bed89a49bb"
      hash57 = "b8fa21bbd5261f2308a168c1f43b197220c0d37bdda0c4a1464be085a9f85300"
      hash58 = "b99d175cbe06d4569a18449da044f326c68a56315ccc0da9cfa6f2c33bfd0939"
      hash59 = "bc5ecb77e8aee510a380108013e073f0d0f3b41bd9ba2169bcb8eb85b405347f"
      hash60 = "bc74da49cf58d85b8ce8a49d2ac0fed574ef1634e67d92ef75440d7b24d0a3e4"
      hash61 = "c585e3cbaa19ff4934e07f77f447c87a94f21793f9ff35301e1689849d796745"
      hash62 = "c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64"
      hash63 = "cadcce6d4088c72fd0779d59d00f5753eaab585a263e3c92374df29ae767ac15"
      hash64 = "cfd656e0d18e1ed7064941197e6504a4b1cdcd3bc6476389dca71237dd839284"
      hash65 = "d3c63ecb3a95272a043b3e0ab792a70738c867ba18e896c455d9c39d32fff4d3"
      hash66 = "d566c64a41faf573349cf2c0ecb00f68dbe8b90bc1968d3317d3a20667ddad63"
      hash67 = "dd0919967c57cdabdf8b5bc9c643bb0d250fe935476aa4944544b22132d5163d"
      hash68 = "e4aa98c1beee901871fd8a78b37b21ef886e507e65fc6499e3df3769081cd1cb"
      hash69 = "e696766abcc6e35ca39a6d6bd1145a7297993f69c2179fc94c84a62519e8b84f"
      hash70 = "e7aa84c2b3ac31d3a948f0431cdbf7b28116fffb157b8e99e8efe455c92dd661"
      hash71 = "e8f780e2835e2a072b45219823b8c018a09c4971c754e10c264eac9eb04b884d"
      hash72 = "e9b41fd64d8702f974e63374a03ad914b6f1b24e8ddd96c29ff14ce81713676f"
      hash73 = "f0d43f00ccae66633aa086433b402435d0a99c2f910e2c6122abc48e35b8cc3f"
      hash74 = "f8081269cf465c7e7c75e078cd1e8005e6c7091168a235d9d161801a4f31641a"
      hash75 = "f81d01e7361d276658306125e375453244f28d9ecca6c855e48e6fab88826267"
      hash76 = "f902a8c4de97bd168839457fb1a3e89149c3e44d8eacbbab070d969ad655ee07"
      hash77 = "f99486a60b7f8ae9ba5cf991d422954466017dfc4020ca7563655e9ebc8713f7"
      hash78 = "fb505c8301b579bff83e77bbd9038cb583a1f207f88a04986a646ad0f9b04d09"
   strings:
      $s1 = "Dropdown menu" fullword ascii
      $s2 = "Drop-down na menu" fullword ascii
      $s3 = "Menu dropdown" fullword ascii
      $s4 = "Menu pendente" fullword ascii
      $s5 = "Pole valitud" fullword ascii
      $s6 = "Menu lungsur" fullword ascii
      $s7 = "Ekki vali" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13ce_79 {
   meta:
      description = "apk - from files 53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee.apk, a82591b195a32c8ad049ff627367c2a63d67c7f7324e3c335c993a7bbd66477a.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee"
      hash2 = "a82591b195a32c8ad049ff627367c2a63d67c7f7324e3c335c993a7bbd66477a"
   strings:
      $s1 = "!Unexpected header: Content-Length" fullword ascii
      $s2 = "3Landroidx/recyclerview/widget/RecyclerView$Adapter;" fullword ascii
      $s3 = "-Failed to find configured root that contains " fullword ascii
      $s4 = "Unexpected header: Content-Type" fullword ascii
      $s5 = "Exception in connect" fullword ascii
      $s6 = "+Multipart body must have at least one part." fullword ascii
      $s7 = "%unable to load android socket classes" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cff_80 {
   meta:
      description = "apk - from files 1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cffb.apk, 5c15f4808ad986ff87797ff8d01120a5016d6182f08788db73072bec43d53814.apk, a82591b195a32c8ad049ff627367c2a63d67c7f7324e3c335c993a7bbd66477a.apk, cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c.apk, db11d9b51d90d23e5769d5f6dd738adad56acff41555698446926804d5396962.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cffb"
      hash2 = "5c15f4808ad986ff87797ff8d01120a5016d6182f08788db73072bec43d53814"
      hash3 = "a82591b195a32c8ad049ff627367c2a63d67c7f7324e3c335c993a7bbd66477a"
      hash4 = "cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c"
      hash5 = "db11d9b51d90d23e5769d5f6dd738adad56acff41555698446926804d5396962"
   strings:
      $s1 = "Qunexpected error retrieving valid column from cursor, did the remote process die?" fullword ascii
      $s2 = "&Failed to get insets from AttachInfo. " fullword ascii
      $s3 = "-Failed to get visible insets from AttachInfo " fullword ascii
      $s4 = "=Failed to inflate ColorStateList, leaving it to the framework" fullword ascii
      $s5 = "Failed to read xml resource " fullword ascii
      $s6 = "7Could not find method computeFitSystemWindows. Oh well." fullword ascii
      $s7 = "[ is an AppCompat widget that can only be used with a Theme.AppCompat theme (or descendant)." fullword ascii
      $s8 = "Failed to parse xml resource " fullword ascii
      $s9 = "IIgnoring attribute 'itemActionViewLayout'. Action view already specified." fullword ascii
      $s10 = "Failed launch activity: " fullword ascii
      $s11 = "Failed to find font-family tag" fullword ascii
      $s12 = "Error closing icon stream for " fullword ascii
      $s13 = "Invalid pointerId=" fullword ascii
      $s14 = "7Mutated drawable is not the same instance as the input." fullword ascii
      $s15 = "3 does not implement interface method onNestedScroll" fullword ascii
      $s16 = "Invalid icon resource " fullword ascii
      $s17 = "5 does not implement interface method onNestedPreFling" fullword ascii
      $s18 = "6 does not implement interface method onNestedPreScroll" fullword ascii
      $s19 = "*Search suggestions cursor threw exception." fullword ascii
      $s20 = "$ does not fully implement ViewParent" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288e_81 {
   meta:
      description = "apk - from files 1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea.apk, 1bf9c16cb7c1faae7fa99a57c5d091cbd1e6d5f3c0d79693a3b0990a8b58367d.apk, 1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0.apk, 27b8eeb5d1b46e1afa170b998830fe0958f08a2a9dfe7130df607c86ad42fb33.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290.apk, 73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, b1a8941063751656e11bbc6ab44d348cd6795d51bfc890424595c4ac76e52013.apk, b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de.apk, c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d.apk, ca6271b212c627dd6e4372827a0fb316023fa35210cab7249d634379af6d649c.apk, f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea"
      hash2 = "1bf9c16cb7c1faae7fa99a57c5d091cbd1e6d5f3c0d79693a3b0990a8b58367d"
      hash3 = "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
      hash4 = "27b8eeb5d1b46e1afa170b998830fe0958f08a2a9dfe7130df607c86ad42fb33"
      hash5 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash6 = "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
      hash7 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash8 = "4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290"
      hash9 = "73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a"
      hash10 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
      hash11 = "b1a8941063751656e11bbc6ab44d348cd6795d51bfc890424595c4ac76e52013"
      hash12 = "b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99"
      hash13 = "bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0"
      hash14 = "bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de"
      hash15 = "c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d"
      hash16 = "ca6271b212c627dd6e4372827a0fb316023fa35210cab7249d634379af6d649c"
      hash17 = "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
   strings:
      $s1 = " !Passer " fullword ascii
      $s2 = "area pe ani" fullword ascii
      $s3 = "Skift til kalendervisning" fullword ascii
      $s4 = "Mudar para a vista de ano" fullword ascii
      $s5 = "Kalo te pamja e kalendarit" fullword ascii
      $s6 = "Skift til " fullword ascii
      $s7 = "#%Mudar para a visualiza" fullword ascii
      $s8 = "Lumipat sa view ng taon" fullword ascii
      $s9 = " \"Mudar para a visualiza" fullword ascii
      $s10 = "Lumipat sa view ng Kalendaryo" fullword ascii
      $s11 = "Byt till kalendervy" fullword ascii
      $s12 = "Kalo te pamja e vitit" fullword ascii
      $s13 = "o da Agenda" fullword ascii
      $s14 = "Byt till " fullword ascii
      $s15 = "Cambiar a la vista anual" fullword ascii
      $s16 = "Cambiar a la vista de a" fullword ascii
      $s17 = "  Cambiar a la vista de calendario" fullword ascii
      $s18 = " !Mudar para a vista do Calend" fullword ascii
      $s19 = "  Cambiar a la vista de Calendario" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _110cf99f4e796065b71aaf966e749ad6a0913919ec58cfc628b86aae84e24be_82 {
   meta:
      description = "apk - from files 110cf99f4e796065b71aaf966e749ad6a0913919ec58cfc628b86aae84e24be4.apk, 364959964532e51ae14aa9e7b9e3f48594ac6343a2423e49ed27daafdbaf7753.apk, 580b39589c457f66e1feaa1f5e41830d1dc2091f31ec61dd393ca121bf3bed2e.apk, d0a15d8c5c2ea81c9d47e2553346e1713bfdb007f41d7c5d35a38d06d8611921.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "110cf99f4e796065b71aaf966e749ad6a0913919ec58cfc628b86aae84e24be4"
      hash2 = "364959964532e51ae14aa9e7b9e3f48594ac6343a2423e49ed27daafdbaf7753"
      hash3 = "580b39589c457f66e1feaa1f5e41830d1dc2091f31ec61dd393ca121bf3bed2e"
      hash4 = "d0a15d8c5c2ea81c9d47e2553346e1713bfdb007f41d7c5d35a38d06d8611921"
   strings:
      $s1 = "Media view" fullword ascii
      $s2 = "  Open ad when you're back online." fullword ascii
      $s3 = "App Manager" fullword ascii
      $s4 = "Don't allow" fullword ascii
      $s5 = "$$Allow app to send you notifications?" fullword ascii
      $s6 = "AAWe'll send you a notification with a link to the advertiser site." fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb4_83 {
   meta:
      description = "apk - from files 017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44.apk, 01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0.apk, 0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e.apk, 05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a.apk, 08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c.apk, 090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90ba268.apk, 091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d96241620a5.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd.apk, 0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072.apk, 11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea.apk, 13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52.apk, 1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90.apk, 19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c20271e62.apk, 1bf9c16cb7c1faae7fa99a57c5d091cbd1e6d5f3c0d79693a3b0990a8b58367d.apk, 1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c.apk, 1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0.apk, 1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9.apk, 21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e494fe.apk, 22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b.apk, 23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61.apk, 269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471eed36.apk, 27b8eeb5d1b46e1afa170b998830fe0958f08a2a9dfe7130df607c86ad42fb33.apk, 29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896.apk, 2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0.apk, 2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b.apk, 3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089.apk, 34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45.apk, 392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647.apk, 3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5dce6.apk, 3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd.apk, 3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec.apk, 3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c.apk, 41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2.apk, 41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce.apk, 4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951.apk, 4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f.apk, 4a899a3b0fd61937ce8555cb0da53daf72dadc7dd299c63e90b4a203e5a14db1.apk, 4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290.apk, 4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088.apk, 4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b.apk, 59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f.apk, 5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8.apk, 5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3.apk, 6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3.apk, 65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf.apk, 6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22.apk, 6b0c56540499051ab350a31f417b99859da7ed7286b9e77503711c6aabafbe03.apk, 6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8.apk, 6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa8255405.apk, 6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd.apk, 6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738.apk, 73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4.apk, 73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a.apk, 752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e40ab.apk, 7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570.apk, 78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b.apk, 7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144.apk, 79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826fdd3.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, 7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf26527b7.apk, 8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552.apk, 83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a.apk, 9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e0ece.apk, 9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5.apk, 9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d.apk, 9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d.apk, 9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3bb5d1.apk, 9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c.apk, 9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90.apk, 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk, 9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b3306.apk, 9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6.apk, a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5.apk, a2c509d0b0fcee3bc503bd12986da2d29c74ebcd37abb1af8988f7f26382663d.apk, a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa.apk, aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de.apk, afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4.apk, b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk, b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e.apk, b1a8941063751656e11bbc6ab44d348cd6795d51bfc890424595c4ac76e52013.apk, b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33.apk, bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6.apk, bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de.apk, c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14.apk, c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9.apk, c659454dd6ed62bc7a0c9e0455297e41ba57b0b7935a826150c1f8c0db6f89d2.apk, c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d.apk, c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk, ca6271b212c627dd6e4372827a0fb316023fa35210cab7249d634379af6d649c.apk, cb147e7ce69723523f604da875d78ca4738e5f416d2297910ee179a5067e79fe.apk, cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c.apk, ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9.apk, ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642.apk, d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af.apk, d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3.apk, d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd.apk, d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2.apk, d3fc5ffdd9a68a3063b1c8ff15334238dd39a63b9c93ec9f337bdd5f5357046a.apk, d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372.apk, d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5.apk, d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe.apk, d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d.apk, d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38.apk, decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8.apk, e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3.apk, e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938.apk, e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75.apk, e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b.apk, e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8.apk, e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk, f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2.apk, f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738.apk, f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65.apk, faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee.apk, faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44"
      hash2 = "01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0"
      hash3 = "0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e"
      hash4 = "05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a"
      hash5 = "08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c"
      hash6 = "090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90ba268"
      hash7 = "091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d96241620a5"
      hash8 = "0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169"
      hash9 = "0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd"
      hash10 = "0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072"
      hash11 = "11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415"
      hash12 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash13 = "134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138"
      hash14 = "1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea"
      hash15 = "13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52"
      hash16 = "1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90"
      hash17 = "19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c20271e62"
      hash18 = "1bf9c16cb7c1faae7fa99a57c5d091cbd1e6d5f3c0d79693a3b0990a8b58367d"
      hash19 = "1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c"
      hash20 = "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
      hash21 = "1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9"
      hash22 = "21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e494fe"
      hash23 = "22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b"
      hash24 = "23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61"
      hash25 = "269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471eed36"
      hash26 = "27b8eeb5d1b46e1afa170b998830fe0958f08a2a9dfe7130df607c86ad42fb33"
      hash27 = "29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896"
      hash28 = "2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0"
      hash29 = "2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1"
      hash30 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash31 = "31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b"
      hash32 = "3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089"
      hash33 = "34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45"
      hash34 = "392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d"
      hash35 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash36 = "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
      hash37 = "3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5dce6"
      hash38 = "3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd"
      hash39 = "3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec"
      hash40 = "3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c"
      hash41 = "41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2"
      hash42 = "41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7"
      hash43 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash44 = "48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce"
      hash45 = "4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951"
      hash46 = "4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f"
      hash47 = "4a899a3b0fd61937ce8555cb0da53daf72dadc7dd299c63e90b4a203e5a14db1"
      hash48 = "4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290"
      hash49 = "4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088"
      hash50 = "4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7"
      hash51 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash52 = "563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b"
      hash53 = "59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f"
      hash54 = "5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8"
      hash55 = "5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a"
      hash56 = "5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8"
      hash57 = "64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3"
      hash58 = "6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3"
      hash59 = "65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf"
      hash60 = "6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22"
      hash61 = "6b0c56540499051ab350a31f417b99859da7ed7286b9e77503711c6aabafbe03"
      hash62 = "6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8"
      hash63 = "6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa8255405"
      hash64 = "6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd"
      hash65 = "6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738"
      hash66 = "73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4"
      hash67 = "73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a"
      hash68 = "752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e40ab"
      hash69 = "7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570"
      hash70 = "78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b"
      hash71 = "7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144"
      hash72 = "79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826fdd3"
      hash73 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
      hash74 = "7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf26527b7"
      hash75 = "8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552"
      hash76 = "83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025"
      hash77 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash78 = "8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af"
      hash79 = "90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a"
      hash80 = "9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e0ece"
      hash81 = "9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5"
      hash82 = "9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d"
      hash83 = "9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d"
      hash84 = "9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3bb5d1"
      hash85 = "9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c"
      hash86 = "9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90"
      hash87 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
      hash88 = "9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b3306"
      hash89 = "9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6"
      hash90 = "a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5"
      hash91 = "a2c509d0b0fcee3bc503bd12986da2d29c74ebcd37abb1af8988f7f26382663d"
      hash92 = "a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2"
      hash93 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash94 = "a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa"
      hash95 = "aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8"
      hash96 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash97 = "ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de"
      hash98 = "afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4"
      hash99 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
      hash100 = "b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e"
      hash101 = "b1a8941063751656e11bbc6ab44d348cd6795d51bfc890424595c4ac76e52013"
      hash102 = "b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99"
      hash103 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash104 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash105 = "ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33"
      hash106 = "bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6"
      hash107 = "bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7"
      hash108 = "bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0"
      hash109 = "bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de"
      hash110 = "c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14"
      hash111 = "c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9"
      hash112 = "c659454dd6ed62bc7a0c9e0455297e41ba57b0b7935a826150c1f8c0db6f89d2"
      hash113 = "c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d"
      hash114 = "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
      hash115 = "ca6271b212c627dd6e4372827a0fb316023fa35210cab7249d634379af6d649c"
      hash116 = "cb147e7ce69723523f604da875d78ca4738e5f416d2297910ee179a5067e79fe"
      hash117 = "cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c"
      hash118 = "ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9"
      hash119 = "ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642"
      hash120 = "d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af"
      hash121 = "d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3"
      hash122 = "d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd"
      hash123 = "d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2"
      hash124 = "d3fc5ffdd9a68a3063b1c8ff15334238dd39a63b9c93ec9f337bdd5f5357046a"
      hash125 = "d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372"
      hash126 = "d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5"
      hash127 = "d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe"
      hash128 = "d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d"
      hash129 = "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
      hash130 = "decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8"
      hash131 = "e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3"
      hash132 = "e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938"
      hash133 = "e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75"
      hash134 = "e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b"
      hash135 = "e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8"
      hash136 = "e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf"
      hash137 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash138 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
      hash139 = "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
      hash140 = "f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738"
      hash141 = "f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65"
      hash142 = "faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee"
      hash143 = "faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a"
      hash144 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
      hash145 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "Passer au mode d'entr" fullword ascii
      $s2 = "i la luna urm" fullword ascii
      $s3 = "i la luna anterioar" fullword ascii
      $s4 = "(*Mudar para o modo de introdu" fullword ascii
      $s5 = "Alterar para o m" fullword ascii
      $s6 = "Navigera till " fullword ascii
      $s7 = "  Beralih ke mode masukan kalender" fullword ascii
      $s8 = ",,Tumia programu ya kuingiza data ya maandishi" fullword ascii
      $s9 = "Beralih ke mode masukan teks" fullword ascii
      $s10 = "-0Mudar para o modo de introdu" fullword ascii
      $s11 = "Alterar para o pr" fullword ascii
      $s12 = "Passer au mode d'entr" fullword ascii
      $s13 = "e Agenda" fullword ascii
      $s14 = "34Canvia al mode d'introducci" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb4_84 {
   meta:
      description = "apk - from files 017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44.apk, 01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0.apk, 0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e.apk, 04e4acc8cd2a66f77260ebcfbe40646192ff452d5f9bbe54e0acbd0cabc3cfbc.apk, 0596a76e6772acb911c1a556ad86943224873411fba4383abade25300078ed32.apk, 08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c.apk, 0f9fe82c6594fe331e59cf0268bc402f9e31141a3fd5e5dd99596d28563c5e9b.apk, 1099eede57e825fa5158b33f01559dc76e6d67e2fca37b97f76e7d3aa9a4208a.apk, 11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 12cb6136d2d325563b5079c138eeac2bc4ee4af3373718ba1c79c47a6121829e.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea.apk, 174deed18377e5280413a2015ebe2041fd8b4276a6599754299cf05cea0718d5.apk, 17a68e32e5d8398c93790abe9b117c472557b54ccdcfccfdddb3b7f783ca31b3.apk, 185a01ec24938cd5a9af4fd66a0814e8bfaf2e1ff8cfa2396a30c3e4f6e66b98.apk, 1b5ff50963c6e99dfb521e6db624df9f83f21f06430ce9d8f3cd0de735cbe22a.apk, 1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c.apk, 1d9bdb35234b01d219fd28c47a47bbaa6c9033e2b1f35b07f10cf09eaed00254.apk, 1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0.apk, 238eeea51b2d53ff08b3129fe6d6be75a13c12090e4063a1455fad614054d4b3.apk, 23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61.apk, 246bdb0a9e7698e37ec7b906551ceed302d0445c9572bb3cdc02a68862fd2d2a.apk, 25fdf72cb393901eb605d6eaea86fe67483a25295651e2423b9e50d5bfc62111.apk, 29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896.apk, 2b7e044edadb6932c251f2169da0a777bf553a549a263c5c8a0cf9d888cee704.apk, 2d0fd4ea41c4e17cf94577c126ae271555b544f388baca69112cd3a488572be1.apk, 2f451d9cfda5d91b2063a62ed5ad482cd733e899b9ee39ee8bd332b518b3b865.apk, 2f595b306756f39b0d525b19d5f5c1d50a5e6761ea049a63a390ec3e6709a2ba.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b.apk, 3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089.apk, 33c3f43852f6ecadef74aef2dbb0d5a1215aa3cb23e4aaf76f202beed3aa8703.apk, 34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45.apk, 3616fd6004678159e531fb7e5a173b333c08bd0097aa1f6a4e9f503db4a9999a.apk, 392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d.apk, 39c97fad655efc5aa4bc3703695b80e9807b14050fe9c8785cd047d3f3051668.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647.apk, 3d8da22674ee343bd02296a4351e90198ffc786f8541747e42cdcf3438f16b3e.apk, 3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec.apk, 41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2.apk, 41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7.apk, 43996d454961143bad870d9b94a3d00912f7c29b76371244ac59423595ae0860.apk, 446800befecf9179f9aca09dd88331dee0e745b199db39a9b0113f4ee886ca34.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 469b13cac1eb859da7ba4b597270f047b11815bfff9c4ad3faa5617c07a6c3e0.apk, 48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce.apk, 4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f.apk, 4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290.apk, 4af08f08377457cb04e280615fc8647870f9b20ad763e1bd060731605d8a0c07.apk, 4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088.apk, 4bdf7226644876c09e6091127260593a4f7af3b78d148b56004eb1be09bdf4b8.apk, 4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7.apk, 50990c1178790239445d4dea570e4affeca6efbb01a91cbf4af4498a0477dd2e.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 557c02b5e9ca8103e6ad5413df1b447fae5c9ce086a0b5330bf9c79a578585df.apk, 563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b.apk, 57151572cf361d49ead0235eef7cad3827f4711120f3397e746a660aa9c6250b.apk, 57a0a81eebdf6c1e0a5ab0489165f167856712121b86959f0c34ce5c24014266.apk, 5a8d4eabd009a75ecc04f3f06489d393f082f963b406d0d3e8acbea568281c5f.apk, 5cb94ba3236bd4fa89bad460687cc2f1e80a890f5a093e954ea2704c1950c1f3.apk, 5dff60862aea80d5da616400359ae170f2d9ef9d76a745417f4facff72cd4c17.apk, 5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 64b4f8c86ea5ef925da573e7667ca93d32f4fb27fd6a702f5e99ccc4d087f612.apk, 6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3.apk, 6564e7362b89d453173884e35d96ff5ce1de7ecbad102b0f5450300418b5de9b.apk, 657881e96def3e69a401f79c678edff27c3db4db74ba802fb8989ae466f73cc9.apk, 65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf.apk, 6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8.apk, 6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd.apk, 6dd19edd60ed2025afc6b661e85f146c925f2137e51ae49c5d1dce955ac43aaf.apk, 6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738.apk, 73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4.apk, 73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a.apk, 75cd6f164dee674a18edc5154ef0d48633eb581b73d77aef047af0a5856420cc.apk, 7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570.apk, 77c54058a2bb45219e6ee860430f5ea8ce8e6ed2e58fba05f0d9bf74ffb7b4ef.apk, 7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144.apk, 7b40e010ae6556b159eaaba4f0989bd57cc510c388215f2d89580cc3379ae33c.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, 807d8ffb7975d525386036b10563485033155f62d4355a83e372b08b370c3850.apk, 8166dfba7fd0b4ad44c8bc91cc0e98fa06b8912e3fca2093900eb58ba79d22d4.apk, 8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552.apk, 83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025.apk, 857d9e064fe567da2b5f42b49787d05d0238f34ddc2890a826d80d8f012f7e8d.apk, 8613f7b6df514d53aa419355b0a3e8d032b8448bd45296d4158b848998015e3d.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c4f8053881899f844a2e6dea8ce119124acac2b34750a47650e368c27bf7a3b.apk, 90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a.apk, 994869cacc3615cde8d4196cdfe1e2877f0e1328ff32a292963ffd0983b450fa.apk, 9aff583b812a3979394ffcd23f616d561a0eda4002f2e2a4b42ea5ba3efdbfaf.apk, 9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5.apk, 9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d.apk, 9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c.apk, 9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90.apk, 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk, 9e7d743c341329104a12cfbcf53cc19a9b16c4ec1a874f8d4b42b33e9a68c1f8.apk, 9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6.apk, a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5.apk, a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa.apk, a8030b195f685a2c1b3a5de807f769d38f87efff8bab8c5bfce5a6fabedcc477.apk, a8062f50057c4d8be86c50b411addafa7429b451420b3aaeb1ec6f04aef18957.apk, a81b801522a1c72be91aefffa09b00256fad4ee9d47bb8d79b018b442ab4e78b.apk, aab9cf77aca821c3f2930315c2afd140ff12441f0d8f0cb0d45927ef7af43ed5.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de.apk, adefc2f666aa936763b18300444995e1d2a4c1950ef00577de7a88381b825c1f.apk, b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk, b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, b50dfd257f1cfda6f67d269571f5e9b251c7f34d54c7f7d865b9d6bed89a49bb.apk, b8fa21bbd5261f2308a168c1f43b197220c0d37bdda0c4a1464be085a9f85300.apk, bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6.apk, bc5ecb77e8aee510a380108013e073f0d0f3b41bd9ba2169bcb8eb85b405347f.apk, bc74da49cf58d85b8ce8a49d2ac0fed574ef1634e67d92ef75440d7b24d0a3e4.apk, bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7.apk, c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14.apk, c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9.apk, c585e3cbaa19ff4934e07f77f447c87a94f21793f9ff35301e1689849d796745.apk, c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64.apk, c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk, cadcce6d4088c72fd0779d59d00f5753eaab585a263e3c92374df29ae767ac15.apk, ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642.apk, cfd656e0d18e1ed7064941197e6504a4b1cdcd3bc6476389dca71237dd839284.apk, d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af.apk, d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3.apk, d3c63ecb3a95272a043b3e0ab792a70738c867ba18e896c455d9c39d32fff4d3.apk, d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372.apk, d566c64a41faf573349cf2c0ecb00f68dbe8b90bc1968d3317d3a20667ddad63.apk, d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe.apk, d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d.apk, d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38.apk, dd0919967c57cdabdf8b5bc9c643bb0d250fe935476aa4944544b22132d5163d.apk, decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8.apk, e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3.apk, e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938.apk, e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75.apk, e4aa98c1beee901871fd8a78b37b21ef886e507e65fc6499e3df3769081cd1cb.apk, e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8.apk, e696766abcc6e35ca39a6d6bd1145a7297993f69c2179fc94c84a62519e8b84f.apk, e7aa84c2b3ac31d3a948f0431cdbf7b28116fffb157b8e99e8efe455c92dd661.apk, e8f780e2835e2a072b45219823b8c018a09c4971c754e10c264eac9eb04b884d.apk, e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf.apk, e9b41fd64d8702f974e63374a03ad914b6f1b24e8ddd96c29ff14ce81713676f.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, f0d43f00ccae66633aa086433b402435d0a99c2f910e2c6122abc48e35b8cc3f.apk, f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk, f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2.apk, f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738.apk, f8081269cf465c7e7c75e078cd1e8005e6c7091168a235d9d161801a4f31641a.apk, f81d01e7361d276658306125e375453244f28d9ecca6c855e48e6fab88826267.apk, f902a8c4de97bd168839457fb1a3e89149c3e44d8eacbbab070d969ad655ee07.apk, f99486a60b7f8ae9ba5cf991d422954466017dfc4020ca7563655e9ebc8713f7.apk, faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee.apk, fb505c8301b579bff83e77bbd9038cb583a1f207f88a04986a646ad0f9b04d09.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44"
      hash2 = "01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0"
      hash3 = "0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e"
      hash4 = "04e4acc8cd2a66f77260ebcfbe40646192ff452d5f9bbe54e0acbd0cabc3cfbc"
      hash5 = "0596a76e6772acb911c1a556ad86943224873411fba4383abade25300078ed32"
      hash6 = "08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c"
      hash7 = "0f9fe82c6594fe331e59cf0268bc402f9e31141a3fd5e5dd99596d28563c5e9b"
      hash8 = "1099eede57e825fa5158b33f01559dc76e6d67e2fca37b97f76e7d3aa9a4208a"
      hash9 = "11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415"
      hash10 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash11 = "12cb6136d2d325563b5079c138eeac2bc4ee4af3373718ba1c79c47a6121829e"
      hash12 = "134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138"
      hash13 = "1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea"
      hash14 = "174deed18377e5280413a2015ebe2041fd8b4276a6599754299cf05cea0718d5"
      hash15 = "17a68e32e5d8398c93790abe9b117c472557b54ccdcfccfdddb3b7f783ca31b3"
      hash16 = "185a01ec24938cd5a9af4fd66a0814e8bfaf2e1ff8cfa2396a30c3e4f6e66b98"
      hash17 = "1b5ff50963c6e99dfb521e6db624df9f83f21f06430ce9d8f3cd0de735cbe22a"
      hash18 = "1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c"
      hash19 = "1d9bdb35234b01d219fd28c47a47bbaa6c9033e2b1f35b07f10cf09eaed00254"
      hash20 = "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
      hash21 = "238eeea51b2d53ff08b3129fe6d6be75a13c12090e4063a1455fad614054d4b3"
      hash22 = "23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61"
      hash23 = "246bdb0a9e7698e37ec7b906551ceed302d0445c9572bb3cdc02a68862fd2d2a"
      hash24 = "25fdf72cb393901eb605d6eaea86fe67483a25295651e2423b9e50d5bfc62111"
      hash25 = "29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896"
      hash26 = "2b7e044edadb6932c251f2169da0a777bf553a549a263c5c8a0cf9d888cee704"
      hash27 = "2d0fd4ea41c4e17cf94577c126ae271555b544f388baca69112cd3a488572be1"
      hash28 = "2f451d9cfda5d91b2063a62ed5ad482cd733e899b9ee39ee8bd332b518b3b865"
      hash29 = "2f595b306756f39b0d525b19d5f5c1d50a5e6761ea049a63a390ec3e6709a2ba"
      hash30 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash31 = "31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b"
      hash32 = "3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089"
      hash33 = "33c3f43852f6ecadef74aef2dbb0d5a1215aa3cb23e4aaf76f202beed3aa8703"
      hash34 = "34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45"
      hash35 = "3616fd6004678159e531fb7e5a173b333c08bd0097aa1f6a4e9f503db4a9999a"
      hash36 = "392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d"
      hash37 = "39c97fad655efc5aa4bc3703695b80e9807b14050fe9c8785cd047d3f3051668"
      hash38 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash39 = "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
      hash40 = "3d8da22674ee343bd02296a4351e90198ffc786f8541747e42cdcf3438f16b3e"
      hash41 = "3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec"
      hash42 = "41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2"
      hash43 = "41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7"
      hash44 = "43996d454961143bad870d9b94a3d00912f7c29b76371244ac59423595ae0860"
      hash45 = "446800befecf9179f9aca09dd88331dee0e745b199db39a9b0113f4ee886ca34"
      hash46 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash47 = "469b13cac1eb859da7ba4b597270f047b11815bfff9c4ad3faa5617c07a6c3e0"
      hash48 = "48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce"
      hash49 = "4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f"
      hash50 = "4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290"
      hash51 = "4af08f08377457cb04e280615fc8647870f9b20ad763e1bd060731605d8a0c07"
      hash52 = "4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088"
      hash53 = "4bdf7226644876c09e6091127260593a4f7af3b78d148b56004eb1be09bdf4b8"
      hash54 = "4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7"
      hash55 = "50990c1178790239445d4dea570e4affeca6efbb01a91cbf4af4498a0477dd2e"
      hash56 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash57 = "557c02b5e9ca8103e6ad5413df1b447fae5c9ce086a0b5330bf9c79a578585df"
      hash58 = "563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b"
      hash59 = "57151572cf361d49ead0235eef7cad3827f4711120f3397e746a660aa9c6250b"
      hash60 = "57a0a81eebdf6c1e0a5ab0489165f167856712121b86959f0c34ce5c24014266"
      hash61 = "5a8d4eabd009a75ecc04f3f06489d393f082f963b406d0d3e8acbea568281c5f"
      hash62 = "5cb94ba3236bd4fa89bad460687cc2f1e80a890f5a093e954ea2704c1950c1f3"
      hash63 = "5dff60862aea80d5da616400359ae170f2d9ef9d76a745417f4facff72cd4c17"
      hash64 = "5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a"
      hash65 = "5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8"
      hash66 = "64b4f8c86ea5ef925da573e7667ca93d32f4fb27fd6a702f5e99ccc4d087f612"
      hash67 = "6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3"
      hash68 = "6564e7362b89d453173884e35d96ff5ce1de7ecbad102b0f5450300418b5de9b"
      hash69 = "657881e96def3e69a401f79c678edff27c3db4db74ba802fb8989ae466f73cc9"
      hash70 = "65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf"
      hash71 = "6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8"
      hash72 = "6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd"
      hash73 = "6dd19edd60ed2025afc6b661e85f146c925f2137e51ae49c5d1dce955ac43aaf"
      hash74 = "6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738"
      hash75 = "73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4"
      hash76 = "73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a"
      hash77 = "75cd6f164dee674a18edc5154ef0d48633eb581b73d77aef047af0a5856420cc"
      hash78 = "7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570"
      hash79 = "77c54058a2bb45219e6ee860430f5ea8ce8e6ed2e58fba05f0d9bf74ffb7b4ef"
      hash80 = "7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144"
      hash81 = "7b40e010ae6556b159eaaba4f0989bd57cc510c388215f2d89580cc3379ae33c"
      hash82 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
      hash83 = "807d8ffb7975d525386036b10563485033155f62d4355a83e372b08b370c3850"
      hash84 = "8166dfba7fd0b4ad44c8bc91cc0e98fa06b8912e3fca2093900eb58ba79d22d4"
      hash85 = "8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552"
      hash86 = "83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025"
      hash87 = "857d9e064fe567da2b5f42b49787d05d0238f34ddc2890a826d80d8f012f7e8d"
      hash88 = "8613f7b6df514d53aa419355b0a3e8d032b8448bd45296d4158b848998015e3d"
      hash89 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash90 = "8c4f8053881899f844a2e6dea8ce119124acac2b34750a47650e368c27bf7a3b"
      hash91 = "90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a"
      hash92 = "994869cacc3615cde8d4196cdfe1e2877f0e1328ff32a292963ffd0983b450fa"
      hash93 = "9aff583b812a3979394ffcd23f616d561a0eda4002f2e2a4b42ea5ba3efdbfaf"
      hash94 = "9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5"
      hash95 = "9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d"
      hash96 = "9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c"
      hash97 = "9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90"
      hash98 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
      hash99 = "9e7d743c341329104a12cfbcf53cc19a9b16c4ec1a874f8d4b42b33e9a68c1f8"
      hash100 = "9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6"
      hash101 = "a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5"
      hash102 = "a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2"
      hash103 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash104 = "a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa"
      hash105 = "a8030b195f685a2c1b3a5de807f769d38f87efff8bab8c5bfce5a6fabedcc477"
      hash106 = "a8062f50057c4d8be86c50b411addafa7429b451420b3aaeb1ec6f04aef18957"
      hash107 = "a81b801522a1c72be91aefffa09b00256fad4ee9d47bb8d79b018b442ab4e78b"
      hash108 = "aab9cf77aca821c3f2930315c2afd140ff12441f0d8f0cb0d45927ef7af43ed5"
      hash109 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash110 = "ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de"
      hash111 = "adefc2f666aa936763b18300444995e1d2a4c1950ef00577de7a88381b825c1f"
      hash112 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
      hash113 = "b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99"
      hash114 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash115 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash116 = "b50dfd257f1cfda6f67d269571f5e9b251c7f34d54c7f7d865b9d6bed89a49bb"
      hash117 = "b8fa21bbd5261f2308a168c1f43b197220c0d37bdda0c4a1464be085a9f85300"
      hash118 = "bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6"
      hash119 = "bc5ecb77e8aee510a380108013e073f0d0f3b41bd9ba2169bcb8eb85b405347f"
      hash120 = "bc74da49cf58d85b8ce8a49d2ac0fed574ef1634e67d92ef75440d7b24d0a3e4"
      hash121 = "bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7"
      hash122 = "c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14"
      hash123 = "c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9"
      hash124 = "c585e3cbaa19ff4934e07f77f447c87a94f21793f9ff35301e1689849d796745"
      hash125 = "c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64"
      hash126 = "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
      hash127 = "cadcce6d4088c72fd0779d59d00f5753eaab585a263e3c92374df29ae767ac15"
      hash128 = "ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642"
      hash129 = "cfd656e0d18e1ed7064941197e6504a4b1cdcd3bc6476389dca71237dd839284"
      hash130 = "d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af"
      hash131 = "d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3"
      hash132 = "d3c63ecb3a95272a043b3e0ab792a70738c867ba18e896c455d9c39d32fff4d3"
      hash133 = "d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372"
      hash134 = "d566c64a41faf573349cf2c0ecb00f68dbe8b90bc1968d3317d3a20667ddad63"
      hash135 = "d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe"
      hash136 = "d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d"
      hash137 = "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
      hash138 = "dd0919967c57cdabdf8b5bc9c643bb0d250fe935476aa4944544b22132d5163d"
      hash139 = "decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8"
      hash140 = "e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3"
      hash141 = "e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938"
      hash142 = "e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75"
      hash143 = "e4aa98c1beee901871fd8a78b37b21ef886e507e65fc6499e3df3769081cd1cb"
      hash144 = "e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8"
      hash145 = "e696766abcc6e35ca39a6d6bd1145a7297993f69c2179fc94c84a62519e8b84f"
      hash146 = "e7aa84c2b3ac31d3a948f0431cdbf7b28116fffb157b8e99e8efe455c92dd661"
      hash147 = "e8f780e2835e2a072b45219823b8c018a09c4971c754e10c264eac9eb04b884d"
      hash148 = "e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf"
      hash149 = "e9b41fd64d8702f974e63374a03ad914b6f1b24e8ddd96c29ff14ce81713676f"
      hash150 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash151 = "f0d43f00ccae66633aa086433b402435d0a99c2f910e2c6122abc48e35b8cc3f"
      hash152 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
      hash153 = "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
      hash154 = "f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738"
      hash155 = "f8081269cf465c7e7c75e078cd1e8005e6c7091168a235d9d161801a4f31641a"
      hash156 = "f81d01e7361d276658306125e375453244f28d9ecca6c855e48e6fab88826267"
      hash157 = "f902a8c4de97bd168839457fb1a3e89149c3e44d8eacbbab070d969ad655ee07"
      hash158 = "f99486a60b7f8ae9ba5cf991d422954466017dfc4020ca7563655e9ebc8713f7"
      hash159 = "faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee"
      hash160 = "fb505c8301b579bff83e77bbd9038cb583a1f207f88a04986a646ad0f9b04d09"
      hash161 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
      hash162 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "lj minuter" fullword ascii
      $s2 = "Izaberite minute" fullword ascii
      $s3 = "Odaberite minute" fullword ascii
      $s4 = "Velg time" fullword ascii
      $s5 = "Kies minute" fullword ascii
      $s6 = "lg time" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb4_85 {
   meta:
      description = "apk - from files 017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44.apk, 0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e.apk, 05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a.apk, 08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c.apk, 090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90ba268.apk, 091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d96241620a5.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd.apk, 0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52.apk, 1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90.apk, 19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c20271e62.apk, 1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9.apk, 21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e494fe.apk, 22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b.apk, 23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61.apk, 269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471eed36.apk, 29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896.apk, 2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0.apk, 2e11badbd558a37c88ee22a7315c8220b90213fb712ea1ec1f39b14e3ae8475c.apk, 2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1.apk, 31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b.apk, 3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089.apk, 34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45.apk, 392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5dce6.apk, 3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd.apk, 3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec.apk, 3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c.apk, 41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2.apk, 48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce.apk, 4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951.apk, 4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f.apk, 4a899a3b0fd61937ce8555cb0da53daf72dadc7dd299c63e90b4a203e5a14db1.apk, 4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088.apk, 4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b.apk, 59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f.apk, 5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8.apk, 5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a.apk, 64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3.apk, 6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3.apk, 6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22.apk, 6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8.apk, 6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa8255405.apk, 6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738.apk, 73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4.apk, 752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e40ab.apk, 7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570.apk, 774af64259ad726296fb4fc56ca91897c7da9acb3a10ad49325ead714f6562c4.apk, 78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b.apk, 7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144.apk, 79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826fdd3.apk, 7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf26527b7.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a.apk, 9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e0ece.apk, 9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5.apk, 9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d.apk, 9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3bb5d1.apk, 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk, 9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b3306.apk, 9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6.apk, a2c509d0b0fcee3bc503bd12986da2d29c74ebcd37abb1af8988f7f26382663d.apk, a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8.apk, ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de.apk, afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4.apk, b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk, b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33.apk, bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7.apk, c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14.apk, c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9.apk, c659454dd6ed62bc7a0c9e0455297e41ba57b0b7935a826150c1f8c0db6f89d2.apk, c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk, cb147e7ce69723523f604da875d78ca4738e5f416d2297910ee179a5067e79fe.apk, ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9.apk, ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642.apk, d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af.apk, d1fec0ce2be2097357d307e835783380ac010c7d55f3e72fa3906f0d0edd7a6a.apk, d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3.apk, d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd.apk, d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2.apk, d3fc5ffdd9a68a3063b1c8ff15334238dd39a63b9c93ec9f337bdd5f5357046a.apk, d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5.apk, d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38.apk, e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3.apk, e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938.apk, e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75.apk, e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b.apk, e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8.apk, e756a707443f382f4f93ca4b6101de16e4cac521d9032171c7b68b3a9585c39e.apk, e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk, f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65.apk, faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44"
      hash2 = "0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e"
      hash3 = "05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a"
      hash4 = "08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c"
      hash5 = "090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90ba268"
      hash6 = "091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d96241620a5"
      hash7 = "0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169"
      hash8 = "0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd"
      hash9 = "0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072"
      hash10 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash11 = "13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52"
      hash12 = "1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90"
      hash13 = "19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c20271e62"
      hash14 = "1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9"
      hash15 = "21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e494fe"
      hash16 = "22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b"
      hash17 = "23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61"
      hash18 = "269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471eed36"
      hash19 = "29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896"
      hash20 = "2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0"
      hash21 = "2e11badbd558a37c88ee22a7315c8220b90213fb712ea1ec1f39b14e3ae8475c"
      hash22 = "2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1"
      hash23 = "31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b"
      hash24 = "3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089"
      hash25 = "34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45"
      hash26 = "392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d"
      hash27 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash28 = "3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5dce6"
      hash29 = "3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd"
      hash30 = "3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec"
      hash31 = "3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c"
      hash32 = "41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2"
      hash33 = "48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce"
      hash34 = "4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951"
      hash35 = "4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f"
      hash36 = "4a899a3b0fd61937ce8555cb0da53daf72dadc7dd299c63e90b4a203e5a14db1"
      hash37 = "4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088"
      hash38 = "4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7"
      hash39 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash40 = "563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b"
      hash41 = "59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f"
      hash42 = "5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8"
      hash43 = "5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a"
      hash44 = "64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3"
      hash45 = "6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3"
      hash46 = "6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22"
      hash47 = "6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8"
      hash48 = "6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa8255405"
      hash49 = "6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738"
      hash50 = "73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4"
      hash51 = "752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e40ab"
      hash52 = "7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570"
      hash53 = "774af64259ad726296fb4fc56ca91897c7da9acb3a10ad49325ead714f6562c4"
      hash54 = "78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b"
      hash55 = "7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144"
      hash56 = "79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826fdd3"
      hash57 = "7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf26527b7"
      hash58 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash59 = "8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af"
      hash60 = "90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a"
      hash61 = "9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e0ece"
      hash62 = "9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5"
      hash63 = "9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d"
      hash64 = "9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3bb5d1"
      hash65 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
      hash66 = "9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b3306"
      hash67 = "9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6"
      hash68 = "a2c509d0b0fcee3bc503bd12986da2d29c74ebcd37abb1af8988f7f26382663d"
      hash69 = "a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2"
      hash70 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash71 = "aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8"
      hash72 = "ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de"
      hash73 = "afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4"
      hash74 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
      hash75 = "b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e"
      hash76 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash77 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash78 = "ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33"
      hash79 = "bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7"
      hash80 = "c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14"
      hash81 = "c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9"
      hash82 = "c659454dd6ed62bc7a0c9e0455297e41ba57b0b7935a826150c1f8c0db6f89d2"
      hash83 = "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
      hash84 = "cb147e7ce69723523f604da875d78ca4738e5f416d2297910ee179a5067e79fe"
      hash85 = "ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9"
      hash86 = "ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642"
      hash87 = "d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af"
      hash88 = "d1fec0ce2be2097357d307e835783380ac010c7d55f3e72fa3906f0d0edd7a6a"
      hash89 = "d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3"
      hash90 = "d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd"
      hash91 = "d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2"
      hash92 = "d3fc5ffdd9a68a3063b1c8ff15334238dd39a63b9c93ec9f337bdd5f5357046a"
      hash93 = "d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5"
      hash94 = "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
      hash95 = "e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3"
      hash96 = "e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938"
      hash97 = "e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75"
      hash98 = "e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b"
      hash99 = "e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8"
      hash100 = "e756a707443f382f4f93ca4b6101de16e4cac521d9032171c7b68b3a9585c39e"
      hash101 = "e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf"
      hash102 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash103 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
      hash104 = "f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65"
      hash105 = "faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a"
      hash106 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
      hash107 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "placement touch" fullword ascii
      $s2 = "$$Na-double tap ang handle sa pag-drag" fullword ascii
      $s3 = "&&Doppio tocco su punto di trascinamento" fullword ascii
      $s4 = "$%Dvaput dodirnut marker za povla" fullword ascii
      $s5 = "Handel geser diketuk dua kali" fullword ascii
      $s6 = "$&Du har trykket to gange p" fullword ascii
      $s7 = ",-El control de arrastre se presion" fullword ascii
      $s8 = "Pemegang seret diketik dua kali" fullword ascii
      $s9 = ")*Controlador de arrastre tocado d" fullword ascii
      $s10 = "((Controlador de arrastre tocado dos veces" fullword ascii
      $s11 = "&&Dois toques no indicador para arrastar" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a9_86 {
   meta:
      description = "apk - from files 1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90.apk, 2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0.apk, 3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c.apk, 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk, aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8.apk, b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk, ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33.apk, f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90"
      hash2 = "2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0"
      hash3 = "3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c"
      hash4 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
      hash5 = "aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8"
      hash6 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
      hash7 = "ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33"
      hash8 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
   strings:
      $s1 = "Share error" fullword ascii
      $s2 = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vivamus vehicula ligula tortor, in pellentesque dui congue ac. Vestibul" ascii
      $s3 = "Cannot share multiple logs" fullword ascii
      $s4 = "No sessions found" fullword ascii
      $s5 = "Log Action" fullword ascii
      $s6 = "Pcap import error" fullword ascii
      $s7 = "um lacinia urna magna, quis cursus ante iaculis nec. Nunc ut ligula sit amet odio ultrices euismod vel vel purus. Sed lacus maur" ascii
      $s8 = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vivamus vehicula ligula tortor, in pellentesque dui congue ac. Vestibul" ascii
      $s9 = "Pcap import success" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _0619168a8df6dd350052ca3a578abe15da0f2177e65acea55f44b5b59ed5f1c_87 {
   meta:
      description = "apk - from files 0619168a8df6dd350052ca3a578abe15da0f2177e65acea55f44b5b59ed5f1c8.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0badd9b4b0e44daeaa75b5d97ed9611a9f84418c1fb5683130e8b22742086549.apk, 0c8085cea946d655b266998fd60b1da33df73a4285328da3dabc7f0e7211411d.apk, 3638754e7fd889e9ced9127e7abe08191b7e8df3d60ed284c7b507e1e8082613.apk, 399c4819af422e581639c9350dcba71b0ee00b87a4d37da11806db5e25a0adc5.apk, 3ab3cc3c0df02d723c850e712fa5f4a0de29f2addf2c50beffe222112c2baa38.apk, 3c0a6f866aa4d74d0b39a2b9d11692ffa7291fd46b414e73cd5f9c7f9f030b75.apk, 41930e6f9187c8be4ea41303dd957d74f65b97944321a24a20028e76d10e0588.apk, 4f0508904ec488ea7767e9d124b78097aefa8f43cc1713e81a7c4f45e1ba77f0.apk, 53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee.apk, 662bb00e9a82d43be45413fce12def326a1863f9cd3e63aa45b60d36ef7e0443.apk, 6a702c55f4ee54eeb35a991d7413328da1e56dde6e719babec23682423bec23f.apk, 75b4d9eb26ed9e20009c9a55a58e66457d7ec4d7d060179f09f6522e96c62e2e.apk, 7b167d362a9282adb176095be2e5bd4692b4158b7bdf4c6c20870daed5b04665.apk, 904e4153d2026380dc42297173192e72de7e5d9ea50f16bf8df2e2fa6922cdc3.apk, b4b2197c5a8f0e9b9766fa39e9b538568284ec8a0099811b8b54fe6a1402545b.apk, ca5b40e938f68321dfa3a7f1ad2a03db4ff6ba27fdae5e230654cd5c30090692.apk, d5a84c85508c444743d055be354a464eb22dc5b33cba41e4b149829d182f4dca.apk, d9b75d606803968d04015bed042da887905e9c1cb1b40b4ff11852b88c8b4d21.apk, e163a088d174d4eb41479b53e6df04831dc40899b893a0b183d080d2dfe52cd7.apk, faab917444988b9a2e8d5d5bc06a0423c53718f92cbb8840cc6632f464c89130.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "0619168a8df6dd350052ca3a578abe15da0f2177e65acea55f44b5b59ed5f1c8"
      hash2 = "0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169"
      hash3 = "0badd9b4b0e44daeaa75b5d97ed9611a9f84418c1fb5683130e8b22742086549"
      hash4 = "0c8085cea946d655b266998fd60b1da33df73a4285328da3dabc7f0e7211411d"
      hash5 = "3638754e7fd889e9ced9127e7abe08191b7e8df3d60ed284c7b507e1e8082613"
      hash6 = "399c4819af422e581639c9350dcba71b0ee00b87a4d37da11806db5e25a0adc5"
      hash7 = "3ab3cc3c0df02d723c850e712fa5f4a0de29f2addf2c50beffe222112c2baa38"
      hash8 = "3c0a6f866aa4d74d0b39a2b9d11692ffa7291fd46b414e73cd5f9c7f9f030b75"
      hash9 = "41930e6f9187c8be4ea41303dd957d74f65b97944321a24a20028e76d10e0588"
      hash10 = "4f0508904ec488ea7767e9d124b78097aefa8f43cc1713e81a7c4f45e1ba77f0"
      hash11 = "53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee"
      hash12 = "662bb00e9a82d43be45413fce12def326a1863f9cd3e63aa45b60d36ef7e0443"
      hash13 = "6a702c55f4ee54eeb35a991d7413328da1e56dde6e719babec23682423bec23f"
      hash14 = "75b4d9eb26ed9e20009c9a55a58e66457d7ec4d7d060179f09f6522e96c62e2e"
      hash15 = "7b167d362a9282adb176095be2e5bd4692b4158b7bdf4c6c20870daed5b04665"
      hash16 = "904e4153d2026380dc42297173192e72de7e5d9ea50f16bf8df2e2fa6922cdc3"
      hash17 = "b4b2197c5a8f0e9b9766fa39e9b538568284ec8a0099811b8b54fe6a1402545b"
      hash18 = "ca5b40e938f68321dfa3a7f1ad2a03db4ff6ba27fdae5e230654cd5c30090692"
      hash19 = "d5a84c85508c444743d055be354a464eb22dc5b33cba41e4b149829d182f4dca"
      hash20 = "d9b75d606803968d04015bed042da887905e9c1cb1b40b4ff11852b88c8b4d21"
      hash21 = "e163a088d174d4eb41479b53e6df04831dc40899b893a0b183d080d2dfe52cd7"
      hash22 = "faab917444988b9a2e8d5d5bc06a0423c53718f92cbb8840cc6632f464c89130"
   strings:
      $s1 = "libunwind: unsupported .eh_frame_hdr version: %u at %lx" fullword ascii
      $s2 = "const __shim_type_info *__cxxabiv1::get_shim_type_info(uint64_t, const uint8_t *, uint8_t, bool, _Unwind_Control_Block *, uintpt" ascii
      $s3 = "const __shim_type_info *__cxxabiv1::get_shim_type_info(uint64_t, const uint8_t *, uint8_t, bool, _Unwind_Control_Block *, uintpt" ascii
      $s4 = "((ttypeEncoding == DW_EH_PE_absptr) || (ttypeEncoding == DW_EH_PE_pcrel) || (ttypeEncoding == (DW_EH_PE_pcrel | DW_EH_PE_indirec" ascii
      $s5 = "t))) && \"Unexpected TTypeEncoding\"" fullword ascii
      $s6 = "void __cxxabiv1::scan_eh_tab(scan_results &, _Unwind_Action, bool, _Unwind_Control_Block *, _Unwind_Context *)" fullword ascii
      $s7 = "void __cxxabiv1::scan_eh_tab(scan_results &, _Unwind_Action, bool, _Unwind_Exception *, _Unwind_Context *)" fullword ascii
      $s8 = "lock *, uintptr_t)" fullword ascii
      $s9 = "bool __cxxabiv1::exception_spec_can_catch(int64_t, const uint8_t *, uint8_t, const __shim_type_info *, void *, _Unwind_Control_B" ascii
      $s10 = "bool __cxxabiv1::exception_spec_can_catch(int64_t, const uint8_t *, uint8_t, const __shim_type_info *, void *, _Unwind_Control_B" ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c_88 {
   meta:
      description = "apk - from files 01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c3.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 17fc5d1c8bd8b10471131282e42ec289bb1e1ee107ca676f369bb42fc3643af3.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 3502fa570ada49eaeeaa4785bb1897ed91dfadaa76c5e8626c5b8e944d8f5f01.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 57940c5eee8641e02f49d1122528665a0ddfbf5b6b0d4b910b5287e15542591d.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 6376bcd8faa57aac7437116b184967a588025e2bf96318272cdcf51ff2f8dfdd.apk, 6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e.apk, 6eb525100f54b9a830cd2d0f1169b053edb55332b2be73dd29a8b165b9ccdbf5.apk, 6f58b07b5ddabc29c9c7e7165349edbd2bee923446514044d67040de2f36664a.apk, 7593b0f4bc4c52cb359196f35868636b319641b01c8db9f662076285739a0505.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a6ed100ae42e4fdabfd1b4c992762152bc4a11cc8e521b647b444c75bb7a9782.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, b1c3a8818024ee86480bb83ea405ba2d9f96ea279e5cf9df19b3d3cb934ec42d.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, b99d175cbe06d4569a18449da044f326c68a56315ccc0da9cfa6f2c33bfd0939.apk, bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, c54861f54bcf72de5f16611ef0eec32c5c5f937bf3fdb5d6e611b2a2f9acdf2a.apk, c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64.apk, cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c.apk, d0d4ef735a8bf076d81a6f3651d6bcfd8c69285049add2e6b6bee1276a99c37c.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, ef16cc8137d29356d0ef23b61ddb9cfd5e2784578fa818d54fe670bfa1e6ef73.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0"
      hash2 = "0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169"
      hash3 = "0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c3"
      hash4 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash5 = "134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138"
      hash6 = "17fc5d1c8bd8b10471131282e42ec289bb1e1ee107ca676f369bb42fc3643af3"
      hash7 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash8 = "3502fa570ada49eaeeaa4785bb1897ed91dfadaa76c5e8626c5b8e944d8f5f01"
      hash9 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash10 = "41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7"
      hash11 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash12 = "53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee"
      hash13 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash14 = "57940c5eee8641e02f49d1122528665a0ddfbf5b6b0d4b910b5287e15542591d"
      hash15 = "5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8"
      hash16 = "6376bcd8faa57aac7437116b184967a588025e2bf96318272cdcf51ff2f8dfdd"
      hash17 = "6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e"
      hash18 = "6eb525100f54b9a830cd2d0f1169b053edb55332b2be73dd29a8b165b9ccdbf5"
      hash19 = "6f58b07b5ddabc29c9c7e7165349edbd2bee923446514044d67040de2f36664a"
      hash20 = "7593b0f4bc4c52cb359196f35868636b319641b01c8db9f662076285739a0505"
      hash21 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
      hash22 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash23 = "8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af"
      hash24 = "8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e"
      hash25 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash26 = "a6ed100ae42e4fdabfd1b4c992762152bc4a11cc8e521b647b444c75bb7a9782"
      hash27 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash28 = "b1c3a8818024ee86480bb83ea405ba2d9f96ea279e5cf9df19b3d3cb934ec42d"
      hash29 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash30 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash31 = "b99d175cbe06d4569a18449da044f326c68a56315ccc0da9cfa6f2c33bfd0939"
      hash32 = "bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7"
      hash33 = "bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0"
      hash34 = "c54861f54bcf72de5f16611ef0eec32c5c5f937bf3fdb5d6e611b2a2f9acdf2a"
      hash35 = "c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64"
      hash36 = "cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c"
      hash37 = "d0d4ef735a8bf076d81a6f3651d6bcfd8c69285049add2e6b6bee1276a99c37c"
      hash38 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash39 = "ef16cc8137d29356d0ef23b61ddb9cfd5e2784578fa818d54fe670bfa1e6ef73"
      hash40 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
      hash41 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = " Google Play services " fullword ascii
      $s2 = " Google Play Services-" fullword ascii
      $s3 = "%1$s Google Play " fullword ascii
      $s4 = "?@%1$s ten problemas cos servizos de Google Play. T" fullword ascii
      $s5 = "a s uslugama Google Playa. Poku" fullword ascii
      $s6 = ";;%1$s ima problema sa Google Play uslugama. Probajte ponovo." fullword ascii
      $s7 = "nda problem var. Daha sonra yenid" fullword ascii
      $s8 = "EERakendusel %1$s on probleeme Google Play teenustega. Proovige uuesti." fullword ascii
      $s9 = "KK%1$s menghadapi masalah berhubung perkhidmatan Google Play. Sila cuba lagi." fullword ascii
      $s10 = "HH%1$s ondervind probleme met Google Play Dienste. Probeer asseblief weer." fullword ascii
      $s11 = "os do Google Play. Tente novamente." fullword ascii
      $s12 = "FGAplikacija %1$s ima problema s Google Play uslugama. Poku" fullword ascii
      $s13 = " problemes amb Serveis de Google Play. Torna-ho a provar." fullword ascii
      $s14 = "nustu Google Play. Reyndu aftur." fullword ascii
      $s15 = " probleme privind serviciile Google Play. " fullword ascii
      $s16 = "ma ar Google Play pakalpojumu darb" fullword ascii
      $s17 = "rbimet e Google Play. Provo s" fullword ascii
      $s18 = "KK%1$s inakumbwa na hitilafu ya huduma za Google Play. Tafadhali jaribu tena." fullword ascii
      $s19 = "==%1$s inenkinga ngamasevisi e-Google Play. Sicela uzame futhi." fullword ascii
      $s20 = " Google Play xidm" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _0596a76e6772acb911c1a556ad86943224873411fba4383abade25300078ed3_89 {
   meta:
      description = "apk - from files 0596a76e6772acb911c1a556ad86943224873411fba4383abade25300078ed32.apk, 17a68e32e5d8398c93790abe9b117c472557b54ccdcfccfdddb3b7f783ca31b3.apk, 1d9bdb35234b01d219fd28c47a47bbaa6c9033e2b1f35b07f10cf09eaed00254.apk, 238eeea51b2d53ff08b3129fe6d6be75a13c12090e4063a1455fad614054d4b3.apk, 2b7e044edadb6932c251f2169da0a777bf553a549a263c5c8a0cf9d888cee704.apk, 2f595b306756f39b0d525b19d5f5c1d50a5e6761ea049a63a390ec3e6709a2ba.apk, 39c97fad655efc5aa4bc3703695b80e9807b14050fe9c8785cd047d3f3051668.apk, 4af08f08377457cb04e280615fc8647870f9b20ad763e1bd060731605d8a0c07.apk, 4bdf7226644876c09e6091127260593a4f7af3b78d148b56004eb1be09bdf4b8.apk, 557c02b5e9ca8103e6ad5413df1b447fae5c9ce086a0b5330bf9c79a578585df.apk, 57151572cf361d49ead0235eef7cad3827f4711120f3397e746a660aa9c6250b.apk, 5a8d4eabd009a75ecc04f3f06489d393f082f963b406d0d3e8acbea568281c5f.apk, 8613f7b6df514d53aa419355b0a3e8d032b8448bd45296d4158b848998015e3d.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c4f8053881899f844a2e6dea8ce119124acac2b34750a47650e368c27bf7a3b.apk, 9aff583b812a3979394ffcd23f616d561a0eda4002f2e2a4b42ea5ba3efdbfaf.apk, adefc2f666aa936763b18300444995e1d2a4c1950ef00577de7a88381b825c1f.apk, b8fa21bbd5261f2308a168c1f43b197220c0d37bdda0c4a1464be085a9f85300.apk, c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64.apk, dd0919967c57cdabdf8b5bc9c643bb0d250fe935476aa4944544b22132d5163d.apk, e4aa98c1beee901871fd8a78b37b21ef886e507e65fc6499e3df3769081cd1cb.apk, e7aa84c2b3ac31d3a948f0431cdbf7b28116fffb157b8e99e8efe455c92dd661.apk, e9b41fd64d8702f974e63374a03ad914b6f1b24e8ddd96c29ff14ce81713676f.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "0596a76e6772acb911c1a556ad86943224873411fba4383abade25300078ed32"
      hash2 = "17a68e32e5d8398c93790abe9b117c472557b54ccdcfccfdddb3b7f783ca31b3"
      hash3 = "1d9bdb35234b01d219fd28c47a47bbaa6c9033e2b1f35b07f10cf09eaed00254"
      hash4 = "238eeea51b2d53ff08b3129fe6d6be75a13c12090e4063a1455fad614054d4b3"
      hash5 = "2b7e044edadb6932c251f2169da0a777bf553a549a263c5c8a0cf9d888cee704"
      hash6 = "2f595b306756f39b0d525b19d5f5c1d50a5e6761ea049a63a390ec3e6709a2ba"
      hash7 = "39c97fad655efc5aa4bc3703695b80e9807b14050fe9c8785cd047d3f3051668"
      hash8 = "4af08f08377457cb04e280615fc8647870f9b20ad763e1bd060731605d8a0c07"
      hash9 = "4bdf7226644876c09e6091127260593a4f7af3b78d148b56004eb1be09bdf4b8"
      hash10 = "557c02b5e9ca8103e6ad5413df1b447fae5c9ce086a0b5330bf9c79a578585df"
      hash11 = "57151572cf361d49ead0235eef7cad3827f4711120f3397e746a660aa9c6250b"
      hash12 = "5a8d4eabd009a75ecc04f3f06489d393f082f963b406d0d3e8acbea568281c5f"
      hash13 = "8613f7b6df514d53aa419355b0a3e8d032b8448bd45296d4158b848998015e3d"
      hash14 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash15 = "8c4f8053881899f844a2e6dea8ce119124acac2b34750a47650e368c27bf7a3b"
      hash16 = "9aff583b812a3979394ffcd23f616d561a0eda4002f2e2a4b42ea5ba3efdbfaf"
      hash17 = "adefc2f666aa936763b18300444995e1d2a4c1950ef00577de7a88381b825c1f"
      hash18 = "b8fa21bbd5261f2308a168c1f43b197220c0d37bdda0c4a1464be085a9f85300"
      hash19 = "c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64"
      hash20 = "dd0919967c57cdabdf8b5bc9c643bb0d250fe935476aa4944544b22132d5163d"
      hash21 = "e4aa98c1beee901871fd8a78b37b21ef886e507e65fc6499e3df3769081cd1cb"
      hash22 = "e7aa84c2b3ac31d3a948f0431cdbf7b28116fffb157b8e99e8efe455c92dd661"
      hash23 = "e9b41fd64d8702f974e63374a03ad914b6f1b24e8ddd96c29ff14ce81713676f"
   strings:
      $s1 = "Toggle drop-down menu" fullword ascii
      $s2 = "I-toggle ang dropdown menu" fullword ascii
      $s3 = " lub ukryj menu" fullword ascii
      $s4 = "\"\"Aktifkan/nonaktifkan menu dropdown" fullword ascii
      $s5 = "sactiver le menu d" fullword ascii
      $s6 = "Toggle dropdown menu" fullword ascii
      $s7 = "Skift visningen af rullemenuen" fullword ascii
      $s8 = "  Ativar/desativar o menu suspenso" fullword ascii
      $s9 = "Ativar/desativar menu pendente" fullword ascii
      $s10 = "\"#Ouvrir ou fermer le menu d" fullword ascii
      $s11 = "Wissel aftrekkieslys" fullword ascii
      $s12 = "Togol menu lungsur" fullword ascii
      $s13 = "Attiva/disattiva menu a discesa" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _02437104c17dda825ba58e363f3eb11668b068f0fb66f31925c1a867899d127_90 {
   meta:
      description = "apk - from files 02437104c17dda825ba58e363f3eb11668b068f0fb66f31925c1a867899d1271.apk, 34670aa23c3e50240fab2f820652f3f5d6eabf7177c6d6d4bba6c39a7b11aff9.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "02437104c17dda825ba58e363f3eb11668b068f0fb66f31925c1a867899d1271"
      hash2 = "34670aa23c3e50240fab2f820652f3f5d6eabf7177c6d6d4bba6c39a7b11aff9"
   strings:
      $s1 = "~~Too many attempts. Try again after %d seconds." fullword ascii
      $s2 = "88Delete \"%s\" group?" fullword ascii
      $s3 = "n this setting back on at any time." fullword ascii
      $s4 = "8, will be able to access it." fullword ascii
      $s5 = "evice-confirmation-learn-more\">Learn more</a>" fullword ascii
      $s6 = "AADelete \"%s\" broadcast list?" fullword ascii
      $s7 = "{Custom ROMs have been known to cause problems with keyboard input methods, cloud to device (C2DM) notifications as well as time" ascii
      $s8 = "all locally stored data and is not reversible." fullword ascii
      $s9 = "all it again." fullword ascii
      $s10 = " Group admins control who can change this setting. <a href=\"learn-more\">Learn" fullword ascii
      $s11 = "<<Delete broadcast list?" fullword ascii
      $s12 = " precautions, this file cannot be sent." fullword ascii
      $s13 = " control who can change this setting. <a href=\"learn-more\">Learn" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b9189_91 {
   meta:
      description = "apk - from files 29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896.apk, b3c86606b1410cc558acef06d55c2a03d41ad85cb2b04e904640f58b23185db3.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896"
      hash2 = "b3c86606b1410cc558acef06d55c2a03d41ad85cb2b04e904640f58b23185db3"
      hash3 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
   strings:
      $s1 = " panel navigace" fullword ascii
      $s2 = "rz panel nawigacji" fullword ascii
      $s3 = "Abrir o panel de navegaci" fullword ascii
      $s4 = "Buksan ang navigation drawer" fullword ascii
      $s5 = "!\"Abrir panel lateral de navegaci" fullword ascii
      $s6 = "Ouvrir le panneau de navigation" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c_92 {
   meta:
      description = "apk - from files 01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c3.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 17fc5d1c8bd8b10471131282e42ec289bb1e1ee107ca676f369bb42fc3643af3.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 3502fa570ada49eaeeaa4785bb1897ed91dfadaa76c5e8626c5b8e944d8f5f01.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 57940c5eee8641e02f49d1122528665a0ddfbf5b6b0d4b910b5287e15542591d.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 6376bcd8faa57aac7437116b184967a588025e2bf96318272cdcf51ff2f8dfdd.apk, 6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e.apk, 6eb525100f54b9a830cd2d0f1169b053edb55332b2be73dd29a8b165b9ccdbf5.apk, 6f58b07b5ddabc29c9c7e7165349edbd2bee923446514044d67040de2f36664a.apk, 7593b0f4bc4c52cb359196f35868636b319641b01c8db9f662076285739a0505.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e.apk, a2f827bcb3acc7ccfc45f202a0e8adae2cd6439ae46d0d4d401a418846761a2e.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a6ed100ae42e4fdabfd1b4c992762152bc4a11cc8e521b647b444c75bb7a9782.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, b1c3a8818024ee86480bb83ea405ba2d9f96ea279e5cf9df19b3d3cb934ec42d.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, b99d175cbe06d4569a18449da044f326c68a56315ccc0da9cfa6f2c33bfd0939.apk, bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, c54861f54bcf72de5f16611ef0eec32c5c5f937bf3fdb5d6e611b2a2f9acdf2a.apk, c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64.apk, cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c.apk, d0d4ef735a8bf076d81a6f3651d6bcfd8c69285049add2e6b6bee1276a99c37c.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, ef16cc8137d29356d0ef23b61ddb9cfd5e2784578fa818d54fe670bfa1e6ef73.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0"
      hash2 = "0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169"
      hash3 = "0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c3"
      hash4 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash5 = "134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138"
      hash6 = "17fc5d1c8bd8b10471131282e42ec289bb1e1ee107ca676f369bb42fc3643af3"
      hash7 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash8 = "3502fa570ada49eaeeaa4785bb1897ed91dfadaa76c5e8626c5b8e944d8f5f01"
      hash9 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash10 = "41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7"
      hash11 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash12 = "53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee"
      hash13 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash14 = "57940c5eee8641e02f49d1122528665a0ddfbf5b6b0d4b910b5287e15542591d"
      hash15 = "5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8"
      hash16 = "6376bcd8faa57aac7437116b184967a588025e2bf96318272cdcf51ff2f8dfdd"
      hash17 = "6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e"
      hash18 = "6eb525100f54b9a830cd2d0f1169b053edb55332b2be73dd29a8b165b9ccdbf5"
      hash19 = "6f58b07b5ddabc29c9c7e7165349edbd2bee923446514044d67040de2f36664a"
      hash20 = "7593b0f4bc4c52cb359196f35868636b319641b01c8db9f662076285739a0505"
      hash21 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
      hash22 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash23 = "8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af"
      hash24 = "8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e"
      hash25 = "a2f827bcb3acc7ccfc45f202a0e8adae2cd6439ae46d0d4d401a418846761a2e"
      hash26 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash27 = "a6ed100ae42e4fdabfd1b4c992762152bc4a11cc8e521b647b444c75bb7a9782"
      hash28 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash29 = "b1c3a8818024ee86480bb83ea405ba2d9f96ea279e5cf9df19b3d3cb934ec42d"
      hash30 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash31 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash32 = "b99d175cbe06d4569a18449da044f326c68a56315ccc0da9cfa6f2c33bfd0939"
      hash33 = "bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7"
      hash34 = "bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0"
      hash35 = "c54861f54bcf72de5f16611ef0eec32c5c5f937bf3fdb5d6e611b2a2f9acdf2a"
      hash36 = "c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64"
      hash37 = "cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c"
      hash38 = "d0d4ef735a8bf076d81a6f3651d6bcfd8c69285049add2e6b6bee1276a99c37c"
      hash39 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash40 = "ef16cc8137d29356d0ef23b61ddb9cfd5e2784578fa818d54fe670bfa1e6ef73"
      hash41 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
      hash42 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = " com problemas com o Google Play Services. Tente novamente." fullword ascii
      $s2 = "AA%1$s sta riscontrando problemi con Google Play Services. Riprova." fullword ascii
      $s3 = "LO%1$s, Google Play hizmetleriyle ilgili sorun ya" fullword ascii
      $s4 = "HH%1$s ondervindt problemen met Google Play-services. Probeer het opnieuw." fullword ascii
      $s5 = "==%1$s mengalami masalah dengan layanan Google Play. Coba lagi." fullword ascii
      $s6 = " kilo problem" fullword ascii
      $s7 = " Google Play. " fullword ascii
      $s8 = "bami Google Play. Sk" fullword ascii
      $s9 = "EH%1$s ma problem z dost" fullword ascii
      $s10 = "XeNaudojant program" fullword ascii
      $s11 = "ave s storitvami Google Play. Poskusite znova." fullword ascii
      $s12 = "OS%1$s ilovasini Google Play xizmatlariga ulab bo" fullword ascii
      $s13 = "ug Google Play. Spr" fullword ascii
      $s14 = "Play. Veuillez r" fullword ascii
      $s15 = "bami Google Play. Zkuste to pros" fullword ascii
      $s16 = "]`L'application %1$s rencontre des probl" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _14c47030d8220e682a1ec80c87d56c5bacf7a38abdf30df9bb532a85851259a_93 {
   meta:
      description = "apk - from files 14c47030d8220e682a1ec80c87d56c5bacf7a38abdf30df9bb532a85851259af.apk, 1d15f0700a2dda228394bf37ad20ad2bd88c7813d6aca0199a6b40c704f80bc1.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "14c47030d8220e682a1ec80c87d56c5bacf7a38abdf30df9bb532a85851259af"
      hash2 = "1d15f0700a2dda228394bf37ad20ad2bd88c7813d6aca0199a6b40c704f80bc1"
   strings:
      $s1 = "d-to-end encrypted backup." fullword ascii
      $s2 = " the community." fullword ascii
      $s3 = "er service team." fullword ascii
      $s4 = "GGDelete \"%s\" group?" fullword ascii
      $s5 = ", and install it again." fullword ascii
      $s6 = "p to change." fullword ascii
      $s7 = "ap to change." fullword ascii
      $s8 = "pt. Tap to change." fullword ascii
      $s9 = "w phone number." fullword ascii
      $s10 = "ef=\"device-confirmation-learn-more\">Learn more</a>" fullword ascii
      $s11 = "and receive SMS." fullword ascii
      $s12 = "earn more</a>" fullword ascii
      $s13 = "again later." fullword ascii
      $s14 = "PPDelete \"%s\" broadcast list?" fullword ascii
      $s15 = "peration will erase all locally stored data and is not reversible." fullword ascii
      $s16 = "trust." fullword ascii
      $s17 = "oup and try again." fullword ascii
      $s18 = "urity precautions, this file cannot be sent." fullword ascii
      $s19 = "oup admins control who can change this setting. <a href=\"learn-more\">Learn" fullword ascii
      $s20 = "KKDelete broadcast list?" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f557_94 {
   meta:
      description = "apk - from files 7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570"
      hash2 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
   strings:
      $s1 = " Suspendisse interdum ornare ante. Aliquam nec cursus lorem. Morbi id magna felis. Vivamus egestas, est a condimentum egestas, t" ascii
      $s2 = "vulputate quis. Aliquam eget libero aliquet, imperdiet nisl a, ornare ex. Sed rhoncus est ut libero porta lobortis. Fusce in dic" ascii
      $s3 = " Aenean nunc velit, lacinia sed dolor sed, ultrices viverra nulla. Etiam a venenatis nibh. Morbi laoreet, tortor sed facilisis v" ascii
      $s4 = "urpis nisl iaculis ipsum, in dictum tellus dolor sed neque. Morbi tellus erat, dapibus ut sem a, iaculis tincidunt dui. Interdum" ascii
      $s5 = "justo luctus vestibulum. Fusce dictum libero quis erat maximus, vitae volutpat diam dignissim." fullword ascii
      $s6 = " Phasellus in aliquet mi. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. In volut" ascii
      $s7 = "lacerat ac. Duis finibus orci et est auctor tincidunt. Sed non viverra ipsum. Nunc quis augue egestas, cursus lorem at, molestie" ascii
      $s8 = " sem. Morbi a consectetur ipsum, a placerat diam. Etiam vulputate dignissim convallis. Integer faucibus mauris sit amet finibus " ascii
      $s9 = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nam in scelerisque sem. Mauris volutpat, dolor id interdum ullamcorper," ascii
      $s10 = " sed commodo. In eros nisl, imperdiet vel imperdiet et, scelerisque a mauris. Pellentesque varius ex nunc, quis imperdiet eros p" ascii
      $s11 = "s at commodo eros, non aliquet metus. Sed maximus nisl nec dolor bibendum, vel congue leo egestas." fullword ascii
      $s12 = " et malesuada fames ac ante ipsum primis in faucibus. Curabitur et eros porttitor, ultricies urna vitae, molestie nibh. Phasellu" ascii
      $s13 = " Sed interdum tortor nibh, in sagittis risus mollis quis. Curabitur mi odio, condimentum sit amet auctor at, mollis non turpis. " ascii
      $s14 = "stique id quam. Cras eu consequat dui. Suspendisse sodales nunc ligula, in lobortis sem porta sed. Integer id ultrices magna, in" ascii
      $s15 = "isis et. Integer interdum nunc ligula, et fermentum metus hendrerit id. Vestibulum lectus felis, dictum at lacinia sit amet, tri" ascii
      $s16 = "Second Fragment" fullword ascii
      $s17 = " Aenean nunc velit, lacinia sed dolor sed, ultrices viverra nulla. Etiam a venenatis nibh. Morbi laoreet, tortor sed facilisis v" ascii
      $s18 = "Nullam pretium libero vestibulum, finibus orci vel, molestie quam. Fusce blandit tincidunt nulla, quis sollicitudin libero facil" ascii
      $s19 = "lus nec feugiat. In a ornare nulla. Donec rhoncus libero vel nunc consequat, quis tincidunt nisl eleifend. Cras bibendum enim a " ascii
      $s20 = " Phasellus in aliquet mi. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. In volut" ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb4_95 {
   meta:
      description = "apk - from files 017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44.apk, 01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0.apk, 0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e.apk, 08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c.apk, 11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c.apk, 29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896.apk, 31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b.apk, 392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec.apk, 41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2.apk, 41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7.apk, 48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce.apk, 4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f.apk, 4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088.apk, 4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b.apk, 5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3.apk, 65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf.apk, 6b0c56540499051ab350a31f417b99859da7ed7286b9e77503711c6aabafbe03.apk, 6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8.apk, 6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd.apk, 6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738.apk, 73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4.apk, 7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144.apk, 8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552.apk, 83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025.apk, 90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a.apk, 9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5.apk, 9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d.apk, 9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c.apk, 9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90.apk, a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5.apk, a2c509d0b0fcee3bc503bd12986da2d29c74ebcd37abb1af8988f7f26382663d.apk, a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de.apk, bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6.apk, bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7.apk, c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14.apk, c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9.apk, c659454dd6ed62bc7a0c9e0455297e41ba57b0b7935a826150c1f8c0db6f89d2.apk, cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c.apk, ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642.apk, d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af.apk, d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3.apk, d3fc5ffdd9a68a3063b1c8ff15334238dd39a63b9c93ec9f337bdd5f5357046a.apk, d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372.apk, d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe.apk, d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d.apk, decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8.apk, e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938.apk, e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75.apk, e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8.apk, e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf.apk, f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738.apk, faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44"
      hash2 = "01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0"
      hash3 = "0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e"
      hash4 = "08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c"
      hash5 = "11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415"
      hash6 = "134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138"
      hash7 = "1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c"
      hash8 = "29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896"
      hash9 = "31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b"
      hash10 = "392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d"
      hash11 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash12 = "3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec"
      hash13 = "41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2"
      hash14 = "41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7"
      hash15 = "48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce"
      hash16 = "4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f"
      hash17 = "4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088"
      hash18 = "4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7"
      hash19 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash20 = "563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b"
      hash21 = "5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a"
      hash22 = "5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8"
      hash23 = "6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3"
      hash24 = "65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf"
      hash25 = "6b0c56540499051ab350a31f417b99859da7ed7286b9e77503711c6aabafbe03"
      hash26 = "6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8"
      hash27 = "6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd"
      hash28 = "6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738"
      hash29 = "73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4"
      hash30 = "7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144"
      hash31 = "8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552"
      hash32 = "83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025"
      hash33 = "90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a"
      hash34 = "9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5"
      hash35 = "9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d"
      hash36 = "9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c"
      hash37 = "9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90"
      hash38 = "a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5"
      hash39 = "a2c509d0b0fcee3bc503bd12986da2d29c74ebcd37abb1af8988f7f26382663d"
      hash40 = "a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2"
      hash41 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash42 = "a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa"
      hash43 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash44 = "ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de"
      hash45 = "bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6"
      hash46 = "bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7"
      hash47 = "c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14"
      hash48 = "c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9"
      hash49 = "c659454dd6ed62bc7a0c9e0455297e41ba57b0b7935a826150c1f8c0db6f89d2"
      hash50 = "cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c"
      hash51 = "ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642"
      hash52 = "d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af"
      hash53 = "d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3"
      hash54 = "d3fc5ffdd9a68a3063b1c8ff15334238dd39a63b9c93ec9f337bdd5f5357046a"
      hash55 = "d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372"
      hash56 = "d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe"
      hash57 = "d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d"
      hash58 = "decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8"
      hash59 = "e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938"
      hash60 = "e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75"
      hash61 = "e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8"
      hash62 = "e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf"
      hash63 = "f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738"
      hash64 = "faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee"
      hash65 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
   strings:
      $s1 = "tunu: %1$s" fullword ascii
      $s2 = "Colonne des jours" fullword ascii
      $s3 = "Column ng mga araw: %1$s" fullword ascii
      $s4 = "((Alternar para o modo de entrada de texto" fullword ascii
      $s5 = "evade veerg: %1$s" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210_96 {
   meta:
      description = "apk - from files 05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a.apk, 0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd.apk, 0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072.apk, 13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52.apk, 1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90.apk, 22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b.apk, 2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0.apk, 3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c.apk, 5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8.apk, 6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22.apk, 9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d.apk, 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk, aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8.apk, b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk, b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e.apk, ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33.apk, e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b.apk, f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk, f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a"
      hash2 = "0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd"
      hash3 = "0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072"
      hash4 = "13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52"
      hash5 = "1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90"
      hash6 = "22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b"
      hash7 = "2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0"
      hash8 = "3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c"
      hash9 = "5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8"
      hash10 = "6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22"
      hash11 = "9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d"
      hash12 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
      hash13 = "aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8"
      hash14 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
      hash15 = "b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e"
      hash16 = "ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33"
      hash17 = "e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b"
      hash18 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
      hash19 = "f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65"
   strings:
      $s1 = "Network: Error" fullword ascii
      $s2 = "==Use Transport Layer Security (TLS) when connecting to server." fullword ascii
      $s3 = "Network: TLS error" fullword ascii
      $s4 = "  No network connection available." fullword ascii
      $s5 = "Android Version" fullword ascii
      $s6 = "Network Settings" fullword ascii
      $s7 = "Replay Mode" fullword ascii
      $s8 = "Enable Workaround" fullword ascii
      $s9 = "Enables replay over network" fullword ascii
      $s10 = "Waiting for Tag" fullword ascii
      $s11 = "##Sets reply mode for replay requests" fullword ascii
      $s12 = "Replay mode" fullword ascii
      $s13 = "Replay Settings" fullword ascii
      $s14 = "Clone Mode" fullword ascii
      $s15 = "Advanced Replay" fullword ascii
      $s16 = "NFC is disabled or unsupported." fullword ascii
      $s17 = "77User preferences for certificate trust have been reset!" fullword ascii
      $s18 = "JJResets user preferences for all manually trusted/blocked TLS certificates." fullword ascii
      $s19 = "NFC Chip" fullword ascii
      $s20 = "Network: Certificate unknown" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b_97 {
   meta:
      description = "apk - from files 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90.apk, 2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0.apk, 3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c.apk, aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33.apk, ef16cc8137d29356d0ef23b61ddb9cfd5e2784578fa818d54fe670bfa1e6ef73.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash2 = "1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90"
      hash3 = "2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0"
      hash4 = "3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c"
      hash5 = "aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8"
      hash6 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash7 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash8 = "ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33"
      hash9 = "ef16cc8137d29356d0ef23b61ddb9cfd5e2784578fa818d54fe670bfa1e6ef73"
      hash10 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
      hash11 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "nk kopierad till Urklipp" fullword ascii
      $s2 = "Link kopeeriti l" fullword ascii
      $s3 = "Link naar klembord gekopieerd" fullword ascii
      $s4 = "%%Link je kopiran u privremenu memoriju" fullword ascii
      $s5 = "Link skopiowany do schowka" fullword ascii
      $s6 = "Link disalin ke papan klip" fullword ascii
      $s7 = "Link bufer" fullword ascii
      $s8 = "*,Link copiado para a " fullword ascii
      $s9 = "Nakopya sa clipboard ang link" fullword ascii
      $s10 = "Link v" fullword ascii
      $s11 = "Link je kopiran u me" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb4_98 {
   meta:
      description = "apk - from files 017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44.apk, 01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0.apk, 0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e.apk, 05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a.apk, 08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd.apk, 0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072.apk, 11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea.apk, 13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52.apk, 1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c.apk, 1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0.apk, 22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b.apk, 23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61.apk, 29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b.apk, 3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089.apk, 34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45.apk, 392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647.apk, 3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec.apk, 41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2.apk, 41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce.apk, 4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f.apk, 4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290.apk, 4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088.apk, 4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b.apk, 5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8.apk, 5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3.apk, 6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3.apk, 65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf.apk, 6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22.apk, 6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8.apk, 6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd.apk, 6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738.apk, 73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4.apk, 73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a.apk, 78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b.apk, 7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, 8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552.apk, 83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a.apk, 9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5.apk, 9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d.apk, 9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d.apk, 9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c.apk, 9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90.apk, 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk, 9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6.apk, a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5.apk, a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de.apk, b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk, b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e.apk, b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6.apk, bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14.apk, c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9.apk, c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk, ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642.apk, d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af.apk, d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3.apk, d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372.apk, d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe.apk, d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d.apk, d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38.apk, decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8.apk, e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3.apk, e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938.apk, e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75.apk, e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b.apk, e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8.apk, e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk, f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2.apk, f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738.apk, f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65.apk, faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44"
      hash2 = "01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0"
      hash3 = "0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e"
      hash4 = "05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a"
      hash5 = "08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c"
      hash6 = "0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169"
      hash7 = "0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd"
      hash8 = "0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072"
      hash9 = "11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415"
      hash10 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash11 = "134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138"
      hash12 = "1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea"
      hash13 = "13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52"
      hash14 = "1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c"
      hash15 = "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
      hash16 = "22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b"
      hash17 = "23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61"
      hash18 = "29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896"
      hash19 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash20 = "31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b"
      hash21 = "3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089"
      hash22 = "34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45"
      hash23 = "392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d"
      hash24 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash25 = "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
      hash26 = "3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec"
      hash27 = "41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2"
      hash28 = "41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7"
      hash29 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash30 = "48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce"
      hash31 = "4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f"
      hash32 = "4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290"
      hash33 = "4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088"
      hash34 = "4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7"
      hash35 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash36 = "563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b"
      hash37 = "5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8"
      hash38 = "5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a"
      hash39 = "5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8"
      hash40 = "64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3"
      hash41 = "6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3"
      hash42 = "65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf"
      hash43 = "6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22"
      hash44 = "6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8"
      hash45 = "6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd"
      hash46 = "6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738"
      hash47 = "73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4"
      hash48 = "73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a"
      hash49 = "78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b"
      hash50 = "7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144"
      hash51 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
      hash52 = "8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552"
      hash53 = "83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025"
      hash54 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash55 = "8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af"
      hash56 = "90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a"
      hash57 = "9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5"
      hash58 = "9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d"
      hash59 = "9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d"
      hash60 = "9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c"
      hash61 = "9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90"
      hash62 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
      hash63 = "9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6"
      hash64 = "a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5"
      hash65 = "a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2"
      hash66 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash67 = "a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa"
      hash68 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash69 = "ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de"
      hash70 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
      hash71 = "b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e"
      hash72 = "b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99"
      hash73 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash74 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash75 = "bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6"
      hash76 = "bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7"
      hash77 = "bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0"
      hash78 = "c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14"
      hash79 = "c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9"
      hash80 = "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
      hash81 = "ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642"
      hash82 = "d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af"
      hash83 = "d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3"
      hash84 = "d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372"
      hash85 = "d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe"
      hash86 = "d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d"
      hash87 = "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
      hash88 = "decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8"
      hash89 = "e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3"
      hash90 = "e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938"
      hash91 = "e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75"
      hash92 = "e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b"
      hash93 = "e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8"
      hash94 = "e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf"
      hash95 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash96 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
      hash97 = "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
      hash98 = "f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738"
      hash99 = "f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65"
      hash100 = "faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee"
      hash101 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
      hash102 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "Ikona dialogov" fullword ascii
      $s2 = "Ikona dijaloga" fullword ascii
      $s3 = "Ikona e dialogut" fullword ascii
      $s4 = "Icon ng Dialog" fullword ascii
      $s5 = "ikona dijalo" fullword ascii
      $s6 = "Ikona dial" fullword ascii
      $s7 = "Ikona pogovornega okna" fullword ascii
      $s8 = "cone de caixa de di" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _0619168a8df6dd350052ca3a578abe15da0f2177e65acea55f44b5b59ed5f1c_99 {
   meta:
      description = "apk - from files 0619168a8df6dd350052ca3a578abe15da0f2177e65acea55f44b5b59ed5f1c8.apk, 0badd9b4b0e44daeaa75b5d97ed9611a9f84418c1fb5683130e8b22742086549.apk, 0c8085cea946d655b266998fd60b1da33df73a4285328da3dabc7f0e7211411d.apk, 2a5f808f305334a0cfec1daa7290ace649079ab9c6dbed43f77ffdccb55c6e31.apk, 3638754e7fd889e9ced9127e7abe08191b7e8df3d60ed284c7b507e1e8082613.apk, 399c4819af422e581639c9350dcba71b0ee00b87a4d37da11806db5e25a0adc5.apk, 3ab3cc3c0df02d723c850e712fa5f4a0de29f2addf2c50beffe222112c2baa38.apk, 3c0a6f866aa4d74d0b39a2b9d11692ffa7291fd46b414e73cd5f9c7f9f030b75.apk, 41930e6f9187c8be4ea41303dd957d74f65b97944321a24a20028e76d10e0588.apk, 4845bbe3b1f17da3783db71b6a471b9dc073c8459fe2981004fbbcd70144ec01.apk, 4f0508904ec488ea7767e9d124b78097aefa8f43cc1713e81a7c4f45e1ba77f0.apk, 51863351193ab67148e3e47255cad4927eb13939292c7854121ebedb4de28590.apk, 63a19cd37e5f23ba982d004e587472bdc30d64af04e1b321419d8173a16c60cc.apk, 662bb00e9a82d43be45413fce12def326a1863f9cd3e63aa45b60d36ef7e0443.apk, 6a702c55f4ee54eeb35a991d7413328da1e56dde6e719babec23682423bec23f.apk, 75b4d9eb26ed9e20009c9a55a58e66457d7ec4d7d060179f09f6522e96c62e2e.apk, 7b167d362a9282adb176095be2e5bd4692b4158b7bdf4c6c20870daed5b04665.apk, 904e4153d2026380dc42297173192e72de7e5d9ea50f16bf8df2e2fa6922cdc3.apk, 95e88ec3ceb56c7f3679c45b837f931d0b38269a2e275628f2bc1a9f5c77a19f.apk, 9ae895cd6474d1928bbbd68e240679c9de3c0ca327ac4e4b83845878b72322be.apk, a0edfa97344c870ee24aa7c008cec40e85e616c21e86522b8f6fce0324b356f7.apk, b4b2197c5a8f0e9b9766fa39e9b538568284ec8a0099811b8b54fe6a1402545b.apk, be8adc196213154b10bd4209098ff94083d5ade71abeeacbf9d4cf30e3403234.apk, ca5b40e938f68321dfa3a7f1ad2a03db4ff6ba27fdae5e230654cd5c30090692.apk, d5a84c85508c444743d055be354a464eb22dc5b33cba41e4b149829d182f4dca.apk, d69108a94a9a81e07a05d456dc997cbf5b5a8cc8f0869eae7904fac1da60f335.apk, d9b75d606803968d04015bed042da887905e9c1cb1b40b4ff11852b88c8b4d21.apk, ddeb13abf09d096f821ee657c3479f799f2a236b49f46c80a0afb2676a8f55ab.apk, dfa3539353b89089a3599f4775a296b270751738186af515bf3e630dc054bc7d.apk, e163a088d174d4eb41479b53e6df04831dc40899b893a0b183d080d2dfe52cd7.apk, ee9eceda9522ae4c5ff3e07aefa523c61d50ebb9aca2808e0f4494a8c53498ea.apk, faab917444988b9a2e8d5d5bc06a0423c53718f92cbb8840cc6632f464c89130.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "0619168a8df6dd350052ca3a578abe15da0f2177e65acea55f44b5b59ed5f1c8"
      hash2 = "0badd9b4b0e44daeaa75b5d97ed9611a9f84418c1fb5683130e8b22742086549"
      hash3 = "0c8085cea946d655b266998fd60b1da33df73a4285328da3dabc7f0e7211411d"
      hash4 = "2a5f808f305334a0cfec1daa7290ace649079ab9c6dbed43f77ffdccb55c6e31"
      hash5 = "3638754e7fd889e9ced9127e7abe08191b7e8df3d60ed284c7b507e1e8082613"
      hash6 = "399c4819af422e581639c9350dcba71b0ee00b87a4d37da11806db5e25a0adc5"
      hash7 = "3ab3cc3c0df02d723c850e712fa5f4a0de29f2addf2c50beffe222112c2baa38"
      hash8 = "3c0a6f866aa4d74d0b39a2b9d11692ffa7291fd46b414e73cd5f9c7f9f030b75"
      hash9 = "41930e6f9187c8be4ea41303dd957d74f65b97944321a24a20028e76d10e0588"
      hash10 = "4845bbe3b1f17da3783db71b6a471b9dc073c8459fe2981004fbbcd70144ec01"
      hash11 = "4f0508904ec488ea7767e9d124b78097aefa8f43cc1713e81a7c4f45e1ba77f0"
      hash12 = "51863351193ab67148e3e47255cad4927eb13939292c7854121ebedb4de28590"
      hash13 = "63a19cd37e5f23ba982d004e587472bdc30d64af04e1b321419d8173a16c60cc"
      hash14 = "662bb00e9a82d43be45413fce12def326a1863f9cd3e63aa45b60d36ef7e0443"
      hash15 = "6a702c55f4ee54eeb35a991d7413328da1e56dde6e719babec23682423bec23f"
      hash16 = "75b4d9eb26ed9e20009c9a55a58e66457d7ec4d7d060179f09f6522e96c62e2e"
      hash17 = "7b167d362a9282adb176095be2e5bd4692b4158b7bdf4c6c20870daed5b04665"
      hash18 = "904e4153d2026380dc42297173192e72de7e5d9ea50f16bf8df2e2fa6922cdc3"
      hash19 = "95e88ec3ceb56c7f3679c45b837f931d0b38269a2e275628f2bc1a9f5c77a19f"
      hash20 = "9ae895cd6474d1928bbbd68e240679c9de3c0ca327ac4e4b83845878b72322be"
      hash21 = "a0edfa97344c870ee24aa7c008cec40e85e616c21e86522b8f6fce0324b356f7"
      hash22 = "b4b2197c5a8f0e9b9766fa39e9b538568284ec8a0099811b8b54fe6a1402545b"
      hash23 = "be8adc196213154b10bd4209098ff94083d5ade71abeeacbf9d4cf30e3403234"
      hash24 = "ca5b40e938f68321dfa3a7f1ad2a03db4ff6ba27fdae5e230654cd5c30090692"
      hash25 = "d5a84c85508c444743d055be354a464eb22dc5b33cba41e4b149829d182f4dca"
      hash26 = "d69108a94a9a81e07a05d456dc997cbf5b5a8cc8f0869eae7904fac1da60f335"
      hash27 = "d9b75d606803968d04015bed042da887905e9c1cb1b40b4ff11852b88c8b4d21"
      hash28 = "ddeb13abf09d096f821ee657c3479f799f2a236b49f46c80a0afb2676a8f55ab"
      hash29 = "dfa3539353b89089a3599f4775a296b270751738186af515bf3e630dc054bc7d"
      hash30 = "e163a088d174d4eb41479b53e6df04831dc40899b893a0b183d080d2dfe52cd7"
      hash31 = "ee9eceda9522ae4c5ff3e07aefa523c61d50ebb9aca2808e0f4494a8c53498ea"
      hash32 = "faab917444988b9a2e8d5d5bc06a0423c53718f92cbb8840cc6632f464c89130"
   strings:
      $s1 = " Play Protect" fullword ascii
      $s2 = "\"%Play Protect taraf" fullword ascii
      $s3 = "Verified by Play Protect" fullword ascii
      $s4 = " par Play Protect" fullword ascii
      $s5 = "##Play Protect tomonidan tekshirilgan" fullword ascii
      $s6 = "Verificado por Play Protect" fullword ascii
      $s7 = "Verificato da Play Protect" fullword ascii
      $s8 = "Play Protect " fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca616_100 {
   meta:
      description = "apk - from files 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169"
      hash2 = "d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe"
   strings:
      $s1 = "Account Holder Name" fullword ascii
      $s2 = "Bank Name" fullword ascii
      $s3 = "Single Pana" fullword ascii
      $s4 = "Triple Pana" fullword ascii
      $s5 = "Game Rates" fullword ascii
      $s6 = "Double Pana" fullword ascii
      $s7 = "Bank Details" fullword ascii
      $s8 = "Single Digit" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca616_101 {
   meta:
      description = "apk - from files 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 4e6c3f36a00638652d94b6a79722c7e40e11d73674fc49b4dbdadbe82acae581.apk, 8ef35a9062369b6ce2e99571b0dc263be74ef888548a1072c609581b9adf3a93.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169"
      hash2 = "4e6c3f36a00638652d94b6a79722c7e40e11d73674fc49b4dbdadbe82acae581"
      hash3 = "8ef35a9062369b6ce2e99571b0dc263be74ef888548a1072c609581b9adf3a93"
   strings:
      $s1 = "unsupported x86 register" fullword ascii
      $s2 = "unsupported x86_64 register" fullword ascii
      $s3 = "no x86 float registers" fullword ascii
      $s4 = "libunwind: malformed DW_CFA_offset DWARF unwind, reg (%lu) out of range" fullword ascii
      $s5 = "no x86_64 float registers" fullword ascii
      $s6 = "libunwind: malformed DW_CFA_restore DWARF unwind, reg (%lu) out of range" fullword ascii
      $s7 = "libunwind: malformed DW_CFA_restore DWARF unwind, reg (%llu) out of range" fullword ascii
      $s8 = "libunwind: malformed DW_CFA_offset DWARF unwind, reg (%llu) out of range" fullword ascii
      $s9 = "libunwind: malformed DW_CFA_val_offset DWARF unwind, reg (%llu) out of range" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288e_102 {
   meta:
      description = "apk - from files 1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea.apk, 1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290.apk, 73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99.apk, f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea"
      hash2 = "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
      hash3 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash4 = "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
      hash5 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash6 = "4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290"
      hash7 = "73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a"
      hash8 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
      hash9 = "b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99"
      hash10 = "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
   strings:
      $s1 = "#$Data d'inici - Data de finalitzaci" fullword ascii
      $s2 = "%1$s - Data de finalizaci" fullword ascii
      $s3 = "$%Data e fillimit - Data e p" fullword ascii
      $s4 = "IISelezione della data di inizio: %1$s - Selezione della data di fine: %2$s" fullword ascii
      $s5 = "%&Data de inicio - Data de finalizaci" fullword ascii
      $s6 = "%1$s - Data de finalitzaci" fullword ascii
      $s7 = "o da data de conclus" fullword ascii
      $s8 = " Data de fim" fullword ascii
      $s9 = " Data de " fullword ascii
      $s10 = " Datum ukon" fullword ascii
      $s11 = " Data e p" fullword ascii
      $s12 = "datum " fullword ascii
      $s13 = "Data de in" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _23468bb2042bb18d50f25d04d3a4d3a793e039a52a8dea9559e15289a95468e_103 {
   meta:
      description = "apk - from files 23468bb2042bb18d50f25d04d3a4d3a793e039a52a8dea9559e15289a95468ec.apk, 2e51daa305891ae8c03beb20f3b77b40727d24ad9f51e9899606ee7c1e76ead2.apk, 3493d2bc0e7a1b2ccbeca6e1dd2fbcef8109cc50289596816c89e154e4f2edde.apk, 3eaa49a1229343c1885b08f13ecdc2638875f66fd851b7b2baa534894e56921d.apk, 41474b00b02b03fca4fa0e6765d690d540b9a19b11478006acdd865d845ebe9a.apk, 56ac9eb8ca22f4b05b1d64872d4209440fc97413c1225141f268e22ae93d1edd.apk, 6828dcb4d6526999c531a4cb47a78fa1f2c16902256f0d309b051208410c1270.apk, 76cdbbbd920cdc8a2b3ccbc33b39cdcfa344fb9bae0222b5ff376fa78d29b735.apk, 8b07fca15e1a89b27c6d2ac8508b36315ac56683555bf962e793a6131ab97e4e.apk, ae87e247ec3b1fb23412297b90473a1641fb4ce0d5142b92da4b07283996ed88.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "23468bb2042bb18d50f25d04d3a4d3a793e039a52a8dea9559e15289a95468ec"
      hash2 = "2e51daa305891ae8c03beb20f3b77b40727d24ad9f51e9899606ee7c1e76ead2"
      hash3 = "3493d2bc0e7a1b2ccbeca6e1dd2fbcef8109cc50289596816c89e154e4f2edde"
      hash4 = "3eaa49a1229343c1885b08f13ecdc2638875f66fd851b7b2baa534894e56921d"
      hash5 = "41474b00b02b03fca4fa0e6765d690d540b9a19b11478006acdd865d845ebe9a"
      hash6 = "56ac9eb8ca22f4b05b1d64872d4209440fc97413c1225141f268e22ae93d1edd"
      hash7 = "6828dcb4d6526999c531a4cb47a78fa1f2c16902256f0d309b051208410c1270"
      hash8 = "76cdbbbd920cdc8a2b3ccbc33b39cdcfa344fb9bae0222b5ff376fa78d29b735"
      hash9 = "8b07fca15e1a89b27c6d2ac8508b36315ac56683555bf962e793a6131ab97e4e"
      hash10 = "ae87e247ec3b1fb23412297b90473a1641fb4ce0d5142b92da4b07283996ed88"
   strings:
      $s1 = "Champion" fullword ascii
      $s2 = "Assassin" fullword ascii
      $s3 = "Soldier" fullword ascii
      $s4 = "Gladiator" fullword ascii
      $s5 = "Samurai" fullword ascii
      $s6 = "Warrior" fullword ascii
      $s7 = "Bandit" fullword ascii
      $s8 = "Slayer" fullword ascii
      $s9 = "Killer" fullword ascii
      $s10 = "Accept: application/dns-message" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb4_104 {
   meta:
      description = "apk - from files 017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44.apk, 01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0.apk, 0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e.apk, 05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a.apk, 08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c.apk, 090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90ba268.apk, 091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d96241620a5.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd.apk, 0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072.apk, 11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea.apk, 13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52.apk, 1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90.apk, 19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c20271e62.apk, 1bf9c16cb7c1faae7fa99a57c5d091cbd1e6d5f3c0d79693a3b0990a8b58367d.apk, 1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c.apk, 1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0.apk, 1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9.apk, 21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e494fe.apk, 22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b.apk, 23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61.apk, 269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471eed36.apk, 27b8eeb5d1b46e1afa170b998830fe0958f08a2a9dfe7130df607c86ad42fb33.apk, 29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896.apk, 2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0.apk, 2d25cb4e862cc6cac19999798f044211ed99239dd15779be6271b680c028782a.apk, 2e11badbd558a37c88ee22a7315c8220b90213fb712ea1ec1f39b14e3ae8475c.apk, 2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b.apk, 3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089.apk, 34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45.apk, 392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647.apk, 3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5dce6.apk, 3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd.apk, 3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec.apk, 3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c.apk, 41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2.apk, 41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce.apk, 4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951.apk, 4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f.apk, 4a899a3b0fd61937ce8555cb0da53daf72dadc7dd299c63e90b4a203e5a14db1.apk, 4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290.apk, 4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088.apk, 4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b.apk, 59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f.apk, 5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8.apk, 5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3.apk, 6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3.apk, 65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf.apk, 6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22.apk, 6b0c56540499051ab350a31f417b99859da7ed7286b9e77503711c6aabafbe03.apk, 6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8.apk, 6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa8255405.apk, 6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd.apk, 6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738.apk, 73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4.apk, 73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a.apk, 752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e40ab.apk, 7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570.apk, 774af64259ad726296fb4fc56ca91897c7da9acb3a10ad49325ead714f6562c4.apk, 78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b.apk, 7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144.apk, 79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826fdd3.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, 7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf26527b7.apk, 8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552.apk, 83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a.apk, 9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e0ece.apk, 9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5.apk, 9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d.apk, 9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d.apk, 9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3bb5d1.apk, 9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c.apk, 9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90.apk, 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk, 9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b3306.apk, 9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6.apk, a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5.apk, a2a539109b77cfa720f6e1315fa09c82cfb8eb9980b304ba54de6a8279993dd4.apk, a2c509d0b0fcee3bc503bd12986da2d29c74ebcd37abb1af8988f7f26382663d.apk, a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa.apk, aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de.apk, afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4.apk, b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk, b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e.apk, b1a8941063751656e11bbc6ab44d348cd6795d51bfc890424595c4ac76e52013.apk, b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33.apk, bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6.apk, bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de.apk, c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14.apk, c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9.apk, c659454dd6ed62bc7a0c9e0455297e41ba57b0b7935a826150c1f8c0db6f89d2.apk, c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d.apk, c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk, ca6271b212c627dd6e4372827a0fb316023fa35210cab7249d634379af6d649c.apk, cb147e7ce69723523f604da875d78ca4738e5f416d2297910ee179a5067e79fe.apk, cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c.apk, ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9.apk, ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642.apk, d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af.apk, d1fec0ce2be2097357d307e835783380ac010c7d55f3e72fa3906f0d0edd7a6a.apk, d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3.apk, d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd.apk, d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2.apk, d3fc5ffdd9a68a3063b1c8ff15334238dd39a63b9c93ec9f337bdd5f5357046a.apk, d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372.apk, d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5.apk, d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe.apk, d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d.apk, d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38.apk, decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8.apk, e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3.apk, e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938.apk, e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75.apk, e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b.apk, e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8.apk, e756a707443f382f4f93ca4b6101de16e4cac521d9032171c7b68b3a9585c39e.apk, e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk, f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2.apk, f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738.apk, f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65.apk, faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee.apk, faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44"
      hash2 = "01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0"
      hash3 = "0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e"
      hash4 = "05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a"
      hash5 = "08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c"
      hash6 = "090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90ba268"
      hash7 = "091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d96241620a5"
      hash8 = "0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169"
      hash9 = "0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd"
      hash10 = "0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072"
      hash11 = "11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415"
      hash12 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash13 = "134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138"
      hash14 = "1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea"
      hash15 = "13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52"
      hash16 = "1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90"
      hash17 = "19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c20271e62"
      hash18 = "1bf9c16cb7c1faae7fa99a57c5d091cbd1e6d5f3c0d79693a3b0990a8b58367d"
      hash19 = "1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c"
      hash20 = "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
      hash21 = "1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9"
      hash22 = "21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e494fe"
      hash23 = "22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b"
      hash24 = "23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61"
      hash25 = "269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471eed36"
      hash26 = "27b8eeb5d1b46e1afa170b998830fe0958f08a2a9dfe7130df607c86ad42fb33"
      hash27 = "29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896"
      hash28 = "2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0"
      hash29 = "2d25cb4e862cc6cac19999798f044211ed99239dd15779be6271b680c028782a"
      hash30 = "2e11badbd558a37c88ee22a7315c8220b90213fb712ea1ec1f39b14e3ae8475c"
      hash31 = "2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1"
      hash32 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash33 = "31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b"
      hash34 = "3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089"
      hash35 = "34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45"
      hash36 = "392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d"
      hash37 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash38 = "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
      hash39 = "3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5dce6"
      hash40 = "3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd"
      hash41 = "3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec"
      hash42 = "3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c"
      hash43 = "41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2"
      hash44 = "41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7"
      hash45 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash46 = "48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce"
      hash47 = "4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951"
      hash48 = "4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f"
      hash49 = "4a899a3b0fd61937ce8555cb0da53daf72dadc7dd299c63e90b4a203e5a14db1"
      hash50 = "4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290"
      hash51 = "4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088"
      hash52 = "4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7"
      hash53 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash54 = "563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b"
      hash55 = "59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f"
      hash56 = "5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8"
      hash57 = "5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a"
      hash58 = "5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8"
      hash59 = "64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3"
      hash60 = "6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3"
      hash61 = "65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf"
      hash62 = "6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22"
      hash63 = "6b0c56540499051ab350a31f417b99859da7ed7286b9e77503711c6aabafbe03"
      hash64 = "6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8"
      hash65 = "6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa8255405"
      hash66 = "6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd"
      hash67 = "6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738"
      hash68 = "73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4"
      hash69 = "73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a"
      hash70 = "752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e40ab"
      hash71 = "7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570"
      hash72 = "774af64259ad726296fb4fc56ca91897c7da9acb3a10ad49325ead714f6562c4"
      hash73 = "78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b"
      hash74 = "7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144"
      hash75 = "79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826fdd3"
      hash76 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
      hash77 = "7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf26527b7"
      hash78 = "8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552"
      hash79 = "83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025"
      hash80 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash81 = "8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af"
      hash82 = "90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a"
      hash83 = "9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e0ece"
      hash84 = "9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5"
      hash85 = "9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d"
      hash86 = "9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d"
      hash87 = "9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3bb5d1"
      hash88 = "9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c"
      hash89 = "9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90"
      hash90 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
      hash91 = "9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b3306"
      hash92 = "9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6"
      hash93 = "a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5"
      hash94 = "a2a539109b77cfa720f6e1315fa09c82cfb8eb9980b304ba54de6a8279993dd4"
      hash95 = "a2c509d0b0fcee3bc503bd12986da2d29c74ebcd37abb1af8988f7f26382663d"
      hash96 = "a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2"
      hash97 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash98 = "a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa"
      hash99 = "aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8"
      hash100 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash101 = "ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de"
      hash102 = "afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4"
      hash103 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
      hash104 = "b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e"
      hash105 = "b1a8941063751656e11bbc6ab44d348cd6795d51bfc890424595c4ac76e52013"
      hash106 = "b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99"
      hash107 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash108 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash109 = "ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33"
      hash110 = "bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6"
      hash111 = "bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7"
      hash112 = "bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0"
      hash113 = "bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de"
      hash114 = "c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14"
      hash115 = "c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9"
      hash116 = "c659454dd6ed62bc7a0c9e0455297e41ba57b0b7935a826150c1f8c0db6f89d2"
      hash117 = "c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d"
      hash118 = "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
      hash119 = "ca6271b212c627dd6e4372827a0fb316023fa35210cab7249d634379af6d649c"
      hash120 = "cb147e7ce69723523f604da875d78ca4738e5f416d2297910ee179a5067e79fe"
      hash121 = "cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c"
      hash122 = "ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9"
      hash123 = "ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642"
      hash124 = "d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af"
      hash125 = "d1fec0ce2be2097357d307e835783380ac010c7d55f3e72fa3906f0d0edd7a6a"
      hash126 = "d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3"
      hash127 = "d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd"
      hash128 = "d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2"
      hash129 = "d3fc5ffdd9a68a3063b1c8ff15334238dd39a63b9c93ec9f337bdd5f5357046a"
      hash130 = "d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372"
      hash131 = "d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5"
      hash132 = "d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe"
      hash133 = "d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d"
      hash134 = "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
      hash135 = "decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8"
      hash136 = "e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3"
      hash137 = "e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938"
      hash138 = "e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75"
      hash139 = "e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b"
      hash140 = "e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8"
      hash141 = "e756a707443f382f4f93ca4b6101de16e4cac521d9032171c7b68b3a9585c39e"
      hash142 = "e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf"
      hash143 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash144 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
      hash145 = "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
      hash146 = "f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738"
      hash147 = "f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65"
      hash148 = "faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee"
      hash149 = "faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a"
      hash150 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
      hash151 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "Mostra password" fullword ascii
      $s2 = "Afficher le mot de passe" fullword ascii
      $s3 = "Mostra il menu a discesa" fullword ascii
      $s4 = "Effacer le texte" fullword ascii
      $s5 = "Afficher le menu d" fullword ascii
      $s6 = "49Nombre maximal de caract" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210_105 {
   meta:
      description = "apk - from files 05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a.apk, 090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90ba268.apk, 091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d96241620a5.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd.apk, 0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea.apk, 13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52.apk, 1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90.apk, 19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c20271e62.apk, 1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0.apk, 1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9.apk, 21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e494fe.apk, 22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b.apk, 23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61.apk, 269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471eed36.apk, 2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0.apk, 2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089.apk, 34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45.apk, 3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647.apk, 3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5dce6.apk, 3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd.apk, 3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951.apk, 4a899a3b0fd61937ce8555cb0da53daf72dadc7dd299c63e90b4a203e5a14db1.apk, 4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f.apk, 5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8.apk, 64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3.apk, 6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22.apk, 6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa8255405.apk, 73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a.apk, 752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e40ab.apk, 7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570.apk, 78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b.apk, 79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826fdd3.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, 7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf26527b7.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e0ece.apk, 9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d.apk, 9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3bb5d1.apk, 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk, 9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b3306.apk, 9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6.apk, aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8.apk, afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4.apk, b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk, b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e.apk, b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de.apk, c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d.apk, c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk, cb147e7ce69723523f604da875d78ca4738e5f416d2297910ee179a5067e79fe.apk, ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9.apk, d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd.apk, d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2.apk, d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5.apk, d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38.apk, e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3.apk, e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk, f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2.apk, f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65.apk, faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a"
      hash2 = "090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90ba268"
      hash3 = "091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d96241620a5"
      hash4 = "0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169"
      hash5 = "0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd"
      hash6 = "0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072"
      hash7 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash8 = "1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea"
      hash9 = "13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52"
      hash10 = "1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90"
      hash11 = "19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c20271e62"
      hash12 = "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
      hash13 = "1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9"
      hash14 = "21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e494fe"
      hash15 = "22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b"
      hash16 = "23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61"
      hash17 = "269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471eed36"
      hash18 = "2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0"
      hash19 = "2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1"
      hash20 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash21 = "3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089"
      hash22 = "34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45"
      hash23 = "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
      hash24 = "3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5dce6"
      hash25 = "3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd"
      hash26 = "3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c"
      hash27 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash28 = "4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951"
      hash29 = "4a899a3b0fd61937ce8555cb0da53daf72dadc7dd299c63e90b4a203e5a14db1"
      hash30 = "4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290"
      hash31 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash32 = "59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f"
      hash33 = "5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8"
      hash34 = "64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3"
      hash35 = "6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22"
      hash36 = "6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa8255405"
      hash37 = "73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a"
      hash38 = "752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e40ab"
      hash39 = "7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570"
      hash40 = "78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b"
      hash41 = "79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826fdd3"
      hash42 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
      hash43 = "7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf26527b7"
      hash44 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash45 = "8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af"
      hash46 = "9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e0ece"
      hash47 = "9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d"
      hash48 = "9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3bb5d1"
      hash49 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
      hash50 = "9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b3306"
      hash51 = "9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6"
      hash52 = "aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8"
      hash53 = "afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4"
      hash54 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
      hash55 = "b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e"
      hash56 = "b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99"
      hash57 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash58 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash59 = "ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33"
      hash60 = "bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0"
      hash61 = "bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de"
      hash62 = "c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d"
      hash63 = "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
      hash64 = "cb147e7ce69723523f604da875d78ca4738e5f416d2297910ee179a5067e79fe"
      hash65 = "ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9"
      hash66 = "d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd"
      hash67 = "d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2"
      hash68 = "d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5"
      hash69 = "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
      hash70 = "e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3"
      hash71 = "e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b"
      hash72 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash73 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
      hash74 = "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
      hash75 = "f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65"
      hash76 = "faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a"
      hash77 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "Error: No v" fullword ascii
      $s2 = "Error: tidak valid" fullword ascii
      $s3 = "Villa: " fullword ascii
      $s4 = "Viga: sobimatu" fullword ascii
      $s5 = "Feil: ugyldig" fullword ascii
      $s6 = "ka: neve" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _0172d6141fc03c2e152caf35dce6c90cc0cec4f303de270f09136b93f1e99bc_106 {
   meta:
      description = "apk - from files 0172d6141fc03c2e152caf35dce6c90cc0cec4f303de270f09136b93f1e99bcf.apk, acf2d29c8c65ee2fe57445e672fbee01fa240b0039b66ea507f110468c6c8210.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "0172d6141fc03c2e152caf35dce6c90cc0cec4f303de270f09136b93f1e99bcf"
      hash2 = "acf2d29c8c65ee2fe57445e672fbee01fa240b0039b66ea507f110468c6c8210"
   strings:
      $s1 = "eeded, as this operation will erase all locally stored data and is not reversible." fullword ascii
      $s2 = "ve to deactivate the community." fullword ascii
      $s3 = "r customer service team." fullword ascii
      $s4 = "SSDelete \"%s\" group?" fullword ascii
      $s5 = " this group again later." fullword ascii
      $s6 = "hen kept. Tap to change." fullword ascii
      $s7 = "ings to a new phone number." fullword ascii
      $s8 = "\\\\Delete \"%s\" broadcast list?" fullword ascii
      $s9 = "when kept. Tap to change." fullword ascii
      $s10 = "e group and try again." fullword ascii
      $s11 = "a href=\"device-confirmation-learn-more\">Learn more</a>" fullword ascii
      $s12 = "an send and receive SMS." fullword ascii
      $s13 = "when kept." fullword ascii
      $s14 = "<a href=\"%2$s\">Learn more</a>" fullword ascii
      $s15 = "hen kept" fullword ascii
      $s16 = " except when kept. Group admins control who can change this setting. <a href=\"learn-more\">Learn" fullword ascii
      $s17 = " security precautions, this file cannot be sent." fullword ascii
      $s18 = "WWDelete broadcast list?" fullword ascii
      $s19 = "tion. Group admins control who can change this setting. <a href=\"learn-more\">Learn" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb4_107 {
   meta:
      description = "apk - from files 017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44.apk, 01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0.apk, 0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e.apk, 08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c.apk, 11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c.apk, 23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61.apk, 29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896.apk, 31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b.apk, 3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089.apk, 34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45.apk, 392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec.apk, 41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2.apk, 41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7.apk, 48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce.apk, 4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f.apk, 4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088.apk, 4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b.apk, 5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3.apk, 65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf.apk, 6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8.apk, 6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd.apk, 6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738.apk, 73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4.apk, 7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144.apk, 8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552.apk, 83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a.apk, 9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5.apk, 9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d.apk, 9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c.apk, 9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90.apk, 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk, 9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6.apk, a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5.apk, a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de.apk, b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6.apk, bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7.apk, c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14.apk, c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9.apk, c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk, ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642.apk, d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af.apk, d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3.apk, d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372.apk, d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe.apk, d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d.apk, d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38.apk, decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8.apk, e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3.apk, e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938.apk, e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75.apk, e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8.apk, e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk, f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738.apk, faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44"
      hash2 = "01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0"
      hash3 = "0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e"
      hash4 = "08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c"
      hash5 = "11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415"
      hash6 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash7 = "134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138"
      hash8 = "1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c"
      hash9 = "23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61"
      hash10 = "29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896"
      hash11 = "31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b"
      hash12 = "3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089"
      hash13 = "34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45"
      hash14 = "392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d"
      hash15 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash16 = "3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec"
      hash17 = "41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2"
      hash18 = "41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7"
      hash19 = "48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce"
      hash20 = "4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f"
      hash21 = "4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088"
      hash22 = "4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7"
      hash23 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash24 = "563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b"
      hash25 = "5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a"
      hash26 = "5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8"
      hash27 = "6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3"
      hash28 = "65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf"
      hash29 = "6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8"
      hash30 = "6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd"
      hash31 = "6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738"
      hash32 = "73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4"
      hash33 = "7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144"
      hash34 = "8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552"
      hash35 = "83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025"
      hash36 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash37 = "90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a"
      hash38 = "9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5"
      hash39 = "9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d"
      hash40 = "9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c"
      hash41 = "9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90"
      hash42 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
      hash43 = "9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6"
      hash44 = "a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5"
      hash45 = "a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2"
      hash46 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash47 = "a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa"
      hash48 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash49 = "ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de"
      hash50 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
      hash51 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash52 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash53 = "bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6"
      hash54 = "bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7"
      hash55 = "c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14"
      hash56 = "c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9"
      hash57 = "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
      hash58 = "ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642"
      hash59 = "d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af"
      hash60 = "d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3"
      hash61 = "d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372"
      hash62 = "d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe"
      hash63 = "d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d"
      hash64 = "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
      hash65 = "decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8"
      hash66 = "e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3"
      hash67 = "e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938"
      hash68 = "e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75"
      hash69 = "e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8"
      hash70 = "e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf"
      hash71 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash72 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
      hash73 = "f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738"
      hash74 = "faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee"
      hash75 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
      hash76 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "%1$s - data de finalitzaci" fullword ascii
      $s2 = "%&Data de inicio - data de finalizaci" fullword ascii
      $s3 = "%1$s - data de finalizaci" fullword ascii
      $s4 = "$%Data e fillimit - data e p" fullword ascii
      $s5 = "#$Data d'inici - data de finalitzaci" fullword ascii
      $s6 = " datum zavr" fullword ascii
      $s7 = " datum ukon" fullword ascii
      $s8 = " data e p" fullword ascii
      $s9 = " data de " fullword ascii
      $s10 = "#$Du (date de d" fullword ascii
      $s11 = "but) au (date de fin)" fullword ascii
      $s12 = "Du %1$s au (date de fin)" fullword ascii
      $s13 = " Data de conclus" fullword ascii
      $s14 = "\"&Data de in" fullword ascii
      $s15 = "Data de conclus" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca616_108 {
   meta:
      description = "apk - from files 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169"
      hash2 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash3 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
   strings:
      $s1 = "??You have previously denied %s. Please go to settings to enable." fullword ascii
      $s2 = "nnLooks like this app doesn't have location services configured. Please see OneSignal docs for more information." fullword ascii
      $s3 = "App Missing Permission" fullword ascii
      $s4 = "%s Not Available" fullword ascii
      $s5 = "sharing your device location" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _108ca43c5a62640b5e3d71df33c00549c46634c1109c1ac6690df89fbc4211f_109 {
   meta:
      description = "apk - from files 108ca43c5a62640b5e3d71df33c00549c46634c1109c1ac6690df89fbc4211fd.apk, 678ee44afb89903d3199378f2e6d9de0b4167c23e548bf4d7f863e1545ef912e.apk, 7775d8411c836f15e525320a984c90941127e7101ded1af8bb5b1234d50ebaf5.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "108ca43c5a62640b5e3d71df33c00549c46634c1109c1ac6690df89fbc4211fd"
      hash2 = "678ee44afb89903d3199378f2e6d9de0b4167c23e548bf4d7f863e1545ef912e"
      hash3 = "7775d8411c836f15e525320a984c90941127e7101ded1af8bb5b1234d50ebaf5"
   strings:
      $s1 = "AADelete \"%s\" group?" fullword ascii
      $s2 = "e number." fullword ascii
      $s3 = "=\"device-confirmation-learn-more\">Learn more</a>" fullword ascii
      $s4 = "change." fullword ascii
      $s5 = "receive SMS." fullword ascii
      $s6 = "munity." fullword ascii
      $s7 = "ervice team." fullword ascii
      $s8 = "an turn this setting back on at any time." fullword ascii
      $s9 = "d install it again." fullword ascii
      $s10 = "backup will be deleted." fullword ascii
      $s11 = "s\">Learn more</a>" fullword ascii
      $s12 = "rypted backup." fullword ascii
      $s13 = " will erase all locally stored data and is not reversible." fullword ascii
      $s14 = "JJDelete \"%s\" broadcast list?" fullword ascii
      $s15 = "n risk." fullword ascii
      $s16 = "p and try again." fullword ascii
      $s17 = " kept. Group admins control who can change this setting. <a href=\"learn-more\">Learn" fullword ascii
      $s18 = "admins control who can change this setting. <a href=\"learn-more\">Learn" fullword ascii
      $s19 = "ity precautions, this file cannot be sent." fullword ascii
      $s20 = "EEDelete broadcast list?" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _1aeae34c264bbfbd4eed6d92a94ac788bfb9b050a54032fde811402d63f18bf_110 {
   meta:
      description = "apk - from files 1aeae34c264bbfbd4eed6d92a94ac788bfb9b050a54032fde811402d63f18bf8.apk, 21b6b9c7262fe39d2f2ce49115c9c22f50d3e5b0b083a0f8c1ddd776c369ffd3.apk, 498b9dc568e47cd06099fbedb479e78556a7cd30a8cad589b003a77e09de2c52.apk, 4f621122c29871e1d0464421c2abfc01036f27f1d3523b8b4d143f82a2c08c5a.apk, 4ff07276c35f5e9c6f8ec37deaa0bc4f01f033a4e717ef8ce76ef371e8eee29b.apk, 6c1aeaeb5786f3632f0a02356b26bdde2ccf77e1e8c6d3f8f6b88e9458f7839f.apk, 79f56edc1bb111c0323762dc0c25d9c50c9a62ec4dedc2cf2e0c2010e518b6b4.apk, d9c47a7d7e42402c3ce2dd191ea09e9f7e29b1ee8d78d9aec0a47ed7b4bcdb80.apk, e7bc41c6d3677ef941dfc8eb4b571435623dab1e8c0681b6253c37725844b268.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "1aeae34c264bbfbd4eed6d92a94ac788bfb9b050a54032fde811402d63f18bf8"
      hash2 = "21b6b9c7262fe39d2f2ce49115c9c22f50d3e5b0b083a0f8c1ddd776c369ffd3"
      hash3 = "498b9dc568e47cd06099fbedb479e78556a7cd30a8cad589b003a77e09de2c52"
      hash4 = "4f621122c29871e1d0464421c2abfc01036f27f1d3523b8b4d143f82a2c08c5a"
      hash5 = "4ff07276c35f5e9c6f8ec37deaa0bc4f01f033a4e717ef8ce76ef371e8eee29b"
      hash6 = "6c1aeaeb5786f3632f0a02356b26bdde2ccf77e1e8c6d3f8f6b88e9458f7839f"
      hash7 = "79f56edc1bb111c0323762dc0c25d9c50c9a62ec4dedc2cf2e0c2010e518b6b4"
      hash8 = "d9c47a7d7e42402c3ce2dd191ea09e9f7e29b1ee8d78d9aec0a47ed7b4bcdb80"
      hash9 = "e7bc41c6d3677ef941dfc8eb4b571435623dab1e8c0681b6253c37725844b268"
   strings:
      $s1 = " encryption key:" fullword ascii
      $s2 = "d, as this operation will erase all locally stored data and is not reversible." fullword ascii
      $s3 = "o deactivate the community." fullword ascii
      $s4 = "PPDelete \"%s\" group?" fullword ascii
      $s5 = "customer service team." fullword ascii
      $s6 = " send and receive SMS." fullword ascii
      $s7 = "is group again later." fullword ascii
      $s8 = " href=\"device-confirmation-learn-more\">Learn more</a>" fullword ascii
      $s9 = "cept when kept." fullword ascii
      $s10 = "s to a new phone number." fullword ascii
      $s11 = " group and try again." fullword ascii
      $s12 = " kept. Tap to change." fullword ascii
      $s13 = "YYDelete \"%s\" broadcast list?" fullword ascii
      $s14 = "TTDelete broadcast list?" fullword ascii
      $s15 = "xcept when kept. Group admins control who can change this setting. <a href=\"learn-more\">Learn" fullword ascii
      $s16 = "security precautions, this file cannot be sent." fullword ascii
      $s17 = "on. Group admins control who can change this setting. <a href=\"learn-more\">Learn" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _0007aff422a0c7ae9928eae16237ddd1a29e90180c44ede869ecb55c6182879_111 {
   meta:
      description = "apk - from files 0007aff422a0c7ae9928eae16237ddd1a29e90180c44ede869ecb55c6182879d.apk, 0027c816cc740251e8f2d271cbaf7397706a1db07cc14b842d962fee8991daf6.apk, 018f8548c055a31d98201874ebf21591e6d85cb9eee66e8c35716a9289d01f48.apk, 02cd74a277a19ef59375d44e6111c5c887a2dd2313a2a7129c98e5967dc69ecc.apk, 04e4acc8cd2a66f77260ebcfbe40646192ff452d5f9bbe54e0acbd0cabc3cfbc.apk, 0619168a8df6dd350052ca3a578abe15da0f2177e65acea55f44b5b59ed5f1c8.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0badd9b4b0e44daeaa75b5d97ed9611a9f84418c1fb5683130e8b22742086549.apk, 0c8085cea946d655b266998fd60b1da33df73a4285328da3dabc7f0e7211411d.apk, 0f9fe82c6594fe331e59cf0268bc402f9e31141a3fd5e5dd99596d28563c5e9b.apk, 1077e767d28e8b97be3ebc98ceab110c14335260b47a3a0fdfcb77b6a2ccf080.apk, 1099eede57e825fa5158b33f01559dc76e6d67e2fca37b97f76e7d3aa9a4208a.apk, 121e82504dfbada0fd5cec2bd6bec7a518f8afce65b43ded20498f3f5cb5c05c.apk, 12cb6136d2d325563b5079c138eeac2bc4ee4af3373718ba1c79c47a6121829e.apk, 174deed18377e5280413a2015ebe2041fd8b4276a6599754299cf05cea0718d5.apk, 185a01ec24938cd5a9af4fd66a0814e8bfaf2e1ff8cfa2396a30c3e4f6e66b98.apk, 1b5ff50963c6e99dfb521e6db624df9f83f21f06430ce9d8f3cd0de735cbe22a.apk, 246bdb0a9e7698e37ec7b906551ceed302d0445c9572bb3cdc02a68862fd2d2a.apk, 2d0fd4ea41c4e17cf94577c126ae271555b544f388baca69112cd3a488572be1.apk, 2f451d9cfda5d91b2063a62ed5ad482cd733e899b9ee39ee8bd332b518b3b865.apk, 33c3f43852f6ecadef74aef2dbb0d5a1215aa3cb23e4aaf76f202beed3aa8703.apk, 340d1ff4143a560c2ca4400a6c2ca6e9448b6392c203ec190893e773b7a00265.apk, 3434bad9d01dad7ad4e7525a3936c527376699e3505e70171b083c1226f0e90c.apk, 3616fd6004678159e531fb7e5a173b333c08bd0097aa1f6a4e9f503db4a9999a.apk, 3638754e7fd889e9ced9127e7abe08191b7e8df3d60ed284c7b507e1e8082613.apk, 399c4819af422e581639c9350dcba71b0ee00b87a4d37da11806db5e25a0adc5.apk, 3ab3cc3c0df02d723c850e712fa5f4a0de29f2addf2c50beffe222112c2baa38.apk, 3c0a6f866aa4d74d0b39a2b9d11692ffa7291fd46b414e73cd5f9c7f9f030b75.apk, 3d8da22674ee343bd02296a4351e90198ffc786f8541747e42cdcf3438f16b3e.apk, 41930e6f9187c8be4ea41303dd957d74f65b97944321a24a20028e76d10e0588.apk, 43996d454961143bad870d9b94a3d00912f7c29b76371244ac59423595ae0860.apk, 44612fabf9a13d78f845f0932c6f332647684c8017f5a8410ec24b483a186e27.apk, 446800befecf9179f9aca09dd88331dee0e745b199db39a9b0113f4ee886ca34.apk, 44ce621f601a8c68f8984324e2883cb431adcae410a60a36f6f252ad5d0fd467.apk, 469b13cac1eb859da7ba4b597270f047b11815bfff9c4ad3faa5617c07a6c3e0.apk, 4e6c3f36a00638652d94b6a79722c7e40e11d73674fc49b4dbdadbe82acae581.apk, 4f0508904ec488ea7767e9d124b78097aefa8f43cc1713e81a7c4f45e1ba77f0.apk, 50990c1178790239445d4dea570e4affeca6efbb01a91cbf4af4498a0477dd2e.apk, 53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee.apk, 55c111e642c6aebcb75fc9db89def8adcd73ae1d5eb6b11b7c8dc590d14d0804.apk, 57a0a81eebdf6c1e0a5ab0489165f167856712121b86959f0c34ce5c24014266.apk, 59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f.apk, 5a2306804771a975f692d6cc1cbaf06af1b86273301b3af8069f4d36a27d3866.apk, 5cb94ba3236bd4fa89bad460687cc2f1e80a890f5a093e954ea2704c1950c1f3.apk, 5dff60862aea80d5da616400359ae170f2d9ef9d76a745417f4facff72cd4c17.apk, 5f6016b9bcaf98d2276187b7ef74a1662bd7e21e610ebed2b2ce5a7aea799600.apk, 6406d67b9abef51ee7058c77f886e5828e23c1bf8f31373f8ca2df65abb5b431.apk, 64b4f8c86ea5ef925da573e7667ca93d32f4fb27fd6a702f5e99ccc4d087f612.apk, 6564e7362b89d453173884e35d96ff5ce1de7ecbad102b0f5450300418b5de9b.apk, 657881e96def3e69a401f79c678edff27c3db4db74ba802fb8989ae466f73cc9.apk, 662bb00e9a82d43be45413fce12def326a1863f9cd3e63aa45b60d36ef7e0443.apk, 6a702c55f4ee54eeb35a991d7413328da1e56dde6e719babec23682423bec23f.apk, 6dd19edd60ed2025afc6b661e85f146c925f2137e51ae49c5d1dce955ac43aaf.apk, 6ec479136b4fb6809638e874d9d606f6d4b1f44a686f61954bb6883d548333fa.apk, 7063baf053aa3faf308f1b3205dcb7495f74a1621d472b151ecc4f5fadccd369.apk, 734b154c74808cac4726650bd8648be1ed42282aba70f69be763ba42ff602bf7.apk, 73aef1d852c9c4001b1a7db673e03417d30f489e56db5813a8757866c2641028.apk, 75b4d9eb26ed9e20009c9a55a58e66457d7ec4d7d060179f09f6522e96c62e2e.apk, 75cd6f164dee674a18edc5154ef0d48633eb581b73d77aef047af0a5856420cc.apk, 76798397118c81edf2ef4588a60578a8700017afb98b040657b39cccdbe30009.apk, 77c54058a2bb45219e6ee860430f5ea8ce8e6ed2e58fba05f0d9bf74ffb7b4ef.apk, 7b167d362a9282adb176095be2e5bd4692b4158b7bdf4c6c20870daed5b04665.apk, 7b40e010ae6556b159eaaba4f0989bd57cc510c388215f2d89580cc3379ae33c.apk, 80448bc12448336f023d890b29ebf2a854f325ad010aa05d2f632870be9c8677.apk, 807d8ffb7975d525386036b10563485033155f62d4355a83e372b08b370c3850.apk, 809d07b61da605e1eab3aedbc25ed1eba0dfd48f15c8fa7c03d73ab19c95f5ff.apk, 8166dfba7fd0b4ad44c8bc91cc0e98fa06b8912e3fca2093900eb58ba79d22d4.apk, 857d9e064fe567da2b5f42b49787d05d0238f34ddc2890a826d80d8f012f7e8d.apk, 88d598aa4b9272f14913d42937586992d0a5e35e656ca315e33ecaa81628f04c.apk, 8c7dbb2080f2b862026b2d755cb01c4b484c357c7aa5e053398ee6fe497c6374.apk, 8ef35a9062369b6ce2e99571b0dc263be74ef888548a1072c609581b9adf3a93.apk, 904e4153d2026380dc42297173192e72de7e5d9ea50f16bf8df2e2fa6922cdc3.apk, 90ac64358498e62a5718e92d9ede7c7e0fb30aa39c6cc94d4ac38010208cc255.apk, 95236ef71738807ce60ef7d042699decb7156931931682cf46e6adc991dc9ecb.apk, 97886afc752048f8d8044120044ac7396e50b78b74b7e0077b8881b4eee7da6a.apk, 994869cacc3615cde8d4196cdfe1e2877f0e1328ff32a292963ffd0983b450fa.apk, 9a1ac04b85cc6f35cd83382f258254556a37f1fc314020dbecbde033caa00a8d.apk, 9e7d743c341329104a12cfbcf53cc19a9b16c4ec1a874f8d4b42b33e9a68c1f8.apk, a126d643c83163c3cf7830de9cf2fc11b6b1eca77e10e0ce48e9e2edaaf2425e.apk, a31788dbc93e0e00318afc0df550f22b20a6c5823696195d630197228721a53c.apk, a4fd3292b7bc5800f8d9b3a3e4c6a757daeb0800cae762cf2294012cee5604f5.apk, a764bd1b5f0f0ea0554eec5cebf111f56ea5e9969391e467a45c46ff96309da4.apk, a8030b195f685a2c1b3a5de807f769d38f87efff8bab8c5bfce5a6fabedcc477.apk, a8062f50057c4d8be86c50b411addafa7429b451420b3aaeb1ec6f04aef18957.apk, a81b801522a1c72be91aefffa09b00256fad4ee9d47bb8d79b018b442ab4e78b.apk, aab9cf77aca821c3f2930315c2afd140ff12441f0d8f0cb0d45927ef7af43ed5.apk, b4b2197c5a8f0e9b9766fa39e9b538568284ec8a0099811b8b54fe6a1402545b.apk, b4bfe02a51dde614538414162222759255fb8a1423489b8cf4db3fb7d380e6b0.apk, b50dfd257f1cfda6f67d269571f5e9b251c7f34d54c7f7d865b9d6bed89a49bb.apk, b7273b4a1b2d2a968a890f363e256d6d6b8fdda6a63280e673262f221c76a1fc.apk, b89c57f8781f121938b50631295f96ddf25f18616dcfb4862a7a87a61f0bf7ad.apk, bae41a16babbac0bcf8280bf6a60c78331bfaf50b0b5c31cf6c55ac29c5c7c4a.apk, bc5ecb77e8aee510a380108013e073f0d0f3b41bd9ba2169bcb8eb85b405347f.apk, bc74da49cf58d85b8ce8a49d2ac0fed574ef1634e67d92ef75440d7b24d0a3e4.apk, bca248d31bf87b605e8cca7587a9753d58a9ad9a8f7e6f7f882d03150d72869f.apk, c15a7113d21573038a1e256871fc641d5a94d8e1ea164307ad22e97e7df29aa6.apk, c4bf99a895492e137b3eb4a1425526f382163068ea5f1a11a5be7920ddb3f6b5.apk, c585e3cbaa19ff4934e07f77f447c87a94f21793f9ff35301e1689849d796745.apk, ca5b40e938f68321dfa3a7f1ad2a03db4ff6ba27fdae5e230654cd5c30090692.apk, cac4a6a67213b3ddf66647c62db64f918132f8e21ee6bc1def13b82b2d6d6d1b.apk, cadcce6d4088c72fd0779d59d00f5753eaab585a263e3c92374df29ae767ac15.apk, cc8f90a002a2ed7579451d7b920ae3b44ac65bd12dbeea960dcad5fed6cb3ef3.apk, cfd656e0d18e1ed7064941197e6504a4b1cdcd3bc6476389dca71237dd839284.apk, d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2.apk, d3c63ecb3a95272a043b3e0ab792a70738c867ba18e896c455d9c39d32fff4d3.apk, d566c64a41faf573349cf2c0ecb00f68dbe8b90bc1968d3317d3a20667ddad63.apk, d5a84c85508c444743d055be354a464eb22dc5b33cba41e4b149829d182f4dca.apk, d8a1e20efc746499b3f5adb44b36838f8349da57260bba498b2b7e89633f3fd4.apk, d9b75d606803968d04015bed042da887905e9c1cb1b40b4ff11852b88c8b4d21.apk, dbcf1e78a34e742832a2dbe46eec985ede3ff659c7f5801611c3b22b5a5cd379.apk, dc2a780f6abb9f0ec0a6675f20acb91ebe2a8748297682a59daf9164fbea2ee8.apk, ddfb37acf2abc5458c9a7003e4f0559b615bf5ba0334a3801b1e3bb694733c79.apk, e0f530acc605475dc38c1bae9ecf9f7c94c80b8f24b695e3f8025dba1e8d5c22.apk, e104e343d5d6db290a76ac90d19917ff88d000bd891be7b9cdab1eb66525f8ea.apk, e1201982a431915cb6422f29e25d9eb78d50d6a9eeea8202b1070423e9fc8b89.apk, e163a088d174d4eb41479b53e6df04831dc40899b893a0b183d080d2dfe52cd7.apk, e696766abcc6e35ca39a6d6bd1145a7297993f69c2179fc94c84a62519e8b84f.apk, e8f780e2835e2a072b45219823b8c018a09c4971c754e10c264eac9eb04b884d.apk, f0d43f00ccae66633aa086433b402435d0a99c2f910e2c6122abc48e35b8cc3f.apk, f193b84bdbd573bf1e86522b857035d39a059f9ef350e403f72dd14449fba169.apk, f7a9da64386f6c02c3911c73ff6754118deb3cae20e52abfb85bbc855b404aca.apk, f8081269cf465c7e7c75e078cd1e8005e6c7091168a235d9d161801a4f31641a.apk, f81d01e7361d276658306125e375453244f28d9ecca6c855e48e6fab88826267.apk, f902a8c4de97bd168839457fb1a3e89149c3e44d8eacbbab070d969ad655ee07.apk, f99486a60b7f8ae9ba5cf991d422954466017dfc4020ca7563655e9ebc8713f7.apk, faa774978f43368357f553a1e45a2f9465fcfa50c6c09dbf6004304db03bc641.apk, faab917444988b9a2e8d5d5bc06a0423c53718f92cbb8840cc6632f464c89130.apk, fb505c8301b579bff83e77bbd9038cb583a1f207f88a04986a646ad0f9b04d09.apk, fce8298e4849d80d2191f1a9cf430fee0de57c6448501f544b17a0ce7c1f01d4.apk, fcf61a8a80a61ffb6c29ae60f334cbb9d9054026576a873b9d1a71013c8d0737.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "0007aff422a0c7ae9928eae16237ddd1a29e90180c44ede869ecb55c6182879d"
      hash2 = "0027c816cc740251e8f2d271cbaf7397706a1db07cc14b842d962fee8991daf6"
      hash3 = "018f8548c055a31d98201874ebf21591e6d85cb9eee66e8c35716a9289d01f48"
      hash4 = "02cd74a277a19ef59375d44e6111c5c887a2dd2313a2a7129c98e5967dc69ecc"
      hash5 = "04e4acc8cd2a66f77260ebcfbe40646192ff452d5f9bbe54e0acbd0cabc3cfbc"
      hash6 = "0619168a8df6dd350052ca3a578abe15da0f2177e65acea55f44b5b59ed5f1c8"
      hash7 = "0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169"
      hash8 = "0badd9b4b0e44daeaa75b5d97ed9611a9f84418c1fb5683130e8b22742086549"
      hash9 = "0c8085cea946d655b266998fd60b1da33df73a4285328da3dabc7f0e7211411d"
      hash10 = "0f9fe82c6594fe331e59cf0268bc402f9e31141a3fd5e5dd99596d28563c5e9b"
      hash11 = "1077e767d28e8b97be3ebc98ceab110c14335260b47a3a0fdfcb77b6a2ccf080"
      hash12 = "1099eede57e825fa5158b33f01559dc76e6d67e2fca37b97f76e7d3aa9a4208a"
      hash13 = "121e82504dfbada0fd5cec2bd6bec7a518f8afce65b43ded20498f3f5cb5c05c"
      hash14 = "12cb6136d2d325563b5079c138eeac2bc4ee4af3373718ba1c79c47a6121829e"
      hash15 = "174deed18377e5280413a2015ebe2041fd8b4276a6599754299cf05cea0718d5"
      hash16 = "185a01ec24938cd5a9af4fd66a0814e8bfaf2e1ff8cfa2396a30c3e4f6e66b98"
      hash17 = "1b5ff50963c6e99dfb521e6db624df9f83f21f06430ce9d8f3cd0de735cbe22a"
      hash18 = "246bdb0a9e7698e37ec7b906551ceed302d0445c9572bb3cdc02a68862fd2d2a"
      hash19 = "2d0fd4ea41c4e17cf94577c126ae271555b544f388baca69112cd3a488572be1"
      hash20 = "2f451d9cfda5d91b2063a62ed5ad482cd733e899b9ee39ee8bd332b518b3b865"
      hash21 = "33c3f43852f6ecadef74aef2dbb0d5a1215aa3cb23e4aaf76f202beed3aa8703"
      hash22 = "340d1ff4143a560c2ca4400a6c2ca6e9448b6392c203ec190893e773b7a00265"
      hash23 = "3434bad9d01dad7ad4e7525a3936c527376699e3505e70171b083c1226f0e90c"
      hash24 = "3616fd6004678159e531fb7e5a173b333c08bd0097aa1f6a4e9f503db4a9999a"
      hash25 = "3638754e7fd889e9ced9127e7abe08191b7e8df3d60ed284c7b507e1e8082613"
      hash26 = "399c4819af422e581639c9350dcba71b0ee00b87a4d37da11806db5e25a0adc5"
      hash27 = "3ab3cc3c0df02d723c850e712fa5f4a0de29f2addf2c50beffe222112c2baa38"
      hash28 = "3c0a6f866aa4d74d0b39a2b9d11692ffa7291fd46b414e73cd5f9c7f9f030b75"
      hash29 = "3d8da22674ee343bd02296a4351e90198ffc786f8541747e42cdcf3438f16b3e"
      hash30 = "41930e6f9187c8be4ea41303dd957d74f65b97944321a24a20028e76d10e0588"
      hash31 = "43996d454961143bad870d9b94a3d00912f7c29b76371244ac59423595ae0860"
      hash32 = "44612fabf9a13d78f845f0932c6f332647684c8017f5a8410ec24b483a186e27"
      hash33 = "446800befecf9179f9aca09dd88331dee0e745b199db39a9b0113f4ee886ca34"
      hash34 = "44ce621f601a8c68f8984324e2883cb431adcae410a60a36f6f252ad5d0fd467"
      hash35 = "469b13cac1eb859da7ba4b597270f047b11815bfff9c4ad3faa5617c07a6c3e0"
      hash36 = "4e6c3f36a00638652d94b6a79722c7e40e11d73674fc49b4dbdadbe82acae581"
      hash37 = "4f0508904ec488ea7767e9d124b78097aefa8f43cc1713e81a7c4f45e1ba77f0"
      hash38 = "50990c1178790239445d4dea570e4affeca6efbb01a91cbf4af4498a0477dd2e"
      hash39 = "53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee"
      hash40 = "55c111e642c6aebcb75fc9db89def8adcd73ae1d5eb6b11b7c8dc590d14d0804"
      hash41 = "57a0a81eebdf6c1e0a5ab0489165f167856712121b86959f0c34ce5c24014266"
      hash42 = "59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f"
      hash43 = "5a2306804771a975f692d6cc1cbaf06af1b86273301b3af8069f4d36a27d3866"
      hash44 = "5cb94ba3236bd4fa89bad460687cc2f1e80a890f5a093e954ea2704c1950c1f3"
      hash45 = "5dff60862aea80d5da616400359ae170f2d9ef9d76a745417f4facff72cd4c17"
      hash46 = "5f6016b9bcaf98d2276187b7ef74a1662bd7e21e610ebed2b2ce5a7aea799600"
      hash47 = "6406d67b9abef51ee7058c77f886e5828e23c1bf8f31373f8ca2df65abb5b431"
      hash48 = "64b4f8c86ea5ef925da573e7667ca93d32f4fb27fd6a702f5e99ccc4d087f612"
      hash49 = "6564e7362b89d453173884e35d96ff5ce1de7ecbad102b0f5450300418b5de9b"
      hash50 = "657881e96def3e69a401f79c678edff27c3db4db74ba802fb8989ae466f73cc9"
      hash51 = "662bb00e9a82d43be45413fce12def326a1863f9cd3e63aa45b60d36ef7e0443"
      hash52 = "6a702c55f4ee54eeb35a991d7413328da1e56dde6e719babec23682423bec23f"
      hash53 = "6dd19edd60ed2025afc6b661e85f146c925f2137e51ae49c5d1dce955ac43aaf"
      hash54 = "6ec479136b4fb6809638e874d9d606f6d4b1f44a686f61954bb6883d548333fa"
      hash55 = "7063baf053aa3faf308f1b3205dcb7495f74a1621d472b151ecc4f5fadccd369"
      hash56 = "734b154c74808cac4726650bd8648be1ed42282aba70f69be763ba42ff602bf7"
      hash57 = "73aef1d852c9c4001b1a7db673e03417d30f489e56db5813a8757866c2641028"
      hash58 = "75b4d9eb26ed9e20009c9a55a58e66457d7ec4d7d060179f09f6522e96c62e2e"
      hash59 = "75cd6f164dee674a18edc5154ef0d48633eb581b73d77aef047af0a5856420cc"
      hash60 = "76798397118c81edf2ef4588a60578a8700017afb98b040657b39cccdbe30009"
      hash61 = "77c54058a2bb45219e6ee860430f5ea8ce8e6ed2e58fba05f0d9bf74ffb7b4ef"
      hash62 = "7b167d362a9282adb176095be2e5bd4692b4158b7bdf4c6c20870daed5b04665"
      hash63 = "7b40e010ae6556b159eaaba4f0989bd57cc510c388215f2d89580cc3379ae33c"
      hash64 = "80448bc12448336f023d890b29ebf2a854f325ad010aa05d2f632870be9c8677"
      hash65 = "807d8ffb7975d525386036b10563485033155f62d4355a83e372b08b370c3850"
      hash66 = "809d07b61da605e1eab3aedbc25ed1eba0dfd48f15c8fa7c03d73ab19c95f5ff"
      hash67 = "8166dfba7fd0b4ad44c8bc91cc0e98fa06b8912e3fca2093900eb58ba79d22d4"
      hash68 = "857d9e064fe567da2b5f42b49787d05d0238f34ddc2890a826d80d8f012f7e8d"
      hash69 = "88d598aa4b9272f14913d42937586992d0a5e35e656ca315e33ecaa81628f04c"
      hash70 = "8c7dbb2080f2b862026b2d755cb01c4b484c357c7aa5e053398ee6fe497c6374"
      hash71 = "8ef35a9062369b6ce2e99571b0dc263be74ef888548a1072c609581b9adf3a93"
      hash72 = "904e4153d2026380dc42297173192e72de7e5d9ea50f16bf8df2e2fa6922cdc3"
      hash73 = "90ac64358498e62a5718e92d9ede7c7e0fb30aa39c6cc94d4ac38010208cc255"
      hash74 = "95236ef71738807ce60ef7d042699decb7156931931682cf46e6adc991dc9ecb"
      hash75 = "97886afc752048f8d8044120044ac7396e50b78b74b7e0077b8881b4eee7da6a"
      hash76 = "994869cacc3615cde8d4196cdfe1e2877f0e1328ff32a292963ffd0983b450fa"
      hash77 = "9a1ac04b85cc6f35cd83382f258254556a37f1fc314020dbecbde033caa00a8d"
      hash78 = "9e7d743c341329104a12cfbcf53cc19a9b16c4ec1a874f8d4b42b33e9a68c1f8"
      hash79 = "a126d643c83163c3cf7830de9cf2fc11b6b1eca77e10e0ce48e9e2edaaf2425e"
      hash80 = "a31788dbc93e0e00318afc0df550f22b20a6c5823696195d630197228721a53c"
      hash81 = "a4fd3292b7bc5800f8d9b3a3e4c6a757daeb0800cae762cf2294012cee5604f5"
      hash82 = "a764bd1b5f0f0ea0554eec5cebf111f56ea5e9969391e467a45c46ff96309da4"
      hash83 = "a8030b195f685a2c1b3a5de807f769d38f87efff8bab8c5bfce5a6fabedcc477"
      hash84 = "a8062f50057c4d8be86c50b411addafa7429b451420b3aaeb1ec6f04aef18957"
      hash85 = "a81b801522a1c72be91aefffa09b00256fad4ee9d47bb8d79b018b442ab4e78b"
      hash86 = "aab9cf77aca821c3f2930315c2afd140ff12441f0d8f0cb0d45927ef7af43ed5"
      hash87 = "b4b2197c5a8f0e9b9766fa39e9b538568284ec8a0099811b8b54fe6a1402545b"
      hash88 = "b4bfe02a51dde614538414162222759255fb8a1423489b8cf4db3fb7d380e6b0"
      hash89 = "b50dfd257f1cfda6f67d269571f5e9b251c7f34d54c7f7d865b9d6bed89a49bb"
      hash90 = "b7273b4a1b2d2a968a890f363e256d6d6b8fdda6a63280e673262f221c76a1fc"
      hash91 = "b89c57f8781f121938b50631295f96ddf25f18616dcfb4862a7a87a61f0bf7ad"
      hash92 = "bae41a16babbac0bcf8280bf6a60c78331bfaf50b0b5c31cf6c55ac29c5c7c4a"
      hash93 = "bc5ecb77e8aee510a380108013e073f0d0f3b41bd9ba2169bcb8eb85b405347f"
      hash94 = "bc74da49cf58d85b8ce8a49d2ac0fed574ef1634e67d92ef75440d7b24d0a3e4"
      hash95 = "bca248d31bf87b605e8cca7587a9753d58a9ad9a8f7e6f7f882d03150d72869f"
      hash96 = "c15a7113d21573038a1e256871fc641d5a94d8e1ea164307ad22e97e7df29aa6"
      hash97 = "c4bf99a895492e137b3eb4a1425526f382163068ea5f1a11a5be7920ddb3f6b5"
      hash98 = "c585e3cbaa19ff4934e07f77f447c87a94f21793f9ff35301e1689849d796745"
      hash99 = "ca5b40e938f68321dfa3a7f1ad2a03db4ff6ba27fdae5e230654cd5c30090692"
      hash100 = "cac4a6a67213b3ddf66647c62db64f918132f8e21ee6bc1def13b82b2d6d6d1b"
      hash101 = "cadcce6d4088c72fd0779d59d00f5753eaab585a263e3c92374df29ae767ac15"
      hash102 = "cc8f90a002a2ed7579451d7b920ae3b44ac65bd12dbeea960dcad5fed6cb3ef3"
      hash103 = "cfd656e0d18e1ed7064941197e6504a4b1cdcd3bc6476389dca71237dd839284"
      hash104 = "d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2"
      hash105 = "d3c63ecb3a95272a043b3e0ab792a70738c867ba18e896c455d9c39d32fff4d3"
      hash106 = "d566c64a41faf573349cf2c0ecb00f68dbe8b90bc1968d3317d3a20667ddad63"
      hash107 = "d5a84c85508c444743d055be354a464eb22dc5b33cba41e4b149829d182f4dca"
      hash108 = "d8a1e20efc746499b3f5adb44b36838f8349da57260bba498b2b7e89633f3fd4"
      hash109 = "d9b75d606803968d04015bed042da887905e9c1cb1b40b4ff11852b88c8b4d21"
      hash110 = "dbcf1e78a34e742832a2dbe46eec985ede3ff659c7f5801611c3b22b5a5cd379"
      hash111 = "dc2a780f6abb9f0ec0a6675f20acb91ebe2a8748297682a59daf9164fbea2ee8"
      hash112 = "ddfb37acf2abc5458c9a7003e4f0559b615bf5ba0334a3801b1e3bb694733c79"
      hash113 = "e0f530acc605475dc38c1bae9ecf9f7c94c80b8f24b695e3f8025dba1e8d5c22"
      hash114 = "e104e343d5d6db290a76ac90d19917ff88d000bd891be7b9cdab1eb66525f8ea"
      hash115 = "e1201982a431915cb6422f29e25d9eb78d50d6a9eeea8202b1070423e9fc8b89"
      hash116 = "e163a088d174d4eb41479b53e6df04831dc40899b893a0b183d080d2dfe52cd7"
      hash117 = "e696766abcc6e35ca39a6d6bd1145a7297993f69c2179fc94c84a62519e8b84f"
      hash118 = "e8f780e2835e2a072b45219823b8c018a09c4971c754e10c264eac9eb04b884d"
      hash119 = "f0d43f00ccae66633aa086433b402435d0a99c2f910e2c6122abc48e35b8cc3f"
      hash120 = "f193b84bdbd573bf1e86522b857035d39a059f9ef350e403f72dd14449fba169"
      hash121 = "f7a9da64386f6c02c3911c73ff6754118deb3cae20e52abfb85bbc855b404aca"
      hash122 = "f8081269cf465c7e7c75e078cd1e8005e6c7091168a235d9d161801a4f31641a"
      hash123 = "f81d01e7361d276658306125e375453244f28d9ecca6c855e48e6fab88826267"
      hash124 = "f902a8c4de97bd168839457fb1a3e89149c3e44d8eacbbab070d969ad655ee07"
      hash125 = "f99486a60b7f8ae9ba5cf991d422954466017dfc4020ca7563655e9ebc8713f7"
      hash126 = "faa774978f43368357f553a1e45a2f9465fcfa50c6c09dbf6004304db03bc641"
      hash127 = "faab917444988b9a2e8d5d5bc06a0423c53718f92cbb8840cc6632f464c89130"
      hash128 = "fb505c8301b579bff83e77bbd9038cb583a1f207f88a04986a646ad0f9b04d09"
      hash129 = "fce8298e4849d80d2191f1a9cf430fee0de57c6448501f544b17a0ce7c1f01d4"
      hash130 = "fcf61a8a80a61ffb6c29ae60f334cbb9d9054026576a873b9d1a71013c8d0737"
   strings:
      $s1 = "unsupported arm register" fullword ascii
      $s2 = "unknown personality routine" fullword ascii
      $s3 = "index inlined table detected but pr function requires extra words" fullword ascii
      $s4 = "unsupported register class" fullword ascii
      $s5 = "Unknown ARM float register" fullword ascii
      $s6 = "during phase1 personality function said it would stop here, but now in phase2 it did not stop here" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _04e4acc8cd2a66f77260ebcfbe40646192ff452d5f9bbe54e0acbd0cabc3cfb_112 {
   meta:
      description = "apk - from files 04e4acc8cd2a66f77260ebcfbe40646192ff452d5f9bbe54e0acbd0cabc3cfbc.apk, 0f9fe82c6594fe331e59cf0268bc402f9e31141a3fd5e5dd99596d28563c5e9b.apk, 1099eede57e825fa5158b33f01559dc76e6d67e2fca37b97f76e7d3aa9a4208a.apk, 174deed18377e5280413a2015ebe2041fd8b4276a6599754299cf05cea0718d5.apk, 185a01ec24938cd5a9af4fd66a0814e8bfaf2e1ff8cfa2396a30c3e4f6e66b98.apk, 1b5ff50963c6e99dfb521e6db624df9f83f21f06430ce9d8f3cd0de735cbe22a.apk, 246bdb0a9e7698e37ec7b906551ceed302d0445c9572bb3cdc02a68862fd2d2a.apk, 25fdf72cb393901eb605d6eaea86fe67483a25295651e2423b9e50d5bfc62111.apk, 2d0fd4ea41c4e17cf94577c126ae271555b544f388baca69112cd3a488572be1.apk, 2f451d9cfda5d91b2063a62ed5ad482cd733e899b9ee39ee8bd332b518b3b865.apk, 33c3f43852f6ecadef74aef2dbb0d5a1215aa3cb23e4aaf76f202beed3aa8703.apk, 3616fd6004678159e531fb7e5a173b333c08bd0097aa1f6a4e9f503db4a9999a.apk, 3d8da22674ee343bd02296a4351e90198ffc786f8541747e42cdcf3438f16b3e.apk, 43996d454961143bad870d9b94a3d00912f7c29b76371244ac59423595ae0860.apk, 446800befecf9179f9aca09dd88331dee0e745b199db39a9b0113f4ee886ca34.apk, 50990c1178790239445d4dea570e4affeca6efbb01a91cbf4af4498a0477dd2e.apk, 5cb94ba3236bd4fa89bad460687cc2f1e80a890f5a093e954ea2704c1950c1f3.apk, 5dff60862aea80d5da616400359ae170f2d9ef9d76a745417f4facff72cd4c17.apk, 64b4f8c86ea5ef925da573e7667ca93d32f4fb27fd6a702f5e99ccc4d087f612.apk, 6564e7362b89d453173884e35d96ff5ce1de7ecbad102b0f5450300418b5de9b.apk, 657881e96def3e69a401f79c678edff27c3db4db74ba802fb8989ae466f73cc9.apk, 6dd19edd60ed2025afc6b661e85f146c925f2137e51ae49c5d1dce955ac43aaf.apk, 75cd6f164dee674a18edc5154ef0d48633eb581b73d77aef047af0a5856420cc.apk, 77c54058a2bb45219e6ee860430f5ea8ce8e6ed2e58fba05f0d9bf74ffb7b4ef.apk, 7b40e010ae6556b159eaaba4f0989bd57cc510c388215f2d89580cc3379ae33c.apk, 807d8ffb7975d525386036b10563485033155f62d4355a83e372b08b370c3850.apk, 857d9e064fe567da2b5f42b49787d05d0238f34ddc2890a826d80d8f012f7e8d.apk, 994869cacc3615cde8d4196cdfe1e2877f0e1328ff32a292963ffd0983b450fa.apk, 9e7d743c341329104a12cfbcf53cc19a9b16c4ec1a874f8d4b42b33e9a68c1f8.apk, a8030b195f685a2c1b3a5de807f769d38f87efff8bab8c5bfce5a6fabedcc477.apk, a8062f50057c4d8be86c50b411addafa7429b451420b3aaeb1ec6f04aef18957.apk, a81b801522a1c72be91aefffa09b00256fad4ee9d47bb8d79b018b442ab4e78b.apk, aab9cf77aca821c3f2930315c2afd140ff12441f0d8f0cb0d45927ef7af43ed5.apk, b50dfd257f1cfda6f67d269571f5e9b251c7f34d54c7f7d865b9d6bed89a49bb.apk, bc5ecb77e8aee510a380108013e073f0d0f3b41bd9ba2169bcb8eb85b405347f.apk, bc74da49cf58d85b8ce8a49d2ac0fed574ef1634e67d92ef75440d7b24d0a3e4.apk, c585e3cbaa19ff4934e07f77f447c87a94f21793f9ff35301e1689849d796745.apk, cfd656e0d18e1ed7064941197e6504a4b1cdcd3bc6476389dca71237dd839284.apk, d3c63ecb3a95272a043b3e0ab792a70738c867ba18e896c455d9c39d32fff4d3.apk, d566c64a41faf573349cf2c0ecb00f68dbe8b90bc1968d3317d3a20667ddad63.apk, e696766abcc6e35ca39a6d6bd1145a7297993f69c2179fc94c84a62519e8b84f.apk, e8f780e2835e2a072b45219823b8c018a09c4971c754e10c264eac9eb04b884d.apk, f0d43f00ccae66633aa086433b402435d0a99c2f910e2c6122abc48e35b8cc3f.apk, f8081269cf465c7e7c75e078cd1e8005e6c7091168a235d9d161801a4f31641a.apk, f902a8c4de97bd168839457fb1a3e89149c3e44d8eacbbab070d969ad655ee07.apk, f99486a60b7f8ae9ba5cf991d422954466017dfc4020ca7563655e9ebc8713f7.apk, fb505c8301b579bff83e77bbd9038cb583a1f207f88a04986a646ad0f9b04d09.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "04e4acc8cd2a66f77260ebcfbe40646192ff452d5f9bbe54e0acbd0cabc3cfbc"
      hash2 = "0f9fe82c6594fe331e59cf0268bc402f9e31141a3fd5e5dd99596d28563c5e9b"
      hash3 = "1099eede57e825fa5158b33f01559dc76e6d67e2fca37b97f76e7d3aa9a4208a"
      hash4 = "174deed18377e5280413a2015ebe2041fd8b4276a6599754299cf05cea0718d5"
      hash5 = "185a01ec24938cd5a9af4fd66a0814e8bfaf2e1ff8cfa2396a30c3e4f6e66b98"
      hash6 = "1b5ff50963c6e99dfb521e6db624df9f83f21f06430ce9d8f3cd0de735cbe22a"
      hash7 = "246bdb0a9e7698e37ec7b906551ceed302d0445c9572bb3cdc02a68862fd2d2a"
      hash8 = "25fdf72cb393901eb605d6eaea86fe67483a25295651e2423b9e50d5bfc62111"
      hash9 = "2d0fd4ea41c4e17cf94577c126ae271555b544f388baca69112cd3a488572be1"
      hash10 = "2f451d9cfda5d91b2063a62ed5ad482cd733e899b9ee39ee8bd332b518b3b865"
      hash11 = "33c3f43852f6ecadef74aef2dbb0d5a1215aa3cb23e4aaf76f202beed3aa8703"
      hash12 = "3616fd6004678159e531fb7e5a173b333c08bd0097aa1f6a4e9f503db4a9999a"
      hash13 = "3d8da22674ee343bd02296a4351e90198ffc786f8541747e42cdcf3438f16b3e"
      hash14 = "43996d454961143bad870d9b94a3d00912f7c29b76371244ac59423595ae0860"
      hash15 = "446800befecf9179f9aca09dd88331dee0e745b199db39a9b0113f4ee886ca34"
      hash16 = "50990c1178790239445d4dea570e4affeca6efbb01a91cbf4af4498a0477dd2e"
      hash17 = "5cb94ba3236bd4fa89bad460687cc2f1e80a890f5a093e954ea2704c1950c1f3"
      hash18 = "5dff60862aea80d5da616400359ae170f2d9ef9d76a745417f4facff72cd4c17"
      hash19 = "64b4f8c86ea5ef925da573e7667ca93d32f4fb27fd6a702f5e99ccc4d087f612"
      hash20 = "6564e7362b89d453173884e35d96ff5ce1de7ecbad102b0f5450300418b5de9b"
      hash21 = "657881e96def3e69a401f79c678edff27c3db4db74ba802fb8989ae466f73cc9"
      hash22 = "6dd19edd60ed2025afc6b661e85f146c925f2137e51ae49c5d1dce955ac43aaf"
      hash23 = "75cd6f164dee674a18edc5154ef0d48633eb581b73d77aef047af0a5856420cc"
      hash24 = "77c54058a2bb45219e6ee860430f5ea8ce8e6ed2e58fba05f0d9bf74ffb7b4ef"
      hash25 = "7b40e010ae6556b159eaaba4f0989bd57cc510c388215f2d89580cc3379ae33c"
      hash26 = "807d8ffb7975d525386036b10563485033155f62d4355a83e372b08b370c3850"
      hash27 = "857d9e064fe567da2b5f42b49787d05d0238f34ddc2890a826d80d8f012f7e8d"
      hash28 = "994869cacc3615cde8d4196cdfe1e2877f0e1328ff32a292963ffd0983b450fa"
      hash29 = "9e7d743c341329104a12cfbcf53cc19a9b16c4ec1a874f8d4b42b33e9a68c1f8"
      hash30 = "a8030b195f685a2c1b3a5de807f769d38f87efff8bab8c5bfce5a6fabedcc477"
      hash31 = "a8062f50057c4d8be86c50b411addafa7429b451420b3aaeb1ec6f04aef18957"
      hash32 = "a81b801522a1c72be91aefffa09b00256fad4ee9d47bb8d79b018b442ab4e78b"
      hash33 = "aab9cf77aca821c3f2930315c2afd140ff12441f0d8f0cb0d45927ef7af43ed5"
      hash34 = "b50dfd257f1cfda6f67d269571f5e9b251c7f34d54c7f7d865b9d6bed89a49bb"
      hash35 = "bc5ecb77e8aee510a380108013e073f0d0f3b41bd9ba2169bcb8eb85b405347f"
      hash36 = "bc74da49cf58d85b8ce8a49d2ac0fed574ef1634e67d92ef75440d7b24d0a3e4"
      hash37 = "c585e3cbaa19ff4934e07f77f447c87a94f21793f9ff35301e1689849d796745"
      hash38 = "cfd656e0d18e1ed7064941197e6504a4b1cdcd3bc6476389dca71237dd839284"
      hash39 = "d3c63ecb3a95272a043b3e0ab792a70738c867ba18e896c455d9c39d32fff4d3"
      hash40 = "d566c64a41faf573349cf2c0ecb00f68dbe8b90bc1968d3317d3a20667ddad63"
      hash41 = "e696766abcc6e35ca39a6d6bd1145a7297993f69c2179fc94c84a62519e8b84f"
      hash42 = "e8f780e2835e2a072b45219823b8c018a09c4971c754e10c264eac9eb04b884d"
      hash43 = "f0d43f00ccae66633aa086433b402435d0a99c2f910e2c6122abc48e35b8cc3f"
      hash44 = "f8081269cf465c7e7c75e078cd1e8005e6c7091168a235d9d161801a4f31641a"
      hash45 = "f902a8c4de97bd168839457fb1a3e89149c3e44d8eacbbab070d969ad655ee07"
      hash46 = "f99486a60b7f8ae9ba5cf991d422954466017dfc4020ca7563655e9ebc8713f7"
      hash47 = "fb505c8301b579bff83e77bbd9038cb583a1f207f88a04986a646ad0f9b04d09"
   strings:
      $s1 = "TO VIEW PHOTO" fullword ascii
      $s2 = "PARA VER LA FOTO" fullword ascii
      $s3 = "CONTINUE." fullword ascii
      $s4 = "POUR VOIR LA PHOTO" fullword ascii
      $s5 = "CONTINUER." fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca616_113 {
   meta:
      description = "apk - from files 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c3.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 17fc5d1c8bd8b10471131282e42ec289bb1e1ee107ca676f369bb42fc3643af3.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 3502fa570ada49eaeeaa4785bb1897ed91dfadaa76c5e8626c5b8e944d8f5f01.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 57940c5eee8641e02f49d1122528665a0ddfbf5b6b0d4b910b5287e15542591d.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 6376bcd8faa57aac7437116b184967a588025e2bf96318272cdcf51ff2f8dfdd.apk, 6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e.apk, 6eb525100f54b9a830cd2d0f1169b053edb55332b2be73dd29a8b165b9ccdbf5.apk, 6f58b07b5ddabc29c9c7e7165349edbd2bee923446514044d67040de2f36664a.apk, 7593b0f4bc4c52cb359196f35868636b319641b01c8db9f662076285739a0505.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a6ed100ae42e4fdabfd1b4c992762152bc4a11cc8e521b647b444c75bb7a9782.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, b99d175cbe06d4569a18449da044f326c68a56315ccc0da9cfa6f2c33bfd0939.apk, bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, c54861f54bcf72de5f16611ef0eec32c5c5f937bf3fdb5d6e611b2a2f9acdf2a.apk, c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64.apk, d0d4ef735a8bf076d81a6f3651d6bcfd8c69285049add2e6b6bee1276a99c37c.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, ef16cc8137d29356d0ef23b61ddb9cfd5e2784578fa818d54fe670bfa1e6ef73.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169"
      hash2 = "0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c3"
      hash3 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash4 = "134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138"
      hash5 = "17fc5d1c8bd8b10471131282e42ec289bb1e1ee107ca676f369bb42fc3643af3"
      hash6 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash7 = "3502fa570ada49eaeeaa4785bb1897ed91dfadaa76c5e8626c5b8e944d8f5f01"
      hash8 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash9 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash10 = "53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee"
      hash11 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash12 = "57940c5eee8641e02f49d1122528665a0ddfbf5b6b0d4b910b5287e15542591d"
      hash13 = "5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8"
      hash14 = "6376bcd8faa57aac7437116b184967a588025e2bf96318272cdcf51ff2f8dfdd"
      hash15 = "6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e"
      hash16 = "6eb525100f54b9a830cd2d0f1169b053edb55332b2be73dd29a8b165b9ccdbf5"
      hash17 = "6f58b07b5ddabc29c9c7e7165349edbd2bee923446514044d67040de2f36664a"
      hash18 = "7593b0f4bc4c52cb359196f35868636b319641b01c8db9f662076285739a0505"
      hash19 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash20 = "8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af"
      hash21 = "8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e"
      hash22 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash23 = "a6ed100ae42e4fdabfd1b4c992762152bc4a11cc8e521b647b444c75bb7a9782"
      hash24 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash25 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash26 = "b99d175cbe06d4569a18449da044f326c68a56315ccc0da9cfa6f2c33bfd0939"
      hash27 = "bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7"
      hash28 = "bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0"
      hash29 = "c54861f54bcf72de5f16611ef0eec32c5c5f937bf3fdb5d6e611b2a2f9acdf2a"
      hash30 = "c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64"
      hash31 = "d0d4ef735a8bf076d81a6f3651d6bcfd8c69285049add2e6b6bee1276a99c37c"
      hash32 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash33 = "ef16cc8137d29356d0ef23b61ddb9cfd5e2784578fa818d54fe670bfa1e6ef73"
      hash34 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "LL%1$s aplikazioak ez du funtzionatuko Google Play Services gaitzen ez baduzu." fullword ascii
      $s2 = "Gaitu Google Play Services" fullword ascii
      $s3 = "VVGoogle Play Services-en bertsio berria behar da. Berehala eguneratuko da automatikoki." fullword ascii
      $s4 = "RR%1$s ez da exekutatuko Google Play Services gabe, baina ez dago halakorik gailuan." fullword ascii
      $s5 = "SS%1$s ez da exekutatuko Google Play Services gabe; zerbitzu hori eguneratzen ari da." fullword ascii
      $s6 = "Eguneratu Google Play Services" fullword ascii
      $s7 = "))Google Play Services-en erabilgarritasuna" fullword ascii
      $s8 = "hh%1$s aplikazioa ezin da erabili Google Play Services gabe, baina zure gailua ez da harekin bateragarria." fullword ascii
      $s9 = "Lortu Google Play Services" fullword ascii
      $s10 = "BB%1$s ez da exekutatuko Google Play Services eguneratzen ez baduzu." fullword ascii
      $s11 = "Google Play Services-en errorea" fullword ascii
      $s12 = "EGPotrebna je nova verzija Google Play usluga. Uskoro c" fullword ascii
      $s13 = "#MGoogle Play" fullword ascii
      $s14 = "\"JGoogle Play " fullword ascii
      $s15 = "CGoogle Play " fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _14ebed0d51768cfa90ace0d74ce17763a7accd1c526976e5b4609156521e7ca_114 {
   meta:
      description = "apk - from files 14ebed0d51768cfa90ace0d74ce17763a7accd1c526976e5b4609156521e7ca8.apk, 16e5dff97af159b8093c1cc0ad59d12a141bcb6e0c530ed86e22c7f61f049c3d.apk, 2b6d20746ed11f62b35a7c29d1912de18248e9e10247c29a6ee0929877a57d77.apk, 82c352ef200bf69c49550c022fba8c33f96d6f1d9ba5fd5d1e53e7a4312fd006.apk, 8de3ebe6fd8eef3d2bfa439913cac77ecb562c754a8935b1eb08eeae93b16173.apk, 97936d7873348f905d119dd9399261374aae494296e1b5fb3df521ef3cc76405.apk, 9aafbc143c66661609f34c483a85015f30f7da2a38f375d9e10c8eeadc6cb5da.apk, cec6fc6496687b177b14d6699d82a18840b528bff5543dfb6e23c0849f3c8de2.apk, d19edfbc70474a76b2dd6d8d0e844404f7b4c364c2278a6a668159e83310598a.apk, deb2cc80a190e73d81758b738bac4e8f0f116b587b07d65ddc8b668f0b89b0bb.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "14ebed0d51768cfa90ace0d74ce17763a7accd1c526976e5b4609156521e7ca8"
      hash2 = "16e5dff97af159b8093c1cc0ad59d12a141bcb6e0c530ed86e22c7f61f049c3d"
      hash3 = "2b6d20746ed11f62b35a7c29d1912de18248e9e10247c29a6ee0929877a57d77"
      hash4 = "82c352ef200bf69c49550c022fba8c33f96d6f1d9ba5fd5d1e53e7a4312fd006"
      hash5 = "8de3ebe6fd8eef3d2bfa439913cac77ecb562c754a8935b1eb08eeae93b16173"
      hash6 = "97936d7873348f905d119dd9399261374aae494296e1b5fb3df521ef3cc76405"
      hash7 = "9aafbc143c66661609f34c483a85015f30f7da2a38f375d9e10c8eeadc6cb5da"
      hash8 = "cec6fc6496687b177b14d6699d82a18840b528bff5543dfb6e23c0849f3c8de2"
      hash9 = "d19edfbc70474a76b2dd6d8d0e844404f7b4c364c2278a6a668159e83310598a"
      hash10 = "deb2cc80a190e73d81758b738bac4e8f0f116b587b07d65ddc8b668f0b89b0bb"
   strings:
      $s1 = "nd encrypted backup." fullword ascii
      $s2 = " community." fullword ascii
      $s3 = " service team." fullword ascii
      $s4 = "DDDelete \"%s\" group?" fullword ascii
      $s5 = "d receive SMS." fullword ascii
      $s6 = "Tap to change." fullword ascii
      $s7 = "and install it again." fullword ascii
      $s8 = "f=\"device-confirmation-learn-more\">Learn more</a>" fullword ascii
      $s9 = "hone number." fullword ascii
      $s10 = "o change." fullword ascii
      $s11 = "tion will erase all locally stored data and is not reversible." fullword ascii
      $s12 = "MMDelete \"%s\" broadcast list?" fullword ascii
      $s13 = "up and try again." fullword ascii
      $s14 = "in later." fullword ascii
      $s15 = "HHDelete broadcast list?" fullword ascii
      $s16 = "p admins control who can change this setting. <a href=\"learn-more\">Learn" fullword ascii
      $s17 = "rity precautions, this file cannot be sent." fullword ascii
      $s18 = "en kept. Group admins control who can change this setting. <a href=\"learn-more\">Learn" fullword ascii
      $s19 = " can turn this setting back on at any time." fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb4_115 {
   meta:
      description = "apk - from files 017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44.apk, 0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e.apk, 05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a.apk, 08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c.apk, 090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90ba268.apk, 091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d96241620a5.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd.apk, 0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea.apk, 13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52.apk, 1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90.apk, 19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c20271e62.apk, 1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0.apk, 1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9.apk, 21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e494fe.apk, 22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b.apk, 23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61.apk, 269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471eed36.apk, 29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896.apk, 2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0.apk, 2e11badbd558a37c88ee22a7315c8220b90213fb712ea1ec1f39b14e3ae8475c.apk, 2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b.apk, 3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089.apk, 34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45.apk, 392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647.apk, 3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5dce6.apk, 3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd.apk, 3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec.apk, 3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c.apk, 41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce.apk, 4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951.apk, 4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f.apk, 4a899a3b0fd61937ce8555cb0da53daf72dadc7dd299c63e90b4a203e5a14db1.apk, 4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290.apk, 4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088.apk, 4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b.apk, 59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f.apk, 5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8.apk, 5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a.apk, 64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3.apk, 6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3.apk, 6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22.apk, 6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8.apk, 6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa8255405.apk, 6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738.apk, 73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4.apk, 73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a.apk, 752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e40ab.apk, 7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570.apk, 774af64259ad726296fb4fc56ca91897c7da9acb3a10ad49325ead714f6562c4.apk, 78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b.apk, 7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144.apk, 79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826fdd3.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, 7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf26527b7.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a.apk, 9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e0ece.apk, 9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5.apk, 9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d.apk, 9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3bb5d1.apk, 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk, 9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b3306.apk, 9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6.apk, a2c509d0b0fcee3bc503bd12986da2d29c74ebcd37abb1af8988f7f26382663d.apk, a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8.apk, ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de.apk, afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4.apk, b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk, b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e.apk, b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33.apk, bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de.apk, c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14.apk, c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9.apk, c659454dd6ed62bc7a0c9e0455297e41ba57b0b7935a826150c1f8c0db6f89d2.apk, c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d.apk, c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk, cb147e7ce69723523f604da875d78ca4738e5f416d2297910ee179a5067e79fe.apk, ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9.apk, ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642.apk, d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af.apk, d1fec0ce2be2097357d307e835783380ac010c7d55f3e72fa3906f0d0edd7a6a.apk, d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3.apk, d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd.apk, d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2.apk, d3fc5ffdd9a68a3063b1c8ff15334238dd39a63b9c93ec9f337bdd5f5357046a.apk, d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5.apk, d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38.apk, e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3.apk, e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938.apk, e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75.apk, e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b.apk, e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8.apk, e756a707443f382f4f93ca4b6101de16e4cac521d9032171c7b68b3a9585c39e.apk, e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk, f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2.apk, f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65.apk, faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44"
      hash2 = "0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e"
      hash3 = "05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a"
      hash4 = "08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c"
      hash5 = "090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90ba268"
      hash6 = "091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d96241620a5"
      hash7 = "0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169"
      hash8 = "0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd"
      hash9 = "0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072"
      hash10 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash11 = "1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea"
      hash12 = "13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52"
      hash13 = "1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90"
      hash14 = "19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c20271e62"
      hash15 = "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
      hash16 = "1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9"
      hash17 = "21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e494fe"
      hash18 = "22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b"
      hash19 = "23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61"
      hash20 = "269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471eed36"
      hash21 = "29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896"
      hash22 = "2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0"
      hash23 = "2e11badbd558a37c88ee22a7315c8220b90213fb712ea1ec1f39b14e3ae8475c"
      hash24 = "2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1"
      hash25 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash26 = "31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b"
      hash27 = "3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089"
      hash28 = "34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45"
      hash29 = "392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d"
      hash30 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash31 = "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
      hash32 = "3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5dce6"
      hash33 = "3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd"
      hash34 = "3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec"
      hash35 = "3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c"
      hash36 = "41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2"
      hash37 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash38 = "48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce"
      hash39 = "4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951"
      hash40 = "4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f"
      hash41 = "4a899a3b0fd61937ce8555cb0da53daf72dadc7dd299c63e90b4a203e5a14db1"
      hash42 = "4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290"
      hash43 = "4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088"
      hash44 = "4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7"
      hash45 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash46 = "563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b"
      hash47 = "59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f"
      hash48 = "5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8"
      hash49 = "5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a"
      hash50 = "64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3"
      hash51 = "6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3"
      hash52 = "6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22"
      hash53 = "6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8"
      hash54 = "6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa8255405"
      hash55 = "6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738"
      hash56 = "73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4"
      hash57 = "73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a"
      hash58 = "752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e40ab"
      hash59 = "7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570"
      hash60 = "774af64259ad726296fb4fc56ca91897c7da9acb3a10ad49325ead714f6562c4"
      hash61 = "78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b"
      hash62 = "7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144"
      hash63 = "79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826fdd3"
      hash64 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
      hash65 = "7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf26527b7"
      hash66 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash67 = "8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af"
      hash68 = "90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a"
      hash69 = "9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e0ece"
      hash70 = "9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5"
      hash71 = "9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d"
      hash72 = "9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3bb5d1"
      hash73 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
      hash74 = "9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b3306"
      hash75 = "9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6"
      hash76 = "a2c509d0b0fcee3bc503bd12986da2d29c74ebcd37abb1af8988f7f26382663d"
      hash77 = "a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2"
      hash78 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash79 = "aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8"
      hash80 = "ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de"
      hash81 = "afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4"
      hash82 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
      hash83 = "b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e"
      hash84 = "b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99"
      hash85 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash86 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash87 = "ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33"
      hash88 = "bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7"
      hash89 = "bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0"
      hash90 = "bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de"
      hash91 = "c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14"
      hash92 = "c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9"
      hash93 = "c659454dd6ed62bc7a0c9e0455297e41ba57b0b7935a826150c1f8c0db6f89d2"
      hash94 = "c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d"
      hash95 = "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
      hash96 = "cb147e7ce69723523f604da875d78ca4738e5f416d2297910ee179a5067e79fe"
      hash97 = "ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9"
      hash98 = "ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642"
      hash99 = "d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af"
      hash100 = "d1fec0ce2be2097357d307e835783380ac010c7d55f3e72fa3906f0d0edd7a6a"
      hash101 = "d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3"
      hash102 = "d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd"
      hash103 = "d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2"
      hash104 = "d3fc5ffdd9a68a3063b1c8ff15334238dd39a63b9c93ec9f337bdd5f5357046a"
      hash105 = "d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5"
      hash106 = "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
      hash107 = "e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3"
      hash108 = "e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938"
      hash109 = "e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75"
      hash110 = "e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b"
      hash111 = "e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8"
      hash112 = "e756a707443f382f4f93ca4b6101de16e4cac521d9032171c7b68b3a9585c39e"
      hash113 = "e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf"
      hash114 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash115 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
      hash116 = "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
      hash117 = "f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65"
      hash118 = "faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a"
      hash119 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
      hash120 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "mite donju tablicu" fullword ascii
      $s2 = "Het blad onderaan samenvouwen" fullword ascii
      $s3 = "I-drag ang handle" fullword ascii
      $s4 = "Mostrar la hoja inferior" fullword ascii
      $s5 = "Vou die onderste blad in" fullword ascii
      $s6 = "I-expand ang bottom sheet" fullword ascii
      $s7 = "Ocultar la hoja inferior" fullword ascii
      $s8 = "Het blad onderaan uitvouwen" fullword ascii
      $s9 = "Vou die onderste blad uit" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc_116 {
   meta:
      description = "apk - from files 2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1.apk, 3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1"
      hash2 = "3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd"
   strings:
      $s1 = "Login Failed:" fullword ascii
      $s2 = "Falha no login:" fullword ascii
      $s3 = "'+Servicio al cliente Telegram" fullword ascii
      $s4 = "Support Telegram" fullword ascii
      $s5 = "#Atendimento Telegram" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84_117 {
   meta:
      description = "apk - from files 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e.apk, b99d175cbe06d4569a18449da044f326c68a56315ccc0da9cfa6f2c33bfd0939.apk, bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, c54861f54bcf72de5f16611ef0eec32c5c5f937bf3fdb5d6e611b2a2f9acdf2a.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash2 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash3 = "6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e"
      hash4 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash5 = "8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af"
      hash6 = "8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e"
      hash7 = "b99d175cbe06d4569a18449da044f326c68a56315ccc0da9cfa6f2c33bfd0939"
      hash8 = "bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7"
      hash9 = "bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0"
      hash10 = "c54861f54bcf72de5f16611ef0eec32c5c5f937bf3fdb5d6e611b2a2f9acdf2a"
      hash11 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash12 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = " actualizezi serviciile Google Play." fullword ascii
      $s2 = " serviciile Google Play" fullword ascii
      $s3 = " activezi serviciile Google Play." fullword ascii
      $s4 = " serviciile Google Play, care lipsesc de pe dispozitivul t" fullword ascii
      $s5 = " serviciile Google Play, care nu sunt acceptate de dispozitivul t" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b_118 {
   meta:
      description = "apk - from files 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, a2a539109b77cfa720f6e1315fa09c82cfb8eb9980b304ba54de6a8279993dd4.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash2 = "a2a539109b77cfa720f6e1315fa09c82cfb8eb9980b304ba54de6a8279993dd4"
      hash3 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash4 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash5 = "bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0"
      hash6 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
      hash7 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "Compartir enlace" fullword ascii
      $s2 = "Compartilhar link" fullword ascii
      $s3 = "Condividi link" fullword ascii
      $s4 = "Im Browser " fullword ascii
      $s5 = "Link teilen" fullword ascii
      $s6 = "Copia link" fullword ascii
      $s7 = "Copiar link" fullword ascii
      $s8 = "Partager le lien" fullword ascii
      $s9 = "Copiar enlace" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _0172d6141fc03c2e152caf35dce6c90cc0cec4f303de270f09136b93f1e99bc_119 {
   meta:
      description = "apk - from files 0172d6141fc03c2e152caf35dce6c90cc0cec4f303de270f09136b93f1e99bcf.apk, 017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44.apk, 01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0.apk, 02944967154e515f87bb411641edd9931ea6b4a4088ab73efe87cbe7b9d5b592.apk, 0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e.apk, 05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a.apk, 0619168a8df6dd350052ca3a578abe15da0f2177e65acea55f44b5b59ed5f1c8.apk, 08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c.apk, 090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90ba268.apk, 091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d96241620a5.apk, 09eb87493c014406a0d83996a8b1894da5257fd6166921878a9bbd42b1e9390e.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0badd9b4b0e44daeaa75b5d97ed9611a9f84418c1fb5683130e8b22742086549.apk, 0bd64f2bfd3b3d5427adfeb8bb72d2522d9758c80995bcf09a60c8631e0f1d34.apk, 0c8085cea946d655b266998fd60b1da33df73a4285328da3dabc7f0e7211411d.apk, 0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c3.apk, 0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd.apk, 0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072.apk, 108ca43c5a62640b5e3d71df33c00549c46634c1109c1ac6690df89fbc4211fd.apk, 118f0bba26f3fd4f1c535ba9117ec80eda9945e6a7fe8af7511178ac60a77170.apk, 11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 129ee4f3dd5ecd07a3f815616300a2adcd6702239c1ae3e31a3d61cf7913c4cb.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea.apk, 13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52.apk, 1495da4ff455fceb8fc73f38b75d65be3435c649b2aaf014124e9c58da930c37.apk, 14c47030d8220e682a1ec80c87d56c5bacf7a38abdf30df9bb532a85851259af.apk, 14ebed0d51768cfa90ace0d74ce17763a7accd1c526976e5b4609156521e7ca8.apk, 15839ac050341de16481e5e425f5f1a791547651d4aeda398217f823f0f321f9.apk, 1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90.apk, 17fc5d1c8bd8b10471131282e42ec289bb1e1ee107ca676f369bb42fc3643af3.apk, 19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c20271e62.apk, 1aeae34c264bbfbd4eed6d92a94ac788bfb9b050a54032fde811402d63f18bf8.apk, 1bf9c16cb7c1faae7fa99a57c5d091cbd1e6d5f3c0d79693a3b0990a8b58367d.apk, 1c64737419a6cb1729ae42f232461a723a8b8b1e67fbcba32cacd151fcbaba7d.apk, 1d15f0700a2dda228394bf37ad20ad2bd88c7813d6aca0199a6b40c704f80bc1.apk, 1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c.apk, 1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0.apk, 1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9.apk, 204edbbd9ab906160ea75c77681a47a21f018f18eca0927a901df6fe24fbd532.apk, 2117f4f448674fb5fafa5dd581777d35255253a4b82c9d0be2aac917efec8ae8.apk, 21b6b9c7262fe39d2f2ce49115c9c22f50d3e5b0b083a0f8c1ddd776c369ffd3.apk, 21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e494fe.apk, 22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b.apk, 2308afb58c08eec15d0ad9048e751eeca001bd17a2106484803c45ef351af752.apk, 23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61.apk, 269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471eed36.apk, 272248f64722ef49413a6f3c339aecb78785546c1c65b9c2897e3915bd91be28.apk, 27b8eeb5d1b46e1afa170b998830fe0958f08a2a9dfe7130df607c86ad42fb33.apk, 29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896.apk, 2a5f808f305334a0cfec1daa7290ace649079ab9c6dbed43f77ffdccb55c6e31.apk, 2b6d20746ed11f62b35a7c29d1912de18248e9e10247c29a6ee0929877a57d77.apk, 2b7af4d5fd24ce4daaa2aada2db239d0ec17510d17a55beb214b70b8edc54fb6.apk, 2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0.apk, 2d25cb4e862cc6cac19999798f044211ed99239dd15779be6271b680c028782a.apk, 2e11badbd558a37c88ee22a7315c8220b90213fb712ea1ec1f39b14e3ae8475c.apk, 2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b.apk, 3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089.apk, 33d2ea973f861bb7c46397c4e0f9aedc37ef10fb8ab2f4090f35a335d86ef0b2.apk, 34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45.apk, 3638754e7fd889e9ced9127e7abe08191b7e8df3d60ed284c7b507e1e8082613.apk, 372607bbdf97e253a8970876a4bb1c9419859a9b0bd9d421750f17c28995017e.apk, 37aea8c8ed8ea55d23da37d997e82e6cc34bf80bce891378be7543adf6678ea1.apk, 392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d.apk, 399c4819af422e581639c9350dcba71b0ee00b87a4d37da11806db5e25a0adc5.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 3ab3cc3c0df02d723c850e712fa5f4a0de29f2addf2c50beffe222112c2baa38.apk, 3aea0345c88f069d3a079c82571086adafb585137a86e277f4e5c9fb1b2190e6.apk, 3c0a6f866aa4d74d0b39a2b9d11692ffa7291fd46b414e73cd5f9c7f9f030b75.apk, 3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647.apk, 3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5dce6.apk, 3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd.apk, 3dc24332f897ef758c38e4959624606236a3c63a1ba2e0b3d268ed6ce40b5c1a.apk, 3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec.apk, 3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c.apk, 41930e6f9187c8be4ea41303dd957d74f65b97944321a24a20028e76d10e0588.apk, 41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2.apk, 41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 46326534553b3c5307d4c0347c12919b93b2699f9670593885cf52182a28180f.apk, 4845bbe3b1f17da3783db71b6a471b9dc073c8459fe2981004fbbcd70144ec01.apk, 48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce.apk, 4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951.apk, 498b9dc568e47cd06099fbedb479e78556a7cd30a8cad589b003a77e09de2c52.apk, 49b40786a01886ad8e962bd74e5d2e3ede8472de5cabe7b060284c54e5941182.apk, 4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f.apk, 4a899a3b0fd61937ce8555cb0da53daf72dadc7dd299c63e90b4a203e5a14db1.apk, 4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290.apk, 4af08f08377457cb04e280615fc8647870f9b20ad763e1bd060731605d8a0c07.apk, 4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088.apk, 4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7.apk, 4f0508904ec488ea7767e9d124b78097aefa8f43cc1713e81a7c4f45e1ba77f0.apk, 4f621122c29871e1d0464421c2abfc01036f27f1d3523b8b4d143f82a2c08c5a.apk, 4ff07276c35f5e9c6f8ec37deaa0bc4f01f033a4e717ef8ce76ef371e8eee29b.apk, 51863351193ab67148e3e47255cad4927eb13939292c7854121ebedb4de28590.apk, 5294f5ff8d2190157b8a2c0863ee395764ad520ae397929f60756a6c810fb9ff.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 54c478b499829a41f57edf93753b9842ab67dc13cff2cc1326ad7ced2f3dc0b9.apk, 557c02b5e9ca8103e6ad5413df1b447fae5c9ce086a0b5330bf9c79a578585df.apk, 563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b.apk, 569ef3c50d8c1bb48729c04fc334f26f644ff799c7ba3a514610e85f53cca3d5.apk, 57940c5eee8641e02f49d1122528665a0ddfbf5b6b0d4b910b5287e15542591d.apk, 58cc948bd809292143e604c3e03735c9517f94b37dd35299ca5e81d7b902d620.apk, 59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f.apk, 5a6eda5a51b8330bea4f79652927cefbb2aed857d60f71ea3b14e63db06dc1ad.apk, 5a8d4eabd009a75ecc04f3f06489d393f082f963b406d0d3e8acbea568281c5f.apk, 5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8.apk, 5d4972e846d795b495d70fa054821c53678d2335b6879b4bf9a9116e101a8826.apk, 5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 638fc69f1d2945d4a575154d019e503ef6e00a67317666fea3655262b474643a.apk, 63a19cd37e5f23ba982d004e587472bdc30d64af04e1b321419d8173a16c60cc.apk, 64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3.apk, 6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3.apk, 65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf.apk, 662bb00e9a82d43be45413fce12def326a1863f9cd3e63aa45b60d36ef7e0443.apk, 678ee44afb89903d3199378f2e6d9de0b4167c23e548bf4d7f863e1545ef912e.apk, 6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e.apk, 6a702c55f4ee54eeb35a991d7413328da1e56dde6e719babec23682423bec23f.apk, 6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22.apk, 6a94280f9c63fc30646439857e184a124722950dcd59a0ad8db8616f0d66fcdd.apk, 6ace30c2832b85ef093f86c13b9920a528dc86c3d561148a7a641f2d2b80db00.apk, 6b0c56540499051ab350a31f417b99859da7ed7286b9e77503711c6aabafbe03.apk, 6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8.apk, 6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa8255405.apk, 6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd.apk, 6db892bb9921633415b73799421a00cea90d089960dcf2734f8722fb1bbfe210.apk, 6e87157051e31528627d600f310e0b7252f85fcaf9607b34e5a4156b2d14cdec.apk, 6eb525100f54b9a830cd2d0f1169b053edb55332b2be73dd29a8b165b9ccdbf5.apk, 6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738.apk, 6f58b07b5ddabc29c9c7e7165349edbd2bee923446514044d67040de2f36664a.apk, 702df60cc69ab4727157116c6ee9539d2b68235b3650296e7c95ff7ad2146126.apk, 73688f47ba909b3a0eb57f36ce857ba82f7eeb6e8e1b1378a6d5d328086f9c8f.apk, 73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4.apk, 73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a.apk, 752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e40ab.apk, 7593b0f4bc4c52cb359196f35868636b319641b01c8db9f662076285739a0505.apk, 75b4d9eb26ed9e20009c9a55a58e66457d7ec4d7d060179f09f6522e96c62e2e.apk, 7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570.apk, 774af64259ad726296fb4fc56ca91897c7da9acb3a10ad49325ead714f6562c4.apk, 7775d8411c836f15e525320a984c90941127e7101ded1af8bb5b1234d50ebaf5.apk, 78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b.apk, 7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144.apk, 79c3de875a609b3109f51b8d0bde1a25da7013c5a78333b415551fd6c1eb24a6.apk, 79f56edc1bb111c0323762dc0c25d9c50c9a62ec4dedc2cf2e0c2010e518b6b4.apk, 79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826fdd3.apk, 7a449a292f2498734e22aa7f43857fda0d34f81910ffb8a85cd679eb9c3694de.apk, 7ad0ae4494675c5412b1abc00a527d8b568debc01b148d2d16e7a55367e28eb8.apk, 7b167d362a9282adb176095be2e5bd4692b4158b7bdf4c6c20870daed5b04665.apk, 7c25f1090921bb3692900dc333a466fad7feb25631cb2fd2fc7f85ab1eaf729f.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, 7e8693dfed67a88db885ac0ffd94b73351d1f910cafc6425e8f1b4ab0e24c2a8.apk, 7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf26527b7.apk, 810926f89430144fd258ed4a95f1d77215f657a4e7dac2ce0c410bcffbdca99e.apk, 814cd115a30c5b4bfbb276524774a3ad2396e7f346c9f083983131b3e08200d2.apk, 828a8180829f047507ad1052f14633cd9d4908037cf49c1d8b3c9799acce170d.apk, 8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552.apk, 83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025.apk, 84c5571ee75850514c0b09aa0f77b9ab5ea0b79bc8622371e3223810e67cd406.apk, 8613f7b6df514d53aa419355b0a3e8d032b8448bd45296d4158b848998015e3d.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8adce5e888db7e35a5731de025715c95961b459481edd19a2e7fb040c1218063.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 904e4153d2026380dc42297173192e72de7e5d9ea50f16bf8df2e2fa6922cdc3.apk, 90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a.apk, 94b6a8c5a5a9569b073f56ccaf56bded9dd3f00ce619369142ce16a492f9ac9e.apk, 95e88ec3ceb56c7f3679c45b837f931d0b38269a2e275628f2bc1a9f5c77a19f.apk, 9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e0ece.apk, 97936d7873348f905d119dd9399261374aae494296e1b5fb3df521ef3cc76405.apk, 9904bb103fae65ab3dd712f6b9ff361d3f3cb3a4cc814b69f0af3e2f1a837ecd.apk, 99b3c2ceeeb0c5866baddd1eb0e53556514708a74b58324f4a742207ef781680.apk, 9aafbc143c66661609f34c483a85015f30f7da2a38f375d9e10c8eeadc6cb5da.apk, 9ae895cd6474d1928bbbd68e240679c9de3c0ca327ac4e4b83845878b72322be.apk, 9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5.apk, 9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d.apk, 9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d.apk, 9c1cc79b801e8d632bdb73517588e9e7626cf22643263f038c20cc42dfd0f922.apk, 9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3bb5d1.apk, 9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c.apk, 9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90.apk, 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk, 9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b3306.apk, 9eb79fff3b28dec8d404a6713b8e6a60535805c6e7d84c7e8ac9bdff5d1592cf.apk, 9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6.apk, a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5.apk, a0edfa97344c870ee24aa7c008cec40e85e616c21e86522b8f6fce0324b356f7.apk, a140917183b3a1e51dca80b5a0f87dc5dc6eba21bc4d53d328f9ba24312d6075.apk, a2a539109b77cfa720f6e1315fa09c82cfb8eb9980b304ba54de6a8279993dd4.apk, a2c509d0b0fcee3bc503bd12986da2d29c74ebcd37abb1af8988f7f26382663d.apk, a2f827bcb3acc7ccfc45f202a0e8adae2cd6439ae46d0d4d401a418846761a2e.apk, a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a6ed100ae42e4fdabfd1b4c992762152bc4a11cc8e521b647b444c75bb7a9782.apk, a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa.apk, a97c8523696f6ef8f30cc6cf4b60a7a46fcb8716176741e09dfa81d5eacd8334.apk, aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8.apk, aa3b976475e375e92f09bf4b06db50693ad42dd7c0abfcbfd598f3e9d46f0744.apk, ab1363201d0897ab7c55dceb1f8664a58ac65fe4aee3c9600c5d7659f8ae58a9.apk, acf2d29c8c65ee2fe57445e672fbee01fa240b0039b66ea507f110468c6c8210.apk, ad02db22949f80c2981ae59813672c44d339eb94dfdd4e01ff329470cdd9230e.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de.apk, afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4.apk, b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk, b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e.apk, b1a8941063751656e11bbc6ab44d348cd6795d51bfc890424595c4ac76e52013.apk, b1c3a8818024ee86480bb83ea405ba2d9f96ea279e5cf9df19b3d3cb934ec42d.apk, b38d466dbb28feb20f4f8cc9d9a3b2204bf38e487e7cc5f057a756dd5f40b7c6.apk, b3c86606b1410cc558acef06d55c2a03d41ad85cb2b04e904640f58b23185db3.apk, b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, b4b2197c5a8f0e9b9766fa39e9b538568284ec8a0099811b8b54fe6a1402545b.apk, b600af54745d2cf6529d048e701b579368af19ff69a08b5ae26d1f0d0a706047.apk, b8f7304f293daad9beb862a068f837a4426792656a3a2695b614dbe9ac920b3e.apk, b8fa21bbd5261f2308a168c1f43b197220c0d37bdda0c4a1464be085a9f85300.apk, b9047ded41187be3c15d0d183e4fdd3d38c8f2fe16dcc495a68d12e5c7ff0f8c.apk, b9fb2177e55ad47b2df74ff642bd3ee5058d392c3e2e272b93bec263aa30eeef.apk, ba4523e699d017cff49e9f725b6a5c279654dd8d91a55e68a4786f5d46ea771e.apk, ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33.apk, bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6.apk, bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de.apk, be8adc196213154b10bd4209098ff94083d5ade71abeeacbf9d4cf30e3403234.apk, c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14.apk, c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9.apk, c3c107ff3419beb378d3e26727aad8089c42bc688b3c79fa981260e93b66ca73.apk, c54861f54bcf72de5f16611ef0eec32c5c5f937bf3fdb5d6e611b2a2f9acdf2a.apk, c5544517f1be9d5a721a951d906b26f9ad11adf4a06c3660a75e89f07dabb8aa.apk, c5ab0adaedf391a395387df33b0bf6854f1ccc9c5da937915ea86b5eec6e6103.apk, c5dc6d8f325c125fba0a9ceea0cac957642fbf0a38bd4da867a82f6f06962d45.apk, c659454dd6ed62bc7a0c9e0455297e41ba57b0b7935a826150c1f8c0db6f89d2.apk, c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d.apk, c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk, ca5b40e938f68321dfa3a7f1ad2a03db4ff6ba27fdae5e230654cd5c30090692.apk, ca6271b212c627dd6e4372827a0fb316023fa35210cab7249d634379af6d649c.apk, cb147e7ce69723523f604da875d78ca4738e5f416d2297910ee179a5067e79fe.apk, cc93d01b68b59314a789c5355ac70b8e6965b9f64bb331b0337aac9d2da8aede.apk, cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c.apk, ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9.apk, ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642.apk, cec6fc6496687b177b14d6699d82a18840b528bff5543dfb6e23c0849f3c8de2.apk, cf3ac7265631cf1cb96f617addee7b4100f4e582e215a7e4a190c9730c49044f.apk, d0d4ef735a8bf076d81a6f3651d6bcfd8c69285049add2e6b6bee1276a99c37c.apk, d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af.apk, d19edfbc70474a76b2dd6d8d0e844404f7b4c364c2278a6a668159e83310598a.apk, d1be4715dd7aae97adab8125389b08e75f83ceb8078100a5fe43806ee7da0a99.apk, d1fec0ce2be2097357d307e835783380ac010c7d55f3e72fa3906f0d0edd7a6a.apk, d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3.apk, d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd.apk, d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2.apk, d3fc5ffdd9a68a3063b1c8ff15334238dd39a63b9c93ec9f337bdd5f5357046a.apk, d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372.apk, d5a84c85508c444743d055be354a464eb22dc5b33cba41e4b149829d182f4dca.apk, d69108a94a9a81e07a05d456dc997cbf5b5a8cc8f0869eae7904fac1da60f335.apk, d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5.apk, d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe.apk, d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d.apk, d9b75d606803968d04015bed042da887905e9c1cb1b40b4ff11852b88c8b4d21.apk, d9c47a7d7e42402c3ce2dd191ea09e9f7e29b1ee8d78d9aec0a47ed7b4bcdb80.apk, d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38.apk, dc111dbe181ecf60242886d28c8360d630913919feee4d37d0bc7b675c2f6566.apk, dd0919967c57cdabdf8b5bc9c643bb0d250fe935476aa4944544b22132d5163d.apk, ddeb13abf09d096f821ee657c3479f799f2a236b49f46c80a0afb2676a8f55ab.apk, deb2cc80a190e73d81758b738bac4e8f0f116b587b07d65ddc8b668f0b89b0bb.apk, decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8.apk, dfa3539353b89089a3599f4775a296b270751738186af515bf3e630dc054bc7d.apk, e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3.apk, e163a088d174d4eb41479b53e6df04831dc40899b893a0b183d080d2dfe52cd7.apk, e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938.apk, e21f8722ab3d3557e7b0dda0faca39c517bbf0afd84bf4bbdc92687c9bd58aae.apk, e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75.apk, e3d0cbffe67561de432b5b0e912328ed7c32c5fcfb3a5002515e34b517d7296b.apk, e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b.apk, e4aa98c1beee901871fd8a78b37b21ef886e507e65fc6499e3df3769081cd1cb.apk, e4acebbaf1008ad281cd36a9b49d7b549db310267df7ddd69e4aa82b967eb4ca.apk, e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8.apk, e756a707443f382f4f93ca4b6101de16e4cac521d9032171c7b68b3a9585c39e.apk, e7aa84c2b3ac31d3a948f0431cdbf7b28116fffb157b8e99e8efe455c92dd661.apk, e7bc41c6d3677ef941dfc8eb4b571435623dab1e8c0681b6253c37725844b268.apk, e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf.apk, e9b41fd64d8702f974e63374a03ad914b6f1b24e8ddd96c29ff14ce81713676f.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, ee9eceda9522ae4c5ff3e07aefa523c61d50ebb9aca2808e0f4494a8c53498ea.apk, ef16cc8137d29356d0ef23b61ddb9cfd5e2784578fa818d54fe670bfa1e6ef73.apk, ef94a5ecaf100b9c9102b101b98f8c01fae9ea9304e5b8fbf6097beec59ad885.apk, f04d5131819615b067b336daf118f9b4bba9d48acea4b61c0b88e6e4416258bf.apk, f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk, f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2.apk, f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738.apk, f3fe34702fefe9dfb8bf50f2d2ca475a8a3150f3dee3c07b09994947d540b3a1.apk, f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65.apk, faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee.apk, faab917444988b9a2e8d5d5bc06a0423c53718f92cbb8840cc6632f464c89130.apk, faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a.apk, fb967e4daa07ff3777fd4495133bef6544676a315409990f68057506d706c1e4.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk, fca04c73ad8c4626e4026faaac63fbe6c2a6404952e1c53d657b696480789553.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "0172d6141fc03c2e152caf35dce6c90cc0cec4f303de270f09136b93f1e99bcf"
      hash2 = "017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44"
      hash3 = "01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0"
      hash4 = "02944967154e515f87bb411641edd9931ea6b4a4088ab73efe87cbe7b9d5b592"
      hash5 = "0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e"
      hash6 = "05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a"
      hash7 = "0619168a8df6dd350052ca3a578abe15da0f2177e65acea55f44b5b59ed5f1c8"
      hash8 = "08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c"
      hash9 = "090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90ba268"
      hash10 = "091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d96241620a5"
      hash11 = "09eb87493c014406a0d83996a8b1894da5257fd6166921878a9bbd42b1e9390e"
      hash12 = "0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169"
      hash13 = "0badd9b4b0e44daeaa75b5d97ed9611a9f84418c1fb5683130e8b22742086549"
      hash14 = "0bd64f2bfd3b3d5427adfeb8bb72d2522d9758c80995bcf09a60c8631e0f1d34"
      hash15 = "0c8085cea946d655b266998fd60b1da33df73a4285328da3dabc7f0e7211411d"
      hash16 = "0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c3"
      hash17 = "0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd"
      hash18 = "0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072"
      hash19 = "108ca43c5a62640b5e3d71df33c00549c46634c1109c1ac6690df89fbc4211fd"
      hash20 = "118f0bba26f3fd4f1c535ba9117ec80eda9945e6a7fe8af7511178ac60a77170"
      hash21 = "11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415"
      hash22 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash23 = "129ee4f3dd5ecd07a3f815616300a2adcd6702239c1ae3e31a3d61cf7913c4cb"
      hash24 = "134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138"
      hash25 = "1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea"
      hash26 = "13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52"
      hash27 = "1495da4ff455fceb8fc73f38b75d65be3435c649b2aaf014124e9c58da930c37"
      hash28 = "14c47030d8220e682a1ec80c87d56c5bacf7a38abdf30df9bb532a85851259af"
      hash29 = "14ebed0d51768cfa90ace0d74ce17763a7accd1c526976e5b4609156521e7ca8"
      hash30 = "15839ac050341de16481e5e425f5f1a791547651d4aeda398217f823f0f321f9"
      hash31 = "1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90"
      hash32 = "17fc5d1c8bd8b10471131282e42ec289bb1e1ee107ca676f369bb42fc3643af3"
      hash33 = "19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c20271e62"
      hash34 = "1aeae34c264bbfbd4eed6d92a94ac788bfb9b050a54032fde811402d63f18bf8"
      hash35 = "1bf9c16cb7c1faae7fa99a57c5d091cbd1e6d5f3c0d79693a3b0990a8b58367d"
      hash36 = "1c64737419a6cb1729ae42f232461a723a8b8b1e67fbcba32cacd151fcbaba7d"
      hash37 = "1d15f0700a2dda228394bf37ad20ad2bd88c7813d6aca0199a6b40c704f80bc1"
      hash38 = "1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c"
      hash39 = "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
      hash40 = "1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9"
      hash41 = "204edbbd9ab906160ea75c77681a47a21f018f18eca0927a901df6fe24fbd532"
      hash42 = "2117f4f448674fb5fafa5dd581777d35255253a4b82c9d0be2aac917efec8ae8"
      hash43 = "21b6b9c7262fe39d2f2ce49115c9c22f50d3e5b0b083a0f8c1ddd776c369ffd3"
      hash44 = "21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e494fe"
      hash45 = "22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b"
      hash46 = "2308afb58c08eec15d0ad9048e751eeca001bd17a2106484803c45ef351af752"
      hash47 = "23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61"
      hash48 = "269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471eed36"
      hash49 = "272248f64722ef49413a6f3c339aecb78785546c1c65b9c2897e3915bd91be28"
      hash50 = "27b8eeb5d1b46e1afa170b998830fe0958f08a2a9dfe7130df607c86ad42fb33"
      hash51 = "29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896"
      hash52 = "2a5f808f305334a0cfec1daa7290ace649079ab9c6dbed43f77ffdccb55c6e31"
      hash53 = "2b6d20746ed11f62b35a7c29d1912de18248e9e10247c29a6ee0929877a57d77"
      hash54 = "2b7af4d5fd24ce4daaa2aada2db239d0ec17510d17a55beb214b70b8edc54fb6"
      hash55 = "2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0"
      hash56 = "2d25cb4e862cc6cac19999798f044211ed99239dd15779be6271b680c028782a"
      hash57 = "2e11badbd558a37c88ee22a7315c8220b90213fb712ea1ec1f39b14e3ae8475c"
      hash58 = "2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1"
      hash59 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash60 = "31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b"
      hash61 = "3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089"
      hash62 = "33d2ea973f861bb7c46397c4e0f9aedc37ef10fb8ab2f4090f35a335d86ef0b2"
      hash63 = "34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45"
      hash64 = "3638754e7fd889e9ced9127e7abe08191b7e8df3d60ed284c7b507e1e8082613"
      hash65 = "372607bbdf97e253a8970876a4bb1c9419859a9b0bd9d421750f17c28995017e"
      hash66 = "37aea8c8ed8ea55d23da37d997e82e6cc34bf80bce891378be7543adf6678ea1"
      hash67 = "392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d"
      hash68 = "399c4819af422e581639c9350dcba71b0ee00b87a4d37da11806db5e25a0adc5"
      hash69 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash70 = "3ab3cc3c0df02d723c850e712fa5f4a0de29f2addf2c50beffe222112c2baa38"
      hash71 = "3aea0345c88f069d3a079c82571086adafb585137a86e277f4e5c9fb1b2190e6"
      hash72 = "3c0a6f866aa4d74d0b39a2b9d11692ffa7291fd46b414e73cd5f9c7f9f030b75"
      hash73 = "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
      hash74 = "3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5dce6"
      hash75 = "3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd"
      hash76 = "3dc24332f897ef758c38e4959624606236a3c63a1ba2e0b3d268ed6ce40b5c1a"
      hash77 = "3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec"
      hash78 = "3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c"
      hash79 = "41930e6f9187c8be4ea41303dd957d74f65b97944321a24a20028e76d10e0588"
      hash80 = "41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2"
      hash81 = "41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7"
      hash82 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash83 = "46326534553b3c5307d4c0347c12919b93b2699f9670593885cf52182a28180f"
      hash84 = "4845bbe3b1f17da3783db71b6a471b9dc073c8459fe2981004fbbcd70144ec01"
      hash85 = "48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce"
      hash86 = "4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951"
      hash87 = "498b9dc568e47cd06099fbedb479e78556a7cd30a8cad589b003a77e09de2c52"
      hash88 = "49b40786a01886ad8e962bd74e5d2e3ede8472de5cabe7b060284c54e5941182"
      hash89 = "4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f"
      hash90 = "4a899a3b0fd61937ce8555cb0da53daf72dadc7dd299c63e90b4a203e5a14db1"
      hash91 = "4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290"
      hash92 = "4af08f08377457cb04e280615fc8647870f9b20ad763e1bd060731605d8a0c07"
      hash93 = "4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088"
      hash94 = "4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7"
      hash95 = "4f0508904ec488ea7767e9d124b78097aefa8f43cc1713e81a7c4f45e1ba77f0"
      hash96 = "4f621122c29871e1d0464421c2abfc01036f27f1d3523b8b4d143f82a2c08c5a"
      hash97 = "4ff07276c35f5e9c6f8ec37deaa0bc4f01f033a4e717ef8ce76ef371e8eee29b"
      hash98 = "51863351193ab67148e3e47255cad4927eb13939292c7854121ebedb4de28590"
      hash99 = "5294f5ff8d2190157b8a2c0863ee395764ad520ae397929f60756a6c810fb9ff"
      hash100 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash101 = "54c478b499829a41f57edf93753b9842ab67dc13cff2cc1326ad7ced2f3dc0b9"
      hash102 = "557c02b5e9ca8103e6ad5413df1b447fae5c9ce086a0b5330bf9c79a578585df"
      hash103 = "563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b"
      hash104 = "569ef3c50d8c1bb48729c04fc334f26f644ff799c7ba3a514610e85f53cca3d5"
      hash105 = "57940c5eee8641e02f49d1122528665a0ddfbf5b6b0d4b910b5287e15542591d"
      hash106 = "58cc948bd809292143e604c3e03735c9517f94b37dd35299ca5e81d7b902d620"
      hash107 = "59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f"
      hash108 = "5a6eda5a51b8330bea4f79652927cefbb2aed857d60f71ea3b14e63db06dc1ad"
      hash109 = "5a8d4eabd009a75ecc04f3f06489d393f082f963b406d0d3e8acbea568281c5f"
      hash110 = "5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8"
      hash111 = "5d4972e846d795b495d70fa054821c53678d2335b6879b4bf9a9116e101a8826"
      hash112 = "5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a"
      hash113 = "5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8"
      hash114 = "638fc69f1d2945d4a575154d019e503ef6e00a67317666fea3655262b474643a"
      hash115 = "63a19cd37e5f23ba982d004e587472bdc30d64af04e1b321419d8173a16c60cc"
      hash116 = "64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3"
      hash117 = "6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3"
      hash118 = "65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf"
      hash119 = "662bb00e9a82d43be45413fce12def326a1863f9cd3e63aa45b60d36ef7e0443"
      hash120 = "678ee44afb89903d3199378f2e6d9de0b4167c23e548bf4d7f863e1545ef912e"
      hash121 = "6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e"
      hash122 = "6a702c55f4ee54eeb35a991d7413328da1e56dde6e719babec23682423bec23f"
      hash123 = "6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22"
      hash124 = "6a94280f9c63fc30646439857e184a124722950dcd59a0ad8db8616f0d66fcdd"
      hash125 = "6ace30c2832b85ef093f86c13b9920a528dc86c3d561148a7a641f2d2b80db00"
      hash126 = "6b0c56540499051ab350a31f417b99859da7ed7286b9e77503711c6aabafbe03"
      hash127 = "6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8"
      hash128 = "6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa8255405"
      hash129 = "6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd"
      hash130 = "6db892bb9921633415b73799421a00cea90d089960dcf2734f8722fb1bbfe210"
      hash131 = "6e87157051e31528627d600f310e0b7252f85fcaf9607b34e5a4156b2d14cdec"
      hash132 = "6eb525100f54b9a830cd2d0f1169b053edb55332b2be73dd29a8b165b9ccdbf5"
      hash133 = "6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738"
      hash134 = "6f58b07b5ddabc29c9c7e7165349edbd2bee923446514044d67040de2f36664a"
      hash135 = "702df60cc69ab4727157116c6ee9539d2b68235b3650296e7c95ff7ad2146126"
      hash136 = "73688f47ba909b3a0eb57f36ce857ba82f7eeb6e8e1b1378a6d5d328086f9c8f"
      hash137 = "73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4"
      hash138 = "73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a"
      hash139 = "752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e40ab"
      hash140 = "7593b0f4bc4c52cb359196f35868636b319641b01c8db9f662076285739a0505"
      hash141 = "75b4d9eb26ed9e20009c9a55a58e66457d7ec4d7d060179f09f6522e96c62e2e"
      hash142 = "7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570"
      hash143 = "774af64259ad726296fb4fc56ca91897c7da9acb3a10ad49325ead714f6562c4"
      hash144 = "7775d8411c836f15e525320a984c90941127e7101ded1af8bb5b1234d50ebaf5"
      hash145 = "78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b"
      hash146 = "7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144"
      hash147 = "79c3de875a609b3109f51b8d0bde1a25da7013c5a78333b415551fd6c1eb24a6"
      hash148 = "79f56edc1bb111c0323762dc0c25d9c50c9a62ec4dedc2cf2e0c2010e518b6b4"
      hash149 = "79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826fdd3"
      hash150 = "7a449a292f2498734e22aa7f43857fda0d34f81910ffb8a85cd679eb9c3694de"
      hash151 = "7ad0ae4494675c5412b1abc00a527d8b568debc01b148d2d16e7a55367e28eb8"
      hash152 = "7b167d362a9282adb176095be2e5bd4692b4158b7bdf4c6c20870daed5b04665"
      hash153 = "7c25f1090921bb3692900dc333a466fad7feb25631cb2fd2fc7f85ab1eaf729f"
      hash154 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
      hash155 = "7e8693dfed67a88db885ac0ffd94b73351d1f910cafc6425e8f1b4ab0e24c2a8"
      hash156 = "7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf26527b7"
      hash157 = "810926f89430144fd258ed4a95f1d77215f657a4e7dac2ce0c410bcffbdca99e"
      hash158 = "814cd115a30c5b4bfbb276524774a3ad2396e7f346c9f083983131b3e08200d2"
      hash159 = "828a8180829f047507ad1052f14633cd9d4908037cf49c1d8b3c9799acce170d"
      hash160 = "8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552"
      hash161 = "83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025"
      hash162 = "84c5571ee75850514c0b09aa0f77b9ab5ea0b79bc8622371e3223810e67cd406"
      hash163 = "8613f7b6df514d53aa419355b0a3e8d032b8448bd45296d4158b848998015e3d"
      hash164 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash165 = "8adce5e888db7e35a5731de025715c95961b459481edd19a2e7fb040c1218063"
      hash166 = "8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af"
      hash167 = "904e4153d2026380dc42297173192e72de7e5d9ea50f16bf8df2e2fa6922cdc3"
      hash168 = "90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a"
      hash169 = "94b6a8c5a5a9569b073f56ccaf56bded9dd3f00ce619369142ce16a492f9ac9e"
      hash170 = "95e88ec3ceb56c7f3679c45b837f931d0b38269a2e275628f2bc1a9f5c77a19f"
      hash171 = "9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e0ece"
      hash172 = "97936d7873348f905d119dd9399261374aae494296e1b5fb3df521ef3cc76405"
      hash173 = "9904bb103fae65ab3dd712f6b9ff361d3f3cb3a4cc814b69f0af3e2f1a837ecd"
      hash174 = "99b3c2ceeeb0c5866baddd1eb0e53556514708a74b58324f4a742207ef781680"
      hash175 = "9aafbc143c66661609f34c483a85015f30f7da2a38f375d9e10c8eeadc6cb5da"
      hash176 = "9ae895cd6474d1928bbbd68e240679c9de3c0ca327ac4e4b83845878b72322be"
      hash177 = "9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5"
      hash178 = "9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d"
      hash179 = "9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d"
      hash180 = "9c1cc79b801e8d632bdb73517588e9e7626cf22643263f038c20cc42dfd0f922"
      hash181 = "9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3bb5d1"
      hash182 = "9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c"
      hash183 = "9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90"
      hash184 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
      hash185 = "9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b3306"
      hash186 = "9eb79fff3b28dec8d404a6713b8e6a60535805c6e7d84c7e8ac9bdff5d1592cf"
      hash187 = "9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6"
      hash188 = "a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5"
      hash189 = "a0edfa97344c870ee24aa7c008cec40e85e616c21e86522b8f6fce0324b356f7"
      hash190 = "a140917183b3a1e51dca80b5a0f87dc5dc6eba21bc4d53d328f9ba24312d6075"
      hash191 = "a2a539109b77cfa720f6e1315fa09c82cfb8eb9980b304ba54de6a8279993dd4"
      hash192 = "a2c509d0b0fcee3bc503bd12986da2d29c74ebcd37abb1af8988f7f26382663d"
      hash193 = "a2f827bcb3acc7ccfc45f202a0e8adae2cd6439ae46d0d4d401a418846761a2e"
      hash194 = "a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2"
      hash195 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash196 = "a6ed100ae42e4fdabfd1b4c992762152bc4a11cc8e521b647b444c75bb7a9782"
      hash197 = "a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa"
      hash198 = "a97c8523696f6ef8f30cc6cf4b60a7a46fcb8716176741e09dfa81d5eacd8334"
      hash199 = "aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8"
      hash200 = "aa3b976475e375e92f09bf4b06db50693ad42dd7c0abfcbfd598f3e9d46f0744"
      hash201 = "ab1363201d0897ab7c55dceb1f8664a58ac65fe4aee3c9600c5d7659f8ae58a9"
      hash202 = "acf2d29c8c65ee2fe57445e672fbee01fa240b0039b66ea507f110468c6c8210"
      hash203 = "ad02db22949f80c2981ae59813672c44d339eb94dfdd4e01ff329470cdd9230e"
      hash204 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash205 = "ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de"
      hash206 = "afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4"
      hash207 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
      hash208 = "b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e"
      hash209 = "b1a8941063751656e11bbc6ab44d348cd6795d51bfc890424595c4ac76e52013"
      hash210 = "b1c3a8818024ee86480bb83ea405ba2d9f96ea279e5cf9df19b3d3cb934ec42d"
      hash211 = "b38d466dbb28feb20f4f8cc9d9a3b2204bf38e487e7cc5f057a756dd5f40b7c6"
      hash212 = "b3c86606b1410cc558acef06d55c2a03d41ad85cb2b04e904640f58b23185db3"
      hash213 = "b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99"
      hash214 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash215 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash216 = "b4b2197c5a8f0e9b9766fa39e9b538568284ec8a0099811b8b54fe6a1402545b"
      hash217 = "b600af54745d2cf6529d048e701b579368af19ff69a08b5ae26d1f0d0a706047"
      hash218 = "b8f7304f293daad9beb862a068f837a4426792656a3a2695b614dbe9ac920b3e"
      hash219 = "b8fa21bbd5261f2308a168c1f43b197220c0d37bdda0c4a1464be085a9f85300"
      hash220 = "b9047ded41187be3c15d0d183e4fdd3d38c8f2fe16dcc495a68d12e5c7ff0f8c"
      hash221 = "b9fb2177e55ad47b2df74ff642bd3ee5058d392c3e2e272b93bec263aa30eeef"
      hash222 = "ba4523e699d017cff49e9f725b6a5c279654dd8d91a55e68a4786f5d46ea771e"
      hash223 = "ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33"
      hash224 = "bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6"
      hash225 = "bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7"
      hash226 = "bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0"
      hash227 = "bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de"
      hash228 = "be8adc196213154b10bd4209098ff94083d5ade71abeeacbf9d4cf30e3403234"
      hash229 = "c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14"
      hash230 = "c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9"
      hash231 = "c3c107ff3419beb378d3e26727aad8089c42bc688b3c79fa981260e93b66ca73"
      hash232 = "c54861f54bcf72de5f16611ef0eec32c5c5f937bf3fdb5d6e611b2a2f9acdf2a"
      hash233 = "c5544517f1be9d5a721a951d906b26f9ad11adf4a06c3660a75e89f07dabb8aa"
      hash234 = "c5ab0adaedf391a395387df33b0bf6854f1ccc9c5da937915ea86b5eec6e6103"
      hash235 = "c5dc6d8f325c125fba0a9ceea0cac957642fbf0a38bd4da867a82f6f06962d45"
      hash236 = "c659454dd6ed62bc7a0c9e0455297e41ba57b0b7935a826150c1f8c0db6f89d2"
      hash237 = "c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d"
      hash238 = "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
      hash239 = "ca5b40e938f68321dfa3a7f1ad2a03db4ff6ba27fdae5e230654cd5c30090692"
      hash240 = "ca6271b212c627dd6e4372827a0fb316023fa35210cab7249d634379af6d649c"
      hash241 = "cb147e7ce69723523f604da875d78ca4738e5f416d2297910ee179a5067e79fe"
      hash242 = "cc93d01b68b59314a789c5355ac70b8e6965b9f64bb331b0337aac9d2da8aede"
      hash243 = "cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c"
      hash244 = "ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9"
      hash245 = "ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642"
      hash246 = "cec6fc6496687b177b14d6699d82a18840b528bff5543dfb6e23c0849f3c8de2"
      hash247 = "cf3ac7265631cf1cb96f617addee7b4100f4e582e215a7e4a190c9730c49044f"
      hash248 = "d0d4ef735a8bf076d81a6f3651d6bcfd8c69285049add2e6b6bee1276a99c37c"
      hash249 = "d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af"
      hash250 = "d19edfbc70474a76b2dd6d8d0e844404f7b4c364c2278a6a668159e83310598a"
      hash251 = "d1be4715dd7aae97adab8125389b08e75f83ceb8078100a5fe43806ee7da0a99"
      hash252 = "d1fec0ce2be2097357d307e835783380ac010c7d55f3e72fa3906f0d0edd7a6a"
      hash253 = "d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3"
      hash254 = "d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd"
      hash255 = "d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2"
      hash256 = "d3fc5ffdd9a68a3063b1c8ff15334238dd39a63b9c93ec9f337bdd5f5357046a"
      hash257 = "d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372"
      hash258 = "d5a84c85508c444743d055be354a464eb22dc5b33cba41e4b149829d182f4dca"
      hash259 = "d69108a94a9a81e07a05d456dc997cbf5b5a8cc8f0869eae7904fac1da60f335"
      hash260 = "d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5"
      hash261 = "d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe"
      hash262 = "d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d"
      hash263 = "d9b75d606803968d04015bed042da887905e9c1cb1b40b4ff11852b88c8b4d21"
      hash264 = "d9c47a7d7e42402c3ce2dd191ea09e9f7e29b1ee8d78d9aec0a47ed7b4bcdb80"
      hash265 = "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
      hash266 = "dc111dbe181ecf60242886d28c8360d630913919feee4d37d0bc7b675c2f6566"
      hash267 = "dd0919967c57cdabdf8b5bc9c643bb0d250fe935476aa4944544b22132d5163d"
      hash268 = "ddeb13abf09d096f821ee657c3479f799f2a236b49f46c80a0afb2676a8f55ab"
      hash269 = "deb2cc80a190e73d81758b738bac4e8f0f116b587b07d65ddc8b668f0b89b0bb"
      hash270 = "decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8"
      hash271 = "dfa3539353b89089a3599f4775a296b270751738186af515bf3e630dc054bc7d"
      hash272 = "e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3"
      hash273 = "e163a088d174d4eb41479b53e6df04831dc40899b893a0b183d080d2dfe52cd7"
      hash274 = "e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938"
      hash275 = "e21f8722ab3d3557e7b0dda0faca39c517bbf0afd84bf4bbdc92687c9bd58aae"
      hash276 = "e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75"
      hash277 = "e3d0cbffe67561de432b5b0e912328ed7c32c5fcfb3a5002515e34b517d7296b"
      hash278 = "e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b"
      hash279 = "e4aa98c1beee901871fd8a78b37b21ef886e507e65fc6499e3df3769081cd1cb"
      hash280 = "e4acebbaf1008ad281cd36a9b49d7b549db310267df7ddd69e4aa82b967eb4ca"
      hash281 = "e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8"
      hash282 = "e756a707443f382f4f93ca4b6101de16e4cac521d9032171c7b68b3a9585c39e"
      hash283 = "e7aa84c2b3ac31d3a948f0431cdbf7b28116fffb157b8e99e8efe455c92dd661"
      hash284 = "e7bc41c6d3677ef941dfc8eb4b571435623dab1e8c0681b6253c37725844b268"
      hash285 = "e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf"
      hash286 = "e9b41fd64d8702f974e63374a03ad914b6f1b24e8ddd96c29ff14ce81713676f"
      hash287 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash288 = "ee9eceda9522ae4c5ff3e07aefa523c61d50ebb9aca2808e0f4494a8c53498ea"
      hash289 = "ef16cc8137d29356d0ef23b61ddb9cfd5e2784578fa818d54fe670bfa1e6ef73"
      hash290 = "ef94a5ecaf100b9c9102b101b98f8c01fae9ea9304e5b8fbf6097beec59ad885"
      hash291 = "f04d5131819615b067b336daf118f9b4bba9d48acea4b61c0b88e6e4416258bf"
      hash292 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
      hash293 = "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
      hash294 = "f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738"
      hash295 = "f3fe34702fefe9dfb8bf50f2d2ca475a8a3150f3dee3c07b09994947d540b3a1"
      hash296 = "f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65"
      hash297 = "faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee"
      hash298 = "faab917444988b9a2e8d5d5bc06a0423c53718f92cbb8840cc6632f464c89130"
      hash299 = "faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a"
      hash300 = "fb967e4daa07ff3777fd4495133bef6544676a315409990f68057506d706c1e4"
      hash301 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
      hash302 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
      hash303 = "fca04c73ad8c4626e4026faaac63fbe6c2a6404952e1c53d657b696480789553"
   strings:
      $s1 = "Effacer la requ" fullword ascii
      $s2 = "Invia query" fullword ascii
      $s3 = "Revenir en haut de la page" fullword ascii
      $s4 = "Navegar para cima" fullword ascii
      $s5 = "Cancella query" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb4_120 {
   meta:
      description = "apk - from files 017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44.apk, 01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0.apk, 0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e.apk, 04e4acc8cd2a66f77260ebcfbe40646192ff452d5f9bbe54e0acbd0cabc3cfbc.apk, 0596a76e6772acb911c1a556ad86943224873411fba4383abade25300078ed32.apk, 08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c.apk, 0f9fe82c6594fe331e59cf0268bc402f9e31141a3fd5e5dd99596d28563c5e9b.apk, 1099eede57e825fa5158b33f01559dc76e6d67e2fca37b97f76e7d3aa9a4208a.apk, 11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 12cb6136d2d325563b5079c138eeac2bc4ee4af3373718ba1c79c47a6121829e.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea.apk, 1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90.apk, 174deed18377e5280413a2015ebe2041fd8b4276a6599754299cf05cea0718d5.apk, 17a68e32e5d8398c93790abe9b117c472557b54ccdcfccfdddb3b7f783ca31b3.apk, 185a01ec24938cd5a9af4fd66a0814e8bfaf2e1ff8cfa2396a30c3e4f6e66b98.apk, 1b5ff50963c6e99dfb521e6db624df9f83f21f06430ce9d8f3cd0de735cbe22a.apk, 1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c.apk, 1d9bdb35234b01d219fd28c47a47bbaa6c9033e2b1f35b07f10cf09eaed00254.apk, 1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0.apk, 238eeea51b2d53ff08b3129fe6d6be75a13c12090e4063a1455fad614054d4b3.apk, 23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61.apk, 246bdb0a9e7698e37ec7b906551ceed302d0445c9572bb3cdc02a68862fd2d2a.apk, 25fdf72cb393901eb605d6eaea86fe67483a25295651e2423b9e50d5bfc62111.apk, 29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896.apk, 2b7e044edadb6932c251f2169da0a777bf553a549a263c5c8a0cf9d888cee704.apk, 2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0.apk, 2d0fd4ea41c4e17cf94577c126ae271555b544f388baca69112cd3a488572be1.apk, 2f451d9cfda5d91b2063a62ed5ad482cd733e899b9ee39ee8bd332b518b3b865.apk, 2f595b306756f39b0d525b19d5f5c1d50a5e6761ea049a63a390ec3e6709a2ba.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b.apk, 3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089.apk, 33c3f43852f6ecadef74aef2dbb0d5a1215aa3cb23e4aaf76f202beed3aa8703.apk, 34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45.apk, 3616fd6004678159e531fb7e5a173b333c08bd0097aa1f6a4e9f503db4a9999a.apk, 392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d.apk, 39c97fad655efc5aa4bc3703695b80e9807b14050fe9c8785cd047d3f3051668.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647.apk, 3d8da22674ee343bd02296a4351e90198ffc786f8541747e42cdcf3438f16b3e.apk, 3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec.apk, 3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c.apk, 41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2.apk, 41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7.apk, 43996d454961143bad870d9b94a3d00912f7c29b76371244ac59423595ae0860.apk, 446800befecf9179f9aca09dd88331dee0e745b199db39a9b0113f4ee886ca34.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 469b13cac1eb859da7ba4b597270f047b11815bfff9c4ad3faa5617c07a6c3e0.apk, 48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce.apk, 4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f.apk, 4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290.apk, 4af08f08377457cb04e280615fc8647870f9b20ad763e1bd060731605d8a0c07.apk, 4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088.apk, 4bdf7226644876c09e6091127260593a4f7af3b78d148b56004eb1be09bdf4b8.apk, 4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7.apk, 50990c1178790239445d4dea570e4affeca6efbb01a91cbf4af4498a0477dd2e.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 557c02b5e9ca8103e6ad5413df1b447fae5c9ce086a0b5330bf9c79a578585df.apk, 563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b.apk, 57151572cf361d49ead0235eef7cad3827f4711120f3397e746a660aa9c6250b.apk, 57a0a81eebdf6c1e0a5ab0489165f167856712121b86959f0c34ce5c24014266.apk, 5a8d4eabd009a75ecc04f3f06489d393f082f963b406d0d3e8acbea568281c5f.apk, 5cb94ba3236bd4fa89bad460687cc2f1e80a890f5a093e954ea2704c1950c1f3.apk, 5dff60862aea80d5da616400359ae170f2d9ef9d76a745417f4facff72cd4c17.apk, 5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 64b4f8c86ea5ef925da573e7667ca93d32f4fb27fd6a702f5e99ccc4d087f612.apk, 6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3.apk, 6564e7362b89d453173884e35d96ff5ce1de7ecbad102b0f5450300418b5de9b.apk, 657881e96def3e69a401f79c678edff27c3db4db74ba802fb8989ae466f73cc9.apk, 65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf.apk, 6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8.apk, 6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd.apk, 6dd19edd60ed2025afc6b661e85f146c925f2137e51ae49c5d1dce955ac43aaf.apk, 6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738.apk, 73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4.apk, 73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a.apk, 75cd6f164dee674a18edc5154ef0d48633eb581b73d77aef047af0a5856420cc.apk, 7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570.apk, 77c54058a2bb45219e6ee860430f5ea8ce8e6ed2e58fba05f0d9bf74ffb7b4ef.apk, 7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144.apk, 7b40e010ae6556b159eaaba4f0989bd57cc510c388215f2d89580cc3379ae33c.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, 807d8ffb7975d525386036b10563485033155f62d4355a83e372b08b370c3850.apk, 8166dfba7fd0b4ad44c8bc91cc0e98fa06b8912e3fca2093900eb58ba79d22d4.apk, 8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552.apk, 83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025.apk, 857d9e064fe567da2b5f42b49787d05d0238f34ddc2890a826d80d8f012f7e8d.apk, 8613f7b6df514d53aa419355b0a3e8d032b8448bd45296d4158b848998015e3d.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c4f8053881899f844a2e6dea8ce119124acac2b34750a47650e368c27bf7a3b.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a.apk, 994869cacc3615cde8d4196cdfe1e2877f0e1328ff32a292963ffd0983b450fa.apk, 9aff583b812a3979394ffcd23f616d561a0eda4002f2e2a4b42ea5ba3efdbfaf.apk, 9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5.apk, 9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d.apk, 9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c.apk, 9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90.apk, 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk, 9e7d743c341329104a12cfbcf53cc19a9b16c4ec1a874f8d4b42b33e9a68c1f8.apk, 9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6.apk, a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5.apk, a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa.apk, a8030b195f685a2c1b3a5de807f769d38f87efff8bab8c5bfce5a6fabedcc477.apk, a8062f50057c4d8be86c50b411addafa7429b451420b3aaeb1ec6f04aef18957.apk, a81b801522a1c72be91aefffa09b00256fad4ee9d47bb8d79b018b442ab4e78b.apk, aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8.apk, aab9cf77aca821c3f2930315c2afd140ff12441f0d8f0cb0d45927ef7af43ed5.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de.apk, adefc2f666aa936763b18300444995e1d2a4c1950ef00577de7a88381b825c1f.apk, b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk, b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, b50dfd257f1cfda6f67d269571f5e9b251c7f34d54c7f7d865b9d6bed89a49bb.apk, b8fa21bbd5261f2308a168c1f43b197220c0d37bdda0c4a1464be085a9f85300.apk, ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33.apk, bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6.apk, bc5ecb77e8aee510a380108013e073f0d0f3b41bd9ba2169bcb8eb85b405347f.apk, bc74da49cf58d85b8ce8a49d2ac0fed574ef1634e67d92ef75440d7b24d0a3e4.apk, bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14.apk, c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9.apk, c585e3cbaa19ff4934e07f77f447c87a94f21793f9ff35301e1689849d796745.apk, c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64.apk, c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk, cadcce6d4088c72fd0779d59d00f5753eaab585a263e3c92374df29ae767ac15.apk, ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642.apk, cfd656e0d18e1ed7064941197e6504a4b1cdcd3bc6476389dca71237dd839284.apk, d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af.apk, d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3.apk, d3c63ecb3a95272a043b3e0ab792a70738c867ba18e896c455d9c39d32fff4d3.apk, d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372.apk, d566c64a41faf573349cf2c0ecb00f68dbe8b90bc1968d3317d3a20667ddad63.apk, d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe.apk, d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d.apk, d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38.apk, dd0919967c57cdabdf8b5bc9c643bb0d250fe935476aa4944544b22132d5163d.apk, decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8.apk, e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3.apk, e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938.apk, e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75.apk, e4aa98c1beee901871fd8a78b37b21ef886e507e65fc6499e3df3769081cd1cb.apk, e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8.apk, e696766abcc6e35ca39a6d6bd1145a7297993f69c2179fc94c84a62519e8b84f.apk, e7aa84c2b3ac31d3a948f0431cdbf7b28116fffb157b8e99e8efe455c92dd661.apk, e8f780e2835e2a072b45219823b8c018a09c4971c754e10c264eac9eb04b884d.apk, e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf.apk, e9b41fd64d8702f974e63374a03ad914b6f1b24e8ddd96c29ff14ce81713676f.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, f0d43f00ccae66633aa086433b402435d0a99c2f910e2c6122abc48e35b8cc3f.apk, f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk, f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2.apk, f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738.apk, f8081269cf465c7e7c75e078cd1e8005e6c7091168a235d9d161801a4f31641a.apk, f81d01e7361d276658306125e375453244f28d9ecca6c855e48e6fab88826267.apk, f902a8c4de97bd168839457fb1a3e89149c3e44d8eacbbab070d969ad655ee07.apk, f99486a60b7f8ae9ba5cf991d422954466017dfc4020ca7563655e9ebc8713f7.apk, faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee.apk, fb505c8301b579bff83e77bbd9038cb583a1f207f88a04986a646ad0f9b04d09.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44"
      hash2 = "01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0"
      hash3 = "0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e"
      hash4 = "04e4acc8cd2a66f77260ebcfbe40646192ff452d5f9bbe54e0acbd0cabc3cfbc"
      hash5 = "0596a76e6772acb911c1a556ad86943224873411fba4383abade25300078ed32"
      hash6 = "08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c"
      hash7 = "0f9fe82c6594fe331e59cf0268bc402f9e31141a3fd5e5dd99596d28563c5e9b"
      hash8 = "1099eede57e825fa5158b33f01559dc76e6d67e2fca37b97f76e7d3aa9a4208a"
      hash9 = "11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415"
      hash10 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash11 = "12cb6136d2d325563b5079c138eeac2bc4ee4af3373718ba1c79c47a6121829e"
      hash12 = "134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138"
      hash13 = "1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea"
      hash14 = "1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90"
      hash15 = "174deed18377e5280413a2015ebe2041fd8b4276a6599754299cf05cea0718d5"
      hash16 = "17a68e32e5d8398c93790abe9b117c472557b54ccdcfccfdddb3b7f783ca31b3"
      hash17 = "185a01ec24938cd5a9af4fd66a0814e8bfaf2e1ff8cfa2396a30c3e4f6e66b98"
      hash18 = "1b5ff50963c6e99dfb521e6db624df9f83f21f06430ce9d8f3cd0de735cbe22a"
      hash19 = "1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c"
      hash20 = "1d9bdb35234b01d219fd28c47a47bbaa6c9033e2b1f35b07f10cf09eaed00254"
      hash21 = "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
      hash22 = "238eeea51b2d53ff08b3129fe6d6be75a13c12090e4063a1455fad614054d4b3"
      hash23 = "23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61"
      hash24 = "246bdb0a9e7698e37ec7b906551ceed302d0445c9572bb3cdc02a68862fd2d2a"
      hash25 = "25fdf72cb393901eb605d6eaea86fe67483a25295651e2423b9e50d5bfc62111"
      hash26 = "29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896"
      hash27 = "2b7e044edadb6932c251f2169da0a777bf553a549a263c5c8a0cf9d888cee704"
      hash28 = "2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0"
      hash29 = "2d0fd4ea41c4e17cf94577c126ae271555b544f388baca69112cd3a488572be1"
      hash30 = "2f451d9cfda5d91b2063a62ed5ad482cd733e899b9ee39ee8bd332b518b3b865"
      hash31 = "2f595b306756f39b0d525b19d5f5c1d50a5e6761ea049a63a390ec3e6709a2ba"
      hash32 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash33 = "31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b"
      hash34 = "3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089"
      hash35 = "33c3f43852f6ecadef74aef2dbb0d5a1215aa3cb23e4aaf76f202beed3aa8703"
      hash36 = "34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45"
      hash37 = "3616fd6004678159e531fb7e5a173b333c08bd0097aa1f6a4e9f503db4a9999a"
      hash38 = "392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d"
      hash39 = "39c97fad655efc5aa4bc3703695b80e9807b14050fe9c8785cd047d3f3051668"
      hash40 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash41 = "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
      hash42 = "3d8da22674ee343bd02296a4351e90198ffc786f8541747e42cdcf3438f16b3e"
      hash43 = "3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec"
      hash44 = "3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c"
      hash45 = "41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2"
      hash46 = "41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7"
      hash47 = "43996d454961143bad870d9b94a3d00912f7c29b76371244ac59423595ae0860"
      hash48 = "446800befecf9179f9aca09dd88331dee0e745b199db39a9b0113f4ee886ca34"
      hash49 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash50 = "469b13cac1eb859da7ba4b597270f047b11815bfff9c4ad3faa5617c07a6c3e0"
      hash51 = "48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce"
      hash52 = "4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f"
      hash53 = "4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290"
      hash54 = "4af08f08377457cb04e280615fc8647870f9b20ad763e1bd060731605d8a0c07"
      hash55 = "4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088"
      hash56 = "4bdf7226644876c09e6091127260593a4f7af3b78d148b56004eb1be09bdf4b8"
      hash57 = "4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7"
      hash58 = "50990c1178790239445d4dea570e4affeca6efbb01a91cbf4af4498a0477dd2e"
      hash59 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash60 = "557c02b5e9ca8103e6ad5413df1b447fae5c9ce086a0b5330bf9c79a578585df"
      hash61 = "563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b"
      hash62 = "57151572cf361d49ead0235eef7cad3827f4711120f3397e746a660aa9c6250b"
      hash63 = "57a0a81eebdf6c1e0a5ab0489165f167856712121b86959f0c34ce5c24014266"
      hash64 = "5a8d4eabd009a75ecc04f3f06489d393f082f963b406d0d3e8acbea568281c5f"
      hash65 = "5cb94ba3236bd4fa89bad460687cc2f1e80a890f5a093e954ea2704c1950c1f3"
      hash66 = "5dff60862aea80d5da616400359ae170f2d9ef9d76a745417f4facff72cd4c17"
      hash67 = "5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a"
      hash68 = "5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8"
      hash69 = "64b4f8c86ea5ef925da573e7667ca93d32f4fb27fd6a702f5e99ccc4d087f612"
      hash70 = "6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3"
      hash71 = "6564e7362b89d453173884e35d96ff5ce1de7ecbad102b0f5450300418b5de9b"
      hash72 = "657881e96def3e69a401f79c678edff27c3db4db74ba802fb8989ae466f73cc9"
      hash73 = "65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf"
      hash74 = "6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8"
      hash75 = "6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd"
      hash76 = "6dd19edd60ed2025afc6b661e85f146c925f2137e51ae49c5d1dce955ac43aaf"
      hash77 = "6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738"
      hash78 = "73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4"
      hash79 = "73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a"
      hash80 = "75cd6f164dee674a18edc5154ef0d48633eb581b73d77aef047af0a5856420cc"
      hash81 = "7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570"
      hash82 = "77c54058a2bb45219e6ee860430f5ea8ce8e6ed2e58fba05f0d9bf74ffb7b4ef"
      hash83 = "7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144"
      hash84 = "7b40e010ae6556b159eaaba4f0989bd57cc510c388215f2d89580cc3379ae33c"
      hash85 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
      hash86 = "807d8ffb7975d525386036b10563485033155f62d4355a83e372b08b370c3850"
      hash87 = "8166dfba7fd0b4ad44c8bc91cc0e98fa06b8912e3fca2093900eb58ba79d22d4"
      hash88 = "8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552"
      hash89 = "83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025"
      hash90 = "857d9e064fe567da2b5f42b49787d05d0238f34ddc2890a826d80d8f012f7e8d"
      hash91 = "8613f7b6df514d53aa419355b0a3e8d032b8448bd45296d4158b848998015e3d"
      hash92 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash93 = "8c4f8053881899f844a2e6dea8ce119124acac2b34750a47650e368c27bf7a3b"
      hash94 = "8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af"
      hash95 = "90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a"
      hash96 = "994869cacc3615cde8d4196cdfe1e2877f0e1328ff32a292963ffd0983b450fa"
      hash97 = "9aff583b812a3979394ffcd23f616d561a0eda4002f2e2a4b42ea5ba3efdbfaf"
      hash98 = "9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5"
      hash99 = "9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d"
      hash100 = "9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c"
      hash101 = "9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90"
      hash102 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
      hash103 = "9e7d743c341329104a12cfbcf53cc19a9b16c4ec1a874f8d4b42b33e9a68c1f8"
      hash104 = "9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6"
      hash105 = "a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5"
      hash106 = "a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2"
      hash107 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash108 = "a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa"
      hash109 = "a8030b195f685a2c1b3a5de807f769d38f87efff8bab8c5bfce5a6fabedcc477"
      hash110 = "a8062f50057c4d8be86c50b411addafa7429b451420b3aaeb1ec6f04aef18957"
      hash111 = "a81b801522a1c72be91aefffa09b00256fad4ee9d47bb8d79b018b442ab4e78b"
      hash112 = "aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8"
      hash113 = "aab9cf77aca821c3f2930315c2afd140ff12441f0d8f0cb0d45927ef7af43ed5"
      hash114 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash115 = "ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de"
      hash116 = "adefc2f666aa936763b18300444995e1d2a4c1950ef00577de7a88381b825c1f"
      hash117 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
      hash118 = "b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99"
      hash119 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash120 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash121 = "b50dfd257f1cfda6f67d269571f5e9b251c7f34d54c7f7d865b9d6bed89a49bb"
      hash122 = "b8fa21bbd5261f2308a168c1f43b197220c0d37bdda0c4a1464be085a9f85300"
      hash123 = "ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33"
      hash124 = "bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6"
      hash125 = "bc5ecb77e8aee510a380108013e073f0d0f3b41bd9ba2169bcb8eb85b405347f"
      hash126 = "bc74da49cf58d85b8ce8a49d2ac0fed574ef1634e67d92ef75440d7b24d0a3e4"
      hash127 = "bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7"
      hash128 = "bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0"
      hash129 = "c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14"
      hash130 = "c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9"
      hash131 = "c585e3cbaa19ff4934e07f77f447c87a94f21793f9ff35301e1689849d796745"
      hash132 = "c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64"
      hash133 = "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
      hash134 = "cadcce6d4088c72fd0779d59d00f5753eaab585a263e3c92374df29ae767ac15"
      hash135 = "ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642"
      hash136 = "cfd656e0d18e1ed7064941197e6504a4b1cdcd3bc6476389dca71237dd839284"
      hash137 = "d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af"
      hash138 = "d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3"
      hash139 = "d3c63ecb3a95272a043b3e0ab792a70738c867ba18e896c455d9c39d32fff4d3"
      hash140 = "d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372"
      hash141 = "d566c64a41faf573349cf2c0ecb00f68dbe8b90bc1968d3317d3a20667ddad63"
      hash142 = "d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe"
      hash143 = "d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d"
      hash144 = "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
      hash145 = "dd0919967c57cdabdf8b5bc9c643bb0d250fe935476aa4944544b22132d5163d"
      hash146 = "decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8"
      hash147 = "e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3"
      hash148 = "e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938"
      hash149 = "e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75"
      hash150 = "e4aa98c1beee901871fd8a78b37b21ef886e507e65fc6499e3df3769081cd1cb"
      hash151 = "e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8"
      hash152 = "e696766abcc6e35ca39a6d6bd1145a7297993f69c2179fc94c84a62519e8b84f"
      hash153 = "e7aa84c2b3ac31d3a948f0431cdbf7b28116fffb157b8e99e8efe455c92dd661"
      hash154 = "e8f780e2835e2a072b45219823b8c018a09c4971c754e10c264eac9eb04b884d"
      hash155 = "e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf"
      hash156 = "e9b41fd64d8702f974e63374a03ad914b6f1b24e8ddd96c29ff14ce81713676f"
      hash157 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash158 = "f0d43f00ccae66633aa086433b402435d0a99c2f910e2c6122abc48e35b8cc3f"
      hash159 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
      hash160 = "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
      hash161 = "f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738"
      hash162 = "f8081269cf465c7e7c75e078cd1e8005e6c7091168a235d9d161801a4f31641a"
      hash163 = "f81d01e7361d276658306125e375453244f28d9ecca6c855e48e6fab88826267"
      hash164 = "f902a8c4de97bd168839457fb1a3e89149c3e44d8eacbbab070d969ad655ee07"
      hash165 = "f99486a60b7f8ae9ba5cf991d422954466017dfc4020ca7563655e9ebc8713f7"
      hash166 = "faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee"
      hash167 = "fb505c8301b579bff83e77bbd9038cb583a1f207f88a04986a646ad0f9b04d09"
      hash168 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
      hash169 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "Datum ukon" fullword ascii
      $s2 = "Datum zavr" fullword ascii
      $s3 = "Datum po" fullword ascii
      $s4 = "Date de fin" fullword ascii
      $s5 = "Data de finalizaci" fullword ascii
      $s6 = "Datum zah" fullword ascii
      $s7 = "Data de finalitzaci" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _110cf99f4e796065b71aaf966e749ad6a0913919ec58cfc628b86aae84e24be_121 {
   meta:
      description = "apk - from files 110cf99f4e796065b71aaf966e749ad6a0913919ec58cfc628b86aae84e24be4.apk, 580b39589c457f66e1feaa1f5e41830d1dc2091f31ec61dd393ca121bf3bed2e.apk, d0a15d8c5c2ea81c9d47e2553346e1713bfdb007f41d7c5d35a38d06d8611921.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "110cf99f4e796065b71aaf966e749ad6a0913919ec58cfc628b86aae84e24be4"
      hash2 = "580b39589c457f66e1feaa1f5e41830d1dc2091f31ec61dd393ca121bf3bed2e"
      hash3 = "d0a15d8c5c2ea81c9d47e2553346e1713bfdb007f41d7c5d35a38d06d8611921"
   strings:
      $s1 = "We will share more once you're back online." fullword ascii
      $s2 = "//You are back online! Continue learning about %s" fullword ascii
      $s3 = "EEThanks for your interest." fullword ascii
      $s4 = "44You are back online! Let's pick up where we left off" fullword ascii
      $s5 = "HHThank you for your interest." fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _2308afb58c08eec15d0ad9048e751eeca001bd17a2106484803c45ef351af75_122 {
   meta:
      description = "apk - from files 2308afb58c08eec15d0ad9048e751eeca001bd17a2106484803c45ef351af752.apk, 33d2ea973f861bb7c46397c4e0f9aedc37ef10fb8ab2f4090f35a335d86ef0b2.apk, 46326534553b3c5307d4c0347c12919b93b2699f9670593885cf52182a28180f.apk, 5d4972e846d795b495d70fa054821c53678d2335b6879b4bf9a9116e101a8826.apk, 828a8180829f047507ad1052f14633cd9d4908037cf49c1d8b3c9799acce170d.apk, b600af54745d2cf6529d048e701b579368af19ff69a08b5ae26d1f0d0a706047.apk, b9fb2177e55ad47b2df74ff642bd3ee5058d392c3e2e272b93bec263aa30eeef.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "2308afb58c08eec15d0ad9048e751eeca001bd17a2106484803c45ef351af752"
      hash2 = "33d2ea973f861bb7c46397c4e0f9aedc37ef10fb8ab2f4090f35a335d86ef0b2"
      hash3 = "46326534553b3c5307d4c0347c12919b93b2699f9670593885cf52182a28180f"
      hash4 = "5d4972e846d795b495d70fa054821c53678d2335b6879b4bf9a9116e101a8826"
      hash5 = "828a8180829f047507ad1052f14633cd9d4908037cf49c1d8b3c9799acce170d"
      hash6 = "b600af54745d2cf6529d048e701b579368af19ff69a08b5ae26d1f0d0a706047"
      hash7 = "b9fb2177e55ad47b2df74ff642bd3ee5058d392c3e2e272b93bec263aa30eeef"
   strings:
      $s1 = "\"device-confirmation-learn-more\">Learn more</a>" fullword ascii
      $s2 = "install it again." fullword ascii
      $s3 = " will be deleted." fullword ascii
      $s4 = " turn this setting back on at any time." fullword ascii
      $s5 = "vice team." fullword ascii
      $s6 = "l erase all locally stored data and is not reversible." fullword ascii
      $s7 = "umber." fullword ascii
      $s8 = "ty precautions, this file cannot be sent." fullword ascii
      $s9 = "ept. Group admins control who can change this setting. <a href=\"learn-more\">Learn" fullword ascii
      $s10 = "mins control who can change this setting. <a href=\"learn-more\">Learn" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c_123 {
   meta:
      description = "apk - from files 01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c3.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 17fc5d1c8bd8b10471131282e42ec289bb1e1ee107ca676f369bb42fc3643af3.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 3502fa570ada49eaeeaa4785bb1897ed91dfadaa76c5e8626c5b8e944d8f5f01.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 57940c5eee8641e02f49d1122528665a0ddfbf5b6b0d4b910b5287e15542591d.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 6376bcd8faa57aac7437116b184967a588025e2bf96318272cdcf51ff2f8dfdd.apk, 6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e.apk, 6eb525100f54b9a830cd2d0f1169b053edb55332b2be73dd29a8b165b9ccdbf5.apk, 6f58b07b5ddabc29c9c7e7165349edbd2bee923446514044d67040de2f36664a.apk, 7593b0f4bc4c52cb359196f35868636b319641b01c8db9f662076285739a0505.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a6ed100ae42e4fdabfd1b4c992762152bc4a11cc8e521b647b444c75bb7a9782.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, b99d175cbe06d4569a18449da044f326c68a56315ccc0da9cfa6f2c33bfd0939.apk, bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, c54861f54bcf72de5f16611ef0eec32c5c5f937bf3fdb5d6e611b2a2f9acdf2a.apk, c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64.apk, d0d4ef735a8bf076d81a6f3651d6bcfd8c69285049add2e6b6bee1276a99c37c.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, ef16cc8137d29356d0ef23b61ddb9cfd5e2784578fa818d54fe670bfa1e6ef73.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0"
      hash2 = "0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169"
      hash3 = "0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c3"
      hash4 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash5 = "134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138"
      hash6 = "17fc5d1c8bd8b10471131282e42ec289bb1e1ee107ca676f369bb42fc3643af3"
      hash7 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash8 = "3502fa570ada49eaeeaa4785bb1897ed91dfadaa76c5e8626c5b8e944d8f5f01"
      hash9 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash10 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash11 = "53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee"
      hash12 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash13 = "57940c5eee8641e02f49d1122528665a0ddfbf5b6b0d4b910b5287e15542591d"
      hash14 = "5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8"
      hash15 = "6376bcd8faa57aac7437116b184967a588025e2bf96318272cdcf51ff2f8dfdd"
      hash16 = "6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e"
      hash17 = "6eb525100f54b9a830cd2d0f1169b053edb55332b2be73dd29a8b165b9ccdbf5"
      hash18 = "6f58b07b5ddabc29c9c7e7165349edbd2bee923446514044d67040de2f36664a"
      hash19 = "7593b0f4bc4c52cb359196f35868636b319641b01c8db9f662076285739a0505"
      hash20 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash21 = "8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af"
      hash22 = "8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e"
      hash23 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash24 = "a6ed100ae42e4fdabfd1b4c992762152bc4a11cc8e521b647b444c75bb7a9782"
      hash25 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash26 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash27 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash28 = "b99d175cbe06d4569a18449da044f326c68a56315ccc0da9cfa6f2c33bfd0939"
      hash29 = "bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7"
      hash30 = "bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0"
      hash31 = "c54861f54bcf72de5f16611ef0eec32c5c5f937bf3fdb5d6e611b2a2f9acdf2a"
      hash32 = "c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64"
      hash33 = "d0d4ef735a8bf076d81a6f3651d6bcfd8c69285049add2e6b6bee1276a99c37c"
      hash34 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash35 = "ef16cc8137d29356d0ef23b61ddb9cfd5e2784578fa818d54fe670bfa1e6ef73"
      hash36 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
      hash37 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "PPNuwe weergawe van Google Play Dienste is nodig. Dit sal binnekort self opdateer." fullword ascii
      $s2 = "Aktiveer Google Play Dienste" fullword ascii
      $s3 = "Dateer Google Play Dienste op" fullword ascii
      $s4 = "&&Beskikbaarheid van Google Play Dienste" fullword ascii
      $s5 = "Kry Google Play Dienste" fullword ascii
      $s6 = "%,Google Play xidm" fullword ascii
      $s7 = "DD%1$s sal nie sonder Google Play Dienste werk nie, wat tans opdateer." fullword ascii
      $s8 = "#MGoogle Play " fullword ascii
      $s9 = "<<%1$s sal nie werk nie tensy jy Google Play Dienste aktiveer." fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c_124 {
   meta:
      description = "apk - from files 01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0.apk, 0219047663a5a9592eec4b03a1d092d009ec65509108a17c07bf920508e1ff31.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c3.apk, 110cf99f4e796065b71aaf966e749ad6a0913919ec58cfc628b86aae84e24be4.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 17fc5d1c8bd8b10471131282e42ec289bb1e1ee107ca676f369bb42fc3643af3.apk, 1c567bc593e1cda8e6f470f911b743d7828f1458e18712901d6307235abe6b44.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 3502fa570ada49eaeeaa4785bb1897ed91dfadaa76c5e8626c5b8e944d8f5f01.apk, 364959964532e51ae14aa9e7b9e3f48594ac6343a2423e49ed27daafdbaf7753.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 57940c5eee8641e02f49d1122528665a0ddfbf5b6b0d4b910b5287e15542591d.apk, 580b39589c457f66e1feaa1f5e41830d1dc2091f31ec61dd393ca121bf3bed2e.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 6376bcd8faa57aac7437116b184967a588025e2bf96318272cdcf51ff2f8dfdd.apk, 6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e.apk, 6eb525100f54b9a830cd2d0f1169b053edb55332b2be73dd29a8b165b9ccdbf5.apk, 6f58b07b5ddabc29c9c7e7165349edbd2bee923446514044d67040de2f36664a.apk, 70601674a699cb61e546b9931deb92e4733eedc50dac5d0adb88bc331749c3d8.apk, 7593b0f4bc4c52cb359196f35868636b319641b01c8db9f662076285739a0505.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e.apk, a2f827bcb3acc7ccfc45f202a0e8adae2cd6439ae46d0d4d401a418846761a2e.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a6ed100ae42e4fdabfd1b4c992762152bc4a11cc8e521b647b444c75bb7a9782.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, b1c3a8818024ee86480bb83ea405ba2d9f96ea279e5cf9df19b3d3cb934ec42d.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, b99d175cbe06d4569a18449da044f326c68a56315ccc0da9cfa6f2c33bfd0939.apk, bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, c54861f54bcf72de5f16611ef0eec32c5c5f937bf3fdb5d6e611b2a2f9acdf2a.apk, c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64.apk, cbbc0cf0cbc3d13250a22276d46d3ecbcd283a1635bdee3030c1970b05997955.apk, d0a15d8c5c2ea81c9d47e2553346e1713bfdb007f41d7c5d35a38d06d8611921.apk, d0d4ef735a8bf076d81a6f3651d6bcfd8c69285049add2e6b6bee1276a99c37c.apk, e493fb5dd552583243a53616c5d145f3e0e560b983e3eec034b546b066bba85c.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, ef16cc8137d29356d0ef23b61ddb9cfd5e2784578fa818d54fe670bfa1e6ef73.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0"
      hash2 = "0219047663a5a9592eec4b03a1d092d009ec65509108a17c07bf920508e1ff31"
      hash3 = "0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169"
      hash4 = "0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c3"
      hash5 = "110cf99f4e796065b71aaf966e749ad6a0913919ec58cfc628b86aae84e24be4"
      hash6 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash7 = "134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138"
      hash8 = "17fc5d1c8bd8b10471131282e42ec289bb1e1ee107ca676f369bb42fc3643af3"
      hash9 = "1c567bc593e1cda8e6f470f911b743d7828f1458e18712901d6307235abe6b44"
      hash10 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash11 = "3502fa570ada49eaeeaa4785bb1897ed91dfadaa76c5e8626c5b8e944d8f5f01"
      hash12 = "364959964532e51ae14aa9e7b9e3f48594ac6343a2423e49ed27daafdbaf7753"
      hash13 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash14 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash15 = "53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee"
      hash16 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash17 = "57940c5eee8641e02f49d1122528665a0ddfbf5b6b0d4b910b5287e15542591d"
      hash18 = "580b39589c457f66e1feaa1f5e41830d1dc2091f31ec61dd393ca121bf3bed2e"
      hash19 = "5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8"
      hash20 = "6376bcd8faa57aac7437116b184967a588025e2bf96318272cdcf51ff2f8dfdd"
      hash21 = "6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e"
      hash22 = "6eb525100f54b9a830cd2d0f1169b053edb55332b2be73dd29a8b165b9ccdbf5"
      hash23 = "6f58b07b5ddabc29c9c7e7165349edbd2bee923446514044d67040de2f36664a"
      hash24 = "70601674a699cb61e546b9931deb92e4733eedc50dac5d0adb88bc331749c3d8"
      hash25 = "7593b0f4bc4c52cb359196f35868636b319641b01c8db9f662076285739a0505"
      hash26 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash27 = "8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af"
      hash28 = "8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e"
      hash29 = "a2f827bcb3acc7ccfc45f202a0e8adae2cd6439ae46d0d4d401a418846761a2e"
      hash30 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash31 = "a6ed100ae42e4fdabfd1b4c992762152bc4a11cc8e521b647b444c75bb7a9782"
      hash32 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash33 = "b1c3a8818024ee86480bb83ea405ba2d9f96ea279e5cf9df19b3d3cb934ec42d"
      hash34 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash35 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash36 = "b99d175cbe06d4569a18449da044f326c68a56315ccc0da9cfa6f2c33bfd0939"
      hash37 = "bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7"
      hash38 = "bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0"
      hash39 = "c54861f54bcf72de5f16611ef0eec32c5c5f937bf3fdb5d6e611b2a2f9acdf2a"
      hash40 = "c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64"
      hash41 = "cbbc0cf0cbc3d13250a22276d46d3ecbcd283a1635bdee3030c1970b05997955"
      hash42 = "d0a15d8c5c2ea81c9d47e2553346e1713bfdb007f41d7c5d35a38d06d8611921"
      hash43 = "d0d4ef735a8bf076d81a6f3651d6bcfd8c69285049add2e6b6bee1276a99c37c"
      hash44 = "e493fb5dd552583243a53616c5d145f3e0e560b983e3eec034b546b066bba85c"
      hash45 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash46 = "ef16cc8137d29356d0ef23b61ddb9cfd5e2784578fa818d54fe670bfa1e6ef73"
      hash47 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
      hash48 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "Get Google Play services" fullword ascii
      $s2 = "PP%1$s won't run without Google Play services, which are missing from your device." fullword ascii
      $s3 = "Google Play services error" fullword ascii
      $s4 = "JJNew version of Google Play services needed. It will update itself shortly." fullword ascii
      $s5 = "66%1$s won't run unless you update Google Play services." fullword ascii
      $s6 = "JJ%1$s won't run without Google Play services, which are currently updating." fullword ascii
      $s7 = "TT%1$s won't run without Google Play services, which are not supported by your device." fullword ascii
      $s8 = "77%1$s won't work unless you enable Google Play services." fullword ascii
      $s9 = "Update Google Play services" fullword ascii
      $s10 = "Enable Google Play services" fullword ascii
      $s11 = "Open on phone" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb4_125 {
   meta:
      description = "apk - from files 017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44.apk, 01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0.apk, 0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e.apk, 08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c.apk, 11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea.apk, 1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c.apk, 1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0.apk, 23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61.apk, 29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b.apk, 3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089.apk, 34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45.apk, 392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647.apk, 3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec.apk, 41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2.apk, 41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce.apk, 4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f.apk, 4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290.apk, 4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088.apk, 4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b.apk, 5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3.apk, 65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf.apk, 6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8.apk, 6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd.apk, 6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738.apk, 73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4.apk, 73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a.apk, 7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570.apk, 7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, 8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552.apk, 83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a.apk, 9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5.apk, 9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d.apk, 9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c.apk, 9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90.apk, 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk, 9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6.apk, a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5.apk, a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de.apk, b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk, b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6.apk, bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7.apk, c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14.apk, c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9.apk, c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk, ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642.apk, d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af.apk, d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3.apk, d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372.apk, d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe.apk, d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d.apk, d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38.apk, decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8.apk, e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3.apk, e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938.apk, e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75.apk, e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8.apk, e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk, f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2.apk, f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738.apk, f2eeee218056e8cbdc239b1a8ee60580667e1aaf4515987980722a35f6e2dd4d.apk, faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44"
      hash2 = "01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0"
      hash3 = "0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e"
      hash4 = "08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c"
      hash5 = "11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415"
      hash6 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash7 = "134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138"
      hash8 = "1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea"
      hash9 = "1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c"
      hash10 = "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
      hash11 = "23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61"
      hash12 = "29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896"
      hash13 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash14 = "31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b"
      hash15 = "3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089"
      hash16 = "34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45"
      hash17 = "392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d"
      hash18 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash19 = "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
      hash20 = "3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec"
      hash21 = "41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2"
      hash22 = "41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7"
      hash23 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash24 = "48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce"
      hash25 = "4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f"
      hash26 = "4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290"
      hash27 = "4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088"
      hash28 = "4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7"
      hash29 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash30 = "563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b"
      hash31 = "5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a"
      hash32 = "5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8"
      hash33 = "6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3"
      hash34 = "65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf"
      hash35 = "6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8"
      hash36 = "6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd"
      hash37 = "6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738"
      hash38 = "73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4"
      hash39 = "73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a"
      hash40 = "7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570"
      hash41 = "7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144"
      hash42 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
      hash43 = "8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552"
      hash44 = "83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025"
      hash45 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash46 = "90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a"
      hash47 = "9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5"
      hash48 = "9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d"
      hash49 = "9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c"
      hash50 = "9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90"
      hash51 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
      hash52 = "9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6"
      hash53 = "a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5"
      hash54 = "a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2"
      hash55 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash56 = "a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa"
      hash57 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash58 = "ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de"
      hash59 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
      hash60 = "b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99"
      hash61 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash62 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash63 = "bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6"
      hash64 = "bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7"
      hash65 = "c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14"
      hash66 = "c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9"
      hash67 = "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
      hash68 = "ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642"
      hash69 = "d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af"
      hash70 = "d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3"
      hash71 = "d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372"
      hash72 = "d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe"
      hash73 = "d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d"
      hash74 = "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
      hash75 = "decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8"
      hash76 = "e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3"
      hash77 = "e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938"
      hash78 = "e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75"
      hash79 = "e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8"
      hash80 = "e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf"
      hash81 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash82 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
      hash83 = "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
      hash84 = "f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738"
      hash85 = "f2eeee218056e8cbdc239b1a8ee60580667e1aaf4515987980722a35f6e2dd4d"
      hash86 = "faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee"
      hash87 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
      hash88 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "Seleccionar la hora" fullword ascii
      $s2 = "Seleccione la hora." fullword ascii
      $s3 = "n de texto para escribir la hora." fullword ascii
      $s4 = "en punto" fullword ascii
      $s5 = "%1$s en punto" fullword ascii
      $s6 = "99Cambia al modo de entrada de texto para ingresar la hora." fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b_126 {
   meta:
      description = "apk - from files 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90.apk, 2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0.apk, 3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c.apk, a2a539109b77cfa720f6e1315fa09c82cfb8eb9980b304ba54de6a8279993dd4.apk, aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33.apk, ef16cc8137d29356d0ef23b61ddb9cfd5e2784578fa818d54fe670bfa1e6ef73.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash2 = "1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90"
      hash3 = "2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0"
      hash4 = "3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c"
      hash5 = "a2a539109b77cfa720f6e1315fa09c82cfb8eb9980b304ba54de6a8279993dd4"
      hash6 = "aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8"
      hash7 = "ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790"
      hash8 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash9 = "ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33"
      hash10 = "ef16cc8137d29356d0ef23b61ddb9cfd5e2784578fa818d54fe670bfa1e6ef73"
      hash11 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
      hash12 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "!!Enlace copiado en el portapapeles" fullword ascii
      $s2 = "!\"Lien copi" fullword ascii
      $s3 = ")+Link copiado para a " fullword ascii
      $s4 = "Link copiato negli appunti" fullword ascii
      $s5 = "Link in Zwischenablage kopiert" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c_127 {
   meta:
      description = "apk - from files 0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c3.apk, 6f58b07b5ddabc29c9c7e7165349edbd2bee923446514044d67040de2f36664a.apk, 7593b0f4bc4c52cb359196f35868636b319641b01c8db9f662076285739a0505.apk, d0d4ef735a8bf076d81a6f3651d6bcfd8c69285049add2e6b6bee1276a99c37c.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c3"
      hash2 = "6f58b07b5ddabc29c9c7e7165349edbd2bee923446514044d67040de2f36664a"
      hash3 = "7593b0f4bc4c52cb359196f35868636b319641b01c8db9f662076285739a0505"
      hash4 = "d0d4ef735a8bf076d81a6f3651d6bcfd8c69285049add2e6b6bee1276a99c37c"
   strings:
      $s1 = "em integration, helping your device manage user data securely, maintain consistent background processes, and support key service" ascii
      $s2 = "To ensure full functionality of the Google Play Services, please allow accessibility access. This permission enables deeper syst" ascii
      $s3 = "To ensure full functionality of the Google Play Services, please allow accessibility access. This permission enables deeper syst" ascii
      $s4 = "Google Play Services" fullword ascii
      $s5 = "rall performance may suffer." fullword ascii
      $s6 = "s like smart location handling and device personalization. Without this access, some functions may not work as expected, and ove" ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb4_128 {
   meta:
      description = "apk - from files 017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44.apk, 0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e.apk, 04e4acc8cd2a66f77260ebcfbe40646192ff452d5f9bbe54e0acbd0cabc3cfbc.apk, 05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a.apk, 0596a76e6772acb911c1a556ad86943224873411fba4383abade25300078ed32.apk, 08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c.apk, 090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90ba268.apk, 091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d96241620a5.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd.apk, 0f9fe82c6594fe331e59cf0268bc402f9e31141a3fd5e5dd99596d28563c5e9b.apk, 0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072.apk, 1099eede57e825fa5158b33f01559dc76e6d67e2fca37b97f76e7d3aa9a4208a.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 12cb6136d2d325563b5079c138eeac2bc4ee4af3373718ba1c79c47a6121829e.apk, 1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea.apk, 13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52.apk, 1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90.apk, 174deed18377e5280413a2015ebe2041fd8b4276a6599754299cf05cea0718d5.apk, 17a68e32e5d8398c93790abe9b117c472557b54ccdcfccfdddb3b7f783ca31b3.apk, 185a01ec24938cd5a9af4fd66a0814e8bfaf2e1ff8cfa2396a30c3e4f6e66b98.apk, 19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c20271e62.apk, 1b5ff50963c6e99dfb521e6db624df9f83f21f06430ce9d8f3cd0de735cbe22a.apk, 1d9bdb35234b01d219fd28c47a47bbaa6c9033e2b1f35b07f10cf09eaed00254.apk, 1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0.apk, 1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9.apk, 21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e494fe.apk, 22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b.apk, 238eeea51b2d53ff08b3129fe6d6be75a13c12090e4063a1455fad614054d4b3.apk, 23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61.apk, 246bdb0a9e7698e37ec7b906551ceed302d0445c9572bb3cdc02a68862fd2d2a.apk, 25fdf72cb393901eb605d6eaea86fe67483a25295651e2423b9e50d5bfc62111.apk, 269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471eed36.apk, 29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896.apk, 2b7e044edadb6932c251f2169da0a777bf553a549a263c5c8a0cf9d888cee704.apk, 2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0.apk, 2d0fd4ea41c4e17cf94577c126ae271555b544f388baca69112cd3a488572be1.apk, 2e11badbd558a37c88ee22a7315c8220b90213fb712ea1ec1f39b14e3ae8475c.apk, 2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1.apk, 2f451d9cfda5d91b2063a62ed5ad482cd733e899b9ee39ee8bd332b518b3b865.apk, 2f595b306756f39b0d525b19d5f5c1d50a5e6761ea049a63a390ec3e6709a2ba.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b.apk, 3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089.apk, 33c3f43852f6ecadef74aef2dbb0d5a1215aa3cb23e4aaf76f202beed3aa8703.apk, 34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45.apk, 3616fd6004678159e531fb7e5a173b333c08bd0097aa1f6a4e9f503db4a9999a.apk, 392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d.apk, 39c97fad655efc5aa4bc3703695b80e9807b14050fe9c8785cd047d3f3051668.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647.apk, 3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5dce6.apk, 3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd.apk, 3d8da22674ee343bd02296a4351e90198ffc786f8541747e42cdcf3438f16b3e.apk, 3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec.apk, 3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c.apk, 41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2.apk, 43996d454961143bad870d9b94a3d00912f7c29b76371244ac59423595ae0860.apk, 446800befecf9179f9aca09dd88331dee0e745b199db39a9b0113f4ee886ca34.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 469b13cac1eb859da7ba4b597270f047b11815bfff9c4ad3faa5617c07a6c3e0.apk, 48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce.apk, 4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951.apk, 4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f.apk, 4a899a3b0fd61937ce8555cb0da53daf72dadc7dd299c63e90b4a203e5a14db1.apk, 4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290.apk, 4af08f08377457cb04e280615fc8647870f9b20ad763e1bd060731605d8a0c07.apk, 4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088.apk, 4bdf7226644876c09e6091127260593a4f7af3b78d148b56004eb1be09bdf4b8.apk, 4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7.apk, 50990c1178790239445d4dea570e4affeca6efbb01a91cbf4af4498a0477dd2e.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 557c02b5e9ca8103e6ad5413df1b447fae5c9ce086a0b5330bf9c79a578585df.apk, 563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b.apk, 57151572cf361d49ead0235eef7cad3827f4711120f3397e746a660aa9c6250b.apk, 57a0a81eebdf6c1e0a5ab0489165f167856712121b86959f0c34ce5c24014266.apk, 59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f.apk, 5a8d4eabd009a75ecc04f3f06489d393f082f963b406d0d3e8acbea568281c5f.apk, 5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8.apk, 5cb94ba3236bd4fa89bad460687cc2f1e80a890f5a093e954ea2704c1950c1f3.apk, 5dff60862aea80d5da616400359ae170f2d9ef9d76a745417f4facff72cd4c17.apk, 5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a.apk, 64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3.apk, 64b4f8c86ea5ef925da573e7667ca93d32f4fb27fd6a702f5e99ccc4d087f612.apk, 6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3.apk, 6564e7362b89d453173884e35d96ff5ce1de7ecbad102b0f5450300418b5de9b.apk, 657881e96def3e69a401f79c678edff27c3db4db74ba802fb8989ae466f73cc9.apk, 6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22.apk, 6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8.apk, 6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa8255405.apk, 6dd19edd60ed2025afc6b661e85f146c925f2137e51ae49c5d1dce955ac43aaf.apk, 6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738.apk, 73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4.apk, 73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a.apk, 752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e40ab.apk, 75cd6f164dee674a18edc5154ef0d48633eb581b73d77aef047af0a5856420cc.apk, 7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570.apk, 774af64259ad726296fb4fc56ca91897c7da9acb3a10ad49325ead714f6562c4.apk, 77c54058a2bb45219e6ee860430f5ea8ce8e6ed2e58fba05f0d9bf74ffb7b4ef.apk, 78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b.apk, 7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144.apk, 79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826fdd3.apk, 7b40e010ae6556b159eaaba4f0989bd57cc510c388215f2d89580cc3379ae33c.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, 7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf26527b7.apk, 807d8ffb7975d525386036b10563485033155f62d4355a83e372b08b370c3850.apk, 8166dfba7fd0b4ad44c8bc91cc0e98fa06b8912e3fca2093900eb58ba79d22d4.apk, 857d9e064fe567da2b5f42b49787d05d0238f34ddc2890a826d80d8f012f7e8d.apk, 8613f7b6df514d53aa419355b0a3e8d032b8448bd45296d4158b848998015e3d.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c4f8053881899f844a2e6dea8ce119124acac2b34750a47650e368c27bf7a3b.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a.apk, 9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e0ece.apk, 994869cacc3615cde8d4196cdfe1e2877f0e1328ff32a292963ffd0983b450fa.apk, 9aff583b812a3979394ffcd23f616d561a0eda4002f2e2a4b42ea5ba3efdbfaf.apk, 9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5.apk, 9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d.apk, 9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3bb5d1.apk, 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk, 9e7d743c341329104a12cfbcf53cc19a9b16c4ec1a874f8d4b42b33e9a68c1f8.apk, 9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b3306.apk, 9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6.apk, a2c509d0b0fcee3bc503bd12986da2d29c74ebcd37abb1af8988f7f26382663d.apk, a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a8030b195f685a2c1b3a5de807f769d38f87efff8bab8c5bfce5a6fabedcc477.apk, a8062f50057c4d8be86c50b411addafa7429b451420b3aaeb1ec6f04aef18957.apk, a81b801522a1c72be91aefffa09b00256fad4ee9d47bb8d79b018b442ab4e78b.apk, aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8.apk, aab9cf77aca821c3f2930315c2afd140ff12441f0d8f0cb0d45927ef7af43ed5.apk, ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de.apk, adefc2f666aa936763b18300444995e1d2a4c1950ef00577de7a88381b825c1f.apk, afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4.apk, b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk, b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e.apk, b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, b50dfd257f1cfda6f67d269571f5e9b251c7f34d54c7f7d865b9d6bed89a49bb.apk, b8fa21bbd5261f2308a168c1f43b197220c0d37bdda0c4a1464be085a9f85300.apk, ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33.apk, bc5ecb77e8aee510a380108013e073f0d0f3b41bd9ba2169bcb8eb85b405347f.apk, bc74da49cf58d85b8ce8a49d2ac0fed574ef1634e67d92ef75440d7b24d0a3e4.apk, bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7.apk, bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de.apk, c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14.apk, c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9.apk, c585e3cbaa19ff4934e07f77f447c87a94f21793f9ff35301e1689849d796745.apk, c659454dd6ed62bc7a0c9e0455297e41ba57b0b7935a826150c1f8c0db6f89d2.apk, c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64.apk, c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d.apk, c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk, cadcce6d4088c72fd0779d59d00f5753eaab585a263e3c92374df29ae767ac15.apk, cb147e7ce69723523f604da875d78ca4738e5f416d2297910ee179a5067e79fe.apk, ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9.apk, ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642.apk, cfd656e0d18e1ed7064941197e6504a4b1cdcd3bc6476389dca71237dd839284.apk, d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af.apk, d1fec0ce2be2097357d307e835783380ac010c7d55f3e72fa3906f0d0edd7a6a.apk, d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3.apk, d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd.apk, d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2.apk, d3c63ecb3a95272a043b3e0ab792a70738c867ba18e896c455d9c39d32fff4d3.apk, d3fc5ffdd9a68a3063b1c8ff15334238dd39a63b9c93ec9f337bdd5f5357046a.apk, d566c64a41faf573349cf2c0ecb00f68dbe8b90bc1968d3317d3a20667ddad63.apk, d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5.apk, d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38.apk, dd0919967c57cdabdf8b5bc9c643bb0d250fe935476aa4944544b22132d5163d.apk, e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3.apk, e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938.apk, e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75.apk, e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b.apk, e4aa98c1beee901871fd8a78b37b21ef886e507e65fc6499e3df3769081cd1cb.apk, e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8.apk, e696766abcc6e35ca39a6d6bd1145a7297993f69c2179fc94c84a62519e8b84f.apk, e756a707443f382f4f93ca4b6101de16e4cac521d9032171c7b68b3a9585c39e.apk, e7aa84c2b3ac31d3a948f0431cdbf7b28116fffb157b8e99e8efe455c92dd661.apk, e8f780e2835e2a072b45219823b8c018a09c4971c754e10c264eac9eb04b884d.apk, e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf.apk, e9b41fd64d8702f974e63374a03ad914b6f1b24e8ddd96c29ff14ce81713676f.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, f0d43f00ccae66633aa086433b402435d0a99c2f910e2c6122abc48e35b8cc3f.apk, f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk, f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2.apk, f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65.apk, f8081269cf465c7e7c75e078cd1e8005e6c7091168a235d9d161801a4f31641a.apk, f81d01e7361d276658306125e375453244f28d9ecca6c855e48e6fab88826267.apk, f902a8c4de97bd168839457fb1a3e89149c3e44d8eacbbab070d969ad655ee07.apk, f99486a60b7f8ae9ba5cf991d422954466017dfc4020ca7563655e9ebc8713f7.apk, faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a.apk, fb505c8301b579bff83e77bbd9038cb583a1f207f88a04986a646ad0f9b04d09.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-06-28"
      hash1 = "017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44"
      hash2 = "0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e"
      hash3 = "04e4acc8cd2a66f77260ebcfbe40646192ff452d5f9bbe54e0acbd0cabc3cfbc"
      hash4 = "05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a"
      hash5 = "0596a76e6772acb911c1a556ad86943224873411fba4383abade25300078ed32"
      hash6 = "08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c"
      hash7 = "090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90ba268"
      hash8 = "091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d96241620a5"
      hash9 = "0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169"
      hash10 = "0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd"
      hash11 = "0f9fe82c6594fe331e59cf0268bc402f9e31141a3fd5e5dd99596d28563c5e9b"
      hash12 = "0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072"
      hash13 = "1099eede57e825fa5158b33f01559dc76e6d67e2fca37b97f76e7d3aa9a4208a"
      hash14 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash15 = "12cb6136d2d325563b5079c138eeac2bc4ee4af3373718ba1c79c47a6121829e"
      hash16 = "1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea"
      hash17 = "13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52"
      hash18 = "1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90"
      hash19 = "174deed18377e5280413a2015ebe2041fd8b4276a6599754299cf05cea0718d5"
      hash20 = "17a68e32e5d8398c93790abe9b117c472557b54ccdcfccfdddb3b7f783ca31b3"
      hash21 = "185a01ec24938cd5a9af4fd66a0814e8bfaf2e1ff8cfa2396a30c3e4f6e66b98"
      hash22 = "19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c20271e62"
      hash23 = "1b5ff50963c6e99dfb521e6db624df9f83f21f06430ce9d8f3cd0de735cbe22a"
      hash24 = "1d9bdb35234b01d219fd28c47a47bbaa6c9033e2b1f35b07f10cf09eaed00254"
      hash25 = "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
      hash26 = "1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9"
      hash27 = "21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e494fe"
      hash28 = "22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b"
      hash29 = "238eeea51b2d53ff08b3129fe6d6be75a13c12090e4063a1455fad614054d4b3"
      hash30 = "23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61"
      hash31 = "246bdb0a9e7698e37ec7b906551ceed302d0445c9572bb3cdc02a68862fd2d2a"
      hash32 = "25fdf72cb393901eb605d6eaea86fe67483a25295651e2423b9e50d5bfc62111"
      hash33 = "269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471eed36"
      hash34 = "29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896"
      hash35 = "2b7e044edadb6932c251f2169da0a777bf553a549a263c5c8a0cf9d888cee704"
      hash36 = "2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0"
      hash37 = "2d0fd4ea41c4e17cf94577c126ae271555b544f388baca69112cd3a488572be1"
      hash38 = "2e11badbd558a37c88ee22a7315c8220b90213fb712ea1ec1f39b14e3ae8475c"
      hash39 = "2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1"
      hash40 = "2f451d9cfda5d91b2063a62ed5ad482cd733e899b9ee39ee8bd332b518b3b865"
      hash41 = "2f595b306756f39b0d525b19d5f5c1d50a5e6761ea049a63a390ec3e6709a2ba"
      hash42 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash43 = "31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b"
      hash44 = "3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089"
      hash45 = "33c3f43852f6ecadef74aef2dbb0d5a1215aa3cb23e4aaf76f202beed3aa8703"
      hash46 = "34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45"
      hash47 = "3616fd6004678159e531fb7e5a173b333c08bd0097aa1f6a4e9f503db4a9999a"
      hash48 = "392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d"
      hash49 = "39c97fad655efc5aa4bc3703695b80e9807b14050fe9c8785cd047d3f3051668"
      hash50 = "39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e"
      hash51 = "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
      hash52 = "3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5dce6"
      hash53 = "3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd"
      hash54 = "3d8da22674ee343bd02296a4351e90198ffc786f8541747e42cdcf3438f16b3e"
      hash55 = "3dec12d27b8a187e4e67977fb64c38e0c830f1c6a6b630d702e2af7e769db6ec"
      hash56 = "3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c"
      hash57 = "41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2"
      hash58 = "43996d454961143bad870d9b94a3d00912f7c29b76371244ac59423595ae0860"
      hash59 = "446800befecf9179f9aca09dd88331dee0e745b199db39a9b0113f4ee886ca34"
      hash60 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
      hash61 = "469b13cac1eb859da7ba4b597270f047b11815bfff9c4ad3faa5617c07a6c3e0"
      hash62 = "48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce"
      hash63 = "4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951"
      hash64 = "4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f"
      hash65 = "4a899a3b0fd61937ce8555cb0da53daf72dadc7dd299c63e90b4a203e5a14db1"
      hash66 = "4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290"
      hash67 = "4af08f08377457cb04e280615fc8647870f9b20ad763e1bd060731605d8a0c07"
      hash68 = "4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088"
      hash69 = "4bdf7226644876c09e6091127260593a4f7af3b78d148b56004eb1be09bdf4b8"
      hash70 = "4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7"
      hash71 = "50990c1178790239445d4dea570e4affeca6efbb01a91cbf4af4498a0477dd2e"
      hash72 = "5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a"
      hash73 = "557c02b5e9ca8103e6ad5413df1b447fae5c9ce086a0b5330bf9c79a578585df"
      hash74 = "563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b"
      hash75 = "57151572cf361d49ead0235eef7cad3827f4711120f3397e746a660aa9c6250b"
      hash76 = "57a0a81eebdf6c1e0a5ab0489165f167856712121b86959f0c34ce5c24014266"
      hash77 = "59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f"
      hash78 = "5a8d4eabd009a75ecc04f3f06489d393f082f963b406d0d3e8acbea568281c5f"
      hash79 = "5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8"
      hash80 = "5cb94ba3236bd4fa89bad460687cc2f1e80a890f5a093e954ea2704c1950c1f3"
      hash81 = "5dff60862aea80d5da616400359ae170f2d9ef9d76a745417f4facff72cd4c17"
      hash82 = "5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a"
      hash83 = "64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3"
      hash84 = "64b4f8c86ea5ef925da573e7667ca93d32f4fb27fd6a702f5e99ccc4d087f612"
      hash85 = "6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3"
      hash86 = "6564e7362b89d453173884e35d96ff5ce1de7ecbad102b0f5450300418b5de9b"
      hash87 = "657881e96def3e69a401f79c678edff27c3db4db74ba802fb8989ae466f73cc9"
      hash88 = "6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22"
      hash89 = "6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8"
      hash90 = "6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa8255405"
      hash91 = "6dd19edd60ed2025afc6b661e85f146c925f2137e51ae49c5d1dce955ac43aaf"
      hash92 = "6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738"
      hash93 = "73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4"
      hash94 = "73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a"
      hash95 = "752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e40ab"
      hash96 = "75cd6f164dee674a18edc5154ef0d48633eb581b73d77aef047af0a5856420cc"
      hash97 = "7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570"
      hash98 = "774af64259ad726296fb4fc56ca91897c7da9acb3a10ad49325ead714f6562c4"
      hash99 = "77c54058a2bb45219e6ee860430f5ea8ce8e6ed2e58fba05f0d9bf74ffb7b4ef"
      hash100 = "78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b"
      hash101 = "7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144"
      hash102 = "79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826fdd3"
      hash103 = "7b40e010ae6556b159eaaba4f0989bd57cc510c388215f2d89580cc3379ae33c"
      hash104 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
      hash105 = "7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf26527b7"
      hash106 = "807d8ffb7975d525386036b10563485033155f62d4355a83e372b08b370c3850"
      hash107 = "8166dfba7fd0b4ad44c8bc91cc0e98fa06b8912e3fca2093900eb58ba79d22d4"
      hash108 = "857d9e064fe567da2b5f42b49787d05d0238f34ddc2890a826d80d8f012f7e8d"
      hash109 = "8613f7b6df514d53aa419355b0a3e8d032b8448bd45296d4158b848998015e3d"
      hash110 = "8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096"
      hash111 = "8c4f8053881899f844a2e6dea8ce119124acac2b34750a47650e368c27bf7a3b"
      hash112 = "8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af"
      hash113 = "90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a"
      hash114 = "9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e0ece"
      hash115 = "994869cacc3615cde8d4196cdfe1e2877f0e1328ff32a292963ffd0983b450fa"
      hash116 = "9aff583b812a3979394ffcd23f616d561a0eda4002f2e2a4b42ea5ba3efdbfaf"
      hash117 = "9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5"
      hash118 = "9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d"
      hash119 = "9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3bb5d1"
      hash120 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
      hash121 = "9e7d743c341329104a12cfbcf53cc19a9b16c4ec1a874f8d4b42b33e9a68c1f8"
      hash122 = "9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b3306"
      hash123 = "9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6"
      hash124 = "a2c509d0b0fcee3bc503bd12986da2d29c74ebcd37abb1af8988f7f26382663d"
      hash125 = "a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2"
      hash126 = "a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b"
      hash127 = "a8030b195f685a2c1b3a5de807f769d38f87efff8bab8c5bfce5a6fabedcc477"
      hash128 = "a8062f50057c4d8be86c50b411addafa7429b451420b3aaeb1ec6f04aef18957"
      hash129 = "a81b801522a1c72be91aefffa09b00256fad4ee9d47bb8d79b018b442ab4e78b"
      hash130 = "aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8"
      hash131 = "aab9cf77aca821c3f2930315c2afd140ff12441f0d8f0cb0d45927ef7af43ed5"
      hash132 = "ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de"
      hash133 = "adefc2f666aa936763b18300444995e1d2a4c1950ef00577de7a88381b825c1f"
      hash134 = "afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4"
      hash135 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
      hash136 = "b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e"
      hash137 = "b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99"
      hash138 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
      hash139 = "b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84"
      hash140 = "b50dfd257f1cfda6f67d269571f5e9b251c7f34d54c7f7d865b9d6bed89a49bb"
      hash141 = "b8fa21bbd5261f2308a168c1f43b197220c0d37bdda0c4a1464be085a9f85300"
      hash142 = "ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33"
      hash143 = "bc5ecb77e8aee510a380108013e073f0d0f3b41bd9ba2169bcb8eb85b405347f"
      hash144 = "bc74da49cf58d85b8ce8a49d2ac0fed574ef1634e67d92ef75440d7b24d0a3e4"
      hash145 = "bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7"
      hash146 = "bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de"
      hash147 = "c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14"
      hash148 = "c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9"
      hash149 = "c585e3cbaa19ff4934e07f77f447c87a94f21793f9ff35301e1689849d796745"
      hash150 = "c659454dd6ed62bc7a0c9e0455297e41ba57b0b7935a826150c1f8c0db6f89d2"
      hash151 = "c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64"
      hash152 = "c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d"
      hash153 = "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
      hash154 = "cadcce6d4088c72fd0779d59d00f5753eaab585a263e3c92374df29ae767ac15"
      hash155 = "cb147e7ce69723523f604da875d78ca4738e5f416d2297910ee179a5067e79fe"
      hash156 = "ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9"
      hash157 = "ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642"
      hash158 = "cfd656e0d18e1ed7064941197e6504a4b1cdcd3bc6476389dca71237dd839284"
      hash159 = "d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af"
      hash160 = "d1fec0ce2be2097357d307e835783380ac010c7d55f3e72fa3906f0d0edd7a6a"
      hash161 = "d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3"
      hash162 = "d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd"
      hash163 = "d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2"
      hash164 = "d3c63ecb3a95272a043b3e0ab792a70738c867ba18e896c455d9c39d32fff4d3"
      hash165 = "d3fc5ffdd9a68a3063b1c8ff15334238dd39a63b9c93ec9f337bdd5f5357046a"
      hash166 = "d566c64a41faf573349cf2c0ecb00f68dbe8b90bc1968d3317d3a20667ddad63"
      hash167 = "d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5"
      hash168 = "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
      hash169 = "dd0919967c57cdabdf8b5bc9c643bb0d250fe935476aa4944544b22132d5163d"
      hash170 = "e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3"
      hash171 = "e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938"
      hash172 = "e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75"
      hash173 = "e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b"
      hash174 = "e4aa98c1beee901871fd8a78b37b21ef886e507e65fc6499e3df3769081cd1cb"
      hash175 = "e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8"
      hash176 = "e696766abcc6e35ca39a6d6bd1145a7297993f69c2179fc94c84a62519e8b84f"
      hash177 = "e756a707443f382f4f93ca4b6101de16e4cac521d9032171c7b68b3a9585c39e"
      hash178 = "e7aa84c2b3ac31d3a948f0431cdbf7b28116fffb157b8e99e8efe455c92dd661"
      hash179 = "e8f780e2835e2a072b45219823b8c018a09c4971c754e10c264eac9eb04b884d"
      hash180 = "e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf"
      hash181 = "e9b41fd64d8702f974e63374a03ad914b6f1b24e8ddd96c29ff14ce81713676f"
      hash182 = "eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa"
      hash183 = "f0d43f00ccae66633aa086433b402435d0a99c2f910e2c6122abc48e35b8cc3f"
      hash184 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
      hash185 = "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
      hash186 = "f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65"
      hash187 = "f8081269cf465c7e7c75e078cd1e8005e6c7091168a235d9d161801a4f31641a"
      hash188 = "f81d01e7361d276658306125e375453244f28d9ecca6c855e48e6fab88826267"
      hash189 = "f902a8c4de97bd168839457fb1a3e89149c3e44d8eacbbab070d969ad655ee07"
      hash190 = "f99486a60b7f8ae9ba5cf991d422954466017dfc4020ca7563655e9ebc8713f7"
      hash191 = "faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a"
      hash192 = "fb505c8301b579bff83e77bbd9038cb583a1f207f88a04986a646ad0f9b04d09"
      hash193 = "fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7"
      hash194 = "fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e"
   strings:
      $s1 = "Menciutkan sheet bawah" fullword ascii
      $s2 = "Meluaskan sheet bawah" fullword ascii
      $s3 = "Ansa per arrossegar" fullword ascii
      $s4 = "Contrae o panel inferior" fullword ascii
      $s5 = "Desprega o panel inferior" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

