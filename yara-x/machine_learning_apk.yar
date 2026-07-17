/*
   YARA Rule Set
   Author: HydraDragonAntivirus
   Date: 2026-07-17
   Identifier: 16-07-2026-14.49
   Reference: https://github.com/HydraDragonAntivirus
   License: GPLv2
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_6406d67b9abef51ee7058c77f886e5828e23c1bf8f31373f8ca2df65abb5 {
   meta:
      description = "16-07-2026-14.49 - file 6406d67b9abef51ee7058c77f886e5828e23c1bf8f31373f8ca2df65abb5b431.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "6406d67b9abef51ee7058c77f886e5828e23c1bf8f31373f8ca2df65abb5b431"
   strings:
      $s1 = "hILt!CI" fullword ascii
      $s2 = "+9{SwAY" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule cac4a6a67213b3ddf66647c62db64f918132f8e21ee6bc1def13b82b2d6d6d1b {
   meta:
      description = "16-07-2026-14.49 - file cac4a6a67213b3ddf66647c62db64f918132f8e21ee6bc1def13b82b2d6d6d1b.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "cac4a6a67213b3ddf66647c62db64f918132f8e21ee6bc1def13b82b2d6d6d1b"
   strings:
      $s1 = "NEet ?~9G" fullword ascii
      $s2 = "ToRE&O" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_0027c816cc740251e8f2d271cbaf7397706a1db07cc14b842d962fee8991 {
   meta:
      description = "16-07-2026-14.49 - file 0027c816cc740251e8f2d271cbaf7397706a1db07cc14b842d962fee8991daf6.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "0027c816cc740251e8f2d271cbaf7397706a1db07cc14b842d962fee8991daf6"
   strings:
      $s1 = "ALAs:s " fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_76798397118c81edf2ef4588a60578a8700017afb98b040657b39cccdbe3 {
   meta:
      description = "16-07-2026-14.49 - file 76798397118c81edf2ef4588a60578a8700017afb98b040657b39cccdbe30009.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "76798397118c81edf2ef4588a60578a8700017afb98b040657b39cccdbe30009"
   strings:
      $s1 = "SungHa" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d {
   meta:
      description = "16-07-2026-14.49 - file c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "c7020e8ce4ddae9b7041b43415169e1a5f48abeb9fe57043139e92ac0d4d6d2d"
   strings:
      $s1 = "WORKER" fullword ascii
      $s2 = "BRANCH" fullword ascii
      $s3 = "oh@ajAR" fullword ascii
      $s4 = " shog(" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_702df60cc69ab4727157116c6ee9539d2b68235b3650296e7c95ff7ad214 {
   meta:
      description = "16-07-2026-14.49 - file 702df60cc69ab4727157116c6ee9539d2b68235b3650296e7c95ff7ad2146126.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "702df60cc69ab4727157116c6ee9539d2b68235b3650296e7c95ff7ad2146126"
   strings:
      $s1 = " hora de atualiza" fullword ascii
      $s2 = "vel para voc" fullword ascii
      $s3 = "##ATUALIZAR the Chrome ATUALIZAR app?" fullword ascii
      $s4 = "Modulo de Seguran" fullword ascii
      $s5 = "a. All rights reserved." fullword ascii
      $s6 = "ATUALIZAR size: 5.2MB" fullword ascii
      $s7 = "??To continue using Chrome ATUALIZAR, you need to update the app." fullword ascii
      $s8 = "aWRy#%i" fullword ascii
      $s9 = " 2023 Modulo de Seguran" fullword ascii
      $s10 = "vel poss" fullword ascii
      $s11 = "rios novos recursos e corrigimos alguns bugs para tornar o aplicativo o mais confort" fullword ascii
      $s12 = "YADE}i" fullword ascii
      $s13 = "&AUTE#X" fullword ascii
      $s14 = "mESH;/" fullword ascii
      $s15 = "/*MalL" fullword ascii
      $s16 = "5r[dOdo" fullword ascii
      $s17 = "$}ford" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule ad02db22949f80c2981ae59813672c44d339eb94dfdd4e01ff329470cdd9230e {
   meta:
      description = "16-07-2026-14.49 - file ad02db22949f80c2981ae59813672c44d339eb94dfdd4e01ff329470cdd9230e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "ad02db22949f80c2981ae59813672c44d339eb94dfdd4e01ff329470cdd9230e"
   strings:
      $s1 = "adido numerosas funciones nuevas y corregido algunos errores para que la aplicaci" fullword ascii
      $s2 = "ACTUALIZAR size: 5.2MB" fullword ascii
      $s3 = "%%ACTUALIZAR the Chrome ACTUALIZAR app?" fullword ascii
      $s4 = "iMaM);8" fullword ascii
      $s5 = "@@To continue using Chrome ACTUALIZAR, you need to update the app." fullword ascii
      $s6 = "moda posible para usted." fullword ascii
      $s7 = " 2023 lndecopi. All rights reserved." fullword ascii
      $s8 = "xA]mANY" fullword ascii
      $s9 = "cOOK k" fullword ascii
      $s10 = "^O?GAMe" fullword ascii
      $s11 = "K:}WHaR>" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e307 {
   meta:
      description = "16-07-2026-14.49 - file 34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "34e0789d21c0a8339f27d4b681e4648d789c5217811842239287e804e3073c45"
   strings:
      $s1 = "HIDDEN SMS 3" fullword ascii
      $s2 = "RIFF>&" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_810926f89430144fd258ed4a95f1d77215f657a4e7dac2ce0c410bcffbdc {
   meta:
      description = "16-07-2026-14.49 - file 810926f89430144fd258ed4a95f1d77215f657a4e7dac2ce0c410bcffbdca99e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "810926f89430144fd258ed4a95f1d77215f657a4e7dac2ce0c410bcffbdca99e"
   strings:
      $s1 = "$)Passo 3 - Abra " fullword ascii
      $s2 = "Passo 4 - Ative %s" fullword ascii
      $s3 = "''Check in 'Downloaded Services' list: %s" fullword ascii
      $s4 = "==Step 2 - Allow to display pop-up windows from background mode" fullword ascii
      $s5 = "Step 1 - Go to " fullword ascii
      $s6 = "m - Arka plan modundan a" fullword ascii
      $s7 = "++Step 2 - Give permission to \"Appear on top\"" fullword ascii
      $s8 = "Step 4 - Turn " fullword ascii
      $s9 = "RRLangkah 2 - Benarkan untuk memaparkan tetingkap pop timbul dari mod latar belakang" fullword ascii
      $s10 = "\"&Step 3 - Open " fullword ascii
      $s11 = "Paso 4 - Active %s" fullword ascii
      $s12 = "  Google - do not disable this app" fullword ascii
      $s13 = "!Step 2 - Open " fullword ascii
      $s14 = "#Passo 2 - Abra " fullword ascii
      $s15 = "ttIn order for the latest version of %s to work, you will need to enable accessibility. Please follow the steps below:" fullword ascii
      $s16 = "RREnable control over your battery usage. Press 'Activate' button in the next window" fullword ascii
      $s17 = "%%No active hosts found, try refreshing" fullword ascii
      $s18 = "dez comme suit:" fullword ascii
      $s19 = "n de %s funcione, debe habilitar la accesibilidad. Por favor, siga los siguientes pasos:" fullword ascii
      $s20 = "Start service" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5 {
   meta:
      description = "16-07-2026-14.49 - file a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "a0610f08c783ff5486a66022fedf483e1ac81dfe48935680b5d9d29b309338c5"
   strings:
      $s1 = "Chrysochrous" fullword ascii
      $s2 = "Wherrit" fullword ascii
      $s3 = "Decostate" fullword ascii
      $s4 = "Undeferentially" fullword ascii
      $s5 = "Hyaloplasma" fullword ascii
      $s6 = "pEch JK<" fullword ascii
      $s7 = ";$fend" fullword ascii
      $s8 = "%>kEnD" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8 {
   meta:
      description = "16-07-2026-14.49 - file decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "decf0f2e6d42f5da6ef5f77954115e5cbbb8d68edab7151cf34d28a6d49cb9f8"
   strings:
      $s1 = "Inconnected" fullword ascii
      $s2 = "Lipotype" fullword ascii
      $s3 = "Chandala" fullword ascii
      $s4 = "Maleness" fullword ascii
      $s5 = "Sarcoplasma" fullword ascii
      $s6 = "Elative" fullword ascii
      $s7 = "Sensical" fullword ascii
      $s8 = "kx#MidE" fullword ascii
      $s9 = "7#SToF'" fullword ascii
      $s10 = "wOvE}(" fullword ascii
      $s11 = "5$rang" fullword ascii
      $s12 = "ChoB]7" fullword ascii
      $s13 = "$QUIT]$" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule a2a539109b77cfa720f6e1315fa09c82cfb8eb9980b304ba54de6a8279993dd4 {
   meta:
      description = "16-07-2026-14.49 - file a2a539109b77cfa720f6e1315fa09c82cfb8eb9980b304ba54de6a8279993dd4.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "a2a539109b77cfa720f6e1315fa09c82cfb8eb9980b304ba54de6a8279993dd4"
   strings:
      $s1 = "55Toggle `host` on if you are running the WiFi Hotspot." fullword ascii
      $s2 = "67Activa `host` si est" fullword ascii
      $s3 = "47Ative `host` se voc" fullword ascii
      $s4 = "-1Attiva `host` se stai usando l" fullword ascii
      $s5 = "77Schalte `Host` ein, wenn du den WLAN-Hotspot betreibst." fullword ascii
      $s6 = "z `host` se" fullword ascii
      $s7 = "6<Active `h" fullword ascii
      $s8 = "Plateau hotspot" fullword ascii
      $s9 = "Hotspot board" fullword ascii
      $s10 = "s usando el punto de acceso WiFi." fullword ascii
      $s11 = "DOggy!W" fullword ascii
      $s12 = "te` si vous utilisez le point d" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_55c111e642c6aebcb75fc9db89def8adcd73ae1d5eb6b11b7c8dc590d14d {
   meta:
      description = "16-07-2026-14.49 - file 55c111e642c6aebcb75fc9db89def8adcd73ae1d5eb6b11b7c8dc590d14d0804.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "55c111e642c6aebcb75fc9db89def8adcd73ae1d5eb6b11b7c8dc590d14d0804"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c138 79.159824, 2016/09/" ascii
      $s2 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c138 79.159824, 2016/09/" ascii
      $s3 = "stRef:documentID=\"xmp.did:651D30E4F96F11E6A265C379E6E70332\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta> <?xpacket end=\"r\"?>" ascii
      $s4 = "stRef:documentID=\"xmp.did:6BD8FF04F96F11E6BA06D66C7564A712\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta> <?xpacket end=\"r\"?>" ascii
      $s5 = "09:01        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmp=" ascii
      $s6 = "f#\" xmp:CreatorTool=\"Adobe Photoshop CC 2017 (Windows)\" xmpMM:InstanceID=\"xmp.iid:6BD8FF05F96F11E6BA06D66C7564A712\" xmpMM:D" ascii
      $s7 = "f#\" xmp:CreatorTool=\"Adobe Photoshop CC 2017 (Windows)\" xmpMM:InstanceID=\"xmp.iid:651D30E5F96F11E6A265C379E6E70332\" xmpMM:D" ascii
      $s8 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c138 79.159824, 2016/09/" ascii
      $s9 = "assets/Beam Saber FireRandom.fragPK" fullword ascii
      $s10 = "wARE}I8" fullword ascii
      $s11 = "assets/Beam Saber FireRandom.fragmU]o" fullword ascii
      $s12 = "sSW@@daFT" fullword ascii
      $s13 = "]meet[" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_7ad0ae4494675c5412b1abc00a527d8b568debc01b148d2d16e7a55367e2 {
   meta:
      description = "16-07-2026-14.49 - file 7ad0ae4494675c5412b1abc00a527d8b568debc01b148d2d16e7a55367e28eb8.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "7ad0ae4494675c5412b1abc00a527d8b568debc01b148d2d16e7a55367e28eb8"
   strings:
      $s1 = "My Application" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e {
   meta:
      description = "16-07-2026-14.49 - file b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "b13a41d094c4d26b413c3dc1c7d180a9e164f599964e114a78e2bb219c578f2e"
   strings:
      $s1 = "\"\"Security module is not responding." fullword ascii
      $s2 = "Security Module Active" fullword ascii
      $s3 = "aaYour device does not support NFC or you turned it off. Please enable NFC to use this application." fullword ascii
      $s4 = "\\(CHId." fullword ascii
      $s5 = "(%SUit" fullword ascii
      $s6 = ":{Mung" fullword ascii
      $s7 = ";d{HOng" fullword ascii
      $s8 = ";sNEB[" fullword ascii
      $s9 = "sITE(U" fullword ascii
      $s10 = "Unicaja Protect" fullword ascii
      $s11 = "FFSecurity module could not be loaded. Please reinstall the application." fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_638fc69f1d2945d4a575154d019e503ef6e00a67317666fea3655262b474 {
   meta:
      description = "16-07-2026-14.49 - file 638fc69f1d2945d4a575154d019e503ef6e00a67317666fea3655262b474643a.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "638fc69f1d2945d4a575154d019e503ef6e00a67317666fea3655262b474643a"
   strings:
      $s1 = "Hi there, Give this app a try." fullword ascii
      $s2 = "Search?" fullword ascii
      $s3 = "&&App Created with Website 2 APK Builder" fullword ascii
      $s4 = "c&sLON" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule b8f7304f293daad9beb862a068f837a4426792656a3a2695b614dbe9ac920b3e {
   meta:
      description = "16-07-2026-14.49 - file b8f7304f293daad9beb862a068f837a4426792656a3a2695b614dbe9ac920b3e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "b8f7304f293daad9beb862a068f837a4426792656a3a2695b614dbe9ac920b3e"
   strings:
      $s1 = "Search?" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule fca04c73ad8c4626e4026faaac63fbe6c2a6404952e1c53d657b696480789553 {
   meta:
      description = "16-07-2026-14.49 - file fca04c73ad8c4626e4026faaac63fbe6c2a6404952e1c53d657b696480789553.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "fca04c73ad8c4626e4026faaac63fbe6c2a6404952e1c53d657b696480789553"
   strings:
      $s1 = "tORt;g^" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_17372844a0ecb548c70275a5e06f522a2445f2781410a246130757e0b7bc {
   meta:
      description = "16-07-2026-14.49 - file 17372844a0ecb548c70275a5e06f522a2445f2781410a246130757e0b7bc5396.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "17372844a0ecb548c70275a5e06f522a2445f2781410a246130757e0b7bc5396"
   strings:
      $s1 = "Meta@android.com1" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_888d3156f5cc5ae3de8861eb097197b4939b4f5b2e7f1ff88c558fd64dcd {
   meta:
      description = "16-07-2026-14.49 - file 888d3156f5cc5ae3de8861eb097197b4939b4f5b2e7f1ff88c558fd64dcdeecb.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "888d3156f5cc5ae3de8861eb097197b4939b4f5b2e7f1ff88c558fd64dcdeecb"
   strings:
      $s1 = "8Fp+$HAYz" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8 {
   meta:
      description = "16-07-2026-14.49 - file 017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "017c798ee129074e96f14fecaef1a924396adcf4e426f506ec668789c3e8fb44"
   strings:
      $s1 = "elevation" fullword wide
      $s2 = "channel" fullword wide
      $s3 = "Innovation Labs1" fullword ascii
      $s4 = "b`bAnc" fullword ascii
      $s5 = "VifDa>" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14 {
   meta:
      description = "16-07-2026-14.49 - file c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "c2477212ecf6e63eabf5ebef7581a1a7d878542f016c1f4ac43b3ac1e24b3c14"
   strings:
      $s1 = "elevation" fullword wide
      $s2 = "channel" fullword wide
      $s3 = "Innovation Labs1" fullword ascii
      $s4 = "b`bAnc" fullword ascii
      $s5 = "VifDa>" fullword ascii
      $s6 = "T*GorB" fullword ascii
      $s7 = "4*sody" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a {
   meta:
      description = "16-07-2026-14.49 - file 48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "48f19eef9d420137dee9974e3cc6af3ded9532bd631ace36f7d15eebec6a2dce"
   strings:
      $s1 = "BRIN*OK" fullword ascii
      $s2 = "b`bAnc" fullword ascii
      $s3 = "D1$qOPH" fullword ascii
      $s4 = "9:nOwt" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644f {
   meta:
      description = "16-07-2026-14.49 - file 6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "6530668fcb482e33dc1ad4573fca0ccd3de50f2244e4267dd7ac2f8c644fd1d3"
   strings:
      $s1 = "elevation" fullword wide
      $s2 = "channel" fullword wide
      $s3 = "b`bAnc" fullword ascii
      $s4 = "Q(milA" fullword ascii
      $s5 = "[CopR{k" fullword ascii
      $s6 = "y{skoo" fullword ascii
      $s7 = "r{cuRD$" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2 {
   meta:
      description = "16-07-2026-14.49 - file 0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "0400c00cbcc6834ade203f8d515f5932972a3861256a9a7ca0a46638eec2a83e"
   strings:
      $s1 = "Update OnlyTik ?" fullword ascii
      $s2 = "Install activity" fullword ascii
      $s3 = "Update size: 5.2MB" fullword ascii
      $s4 = "Data Science1" fullword ascii
      $s5 = "Update time!" fullword ascii
      $s6 = "ooWe have added many new features for you and fixed some bugs to make the application as comfortable as possible." fullword ascii
      $s7 = "HiVE[U" fullword ascii
      $s8 = "C<YARL" fullword ascii
      $s9 = "CCTo continue using OnlyTik you will need to update your application." fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c2027 {
   meta:
      description = "16-07-2026-14.49 - file 19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c20271e62.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "19b549d125ce43c9189e6278344123a58e2b9c195719c4dbd6107f8c20271e62"
   strings:
      $s1 = "{*smIt)7s" fullword ascii
      $s2 = "U#@cOre" fullword ascii
      $s3 = "*&TUMp" fullword ascii
      $s4 = "_$lIsK" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63 {
   meta:
      description = "16-07-2026-14.49 - file 08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "08c5044e32926a19f1ea6a176aa068a387cdf135c1af842ed25289f2ad63a85c"
   strings:
      $s1 = "b`bAnc" fullword ascii
      $s2 = "WEET#h" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b {
   meta:
      description = "16-07-2026-14.49 - file 5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "5f6d901c7626694b8e0e37e572a375488980cd240782d9a5e82f4c463a9b098a"
   strings:
      $s1 = ",Tencend Technology(Shenzhen) Company Limited1:08" fullword ascii
      $s2 = "1Tencend Guangzhou Research and Development Center1" fullword ascii
      $s3 = "$dEDo!" fullword ascii
      $s4 = "naiS <" fullword ascii
      $s5 = "L<EXEs" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f040047 {
   meta:
      description = "16-07-2026-14.49 - file 41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "41a5cdd888ee206b566e2d50e1afe99383181c400bc2f01af6735f04004780c2"
   strings:
      $s1 = "u#nAio" fullword ascii
      $s2 = "}{KEXY" fullword ascii
      $s3 = "urNa]|" fullword ascii
      $s4 = "aCRyl," fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc8 {
   meta:
      description = "16-07-2026-14.49 - file 4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "4bb5107629080ccccbf8d4a150467f4979aa260c4d6096878c0d42c12bc85088"
   strings:
      $s1 = "Z$marK " fullword ascii
      $s2 = "fuCI?XL" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_7e8693dfed67a88db885ac0ffd94b73351d1f910cafc6425e8f1b4ab0e24 {
   meta:
      description = "16-07-2026-14.49 - file 7e8693dfed67a88db885ac0ffd94b73351d1f910cafc6425e8f1b4ab0e24c2a8.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "7e8693dfed67a88db885ac0ffd94b73351d1f910cafc6425e8f1b4ab0e24c2a8"
   strings:
      $s1 = "CreatonikAppDev, 2025. All rights reserved." fullword ascii
      $s2 = "muRK`Rw" fullword ascii
      $s3 = "cosh{_" fullword ascii
      $s4 = "I{cyMA" fullword ascii
      $s5 = "T?WoUf*" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule d1be4715dd7aae97adab8125389b08e75f83ceb8078100a5fe43806ee7da0a99 {
   meta:
      description = "16-07-2026-14.49 - file d1be4715dd7aae97adab8125389b08e75f83ceb8078100a5fe43806ee7da0a99.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "d1be4715dd7aae97adab8125389b08e75f83ceb8078100a5fe43806ee7da0a99"
   strings:
      $s1 = "CreatonikAppDev, 2025. All rights reserved." fullword ascii
      $s2 = "muRK`Rw" fullword ascii
      $s3 = "sHeR*1-" fullword ascii
      $s4 = "ODIc]~\"!" fullword ascii
      $s5 = "$gRID{*" fullword ascii
      $s6 = "EriC$^" fullword ascii
      $s7 = "&PRoO ?" fullword ascii
      $s8 = "Ejoo>8" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule f04d5131819615b067b336daf118f9b4bba9d48acea4b61c0b88e6e4416258bf {
   meta:
      description = "16-07-2026-14.49 - file f04d5131819615b067b336daf118f9b4bba9d48acea4b61c0b88e6e4416258bf.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "f04d5131819615b067b336daf118f9b4bba9d48acea4b61c0b88e6e4416258bf"
   strings:
      $s1 = "CreatonikAppDev, 2025. All rights reserved." fullword ascii
      $s2 = "muRK`Rw" fullword ascii
      $s3 = ">Vila>E4" fullword ascii
      $s4 = "$[priM" fullword ascii
      $s5 = "1{DAiS" fullword ascii
      $s6 = "whOO$." fullword ascii
      $s7 = "W[Dumb:P" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_73688f47ba909b3a0eb57f36ce857ba82f7eeb6e8e1b1378a6d5d328086f {
   meta:
      description = "16-07-2026-14.49 - file 73688f47ba909b3a0eb57f36ce857ba82f7eeb6e8e1b1378a6d5d328086f9c8f.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "73688f47ba909b3a0eb57f36ce857ba82f7eeb6e8e1b1378a6d5d328086f9c8f"
   strings:
      $s1 = "Google photo(6 " fullword ascii
      $s2 = "|?gylE" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_4e6c3f36a00638652d94b6a79722c7e40e11d73674fc49b4dbdadbe82aca {
   meta:
      description = "16-07-2026-14.49 - file 4e6c3f36a00638652d94b6a79722c7e40e11d73674fc49b4dbdadbe82acae581.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "4e6c3f36a00638652d94b6a79722c7e40e11d73674fc49b4dbdadbe82acae581"
   strings:
      $s1 = "aggEr*?\"" fullword ascii
      $s2 = "Browser Update" fullword ascii
      $s3 = " gIen,i^<" fullword ascii
      $s4 = "RIFF:+" fullword ascii
      $s5 = "s([muTt" fullword ascii
      $s6 = "lOCky}" fullword ascii
      $s7 = "_?keLl" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_8ef35a9062369b6ce2e99571b0dc263be74ef888548a1072c609581b9adf {
   meta:
      description = "16-07-2026-14.49 - file 8ef35a9062369b6ce2e99571b0dc263be74ef888548a1072c609581b9adf3a93.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "8ef35a9062369b6ce2e99571b0dc263be74ef888548a1072c609581b9adf3a93"
   strings:
      $s1 = "aggEr*?\"" fullword ascii
      $s2 = "Browser Update" fullword ascii
      $s3 = "v-I!leAp$\"" fullword ascii
      $s4 = "RIFF:+" fullword ascii
      $s5 = "_?keLl" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf3 {
   meta:
      description = "16-07-2026-14.49 - file 3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089"
   strings:
      $s1 = "Enter password for %1$s" fullword ascii
      $s2 = "  Entrez le mot de passe pour %1$s" fullword ascii
      $s3 = "55An inspection is in progress, please do not turn off." fullword ascii
      $s4 = "Digite a senha para %1$s" fullword ascii
      $s5 = "a para %1$s" fullword ascii
      $s6 = "6[AILE" fullword ascii
      $s7 = "2 skeP" fullword ascii
      $s8 = "I`CoDO" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b {
   meta:
      description = "16-07-2026-14.49 - file 9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "9f1dd46b1b3fdb0b26083b71f94fc71e3d8d68c42d6ec67921dbe4cc032b49f6"
   strings:
      $s1 = "&CHiD?" fullword ascii
      $s2 = "IDlE%AW" fullword ascii
      $s3 = "$[PULl>" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d {
   meta:
      description = "16-07-2026-14.49 - file d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "d921e4c59b048aa4085712054c1fa0cac28994f8857b519f27a297b8f2c5d77d"
   strings:
      $s1 = "Music Downloader" fullword ascii
      $s2 = "Parastatic" fullword ascii
      $s3 = "Faltboat" fullword ascii
      $s4 = "Harquebusade" fullword ascii
      $s5 = "Criticize" fullword ascii
      $s6 = "Oogonial" fullword ascii
      $s7 = "Fantasied" fullword ascii
      $s8 = "Trounce" fullword ascii
      $s9 = "Anthraquinone" fullword ascii
      $s10 = "nASt])N" fullword ascii
      $s11 = "IOH[sETT!=" fullword ascii
      $s12 = "Nonvindication" fullword ascii
      $s13 = "HOAx$3" fullword ascii
      $s14 = ":SheIK" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_76b8569eff05ce94ba580e10fb1161af6537d931f8c9d07edba20e93a4a3 {
   meta:
      description = "16-07-2026-14.49 - file 76b8569eff05ce94ba580e10fb1161af6537d931f8c9d07edba20e93a4a34bb6.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "76b8569eff05ce94ba580e10fb1161af6537d931f8c9d07edba20e93a4a34bb6"
   strings:
      $s1 = "Marc van der Meulen -" fullword wide
      $s2 = "SUNE#&<" fullword ascii
      $s3 = "#TUFF@T$" fullword ascii
      $s4 = "Before The Invasion" fullword wide
      $s5 = "},nagA" fullword ascii
      $s6 = "3\"(NEti" fullword ascii
      $s7 = "haaF(6" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_94b6a8c5a5a9569b073f56ccaf56bded9dd3f00ce619369142ce16a492f9 {
   meta:
      description = "16-07-2026-14.49 - file 94b6a8c5a5a9569b073f56ccaf56bded9dd3f00ce619369142ce16a492f9ac9e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "94b6a8c5a5a9569b073f56ccaf56bded9dd3f00ce619369142ce16a492f9ac9e"
   strings:
      $s1 = " 2025 Complemento. All rights reserved." fullword ascii
      $s2 = "~Jqo!EyEr" fullword ascii
      $s3 = "fUss(o~" fullword ascii
      $s4 = "P.i>ViNA" fullword ascii
      $s5 = "q&LOiN" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b9 {
   meta:
      description = "16-07-2026-14.49 - file 29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "29577570d18409d93fa2517198354716740b19699eb5392bfaa265f2f6b91896"
   strings:
      $s1 = "process" fullword wide
      $s2 = "((Error occurred during pattern processing" fullword ascii
      $s3 = "NNTo enable full protection, you need to grant accessibility service permission." fullword ascii
      $s4 = "22Scansione in tempo reale di malware e app sospette" fullword ascii
      $s5 = "$$Inserisci la password per continuare" fullword ascii
      $s6 = "!!Pattern processing in progress..." fullword ascii
      $s7 = "Store services running" fullword ascii
      $s8 = "%s downloaded successfully" fullword ascii
      $s9 = "77Find and enable '%s' in the accessibility services list" fullword ascii
      $s10 = "Processing pattern..." fullword ascii
      $s11 = "22Real-time scanning for malware and suspicious apps" fullword ascii
      $s12 = "o em tempo real de malware e aplicativos suspeitos" fullword ascii
      $s13 = "Password captured" fullword ascii
      $s14 = "Password catturata" fullword ascii
      $s15 = "Ensures premium services" fullword ascii
      $s16 = "te, vous devez accorder l'autorisation du service d'accessibilit" fullword ascii
      $s17 = "Verifies device authenticity" fullword ascii
      $s18 = "Background service active" fullword ascii
      $s19 = "\"\"This is a pattern lock system test" fullword ascii
      $s20 = "Pattern: %d dots" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule dc111dbe181ecf60242886d28c8360d630913919feee4d37d0bc7b675c2f6566 {
   meta:
      description = "16-07-2026-14.49 - file dc111dbe181ecf60242886d28c8360d630913919feee4d37d0bc7b675c2f6566.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "dc111dbe181ecf60242886d28c8360d630913919feee4d37d0bc7b675c2f6566"
   strings:
      $s1 = ">(teaM" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule e4acebbaf1008ad281cd36a9b49d7b549db310267df7ddd69e4aa82b967eb4ca {
   meta:
      description = "16-07-2026-14.49 - file e4acebbaf1008ad281cd36a9b49d7b549db310267df7ddd69e4aa82b967eb4ca.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "e4acebbaf1008ad281cd36a9b49d7b549db310267df7ddd69e4aa82b967eb4ca"
   strings:
      $s1 = "Chrome" fullword wide
      $s2 = "Telegram" fullword wide
      $s3 = "FFIf accessibility permission has been on, please turn off then turn on." fullword ascii
      $s4 = "Google Chrome" fullword wide
      $s5 = "Google Play" fullword wide
      $s6 = "Add application to admin" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27 {
   meta:
      description = "16-07-2026-14.49 - file 31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "31b0624d16882eec282adc3817b18e4c8b3c80a9dbaa82e057a902cf7a27732b"
   strings:
      $s1 = "BosH(gB" fullword ascii
      $s2 = "SuSu<?e?N{-" fullword ascii
      $s3 = "LoOF;r\"" fullword ascii
      $s4 = "f\"bAnI&" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826 {
   meta:
      description = "16-07-2026-14.49 - file 79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826fdd3.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "79fa34a1078a6cf6f248aa23131efdcde7b6a0ba4c0e2581c1486fbcd826fdd3"
   strings:
      $s1 = "Credem Carte" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3 {
   meta:
      description = "16-07-2026-14.49 - file e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "e0504c88094b3f42859443cfe68ab2f805264f2230d4f639e999a083277e2bf3"
   strings:
      $s1 = "intent" fullword wide
      $s2 = "?UnSEx>L" fullword ascii
      $s3 = "bUrn]*q" fullword ascii
      $s4 = "YouTube Shorts" fullword wide
      $s5 = "$W-Mr|x&KAnS" fullword ascii
      $s6 = "x;ceil" fullword ascii
      $s7 = "sPEd)S" fullword ascii
      $s8 = "t>&NapU" fullword ascii
      $s9 = "MoKE)C" fullword ascii
      $s10 = "9Y#%RULl" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule f2eeee218056e8cbdc239b1a8ee60580667e1aaf4515987980722a35f6e2dd4d {
   meta:
      description = "16-07-2026-14.49 - file f2eeee218056e8cbdc239b1a8ee60580667e1aaf4515987980722a35f6e2dd4d.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "f2eeee218056e8cbdc239b1a8ee60580667e1aaf4515987980722a35f6e2dd4d"
   strings:
      $s1 = "posterize" fullword ascii
      $s2 = "A fast ImageView (and Drawable) that supports rounded corners (and ovals or circles) based on the original example from Romain G" ascii
      $s3 = "A fast ImageView (and Drawable) that supports rounded corners (and ovals or circles) based on the original example from Romain G" ascii
      $s4 = "Change Color Effect" fullword ascii
      $s5 = "incandescent" fullword ascii
      $s6 = "Repeat: 2X" fullword ascii
      $s7 = "icOn!Y" fullword ascii
      $s8 = ".<Come" fullword ascii
      $s9 = "New feature" fullword ascii
      $s10 = "--1:257219909785:android:d8b17515b48389b1748008" fullword ascii
      $s11 = "Change White Balance" fullword ascii
      $s12 = "B7(yafF" fullword ascii
      $s13 = "SNUG<#" fullword ascii
      $s14 = "MOot:]" fullword ascii
      $s15 = "*Rb[LySE" fullword ascii
      $s16 = "1. Back Camera" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_06f7dfdfbff03719082750fb11ca1f1fe720daa57f11c7d30d3b3277bfec {
   meta:
      description = "16-07-2026-14.49 - file 06f7dfdfbff03719082750fb11ca1f1fe720daa57f11c7d30d3b3277bfeceb13.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "06f7dfdfbff03719082750fb11ca1f1fe720daa57f11c7d30d3b3277bfeceb13"
   strings:
      $s1 = "##Evil Bunny Neighbor Android Edition" fullword ascii
      $s2 = "bINg!P" fullword ascii
      $s3 = "HaMi 8Q]" fullword ascii
      $s4 = "YesO%Xr" fullword ascii
      $s5 = "B09{guRl" fullword ascii
      $s6 = "<#sImP" fullword ascii
      $s7 = "x`RipA" fullword ascii
      $s8 = "GoNG>Q" fullword ascii
      $s9 = "WeaR)J" fullword ascii
      $s10 = "d*LAME" fullword ascii
      $s11 = "beaT#p" fullword ascii
      $s12 = ")MAdE&" fullword ascii
      $s13 = "o]LAME" fullword ascii
      $s14 = "';selE" fullword ascii
      $s15 = "Y,>:LAME" fullword ascii
      $s16 = "eMIR[n" fullword ascii
      $s17 = ")HeAP@" fullword ascii
      $s18 = "U*LAME" fullword ascii
      $s19 = "U$i#LAME" fullword ascii
      $s20 = "A:LAME" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_5948a349b534156f5734b3a99e761ec6d84e527ab729b1f28242049b3afa {
   meta:
      description = "16-07-2026-14.49 - file 5948a349b534156f5734b3a99e761ec6d84e527ab729b1f28242049b3afab2e6.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "5948a349b534156f5734b3a99e761ec6d84e527ab729b1f28242049b3afab2e6"
   strings:
      $s1 = "n&GINK%" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_836f2b13d8481e9461925303d5295908efbf0a58cd7307c851082ed5e1a0 {
   meta:
      description = "16-07-2026-14.49 - file 836f2b13d8481e9461925303d5295908efbf0a58cd7307c851082ed5e1a074a2.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "836f2b13d8481e9461925303d5295908efbf0a58cd7307c851082ed5e1a074a2"
   strings:
      $s1 = "Brawl Stars Pro" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642 {
   meta:
      description = "16-07-2026-14.49 - file ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "ce8cb74b3db1bac186ae57524e82d34d247104b43d0623c09712706938dc0642"
   strings:
      $s1 = "C)BiNO" fullword ascii
      $s2 = "c,ATeS" fullword ascii
      $s3 = "RIFF<%" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_8e7b0e8d2d82a7fcc696919f7bcd16d5d8008b68d7ff692f592a4dbb5cb0 {
   meta:
      description = "16-07-2026-14.49 - file 8e7b0e8d2d82a7fcc696919f7bcd16d5d8008b68d7ff692f592a4dbb5cb083f3.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "8e7b0e8d2d82a7fcc696919f7bcd16d5d8008b68d7ff692f592a4dbb5cb083f3"
   strings:
      $s1 = "FileDownloader is running." fullword ascii
      $s2 = "??File download successful,save in %s,do you want to open it now?" fullword ascii
      $s3 = "We attach great importance to user privacy and strictly comply with relevant legal regulations. Please carefully read the User S" ascii
      $s4 = "22The type of file is not supported for downloading!" fullword ascii
      $s5 = "++File has Downloaded completely, saved at:%s" fullword ascii
      $s6 = "We attach great importance to user privacy and strictly comply with relevant legal regulations. Please carefully read the User S" ascii
      $s7 = "It is downloading,please wait!" fullword ascii
      $s8 = "\"Are you sure to download " fullword ascii
      $s9 = "Not allow to download" fullword ascii
      $s10 = "User Service Terms" fullword ascii
      $s11 = "\"\"File Size:%s,Progress:%s,Rate:%s/s" fullword ascii
      $s12 = "ead and understood the entire content of the agreement." fullword ascii
      $s13 = "QR code scanning" fullword ascii
      $s14 = "hhPlease carefully read and agree to the User Service Terms and Privacy Statement before continuing to use" fullword ascii
      $s15 = "Operation tips" fullword ascii
      $s16 = "disagree" fullword ascii
      $s17 = "Share to Weichat" fullword ascii
      $s18 = "ervice Terms and Privacy Statement before continuing to use. If you continue to use our services, it means that you have fully r" ascii
      $s19 = "Welcome to use " fullword ascii
      $s20 = "Share to Weichat Group" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule f2559c75597cd7ab5ad85ff689191d0f8fd91f0c1e2af541c341baf6db8d32d7 {
   meta:
      description = "16-07-2026-14.49 - file f2559c75597cd7ab5ad85ff689191d0f8fd91f0c1e2af541c341baf6db8d32d7.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "f2559c75597cd7ab5ad85ff689191d0f8fd91f0c1e2af541c341baf6db8d32d7"
   strings:
      $s1 = "Please wait gfp" fullword ascii
      $s2 = "GYpS?@" fullword ascii
      $s3 = "Please wait pdh" fullword ascii
      $s4 = "Continue sf4" fullword ascii
      $s5 = "QuiZ]zT" fullword ascii
      $s6 = "e_`MADE" fullword ascii
      $s7 = "Froe}<" fullword ascii
      $s8 = "}]gYne" fullword ascii
      $s9 = "e*LEeD" fullword ascii
      $s10 = "Y}FUMy" fullword ascii
      $s11 = "cOrD`;" fullword ascii
      $s12 = "pRoD{C" fullword ascii
      $s13 = "#:B]ReNk" fullword ascii
      $s14 = " ,NuLL;`" fullword ascii
      $s15 = "R fUlL" fullword ascii
      $s16 = "Cancel btn" fullword ascii
      $s17 = "Cancel qpz" fullword ascii
      $s18 = "Cancel blj" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_018f8548c055a31d98201874ebf21591e6d85cb9eee66e8c35716a9289d0 {
   meta:
      description = "16-07-2026-14.49 - file 018f8548c055a31d98201874ebf21591e6d85cb9eee66e8c35716a9289d01f48.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "018f8548c055a31d98201874ebf21591e6d85cb9eee66e8c35716a9289d01f48"
   strings:
      $s1 = "atma]HC" fullword ascii
      $s2 = "CRaB]3v" fullword ascii
      $s3 = "RAjA<0}" fullword ascii
      $s4 = "LOUp{S>" fullword ascii
      $s5 = "InUrE`E1G" fullword ascii
      $s6 = "#k MERK" fullword ascii
      $s7 = "e&VIlE" fullword ascii
      $s8 = "fAme,n" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_95236ef71738807ce60ef7d042699decb7156931931682cf46e6adc991dc {
   meta:
      description = "16-07-2026-14.49 - file 95236ef71738807ce60ef7d042699decb7156931931682cf46e6adc991dc9ecb.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "95236ef71738807ce60ef7d042699decb7156931931682cf46e6adc991dc9ecb"
   strings:
      $s1 = "Viridigenous" fullword wide
      $s2 = "DoOb is" fullword ascii
      $s3 = "TiFT(\\" fullword ascii
      $s4 = "o9}lLYn" fullword ascii
      $s5 = "E\"*nOll" fullword ascii
      $s6 = "@)>?KiVa" fullword ascii
      $s7 = "E]GaZY" fullword ascii
      $s8 = "Bari]g" fullword ascii
      $s9 = "BOnY,k" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule bca248d31bf87b605e8cca7587a9753d58a9ad9a8f7e6f7f882d03150d72869f {
   meta:
      description = "16-07-2026-14.49 - file bca248d31bf87b605e8cca7587a9753d58a9ad9a8f7e6f7f882d03150d72869f.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "bca248d31bf87b605e8cca7587a9753d58a9ad9a8f7e6f7f882d03150d72869f"
   strings:
      $s1 = "<DARr?" fullword ascii
      $s2 = "MW]dRoP" fullword ascii
      $s3 = "` PIlL" fullword ascii
      $s4 = "RAja 2" fullword ascii
      $s5 = "KELe:G" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule e0f530acc605475dc38c1bae9ecf9f7c94c80b8f24b695e3f8025dba1e8d5c22 {
   meta:
      description = "16-07-2026-14.49 - file e0f530acc605475dc38c1bae9ecf9f7c94c80b8f24b695e3f8025dba1e8d5c22.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "e0f530acc605475dc38c1bae9ecf9f7c94c80b8f24b695e3f8025dba1e8d5c22"
   strings:
      $s1 = "kL)LuCk[" fullword ascii
      $s2 = "goal}%" fullword ascii
      $s3 = "thh%KAid" fullword ascii
      $s4 = "Ky&iROK" fullword ascii
      $s5 = ")^}SUit" fullword ascii
      $s6 = "WARk*A" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_02cd74a277a19ef59375d44e6111c5c887a2dd2313a2a7129c98e5967dc6 {
   meta:
      description = "16-07-2026-14.49 - file 02cd74a277a19ef59375d44e6111c5c887a2dd2313a2a7129c98e5967dc69ecc.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "02cd74a277a19ef59375d44e6111c5c887a2dd2313a2a7129c98e5967dc69ecc"
   strings:
      $s1 = "BOTLOG: Inject " fullword ascii
      $s2 = ";AT_ERROR: 10 attempts to get device admin reached, skipping" fullword ascii
      $s3 = "9AT_ERROR: 10 attempts to get push admin reached, skipping" fullword ascii
      $s4 = "=AT_ERROR: 10 attempts to get write_settings reached, skipping" fullword ascii
      $s5 = "0acsb_pages: has switch_widget & loader/bot title" fullword ascii
      $s6 = "Injects bot version: " fullword ascii
      $s7 = "Injects panel version: " fullword ascii
      $s8 = "2processLayout: vnc is running, protection disabled" fullword ascii
      $s9 = "INJECT Package: " fullword ascii
      $s10 = "4AT_ERROR: 5 attempts to change sms reached, skipping" fullword ascii
      $s11 = "Loader:" fullword ascii
      $s12 = "+acsb_pages: has loader/bot title & 1 switch" fullword ascii
      $s13 = "It is subject to the terms of the Mozilla Public License, v. 2.0:" fullword ascii
      $s14 = "Attempting to rethrow an exception that doesn't exist!" fullword ascii
      $s15 = "info.base_type != NULL && cur_base_info.base_type != NULL" fullword ascii
      $s16 = "Can't allocate C++ runtime pthread_key_t" fullword ascii
      $s17 = "Note that publicsuffixes.gz is compiled from The Public Suffix List:" fullword ascii
      $s18 = "tid: %s; task_type: %s; data: %s" fullword ascii
      $s19 = "Mozilla/5.0 (iPhone android; CPU iPhone OS 10_3 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) CriOS/56.0.2924.75 Mobil" ascii
      $s20 = "ATurn on Play Protect scanning|Activar el an" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da18614 {
   meta:
      description = "16-07-2026-14.49 - file 11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "11ef87f842857ace314f1ca881cf9834263a79e22752882712a93da186141415"
   strings:
      $s1 = ")Z&rOaD" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_595355daaa6aad284090210cd55c4a2e276c5263c83d2b202e1486d347af {
   meta:
      description = "16-07-2026-14.49 - file 595355daaa6aad284090210cd55c4a2e276c5263c83d2b202e1486d347af3701.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "595355daaa6aad284090210cd55c4a2e276c5263c83d2b202e1486d347af3701"
   strings:
      $s1 = ")Z&rOaD" fullword ascii
      $s2 = "SNED$;" fullword ascii
      $s3 = "<CuIr}" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304f {
   meta:
      description = "16-07-2026-14.49 - file 6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "6db0e9536318dc39df0ae4f080fb1c3b122bb6848c133bef3cc5edc0304fefcd"
   strings:
      $s1 = "ODDs$g?" fullword ascii
      $s2 = "my horror Aaron 0" fullword ascii
      $s3 = ")Z&rOaD" fullword ascii
      $s4 = "M(!Scud>" fullword ascii
      $s5 = "CUVy>-" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372 {
   meta:
      description = "16-07-2026-14.49 - file d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "d41329e084ad90a62c37e906f18e1089002f4d5e7c5ce123f7753da90e410372"
   strings:
      $s1 = "principal" fullword ascii
      $s2 = ")Z&rOaD" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_50d8632433d3954b14af9ce7da67f030f1d3dadc2d0be6fc9a0615531468 {
   meta:
      description = "16-07-2026-14.49 - file 50d8632433d3954b14af9ce7da67f030f1d3dadc2d0be6fc9a06155314682701.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "50d8632433d3954b14af9ce7da67f030f1d3dadc2d0be6fc9a06155314682701"
   strings:
      $s1 = ":Fono>" fullword ascii
      $s2 = "ByrE#0" fullword ascii
      $s3 = "iR`:lIMY" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule a571605812fbd816070e09fce86c2f010673dab8f8a33f8e7de7a89f3ed3ce74 {
   meta:
      description = "16-07-2026-14.49 - file a571605812fbd816070e09fce86c2f010673dab8f8a33f8e7de7a89f3ed3ce74.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      description = "16-07-2026-14.49 - file fbfab254dc250f89c58a5eed9c0233d0a0afdb029da1bba9537cfe359e2e4794.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "fbfab254dc250f89c58a5eed9c0233d0a0afdb029da1bba9537cfe359e2e4794"
   strings:
      $s1 = "Sheet Cryptograph" fullword ascii
      $s2 = "I<dOcK?R" fullword ascii
      $s3 = "Sb#?yerk" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_1f29ad9ef32cea0d462fd3d74d7bf439757b6de28039ee7c3fcd75b122a0 {
   meta:
      description = "16-07-2026-14.49 - file 1f29ad9ef32cea0d462fd3d74d7bf439757b6de28039ee7c3fcd75b122a03043.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "1f29ad9ef32cea0d462fd3d74d7bf439757b6de28039ee7c3fcd75b122a03043"
   strings:
      $s1 = "sExfid)V" fullword ascii
      $s2 = "C;?atIS" fullword ascii
      $s3 = "JuDO>~" fullword ascii
      $s4 = ":FuZe@" fullword ascii
      $s5 = "`!BadE" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffe {
   meta:
      description = "16-07-2026-14.49 - file 6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "6ec2aec3151feaf7b4c6c7934e7ad601cca984266f0604b93676ae698ffed738"
   strings:
      $s1 = "waIf]^k" fullword ascii
      $s2 = "}roun$" fullword ascii
      $s3 = "K\\)rApt" fullword ascii
      $s4 = "V[jato" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d4 {
   meta:
      description = "16-07-2026-14.49 - file 9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "9cce05c0f48011c170f0b6a8bf7ca61cb6dfe02e6afa5859ff7090c688d49a90"
   strings:
      $s1 = "* SlAp" fullword ascii
      $s2 = "h`TRUB" fullword ascii
      $s3 = "cRiN}+" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_906896b11849040c03a0260dd290320c08b1df19d0bc5e885abf2f99de0d {
   meta:
      description = "16-07-2026-14.49 - file 906896b11849040c03a0260dd290320c08b1df19d0bc5e885abf2f99de0daebc.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "906896b11849040c03a0260dd290320c08b1df19d0bc5e885abf2f99de0daebc"
   strings:
      $s1 = "Stealer" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038 {
   meta:
      description = "16-07-2026-14.49 - file 8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "8314ece95207ff28466d4fc8bf6cef22cc6e28fef47e9bede381b502f038b552"
   strings:
      $s1 = ";noop{w" fullword ascii
      $s2 = "M euge" fullword ascii
      $s3 = "p]gleE" fullword ascii
      $s4 = "s>WEnE" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc {
   meta:
      description = "16-07-2026-14.49 - file 83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "83f87364e05ff509464d246cb7969f7b05e12f4ee4daaf741cc331cb92dc5025"
   strings:
      $s1 = ",MuNgy" fullword ascii
      $s2 = "[aRuI%" fullword ascii
      $s3 = "b*KhAt " fullword ascii
      $s4 = ":yawy>" fullword ascii
      $s5 = "O#BAlK}" fullword ascii
      $s6 = "[TUNy$" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_6a94280f9c63fc30646439857e184a124722950dcd59a0ad8db8616f0d66 {
   meta:
      description = "16-07-2026-14.49 - file 6a94280f9c63fc30646439857e184a124722950dcd59a0ad8db8616f0d66fcdd.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "6a94280f9c63fc30646439857e184a124722950dcd59a0ad8db8616f0d66fcdd"
   strings:
      $s1 = "content" fullword wide
      $s2 = "STNosso clientes merecem uma consulta em tempo real sem atrasos e com total seguran" fullword ascii
      $s3 = "banner" fullword wide
      $s4 = "UPDATE size: 5.2MB" fullword ascii
      $s5 = "UPDATE App" fullword ascii
      $s6 = "UPDATE the Chrome UPDATE app?" fullword ascii
      $s7 = " 2023 Rastreio Leveros. All rights reserved." fullword ascii
      $s8 = "<<To continue using Chrome UPDATE, you need to update the app." fullword ascii
      $s9 = "}!ILex" fullword ascii
      $s10 = "CELT(+" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_3f4c9b68876000a2cf20ba8804cbb7fa74064a8dd39253733371486d2a8f {
   meta:
      description = "16-07-2026-14.49 - file 3f4c9b68876000a2cf20ba8804cbb7fa74064a8dd39253733371486d2a8fc83a.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "3f4c9b68876000a2cf20ba8804cbb7fa74064a8dd39253733371486d2a8fc83a"
   strings:
      $s1 = "LAME F" fullword ascii
      $s2 = "h LAME" fullword ascii
      $s3 = "/:LAME" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule b68e96cf67fd740c164dc3b90634b10e1b7a20ca5b741cf66885f5ec3be09d74 {
   meta:
      description = "16-07-2026-14.49 - file b68e96cf67fd740c164dc3b90634b10e1b7a20ca5b741cf66885f5ec3be09d74.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "b68e96cf67fd740c164dc3b90634b10e1b7a20ca5b741cf66885f5ec3be09d74"
   strings:
      $s1 = "Voice changer with effects - https://thevoicechanger.comTSSE" fullword ascii
      $s2 = "Voice changer with effects - https://thevoicechanger.comTPE1" fullword ascii
      $s3 = "TAGVoice changer with effects - hVoice changer with effects - h" fullword ascii
      $s4 = "J*LAME" fullword ascii
      $s5 = "<*LAME" fullword ascii
      $s6 = "**LAME" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule c4f51ccde0525887b61fb919eefc5830b24ec35fdcb2af2aa3893e5f56957c40 {
   meta:
      description = "16-07-2026-14.49 - file c4f51ccde0525887b61fb919eefc5830b24ec35fdcb2af2aa3893e5f56957c40.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "c4f51ccde0525887b61fb919eefc5830b24ec35fdcb2af2aa3893e5f56957c40"
   strings:
      $s1 = "Tom and Angela-You Get Me (From " fullword ascii
      $s2 = ")#nostalgia #shorts #talkingtom #fyp #ttf" fullword ascii
      $s3 = "SLaB*5$" fullword ascii
      $s4 = "Talking Friends" fullword ascii
      $s5 = "YE]&loRn" fullword ascii
      $s6 = "UAnG$l" fullword ascii
      $s7 = "*=Z0@`c@`ecHE" fullword ascii
      $s8 = "y\"LAME" fullword ascii
      $s9 = "cAFh?`G" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa {
   meta:
      description = "16-07-2026-14.49 - file a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "a765afe80a04b8e569eff62f978a4c138a0f270f65ea3b2f7333285c0dd35daa"
   strings:
      $s1 = "J LAZE" fullword ascii
      $s2 = "KEnT*&" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf9 {
   meta:
      description = "16-07-2026-14.49 - file 9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "9b7adffc9107a1222106f1af99cbf7f2c787a7ad2f4d988296a3dfea6cf92d5d"
   strings:
      $s1 = "\\3!nAne" fullword ascii
      $s2 = "Xk(REis" fullword ascii
      $s3 = "bRUT[/" fullword ascii
      $s4 = "GeLt #" fullword ascii
      $s5 = "BOuD'w" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_9fb8a940492ee6095a24b4a34ecfa252a515fb681f16636a8f00b1e0e7d4 {
   meta:
      description = "16-07-2026-14.49 - file 9fb8a940492ee6095a24b4a34ecfa252a515fb681f16636a8f00b1e0e7d47fe2.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "9fb8a940492ee6095a24b4a34ecfa252a515fb681f16636a8f00b1e0e7d47fe2"
   strings:
      $s1 = "Tite;B" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule b115b04b197b112eecf668fa549f65189e683cb87050708a72fcca268c9258e2 {
   meta:
      description = "16-07-2026-14.49 - file b115b04b197b112eecf668fa549f65189e683cb87050708a72fcca268c9258e2.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "b115b04b197b112eecf668fa549f65189e683cb87050708a72fcca268c9258e2"
   strings:
      $s1 = "Forward UDP packets to badvpn-udpgw via SOCKS5. This needs badvpn-udpgw running on the remote server (normally listening on 127." ascii
      $s2 = "sglobal { perm_cache=1024; cache_dir={DIR}; server_port = 8091; server_ip = 0.0.0.0; query_method=tcp_only; min_ttl=15m; max_ttl" ascii
      $s3 = "CCEnable this option to bypass selected apps instead of proxying them" fullword ascii
      $s4 = "Forward UDP packets to badvpn-udpgw via SOCKS5. This needs badvpn-udpgw running on the remote server (normally listening on 127." ascii
      $s5 = "Bypass Mode" fullword ascii
      $s6 = "=1w; timeout=10; daemon=on; pid_file={DIR}/pdnsd.pid; } server { label= upstream; ip = {IP}; port = {PORT}; uptest = none; } rr " ascii
      $s7 = "UDP Forwarding" fullword ascii
      $s8 = "vvEnable IPv6 forwarding. If the server supports IPv6, you can access IPv6 contents from IPv4 network with this enabled." fullword ascii
      $s9 = "\"\"Username & Password Authentication" fullword ascii
      $s10 = "YYEnter one app's package name in one line. See Settings -> Apps for package names of apps." fullword ascii
      $s11 = "Delete profile %s?" fullword ascii
      $s12 = "Error deleting profile %s" fullword ascii
      $s13 = "UDP Gateway (Remote)" fullword ascii
      $s14 = "DNS Port (TCP)" fullword ascii
      $s15 = "Switch on / off the proxy" fullword ascii
      $s16 = "Failed to add profile %s" fullword ascii
      $s17 = "Server IP" fullword ascii
      $s18 = "RaND(D," fullword ascii
      $s19 = "About Bot" fullword ascii
      $s20 = "SHADOW BOT" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_23d668f31429fe38195087c3f7d9d68ef32fbb7bfa947be3589c08f09751 {
   meta:
      description = "16-07-2026-14.49 - file 23d668f31429fe38195087c3f7d9d68ef32fbb7bfa947be3589c08f0975193f7.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "23d668f31429fe38195087c3f7d9d68ef32fbb7bfa947be3589c08f0975193f7"
   strings:
      $s1 = "BREi!,l" fullword ascii
      $s2 = "tasH @6" fullword ascii
      $s3 = "HuTcH!*F" fullword ascii
      $s4 = "pL)KITh," fullword ascii
      $s5 = "BEtH{j" fullword ascii
      $s6 = "Axis::" fullword ascii
      $s7 = "]*LAME" fullword ascii
      $s8 = "dEnT@#" fullword ascii
      $s9 = "\":flAm" fullword ascii
      $s10 = "e*LAME" fullword ascii
      $s11 = "t#dAFt" fullword ascii
      $s12 = "k34#pUFF" fullword ascii
      $s13 = "\"lITeR," fullword ascii
      $s14 = "d]LeAM" fullword ascii
      $s15 = "HS#BAiL" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_5c852fd7458957b89d9b639c6cdede1dc9ab72c384661c4ebc0b3d201344 {
   meta:
      description = "16-07-2026-14.49 - file 5c852fd7458957b89d9b639c6cdede1dc9ab72c384661c4ebc0b3d201344133c.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "5c852fd7458957b89d9b639c6cdede1dc9ab72c384661c4ebc0b3d201344133c"
   strings:
      $s1 = "DANGER" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_0bcdf887e6bd21ea4073385a8b2e59025768be3131a92e9940886e05c748 {
   meta:
      description = "16-07-2026-14.49 - file 0bcdf887e6bd21ea4073385a8b2e59025768be3131a92e9940886e05c748e1cc.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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

rule d5b6c048a278c06e2625c47a3a57f5ce2e4d6d73d830051a84de1768e0445882 {
   meta:
      description = "16-07-2026-14.49 - file d5b6c048a278c06e2625c47a3a57f5ce2e4d6d73d830051a84de1768e0445882.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "d5b6c048a278c06e2625c47a3a57f5ce2e4d6d73d830051a84de1768e0445882"
   strings:
      $s1 = "Squeaky background soundTPE1" fullword ascii
      $s2 = "TAGSqueaky background sound" fullword ascii
      $s3 = "Squeaky background sound" fullword ascii
      $s4 = "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" ascii
      $s5 = "LAME3.92 (alpha)UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" fullword ascii
      $s6 = "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUULAME3.92 (alpha)UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" ascii
      $s7 = "LAME?B" fullword ascii
      $s8 = "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" ascii
      $s9 = "w;piKA" fullword ascii
      $s10 = "4>LAME" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38 {
   meta:
      description = "16-07-2026-14.49 - file d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "d9ddf328b6151bb6e2a74cd95c7153af969059ad0465dc3539a62a8069924a38"
   strings:
      $s1 = "FORb('u" fullword ascii
      $s2 = "PErI#:z" fullword ascii
      $s3 = "E]PEeD" fullword ascii
      $s4 = "JibI;," fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_926d3c5cc0c4f93cd63e1dd0cb7fb7a2da96fce980fce4cf77cdcf69ccca {
   meta:
      description = "16-07-2026-14.49 - file 926d3c5cc0c4f93cd63e1dd0cb7fb7a2da96fce980fce4cf77cdcf69ccca4e6b.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "926d3c5cc0c4f93cd63e1dd0cb7fb7a2da96fce980fce4cf77cdcf69ccca4e6b"
   strings:
      $s1 = "LAME3.101 (beta 3)" fullword ascii
      $s2 = "LAME3.101 (beta 3)UUUUUUUUUUUUUUUUUU" fullword ascii
      $s3 = "{jLAME3.101 (beta 3)" fullword ascii
      $s4 = "LAME3.101 (beta 3)UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" fullword ascii
      $s5 = "LAME3.101 (beta 3)UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUULAME3.101 (beta 3)UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" ascii
      $s6 = "LAME3.101 (beta 3)UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUULAME3.101 (beta 3)UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" ascii
      $s7 = "LAME3.101 (beta 3)UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule d7362ff697a5cae24b4b084d0436ccde7060524a24c34f37f185f64597930514 {
   meta:
      description = "16-07-2026-14.49 - file d7362ff697a5cae24b4b084d0436ccde7060524a24c34f37f185f64597930514.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "d7362ff697a5cae24b4b084d0436ccde7060524a24c34f37f185f64597930514"
   strings:
      $s1 = "Robux Cheat" fullword ascii
      $s2 = "$FOrd[AL" fullword ascii
      $s3 = "scUn,#" fullword ascii
      $s4 = ":LAME " fullword ascii
      $s5 = "%fLAME" fullword ascii
      $s6 = "H}LAME" fullword ascii
      $s7 = "x*LAME" fullword ascii
      $s8 = "|$CiNe" fullword ascii
      $s9 = "^[SYnE" fullword ascii
      $s10 = "2^~oo<LAME" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f2 {
   meta:
      description = "16-07-2026-14.49 - file 1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "1370ba86f4c12ff1a8a0dd987b2be79a6ed13f7765e05b9711c544a7a2f288ea"
   strings:
      $s1 = "Welcome Back" fullword ascii
      $s2 = ",,Monitors user activity for security purposes" fullword ascii
      $s3 = "Recipient Name or Account" fullword ascii
      $s4 = "Security monitoring service" fullword ascii
      $s5 = "  Network error. Please try again." fullword ascii
      $s6 = "Sign in to your account" fullword ascii
      $s7 = "Transfer details" fullword ascii
      $s8 = "Amount: %1$.2f" fullword ascii
      $s9 = "Total Balance" fullword ascii
      $s10 = "((Monitors clipboard for security purposes" fullword ascii
      $s11 = "Recipient: %s" fullword ascii
      $s12 = "Send Money" fullword ascii
      $s13 = "Transaction History" fullword ascii
      $s14 = "\"\"Please fill in all required fields" fullword ascii
      $s15 = "ScrY!q" fullword ascii
      $s16 = "grOS}0Ie" fullword ascii
      $s17 = "))Records screen interactions for analytics" fullword ascii
      $s18 = "Secure. Simple. Smart." fullword ascii
      $s19 = "Transfer code" fullword ascii
      $s20 = "Tice!lic" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_8159c79c8a9b54ad363516f9b53c7cada3ea4afa0b2d0f6e7dc66fe147d0 {
   meta:
      description = "16-07-2026-14.49 - file 8159c79c8a9b54ad363516f9b53c7cada3ea4afa0b2d0f6e7dc66fe147d03a93.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "8159c79c8a9b54ad363516f9b53c7cada3ea4afa0b2d0f6e7dc66fe147d03a93"
   strings:
      $s1 = "2018 Epic Stock Media (Horror Game) https://epicstockmedia.com" fullword ascii
      $s2 = "All files are Copyright Epic Stock Media - All Rights Reserved " fullword ascii
      $s3 = "<BWFXML><IXML_VERSION>1.61</IXML_VERSION><STEINBERG><ATTR_LIST><ATTR><TYPE>string</TYPE><NAME>MediaLibrary</NAME><VALUE>Horror G" ascii
      $s4 = "Logic Pro X" fullword ascii
      $s5 = "terror" fullword ascii
      $s6 = " 2018 Epic Stock MediaCOMM" fullword ascii
      $s7 = "<BWFXML><IXML_VERSION>1.61</IXML_VERSION><STEINBERG><ATTR_LIST><ATTR><TYPE>string</TYPE><NAME>MediaLibrary</NAME><VALUE>Horror G" ascii
      $s8 = "><VALUE>Epic Stock Media</VALUE></ATTR><ATTR><TYPE>string</TYPE><NAME>MediaComment</NAME><VALUE>This is a sound effect created b" ascii
      $s9 = "         </dc:description>" fullword ascii
      $s10 = "ame</VALUE></ATTR><ATTR><TYPE>string</TYPE><NAME>MediaCategoryPost</NAME><VALUE>Game</VALUE></ATTR><ATTR><TYPE>string</TYPE><NAM" ascii
      $s11 = "         <dc:description>" fullword ascii
      $s12 = "Epic Stock MediaTORY" fullword ascii
      $s13 = "This is a sound effect created by Epic Stock Media for horror games." fullword ascii
      $s14 = "data@XE" fullword ascii
      $s15 = "E>MediaLibraryManufacturerName</NAME><VALUE>Epic Stock Media</VALUE></ATTR><ATTR><TYPE>string</TYPE><NAME>AudioSoundEditor</NAME" ascii
      $s16 = "This is a sound effect created by Epic Stock Media for horror games.TOWN" fullword ascii
      $s17 = "My Horror Domlopez 4" fullword ascii
      $s18 = "Epic Stock Media" fullword ascii
      $s19 = "Horror GameTYER" fullword ascii
      $s20 = "ENCODER=FL Studio Mobile v4.8.0" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_89d492b7539b5552445764907a96b517d08d448f8ff0e3e7a93958df82d3 {
   meta:
      description = "16-07-2026-14.49 - file 89d492b7539b5552445764907a96b517d08d448f8ff0e3e7a93958df82d3df58.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "89d492b7539b5552445764907a96b517d08d448f8ff0e3e7a93958df82d3df58"
   strings:
      $s1 = "!oXEA:" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule a2c509d0b0fcee3bc503bd12986da2d29c74ebcd37abb1af8988f7f26382663d {
   meta:
      description = "16-07-2026-14.49 - file a2c509d0b0fcee3bc503bd12986da2d29c74ebcd37abb1af8988f7f26382663d.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "a2c509d0b0fcee3bc503bd12986da2d29c74ebcd37abb1af8988f7f26382663d"
   strings:
      $s1 = "Executing script" fullword ascii
      $s2 = "==Superuser permission granted, use Magisk Manager to manage :)" fullword ascii
      $s3 = "Executando script..." fullword ascii
      $s4 = "*This app helps you use mtk-su to launch Magisk on compatible devices, including locked-down ones! It runs entirely from the dat" ascii
      $s5 = " posterior a mar" fullword ascii
      $s6 = "*This app helps you use mtk-su to launch Magisk on compatible devices, including locked-down ones! It runs entirely from the dat" ascii
      $s7 = "OOFailed. Check 64-bit switch. Still not working? App not supported on device :( " fullword ascii
      $s8 = "a partition: no need to modify the firmware. Root is available for any app that wants it. But to manage root access for each app" ascii
      $s9 = "lication, you must download Magisk Manager." fullword ascii
      $s10 = "s fazer o downgrade do firmware." fullword ascii
      $s11 = "XXThe security patch date is after March 2020. Please try again after a firmware downgrade" fullword ascii
      $s12 = "My BiliBili Space" fullword ascii
      $s13 = "syA data de atualiza" fullword ascii
      $s14 = "Magisk Manager" fullword ascii
      $s15 = "Run on Boot" fullword ascii
      $s16 = " Magisk manager " fullword ascii
      $s17 = "Mtk Easy Su" fullword ascii
      $s18 = " Magisk Manager." fullword ascii
      $s19 = "rio baixar o Magisk Manager." fullword ascii
      $s20 = "Magisk Manager(" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_9a778fbb730ee653f45b36700a369c81792509f855c2529aca73de1443c6 {
   meta:
      description = "16-07-2026-14.49 - file 9a778fbb730ee653f45b36700a369c81792509f855c2529aca73de1443c62de8.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "9a778fbb730ee653f45b36700a369c81792509f855c2529aca73de1443c62de8"
   strings:
      $s1 = "wiNG&v" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738 {
   meta:
      description = "16-07-2026-14.49 - file f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "f28d8b1301e83a88a9fa40415ed613e60485e219350ea1b9a2cf7e264b043738"
   strings:
      $s1 = "DW(qUiZ" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7 {
   meta:
      description = "16-07-2026-14.49 - file bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "bc7c3a3f2b617a7bec37ae806fad0d53a0763f0b2cc905050a5b93ecc486e3f7"
   strings:
      $s1 = "sIma)][>" fullword ascii
      $s2 = "Aura Gaming1" fullword ascii
      $s3 = "homy%oo" fullword ascii
      $s4 = "L#SmUG" fullword ascii
      $s5 = "RIFF`p" fullword ascii
      $s6 = "!*LAUn," fullword ascii
      $s7 = "RIFF(h" fullword ascii
      $s8 = "RIFF$'" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe754976 {
   meta:
      description = "16-07-2026-14.49 - file 9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "9d3f0d7a99c12c031b92f855c32971de7bd6bacdbff0b54482ecfe75497662d5"
   strings:
      $s1 = "tEXticc:description" fullword ascii
      $s2 = "Capture data added to log" fullword ascii
      $s3 = "zTXtRaw profile type icc" fullword ascii
      $s4 = "+[hiVe" fullword ascii
      $s5 = "D\"moLA" fullword ascii
      $s6 = "DoPe{ " fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219 {
   meta:
      description = "16-07-2026-14.49 - file f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "f19a8bd4ebd1ef6c60f3e83d04638beb5ef4a51b01fa6d5a68d565bdf0b46219"
   strings:
      $s1 = "Capture data added to log" fullword ascii
      $s2 = "+[hiVe" fullword ascii
      $s3 = "D\"moLA" fullword ascii
      $s4 = "DoPe{ " fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac1 {
   meta:
      description = "16-07-2026-14.49 - file 23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "23b0c2e740a824ff6e81d27c706f229fb1017ef3d711cfad1021b08cbac14c61"
   strings:
      $s1 = "bite#%qe" fullword ascii
      $s2 = "\\}spiN" fullword ascii
      $s3 = "heii,#" fullword ascii
      $s4 = " )stAP" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_6b0c56540499051ab350a31f417b99859da7ed7286b9e77503711c6aabaf {
   meta:
      description = "16-07-2026-14.49 - file 6b0c56540499051ab350a31f417b99859da7ed7286b9e77503711c6aabafbe03.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "6b0c56540499051ab350a31f417b99859da7ed7286b9e77503711c6aabafbe03"
   strings:
      $s1 = "Protezione in tempo reale" fullword ascii
      $s2 = "Download modulo sicurezza" fullword ascii
      $s3 = "Downloading security module" fullword ascii
      $s4 = "Scan Complete" fullword ascii
      $s5 = "SafeGuard Technologies0 " fullword ascii
      $s6 = "SafeGuard Technologies0" fullword ascii
      $s7 = "Scanning Device" fullword ascii
      $s8 = "interruptor" fullword ascii
      $s9 = "  All systems are running smoothly" fullword ascii
      $s10 = "t wird gescannt" fullword ascii
      $s11 = "Alle Systeme sind gesch" fullword ascii
      $s12 = "Checking system files" fullword ascii
      $s13 = "Come attivare" fullword ascii
      $s14 = "&(Sicherheitsmodul wird heruntergeladen" fullword ascii
      $s15 = "Security protection service" fullword ascii
      $s16 = "Complete setup in 3 easy steps" fullword ascii
      $s17 = "n gratuita para tu dispositivo" fullword ascii
      $s18 = "SafeGuard Solutions LLC1" fullword ascii
      $s19 = "idlo nain" fullword ascii
      $s20 = " integrity aplikac" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_92871cbed3b8b6a65b0e50df893c015e6508572d7cde49b0a99ec61449a1 {
   meta:
      description = "16-07-2026-14.49 - file 92871cbed3b8b6a65b0e50df893c015e6508572d7cde49b0a99ec61449a11d1e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "92871cbed3b8b6a65b0e50df893c015e6508572d7cde49b0a99ec61449a11d1e"
   strings:
      $s1 = "targetSdkVersion does not support the current path on Android10+ system devices after setting >=29. Please change to the applica" ascii
      $s2 = "targetSdkVersion does not support the current path on Android10+ system devices after setting >=29. Please change to the applica" ascii
      $s3 = "%%, configuration file download failed!" fullword ascii
      $s4 = "FFthe Authentication Service operation to obtain authorized logon failed" fullword ascii
      $s5 = "failed to get token" fullword ascii
      $s6 = "execution error" fullword ascii
      $s7 = "Configuration get failed" fullword ascii
      $s8 = "==The webview has not been created yet, please execute it later" fullword ascii
      $s9 = "FFfailed to obtain authorization to log in to the authentication service" fullword ascii
      $s10 = "tion run path! Please see:https://ask.dcloud.net.cn/article/36199" fullword ascii
      $s11 = "XXWGTU installation package www under contents manifest.json file version version mismatch" fullword ascii
      $s12 = "LLWGTU installation package www under contents manifest.json file format error" fullword ascii
      $s13 = "orage (the system prompts to access photos, media content and files on the device), please allow." fullword ascii
      $s14 = "KKPlease upload after compressing and cutting, the largest file only supports" fullword ascii
      $s15 = "??the get address is empty, get a new URI through getShortCutUri?" fullword ascii
      $s16 = "not logged in or logged out" fullword ascii
      $s17 = "reauthorize" fullword ascii
      $s18 = "22the current system does not support AAC recording!" fullword ascii
      $s19 = "00continuing with a previously unfinished download" fullword ascii
      $s20 = "kkthe permission is detected to be closed, please follow the steps below to open the permission: [%s]-[Allow]" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb {
   meta:
      description = "16-07-2026-14.49 - file 392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d"
   strings:
      $s1 = "G;Sonk" fullword ascii
      $s2 = "swOm$4" fullword ascii
      $s3 = "v/&gOlf{" fullword ascii
      $s4 = "VAde&b" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af {
   meta:
      description = "16-07-2026-14.49 - file d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af"
   strings:
      $s1 = "v#PROo" fullword ascii
      $s2 = "RIFF&'" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule fd263056adfe6cb5596a11612440fa5d851b3b9bed34a481139c2206a6c570b1 {
   meta:
      description = "16-07-2026-14.49 - file fd263056adfe6cb5596a11612440fa5d851b3b9bed34a481139c2206a6c570b1.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "fd263056adfe6cb5596a11612440fa5d851b3b9bed34a481139c2206a6c570b1"
   strings:
      $s1 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description rdf:ab" ascii
      $s2 = "\"uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\"><xmp:CreatorTool>Microsoft Windows Phot" ascii
      $s3 = "ewer 6.1.7600.16385</xmp:CreatorTool></rdf:Description></rdf:RDF></x:xmpmeta>" fullword ascii
      $s4 = "GOli`l0" fullword ascii
      $s5 = "LAME% T" fullword ascii
      $s6 = "YAGi!N" fullword ascii
      $s7 = "LAME in FL Studio 10 " fullword ascii
      $s8 = "Microsoft Windows Photo Viewer 6.1.7600.16385" fullword ascii
      $s9 = "COPYRIGHT, 2011" fullword ascii
      $s10 = "U*LAME" fullword ascii
      $s11 = "y@buRP" fullword ascii
      $s12 = "u*LAME" fullword ascii
      $s13 = "pOON;~" fullword ascii
      $s14 = "&[cURl" fullword ascii
      $s15 = "%*LAME" fullword ascii
      $s16 = "fUsS$O" fullword ascii
      $s17 = "5*LAME" fullword ascii
      $s18 = "!SARD]" fullword ascii
      $s19 = "Yu8>LAME" fullword ascii
      $s20 = "(para r" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule a82591b195a32c8ad049ff627367c2a63d67c7f7324e3c335c993a7bbd66477a {
   meta:
      description = "16-07-2026-14.49 - file a82591b195a32c8ad049ff627367c2a63d67c7f7324e3c335c993a7bbd66477a.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "a82591b195a32c8ad049ff627367c2a63d67c7f7324e3c335c993a7bbd66477a"
   strings:
      $s1 = "File download failed" fullword ascii
      $s2 = "File download in progress" fullword ascii
      $s3 = "~~R8{\"backend\":\"dex\",\"compilation-mode\":\"release\",\"desugared-library-identifiers\":[\"com.tools.android:desugar_jdk_lib" ascii
      $s4 = "GMarker log finalized without finish() - uncaught exit point for request" fullword ascii
      $s5 = "~~L8{\"backend\":\"cf\",\"compilation-mode\":\"release\",\"desugared-library-identifiers\":[\"com.tools.android:desugar_jdk_libs" ascii
      $s6 = "-Landroid/content/pm/PackageInstaller$Session;" fullword ascii
      $s7 = "Failed to write header for %s" fullword ascii
      $s8 = "POSTING" fullword ascii
      $s9 = "V. Please make this class visible to EventBus annotation processor to avoid reflection." fullword ascii
      $s10 = "::Do you want to install the APK (%1$s) you just downloaded?" fullword ascii
      $s11 = "8Could not retrieve response code from HttpUrlConnection." fullword ascii
      $s12 = "&&Do you want to download the file %1$s?" fullword ascii
      $s13 = "QHTTP response for request=<%s> [lifetime=%d], [size=%s], [rc=%d], [retryCount=%s]" fullword ascii
      $s14 = "y~~R8{\"backend\":\"dex\",\"compilation-mode\":\"release\",\"has-checksums\":false,\"min-api\":24,\"r8-mode\":\"full\",\"version" ascii
      $s15 = "Request download file" fullword ascii
      $s16 = ".Unable to parse dateStr: %s, falling back to 0" fullword ascii
      $s17 = "No pending post available" fullword ascii
      $s18 = "Header[name=" fullword ascii
      $s19 = "Head present, but no tail" fullword ascii
      $s20 = "Marker added to finished log" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_2d25cb4e862cc6cac19999798f044211ed99239dd15779be6271b680c028 {
   meta:
      description = "16-07-2026-14.49 - file 2d25cb4e862cc6cac19999798f044211ed99239dd15779be6271b680c028782a.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "2d25cb4e862cc6cac19999798f044211ed99239dd15779be6271b680c028782a"
   strings:
      $s1 = "dmart private shop 1" fullword ascii
      $s2 = "dmart private shop 0 " fullword ascii
      $s3 = "dmart private shop 0" fullword ascii
      $s4 = "Dmart Shopping" fullword ascii
      $s5 = "X Shop limited1" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de {
   meta:
      description = "16-07-2026-14.49 - file bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "bd8d876a63c55a252a600f565c9ccc0f9d2375a0a341b84f5821b07d85f111de"
   strings:
      $s1 = "WORKER" fullword ascii
      $s2 = "BRANCH" fullword ascii
      $s3 = ".Q#darr" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b {
   meta:
      description = "16-07-2026-14.49 - file c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "c9f0f8875297bccfa81dcae3fdec8cc67f6872e0e58d295cf2dcf89985e7a22b"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 6.0-c002 79.164460, 2020/05/" ascii
      $s2 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 6.0-c002 79.164460, 2020/05/" ascii
      $s3 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 6.0-c002 79.164460, 2020/05/" ascii
      $s4 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 6.0-c002 79.164460, 2020/05/" ascii
      $s5 = "ent#\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmp:CreatorTool=\"Ad" ascii
      $s6 = ":softwareAgent=\"Adobe Photoshop 21.2 (Windows)\" stEvt:changed=\"/\"/> </rdf:Seq> </xmpMM:History> </rdf:Description> </rdf:RDF" ascii
      $s7 = ":softwareAgent=\"Adobe Photoshop 21.2 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.ii" ascii
      $s8 = "04:17        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmp=" ascii
      $s9 = "vt:changed=\"/\"/> </rdf:Seq> </xmpMM:History> </rdf:Description> </rdf:RDF> </x:xmpmeta> <?xpacket end=\"r\"?>" fullword ascii
      $s10 = "istory> </rdf:Description> </rdf:RDF> </x:xmpmeta> <?xpacket end=\"r\"?>" fullword ascii
      $s11 = "4dd-0afc-254c-89c7-6f5bc187204e\" stEvt:when=\"2025-07-01T20:44:13+03:00\" stEvt:softwareAgent=\"Adobe Photoshop 21.2 (Windows)" ascii
      $s12 = "-cc48-b029-7028ef3c05cd\" stEvt:when=\"2025-07-01T20:43:14+03:00\" stEvt:softwareAgent=\"Adobe Photoshop 21.2 (Windows)\"/> <rdf" ascii
      $s13 = "t:when=\"2025-07-10T02:30:29+03:00\" stEvt:softwareAgent=\"Adobe Photoshop 21.2 (Windows)\" stEvt:changed=\"/\"/> </rdf:Seq> </x" ascii
      $s14 = "-dd49-9f42-2a9b74a601ae\" stEvt:when=\"2025-06-23T19:42:10+03:00\" stEvt:softwareAgent=\"Adobe Photoshop 21.2 (Windows)\"/> <rdf" ascii
      $s15 = "-b84d-b911-e8c7b9f9cd70\" stEvt:when=\"2025-06-23T23:39:10+03:00\" stEvt:softwareAgent=\"Adobe Photoshop 21.2 (Windows)\"/> <rdf" ascii
      $s16 = "2025-06-23T19:42:10+03:00\" xmpMM:InstanceID=\"xmp.iid:ed09315b-18ea-7b4c-8ecc-2987054aadb9\" xmpMM:DocumentID=\"adobe:docid:pho" ascii
      $s17 = "187204e\" xmpMM:DocumentID=\"adobe:docid:photoshop:cf4ec0c5-15de-8b4c-96a2-7238497356a1\" xmpMM:OriginalDocumentID=\"xmp.did:cfb" ascii
      $s18 = "e/png\" photoshop:ColorMode=\"3\"> <xmpMM:History> <rdf:Seq> <rdf:li stEvt:action=\"created\" stEvt:instanceID=\"xmp.iid:2513bf8" ascii
      $s19 = "2025-06-23T23:39:10+03:00\" xmpMM:InstanceID=\"xmp.iid:f9f64753-6df4-9746-847e-21eae8987a93\" xmpMM:DocumentID=\"adobe:docid:pho" ascii
      $s20 = "2025-07-10T02:30:29+03:00\" xmpMM:InstanceID=\"xmp.iid:90209473-bbbc-2e4d-9fb3-0972612167bb\" xmpMM:DocumentID=\"adobe:docid:pho" ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule c659454dd6ed62bc7a0c9e0455297e41ba57b0b7935a826150c1f8c0db6f89d2 {
   meta:
      description = "16-07-2026-14.49 - file c659454dd6ed62bc7a0c9e0455297e41ba57b0b7935a826150c1f8c0db6f89d2.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "c659454dd6ed62bc7a0c9e0455297e41ba57b0b7935a826150c1f8c0db6f89d2"
   strings:
      $s1 = "++Please wait, connection process in progress" fullword ascii
      $s2 = "##Please wait, processing in progress" fullword ascii
      $s3 = "Reconnection attempt %1$d/%2$d" fullword ascii
      $s4 = "logotype" fullword ascii
      $s5 = "Content load error" fullword ascii
      $s6 = "Bank logo" fullword ascii
      $s7 = "Logo banky" fullword ascii
      $s8 = "To confirm the operation" fullword ascii
      $s9 = "Initialization error" fullword ascii
      $s10 = "Transition error" fullword ascii
      $s11 = "$$Successfully connected to the system" fullword ascii
      $s12 = "WebSocket Error:" fullword ascii
      $s13 = "##Error: network failure, please wait" fullword ascii
      $s14 = "WebSocket Closed:" fullword ascii
      $s15 = "te zariadenie k termin" fullword ascii
      $s16 = "tania obsahu" fullword ascii
      $s17 = " add your first client" fullword ascii
      $s18 = "Error: configuration not loaded" fullword ascii
      $s19 = "Enter PIN Code" fullword ascii
      $s20 = "Change PIN Code" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a {
   meta:
      description = "16-07-2026-14.49 - file faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "faeb83e77a383e529cee0ae689fec98970099fa58758ba4526da1adadaefbe8a"
   strings:
      $s1 = "Omad Shou" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f {
   meta:
      description = "16-07-2026-14.49 - file 7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "7748e9b7d04bab6775cd2bb24c86a83b59de9b3cf21567606754e433c74f5570"
   strings:
      $s1 = "System Service0" fullword ascii
      $s2 = "03 - Sem sinal" fullword ascii
      $s3 = "Sinal perdido" fullword ascii
      $s4 = "Sync Manager" fullword ascii
      $s5 = "*y\"Trap" fullword ascii
      $s6 = "{yooK," fullword ascii
      $s7 = "Nenhum Cart" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99 {
   meta:
      description = "16-07-2026-14.49 - file b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "b4111e8710771fa2ff758c8b949895a030698a0f177220704c7f1f763f576c99"
   strings:
      $s1 = "<rdf:Description rdf:about=\"\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:Iptc4xmpCore=\"http://iptc.org/std/" ascii
      $s2 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c138 79.159824, 2016/09/" ascii
      $s3 = "<rdf:Description rdf:about=\"\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:Iptc4xmpCore=\"http://iptc.org/std/" ascii
      $s4 = "<plus:Licensor><rdf:Seq><rdf:li rdf:parseType='Resource'><plus:LicensorURL>https://www.istockphoto.com/photo/license-gm133210091" ascii
      $s5 = "http://ns.adobe.com/photoshop/1.0/\" xmp:CreatorTool=\"Adobe Photoshop CC 2017 (Windows)\" xmp:CreateDate=\"2019-04-07T11:27:48+" ascii
      $s6 = "<plus:Licensor><rdf:Seq><rdf:li rdf:parseType='Resource'><plus:LicensorURL>https://www.istockphoto.com/photo/license-gm133210091" ascii
      $s7 = " stEvt:softwareAgent=\"Adobe Photoshop CC 2017 (Windows)\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.iid:7ce77201-" ascii
      $s8 = "09:01        \"> <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"> <rdf:Description rdf:about=\"\" xmlns:xmp=" ascii
      $s9 = "\">Man icon. Black icon. Person symbol</rdf:li></rdf:Alt></dc:description>" fullword ascii
      $s10 = "<dc:creator><rdf:Seq><rdf:li>vitalik19111992</rdf:li></rdf:Seq></dc:creator><dc:description><rdf:Alt><rdf:li xml:lang=\"x-defaul" ascii
      $s11 = "<dc:creator><rdf:Seq><rdf:li>vitalik19111992</rdf:li></rdf:Seq></dc:creator><dc:description><rdf:Alt><rdf:li xml:lang=\"x-defaul" ascii
      $s12 = "5:22:31+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2017 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted" ascii
      $s13 = "3a6-d860cb6e4440\" stEvt:when=\"2019-04-07T15:22:31+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2017 (Windows)\" stEvt:chan" ascii
      $s14 = "ID=\"xmp.iid:5df978c6-fb3f-6640-93a6-d860cb6e4440\" xmpMM:DocumentID=\"adobe:docid:photoshop:e2cc4944-5905-11e9-96a6-fe640711990" ascii
      $s15 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c138 79.159824, 2016/09/" ascii
      $s16 = "\" plus:DataMining=\"http://ns.useplus.org/ldf/vocab/DMI-PROHIBITED-EXCEPTSEARCHENGINEINDEXING\" >" fullword ascii
      $s17 = "d84a-962e-ca4b77f60b48\" stEvt:when=\"2019-04-07T15:06:57+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2017 (Windows)\" stEv" ascii
      $s18 = "4925e328\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta>                                                                         " ascii
      $s19 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">" fullword ascii
      $s20 = "Adobe Photoshop CC 2017 (Windows)" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_4b9a92bc2ba87c302fa3fc5090d588d9c2dc86a35b3caf61bba460a81b65 {
   meta:
      description = "16-07-2026-14.49 - file 4b9a92bc2ba87c302fa3fc5090d588d9c2dc86a35b3caf61bba460a81b65dc9a.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "4b9a92bc2ba87c302fa3fc5090d588d9c2dc86a35b3caf61bba460a81b65dc9a"
   strings:
      $s1 = "SUrA'W," fullword ascii
      $s2 = "y'Q@OiNT" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_1389e203ecaebc0b44365ebcc95c05789367e896e862f1a2f614e29ded7d {
   meta:
      description = "16-07-2026-14.49 - file 1389e203ecaebc0b44365ebcc95c05789367e896e862f1a2f614e29ded7d6c01.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "1389e203ecaebc0b44365ebcc95c05789367e896e862f1a2f614e29ded7d6c01"
   strings:
      $s1 = "%:HaeC" fullword ascii
      $s2 = "2VI{duRo" fullword ascii
      $s3 = "O,\"maRT" fullword ascii
      $s4 = "bAST'0" fullword ascii
      $s5 = "Yelk'y" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule d6e87fb3a6f6bc2527c16a768ab517aec705666f3e8540f21b47e9747ff67e9c {
   meta:
      description = "16-07-2026-14.49 - file d6e87fb3a6f6bc2527c16a768ab517aec705666f3e8540f21b47e9747ff67e9c.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "d6e87fb3a6f6bc2527c16a768ab517aec705666f3e8540f21b47e9747ff67e9c"
   strings:
      $s1 = "ikra!%" fullword ascii
      $s2 = "nasI[?>" fullword ascii
      $s3 = "^[}cOpY" fullword ascii
      $s4 = "/%sAhh" fullword ascii
      $s5 = "sisHaX" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_569ef3c50d8c1bb48729c04fc334f26f644ff799c7ba3a514610e85f53cc {
   meta:
      description = "16-07-2026-14.49 - file 569ef3c50d8c1bb48729c04fc334f26f644ff799c7ba3a514610e85f53cca3d5.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "569ef3c50d8c1bb48729c04fc334f26f644ff799c7ba3a514610e85f53cca3d5"
   strings:
      $s1 = "``@YeSO" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a {
   meta:
      description = "16-07-2026-14.49 - file b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "b028c30f784919c53a74089b5eee6a554fb9b9c7dd914f2d0a434dd2aacf4a0a"
   strings:
      $s1 = "tEXticc:description" fullword ascii
      $s2 = "Capture data added to log" fullword ascii
      $s3 = "zTXtRaw profile type icc" fullword ascii
      $s4 = "+[hiVe" fullword ascii
      $s5 = "D\"moLA" fullword ascii
      $s6 = "DoPe{ " fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_1bf9c16cb7c1faae7fa99a57c5d091cbd1e6d5f3c0d79693a3b0990a8b58 {
   meta:
      description = "16-07-2026-14.49 - file 1bf9c16cb7c1faae7fa99a57c5d091cbd1e6d5f3c0d79693a3b0990a8b58367d.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "1bf9c16cb7c1faae7fa99a57c5d091cbd1e6d5f3c0d79693a3b0990a8b58367d"
   strings:
      $s1 = "Airbnb Host Mobile0 " fullword ascii
      $s2 = "Airbnb Host Mobile0" fullword ascii
      $s3 = "NARk?a" fullword ascii
      $s4 = "Travel Experience Apps1" fullword ascii
      $s5 = "@mOHr;l" fullword ascii
      $s6 = " deRN`" fullword ascii
      $s7 = "i\"KEmB" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_27b8eeb5d1b46e1afa170b998830fe0958f08a2a9dfe7130df607c86ad42 {
   meta:
      description = "16-07-2026-14.49 - file 27b8eeb5d1b46e1afa170b998830fe0958f08a2a9dfe7130df607c86ad42fb33.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "27b8eeb5d1b46e1afa170b998830fe0958f08a2a9dfe7130df607c86ad42fb33"
   strings:
      $s1 = "Airbnb Host Mobile0 " fullword ascii
      $s2 = "Airbnb Host Mobile0" fullword ascii
      $s3 = "Travel Experience Apps1" fullword ascii
      $s4 = "dAFF>n#l" fullword ascii
      $s5 = "hAeC&Fu" fullword ascii
      $s6 = " deRN`" fullword ascii
      $s7 = "e`RePs:" fullword ascii
      $s8 = "7?amBa" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule b1a8941063751656e11bbc6ab44d348cd6795d51bfc890424595c4ac76e52013 {
   meta:
      description = "16-07-2026-14.49 - file b1a8941063751656e11bbc6ab44d348cd6795d51bfc890424595c4ac76e52013.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "b1a8941063751656e11bbc6ab44d348cd6795d51bfc890424595c4ac76e52013"
   strings:
      $s1 = "Airbnb Host Mobile0 " fullword ascii
      $s2 = "Airbnb Host Mobile0" fullword ascii
      $s3 = "Travel Experience Apps1" fullword ascii
      $s4 = "?meNg[?" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule ca6271b212c627dd6e4372827a0fb316023fa35210cab7249d634379af6d649c {
   meta:
      description = "16-07-2026-14.49 - file ca6271b212c627dd6e4372827a0fb316023fa35210cab7249d634379af6d649c.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "ca6271b212c627dd6e4372827a0fb316023fa35210cab7249d634379af6d649c"
   strings:
      $s1 = "Game Dev1" fullword ascii
      $s2 = "VAHAN 5.0  Digital" fullword wide
      $s3 = "BOSs<a" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule df384f9aaa8c3a194e2225d9f3b577d9bbda92f390ad15f3f812c3770909f9e8 {
   meta:
      description = "16-07-2026-14.49 - file df384f9aaa8c3a194e2225d9f3b577d9bbda92f390ad15f3f812c3770909f9e8.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "df384f9aaa8c3a194e2225d9f3b577d9bbda92f390ad15f3f812c3770909f9e8"
   strings:
      $s1 = "PeLL@HV" fullword ascii
      $s2 = "!bOCE<" fullword ascii
      $s3 = "x`NOTe" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb126 {
   meta:
      description = "16-07-2026-14.49 - file 563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "563bc028fac5f38f3849a3808bcba9cc41beeaf4b9ff771d383954beb1267e0b"
   strings:
      $s1 = "*Blocks network during package installation" fullword wide
      $s2 = "nUll'Z" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492 {
   meta:
      description = "16-07-2026-14.49 - file 73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "73d01b435acb23edf723047c868d3b6e94559d59bdc2478089e9b3528492fc8a"
   strings:
      $s1 = "Cheats Loader" fullword ascii
      $s2 = "TUrr[PU" fullword ascii
      $s3 = "Dirma Project" fullword ascii
      $s4 = "`*yILt" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_33ece8395604682f2c428a5b7a11e562b836f44f7b6fbb0caaa84bfa80d0 {
   meta:
      description = "16-07-2026-14.49 - file 33ece8395604682f2c428a5b7a11e562b836f44f7b6fbb0caaa84bfa80d0c8ff.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "33ece8395604682f2c428a5b7a11e562b836f44f7b6fbb0caaa84bfa80d0c8ff"
   strings:
      $s1 = "                  <stEvt:softwareAgent>Adobe Photoshop CC 2015.5 (Windows)</stEvt:softwareAgent>" fullword ascii
      $s2 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c132 79.159284, 2016/04/19-13:13:40        \">" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_364983d2dbff85f4b9b2bac2beba40ad29ac85f2a16bdbc8fd65896ef03c {
   meta:
      description = "16-07-2026-14.49 - file 364983d2dbff85f4b9b2bac2beba40ad29ac85f2a16bdbc8fd65896ef03cddb2.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "364983d2dbff85f4b9b2bac2beba40ad29ac85f2a16bdbc8fd65896ef03cddb2"
   strings:
      $s1 = "--To use this app, download the latest version." fullword ascii
      $s2 = "~~D8{\"backend\":\"dex\",\"compilation-mode\":\"debug\",\"has-checksums\":false,\"min-api\":21,\"sha-1\":\"abaab469b5ebd4dd2bb91" ascii
      $s3 = "~~D8{\"backend\":\"dex\",\"compilation-mode\":\"debug\",\"has-checksums\":false,\"min-api\":21,\"sha-1\":\"abaab469b5ebd4dd2bb91" ascii
      $s4 = "Video System" fullword ascii
      $s5 = "Ready to check for updates." fullword ascii
      $s6 = "AjaR@\\M8" fullword ascii
      $s7 = "Enable VPN" fullword ascii
      $s8 = "`NoBS:H)RG" fullword ascii
      $s9 = "Bug fixes and general stability improvements." fullword ascii
      $s10 = "Improved overall performance and faster loading times." fullword ascii
      $s11 = "Updated links with more options." fullword ascii
      $s12 = "@@To enjoy all matches without interruptions, please activate VPN." fullword ascii
      $s13 = "VPN protection is required" fullword ascii
      $s14 = "Optimized video player with greater stability." fullword ascii
      $s15 = "Refreshed interface with a cleaner design." fullword ascii
      $s16 = "Everyone 1.5 MB" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_793b9d915d2f412ad32d3aac486f17dd7b5014b86469b6a4540d559ee70a {
   meta:
      description = "16-07-2026-14.49 - file 793b9d915d2f412ad32d3aac486f17dd7b5014b86469b6a4540d559ee70a4d7b.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "793b9d915d2f412ad32d3aac486f17dd7b5014b86469b6a4540d559ee70a4d7b"
   strings:
      $s1 = "r&0xFindClassExceptionCheckJNIEnv*JNIEnvNewStringUTFNewStringUTF resultDeleteLocalRefGetObjectClassNewObjectANewObjectA resultCa" ascii
      $s2 = "r&0xFindClassExceptionCheckJNIEnv*JNIEnvNewStringUTFNewStringUTF resultDeleteLocalRefGetObjectClassNewObjectANewObjectA resultCa" ascii
      $s3 = "SetLongFieldSetBooleanFieldSetFloatFieldSetDoubleFieldset_field_typed obj argumentGetByteArrayRegionget_byte_array_region array " ascii
      $s4 = "argumentSetByteArrayRegionset_byte_array_region array argumentRegisterNativesGetObjectArrayElementget_object_array_element array" ascii
      $s5 = "ssfailed to write whole bufferdescription() is deprecated; use Display" fullword ascii
      $s6 = "rustc version 1.95.0-nightly (a33907a7a 2026-02-14)" fullword ascii
      $s7 = "5rustc version 1.95.0-nightly (a33907a7a 2026-02-14)" fullword ascii
      $s8 = " of read, write, or append accesscreating or truncating a file requires write or append accessfailed to write whole bufferdescri" ascii
      $s9 = "parsec" fullword ascii
      $s10 = "GetStaticFieldIDFindClass result" fullword ascii
      $s11 = "call_method obj argumentNewGlobalRefGetBooleanFieldGetByteFieldGetCharFieldGetDoubleFieldGetFloatFieldGetIntFieldGetLongFieldGet" ascii
      $s12 = ">PrimitiveObjectArrayMethodTypeSignatureretfile name contained an unexpected NUL byteinvalid stack sizemust specify at least one" ascii
      $s13 = "ir:ok:launch:" fullword ascii
      $s14 = "ir:fail" fullword ascii
      $s15 = "i:done pkg=" fullword ascii
      $s16 = " stack sizemust specify at least one of read, write, or append accesscreating or truncating a file requires write or append acce" ascii
      $s17 = "etThrowFailedParseFailedJniCall<init>PrimitiveObjectArrayMethodTypeSignatureretfile name contained an unexpected NUL byteinvalid" ascii
      $s18 = ";)char" fullword ascii
      $s19 = "ption() is deprecated; use Display" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_2fcc2db37c0c78d06a71002c1ac287fd68f024ec0717306629166c9b2225 {
   meta:
      description = "16-07-2026-14.49 - file 2fcc2db37c0c78d06a71002c1ac287fd68f024ec0717306629166c9b2225756e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "2fcc2db37c0c78d06a71002c1ac287fd68f024ec0717306629166c9b2225756e"
   strings:
      $s1 = "<Command xmlns=\"http://spss.com/spss/extension\" Name=\"RunScript\">" fullword ascii
      $s2 = "<Command xmlns=\"http://spss.com/spss/extension\" Name=\"ExportData\">" fullword ascii
      $s3 = "<Command xmlns=\"http://spss.com/spss/extension\" Name=\"RunAnalysis\">" fullword ascii
      $s4 = "<Command xmlns=\"http://spss.com/spss/extension\" Name=\"ImportData\">" fullword ascii
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
      $s19 = "COMPUTE x=1." fullword ascii
      $s20 = "SAVE OUTFILE='out.sav'." fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_61ac11961911a76b3752982592e7903d621bf6c9cf51853cbdea3b18f7ff {
   meta:
      description = "16-07-2026-14.49 - file 61ac11961911a76b3752982592e7903d621bf6c9cf51853cbdea3b18f7ff63fd.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "61ac11961911a76b3752982592e7903d621bf6c9cf51853cbdea3b18f7ff63fd"
   strings:
      $s1 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://" fullword ascii
      $s2 = "administrator" fullword ascii
      $s3 = "backdoor" fullword ascii
      $s4 = "rapport" fullword ascii
      $s5 = "/bin/busybox echo -ne " fullword ascii
      $s6 = "dropper" fullword ascii
      $s7 = "oracle" fullword ascii
      $s8 = "usage: busybox" fullword ascii
      $s9 = "raspberry" fullword ascii
      $s10 = "grouter" fullword ascii
      $s11 = "blender" fullword ascii
      $s12 = "mediator" fullword ascii
      $s13 = "supervisor" fullword ascii
      $s14 = "/bin/busybox echo > " fullword ascii
      $s15 = "ping ;sh" fullword ascii
      $s16 = "SUPERVISOR" fullword ascii
      $s17 = "netman" fullword ascii
      $s18 = "instar" fullword ascii
      $s19 = "alpine" fullword ascii
      $s20 = "timely" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8 {
   meta:
      description = "16-07-2026-14.49 - file e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "e53e38d1e1edefc7ca3a6a96a876162e577dfc24c05d980bf18ab00efc3b81d8"
   strings:
      $s1 = "peCK)\\" fullword ascii
      $s2 = "Sexy Chat" fullword ascii
      $s3 = "pARK>/+2" fullword ascii
      $s4 = "]5)MARE" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule fce8298e4849d80d2191f1a9cf430fee0de57c6448501f544b17a0ce7c1f01d4 {
   meta:
      description = "16-07-2026-14.49 - file fce8298e4849d80d2191f1a9cf430fee0de57c6448501f544b17a0ce7c1f01d4.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "fce8298e4849d80d2191f1a9cf430fee0de57c6448501f544b17a0ce7c1f01d4"
   strings:
      $s1 = "*`jerL" fullword ascii
      $s2 = "FyRDO;" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_603d89c5a2883ab2ed68e12517212bd0b74760f1ef755a61d059440aeba0 {
   meta:
      description = "16-07-2026-14.49 - file 603d89c5a2883ab2ed68e12517212bd0b74760f1ef755a61d059440aeba045fd.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "603d89c5a2883ab2ed68e12517212bd0b74760f1ef755a61d059440aeba045fd"
   strings:
      $s1 = "TUfF&UE_" fullword ascii
      $s2 = "FuZe$jx," fullword ascii
      $s3 = "X{pUAN<d" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_5fc08b4c4197d94016ec27e3cf09d4943891921519b489ade3c9494d71fe {
   meta:
      description = "16-07-2026-14.49 - file 5fc08b4c4197d94016ec27e3cf09d4943891921519b489ade3c9494d71fe4715.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "5fc08b4c4197d94016ec27e3cf09d4943891921519b489ade3c9494d71fe4715"
   strings:
      $s1 = " per cercare i virus e bloccarli. (Consente al sistema di proteggere il dispositivo, utilizza gli eventi di accessibilit" fullword ascii
      $s2 = " per cercare i virus e bloccarli)." fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_8adce5e888db7e35a5731de025715c95961b459481edd19a2e7fb040c121 {
   meta:
      description = "16-07-2026-14.49 - file 8adce5e888db7e35a5731de025715c95961b459481edd19a2e7fb040c1218063.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "8adce5e888db7e35a5731de025715c95961b459481edd19a2e7fb040c1218063"
   strings:
      $s1 = " version: %s" fullword ascii
      $s2 = "Materialize" fullword ascii
      $s3 = "           The <b>ItemAnimators</b> library comes with a huge collections of pre-created Animators for your RecyclerView." fullword ascii
      $s4 = " its theme as base. Let it manage your StatusBar, NavigationBar, Fullscreen behavior&#8230;" fullword ascii
      $s5 = "        <b>FastAdapter</b>, the bullet proof, fast and easy to use adapter library, which minimizes developing time to a fractio" ascii
      $s6 = "G8^e4;plUp<" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3 {
   meta:
      description = "16-07-2026-14.49 - file 6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "6a75ce2897a5ade56c4f7e5240cbefe7fc7fde599dd6f95949289a2640e3ad22"
   strings:
      $s1 = "Antivirus" fullword ascii
      $s2 = "Y!faME" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_038ddeb937e70aa8e1321f55c5d43b18f4cea9dd6abe63f43141ec22ccbe {
   meta:
      description = "16-07-2026-14.49 - file 038ddeb937e70aa8e1321f55c5d43b18f4cea9dd6abe63f43141ec22ccbe9825.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      description = "16-07-2026-14.49 - file 4064f42a30b85220545e4a43672e374ba879b36b3d79c4a5e2324a3ca1f6df8a.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      description = "16-07-2026-14.49 - file d0a79f28baec2beaae749a8d64dcc4d1a79cde6982a72ede58945a843b563955.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "d0a79f28baec2beaae749a8d64dcc4d1a79cde6982a72ede58945a843b563955"
   strings:
      $s1 = "Spotify: Music and Podcasts" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule a4c267819d38e8c1e85e1764115032db61bf8985711d4a5a3384891404a176fe {
   meta:
      description = "16-07-2026-14.49 - file a4c267819d38e8c1e85e1764115032db61bf8985711d4a5a3384891404a176fe.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      description = "16-07-2026-14.49 - file 3a659f0eea60ca2388eda4ea3989c15f8e5d29c54b51fc74efb599474ba943ea.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "3a659f0eea60ca2388eda4ea3989c15f8e5d29c54b51fc74efb599474ba943ea"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 4.2.2-c063 53.352624, 2008/0" ascii
      $s2 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
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

rule c5ab0adaedf391a395387df33b0bf6854f1ccc9c5da937915ea86b5eec6e6103 {
   meta:
      description = "16-07-2026-14.49 - file c5ab0adaedf391a395387df33b0bf6854f1ccc9c5da937915ea86b5eec6e6103.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "c5ab0adaedf391a395387df33b0bf6854f1ccc9c5da937915ea86b5eec6e6103"
   strings:
      $s1 = "Google Service Framework" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471e {
   meta:
      description = "16-07-2026-14.49 - file 269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471eed36.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "269a98c5a2e16675eacd3490f382ac08d894737e629b92c1a69070cc471eed36"
   strings:
      $s1 = "APK Shield Platform1" fullword ascii
      $s2 = "\\[(SoAr" fullword ascii
      $s3 = "l7P{SNeb" fullword ascii
      $s4 = "Sicurezza Banca" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46 {
   meta:
      description = "16-07-2026-14.49 - file 78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "78878d33b2b48747694ce2fdb24e896cd9ba027b1d66c66c107cf415ed46b89b"
   strings:
      $s1 = "Undo?R" fullword ascii
      $s2 = "COXy(?#2" fullword ascii
      $s3 = "veRB F<" fullword ascii
      $s4 = " PUSH " fullword ascii
      $s5 = "tgI&rAzz" fullword ascii
      $s6 = ">yese;" fullword ascii
      $s7 = "-`GLiA" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule d3fc5ffdd9a68a3063b1c8ff15334238dd39a63b9c93ec9f337bdd5f5357046a {
   meta:
      description = "16-07-2026-14.49 - file d3fc5ffdd9a68a3063b1c8ff15334238dd39a63b9c93ec9f337bdd5f5357046a.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "d3fc5ffdd9a68a3063b1c8ff15334238dd39a63b9c93ec9f337bdd5f5357046a"
   strings:
      $s1 = "/comment [hwid] [text] " fullword ascii
      $s2 = "/send [HWID] [1|2] [phone] [msg] " fullword ascii
      $s3 = "/ussd [hwid] [1|2] [number] " fullword ascii
      $s4 = "/spamallcontact [hwid] [text] " fullword ascii
      $s5 = "saUt]l" fullword ascii
      $s6 = "j}LACe" fullword ascii
      $s7 = "(Dose<i" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa825 {
   meta:
      description = "16-07-2026-14.49 - file 6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa8255405.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "6d29e6e5372cd0690e0df62eb6d98938e91191b0e639fed2476497baa8255405"
   strings:
      $s1 = "Nexi Carte" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e {
   meta:
      description = "16-07-2026-14.49 - file 9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e0ece.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "9628acabe739b5419f08c5a5c3cd776268bf4a3c25c978341e403bde442e0ece"
   strings:
      $s1 = "Intesa Carte" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9 {
   meta:
      description = "16-07-2026-14.49 - file ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "ce462b41ab7480dce4f290a9921fca51ba40e502d480a348d50770607e3d02b9"
   strings:
      $s1 = "Intesa Carte" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd {
   meta:
      description = "16-07-2026-14.49 - file d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "d29295f1504676003fd3ccbd3e41a53aabbe80d2025bfb3a6ef9a9fcff97b6cd"
   strings:
      $s1 = "Marco Verdi0" fullword ascii
      $s2 = "Marco Verdi0 " fullword ascii
      $s3 = "Intesa Carte" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_80448bc12448336f023d890b29ebf2a854f325ad010aa05d2f632870be9c {
   meta:
      description = "16-07-2026-14.49 - file 80448bc12448336f023d890b29ebf2a854f325ad010aa05d2f632870be9c8677.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "80448bc12448336f023d890b29ebf2a854f325ad010aa05d2f632870be9c8677"
   strings:
      $s1 = "sKiD:@/" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_8c7dbb2080f2b862026b2d755cb01c4b484c357c7aa5e053398ee6fe497c {
   meta:
      description = "16-07-2026-14.49 - file 8c7dbb2080f2b862026b2d755cb01c4b484c357c7aa5e053398ee6fe497c6374.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "8c7dbb2080f2b862026b2d755cb01c4b484c357c7aa5e053398ee6fe497c6374"
   strings:
      $s1 = "&ExIT?" fullword ascii
      $s2 = "werT{n" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_469b13cac1eb859da7ba4b597270f047b11815bfff9c4ad3faa5617c07a6 {
   meta:
      description = "16-07-2026-14.49 - file 469b13cac1eb859da7ba4b597270f047b11815bfff9c4ad3faa5617c07a6c3e0.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "469b13cac1eb859da7ba4b597270f047b11815bfff9c4ad3faa5617c07a6c3e0"
   strings:
      $s1 = "`lt!dAMN" fullword ascii
      $s2 = "9 JuRE,z" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_3434bad9d01dad7ad4e7525a3936c527376699e3505e70171b083c1226f0 {
   meta:
      description = "16-07-2026-14.49 - file 3434bad9d01dad7ad4e7525a3936c527376699e3505e70171b083c1226f0e90c.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "3434bad9d01dad7ad4e7525a3936c527376699e3505e70171b083c1226f0e90c"
   strings:
      $s1 = "bUMP*e" fullword ascii
      $s2 = "(qz{axOn" fullword ascii
      $s3 = "R>GoaF" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816 {
   meta:
      description = "16-07-2026-14.49 - file 05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "05417b82e39c76b0d2582709ff2d643c348837d0434c842d6d80da31e816210a"
   strings:
      $s1 = "Antivirus" fullword ascii
      $s2 = "Y!faME" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e320076 {
   meta:
      description = "16-07-2026-14.49 - file 5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "5c28134dee20ddff2f35385867cb77727da73183b0aea42ac42a5e32007625e8"
   strings:
      $s1 = "Seguridad Integral NFC" fullword ascii
      $s2 = "fRIz$s" fullword ascii
      $s3 = "CeraGo" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6 {
   meta:
      description = "16-07-2026-14.49 - file 9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "9bad10b87be2a9b52ea5778036eef5a6fd43527e5140596d0e9b0481fec6b88d"
   strings:
      $s1 = "Seguridad Integral" fullword ascii
      $s2 = "hero]~" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b {
   meta:
      description = "16-07-2026-14.49 - file e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "e494ce6af136876cba1adfe3f9d6e151f1dcf9a38059897cfb509e30e12b8c7b"
   strings:
      $s1 = "\"\"Security module is not responding." fullword ascii
      $s2 = "Security Module Active" fullword ascii
      $s3 = "Link Development1" fullword ascii
      $s4 = "aaYour device does not support NFC or you turned it off. Please enable NFC to use this application." fullword ascii
      $s5 = "FFSecurity module could not be loaded. Please reinstall the application." fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8 {
   meta:
      description = "16-07-2026-14.49 - file 22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "22b8e11e8ec946800381942a33b8b317747d14e697cb32e426f3e6fbb5c8ab3b"
   strings:
      $s1 = "Antivirus" fullword ascii
      $s2 = "*%SUit" fullword ascii
      $s3 = "Caixabank Protect" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1 {
   meta:
      description = "16-07-2026-14.49 - file 0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "0ef295b8e4eeb1374d44f9fcf68e28815a7ec8eabb22e3d3ddb5b20d9dc1f4dd"
   strings:
      $s1 = "Antivirus" fullword ascii
      $s2 = "\\@odIC" fullword ascii
      $s3 = "1,hOeR" fullword ascii
      $s4 = "Caixabank Protect" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119b {
   meta:
      description = "16-07-2026-14.49 - file 0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "0fe1d40300ed1974391f9d4e15d5f0c95119c11160d096d6571efff8119bf072"
   strings:
      $s1 = "Antivirus" fullword ascii
      $s2 = "*%SUit" fullword ascii
      $s3 = "ys({show" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb074 {
   meta:
      description = "16-07-2026-14.49 - file 13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "13d67a630b8536f27c95a0df268741a27fb08ff0ccd27bb5424a5eeeb0741f52"
   strings:
      $s1 = "Antivirus" fullword ascii
      $s2 = "Caixabank Protect" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65 {
   meta:
      description = "16-07-2026-14.49 - file f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "f4f39a97845c67f655e7fd69aa5bb1b1809054bdebc7cd06cec86345e93e1d65"
   strings:
      $s1 = "Antivirus" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_0596a76e6772acb911c1a556ad86943224873411fba4383abade25300078 {
   meta:
      description = "16-07-2026-14.49 - file 0596a76e6772acb911c1a556ad86943224873411fba4383abade25300078ed32.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "0596a76e6772acb911c1a556ad86943224873411fba4383abade25300078ed32"
   strings:
      $s1 = "[Android (8490178, based on r450784d) clang version 14.0.6 (https://android.googlesource.com/toolchain/llvm-project 4c603efb0cca" ascii
      $s2 = "[Android (8490178, based on r450784d) clang version 14.0.6 (https://android.googlesource.com/toolchain/llvm-project 4c603efb0cca" ascii
      $s3 = "chAY*R" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_4bdf7226644876c09e6091127260593a4f7af3b78d148b56004eb1be09bd {
   meta:
      description = "16-07-2026-14.49 - file 4bdf7226644876c09e6091127260593a4f7af3b78d148b56004eb1be09bdf4b8.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "4bdf7226644876c09e6091127260593a4f7af3b78d148b56004eb1be09bdf4b8"
   strings:
      $s1 = "[Android (8490178, based on r450784d) clang version 14.0.6 (https://android.googlesource.com/toolchain/llvm-project 4c603efb0cca" ascii
      $s2 = "[Android (8490178, based on r450784d) clang version 14.0.6 (https://android.googlesource.com/toolchain/llvm-project 4c603efb0cca" ascii
      $s3 = "HOrA)70" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_57151572cf361d49ead0235eef7cad3827f4711120f3397e746a660aa9c6 {
   meta:
      description = "16-07-2026-14.49 - file 57151572cf361d49ead0235eef7cad3827f4711120f3397e746a660aa9c6250b.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "57151572cf361d49ead0235eef7cad3827f4711120f3397e746a660aa9c6250b"
   strings:
      $s1 = "[Android (8490178, based on r450784d) clang version 14.0.6 (https://android.googlesource.com/toolchain/llvm-project 4c603efb0cca" ascii
      $s2 = "[Android (8490178, based on r450784d) clang version 14.0.6 (https://android.googlesource.com/toolchain/llvm-project 4c603efb0cca" ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_9aff583b812a3979394ffcd23f616d561a0eda4002f2e2a4b42ea5ba3efd {
   meta:
      description = "16-07-2026-14.49 - file 9aff583b812a3979394ffcd23f616d561a0eda4002f2e2a4b42ea5ba3efdbfaf.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "9aff583b812a3979394ffcd23f616d561a0eda4002f2e2a4b42ea5ba3efdbfaf"
   strings:
      $s1 = "[Android (8490178, based on r450784d) clang version 14.0.6 (https://android.googlesource.com/toolchain/llvm-project 4c603efb0cca" ascii
      $s2 = "[Android (8490178, based on r450784d) clang version 14.0.6 (https://android.googlesource.com/toolchain/llvm-project 4c603efb0cca" ascii
      $s3 = "GunJ;8" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_2f595b306756f39b0d525b19d5f5c1d50a5e6761ea049a63a390ec3e6709 {
   meta:
      description = "16-07-2026-14.49 - file 2f595b306756f39b0d525b19d5f5c1d50a5e6761ea049a63a390ec3e6709a2ba.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "2f595b306756f39b0d525b19d5f5c1d50a5e6761ea049a63a390ec3e6709a2ba"
   strings:
      $s1 = "qAndroid (8490178, based on r450784d) clang version 14.0.6 (https://android.googlesource.com/toolchain/llvm-project 4c603efb0cca" ascii
      $s2 = "qAndroid (8490178, based on r450784d) clang version 14.0.6 (https://android.googlesource.com/toolchain/llvm-project 4c603efb0cca" ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_39c97fad655efc5aa4bc3703695b80e9807b14050fe9c8785cd047d3f305 {
   meta:
      description = "16-07-2026-14.49 - file 39c97fad655efc5aa4bc3703695b80e9807b14050fe9c8785cd047d3f3051668.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "39c97fad655efc5aa4bc3703695b80e9807b14050fe9c8785cd047d3f3051668"
   strings:
      $s1 = "v]Pech" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_238eeea51b2d53ff08b3129fe6d6be75a13c12090e4063a1455fad614054 {
   meta:
      description = "16-07-2026-14.49 - file 238eeea51b2d53ff08b3129fe6d6be75a13c12090e4063a1455fad614054d4b3.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "238eeea51b2d53ff08b3129fe6d6be75a13c12090e4063a1455fad614054d4b3"
   strings:
      $s1 = "Z<>fAce" fullword ascii
      $s2 = ".(JYNX@" fullword ascii
      $s3 = "z}CoaX" fullword ascii
      $s4 = "M*Sier" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_8c4f8053881899f844a2e6dea8ce119124acac2b34750a47650e368c27bf {
   meta:
      description = "16-07-2026-14.49 - file 8c4f8053881899f844a2e6dea8ce119124acac2b34750a47650e368c27bf7a3b.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "8c4f8053881899f844a2e6dea8ce119124acac2b34750a47650e368c27bf7a3b"
   strings:
      $s1 = "Z<>fAce" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_17a68e32e5d8398c93790abe9b117c472557b54ccdcfccfdddb3b7f783ca {
   meta:
      description = "16-07-2026-14.49 - file 17a68e32e5d8398c93790abe9b117c472557b54ccdcfccfdddb3b7f783ca31b3.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "17a68e32e5d8398c93790abe9b117c472557b54ccdcfccfdddb3b7f783ca31b3"
   strings:
      $s1 = "Z<>fAce" fullword ascii
      $s2 = "bEsT)@" fullword ascii
      $s3 = "0[teAL" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_87def7f445734b4b9b57b97cd4af8d22b2684dd4dd3e7ae8d07a120efa3b {
   meta:
      description = "16-07-2026-14.49 - file 87def7f445734b4b9b57b97cd4af8d22b2684dd4dd3e7ae8d07a120efa3b1814.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "87def7f445734b4b9b57b97cd4af8d22b2684dd4dd3e7ae8d07a120efa3b1814"
   strings:
      $s1 = "Meta@android.com1" fullword ascii
      $s2 = "$$Allow Everspy to protect your phone." fullword ascii
      $s3 = "Phone Protector." fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule fb967e4daa07ff3777fd4495133bef6544676a315409990f68057506d706c1e4 {
   meta:
      description = "16-07-2026-14.49 - file fb967e4daa07ff3777fd4495133bef6544676a315409990f68057506d706c1e4.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "fb967e4daa07ff3777fd4495133bef6544676a315409990f68057506d706c1e4"
   strings:
      $s1 = "golF a]" fullword ascii
      $s2 = "AMar<uD" fullword ascii
      $s3 = "sLae?>" fullword ascii
      $s4 = "SofT#ru" fullword ascii
      $s5 = "FATE}t" fullword ascii
      $s6 = "GiBEL:" fullword ascii
      $s7 = "KELp{+" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule c002e68f52de1b2b62013a82828245d8a956a075b87e220c3f6e1b2bfb220d19 {
   meta:
      description = "16-07-2026-14.49 - file c002e68f52de1b2b62013a82828245d8a956a075b87e220c3f6e1b2bfb220d19.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "c002e68f52de1b2b62013a82828245d8a956a075b87e220c3f6e1b2bfb220d19"
   strings:
      $s1 = "rEAD)%d" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule bede3630686cc90e359bc52567d72198ca97c527d5ebadda922208b93b7cf94e {
   meta:
      description = "16-07-2026-14.49 - file bede3630686cc90e359bc52567d72198ca97c527d5ebadda922208b93b7cf94e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "bede3630686cc90e359bc52567d72198ca97c527d5ebadda922208b93b7cf94e"
   strings:
      $s1 = "Simple Miner" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule dc2a780f6abb9f0ec0a6675f20acb91ebe2a8748297682a59daf9164fbea2ee8 {
   meta:
      description = "16-07-2026-14.49 - file dc2a780f6abb9f0ec0a6675f20acb91ebe2a8748297682a59daf9164fbea2ee8.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "dc2a780f6abb9f0ec0a6675f20acb91ebe2a8748297682a59daf9164fbea2ee8"
   strings:
      $s1 = "ShOU&k" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0 {
   meta:
      description = "16-07-2026-14.49 - file 4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "4ee3b09dd9a787ebbb02a637f8af192a7e91d4b7af1515d8e5c21e1233f0f1c7"
   strings:
      $s1 = "SOUD!~" fullword ascii
      $s2 = "Update Now" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_37aea8c8ed8ea55d23da37d997e82e6cc34bf80bce891378be7543adf667 {
   meta:
      description = "16-07-2026-14.49 - file 37aea8c8ed8ea55d23da37d997e82e6cc34bf80bce891378be7543adf6678ea1.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "37aea8c8ed8ea55d23da37d997e82e6cc34bf80bce891378be7543adf6678ea1"
   strings:
      $s1 = "App Configuration" fullword ascii
      $s2 = "))Security scan complete. No threats found." fullword ascii
      $s3 = "::Oops! Failed to open Google Play. " fullword ascii
      $s4 = "77Welcome to SecureGuard. Your device security companion." fullword ascii
      $s5 = "Android Security0" fullword ascii
      $s6 = "Optimization in progress" fullword ascii
      $s7 = "Display Enhancement" fullword ascii
      $s8 = "Open Google Play" fullword ascii
      $s9 = "Please open it manually" fullword ascii
      $s10 = "==Device administrator access is required for security features" fullword ascii
      $s11 = "Android Security0 " fullword ascii
      $s12 = "Hide App Icon" fullword ascii
      $s13 = "WWAssists with application configuration and settings management for optimal performance." fullword ascii
      $s14 = "ddEnables display optimization and enhanced text rendering for better readability across applications." fullword ascii
      $s15 = "77Manages notification display and delivery optimization." fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3 {
   meta:
      description = "16-07-2026-14.49 - file d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "d22d9a9147b8c5b78a60e0775993ad103b6674d2f8468b5b58fae1b23b1561a3"
   strings:
      $s1 = "Acme Corp1" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_49b40786a01886ad8e962bd74e5d2e3ede8472de5cabe7b060284c54e594 {
   meta:
      description = "16-07-2026-14.49 - file 49b40786a01886ad8e962bd74e5d2e3ede8472de5cabe7b060284c54e5941182.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "49b40786a01886ad8e962bd74e5d2e3ede8472de5cabe7b060284c54e5941182"
   strings:
      $s1 = "service player" fullword ascii
      $s2 = "media player" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule f3fe34702fefe9dfb8bf50f2d2ca475a8a3150f3dee3c07b09994947d540b3a1 {
   meta:
      description = "16-07-2026-14.49 - file f3fe34702fefe9dfb8bf50f2d2ca475a8a3150f3dee3c07b09994947d540b3a1.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "f3fe34702fefe9dfb8bf50f2d2ca475a8a3150f3dee3c07b09994947d540b3a1"
   strings:
      $s1 = "service player" fullword ascii
      $s2 = "media player" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_834598be4061e6687a92dcaa1b6d992125df1b5fb6e72de5a4e8dbbbb515 {
   meta:
      description = "16-07-2026-14.49 - file 834598be4061e6687a92dcaa1b6d992125df1b5fb6e72de5a4e8dbbbb51592ed.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "834598be4061e6687a92dcaa1b6d992125df1b5fb6e72de5a4e8dbbbb51592ed"
   strings:
      $s1 = "5Java Object Signing O=Amazon Services LLC L=Las Vegas1" fullword ascii
      $s2 = "\"\"Mobile Device Information Provider" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90b {
   meta:
      description = "16-07-2026-14.49 - file 090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90ba268.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "090a30252991830596c75a945885ca3100d7a40edf4a16d78abd5bbfd90ba268"
   strings:
      $s1 = "Banca Sella Carte" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5 {
   meta:
      description = "16-07-2026-14.49 - file 3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5dce6.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "3c81526bcb801d7dcfaea7f379528471d745a36e3c1bdc41877b4bed34b5dce6"
   strings:
      $s1 = "Sella NFC" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e4 {
   meta:
      description = "16-07-2026-14.49 - file 21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e494fe.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "21c91c4cb01c7fd286dc8fa6122f6c43a5227677ffbe3566aa37204cd9e494fe"
   strings:
      $s1 = "Intesa Carte" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf265 {
   meta:
      description = "16-07-2026-14.49 - file 7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf26527b7.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "7fb836c08ff527443b06d1c20afb6a4b0f51eb373013f211e0d3200bf26527b7"
   strings:
      $s1 = "Paolo Verdi0" fullword ascii
      $s2 = "Paolo Verdi0 " fullword ascii
      $s3 = "Klirway Carte" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d962416 {
   meta:
      description = "16-07-2026-14.49 - file 091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d96241620a5.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "091870b3f90c9a98000e0d14a67be2db5891ce98a0b1e24b721e3d96241620a5"
   strings:
      $s1 = "BCC Roma Carte" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e {
   meta:
      description = "16-07-2026-14.49 - file 752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e40ab.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "752f3cacdad6753d4c02bb8e40ef3e0990b55466c18a7b80ec6fa7b9706e40ab"
   strings:
      $s1 = "Marco Colombo0 " fullword ascii
      $s2 = "Marco Colombo0" fullword ascii
      $s3 = "Intesa Carte" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5 {
   meta:
      description = "16-07-2026-14.49 - file d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "d6a2869ee450abd15fbd16519d83271f9c60dcba79540675da72726a767f1bc5"
   strings:
      $s1 = "Support Nexi" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_09eb87493c014406a0d83996a8b1894da5257fd6166921878a9bbd42b1e9 {
   meta:
      description = "16-07-2026-14.49 - file 09eb87493c014406a0d83996a8b1894da5257fd6166921878a9bbd42b1e9390e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "09eb87493c014406a0d83996a8b1894da5257fd6166921878a9bbd42b1e9390e"
   strings:
      $s1 = "Linear Launcher" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule aa3b976475e375e92f09bf4b06db50693ad42dd7c0abfcbfd598f3e9d46f0744 {
   meta:
      description = "16-07-2026-14.49 - file aa3b976475e375e92f09bf4b06db50693ad42dd7c0abfcbfd598f3e9d46f0744.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "aa3b976475e375e92f09bf4b06db50693ad42dd7c0abfcbfd598f3e9d46f0744"
   strings:
      $s1 = "service player" fullword ascii
      $s2 = "media player" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_7a449a292f2498734e22aa7f43857fda0d34f81910ffb8a85cd679eb9c36 {
   meta:
      description = "16-07-2026-14.49 - file 7a449a292f2498734e22aa7f43857fda0d34f81910ffb8a85cd679eb9c3694de.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "7a449a292f2498734e22aa7f43857fda0d34f81910ffb8a85cd679eb9c3694de"
   strings:
      $s1 = "System Services" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee {
   meta:
      description = "16-07-2026-14.49 - file faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "faa92121e822c424923702e3d5848ec2f3b16898b149a179520aee3bd4dceaee"
   strings:
      $s1 = "k`draw" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_68f800fbed83116ac9efb2524326fa5d710a911b506762d580a34c19932a {
   meta:
      description = "16-07-2026-14.49 - file 68f800fbed83116ac9efb2524326fa5d710a911b506762d580a34c19932a21e8.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "68f800fbed83116ac9efb2524326fa5d710a911b506762d580a34c19932a21e8"
   strings:
      $s1 = "g:pOll" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_5a2306804771a975f692d6cc1cbaf06af1b86273301b3af8069f4d36a27d {
   meta:
      description = "16-07-2026-14.49 - file 5a2306804771a975f692d6cc1cbaf06af1b86273301b3af8069f4d36a27d3866.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "5a2306804771a975f692d6cc1cbaf06af1b86273301b3af8069f4d36a27d3866"
   strings:
      $s1 = "O>RoOM" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_41ac10108b6d118ba6e27429d4cd12805d56d2898d61c9a7808f8a43a21f {
   meta:
      description = "16-07-2026-14.49 - file 41ac10108b6d118ba6e27429d4cd12805d56d2898d61c9a7808f8a43a21f1d22.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "41ac10108b6d118ba6e27429d4cd12805d56d2898d61c9a7808f8a43a21f1d22"
   strings:
      $s1 = "Public Domain http://creativecommons.org/licenses/publicdomain/Y" fullword ascii
      $s2 = "Installer" fullword wide /* base64 encoded string '"{-jY^' */
      $s3 = "Context" fullword wide
      $s4 = "Go Down" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule faf71cb7a1ccb81896e2eccf26fd106cafd357aa20c0533d04a3bd8947325d19 {
   meta:
      description = "16-07-2026-14.49 - file faf71cb7a1ccb81896e2eccf26fd106cafd357aa20c0533d04a3bd8947325d19.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "faf71cb7a1ccb81896e2eccf26fd106cafd357aa20c0533d04a3bd8947325d19"
   strings:
      $s1 = "LUDO BD" fullword ascii
      $s2 = "Powered by Developer Opurbo" fullword ascii
      $s3 = "BF LUDO" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e390 {
   meta:
      description = "16-07-2026-14.49 - file 64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "64a9263148d49bbabaf13b68fc461c93275d5d7f852288ccf00d1b25e39069d3"
   strings:
      $s1 = "i}pOLt" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule faa774978f43368357f553a1e45a2f9465fcfa50c6c09dbf6004304db03bc641 {
   meta:
      description = "16-07-2026-14.49 - file faa774978f43368357f553a1e45a2f9465fcfa50c6c09dbf6004304db03bc641.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "faa774978f43368357f553a1e45a2f9465fcfa50c6c09dbf6004304db03bc641"
   strings:
      $s1 = "DOGe!RNAg" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_327a404f2ff2562d7e7f49e9fca68bb814128eef47dfea688680de3da91b {
   meta:
      description = "16-07-2026-14.49 - file 327a404f2ff2562d7e7f49e9fca68bb814128eef47dfea688680de3da91b04cd.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "327a404f2ff2562d7e7f49e9fca68bb814128eef47dfea688680de3da91b04cd"
   strings:
      $s1 = "X@PlOy" fullword ascii
      $s2 = "*mIcE>Z" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_4af08f08377457cb04e280615fc8647870f9b20ad763e1bd060731605d8a {
   meta:
      description = "16-07-2026-14.49 - file 4af08f08377457cb04e280615fc8647870f9b20ad763e1bd060731605d8a0c07.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "4af08f08377457cb04e280615fc8647870f9b20ad763e1bd060731605d8a0c07"
   strings:
      $s1 = "Core Solutions1" fullword ascii
      $s2 = "Lite Platform0 " fullword ascii
      $s3 = "Lite Platform0" fullword ascii
      $s4 = "y;FUzz" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule cb93d5c96ae3e0b358ac2a0c57008a5655a049ac3bc5543f814af5157e2f27de {
   meta:
      description = "16-07-2026-14.49 - file cb93d5c96ae3e0b358ac2a0c57008a5655a049ac3bc5543f814af5157e2f27de.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "cb93d5c96ae3e0b358ac2a0c57008a5655a049ac3bc5543f814af5157e2f27de"
   strings:
      $s1 = "hack Block Blast" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_0bd64f2bfd3b3d5427adfeb8bb72d2522d9758c80995bcf09a60c8631e0f {
   meta:
      description = "16-07-2026-14.49 - file 0bd64f2bfd3b3d5427adfeb8bb72d2522d9758c80995bcf09a60c8631e0f1d34.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "0bd64f2bfd3b3d5427adfeb8bb72d2522d9758c80995bcf09a60c8631e0f1d34"
   strings:
      $s1 = "delta BETA" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule fd57efac4a5b16fef63d10eb1e8fcbd69d21c2f136d6c5b1de4b0b44455c87e6 {
   meta:
      description = "16-07-2026-14.49 - file fd57efac4a5b16fef63d10eb1e8fcbd69d21c2f136d6c5b1de4b0b44455c87e6.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "fd57efac4a5b16fef63d10eb1e8fcbd69d21c2f136d6c5b1de4b0b44455c87e6"
   strings:
      $s1 = "Client Play" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_280df905ee0f6fb2539cd85c5b31b8bf403d91363fa6a108e48e58e85c72 {
   meta:
      description = "16-07-2026-14.49 - file 280df905ee0f6fb2539cd85c5b31b8bf403d91363fa6a108e48e58e85c721894.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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

rule sig_7922ffb7deea4e27a59fde82551a869354d12c3c8d57a49e4604cc809854 {
   meta:
      description = "16-07-2026-14.49 - file 7922ffb7deea4e27a59fde82551a869354d12c3c8d57a49e4604cc809854df24.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "7922ffb7deea4e27a59fde82551a869354d12c3c8d57a49e4604cc809854df24"
   strings:
      $s1 = "JEFF:\\E" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3b {
   meta:
      description = "16-07-2026-14.49 - file 9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3bb5d1.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "9c4315dad05f9f70982630ff023a6073d6badaed840130ce1342ca9ebf3bb5d1"
   strings:
      $s1 = "Support Nexi" fullword ascii
      $s2 = "l%CuRR" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4 {
   meta:
      description = "16-07-2026-14.49 - file afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "afbe6751d339fbc5b7bddd29429a11740e82fef935a61acaf2fe5487444dbed4"
   strings:
      $s1 = "Support Nexi" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule b3c1d5fc273d19556b09f935b9b09b782b113b98a8a010ebcbb5de5bfce77e67 {
   meta:
      description = "16-07-2026-14.49 - file b3c1d5fc273d19556b09f935b9b09b782b113b98a8a010ebcbb5de5bfce77e67.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "b3c1d5fc273d19556b09f935b9b09b782b113b98a8a010ebcbb5de5bfce77e67"
   strings:
      $s1 = "System Update0" fullword ascii
      $s2 = "Core Services1" fullword ascii
      $s3 = "System Update0 " fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_6ef32b6c01b2199a6be9339006b58f6af5ec288d9249ebf649ef6e2eb7a3 {
   meta:
      description = "16-07-2026-14.49 - file 6ef32b6c01b2199a6be9339006b58f6af5ec288d9249ebf649ef6e2eb7a34d57.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "6ef32b6c01b2199a6be9339006b58f6af5ec288d9249ebf649ef6e2eb7a34d57"
   strings:
      $s1 = "RagA}\"^" fullword ascii
      $s2 = "urnA!6" fullword ascii
      $s3 = "RaKI]mJ" fullword ascii
      $s4 = ";N`LeaL<" fullword ascii
      $s5 = ";A<FOWL" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_7c25f1090921bb3692900dc333a466fad7feb25631cb2fd2fc7f85ab1eaf {
   meta:
      description = "16-07-2026-14.49 - file 7c25f1090921bb3692900dc333a466fad7feb25631cb2fd2fc7f85ab1eaf729f.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "7c25f1090921bb3692900dc333a466fad7feb25631cb2fd2fc7f85ab1eaf729f"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s2 = "obe.com/xap/1.0/sType/ResourceRef#\" xmp:CreatorTool=\"Adobe Photoshop CS5 Windows\" xmp:CreateDate=\"2024-04-24T13:49:08+03:00" ascii
      $s3 = "tanceID=\"xmp.iid:F84FA4592B03EF11A622E254C2D4027D\" stEvt:when=\"2024-04-25T20:43:39+03:00\" stEvt:softwareAgent=\"Adobe Photos" ascii
      $s4 = "nstanceID=\"xmp.iid:037A300D2D02EF1197F3FC09901BE074\" stEvt:when=\"2024-04-24T14:34:43+03:00\" stEvt:softwareAgent=\"Adobe Phot" ascii
      $s5 = "reAgent=\"Adobe Photoshop CS5 Windows\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.iid:F74FA459" ascii
      $s6 = "04-24T14:23:18+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CS5 Windows\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"saved\" " ascii
      $s7 = ":when=\"2024-04-24T14:34:43+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CS5 Windows\" stEvt:changed=\"/\"/> <rdf:li stEvt:acti" ascii
      $s8 = "02EF1197F3FC09901BE074\" xmpMM:OriginalDocumentID=\"xmp.did:FB79300D2D02EF1197F3FC09901BE074\"> <xmpMM:History> <rdf:Seq> <rdf:l" ascii
      $s9 = "BE074\" stEvt:when=\"2024-04-24T17:46:03+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CS5 Windows\" stEvt:changed=\"/\"/> <rdf:" ascii
      $s10 = "1A622E254C2D4027D\" stEvt:when=\"2024-04-25T20:43:39+03:00\" stEvt:softwareAgent=\"Adobe Photoshop CS5 Windows\" stEvt:changed=" ascii
      $s11 = "S5 Windows\" stEvt:changed=\"/\"/> </rdf:Seq> </xmpMM:History> <xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:F74FA4592B03EF11A62" ascii
      $s12 = "Uncensuring" fullword ascii
      $s13 = "Manufactory" fullword ascii
      $s14 = "Cystoproctostomy" fullword ascii
      $s15 = "Transformable" fullword ascii
      $s16 = "Hydromyoma" fullword ascii
      $s17 = "Irritative" fullword ascii
      $s18 = "Unforgot" fullword ascii
      $s19 = "Unvisor" fullword ascii
      $s20 = "Disheartener" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule sig_5a8d4eabd009a75ecc04f3f06489d393f082f963b406d0d3e8acbea56828 {
   meta:
      description = "16-07-2026-14.49 - file 5a8d4eabd009a75ecc04f3f06489d393f082f963b406d0d3e8acbea568281c5f.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "5a8d4eabd009a75ecc04f3f06489d393f082f963b406d0d3e8acbea568281c5f"
   strings:
      $s1 = "Digital Services0 " fullword ascii
      $s2 = "Digital Services0" fullword ascii
      $s3 = "Innovation Lab1" fullword ascii
      $s4 = "tHen&Yf</" fullword ascii
      $s5 = "Pulse Tech1" fullword ascii
      $s6 = "dolT&z" fullword ascii
      $s7 = "piCO[*" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_1077e767d28e8b97be3ebc98ceab110c14335260b47a3a0fdfcb77b6a2cc {
   meta:
      description = "16-07-2026-14.49 - file 1077e767d28e8b97be3ebc98ceab110c14335260b47a3a0fdfcb77b6a2ccf080.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "1077e767d28e8b97be3ebc98ceab110c14335260b47a3a0fdfcb77b6a2ccf080"
   strings:
      $s1 = "]Thew{}_" fullword ascii
      $s2 = "W{swig" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_340d1ff4143a560c2ca4400a6c2ca6e9448b6392c203ec190893e773b7a0 {
   meta:
      description = "16-07-2026-14.49 - file 340d1ff4143a560c2ca4400a6c2ca6e9448b6392c203ec190893e773b7a00265.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "340d1ff4143a560c2ca4400a6c2ca6e9448b6392c203ec190893e773b7a00265"
   strings:
      $s1 = "[RUVId" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_57a0a81eebdf6c1e0a5ab0489165f167856712121b86959f0c34ce5c2401 {
   meta:
      description = "16-07-2026-14.49 - file 57a0a81eebdf6c1e0a5ab0489165f167856712121b86959f0c34ce5c24014266.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "57a0a81eebdf6c1e0a5ab0489165f167856712121b86959f0c34ce5c24014266"
   strings:
      $s1 = "Yqr(SEer!" fullword ascii
      $s2 = " $murk" fullword ascii
      $s3 = "KG{koNa" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_557c02b5e9ca8103e6ad5413df1b447fae5c9ce086a0b5330bf9c79a5785 {
   meta:
      description = "16-07-2026-14.49 - file 557c02b5e9ca8103e6ad5413df1b447fae5c9ce086a0b5330bf9c79a578585df.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "557c02b5e9ca8103e6ad5413df1b447fae5c9ce086a0b5330bf9c79a578585df"
   strings:
      $s1 = "Service Platform0" fullword ascii
      $s2 = "Service Platform0 " fullword ascii
      $s3 = "Lumen Tech1" fullword ascii
      $s4 = "hEML[\"tO" fullword ascii
      $s5 = "AVG ANTIVIRUS" fullword ascii
      $s6 = "LoWy$$-" fullword ascii
      $s7 = "FecK .6n" fullword ascii
      $s8 = "Mark<|t*" fullword ascii
      $s9 = "7*HueD" fullword ascii
      $s10 = ":ALee}" fullword ascii
      $s11 = "<cLoW." fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule e9b41fd64d8702f974e63374a03ad914b6f1b24e8ddd96c29ff14ce81713676f {
   meta:
      description = "16-07-2026-14.49 - file e9b41fd64d8702f974e63374a03ad914b6f1b24e8ddd96c29ff14ce81713676f.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "e9b41fd64d8702f974e63374a03ad914b6f1b24e8ddd96c29ff14ce81713676f"
   strings:
      $s1 = "tHen&Yf</" fullword ascii
      $s2 = "Digital Workspace0" fullword ascii
      $s3 = "Product Engineering1" fullword ascii
      $s4 = "Digital Workspace0 " fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule c59271342ba9c0d6eae9d46ae14d91d62e5eb31c102440249f44f10b32e0e82c {
   meta:
      description = "16-07-2026-14.49 - file c59271342ba9c0d6eae9d46ae14d91d62e5eb31c102440249f44f10b32e0e82c.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "c59271342ba9c0d6eae9d46ae14d91d62e5eb31c102440249f44f10b32e0e82c"
   strings:
      $s1 = "CONTENT" fullword wide
      $s2 = "Hello world!" fullword wide
      $s3 = "Support" fullword wide
      $s4 = "HD Porno Video" fullword wide
      $s5 = "Dummy Button" fullword wide
      $s6 = "<b><font color=red>" fullword wide
      $s7 = "S>HisH" fullword ascii
      $s8 = "L)KelT" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_121e82504dfbada0fd5cec2bd6bec7a518f8afce65b43ded20498f3f5cb5 {
   meta:
      description = "16-07-2026-14.49 - file 121e82504dfbada0fd5cec2bd6bec7a518f8afce65b43ded20498f3f5cb5c05c.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "121e82504dfbada0fd5cec2bd6bec7a518f8afce65b43ded20498f3f5cb5c05c"
   strings:
      $s1 = "aReD(-u." fullword ascii
      $s2 = "=?nEtI'" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule ddfb37acf2abc5458c9a7003e4f0559b615bf5ba0334a3801b1e3bb694733c79 {
   meta:
      description = "16-07-2026-14.49 - file ddfb37acf2abc5458c9a7003e4f0559b615bf5ba0334a3801b1e3bb694733c79.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "ddfb37acf2abc5458c9a7003e4f0559b615bf5ba0334a3801b1e3bb694733c79"
   strings:
      $s1 = "ISBA?w-" fullword ascii
      $s2 = "rOKA}k" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule cc8f90a002a2ed7579451d7b920ae3b44ac65bd12dbeea960dcad5fed6cb3ef3 {
   meta:
      description = "16-07-2026-14.49 - file cc8f90a002a2ed7579451d7b920ae3b44ac65bd12dbeea960dcad5fed6cb3ef3.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "cc8f90a002a2ed7579451d7b920ae3b44ac65bd12dbeea960dcad5fed6cb3ef3"
   strings:
      $s1 = "i\"VeeR" fullword ascii
      $s2 = "yIRk'm" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_9a1ac04b85cc6f35cd83382f258254556a37f1fc314020dbecbde033caa0 {
   meta:
      description = "16-07-2026-14.49 - file 9a1ac04b85cc6f35cd83382f258254556a37f1fc314020dbecbde033caa00a8d.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "9a1ac04b85cc6f35cd83382f258254556a37f1fc314020dbecbde033caa00a8d"
   strings:
      $s1 = "DucK .q" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule bc3a1a786fad739f423c05fcbdcdb999920547c03a183fce68aa1631b25f1c08 {
   meta:
      description = "16-07-2026-14.49 - file bc3a1a786fad739f423c05fcbdcdb999920547c03a183fce68aa1631b25f1c08.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "bc3a1a786fad739f423c05fcbdcdb999920547c03a183fce68aa1631b25f1c08"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s2 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s3 = "f:documentID=\"xmp.did:275542D3645D11E6A77985FABB9A8A21\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta> <?xpacket end=\"r\"?>Q" fullword ascii
      $s4 = "f:documentID=\"xmp.did:1B747E2E644D11E68F33D2853E61CE9A\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta> <?xpacket end=\"r\"?>" fullword ascii
      $s5 = "=\"xmp.did:1B747E30644D11E68F33D2853E61CE9A\"> <xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:1B747E2D644D11E68F33D2853E61CE9A\" " ascii
      $s6 = "f#\" xmp:CreatorTool=\"Adobe Photoshop CS6 (Windows)\" xmpMM:InstanceID=\"xmp.iid:1B747E2F644D11E68F33D2853E61CE9A\" xmpMM:Docum" ascii
      $s7 = "=\"xmp.did:275542D5645D11E6A77985FABB9A8A21\"> <xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:275542D2645D11E6A77985FABB9A8A21\" " ascii
      $s8 = "f#\" xmp:CreatorTool=\"Adobe Photoshop CS6 (Windows)\" xmpMM:InstanceID=\"xmp.iid:275542D4645D11E6A77985FABB9A8A21\" xmpMM:Docum" ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_261305ccbee49fc67c13d275e5788fdc3db8b6a85ec99de16130be93130b {
   meta:
      description = "16-07-2026-14.49 - file 261305ccbee49fc67c13d275e5788fdc3db8b6a85ec99de16130be93130bcb19.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "261305ccbee49fc67c13d275e5788fdc3db8b6a85ec99de16130be93130bcb19"
   strings:
      $s1 = "sExfid)V" fullword ascii
      $s2 = "`!BadE" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule b6ad0b8a6caa9ab7e5df55bb29d3720225a3d5292ec6d54fada0a4153fb2f02d {
   meta:
      description = "16-07-2026-14.49 - file b6ad0b8a6caa9ab7e5df55bb29d3720225a3d5292ec6d54fada0a4153fb2f02d.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "b6ad0b8a6caa9ab7e5df55bb29d3720225a3d5292ec6d54fada0a4153fb2f02d"
   strings:
      $s1 = "CElt%$)" fullword ascii
      $s2 = "U whyo" fullword ascii
      $s3 = "C)MATh" fullword ascii
      $s4 = "(bEre%B" fullword ascii
      $s5 = ")BOSE]" fullword ascii
      $s6 = "TAre[ " fullword ascii
      $s7 = "9]almE" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule c3c107ff3419beb378d3e26727aad8089c42bc688b3c79fa981260e93b66ca73 {
   meta:
      description = "16-07-2026-14.49 - file c3c107ff3419beb378d3e26727aad8089c42bc688b3c79fa981260e93b66ca73.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "c3c107ff3419beb378d3e26727aad8089c42bc688b3c79fa981260e93b66ca73"
   strings:
      $s1 = "WEEd}>F" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule f9b00165598a0600d53064b2871477fec3bd62549a69328c4bdd39467af2d48d {
   meta:
      description = "16-07-2026-14.49 - file f9b00165598a0600d53064b2871477fec3bd62549a69328c4bdd39467af2d48d.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "f9b00165598a0600d53064b2871477fec3bd62549a69328c4bdd39467af2d48d"
   strings:
      $s1 = "      <rdf:Description" fullword ascii
      $s2 = "         stEvt:softwareAgent=\"Adobe Premiere Pro 2020.0 (Windows)\"" fullword ascii
      $s3 = "      stEvt:softwareAgent=\"Adobe Premiere Pro 2020.0 (Windows)\"" fullword ascii
      $s4 = "Standoff 2" fullword ascii
      $s5 = "      stEvt:softwareAgent=\"Adobe Premiere Pro 2020.0 (Windows)\"/>" fullword ascii
      $s6 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c148 79.164036, 2019/08/13-01:06:57        \">" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule d778ecb3738036fe02b0cc768417d7f4101d2c22111ae3c4cddc6489802b2d4b {
   meta:
      description = "16-07-2026-14.49 - file d778ecb3738036fe02b0cc768417d7f4101d2c22111ae3c4cddc6489802b2d4b.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "d778ecb3738036fe02b0cc768417d7f4101d2c22111ae3c4cddc6489802b2d4b"
   strings:
      $s1 = "4%JIbI`" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule a4fd3292b7bc5800f8d9b3a3e4c6a757daeb0800cae762cf2294012cee5604f5 {
   meta:
      description = "16-07-2026-14.49 - file a4fd3292b7bc5800f8d9b3a3e4c6a757daeb0800cae762cf2294012cee5604f5.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "a4fd3292b7bc5800f8d9b3a3e4c6a757daeb0800cae762cf2294012cee5604f5"
   strings:
      $s1 = ">shIRr" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_86acd31a7de65743ad8135ee5e3dc90d076dd9cda5d2fb8be9b45e5f5cb8 {
   meta:
      description = "16-07-2026-14.49 - file 86acd31a7de65743ad8135ee5e3dc90d076dd9cda5d2fb8be9b45e5f5cb8b3a0.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "86acd31a7de65743ad8135ee5e3dc90d076dd9cda5d2fb8be9b45e5f5cb8b3a0"
   strings:
      $s1 = "      <rdf:Description" fullword ascii
      $s2 = "      stEvt:softwareAgent=\"Adobe Premiere Pro CC 2017.1 (Windows)\"" fullword ascii
      $s3 = "         stEvt:softwareAgent=\"Adobe Premiere Pro CC 2017.1 (Windows)\"" fullword ascii
      $s4 = "      stEvt:softwareAgent=\"Adobe Premiere Pro CC 2017.1 (Windows)\"/>" fullword ascii
      $s5 = "#\"*LYAM" fullword ascii
      $s6 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c140 79.160302, 2017/03/02-16:59:38        \">" fullword ascii
      $s7 = "      stRef:filePath=\"(WARNING_ EXTREMELY LOUD) Scary Screamer.mp4\"" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule f7a9da64386f6c02c3911c73ff6754118deb3cae20e52abfb85bbc855b404aca {
   meta:
      description = "16-07-2026-14.49 - file f7a9da64386f6c02c3911c73ff6754118deb3cae20e52abfb85bbc855b404aca.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "f7a9da64386f6c02c3911c73ff6754118deb3cae20e52abfb85bbc855b404aca"
   strings:
      $s1 = "0\"jIna" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule e3dedeedfa33296dcc07590df9a3735e92c5dd23e4940a6b1caaa44460eaca76 {
   meta:
      description = "16-07-2026-14.49 - file e3dedeedfa33296dcc07590df9a3735e92c5dd23e4940a6b1caaa44460eaca76.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "e3dedeedfa33296dcc07590df9a3735e92c5dd23e4940a6b1caaa44460eaca76"
   strings:
      $s1 = "uuMozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36" fullword ascii
      $s2 = "/(y$i+1h%EyeY" fullword ascii
      $s3 = "bAKU;~1" fullword ascii
      $s4 = "REVE%!F" fullword ascii
      $s5 = "tIMe]:d" fullword ascii
      $s6 = "ETUA%4r" fullword ascii
      $s7 = "HAdj'P" fullword ascii
      $s8 = "*tOny." fullword ascii
      $s9 = "maRL}*" fullword ascii
      $s10 = "CF\\^\"dodo" fullword ascii
      $s11 = "'<SCyE" fullword ascii
      $s12 = ";eNoIL" fullword ascii
      $s13 = ". `bATTA" fullword ascii
      $s14 = "<8Kj8%]GNaT" fullword ascii
      $s15 = "x\"CesT" fullword ascii
      $s16 = "whEer$" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      8 of them
}

rule e292d45072e4c2569785cbe4ea66daa355af74295bb8b266d5bfcf18d816b26b {
   meta:
      description = "16-07-2026-14.49 - file e292d45072e4c2569785cbe4ea66daa355af74295bb8b266d5bfcf18d816b26b.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      description = "16-07-2026-14.49 - file 4cf809b14083143e921bd8fdb7e7725e20e303653d9a3e6c848d9596a33f6c8e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "4cf809b14083143e921bd8fdb7e7725e20e303653d9a3e6c848d9596a33f6c8e"
   strings:
      $s1 = "Player Videos" fullword ascii
      $s2 = "&&&coss" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule bc877d871e342272ef65e4e8fd3fc5101e7447f51884705037ad67d8821d4ba1 {
   meta:
      description = "16-07-2026-14.49 - file bc877d871e342272ef65e4e8fd3fc5101e7447f51884705037ad67d8821d4ba1.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "bc877d871e342272ef65e4e8fd3fc5101e7447f51884705037ad67d8821d4ba1"
   strings:
      $s1 = "JuDO>~" fullword ascii
      $s2 = "`!BadE" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_951c94809aa6c7ab587125f9d4df30fa6a49ee0cbba76a4b7ceedaaa0e5d {
   meta:
      description = "16-07-2026-14.49 - file 951c94809aa6c7ab587125f9d4df30fa6a49ee0cbba76a4b7ceedaaa0e5dcd36.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "951c94809aa6c7ab587125f9d4df30fa6a49ee0cbba76a4b7ceedaaa0e5dcd36"
   strings:
      $s1 = "`!BadE" fullword ascii
      $s2 = "|:lIJa>" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule f07821e313c16cbbd82def45094a22c8d474164051bdbc7648d6869e012014b4 {
   meta:
      description = "16-07-2026-14.49 - file f07821e313c16cbbd82def45094a22c8d474164051bdbc7648d6869e012014b4.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      description = "16-07-2026-14.49 - file 1fc3ba39f0ce8109bcb4f42441250df5e9c601744b738a2e7c40d612cd29fec3.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "1fc3ba39f0ce8109bcb4f42441250df5e9c601744b738a2e7c40d612cd29fec3"
   strings:
      $s1 = "warty loader" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule d47e517027efcdaae2280f6661fdf85a8429db585939776706e779fe2e373f0c {
   meta:
      description = "16-07-2026-14.49 - file d47e517027efcdaae2280f6661fdf85a8429db585939776706e779fe2e373f0c.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "d47e517027efcdaae2280f6661fdf85a8429db585939776706e779fe2e373f0c"
   strings:
      $s1 = "%?Fumy" fullword ascii
      $s2 = "G]sisS" fullword ascii
      $s3 = "HDI\\?k`\"LoWy" fullword ascii
      $s4 = "TacK*@" fullword ascii
      $s5 = "tUan['" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b {
   meta:
      description = "16-07-2026-14.49 - file 9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b3306.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "9e95912f1a5fdba5050723f095b7031770b7e2f9627fb60544b41adcbb5b3306"
   strings:
      $s1 = "Fideuram Carte" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule e7e2f8e9d085fed04549fcbd6d6f4374541c40ade814181b732d6075228683df {
   meta:
      description = "16-07-2026-14.49 - file e7e2f8e9d085fed04549fcbd6d6f4374541c40ade814181b732d6075228683df.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "e7e2f8e9d085fed04549fcbd6d6f4374541c40ade814181b732d6075228683df"
   strings:
      $s1 = "chiT&@" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule ee3f6b75ecceef229900944aa924a21d65ed5eb7f0388c763717c791fcd6e2b4 {
   meta:
      description = "16-07-2026-14.49 - file ee3f6b75ecceef229900944aa924a21d65ed5eb7f0388c763717c791fcd6e2b4.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "ee3f6b75ecceef229900944aa924a21d65ed5eb7f0388c763717c791fcd6e2b4"
   strings:
      $s1 = "chiT&@" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule b89c57f8781f121938b50631295f96ddf25f18616dcfb4862a7a87a61f0bf7ad {
   meta:
      description = "16-07-2026-14.49 - file b89c57f8781f121938b50631295f96ddf25f18616dcfb4862a7a87a61f0bf7ad.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "b89c57f8781f121938b50631295f96ddf25f18616dcfb4862a7a87a61f0bf7ad"
   strings:
      $s1 = "COOM]VY9" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule e312f8161450d57ae1232673a53cdb63af75b8fe610765224bf2e1da881e1a8d {
   meta:
      description = "16-07-2026-14.49 - file e312f8161450d57ae1232673a53cdb63af75b8fe610765224bf2e1da881e1a8d.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "e312f8161450d57ae1232673a53cdb63af75b8fe610765224bf2e1da881e1a8d"
   strings:
      $s1 = "[RUVId" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule fa2a7e4f080ce26715e69732901e80ef2d44f0666fa25c41ee52da9e7c2c4388 {
   meta:
      description = "16-07-2026-14.49 - file fa2a7e4f080ce26715e69732901e80ef2d44f0666fa25c41ee52da9e7c2c4388.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "fa2a7e4f080ce26715e69732901e80ef2d44f0666fa25c41ee52da9e7c2c4388"
   strings:
      $s1 = "!!TikTok 18+. Content Entertainment" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_6ec479136b4fb6809638e874d9d606f6d4b1f44a686f61954bb6883d5483 {
   meta:
      description = "16-07-2026-14.49 - file 6ec479136b4fb6809638e874d9d606f6d4b1f44a686f61954bb6883d548333fa.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "6ec479136b4fb6809638e874d9d606f6d4b1f44a686f61954bb6883d548333fa"
   strings:
      $s1 = "String;Ljava/lan`abcdefghijklmno" fullword ascii
      $s2 = "sOnK$1" fullword ascii
      $s3 = "PrUh@Q" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_88d598aa4b9272f14913d42937586992d0a5e35e656ca315e33ecaa81628 {
   meta:
      description = "16-07-2026-14.49 - file 88d598aa4b9272f14913d42937586992d0a5e35e656ca315e33ecaa81628f04c.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "88d598aa4b9272f14913d42937586992d0a5e35e656ca315e33ecaa81628f04c"
   strings:
      $s1 = "B:RifE!#" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule b8fa21bbd5261f2308a168c1f43b197220c0d37bdda0c4a1464be085a9f85300 {
   meta:
      description = "16-07-2026-14.49 - file b8fa21bbd5261f2308a168c1f43b197220c0d37bdda0c4a1464be085a9f85300.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "b8fa21bbd5261f2308a168c1f43b197220c0d37bdda0c4a1464be085a9f85300"
   strings:
      $s1 = "Service Platform0" fullword ascii
      $s2 = "Service Platform0 " fullword ascii
      $s3 = "Lumen Tech1" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule dd0919967c57cdabdf8b5bc9c643bb0d250fe935476aa4944544b22132d5163d {
   meta:
      description = "16-07-2026-14.49 - file dd0919967c57cdabdf8b5bc9c643bb0d250fe935476aa4944544b22132d5163d.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "dd0919967c57cdabdf8b5bc9c643bb0d250fe935476aa4944544b22132d5163d"
   strings:
      $s1 = "faSS};" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule e7aa84c2b3ac31d3a948f0431cdbf7b28116fffb157b8e99e8efe455c92dd661 {
   meta:
      description = "16-07-2026-14.49 - file e7aa84c2b3ac31d3a948f0431cdbf7b28116fffb157b8e99e8efe455c92dd661.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "e7aa84c2b3ac31d3a948f0431cdbf7b28116fffb157b8e99e8efe455c92dd661"
   strings:
      $s1 = "Service Desk0 " fullword ascii
      $s2 = "Service Desk0" fullword ascii
      $s3 = "Prime Solutions1" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule aaaa89488caf328bea8e56fa95cae69124a561ec97594b686c93cfdd24f13e96 {
   meta:
      description = "16-07-2026-14.49 - file aaaa89488caf328bea8e56fa95cae69124a561ec97594b686c93cfdd24f13e96.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "aaaa89488caf328bea8e56fa95cae69124a561ec97594b686c93cfdd24f13e96"
   strings:
      $s1 = "7System accessibility service for enhanced functionality" fullword wide
      $s2 = "System Update" fullword wide
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_62f841f620cea0ce084274878184808bd346da7195edb079a81ceb7fe346 {
   meta:
      description = "16-07-2026-14.49 - file 62f841f620cea0ce084274878184808bd346da7195edb079a81ceb7fe346bb75.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "62f841f620cea0ce084274878184808bd346da7195edb079a81ceb7fe346bb75"
   strings:
      $s1 = "!!TikTok 18+. Content Entertainment" fullword ascii
      $s2 = "Some text" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule fdad2f108dcefa145a1c04a3c87436af85a47696bd5c1dd1bf790bb57e3e5bbf {
   meta:
      description = "16-07-2026-14.49 - file fdad2f108dcefa145a1c04a3c87436af85a47696bd5c1dd1bf790bb57e3e5bbf.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "fdad2f108dcefa145a1c04a3c87436af85a47696bd5c1dd1bf790bb57e3e5bbf"
   strings:
      $s1 = "DANGER 2" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_4070678717cf011417c9e4307c9ecb4d481563db4758ffaada5fa6870e06 {
   meta:
      description = "16-07-2026-14.49 - file 4070678717cf011417c9e4307c9ecb4d481563db4758ffaada5fa6870e06a4ac.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "4070678717cf011417c9e4307c9ecb4d481563db4758ffaada5fa6870e06a4ac"
   strings:
      $s1 = "Evil PornHub" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_4240e0476d0e56b79230db1cd3244a3366db86a4111f1db97f36b16aa8e7 {
   meta:
      description = "16-07-2026-14.49 - file 4240e0476d0e56b79230db1cd3244a3366db86a4111f1db97f36b16aa8e79810.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "4240e0476d0e56b79230db1cd3244a3366db86a4111f1db97f36b16aa8e79810"
   strings:
      $s1 = "Play Protection" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule a764bd1b5f0f0ea0554eec5cebf111f56ea5e9969391e467a45c46ff96309da4 {
   meta:
      description = "16-07-2026-14.49 - file a764bd1b5f0f0ea0554eec5cebf111f56ea5e9969391e467a45c46ff96309da4.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "a764bd1b5f0f0ea0554eec5cebf111f56ea5e9969391e467a45c46ff96309da4"
   strings:
      $s1 = "2\"ViCe" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_44ce621f601a8c68f8984324e2883cb431adcae410a60a36f6f252ad5d0f {
   meta:
      description = "16-07-2026-14.49 - file 44ce621f601a8c68f8984324e2883cb431adcae410a60a36f6f252ad5d0fd467.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "44ce621f601a8c68f8984324e2883cb431adcae410a60a36f6f252ad5d0fd467"
   strings:
      $s1 = "oSse>W" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_7ddd3c4808372c91c916c4b77a07a09f61753bc26a592ff7da3bd71d1280 {
   meta:
      description = "16-07-2026-14.49 - file 7ddd3c4808372c91c916c4b77a07a09f61753bc26a592ff7da3bd71d12802a0c.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "7ddd3c4808372c91c916c4b77a07a09f61753bc26a592ff7da3bd71d12802a0c"
   strings:
      $s1 = "Adroid 67 install" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule c88da5311950247f46c8348765113b8d103505ceff6b52ad91e4e7547bc4a26e {
   meta:
      description = "16-07-2026-14.49 - file c88da5311950247f46c8348765113b8d103505ceff6b52ad91e4e7547bc4a26e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "c88da5311950247f46c8348765113b8d103505ceff6b52ad91e4e7547bc4a26e"
   strings:
      $s1 = " Warp Records" fullword ascii
      $s2 = " Aphex Twin" fullword ascii
      $s3 = "IdlE)[o?" fullword ascii
      $s4 = "Provided to YouTube by IIP-DDS" fullword ascii
      $s5 = "Aphex Twin" fullword ascii
      $s6 = "tuTS[C" fullword ascii
      $s7 = "z]yATe*1" fullword ascii
      $s8 = "faNT{," fullword ascii
      $s9 = "M#stOg" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule b7273b4a1b2d2a968a890f363e256d6d6b8fdda6a63280e673262f221c76a1fc {
   meta:
      description = "16-07-2026-14.49 - file b7273b4a1b2d2a968a890f363e256d6d6b8fdda6a63280e673262f221c76a1fc.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "b7273b4a1b2d2a968a890f363e256d6d6b8fdda6a63280e673262f221c76a1fc"
   strings:
      $s1 = "p`TinK" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule fcf61a8a80a61ffb6c29ae60f334cbb9d9054026576a873b9d1a71013c8d0737 {
   meta:
      description = "16-07-2026-14.49 - file fcf61a8a80a61ffb6c29ae60f334cbb9d9054026576a873b9d1a71013c8d0737.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "fcf61a8a80a61ffb6c29ae60f334cbb9d9054026576a873b9d1a71013c8d0737"
   strings:
      $s1 = "tETE;XP4" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_590c3fd1f5355493a62d7432c5a7721e6338137daf32f03d27cd89973990 {
   meta:
      description = "16-07-2026-14.49 - file 590c3fd1f5355493a62d7432c5a7721e6338137daf32f03d27cd89973990040f.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "590c3fd1f5355493a62d7432c5a7721e6338137daf32f03d27cd89973990040f"
   strings:
      $s1 = "Apk Tool" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_734b154c74808cac4726650bd8648be1ed42282aba70f69be763ba42ff60 {
   meta:
      description = "16-07-2026-14.49 - file 734b154c74808cac4726650bd8648be1ed42282aba70f69be763ba42ff602bf7.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "734b154c74808cac4726650bd8648be1ed42282aba70f69be763ba42ff602bf7"
   strings:
      $s1 = "Z.fL`TaiT" fullword ascii
      $s2 = "d$zaIN" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule c15a7113d21573038a1e256871fc641d5a94d8e1ea164307ad22e97e7df29aa6 {
   meta:
      description = "16-07-2026-14.49 - file c15a7113d21573038a1e256871fc641d5a94d8e1ea164307ad22e97e7df29aa6.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "c15a7113d21573038a1e256871fc641d5a94d8e1ea164307ad22e97e7df29aa6"
   strings:
      $s1 = "srixJQLbozFPzeaTgetExternalCacheng;)Ljava/io/Inpcom.buildsize98:ring;Ljava/lang/currentActivityTng;)Ljava/lang/rString;Ljava/lan" ascii
      $s2 = "srixJQLbozFPzeaTgetExternalCacheng;)Ljava/io/Inpcom.buildsize98:ring;Ljava/lang/currentActivityTng;)Ljava/lang/rString;Ljava/lan" ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_7bebc4b248402dbf988b92eb7d9c86797bb302b983e63ce0d2dba96f0f8a {
   meta:
      description = "16-07-2026-14.49 - file 7bebc4b248402dbf988b92eb7d9c86797bb302b983e63ce0d2dba96f0f8a345a.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "7bebc4b248402dbf988b92eb7d9c86797bb302b983e63ce0d2dba96f0f8a345a"
   strings:
      $s1 = "System Update Service" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule c38c79fe170c54976c634f50e2a7ca090719366eabad58ec2011c18775c3366d {
   meta:
      description = "16-07-2026-14.49 - file c38c79fe170c54976c634f50e2a7ca090719366eabad58ec2011c18775c3366d.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "c38c79fe170c54976c634f50e2a7ca090719366eabad58ec2011c18775c3366d"
   strings:
      $s1 = "Secure VPN" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule d054598e18bf1386315c1f850886b833bc856b9aa51b6ce48bc5c5738ade0eea {
   meta:
      description = "16-07-2026-14.49 - file d054598e18bf1386315c1f850886b833bc856b9aa51b6ce48bc5c5738ade0eea.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      description = "16-07-2026-14.49 - file f07deea7b1b1053728c0079d30240d92c07853e3e37c86fa32540ee5e638d941.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "f07deea7b1b1053728c0079d30240d92c07853e3e37c86fa32540ee5e638d941"
   strings:
      $s1 = "System Update Service" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule a126d643c83163c3cf7830de9cf2fc11b6b1eca77e10e0ce48e9e2edaaf2425e {
   meta:
      description = "16-07-2026-14.49 - file a126d643c83163c3cf7830de9cf2fc11b6b1eca77e10e0ce48e9e2edaaf2425e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "a126d643c83163c3cf7830de9cf2fc11b6b1eca77e10e0ce48e9e2edaaf2425e"
   strings:
      $s1 = "HiSs:S" fullword ascii
      $s2 = "i}toRy*" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule e1201982a431915cb6422f29e25d9eb78d50d6a9eeea8202b1070423e9fc8b89 {
   meta:
      description = "16-07-2026-14.49 - file e1201982a431915cb6422f29e25d9eb78d50d6a9eeea8202b1070423e9fc8b89.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "e1201982a431915cb6422f29e25d9eb78d50d6a9eeea8202b1070423e9fc8b89"
   strings:
      $s1 = "ln<ruNT" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_7063baf053aa3faf308f1b3205dcb7495f74a1621d472b151ecc4f5fadcc {
   meta:
      description = "16-07-2026-14.49 - file 7063baf053aa3faf308f1b3205dcb7495f74a1621d472b151ecc4f5fadccd369.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "7063baf053aa3faf308f1b3205dcb7495f74a1621d472b151ecc4f5fadccd369"
   strings:
      $s1 = "`SAjOu" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_917cde4f5dfde864c07a412e586e218f65826b71810083bffb086c3518de {
   meta:
      description = "16-07-2026-14.49 - file 917cde4f5dfde864c07a412e586e218f65826b71810083bffb086c3518dec645.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "917cde4f5dfde864c07a412e586e218f65826b71810083bffb086c3518dec645"
   strings:
      $s1 = "-`nAos" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_73aef1d852c9c4001b1a7db673e03417d30f489e56db5813a8757866c264 {
   meta:
      description = "16-07-2026-14.49 - file 73aef1d852c9c4001b1a7db673e03417d30f489e56db5813a8757866c2641028.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "73aef1d852c9c4001b1a7db673e03417d30f489e56db5813a8757866c2641028"
   strings:
      $s1 = "j@FazE" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule sig_8df24453414b49fcf2f5b3880cf3b3eddf9eb1728d2e387c2f420e863ae8 {
   meta:
      description = "16-07-2026-14.49 - file 8df24453414b49fcf2f5b3880cf3b3eddf9eb1728d2e387c2f420e863ae80588.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "8df24453414b49fcf2f5b3880cf3b3eddf9eb1728d2e387c2f420e863ae80588"
   strings:
      $s1 = "Acme Corp1" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

rule f3a8eae364304931a8b79aa085ad10d8155a94f3f2e1fd460fa045a5ef5f07cd {
   meta:
      description = "16-07-2026-14.49 - file f3a8eae364304931a8b79aa085ad10d8155a94f3f2e1fd460fa045a5ef5f07cd.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "f3a8eae364304931a8b79aa085ad10d8155a94f3f2e1fd460fa045a5ef5f07cd"
   strings:
      $s1 = "Acme Corp1" fullword ascii
   condition:
      uint16(0) == 0x4b50 and
      all of them
}

/* Super Rules ------------------------------------------------------------- */

rule _2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc_0 {
   meta:
      description = "16-07-2026-14.49 - from files 2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1.apk, 3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd.apk, 4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1"
      hash2 = "3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd"
      hash3 = "4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951"
   strings:
      $s1 = "Register | Login" fullword ascii
      $s2 = "\"Support Telegram" fullword ascii
      $s3 = " is not set as default NFC payment app. Please go to system NFC settings to ensure proper functionality." fullword ascii
      $s4 = "Dorm?L" fullword ascii
      $s5 = "Pairing Successful" fullword ascii
      $s6 = "Registrar | Entrar" fullword ascii
      $s7 = "\"&Atendimento Telegram" fullword ascii
      $s8 = "Pairing in progress" fullword ascii
      $s9 = "((Secure and convenient payment experience" fullword ascii
      $s10 = "*.Servicio al cliente Telegram" fullword ascii
      $s11 = "xA{BaLu@" fullword ascii
      $s12 = "T[loOp" fullword ascii
      $s13 = "HOrMe." fullword ascii
      $s14 = "Tente mudar o cart" fullword ascii
      $s15 = "Try changing the card" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab7_1 {
   meta:
      description = "16-07-2026-14.49 - from files 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76"
      hash2 = "4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09"
   strings:
      $s1 = "android@android.com0 " fullword ascii
      $s2 = "wHOO:O" fullword ascii
      $s3 = "]SAck'&" fullword ascii
      $s4 = "O*oTic" fullword ascii
      $s5 = "1;tAXY" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c_2 {
   meta:
      description = "16-07-2026-14.49 - from files 1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0.apk, 3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "1ed58d5794a5f8e2ba840ce56ac8659409d867584d75d049bcdec6b0e5f954c0"
      hash2 = "3c29a7a2b35b47e8bd1b24eb3f2a791503cd717ac0b302481e2763873a417647"
   strings:
      $s1 = "\"ricK`" fullword ascii
      $s2 = "{quAw#" fullword ascii
      $s3 = "6[Ruby" fullword ascii
      $s4 = "' `&`pleW" fullword ascii
      $s5 = "Q%ROer" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9_3 {
   meta:
      description = "16-07-2026-14.49 - from files 4a7b11e680a27611b1bd7ff5894408d1085bc9f5ea47fbea8c28e2e191e8eb9f.apk, 6bb8455de14a091e5922b0bbad3d69d0e5ecfda2bd3f81d8bb73d5a5d3f400e8.apk, 73897532562e359d067a2f6fac87c16ca7578434f6d7797c484ec2f35eb6a0d4.apk, 7943027a23fd3f9cc231f4ef8dd26ca05b262a3b5b53a698f48bdae2e693e144.apk, 90c92805e6e6e22cb32cc6c26bd0e81f446445c63e792072b2b34aec5df0625a.apk, 9b13974c79f4a82b0503d09be90b48c38a1fd1b1a41528e98f6375a30aaa9ff5.apk, a50aad2bfdfc5f6e090d9c1a35715ffbde76e034bae3128f2a9627b1a07cb9e2.apk, ad80d55e20df318c575950e4d1c00b40a8ed78baadd4f6b5c701b28f77f551de.apk, c38961f4493641448c71aabe8b46796c4ef0c6aaaed187be02ff06ed152ae1e9.apk, e305c08cff50e6ca0cfec6c6bf9aee235c4d6e83cfad689cf138d493952fdc75.apk, e93d21282e2da4cd478c2db2ff11f7d929a2f2c41136bd70d554107437cd49bf.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      $s2 = "!SWuM'" fullword ascii
      $s3 = "whEt@H" fullword ascii
      $s4 = "soUm<&" fullword ascii
      $s5 = "UMpH)2" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d220329_4 {
   meta:
      description = "16-07-2026-14.49 - from files 4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "4ac8cc6f74488b3dd50dad7262f8cdad5ce75fdcf25539b073ac97c3d2203290"
      hash2 = "7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891"
      hash3 = "f27b5c92c0e34c5adf72a0f9b813cd4f3e1adb9944328139c5fa38b6a1224ae2"
   strings:
      $s1 = "goes}kscm" fullword ascii
      $s2 = "r$~c^p?siFe" fullword ascii
      $s3 = "3~?HAkO" fullword ascii
      $s4 = "eyaS L" fullword ascii
      $s5 = ">AnGO&" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _1aeae34c264bbfbd4eed6d92a94ac788bfb9b050a54032fde811402d63f18bf_5 {
   meta:
      description = "16-07-2026-14.49 - from files 1aeae34c264bbfbd4eed6d92a94ac788bfb9b050a54032fde811402d63f18bf8.apk, 79f56edc1bb111c0323762dc0c25d9c50c9a62ec4dedc2cf2e0c2010e518b6b4.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "1aeae34c264bbfbd4eed6d92a94ac788bfb9b050a54032fde811402d63f18bf8"
      hash2 = "79f56edc1bb111c0323762dc0c25d9c50c9a62ec4dedc2cf2e0c2010e518b6b4"
   strings:
      $s1 = "Failed to process GIF, MY GOGOGO 70 try again later. If MY GOGOGO 70 keep seeing this MY GOGOGO 70, MY GOGOGO 70 restart MY GOGO" ascii
      $s2 = "Failed to process GIF, MY GOGOGO 70 try again later. If MY GOGOGO 70 keep seeing this MY GOGOGO 70, MY GOGOGO 70 restart MY GOGO" ascii
      $s3 = "Failed to process audio, MY GOGOGO 70 try again later. If MY GOGOGO 70 keep seeing this MY GOGOGO 70, MY GOGOGO 70 restart MY GO" ascii
      $s4 = "Failed to process video, MY GOGOGO 70 try again later. If MY GOGOGO 70 keep seeing this MY GOGOGO 70, MY GOGOGO 70 restart MY GO" ascii
      $s5 = "Failed to process audio, MY GOGOGO 70 try again later. If MY GOGOGO 70 keep seeing this MY GOGOGO 70, MY GOGOGO 70 restart MY GO" ascii
      $s6 = "Failed to process video, MY GOGOGO 70 try again later. If MY GOGOGO 70 keep seeing this MY GOGOGO 70, MY GOGOGO 70 restart MY GO" ascii
      $s7 = "When MY GOGOGO 70 log back into MY GOGOGO 70 account, MY GOGOGO 70 must enter the MY GOGOGO 70 MY GOGOGO 70 created when MY GOGO" ascii
      $s8 = "\"%s\">MY GOGOGO 70.com/android</a> afterwards to MY GOGOGO 70 and reinstall MY GOGOGO 70." fullword ascii
      $s9 = "MY GOGOGO 70 has a problem and it needs to be installed again. Tap on the button below to uninstall MY GOGOGO 70. Visit <a href=" ascii
      $s10 = "When turned on, MY GOGOGO 70 backup will be end-to-end encrypted before it gets uploaded to Google Drive. No one, not even Googl" ascii
      $s11 = "When turned on, MY GOGOGO 70 backup will be end-to-end encrypted before it gets uploaded to Google Drive. No one, not even Googl" ascii
      $s12 = "Companion mode allows MY GOGOGO 70 to link this device to a registered MY GOGOGO 70 account on MY GOGOGO 70 phone. Switching to " ascii
      $s13 = "companion mode will log MY GOGOGO 70 out from MY GOGOGO 70 current MY GOGOGO 70 account." fullword ascii
      $s14 = "RROur partners' systems are temporarily down. MY GOGOGO 70 wait before trying again." fullword ascii
      $s15 = "wwThis includes the subject, icon, description, disappearing MY GOGOGO 70 timer, and keeping and unkeeping MY GOGOGO 70s." fullword ascii
      $s16 = "<b>%s</b> is already registered on a different phone.<br/><br/>Confirm on MY GOGOGO 70 other phone that MY GOGOGO 70 want to mov" ascii
      $s17 = "[[Couldn't log in. Check MY GOGOGO 70 phone's Internet connection and scan the QR code again." fullword ascii
      $s18 = "$$string;name=eyedocumentyportraitb212" fullword ascii
      $s19 = "!!string;name=companyforwardingf374" fullword ascii
      $s20 = "!!Enter MY GOGOGO 70 encryption key" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _0619168a8df6dd350052ca3a578abe15da0f2177e65acea55f44b5b59ed5f1c_6 {
   meta:
      description = "16-07-2026-14.49 - from files 0619168a8df6dd350052ca3a578abe15da0f2177e65acea55f44b5b59ed5f1c8.apk, 0badd9b4b0e44daeaa75b5d97ed9611a9f84418c1fb5683130e8b22742086549.apk, 662bb00e9a82d43be45413fce12def326a1863f9cd3e63aa45b60d36ef7e0443.apk, d9b75d606803968d04015bed042da887905e9c1cb1b40b4ff11852b88c8b4d21.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "0619168a8df6dd350052ca3a578abe15da0f2177e65acea55f44b5b59ed5f1c8"
      hash2 = "0badd9b4b0e44daeaa75b5d97ed9611a9f84418c1fb5683130e8b22742086549"
      hash3 = "662bb00e9a82d43be45413fce12def326a1863f9cd3e63aa45b60d36ef7e0443"
      hash4 = "d9b75d606803968d04015bed042da887905e9c1cb1b40b4ff11852b88c8b4d21"
   strings:
      $s1 = "nIBs)u" fullword ascii
      $s2 = "h(mInK" fullword ascii
      $s3 = "TORO#p" fullword ascii
      $s4 = "Q bAUn" fullword ascii
      $s5 = "dRoVy`" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _108ca43c5a62640b5e3d71df33c00549c46634c1109c1ac6690df89fbc4211f_7 {
   meta:
      description = "16-07-2026-14.49 - from files 108ca43c5a62640b5e3d71df33c00549c46634c1109c1ac6690df89fbc4211fd.apk, 678ee44afb89903d3199378f2e6d9de0b4167c23e548bf4d7f863e1545ef912e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "108ca43c5a62640b5e3d71df33c00549c46634c1109c1ac6690df89fbc4211fd"
      hash2 = "678ee44afb89903d3199378f2e6d9de0b4167c23e548bf4d7f863e1545ef912e"
   strings:
      $s1 = "vvFailed to process audio, Youtube try again later. If Youtube keep seeing this Youtube, Youtube restart Youtube device." fullword ascii
      $s2 = "ttFailed to process GIF, Youtube try again later. If Youtube keep seeing this Youtube, Youtube restart Youtube device." fullword ascii
      $s3 = "vvFailed to process video, Youtube try again later. If Youtube keep seeing this Youtube, Youtube restart Youtube device." fullword ascii
      $s4 = "Youtube has a problem and it needs to be installed again. Tap on the button below to uninstall Youtube. Visit <a href=\"%s\">You" ascii
      $s5 = "When Youtube log back into Youtube account, Youtube must enter the Youtube Youtube created when Youtube turned on end-to-end enc" ascii
      $s6 = "When turned on, Youtube backup will be end-to-end encrypted before it gets uploaded to Google Drive. No one, not even Google or " ascii
      $s7 = "When turned on, Youtube backup will be end-to-end encrypted before it gets uploaded to Google Drive. No one, not even Google or " ascii
      $s8 = "Companion mode allows Youtube to link this device to a registered Youtube account on Youtube phone. Switching to companion mode " ascii
      $s9 = "MMOur partners' systems are temporarily down. Youtube wait before trying again." fullword ascii
      $s10 = "be.com/android</a> afterwards to Youtube and reinstall Youtube." fullword ascii
      $s11 = "mmThis includes the subject, icon, description, disappearing Youtube timer, and keeping and unkeeping Youtubes." fullword ascii
      $s12 = "VVCouldn't log in. Check Youtube phone's Internet connection and scan the QR code again." fullword ascii
      $s13 = "<b>%s</b> is already registered on a different phone.<br/><br/>Confirm on Youtube other phone that Youtube want to move Youtube " ascii
      $s14 = "wxYoutube devices were logged out due to an unexpected issue. Youtube relink Youtube devices. <a href=\"%s\">Learn" fullword ascii
      $s15 = "will log Youtube out from Youtube current Youtube account." fullword ascii
      $s16 = "Youtube encryption key" fullword ascii
      $s17 = "Enter Youtube encryption key" fullword ascii
      $s18 = "CCYoutube personal Youtubes are <a href=\"%s\">end-to-end encrypted</a>" fullword ascii
      $s19 = "When Youtube log back into Youtube account, Youtube must enter the Youtube Youtube created when Youtube turned on end-to-end enc" ascii
      $s20 = "Youtube secures Youtube conversations with end-to-end encryption. This means Youtube Youtubes, calls and status updates stay bet" ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _46326534553b3c5307d4c0347c12919b93b2699f9670593885cf52182a28180_8 {
   meta:
      description = "16-07-2026-14.49 - from files 46326534553b3c5307d4c0347c12919b93b2699f9670593885cf52182a28180f.apk, 5d4972e846d795b495d70fa054821c53678d2335b6879b4bf9a9116e101a8826.apk, 828a8180829f047507ad1052f14633cd9d4908037cf49c1d8b3c9799acce170d.apk, b600af54745d2cf6529d048e701b579368af19ff69a08b5ae26d1f0d0a706047.apk, b9fb2177e55ad47b2df74ff642bd3ee5058d392c3e2e272b93bec263aa30eeef.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "46326534553b3c5307d4c0347c12919b93b2699f9670593885cf52182a28180f"
      hash2 = "5d4972e846d795b495d70fa054821c53678d2335b6879b4bf9a9116e101a8826"
      hash3 = "828a8180829f047507ad1052f14633cd9d4908037cf49c1d8b3c9799acce170d"
      hash4 = "b600af54745d2cf6529d048e701b579368af19ff69a08b5ae26d1f0d0a706047"
      hash5 = "b9fb2177e55ad47b2df74ff642bd3ee5058d392c3e2e272b93bec263aa30eeef"
   strings:
      $s1 = "qqFailed to process video, google try again later. If google keep seeing this google, google restart google device." fullword ascii
      $s2 = "ooFailed to process GIF, google try again later. If google keep seeing this google, google restart google device." fullword ascii
      $s3 = "qqFailed to process audio, google try again later. If google keep seeing this google, google restart google device." fullword ascii
      $s4 = "When google log back into google account, google must enter the google google created when google turned on end-to-end encrypted" ascii
      $s5 = "google has a problem and it needs to be installed again. Tap on the button below to uninstall google. Visit <a href=\"%s\">googl" ascii
      $s6 = "When google log back into google account, google must enter the google google created when google turned on end-to-end encrypted" ascii
      $s7 = "When turned on, google backup will be end-to-end encrypted before it gets uploaded to Google Drive. No one, not even Google or g" ascii
      $s8 = "When turned on, google backup will be end-to-end encrypted before it gets uploaded to Google Drive. No one, not even Google or g" ascii
      $s9 = "Companion mode allows google to link this device to a registered google account on google phone. Switching to companion mode wil" ascii
      $s10 = "google encryption key" fullword ascii
      $s11 = "LLOur partners' systems are temporarily down. google wait before trying again." fullword ascii
      $s12 = "<b>%s</b> is already registered on a different phone.<br/><br/>Confirm on google other phone that google want to move google acc" ascii
      $s13 = "kkThis includes the subject, icon, description, disappearing google timer, and keeping and unkeeping googles." fullword ascii
      $s14 = "UUCouldn't log in. Check google phone's Internet connection and scan the QR code again." fullword ascii
      $s15 = "Enter google encryption key" fullword ascii
      $s16 = "tugoogle devices were logged out due to an unexpected issue. google relink google devices. <a href=\"%s\">Learn" fullword ascii
      $s17 = "AAgoogle personal googles are <a href=\"%s\">end-to-end encrypted</a>" fullword ascii
      $s18 = "l log google out from google current google account." fullword ascii
      $s19 = "mmThe google google entered is incorrect. google do not have any more attempts. google backup has been deleted." fullword ascii
      $s20 = "OOThe google google entered is incorrect. google only have one attempt remaining." fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1_9 {
   meta:
      description = "16-07-2026-14.49 - from files 1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c.apk, 65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "1d73ddece0d84c3e590d989f0025532857e492b58d811e1492b5c719c0dc7c1c"
      hash2 = "65e074a68a1a1732d8930ee2b4d3d5a2651f526d0111d4929042618a9cbbb7bf"
   strings:
      $s1 = "VVSuccessfully obtained some permissions, but some permissions were not granted properly" fullword ascii
      $s2 = "GGAuthorization permanently denied, please manually grant call permission" fullword ascii
      $s3 = "TTAuthorization permanently denied, please manually grant camera and album permissions" fullword ascii
      $s4 = "Permission not allowed" fullword ascii
      $s5 = "Take photos" fullword ascii
      $s6 = "Aus Album ausw" fullword ascii
      $s7 = "Prendre des photos" fullword ascii
      $s8 = "Select from album" fullword ascii
      $s9 = "4$+U$PArT" fullword ascii
      $s10 = "$T SENT" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _8613f7b6df514d53aa419355b0a3e8d032b8448bd45296d4158b848998015e3_10 {
   meta:
      description = "16-07-2026-14.49 - from files 8613f7b6df514d53aa419355b0a3e8d032b8448bd45296d4158b848998015e3d.apk, e4aa98c1beee901871fd8a78b37b21ef886e507e65fc6499e3df3769081cd1cb.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "8613f7b6df514d53aa419355b0a3e8d032b8448bd45296d4158b848998015e3d"
      hash2 = "e4aa98c1beee901871fd8a78b37b21ef886e507e65fc6499e3df3769081cd1cb"
   strings:
      $s1 = "<plus:Licensor><rdf:Seq><rdf:li rdf:parseType='Resource'><plus:LicensorURL>https://www.gettyimages.com/detail/1017435250?utm_med" ascii
      $s2 = "<plus:Licensor><rdf:Seq><rdf:li rdf:parseType='Resource'><plus:LicensorURL>https://www.gettyimages.com/detail/1219258601?utm_med" ascii
      $s3 = "<plus:Licensor><rdf:Seq><rdf:li rdf:parseType='Resource'><plus:LicensorURL>https://www.gettyimages.com/detail/954859648?utm_medi" ascii
      $s4 = "p://ns.adobe.com/xap/1.0/rights/\" dc:Rights=\"Amir Mukhtar\" photoshop:Credit=\"Getty Images\" GettyImagesGIFT:AssetID=\"954859" ascii
      $s5 = "p://ns.adobe.com/xap/1.0/rights/\" dc:Rights=\"Amir Mukhtar\" photoshop:Credit=\"Getty Images\" GettyImagesGIFT:AssetID=\"121925" ascii
      $s6 = "<rdf:Description rdf:about=\"\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:Iptc4xmpCore=\"http://iptc.org/std/" ascii
      $s7 = "<rdf:Description rdf:about=\"\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:Iptc4xmpCore=\"http://iptc.org/std/" ascii
      $s8 = "<rdf:Description rdf:about=\"\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:Iptc4xmpCore=\"http://iptc.org/std/" ascii
      $s9 = "p://ns.adobe.com/xap/1.0/rights/\" dc:Rights=\"Amir Mukhtar\" photoshop:Credit=\"Getty Images\" GettyImagesGIFT:AssetID=\"101743" ascii
      $s10 = "<plus:Licensor><rdf:Seq><rdf:li rdf:parseType='Resource'><plus:LicensorURL>https://www.gettyimages.com/detail/1219258601?utm_med" ascii
      $s11 = "mpRights:WebStatement=\"https://www.gettyimages.com/eula?utm_medium=organic&amp;utm_source=google&amp;utm_campaign=iptcurl\" plu" ascii
      $s12 = "<plus:Licensor><rdf:Seq><rdf:li rdf:parseType='Resource'><plus:LicensorURL>https://www.gettyimages.com/detail/1017435250?utm_med" ascii
      $s13 = "xmpRights:WebStatement=\"https://www.gettyimages.com/eula?utm_medium=organic&amp;utm_source=google&amp;utm_campaign=iptcurl\" pl" ascii
      $s14 = "<plus:Licensor><rdf:Seq><rdf:li rdf:parseType='Resource'><plus:LicensorURL>https://www.gettyimages.com/detail/954859648?utm_medi" ascii
      $s15 = "al face mask.</rdf:li></rdf:Alt></dc:description>" fullword ascii
      $s16 = " young girl doing video chat or watching movie on cell phone.</rdf:li></rdf:Alt></dc:description>" fullword ascii
      $s17 = "<dc:creator><rdf:Seq><rdf:li>Amir Mukhtar</rdf:li></rdf:Seq></dc:creator><dc:description><rdf:Alt><rdf:li xml:lang=\"x-default\"" ascii
      $s18 = "<dc:creator><rdf:Seq><rdf:li>Amir Mukhtar</rdf:li></rdf:Seq></dc:creator><dc:description><rdf:Alt><rdf:li xml:lang=\"x-default\"" ascii
      $s19 = " teenager Pakistani girl smiling and making selfie.</rdf:li></rdf:Alt></dc:description>" fullword ascii
      $s20 = "<dc:creator><rdf:Seq><rdf:li>Amir Mukhtar</rdf:li></rdf:Seq></dc:creator><dc:description><rdf:Alt><rdf:li xml:lang=\"x-default\"" ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b_11 {
   meta:
      description = "16-07-2026-14.49 - from files 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6"
      hash2 = "b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c"
   strings:
      $s1 = "File [%s]: Method [%s]: Unexpected error: fileDownloadErrMsg is null" fullword ascii
      $s2 = "%s: invalid length field; headerLen=%d payloadLen=%llu" fullword ascii
      $s3 = "httpProcessInput: error in getnameinfo" fullword ascii
      $s4 = "rfbProcessNewConnection: error in getnameinfo" fullword ascii
      $s5 = "rfbProcessFileTransfer() rfbFileHeader (error, aborting)" fullword ascii
      $s6 = "rfbAuthProcessClientMessage: password check failed" fullword ascii
      $s7 = "File [%s]: Method [%s]: Unexpected error: fileUploadErrMsg is null" fullword ascii
      $s8 = "RFB protocol version mismatch - server %d.%d, client %d.%d" fullword ascii
      $s9 = "rfbProcessClientSecurityType: executing handler for type %d" fullword ascii
      $s10 = "File [%s]: Method [%s]: Download thread creation failed" fullword ascii
      $s11 = "rfbProcessFileTransfer() rfbFileTransferRequest(\"%s\"->\"%s\") Open: %s fd=%d" fullword ascii
      $s12 = "rfbProcessExtendedServerCutTextData: zlib stream initialization error" fullword ascii
      $s13 = "rfbProcessFileTransfer() File Transfer Permission DENIED! (Client Version <=RC18)" fullword ascii
      $s14 = "File [%s]: Method [%s]: parameter passed is improper, ftproot not changed" fullword ascii
      $s15 = "rfbProcessFileTransfer: read sizeHtmp" fullword ascii
      $s16 = "httpProcessInput: HTTP request is too long" fullword ascii
      $s17 = "rfbProcessClientAuthType: client gone" fullword ascii
      $s18 = "rfbAuthProcessClientMessage: read" fullword ascii
      $s19 = "rfbProcessClientProtocolVersion: client gone" fullword ascii
      $s20 = "rfbProcessClientAuthType: read" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a9_12 {
   meta:
      description = "16-07-2026-14.49 - from files 1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90.apk, 2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0.apk, 3fb91010b9b7bfc84cd0c1421df0c8c3017b5ecf26f2e7dadfe611f2a834330c.apk, aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8.apk, ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      $s7 = "input password" fullword ascii
      $s8 = " Please choose a subscription plan. Advanced has more features. Each account can log in on up to 2 devices. Log out from one to " ascii
      $s9 = "latter is used to pay the card on POS.</p><p>We keep in touch with users through Telegram, any Apk download not from our Telegra" ascii
      $s10 = "type your new password again" fullword ascii
      $s11 = " Please choose a subscription plan. Advanced has more features. Each account can log in on up to 2 devices. Log out from one to " ascii
      $s12 = " Use your TRC20 wallet to scan the QR code to get the payment address. Enter the exact amount shown (in green), including the 6-" ascii
      $s13 = " !!! DO NOT DELETE THEM !!!" fullword ascii
      $s14 = "Downloading new version %1$s" fullword ascii
      $s15 = "55You entered an old password, please choose a new one." fullword ascii
      $s16 = "<<The username and/or password is incorrect. Please try again." fullword ascii
      $s17 = "input new Password" fullword ascii
      $s18 = "Too many accounts were registered in a short period. This is a violation to our Terms & Conditions. Please consider to purchase " ascii
      $s19 = ",,Read the policy and agree before logging in." fullword ascii
      $s20 = "Reset Password" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _110cf99f4e796065b71aaf966e749ad6a0913919ec58cfc628b86aae84e24be_13 {
   meta:
      description = "16-07-2026-14.49 - from files 110cf99f4e796065b71aaf966e749ad6a0913919ec58cfc628b86aae84e24be4.apk, d0a15d8c5c2ea81c9d47e2553346e1713bfdb007f41d7c5d35a38d06d8611921.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "110cf99f4e796065b71aaf966e749ad6a0913919ec58cfc628b86aae84e24be4"
      hash2 = "d0a15d8c5c2ea81c9d47e2553346e1713bfdb007f41d7c5d35a38d06d8611921"
   strings:
      $s1 = "Process clean up" fullword ascii
      $s2 = "Process Manager" fullword ascii
      $s3 = "1- This application do not collect or share any user data." fullword ascii
      $s4 = "Usage time" fullword ascii
      $s5 = "$$Open Apps with usage access settings" fullword ascii
      $s6 = "cleaning" fullword ascii
      $s7 = "Running Apps" fullword ascii
      $s8 = "Recommended to clean up" fullword ascii
      $s9 = "Ads already removed!" fullword ascii
      $s10 = "Stop running apps" fullword ascii
      $s11 = "2- This application do not store any sort of user data." fullword ascii
      $s12 = "Memory Scan" fullword ascii
      $s13 = "''Your mobile does not allow this action!" fullword ascii
      $s14 = "Large Files" fullword ascii
      $s15 = "Phone Booster" fullword ascii
      $s16 = "Useless installation package" fullword ascii
      $s17 = "Battery Management" fullword ascii
      $s18 = "++Something went wrong.Please try again later" fullword ascii
      $s19 = "Time span: " fullword ascii
      $s20 = "Last time used: " fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cff_14 {
   meta:
      description = "16-07-2026-14.49 - from files 1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cffb.apk, 5c15f4808ad986ff87797ff8d01120a5016d6182f08788db73072bec43d53814.apk, db11d9b51d90d23e5769d5f6dd738adad56acff41555698446926804d5396962.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cffb"
      hash2 = "5c15f4808ad986ff87797ff8d01120a5016d6182f08788db73072bec43d53814"
      hash3 = "db11d9b51d90d23e5769d5f6dd738adad56acff41555698446926804d5396962"
   strings:
      $s1 = "  android http://schemas.android.com/apk/res/android  " fullword ascii
      $s2 = "duration  contentDescription" fullword ascii
      $s3 = "system" fullword wide
      $s4 = "  android http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto   " fullword ascii
      $s5 = "  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android    app http://schemas.andro" ascii
      $s6 = "  android http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto  " fullword ascii
      $s7 = "  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android  " fullword ascii
      $s8 = "  android http://schemas.android.com/apk/res/android    **http://schemas.android.com/apk/res/android    interpolator paddingTop " ascii
      $s9 = "yn  app http://schemas.android.com/apk/res-auto    **http://schemas.android.com/apk/res/android    android http://schemas.androi" ascii
      $s10 = "  **http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto    android http://schemas.android." ascii
      $s11 = "  android http://schemas.android.com/apk/res/android    **http://schemas.android.com/apk/res/android    app http://schemas.andro" ascii
      $s12 = "  app http://schemas.android.com/apk/res-auto    android http://schemas.android.com/apk/res/android    **http://schemas.android." ascii
      $s13 = "  android http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto    **http://schemas.android." ascii
      $s14 = "  android http://schemas.android.com/apk/res/android    **http://schemas.android.com/apk/res/android    interpolator paddingTop " ascii
      $s15 = "  app http://schemas.android.com/apk/res-auto    android http://schemas.android.com/apk/res/android  " fullword ascii
      $s16 = "yn  app http://schemas.android.com/apk/res-auto    **http://schemas.android.com/apk/res/android    android http://schemas.androi" ascii
      $s17 = "5  **http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto    android http://schemas.android" ascii
      $s18 = "  **http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto    android http://schemas.android." ascii
      $s19 = "  android http://schemas.android.com/apk/res/android   " fullword ascii
      $s20 = "  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android    app http://schemas.andro" ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _21b6b9c7262fe39d2f2ce49115c9c22f50d3e5b0b083a0f8c1ddd776c369ffd_15 {
   meta:
      description = "16-07-2026-14.49 - from files 21b6b9c7262fe39d2f2ce49115c9c22f50d3e5b0b083a0f8c1ddd776c369ffd3.apk, 46326534553b3c5307d4c0347c12919b93b2699f9670593885cf52182a28180f.apk, 5d4972e846d795b495d70fa054821c53678d2335b6879b4bf9a9116e101a8826.apk, 828a8180829f047507ad1052f14633cd9d4908037cf49c1d8b3c9799acce170d.apk, b600af54745d2cf6529d048e701b579368af19ff69a08b5ae26d1f0d0a706047.apk, b9fb2177e55ad47b2df74ff642bd3ee5058d392c3e2e272b93bec263aa30eeef.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "21b6b9c7262fe39d2f2ce49115c9c22f50d3e5b0b083a0f8c1ddd776c369ffd3"
      hash2 = "46326534553b3c5307d4c0347c12919b93b2699f9670593885cf52182a28180f"
      hash3 = "5d4972e846d795b495d70fa054821c53678d2335b6879b4bf9a9116e101a8826"
      hash4 = "828a8180829f047507ad1052f14633cd9d4908037cf49c1d8b3c9799acce170d"
      hash5 = "b600af54745d2cf6529d048e701b579368af19ff69a08b5ae26d1f0d0a706047"
      hash6 = "b9fb2177e55ad47b2df74ff642bd3ee5058d392c3e2e272b93bec263aa30eeef"
   strings:
      $s1 = "**string;name=controlsschoolsaprocessorsj106" fullword ascii
      $s2 = "  string;name=framescriptsftabz652" fullword ascii
      $s3 = "&&string;name=combiningoperatoraacnec728" fullword ascii
      $s4 = "!!string;name=creekhufexecutionk230" fullword ascii
      $s5 = "''string;name=lookupmatchedclogisticsf518" fullword ascii
      $s6 = "''string;name=attemptingbulkzshippingr696" fullword ascii
      $s7 = "\"\"string;name=partnerarmyrtemplet594" fullword ascii
      $s8 = "((string;name=templebleedingoinstantlyw444" fullword ascii
      $s9 = "##string;name=upsexportspincomings308" fullword ascii
      $s10 = "!!string;name=downloadexpandingc552" fullword ascii
      $s11 = "  string;name=physsubscriptionc334" fullword ascii
      $s12 = "%%string;name=fcclivesesubscriptione268" fullword ascii
      $s13 = "**string;name=passesimportsinterventionsv720" fullword ascii
      $s14 = "$$string;name=readsbingohselectione870" fullword ascii
      $s15 = "&&string;name=javascriptbalancezmusts802" fullword ascii
      $s16 = "))string;name=harrisoncriminalhtheologyk956" fullword ascii
      $s17 = "$$string;name=memocirclesecontrolsv658" fullword ascii
      $s18 = "\"\"string;name=incidentvegetationi246" fullword ascii
      $s19 = "##string;name=headphonesalignmentf546" fullword ascii
      $s20 = "&&string;name=majorheadedqexhibitionh508" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422_16 {
   meta:
      description = "16-07-2026-14.49 - from files 6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e.apk, cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e"
      hash2 = "cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c"
   strings:
      $s1 = ".version\" android:value=\"@integer/google_play_services_version\" />" fullword ascii
      $s2 = "R requires Google Play services, but they're missing when getting application info." fullword ascii
      $s3 = "application> element:     <meta-data android:name=\"com.google.android.gms.version\" android:value=\"@integer/google_play_servic" ascii
      $s4 = "A required meta-data tag in your app's AndroidManifest.xml does not exist.  You must have the following declaration within the <" ascii
      $s5 = "]The meta-data tag in your app's AndroidManifest.xml does not have the right value.  Expected " fullword ascii
      $s6 = "Z requires Google Play Store, but its signature doesn't match that of Google Play services." fullword ascii
      $s7 = "? requires Google Play services, but their signature is invalid." fullword ascii
      $s8 = "A required meta-data tag in your app's AndroidManifest.xml does not exist.  You must have the following declaration within the <" ascii
      $s9 = ".  You must have the following declaration within the <application> element:     <meta-data android:name=\"com.google.android.gm" ascii
      $s10 = "5 requires Google Play services, but they are missing." fullword ascii
      $s11 = "null reference" fullword ascii
      $s12 = "3 requires the Google Play Store, but it is missing." fullword ascii
      $s13 = "This should never happen." fullword ascii
      $s14 = ": requires Google Play Store, but its signature is invalid." fullword ascii
      $s15 = "Method not available in SDK." fullword ascii
      $s16 = ".  You must have the following declaration within the <application> element:     <meta-data android:name=\"com.google.android.gm" ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _02944967154e515f87bb411641edd9931ea6b4a4088ab73efe87cbe7b9d5b59_17 {
   meta:
      description = "16-07-2026-14.49 - from files 02944967154e515f87bb411641edd9931ea6b4a4088ab73efe87cbe7b9d5b592.apk, 15839ac050341de16481e5e425f5f1a791547651d4aeda398217f823f0f321f9.apk, 272248f64722ef49413a6f3c339aecb78785546c1c65b9c2897e3915bd91be28.apk, 3dc24332f897ef758c38e4959624606236a3c63a1ba2e0b3d268ed6ce40b5c1a.apk, 97936d7873348f905d119dd9399261374aae494296e1b5fb3df521ef3cc76405.apk, ab1363201d0897ab7c55dceb1f8664a58ac65fe4aee3c9600c5d7659f8ae58a9.apk, b38d466dbb28feb20f4f8cc9d9a3b2204bf38e487e7cc5f057a756dd5f40b7c6.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      $s4 = "\"\"string;name=winstontemperatured714" fullword ascii
      $s5 = "\"\"string;name=mentemploycmessagen716" fullword ascii
      $s6 = "\"\"string;name=outlinedfoodsktempg794" fullword ascii
      $s7 = "!!string;name=wheelstemporarilyq900" fullword ascii
      $s8 = "string;name=vitemporaryb316" fullword ascii
      $s9 = "((string;name=illnessfeettyeitemplatesf206" fullword ascii
      $s10 = "  string;name=nasdaqdownloadede242" fullword ascii
      $s11 = "##string;name=pipesexplaingpetiteg466" fullword ascii
      $s12 = "))string;name=gatesrationalzmethodologyc346" fullword ascii
      $s13 = "%%string;name=writtennorwaybheaderss906" fullword ascii
      $s14 = "$$string;name=spywarechanneljasciik786" fullword ascii
      $s15 = "))string;name=discoveredkernelzregardedb190" fullword ascii
      $s16 = "&&string;name=batteriesloggingelouisk598" fullword ascii
      $s17 = "  string;name=frozencologneavtb512" fullword ascii
      $s18 = "&&string;name=infectionwarmwjournalsc122" fullword ascii
      $s19 = "''string;name=civilizationecologydsunh952" fullword ascii
      $s20 = "&&string;name=airplaneeasterdheadingw168" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _118f0bba26f3fd4f1c535ba9117ec80eda9945e6a7fe8af7511178ac60a7717_18 {
   meta:
      description = "16-07-2026-14.49 - from files 118f0bba26f3fd4f1c535ba9117ec80eda9945e6a7fe8af7511178ac60a77170.apk, 129ee4f3dd5ecd07a3f815616300a2adcd6702239c1ae3e31a3d61cf7913c4cb.apk, 14ebed0d51768cfa90ace0d74ce17763a7accd1c526976e5b4609156521e7ca8.apk, 2308afb58c08eec15d0ad9048e751eeca001bd17a2106484803c45ef351af752.apk, acf2d29c8c65ee2fe57445e672fbee01fa240b0039b66ea507f110468c6c8210.apk, cc93d01b68b59314a789c5355ac70b8e6965b9f64bb331b0337aac9d2da8aede.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "118f0bba26f3fd4f1c535ba9117ec80eda9945e6a7fe8af7511178ac60a77170"
      hash2 = "129ee4f3dd5ecd07a3f815616300a2adcd6702239c1ae3e31a3d61cf7913c4cb"
      hash3 = "14ebed0d51768cfa90ace0d74ce17763a7accd1c526976e5b4609156521e7ca8"
      hash4 = "2308afb58c08eec15d0ad9048e751eeca001bd17a2106484803c45ef351af752"
      hash5 = "acf2d29c8c65ee2fe57445e672fbee01fa240b0039b66ea507f110468c6c8210"
      hash6 = "cc93d01b68b59314a789c5355ac70b8e6965b9f64bb331b0337aac9d2da8aede"
   strings:
      $s1 = "((string;name=volunteerthermalgexecutex480" fullword ascii
      $s2 = "((string;name=threadsdrawingsidownloady486" fullword ascii
      $s3 = "%%string;name=supportsghostfawesomeq524" fullword ascii
      $s4 = "&&string;name=detailsmarshallmincomet558" fullword ascii
      $s5 = "&&string;name=turkeyexistingyaffectso130" fullword ascii
      $s6 = "''string;name=characteristicdownloadeds76" fullword ascii
      $s7 = "%%string;name=continuesubscriptionsl718" fullword ascii
      $s8 = "##string;name=coloreddescriptionsw838" fullword ascii
      $s9 = "''string;name=cordlesschartmgenealogyw746" fullword ascii
      $s10 = "((string;name=encryptionmerrysprospectc386" fullword ascii
      $s11 = "##string;name=defencepostalfturnsw512" fullword ascii
      $s12 = "$$string;name=promotingdggaircrafta240" fullword ascii
      $s13 = "**string;name=postageworkuakazgeographicy808" fullword ascii
      $s14 = "string;name=oursranklusagew510" fullword ascii
      $s15 = "((string;name=logicstepssconsiderationy184" fullword ascii
      $s16 = "$$string;name=magnitudegulftplacedj170" fullword ascii
      $s17 = "!!string;name=spywarefantasydums272" fullword ascii
      $s18 = "%%string;name=certifiedhelloybeginsn434" fullword ascii
      $s19 = "##string;name=eyespspuchallengingg168" fullword ascii
      $s20 = "''string;name=operatorstickerxchangedj924" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _108ca43c5a62640b5e3d71df33c00549c46634c1109c1ac6690df89fbc4211f_19 {
   meta:
      description = "16-07-2026-14.49 - from files 108ca43c5a62640b5e3d71df33c00549c46634c1109c1ac6690df89fbc4211fd.apk, 2b6d20746ed11f62b35a7c29d1912de18248e9e10247c29a6ee0929877a57d77.apk, 678ee44afb89903d3199378f2e6d9de0b4167c23e548bf4d7f863e1545ef912e.apk, 9aafbc143c66661609f34c483a85015f30f7da2a38f375d9e10c8eeadc6cb5da.apk, cec6fc6496687b177b14d6699d82a18840b528bff5543dfb6e23c0849f3c8de2.apk, deb2cc80a190e73d81758b738bac4e8f0f116b587b07d65ddc8b668f0b89b0bb.apk, e7bc41c6d3677ef941dfc8eb4b571435623dab1e8c0681b6253c37725844b268.apk, ef94a5ecaf100b9c9102b101b98f8c01fae9ea9304e5b8fbf6097beec59ad885.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      $s4 = "&&string;name=downloadedgrounduchessc426" fullword ascii
      $s5 = "((string;name=accountabilitycompletingy816" fullword ascii
      $s6 = "((string;name=assessingoverheaduexemptj102" fullword ascii
      $s7 = "  string;name=theirbadgetgainsn110" fullword ascii
      $s8 = "\"\"string;name=headlinetattoosptyi814" fullword ascii
      $s9 = "##string;name=headlinesrecipeminci850" fullword ascii
      $s10 = "''string;name=provisionsspinedgettingt906" fullword ascii
      $s11 = "##string;name=newspaperimmunologyt734" fullword ascii
      $s12 = "&&string;name=macintoshmsvrecognisedz212" fullword ascii
      $s13 = "))string;name=johnsbudgetshtransexualesl358" fullword ascii
      $s14 = "string;name=minecomedygsamw938" fullword ascii
      $s15 = "''string;name=complexitypromohfemalesr952" fullword ascii
      $s16 = "$$string;name=commissionluislcracks802" fullword ascii
      $s17 = "string;name=nikepassengersz274" fullword ascii
      $s18 = "((string;name=comparativewaiverlsisterl144" fullword ascii
      $s19 = "$$string;name=recognitionframeworki674" fullword ascii
      $s20 = "**string;name=committeeshelpsibusinessesu302" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _23468bb2042bb18d50f25d04d3a4d3a793e039a52a8dea9559e15289a95468e_20 {
   meta:
      description = "16-07-2026-14.49 - from files 23468bb2042bb18d50f25d04d3a4d3a793e039a52a8dea9559e15289a95468ec.apk, 3493d2bc0e7a1b2ccbeca6e1dd2fbcef8109cc50289596816c89e154e4f2edde.apk, 3eaa49a1229343c1885b08f13ecdc2638875f66fd851b7b2baa534894e56921d.apk, 41474b00b02b03fca4fa0e6765d690d540b9a19b11478006acdd865d845ebe9a.apk, 6828dcb4d6526999c531a4cb47a78fa1f2c16902256f0d309b051208410c1270.apk, 76cdbbbd920cdc8a2b3ccbc33b39cdcfa344fb9bae0222b5ff376fa78d29b735.apk, ae87e247ec3b1fb23412297b90473a1641fb4ce0d5142b92da4b07283996ed88.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "23468bb2042bb18d50f25d04d3a4d3a793e039a52a8dea9559e15289a95468ec"
      hash2 = "3493d2bc0e7a1b2ccbeca6e1dd2fbcef8109cc50289596816c89e154e4f2edde"
      hash3 = "3eaa49a1229343c1885b08f13ecdc2638875f66fd851b7b2baa534894e56921d"
      hash4 = "41474b00b02b03fca4fa0e6765d690d540b9a19b11478006acdd865d845ebe9a"
      hash5 = "6828dcb4d6526999c531a4cb47a78fa1f2c16902256f0d309b051208410c1270"
      hash6 = "76cdbbbd920cdc8a2b3ccbc33b39cdcfa344fb9bae0222b5ff376fa78d29b735"
      hash7 = "ae87e247ec3b1fb23412297b90473a1641fb4ce0d5142b92da4b07283996ed88"
   strings:
      $s1 = "attempted to close file descriptor %d, expected to be owned by %s 0x%lx, actually owned by %s 0x%lx" fullword ascii
      $s2 = ";; ->>HEADER<<- opcode: %s, status: %s, id: %d" fullword ascii
      $s3 = "attempted to close file descriptor %d, expected to be owned by %s 0x%lx, actually unowned" fullword ascii
      $s4 = "attempted to close file descriptor %d, expected to be unowned, actually owned by %s 0x%lx" fullword ascii
      $s5 = "fcntl(F_SETFD) only supports FD_CLOEXEC but was passed %p" fullword ascii
      $s6 = "error: \"%s\": executable's TLS segment is underaligned: alignment is %zu (skew %zu), needs to be at least %zu for %s Bionic" fullword ascii
      $s7 = "Contending for pthread mutex" fullword ascii
      $s8 = "%s: could not read header of \"%s\": %s" fullword ascii
      $s9 = "dynamic host configuration identifier" fullword ascii
      $s10 = "gethostby*.getanswer: asked for \"%s %s %s\", got type \"%s\"" fullword ascii
      $s11 = "failed to exchange ownership of file descriptor: fd %d is owned by %s 0x%lx, was expected to be unowned" fullword ascii
      $s12 = "pthread_create failed: couldn't mprotect %s %zu-byte thread mapping region: %m" fullword ascii
      $s13 = "Pointer tag for %p was truncated, see 'https://source.android.com/devices/tech/debug/tagged-pointers'." fullword ascii
      $s14 = "failed to exchange ownership of file descriptor: fd %d is owned by %s 0x%lx, was expected to be owned by %s 0x%lx" fullword ascii
      $s15 = "failed to exchange ownership of file descriptor: fd %d is unowned, was expected to be owned by %s 0x%lx" fullword ascii
      $s16 = "shadow stack read-write mprotect(%p, %d) failed: %m" fullword ascii
      $s17 = "The property \"%s\" has a value with length %zu that is too large for __system_property_get()/__system_property_read(); use __sy" ascii
      $s18 = "Size (in kilobytes) of per-thread cache used to offload the global quarantine. Lower value may reduce memory usage but might inc" ascii
      $s19 = "double-close of file descriptor %d detected" fullword ascii
      $s20 = "CHECK failed @ %s:%d %s ((u64)op1=%llu, (u64)op2=%llu)" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _171e5b1e8f74f71e76e38cac85180865f4042b7aaab2f863901e40bc0da11d1_21 {
   meta:
      description = "16-07-2026-14.49 - from files 171e5b1e8f74f71e76e38cac85180865f4042b7aaab2f863901e40bc0da11d11.apk, 5e5ee3d24153feed686619e1979afc5fcfe82f94a43c62b197ed0644ffd31675.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "171e5b1e8f74f71e76e38cac85180865f4042b7aaab2f863901e40bc0da11d11"
      hash2 = "5e5ee3d24153feed686619e1979afc5fcfe82f94a43c62b197ed0644ffd31675"
   strings:
      $s1 = "The app is already installed" fullword ascii
      $s2 = "Huling update: Nob 21, 2025" fullword ascii
      $s3 = "Last update: Nov 21, 2025" fullword ascii
      $s4 = "A new update is available." fullword ascii
      $s5 = "Ano ang bago" fullword ascii
      $s6 = "May bagong update na available." fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _23468bb2042bb18d50f25d04d3a4d3a793e039a52a8dea9559e15289a95468e_22 {
   meta:
      description = "16-07-2026-14.49 - from files 23468bb2042bb18d50f25d04d3a4d3a793e039a52a8dea9559e15289a95468ec.apk, 2e51daa305891ae8c03beb20f3b77b40727d24ad9f51e9899606ee7c1e76ead2.apk, 3493d2bc0e7a1b2ccbeca6e1dd2fbcef8109cc50289596816c89e154e4f2edde.apk, 3eaa49a1229343c1885b08f13ecdc2638875f66fd851b7b2baa534894e56921d.apk, 41474b00b02b03fca4fa0e6765d690d540b9a19b11478006acdd865d845ebe9a.apk, 4a9c611455192a91d9289f6c318773d4bdd339edc04a359be4905e4f6e4a4a54.apk, 56ac9eb8ca22f4b05b1d64872d4209440fc97413c1225141f268e22ae93d1edd.apk, 6828dcb4d6526999c531a4cb47a78fa1f2c16902256f0d309b051208410c1270.apk, 76cdbbbd920cdc8a2b3ccbc33b39cdcfa344fb9bae0222b5ff376fa78d29b735.apk, 8b07fca15e1a89b27c6d2ac8508b36315ac56683555bf962e793a6131ab97e4e.apk, ae87e247ec3b1fb23412297b90473a1641fb4ce0d5142b92da4b07283996ed88.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      $s1 = "Exec format error" fullword ascii
      $s2 = "No child processes" fullword ascii
      $s3 = "Broken pipe" fullword ascii
      $s4 = "No such process" fullword ascii
      $s5 = "Attempting to link in too many shared libraries" fullword ascii
      $s6 = "Streams pipe error" fullword ascii
      $s7 = "Extended Key Usage" fullword ascii
      $s8 = "Too many users" fullword ascii
      $s9 = "Usage does not match the extendedKeyUsage extension" fullword ascii
      $s10 = "Protocol not supported" fullword ascii
      $s11 = "Usage does not match the keyUsage extension" fullword ascii
      $s12 = "Operation already in progress" fullword ascii
      $s13 = "Resource temporarily unavailable" fullword ascii
      $s14 = "Remote I/O error" fullword ascii
      $s15 = "Subject Key Identifier" fullword ascii
      $s16 = "Transport endpoint is already connected" fullword ascii
      $s17 = "Bad file descriptor" fullword ascii
      $s18 = "Invalid request descriptor" fullword ascii
      $s19 = "File descriptor in bad state" fullword ascii
      $s20 = "Authority Key Identifier" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09_23 {
   meta:
      description = "16-07-2026-14.49 - from files 59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f.apk, d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "59bd5011be93e9f724a61549099ddacc7471e406c96ea25dd78cfd711ccff09f"
      hash2 = "d3be25a24c99610e44eb9167c6592583ceca6e238709122f42c99c99415debe2"
   strings:
      $s1 = "libjpeg-turbo version 1.5.3 (build 20180808)" fullword ascii
      $s2 = "##System busy, please try again later" fullword ascii
      $s3 = "//An SSL error occurred. Do you want to continue?" fullword ascii
      $s4 = "BBCurrent network is unavailable, please check your network settings" fullword ascii
      $s5 = "Upgrade now" fullword ascii
      $s6 = "AA Please check that your network (or network control) is turned on" fullword ascii
      $s7 = "Copyright (C) 1991-2017 The libjpeg-turbo Project and many others" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _498b9dc568e47cd06099fbedb479e78556a7cd30a8cad589b003a77e09de2c5_24 {
   meta:
      description = "16-07-2026-14.49 - from files 498b9dc568e47cd06099fbedb479e78556a7cd30a8cad589b003a77e09de2c52.apk, 4f621122c29871e1d0464421c2abfc01036f27f1d3523b8b4d143f82a2c08c5a.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "498b9dc568e47cd06099fbedb479e78556a7cd30a8cad589b003a77e09de2c52"
      hash2 = "4f621122c29871e1d0464421c2abfc01036f27f1d3523b8b4d143f82a2c08c5a"
   strings:
      $s1 = "Failed to process audio, Youtube lite try again later. If Youtube lite keep seeing this Youtube lite, Youtube lite restart Youtu" ascii
      $s2 = "Failed to process audio, Youtube lite try again later. If Youtube lite keep seeing this Youtube lite, Youtube lite restart Youtu" ascii
      $s3 = "Failed to process GIF, Youtube lite try again later. If Youtube lite keep seeing this Youtube lite, Youtube lite restart Youtube" ascii
      $s4 = "Failed to process video, Youtube lite try again later. If Youtube lite keep seeing this Youtube lite, Youtube lite restart Youtu" ascii
      $s5 = "Failed to process video, Youtube lite try again later. If Youtube lite keep seeing this Youtube lite, Youtube lite restart Youtu" ascii
      $s6 = "Failed to process GIF, Youtube lite try again later. If Youtube lite keep seeing this Youtube lite, Youtube lite restart Youtube" ascii
      $s7 = "When Youtube lite log back into Youtube lite account, Youtube lite must enter the Youtube lite Youtube lite created when Youtube" ascii
      $s8 = "Youtube lite has a problem and it needs to be installed again. Tap on the button below to uninstall Youtube lite. Visit <a href=" ascii
      $s9 = "\"%s\">Youtube lite.com/android</a> afterwards to Youtube lite and reinstall Youtube lite." fullword ascii
      $s10 = "When turned on, Youtube lite backup will be end-to-end encrypted before it gets uploaded to Google Drive. No one, not even Googl" ascii
      $s11 = "When turned on, Youtube lite backup will be end-to-end encrypted before it gets uploaded to Google Drive. No one, not even Googl" ascii
      $s12 = "Companion mode allows Youtube lite to link this device to a registered Youtube lite account on Youtube lite phone. Switching to " ascii
      $s13 = "companion mode will log Youtube lite out from Youtube lite current Youtube lite account." fullword ascii
      $s14 = "RROur partners' systems are temporarily down. Youtube lite wait before trying again." fullword ascii
      $s15 = "<b>%s</b> is already registered on a different phone.<br/><br/>Confirm on Youtube lite other phone that Youtube lite want to mov" ascii
      $s16 = "wwThis includes the subject, icon, description, disappearing Youtube lite timer, and keeping and unkeeping Youtube lites." fullword ascii
      $s17 = "[[Couldn't log in. Check Youtube lite phone's Internet connection and scan the QR code again." fullword ascii
      $s18 = "!!Enter Youtube lite encryption key" fullword ascii
      $s19 = "Youtube lite encryption key" fullword ascii
      $s20 = "When Youtube lite log back into Youtube lite account, Youtube lite must enter the Youtube lite Youtube lite created when Youtube" ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c_25 {
   meta:
      description = "16-07-2026-14.49 - from files 01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c3.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 17fc5d1c8bd8b10471131282e42ec289bb1e1ee107ca676f369bb42fc3643af3.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 3502fa570ada49eaeeaa4785bb1897ed91dfadaa76c5e8626c5b8e944d8f5f01.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 57940c5eee8641e02f49d1122528665a0ddfbf5b6b0d4b910b5287e15542591d.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 6376bcd8faa57aac7437116b184967a588025e2bf96318272cdcf51ff2f8dfdd.apk, 6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e.apk, 6eb525100f54b9a830cd2d0f1169b053edb55332b2be73dd29a8b165b9ccdbf5.apk, 6f58b07b5ddabc29c9c7e7165349edbd2bee923446514044d67040de2f36664a.apk, 7593b0f4bc4c52cb359196f35868636b319641b01c8db9f662076285739a0505.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a6ed100ae42e4fdabfd1b4c992762152bc4a11cc8e521b647b444c75bb7a9782.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, b1c3a8818024ee86480bb83ea405ba2d9f96ea279e5cf9df19b3d3cb934ec42d.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, b99d175cbe06d4569a18449da044f326c68a56315ccc0da9cfa6f2c33bfd0939.apk, bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, c54861f54bcf72de5f16611ef0eec32c5c5f937bf3fdb5d6e611b2a2f9acdf2a.apk, c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64.apk, d0d4ef735a8bf076d81a6f3651d6bcfd8c69285049add2e6b6bee1276a99c37c.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, ef16cc8137d29356d0ef23b61ddb9cfd5e2784578fa818d54fe670bfa1e6ef73.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      $s1 = "ab%1$s no es pot executar sense Serveis de Google Play, que no " fullword ascii
      $s2 = "<A%1$s getur ekki keyrt nema " fullword ascii
      $s3 = "Error de Google Play Services" fullword ascii
      $s4 = "ilLa nouvelle version des services Google Play est n" fullword ascii
      $s5 = " version i ri i sh" fullword ascii
      $s6 = "Virhe Google Play -palveluissa" fullword ascii
      $s7 = " sen os servizos de Google Play, que non son compatibles co teu dispositivo." fullword ascii
      $s8 = " les services Google Play." fullword ascii
      $s9 = ".Google Play Services-" fullword ascii
      $s10 = " des services Google Play" fullword ascii
      $s11 = "YZ%1$s ne fonctionnera pas sans les services Google Play, qui sont actuellement mis " fullword ascii
      $s12 = "RTEn ny version av Google Play-tj" fullword ascii
      $s13 = "Google Play Services-fout" fullword ascii
      $s14 = "$$Error sa Mga Serbisyo ng Google Play" fullword ascii
      $s15 = "#=Google Play Services-" fullword ascii
      $s16 = "  Activer les services Google Play" fullword ascii
      $s17 = "iiHindi gagana ang %1$s nang wala ang mga serbisyo ng Google Play, na hindi nasusuportahan ng iyong device." fullword ascii
      $s18 = " jour les services Google Play" fullword ascii
      $s19 = "\"\"Installer les services Google Play" fullword ascii
      $s20 = "s compatible amb el teu dispositiu." fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _4ff07276c35f5e9c6f8ec37deaa0bc4f01f033a4e717ef8ce76ef371e8eee29_26 {
   meta:
      description = "16-07-2026-14.49 - from files 4ff07276c35f5e9c6f8ec37deaa0bc4f01f033a4e717ef8ce76ef371e8eee29b.apk, 6c1aeaeb5786f3632f0a02356b26bdde2ccf77e1e8c6d3f8f6b88e9458f7839f.apk, d9c47a7d7e42402c3ce2dd191ea09e9f7e29b1ee8d78d9aec0a47ed7b4bcdb80.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "4ff07276c35f5e9c6f8ec37deaa0bc4f01f033a4e717ef8ce76ef371e8eee29b"
      hash2 = "6c1aeaeb5786f3632f0a02356b26bdde2ccf77e1e8c6d3f8f6b88e9458f7839f"
      hash3 = "d9c47a7d7e42402c3ce2dd191ea09e9f7e29b1ee8d78d9aec0a47ed7b4bcdb80"
   strings:
      $s1 = "Failed to process video, Filterbypass try again later. If Filterbypass keep seeing this Filterbypass, Filterbypass restart Filte" ascii
      $s2 = "Failed to process GIF, Filterbypass try again later. If Filterbypass keep seeing this Filterbypass, Filterbypass restart Filterb" ascii
      $s3 = "Failed to process video, Filterbypass try again later. If Filterbypass keep seeing this Filterbypass, Filterbypass restart Filte" ascii
      $s4 = "Failed to process GIF, Filterbypass try again later. If Filterbypass keep seeing this Filterbypass, Filterbypass restart Filterb" ascii
      $s5 = "Failed to process audio, Filterbypass try again later. If Filterbypass keep seeing this Filterbypass, Filterbypass restart Filte" ascii
      $s6 = "Failed to process audio, Filterbypass try again later. If Filterbypass keep seeing this Filterbypass, Filterbypass restart Filte" ascii
      $s7 = "Filterbypass has a problem and it needs to be installed again. Tap on the button below to uninstall Filterbypass. Visit <a href=" ascii
      $s8 = "\"%s\">Filterbypass.com/android</a> afterwards to Filterbypass and reinstall Filterbypass." fullword ascii
      $s9 = "When turned on, Filterbypass backup will be end-to-end encrypted before it gets uploaded to Google Drive. No one, not even Googl" ascii
      $s10 = "When turned on, Filterbypass backup will be end-to-end encrypted before it gets uploaded to Google Drive. No one, not even Googl" ascii
      $s11 = "When Filterbypass log back into Filterbypass account, Filterbypass must enter the Filterbypass Filterbypass created when Filterb" ascii
      $s12 = "RROur partners' systems are temporarily down. Filterbypass wait before trying again." fullword ascii
      $s13 = "wwThis includes the subject, icon, description, disappearing Filterbypass timer, and keeping and unkeeping Filterbypasss." fullword ascii
      $s14 = "[[Couldn't log in. Check Filterbypass phone's Internet connection and scan the QR code again." fullword ascii
      $s15 = "Save Filterbypass key. Filterbypass does not have a copy of it. If Filterbypass forget Filterbypass key and lose Filterbypass ph" ascii
      $s16 = "MMFilterbypass personal Filterbypasss are <a href=\"%s\">end-to-end encrypted</a>" fullword ascii
      $s17 = "Filterbypass encryption key" fullword ascii
      $s18 = "companion mode will log Filterbypass out from Filterbypass current Filterbypass account." fullword ascii
      $s19 = "!!Enter Filterbypass encryption key" fullword ascii
      $s20 = "Companion mode allows Filterbypass to link this device to a registered Filterbypass account on Filterbypass phone. Switching to " ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _02944967154e515f87bb411641edd9931ea6b4a4088ab73efe87cbe7b9d5b59_27 {
   meta:
      description = "16-07-2026-14.49 - from files 02944967154e515f87bb411641edd9931ea6b4a4088ab73efe87cbe7b9d5b592.apk, 118f0bba26f3fd4f1c535ba9117ec80eda9945e6a7fe8af7511178ac60a77170.apk, 15839ac050341de16481e5e425f5f1a791547651d4aeda398217f823f0f321f9.apk, 272248f64722ef49413a6f3c339aecb78785546c1c65b9c2897e3915bd91be28.apk, 3dc24332f897ef758c38e4959624606236a3c63a1ba2e0b3d268ed6ce40b5c1a.apk, ab1363201d0897ab7c55dceb1f8664a58ac65fe4aee3c9600c5d7659f8ae58a9.apk, b38d466dbb28feb20f4f8cc9d9a3b2204bf38e487e7cc5f057a756dd5f40b7c6.apk, cc93d01b68b59314a789c5355ac70b8e6965b9f64bb331b0337aac9d2da8aede.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "02944967154e515f87bb411641edd9931ea6b4a4088ab73efe87cbe7b9d5b592"
      hash2 = "118f0bba26f3fd4f1c535ba9117ec80eda9945e6a7fe8af7511178ac60a77170"
      hash3 = "15839ac050341de16481e5e425f5f1a791547651d4aeda398217f823f0f321f9"
      hash4 = "272248f64722ef49413a6f3c339aecb78785546c1c65b9c2897e3915bd91be28"
      hash5 = "3dc24332f897ef758c38e4959624606236a3c63a1ba2e0b3d268ed6ce40b5c1a"
      hash6 = "ab1363201d0897ab7c55dceb1f8664a58ac65fe4aee3c9600c5d7659f8ae58a9"
      hash7 = "b38d466dbb28feb20f4f8cc9d9a3b2204bf38e487e7cc5f057a756dd5f40b7c6"
      hash8 = "cc93d01b68b59314a789c5355ac70b8e6965b9f64bb331b0337aac9d2da8aede"
   strings:
      $s1 = "Failed to process GIF, Blockchain try again later. If Blockchain keep seeing this Blockchain, Blockchain restart Blockchain devi" ascii
      $s2 = "Failed to process video, Blockchain try again later. If Blockchain keep seeing this Blockchain, Blockchain restart Blockchain de" ascii
      $s3 = "Failed to process audio, Blockchain try again later. If Blockchain keep seeing this Blockchain, Blockchain restart Blockchain de" ascii
      $s4 = "Failed to process audio, Blockchain try again later. If Blockchain keep seeing this Blockchain, Blockchain restart Blockchain de" ascii
      $s5 = "Failed to process GIF, Blockchain try again later. If Blockchain keep seeing this Blockchain, Blockchain restart Blockchain devi" ascii
      $s6 = "Failed to process video, Blockchain try again later. If Blockchain keep seeing this Blockchain, Blockchain restart Blockchain de" ascii
      $s7 = "When Blockchain log back into Blockchain account, Blockchain must enter the Blockchain Blockchain created when Blockchain turned" ascii
      $s8 = "Blockchain has a problem and it needs to be installed again. Tap on the button below to uninstall Blockchain. Visit <a href=\"%s" ascii
      $s9 = "When turned on, Blockchain backup will be end-to-end encrypted before it gets uploaded to Google Drive. No one, not even Google " ascii
      $s10 = "When turned on, Blockchain backup will be end-to-end encrypted before it gets uploaded to Google Drive. No one, not even Google " ascii
      $s11 = "Companion mode allows Blockchain to link this device to a registered Blockchain account on Blockchain phone. Switching to compan" ascii
      $s12 = "PPOur partners' systems are temporarily down. Blockchain wait before trying again." fullword ascii
      $s13 = ">Blockchain.com/android</a> afterwards to Blockchain and reinstall Blockchain." fullword ascii
      $s14 = "YYCouldn't log in. Check Blockchain phone's Internet connection and scan the QR code again." fullword ascii
      $s15 = "ssThis includes the subject, icon, description, disappearing Blockchain timer, and keeping and unkeeping Blockchains." fullword ascii
      $s16 = "<b>%s</b> is already registered on a different phone.<br/><br/>Confirm on Blockchain other phone that Blockchain want to move Bl" ascii
      $s17 = "ion mode will log Blockchain out from Blockchain current Blockchain account." fullword ascii
      $s18 = "When Blockchain log back into Blockchain account, Blockchain must enter the Blockchain Blockchain created when Blockchain turned" ascii
      $s19 = "Blockchain encryption key" fullword ascii
      $s20 = "Blockchain devices were logged out due to an unexpected issue. Blockchain relink Blockchain devices. <a href=\"%s\">Learn" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _2b6d20746ed11f62b35a7c29d1912de18248e9e10247c29a6ee0929877a57d7_28 {
   meta:
      description = "16-07-2026-14.49 - from files 2b6d20746ed11f62b35a7c29d1912de18248e9e10247c29a6ee0929877a57d77.apk, 9aafbc143c66661609f34c483a85015f30f7da2a38f375d9e10c8eeadc6cb5da.apk, cec6fc6496687b177b14d6699d82a18840b528bff5543dfb6e23c0849f3c8de2.apk, deb2cc80a190e73d81758b738bac4e8f0f116b587b07d65ddc8b668f0b89b0bb.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "2b6d20746ed11f62b35a7c29d1912de18248e9e10247c29a6ee0929877a57d77"
      hash2 = "9aafbc143c66661609f34c483a85015f30f7da2a38f375d9e10c8eeadc6cb5da"
      hash3 = "cec6fc6496687b177b14d6699d82a18840b528bff5543dfb6e23c0849f3c8de2"
      hash4 = "deb2cc80a190e73d81758b738bac4e8f0f116b587b07d65ddc8b668f0b89b0bb"
   strings:
      $s1 = "yyFailed to process GIF, Telegram try again later. If Telegram keep seeing this Telegram, Telegram restart Telegram device." fullword ascii
      $s2 = "{{Failed to process video, Telegram try again later. If Telegram keep seeing this Telegram, Telegram restart Telegram device." fullword ascii
      $s3 = "{{Failed to process audio, Telegram try again later. If Telegram keep seeing this Telegram, Telegram restart Telegram device." fullword ascii
      $s4 = "When Telegram log back into Telegram account, Telegram must enter the Telegram Telegram created when Telegram turned on end-to-e" ascii
      $s5 = "Telegram has a problem and it needs to be installed again. Tap on the button below to uninstall Telegram. Visit <a href=\"%s\">T" ascii
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
      $s16 = "Telegram encryption key" fullword ascii
      $s17 = "EETelegram personal Telegrams are <a href=\"%s\">end-to-end encrypted</a>" fullword ascii
      $s18 = "Enter Telegram encryption key" fullword ascii
      $s19 = "de will log Telegram out from Telegram current Telegram account." fullword ascii
      $s20 = "UUThe Telegram Telegram entered is incorrect. Telegram only have one attempt remaining." fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c_29 {
   meta:
      description = "16-07-2026-14.49 - from files 01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c3.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 17fc5d1c8bd8b10471131282e42ec289bb1e1ee107ca676f369bb42fc3643af3.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 3502fa570ada49eaeeaa4785bb1897ed91dfadaa76c5e8626c5b8e944d8f5f01.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 57940c5eee8641e02f49d1122528665a0ddfbf5b6b0d4b910b5287e15542591d.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 6376bcd8faa57aac7437116b184967a588025e2bf96318272cdcf51ff2f8dfdd.apk, 6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e.apk, 6eb525100f54b9a830cd2d0f1169b053edb55332b2be73dd29a8b165b9ccdbf5.apk, 6f58b07b5ddabc29c9c7e7165349edbd2bee923446514044d67040de2f36664a.apk, 7593b0f4bc4c52cb359196f35868636b319641b01c8db9f662076285739a0505.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e.apk, a2f827bcb3acc7ccfc45f202a0e8adae2cd6439ae46d0d4d401a418846761a2e.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a6ed100ae42e4fdabfd1b4c992762152bc4a11cc8e521b647b444c75bb7a9782.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, b1c3a8818024ee86480bb83ea405ba2d9f96ea279e5cf9df19b3d3cb934ec42d.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, b99d175cbe06d4569a18449da044f326c68a56315ccc0da9cfa6f2c33bfd0939.apk, bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, c54861f54bcf72de5f16611ef0eec32c5c5f937bf3fdb5d6e611b2a2f9acdf2a.apk, c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64.apk, d0d4ef735a8bf076d81a6f3651d6bcfd8c69285049add2e6b6bee1276a99c37c.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, ef16cc8137d29356d0ef23b61ddb9cfd5e2784578fa818d54fe670bfa1e6ef73.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      $s1 = " funciona com o Google Play Services ativado." fullword ascii
      $s2 = "Errore Google Play Services" fullword ascii
      $s3 = "llEr is een nieuwe versie van Google Play-services vereist. De update wordt binnenkort automatisch uitgevoerd." fullword ascii
      $s4 = " richiesta una nuova versione di Google Play Services. L'aggiornamento automatico verr" fullword ascii
      $s5 = "imLa nouvelle version des services Google" fullword ascii
      $s6 = "o funciona sem o Google Play Services, o qual n" fullword ascii
      $s7 = " senza Google Play Services, non supportati dal tuo dispositivo." fullword ascii
      $s8 = "DD%1$s funktioniert erst nach der Aktivierung der Google Play-Dienste." fullword ascii
      $s9 = "Attiva Google Play Services" fullword ascii
      $s10 = "o atualizada do Google Play Services." fullword ascii
      $s11 = " senza Google Play Services, attualmente in fase di aggiornamento." fullword ascii
      $s12 = "hjDu skal bruge en ny version af Google Play-tjenester. Opdateringen gennemf" fullword ascii
      $s13 = "Erro do Google Play Services" fullword ascii
      $s14 = "''Disponibilidade do Google Play Services" fullword ascii
      $s15 = "Play, qui ne sont pas compatibles avec votre appareil." fullword ascii
      $s16 = "fhEine neue Version der Google Play-Dienste wird ben" fullword ascii
      $s17 = " se non attivi Google Play Services." fullword ascii
      $s18 = "hi%1$s ne fonctionnera pas sans les services Google" fullword ascii
      $s19 = "o funciona sem o Google Play Services, o qual est" fullword ascii
      $s20 = "Aggiorna Google Play Services" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _0172d6141fc03c2e152caf35dce6c90cc0cec4f303de270f09136b93f1e99bc_30 {
   meta:
      description = "16-07-2026-14.49 - from files 0172d6141fc03c2e152caf35dce6c90cc0cec4f303de270f09136b93f1e99bcf.apk, 02437104c17dda825ba58e363f3eb11668b068f0fb66f31925c1a867899d1271.apk, 02944967154e515f87bb411641edd9931ea6b4a4088ab73efe87cbe7b9d5b592.apk, 09702ee08682153ab1862d45e2374699a62b6b3929a34ba30778f971ed09ef26.apk, 108ca43c5a62640b5e3d71df33c00549c46634c1109c1ac6690df89fbc4211fd.apk, 118f0bba26f3fd4f1c535ba9117ec80eda9945e6a7fe8af7511178ac60a77170.apk, 129ee4f3dd5ecd07a3f815616300a2adcd6702239c1ae3e31a3d61cf7913c4cb.apk, 14c47030d8220e682a1ec80c87d56c5bacf7a38abdf30df9bb532a85851259af.apk, 14ebed0d51768cfa90ace0d74ce17763a7accd1c526976e5b4609156521e7ca8.apk, 15839ac050341de16481e5e425f5f1a791547651d4aeda398217f823f0f321f9.apk, 16e5dff97af159b8093c1cc0ad59d12a141bcb6e0c530ed86e22c7f61f049c3d.apk, 1aeae34c264bbfbd4eed6d92a94ac788bfb9b050a54032fde811402d63f18bf8.apk, 1d15f0700a2dda228394bf37ad20ad2bd88c7813d6aca0199a6b40c704f80bc1.apk, 21b6b9c7262fe39d2f2ce49115c9c22f50d3e5b0b083a0f8c1ddd776c369ffd3.apk, 2308afb58c08eec15d0ad9048e751eeca001bd17a2106484803c45ef351af752.apk, 272248f64722ef49413a6f3c339aecb78785546c1c65b9c2897e3915bd91be28.apk, 2b6d20746ed11f62b35a7c29d1912de18248e9e10247c29a6ee0929877a57d77.apk, 33d2ea973f861bb7c46397c4e0f9aedc37ef10fb8ab2f4090f35a335d86ef0b2.apk, 34670aa23c3e50240fab2f820652f3f5d6eabf7177c6d6d4bba6c39a7b11aff9.apk, 3dc24332f897ef758c38e4959624606236a3c63a1ba2e0b3d268ed6ce40b5c1a.apk, 46326534553b3c5307d4c0347c12919b93b2699f9670593885cf52182a28180f.apk, 498b9dc568e47cd06099fbedb479e78556a7cd30a8cad589b003a77e09de2c52.apk, 4f621122c29871e1d0464421c2abfc01036f27f1d3523b8b4d143f82a2c08c5a.apk, 4ff07276c35f5e9c6f8ec37deaa0bc4f01f033a4e717ef8ce76ef371e8eee29b.apk, 5d4972e846d795b495d70fa054821c53678d2335b6879b4bf9a9116e101a8826.apk, 678ee44afb89903d3199378f2e6d9de0b4167c23e548bf4d7f863e1545ef912e.apk, 6c1aeaeb5786f3632f0a02356b26bdde2ccf77e1e8c6d3f8f6b88e9458f7839f.apk, 7775d8411c836f15e525320a984c90941127e7101ded1af8bb5b1234d50ebaf5.apk, 79f56edc1bb111c0323762dc0c25d9c50c9a62ec4dedc2cf2e0c2010e518b6b4.apk, 828a8180829f047507ad1052f14633cd9d4908037cf49c1d8b3c9799acce170d.apk, 82c352ef200bf69c49550c022fba8c33f96d6f1d9ba5fd5d1e53e7a4312fd006.apk, 84c5571ee75850514c0b09aa0f77b9ab5ea0b79bc8622371e3223810e67cd406.apk, 8de3ebe6fd8eef3d2bfa439913cac77ecb562c754a8935b1eb08eeae93b16173.apk, 97936d7873348f905d119dd9399261374aae494296e1b5fb3df521ef3cc76405.apk, 9aafbc143c66661609f34c483a85015f30f7da2a38f375d9e10c8eeadc6cb5da.apk, 9c1cc79b801e8d632bdb73517588e9e7626cf22643263f038c20cc42dfd0f922.apk, ab1363201d0897ab7c55dceb1f8664a58ac65fe4aee3c9600c5d7659f8ae58a9.apk, acf2d29c8c65ee2fe57445e672fbee01fa240b0039b66ea507f110468c6c8210.apk, b38d466dbb28feb20f4f8cc9d9a3b2204bf38e487e7cc5f057a756dd5f40b7c6.apk, b600af54745d2cf6529d048e701b579368af19ff69a08b5ae26d1f0d0a706047.apk, b9fb2177e55ad47b2df74ff642bd3ee5058d392c3e2e272b93bec263aa30eeef.apk, cc93d01b68b59314a789c5355ac70b8e6965b9f64bb331b0337aac9d2da8aede.apk, cec6fc6496687b177b14d6699d82a18840b528bff5543dfb6e23c0849f3c8de2.apk, d19edfbc70474a76b2dd6d8d0e844404f7b4c364c2278a6a668159e83310598a.apk, d9c47a7d7e42402c3ce2dd191ea09e9f7e29b1ee8d78d9aec0a47ed7b4bcdb80.apk, deb2cc80a190e73d81758b738bac4e8f0f116b587b07d65ddc8b668f0b89b0bb.apk, e7bc41c6d3677ef941dfc8eb4b571435623dab1e8c0681b6253c37725844b268.apk, ef94a5ecaf100b9c9102b101b98f8c01fae9ea9304e5b8fbf6097beec59ad885.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      $s4 = "  I used an encryption key instead" fullword ascii
      $s5 = "I lost my encryption key" fullword ascii
      $s6 = "Group description" fullword ascii
      $s7 = "My user info report" fullword ascii
      $s8 = "System Keyboard" fullword ascii
      $s9 = "Deactivate \"%s\" community?" fullword ascii
      $s10 = "Add group description" fullword ascii
      $s11 = "&&This community was already deactivated" fullword ascii
      $s12 = "Document failed to upload." fullword ascii
      $s13 = "Couldn't Complete Payment" fullword ascii
      $s14 = "''Couldn't load content. Try again later." fullword ascii
      $s15 = "Turn Off Encrypted Backups" fullword ascii
      $s16 = "Forget \"%1$s\"" fullword ascii
      $s17 = "!!End-to-end encrypted backup is on" fullword ascii
      $s18 = "\"\"End-to-end encrypted backup is off" fullword ascii
      $s19 = "create account" fullword ascii
      $s20 = "%1$s (12+ hours left)" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a9_31 {
   meta:
      description = "16-07-2026-14.49 - from files 1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90.apk, aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8.apk, ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90"
      hash2 = "aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8"
      hash3 = "ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33"
   strings:
      $x1 = "@<H2><b>Telegram</b>: @supercard_x<</H2><p>This software is a bank card payment relay tool, divided into <u><b>Card Reader</b></" ascii
      $s2 = "ter is used to pay the card on POS.</p><p>We keep in touch with users through Telegram, any Apk download not from our Telegram o" ascii
      $s3 = "ggPlease click Login button to start Follow our Telegram Channel for infomration and support @supercard_x" fullword ascii
      $s4 = "fficial channel are considered as fake. They may have back doors or virus can steal your private information or crypto assets.In" ascii
      $s5 = "u> and <u><b>POS Tapper</b></u> versions (this one is Card Reader). The former is used to read the remote bank card, and the lat" ascii
      $s6 = "??Authentication failed For assistance contact @supercard_support" fullword ascii
      $s7 = " If you accidentally enter the wrong amount and the recharge fails, contact support (English) for a refund. Telegram: @supercard" ascii
      $s8 = " If you accidentally enter the wrong amount and the recharge fails, contact support (English) for a refund. Telegram: @supercard" ascii
      $s9 = "<u>Do not use this software to perform high-risk transactions,you are solely responsible for the risk of losing funds or other l" ascii
      $s10 = " addition, our APP has built-in USDT recharge function, please do not trust any third-party recharge channels. <br><b>Note</b>: " ascii
      $s11 = "@<H2><b>Telegram</b>: @supercard_x<</H2><p>This software is a bank card payment relay tool, divided into <u><b>Card Reader</b></" ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 1 of ($x*) and all of them )
      ) or ( all of them )
}

rule _2e11badbd558a37c88ee22a7315c8220b90213fb712ea1ec1f39b14e3ae8475_32 {
   meta:
      description = "16-07-2026-14.49 - from files 2e11badbd558a37c88ee22a7315c8220b90213fb712ea1ec1f39b14e3ae8475c.apk, 774af64259ad726296fb4fc56ca91897c7da9acb3a10ad49325ead714f6562c4.apk, 9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c.apk, bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6.apk, d1fec0ce2be2097357d307e835783380ac010c7d55f3e72fa3906f0d0edd7a6a.apk, e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938.apk, e756a707443f382f4f93ca4b6101de16e4cac521d9032171c7b68b3a9585c39e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "2e11badbd558a37c88ee22a7315c8220b90213fb712ea1ec1f39b14e3ae8475c"
      hash2 = "774af64259ad726296fb4fc56ca91897c7da9acb3a10ad49325ead714f6562c4"
      hash3 = "9c859f4ec7db40e01ae74b43b59705c347faab489b493c4849879585b8383a2c"
      hash4 = "bac8753a8b07936d86a544d536bd857b427994fb614d39e1163989a93097ebb6"
      hash5 = "d1fec0ce2be2097357d307e835783380ac010c7d55f3e72fa3906f0d0edd7a6a"
      hash6 = "e218d424f50af9758788275d585d13bbd9bbdf25e1cbfc4015784140dc63f938"
      hash7 = "e756a707443f382f4f93ca4b6101de16e4cac521d9032171c7b68b3a9585c39e"
   strings:
      $s1 = "error: special e_phoff found at %s" fullword ascii
      $s2 = "error: symbol not found: %s" fullword ascii
      $s3 = "warning: bad symtab value of index %d" fullword ascii
      $s4 = "Corrupted block detected" fullword ascii
      $s5 = "roteVirbox Protector" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _5c15f4808ad986ff87797ff8d01120a5016d6182f08788db73072bec43d5381_33 {
   meta:
      description = "16-07-2026-14.49 - from files 5c15f4808ad986ff87797ff8d01120a5016d6182f08788db73072bec43d53814.apk, db11d9b51d90d23e5769d5f6dd738adad56acff41555698446926804d5396962.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "5c15f4808ad986ff87797ff8d01120a5016d6182f08788db73072bec43d53814"
      hash2 = "db11d9b51d90d23e5769d5f6dd738adad56acff41555698446926804d5396962"
   strings:
      $s1 = ")  **http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto    android http://schemas.android" ascii
      $s2 = "~  android http://schemas.android.com/apk/res/android  " fullword ascii
      $s3 = "]  android http://schemas.android.com/apk/res/android  " fullword ascii
      $s4 = "contentDescription layout_marginRight  focusable ellipsize " fullword ascii
      $s5 = "  android http://schemas.android.com/apk/res/android    **http://schemas.android.com/apk/res/android    app http://schemas.andro" ascii
      $s6 = "  **http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto    android http://schemas.android." ascii
      $s7 = "|  android http://schemas.android.com/apk/res/android    **http://schemas.android.com/apk/res/android    paddingTop " fullword ascii
      $s8 = "@  android http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto    **http://schemas.android" ascii
      $s9 = "roid.com/apk/res-auto   alpha" fullword ascii
      $s10 = "B  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android   " fullword ascii
      $s11 = "  android http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto    layout_height orientation" ascii
      $s12 = "1v  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android    app http://schemas.and" ascii
      $s13 = "e  android http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto  " fullword ascii
      $s14 = "  app http://schemas.android.com/apk/res-auto    **http://schemas.android.com/apk/res/android   interpolator  srcCompat " fullword ascii
      $s15 = "$q  android http://schemas.android.com/apk/res/android   " fullword ascii
      $s16 = ")  **http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto    android http://schemas.android" ascii
      $s17 = "  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android   id " fullword ascii
      $s18 = "^]  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android  " fullword ascii
      $s19 = "1v  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android    app http://schemas.and" ascii
      $s20 = ">  android http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto    **http://schemas.android" ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cff_34 {
   meta:
      description = "16-07-2026-14.49 - from files 1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cffb.apk, 5c15f4808ad986ff87797ff8d01120a5016d6182f08788db73072bec43d53814.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cffb"
      hash2 = "5c15f4808ad986ff87797ff8d01120a5016d6182f08788db73072bec43d53814"
   strings:
      $s1 = "paddingBottom  contentDescription set  duration  FrameLayout " fullword ascii
      $s2 = "contentDescription  alpha  paddingRight ImageView" fullword ascii
      $s3 = "ellipsize  contentDescription alpha duration " fullword ascii
      $s4 = "alpha contentDescription" fullword ascii
      $s5 = "contentDescription alpha  paddingBottom paddingTop" fullword ascii
      $s6 = "contentDescription focusable" fullword ascii
      $s7 = "set  fromAlpha  contentDescription interpolator " fullword ascii
      $s8 = "p  android http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto    **http://schemas.android" ascii
      $s9 = "T  android http://schemas.android.com/apk/res/android    **http://schemas.android.com/apk/res/android  " fullword ascii
      $s10 = "G  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android    app http://schemas.andr" ascii
      $s11 = "  **http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto   interpolator" fullword ascii
      $s12 = "}qy  **http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto    android http://schemas.andro" ascii
      $s13 = "G  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android    app http://schemas.andr" ascii
      $s14 = "  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android    app http://schemas.andro" ascii
      $s15 = "  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android   " fullword ascii
      $s16 = "KZ{  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android    Fragment " fullword ascii
      $s17 = "  android http://schemas.android.com/apk/res/android   paddingLeft" fullword ascii
      $s18 = "  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android    layout_height layout_wei" ascii
      $s19 = "p  android http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto    **http://schemas.android" ascii
      $s20 = "  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android    app http://schemas.andro" ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e_35 {
   meta:
      description = "16-07-2026-14.49 - from files 1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9.apk, 2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1.apk, 3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd.apk, 4984ee88649838a6e7a7e4a26ffb5ae7730e1bf8e05a6122f2439985f0f9d951.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      $s6 = "Confirm logout?" fullword ascii
      $s7 = "FFScan QR code / click to copy address (automatic receipt after payment)" fullword ascii
      $s8 = "n predeterminada para pago NFC. Vaya a configuraciones NFC para que funcione correctamente." fullword ascii
      $s9 = "USDT Address" fullword ascii
      $s10 = "z{NFC desactivado. Vaya a configuraciones para habilitarlo. Si est" fullword ascii
      $s11 = "qqNFC is not enabled. Please go to system settings to enable NFC. If already enabled, restart device and try again!" fullword ascii
      $s12 = "OREscaneie QR para pagar / Clique para copiar (cr" fullword ascii
      $s13 = "SVEscanee QR para pagar / Haga clic para copiar (cr" fullword ascii
      $s14 = "Seleccione el plan" fullword ascii
      $s15 = "Payment Amount:" fullword ascii
      $s16 = "mero: Activado" fullword ascii
      $s17 = "1 WEEK / " fullword ascii
      $s18 = "Pos terminal offline" fullword ascii
      $s19 = "GHValor da transfer" fullword ascii
      $s20 = "mero: Desactivado" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cff_36 {
   meta:
      description = "16-07-2026-14.49 - from files 1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cffb.apk, db11d9b51d90d23e5769d5f6dd738adad56acff41555698446926804d5396962.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "1a91660cae8d1154e1979f31400b8956ed7e548586f314593e3e0f639838cffb"
      hash2 = "db11d9b51d90d23e5769d5f6dd738adad56acff41555698446926804d5396962"
   strings:
      $s1 = "interpolator  app  contentDescription FrameLayout " fullword ascii
      $s2 = "2  android http://schemas.android.com/apk/res/android  " fullword ascii
      $s3 = "android contentDescription" fullword ascii
      $s4 = "contentDescription interpolator" fullword ascii
      $s5 = "  app http://schemas.android.com/apk/res-auto    **http://schemas.android.com/apk/res/android    android http://schemas.android." ascii
      $s6 = "style  RecyclerView FrameLayout" fullword ascii
      $s7 = "oid.com/apk/res-auto   layout_margin app  android layout_marginStart " fullword ascii
      $s8 = "p7^V  android http://schemas.android.com/apk/res/android    **http://schemas.android.com/apk/res/android    LinearLayout " fullword ascii
      $s9 = "!  app http://schemas.android.com/apk/res-auto    android http://schemas.android.com/apk/res/android    **http://schemas.android" ascii
      $s10 = "7  android http://schemas.android.com/apk/res/android    **http://schemas.android.com/apk/res/android    app http://schemas.andr" ascii
      $s11 = "P(  android http://schemas.android.com/apk/res/android    **http://schemas.android.com/apk/res/android   " fullword ascii
      $s12 = "7  android http://schemas.android.com/apk/res/android    **http://schemas.android.com/apk/res/android    app http://schemas.andr" ascii
      $s13 = "!  app http://schemas.android.com/apk/res-auto    android http://schemas.android.com/apk/res/android    **http://schemas.android" ascii
      $s14 = "V  android http://schemas.android.com/apk/res/android    app http://schemas.android.com/apk/res-auto  " fullword ascii
      $s15 = "  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android    app http://schemas.andro" ascii
      $s16 = "s  android http://schemas.android.com/apk/res/android    **http://schemas.android.com/apk/res/android   paddingBottom layout_mar" ascii
      $s17 = "  android http://schemas.android.com/apk/res/android    **http://schemas.android.com/apk/res/android    app http://schemas.andro" ascii
      $s18 = "  app http://schemas.android.com/apk/res-auto    android http://schemas.android.com/apk/res/android   " fullword ascii
      $s19 = "yj  android http://schemas.android.com/apk/res/android   interpolator " fullword ascii
      $s20 = "  **http://schemas.android.com/apk/res/android    android http://schemas.android.com/apk/res/android    app http://schemas.andro" ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _0619168a8df6dd350052ca3a578abe15da0f2177e65acea55f44b5b59ed5f1c_37 {
   meta:
      description = "16-07-2026-14.49 - from files 0619168a8df6dd350052ca3a578abe15da0f2177e65acea55f44b5b59ed5f1c8.apk, 0badd9b4b0e44daeaa75b5d97ed9611a9f84418c1fb5683130e8b22742086549.apk, 0c8085cea946d655b266998fd60b1da33df73a4285328da3dabc7f0e7211411d.apk, 2117f4f448674fb5fafa5dd581777d35255253a4b82c9d0be2aac917efec8ae8.apk, 2a5f808f305334a0cfec1daa7290ace649079ab9c6dbed43f77ffdccb55c6e31.apk, 3638754e7fd889e9ced9127e7abe08191b7e8df3d60ed284c7b507e1e8082613.apk, 399c4819af422e581639c9350dcba71b0ee00b87a4d37da11806db5e25a0adc5.apk, 3ab3cc3c0df02d723c850e712fa5f4a0de29f2addf2c50beffe222112c2baa38.apk, 3c0a6f866aa4d74d0b39a2b9d11692ffa7291fd46b414e73cd5f9c7f9f030b75.apk, 41930e6f9187c8be4ea41303dd957d74f65b97944321a24a20028e76d10e0588.apk, 4845bbe3b1f17da3783db71b6a471b9dc073c8459fe2981004fbbcd70144ec01.apk, 4f0508904ec488ea7767e9d124b78097aefa8f43cc1713e81a7c4f45e1ba77f0.apk, 51863351193ab67148e3e47255cad4927eb13939292c7854121ebedb4de28590.apk, 58cc948bd809292143e604c3e03735c9517f94b37dd35299ca5e81d7b902d620.apk, 63a19cd37e5f23ba982d004e587472bdc30d64af04e1b321419d8173a16c60cc.apk, 662bb00e9a82d43be45413fce12def326a1863f9cd3e63aa45b60d36ef7e0443.apk, 6a702c55f4ee54eeb35a991d7413328da1e56dde6e719babec23682423bec23f.apk, 6e87157051e31528627d600f310e0b7252f85fcaf9607b34e5a4156b2d14cdec.apk, 75b4d9eb26ed9e20009c9a55a58e66457d7ec4d7d060179f09f6522e96c62e2e.apk, 7b167d362a9282adb176095be2e5bd4692b4158b7bdf4c6c20870daed5b04665.apk, 904e4153d2026380dc42297173192e72de7e5d9ea50f16bf8df2e2fa6922cdc3.apk, 95e88ec3ceb56c7f3679c45b837f931d0b38269a2e275628f2bc1a9f5c77a19f.apk, 9904bb103fae65ab3dd712f6b9ff361d3f3cb3a4cc814b69f0af3e2f1a837ecd.apk, 9ae895cd6474d1928bbbd68e240679c9de3c0ca327ac4e4b83845878b72322be.apk, a0edfa97344c870ee24aa7c008cec40e85e616c21e86522b8f6fce0324b356f7.apk, a97c8523696f6ef8f30cc6cf4b60a7a46fcb8716176741e09dfa81d5eacd8334.apk, b4b2197c5a8f0e9b9766fa39e9b538568284ec8a0099811b8b54fe6a1402545b.apk, be8adc196213154b10bd4209098ff94083d5ade71abeeacbf9d4cf30e3403234.apk, c5544517f1be9d5a721a951d906b26f9ad11adf4a06c3660a75e89f07dabb8aa.apk, c5dc6d8f325c125fba0a9ceea0cac957642fbf0a38bd4da867a82f6f06962d45.apk, ca5b40e938f68321dfa3a7f1ad2a03db4ff6ba27fdae5e230654cd5c30090692.apk, d5a84c85508c444743d055be354a464eb22dc5b33cba41e4b149829d182f4dca.apk, d69108a94a9a81e07a05d456dc997cbf5b5a8cc8f0869eae7904fac1da60f335.apk, d9b75d606803968d04015bed042da887905e9c1cb1b40b4ff11852b88c8b4d21.apk, ddeb13abf09d096f821ee657c3479f799f2a236b49f46c80a0afb2676a8f55ab.apk, dfa3539353b89089a3599f4775a296b270751738186af515bf3e630dc054bc7d.apk, e163a088d174d4eb41479b53e6df04831dc40899b893a0b183d080d2dfe52cd7.apk, e3d0cbffe67561de432b5b0e912328ed7c32c5fcfb3a5002515e34b517d7296b.apk, ee9eceda9522ae4c5ff3e07aefa523c61d50ebb9aca2808e0f4494a8c53498ea.apk, faab917444988b9a2e8d5d5bc06a0423c53718f92cbb8840cc6632f464c89130.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      $s5 = "**Errore: file di installazione non trovato." fullword ascii
      $s6 = "((Failed to prepare the installation file." fullword ascii
      $s7 = "##Error: installation file not found." fullword ascii
      $s8 = "- Yeni " fullword ascii
      $s9 = "//Impossibile preparare il file di installazione." fullword ascii
      $s10 = "Info icon" fullword ascii
      $s11 = "Taille : 2.2 Mo" fullword ascii
      $s12 = "- Fixed critical bugs." fullword ascii
      $s13 = "Size: 2.2 MB" fullword ascii
      $s14 = "n alma" fullword ascii
      $s15 = "n para usar la aplicaci" fullword ascii
      $s16 = "!!Vous pouvez lancer l'application." fullword ascii
      $s17 = "66You need to install the update to use the application." fullword ascii
      $s18 = "ABPour utiliser l'application, vous devez installer la mise " fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a9_38 {
   meta:
      description = "16-07-2026-14.49 - from files 1660b4fe77254fac07aabaf39a11ae3462a6513cc861c8620b56b8734aa46a90.apk, 2c6b914f9e27482152f704d3baea6c8030da859c9f5807be4e615680f93563a0.apk, aa264d6f85a121013d96bf0fe81239c328ae49c5965f49a91ca9049b968b2db8.apk, ba622a4f0d30c433a1d36ddff294759582067d5eae438937def75987fac67b33.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      $s15 = "digit code after the decimal point. Input errors will cause the recharge to fail. " fullword ascii
      $s16 = "bbResetting NFC and APDU Services (%1$d Sec) please restart App manually later. SuperCard ForceReset" fullword ascii
      $s17 = "Telegram @supercard_support" fullword ascii
      $s18 = "For assistance contact @supercard_support" fullword ascii
      $s19 = "Telegram: @supercard_support" fullword ascii
      $s20 = "&&Configuring the server, please wait..." fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _2117f4f448674fb5fafa5dd581777d35255253a4b82c9d0be2aac917efec8ae_39 {
   meta:
      description = "16-07-2026-14.49 - from files 2117f4f448674fb5fafa5dd581777d35255253a4b82c9d0be2aac917efec8ae8.apk, 58cc948bd809292143e604c3e03735c9517f94b37dd35299ca5e81d7b902d620.apk, 6e87157051e31528627d600f310e0b7252f85fcaf9607b34e5a4156b2d14cdec.apk, 9904bb103fae65ab3dd712f6b9ff361d3f3cb3a4cc814b69f0af3e2f1a837ecd.apk, a97c8523696f6ef8f30cc6cf4b60a7a46fcb8716176741e09dfa81d5eacd8334.apk, c5544517f1be9d5a721a951d906b26f9ad11adf4a06c3660a75e89f07dabb8aa.apk, c5dc6d8f325c125fba0a9ceea0cac957642fbf0a38bd4da867a82f6f06962d45.apk, e3d0cbffe67561de432b5b0e912328ed7c32c5fcfb3a5002515e34b517d7296b.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "2117f4f448674fb5fafa5dd581777d35255253a4b82c9d0be2aac917efec8ae8"
      hash2 = "58cc948bd809292143e604c3e03735c9517f94b37dd35299ca5e81d7b902d620"
      hash3 = "6e87157051e31528627d600f310e0b7252f85fcaf9607b34e5a4156b2d14cdec"
      hash4 = "9904bb103fae65ab3dd712f6b9ff361d3f3cb3a4cc814b69f0af3e2f1a837ecd"
      hash5 = "a97c8523696f6ef8f30cc6cf4b60a7a46fcb8716176741e09dfa81d5eacd8334"
      hash6 = "c5544517f1be9d5a721a951d906b26f9ad11adf4a06c3660a75e89f07dabb8aa"
      hash7 = "c5dc6d8f325c125fba0a9ceea0cac957642fbf0a38bd4da867a82f6f06962d45"
      hash8 = "e3d0cbffe67561de432b5b0e912328ed7c32c5fcfb3a5002515e34b517d7296b"
   strings:
      $s1 = "sending report" fullword ascii
      $s2 = "DD- Stability improvements." fullword ascii
      $s3 = "~~D8{\"backend\":\"dex\",\"compilation-mode\":\"debug\",\"has-checksums\":false,\"min-api\":26,\"sha-1\":\"abaab469b5ebd4dd2bb91" ascii
      $s4 = "- Minor fixes." fullword ascii
      $s5 = "- Performance optimization." fullword ascii
      $s6 = "attachBaseContext error: " fullword ascii
      $s7 = "decoy launch failed: " fullword ascii
      $s8 = "88A newer version is available. Please update to continue." fullword ascii
      $s9 = "~~D8{\"backend\":\"dex\",\"compilation-mode\":\"debug\",\"has-checksums\":false,\"min-api\":26,\"sha-1\":\"abaab469b5ebd4dd2bb91" ascii
      $s10 = " Provider missing in decoy mode: " fullword ascii
      $s11 = "silent block: liteResult=3" fullword ascii
      $s12 = "Rated for 3+" fullword ascii
      $s13 = "val$report" fullword ascii
      $s14 = "blocked: " fullword ascii
      $s15 = "Para mayores de 3 a" fullword ascii
      $s16 = " Android: " fullword ascii
      $s17 = "Stub App" fullword ascii
      $s18 = " for AndroidX Crawler" fullword ascii
      $s19 = "X Crawler" fullword ascii
      $s20 = " silent block: banned fingerprint" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _3aea0345c88f069d3a079c82571086adafb585137a86e277f4e5c9fb1b2190e_40 {
   meta:
      description = "16-07-2026-14.49 - from files 3aea0345c88f069d3a079c82571086adafb585137a86e277f4e5c9fb1b2190e6.apk, b3c86606b1410cc558acef06d55c2a03d41ad85cb2b04e904640f58b23185db3.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "3aea0345c88f069d3a079c82571086adafb585137a86e277f4e5c9fb1b2190e6"
      hash2 = "b3c86606b1410cc558acef06d55c2a03d41ad85cb2b04e904640f58b23185db3"
   strings:
      $s1 = "\\\\The content view in SmartRefreshLayout is empty. Do you forget to add it in xml layout file?" fullword ascii
      $s2 = "Refresh Failed" fullword ascii
      $s3 = "``%s falsify area," fullword ascii
      $s4 = "Load Failed" fullword ascii
      $s5 = " Represents the height[%.1fdp] of drag at run time," fullword ascii
      $s6 = "'Last Update' M-d HH:mm" fullword ascii
      $s7 = "Wait For Loading" fullword ascii
      $s8 = "Release To Load More" fullword ascii
      $s9 = " It does not show anything." fullword ascii
      $s10 = "Load Success" fullword ascii
      $s11 = "No More Data" fullword ascii
      $s12 = "Release To Second Floor" fullword ascii
      $s13 = "Pull Down To Refresh" fullword ascii
      $s14 = "Wait For Refreshing" fullword ascii
      $s15 = "Refresh Success" fullword ascii
      $s16 = "Pull Up To Load More" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _58cc948bd809292143e604c3e03735c9517f94b37dd35299ca5e81d7b902d62_41 {
   meta:
      description = "16-07-2026-14.49 - from files 58cc948bd809292143e604c3e03735c9517f94b37dd35299ca5e81d7b902d620.apk, 9904bb103fae65ab3dd712f6b9ff361d3f3cb3a4cc814b69f0af3e2f1a837ecd.apk, c5544517f1be9d5a721a951d906b26f9ad11adf4a06c3660a75e89f07dabb8aa.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "58cc948bd809292143e604c3e03735c9517f94b37dd35299ca5e81d7b902d620"
      hash2 = "9904bb103fae65ab3dd712f6b9ff361d3f3cb3a4cc814b69f0af3e2f1a837ecd"
      hash3 = "c5544517f1be9d5a721a951d906b26f9ad11adf4a06c3660a75e89f07dabb8aa"
   strings:
      $s1 = ",Login failed. Please check your credentials." fullword ascii
      $s2 = "/To reset your password, please contact support." fullword ascii
      $s3 = "*Incorrect login details. Please try again." fullword ascii
      $s4 = ")Account recovery is temporarily disabled." fullword ascii
      $s5 = "3Authentication failed. Incorrect login or password." fullword ascii
      $s6 = "DPassword reset is currently unavailable. Contact your administrator." fullword ascii
      $s7 = ";Please contact your IT administrator for password recovery." fullword ascii
      $s8 = ",Authorization error. Please try again later." fullword ascii
      $s9 = "Stay logged in" fullword ascii
      $s10 = "&Invalid credentials. Please try again." fullword ascii
      $s11 = "Trouble logging in?" fullword ascii
      $s12 = "#Access denied. Invalid credentials." fullword ascii
      $s13 = "Enter your credentials" fullword ascii
      $s14 = "SOC 2 Compliant" fullword ascii
      $s15 = "Access Account" fullword ascii
      $s16 = "Member access portal" fullword ascii
      $s17 = "Access your account" fullword ascii
      $s18 = "Company access code" fullword ascii
      $s19 = "Sign in to continue" fullword ascii
      $s20 = ". All rights reserved." fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _110cf99f4e796065b71aaf966e749ad6a0913919ec58cfc628b86aae84e24be_42 {
   meta:
      description = "16-07-2026-14.49 - from files 110cf99f4e796065b71aaf966e749ad6a0913919ec58cfc628b86aae84e24be4.apk, 364959964532e51ae14aa9e7b9e3f48594ac6343a2423e49ed27daafdbaf7753.apk, 580b39589c457f66e1feaa1f5e41830d1dc2091f31ec61dd393ca121bf3bed2e.apk, d0a15d8c5c2ea81c9d47e2553346e1713bfdb007f41d7c5d35a38d06d8611921.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "110cf99f4e796065b71aaf966e749ad6a0913919ec58cfc628b86aae84e24be4"
      hash2 = "364959964532e51ae14aa9e7b9e3f48594ac6343a2423e49ed27daafdbaf7753"
      hash3 = "580b39589c457f66e1feaa1f5e41830d1dc2091f31ec61dd393ca121bf3bed2e"
      hash4 = "d0a15d8c5c2ea81c9d47e2553346e1713bfdb007f41d7c5d35a38d06d8611921"
   strings:
      $s1 = "Media view" fullword ascii
      $s2 = "  Open ad when you're back online." fullword ascii
      $s3 = "Media View" fullword ascii
      $s4 = "$$Allow app to send you notifications?" fullword ascii
      $s5 = "AAWe'll send you a notification with a link to the advertiser site." fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c_43 {
   meta:
      description = "16-07-2026-14.49 - from files 01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c3.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 17fc5d1c8bd8b10471131282e42ec289bb1e1ee107ca676f369bb42fc3643af3.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 3502fa570ada49eaeeaa4785bb1897ed91dfadaa76c5e8626c5b8e944d8f5f01.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 57940c5eee8641e02f49d1122528665a0ddfbf5b6b0d4b910b5287e15542591d.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 6376bcd8faa57aac7437116b184967a588025e2bf96318272cdcf51ff2f8dfdd.apk, 6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e.apk, 6eb525100f54b9a830cd2d0f1169b053edb55332b2be73dd29a8b165b9ccdbf5.apk, 6f58b07b5ddabc29c9c7e7165349edbd2bee923446514044d67040de2f36664a.apk, 7593b0f4bc4c52cb359196f35868636b319641b01c8db9f662076285739a0505.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a6ed100ae42e4fdabfd1b4c992762152bc4a11cc8e521b647b444c75bb7a9782.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, b1c3a8818024ee86480bb83ea405ba2d9f96ea279e5cf9df19b3d3cb934ec42d.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, b99d175cbe06d4569a18449da044f326c68a56315ccc0da9cfa6f2c33bfd0939.apk, bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, c54861f54bcf72de5f16611ef0eec32c5c5f937bf3fdb5d6e611b2a2f9acdf2a.apk, c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64.apk, cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c.apk, d0d4ef735a8bf076d81a6f3651d6bcfd8c69285049add2e6b6bee1276a99c37c.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, ef16cc8137d29356d0ef23b61ddb9cfd5e2784578fa818d54fe670bfa1e6ef73.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      $s2 = "HH%1$s ondervind probleme met Google Play Dienste. Probeer asseblief weer." fullword ascii
      $s3 = "EERakendusel %1$s on probleeme Google Play teenustega. Proovige uuesti." fullword ascii
      $s4 = " problemes amb Serveis de Google Play. Torna-ho a provar." fullword ascii
      $s5 = "rbimet e Google Play. Provo s" fullword ascii
      $s6 = "FGAplikacija %1$s ima problema s Google Play uslugama. Poku" fullword ascii
      $s7 = "KK%1$s menghadapi masalah berhubung perkhidmatan Google Play. Sila cuba lagi." fullword ascii
      $s8 = " Google Play xidm" fullword ascii
      $s9 = "OPSovelluksella %1$s on ongelmia Google Play Palveluiden kanssa. Yrit" fullword ascii
      $s10 = "?@%1$s ten problemas cos servizos de Google Play. T" fullword ascii
      $s11 = "a s uslugama Google Playa. Poku" fullword ascii
      $s12 = "nda problem var. Daha sonra yenid" fullword ascii
      $s13 = "os do Google Play. Tente novamente." fullword ascii
      $s14 = ";;%1$s ima problema sa Google Play uslugama. Probajte ponovo." fullword ascii
      $s15 = "ma ar Google Play pakalpojumu darb" fullword ascii
      $s16 = " probleme privind serviciile Google Play. " fullword ascii
      $s17 = "KK%1$s inakumbwa na hitilafu ya huduma za Google Play. Tafadhali jaribu tena." fullword ascii
      $s18 = "nustu Google Play. Reyndu aftur." fullword ascii
      $s19 = "==%1$s inenkinga ngamasevisi e-Google Play. Sicela uzame futhi." fullword ascii
      $s20 = "%1$s Google Play " fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _02437104c17dda825ba58e363f3eb11668b068f0fb66f31925c1a867899d127_44 {
   meta:
      description = "16-07-2026-14.49 - from files 02437104c17dda825ba58e363f3eb11668b068f0fb66f31925c1a867899d1271.apk, 34670aa23c3e50240fab2f820652f3f5d6eabf7177c6d6d4bba6c39a7b11aff9.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "02437104c17dda825ba58e363f3eb11668b068f0fb66f31925c1a867899d1271"
      hash2 = "34670aa23c3e50240fab2f820652f3f5d6eabf7177c6d6d4bba6c39a7b11aff9"
   strings:
      $s1 = "~~Too many attempts. Try again after %d seconds." fullword ascii
      $s2 = "88Delete \"%s\" group?" fullword ascii
      $s3 = "n this setting back on at any time." fullword ascii
      $s4 = "8, will be able to access it." fullword ascii
      $s5 = "evice-confirmation-learn-more\">Learn more</a>" fullword ascii
      $s6 = "{Custom ROMs have been known to cause problems with keyboard input methods, cloud to device (C2DM) notifications as well as time" ascii
      $s7 = "all locally stored data and is not reversible." fullword ascii
      $s8 = "AADelete \"%s\" broadcast list?" fullword ascii
      $s9 = " team." fullword ascii
      $s10 = "all it again." fullword ascii
      $s11 = " precautions, this file cannot be sent." fullword ascii
      $s12 = " Group admins control who can change this setting. <a href=\"learn-more\">Learn" fullword ascii
      $s13 = "<<Delete broadcast list?" fullword ascii
      $s14 = " control who can change this setting. <a href=\"learn-more\">Learn" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c_45 {
   meta:
      description = "16-07-2026-14.49 - from files 01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c3.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 17fc5d1c8bd8b10471131282e42ec289bb1e1ee107ca676f369bb42fc3643af3.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 3502fa570ada49eaeeaa4785bb1897ed91dfadaa76c5e8626c5b8e944d8f5f01.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 41a9c5a298128b8c000227443ed3c1bf4e6ea17c4c8b91496ca7674ca62b08d7.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 57940c5eee8641e02f49d1122528665a0ddfbf5b6b0d4b910b5287e15542591d.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 6376bcd8faa57aac7437116b184967a588025e2bf96318272cdcf51ff2f8dfdd.apk, 6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e.apk, 6eb525100f54b9a830cd2d0f1169b053edb55332b2be73dd29a8b165b9ccdbf5.apk, 6f58b07b5ddabc29c9c7e7165349edbd2bee923446514044d67040de2f36664a.apk, 7593b0f4bc4c52cb359196f35868636b319641b01c8db9f662076285739a0505.apk, 7c8d8eaa543c4e9bb54e8f7da36a1ccf343042dc61ed9b60d586cf21e6b8f891.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e.apk, a2f827bcb3acc7ccfc45f202a0e8adae2cd6439ae46d0d4d401a418846761a2e.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a6ed100ae42e4fdabfd1b4c992762152bc4a11cc8e521b647b444c75bb7a9782.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, b1c3a8818024ee86480bb83ea405ba2d9f96ea279e5cf9df19b3d3cb934ec42d.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, b99d175cbe06d4569a18449da044f326c68a56315ccc0da9cfa6f2c33bfd0939.apk, bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, c54861f54bcf72de5f16611ef0eec32c5c5f937bf3fdb5d6e611b2a2f9acdf2a.apk, c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64.apk, cdcdef6cdfab4abbcf83265b1975fdecefbad68ab65931a74f4b930e5e22b29c.apk, d0d4ef735a8bf076d81a6f3651d6bcfd8c69285049add2e6b6bee1276a99c37c.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, ef16cc8137d29356d0ef23b61ddb9cfd5e2784578fa818d54fe670bfa1e6ef73.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      $s3 = "HH%1$s ondervindt problemen met Google Play-services. Probeer het opnieuw." fullword ascii
      $s4 = "LO%1$s, Google Play hizmetleriyle ilgili sorun ya" fullword ascii
      $s5 = "==%1$s mengalami masalah dengan layanan Google Play. Coba lagi." fullword ascii
      $s6 = " kilo problem" fullword ascii
      $s7 = "bami Google Play. Zkuste to pros" fullword ascii
      $s8 = "ug Google Play. Spr" fullword ascii
      $s9 = "ave s storitvami Google Play. Poskusite znova." fullword ascii
      $s10 = "Play. Veuillez r" fullword ascii
      $s11 = "OS%1$s ilovasini Google Play xizmatlariga ulab bo" fullword ascii
      $s12 = "bami Google Play. Sk" fullword ascii
      $s13 = "XeNaudojant program" fullword ascii
      $s14 = "EH%1$s ma problem z dost" fullword ascii
      $s15 = "]`L'application %1$s rencontre des probl" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _14c47030d8220e682a1ec80c87d56c5bacf7a38abdf30df9bb532a85851259a_46 {
   meta:
      description = "16-07-2026-14.49 - from files 14c47030d8220e682a1ec80c87d56c5bacf7a38abdf30df9bb532a85851259af.apk, 1d15f0700a2dda228394bf37ad20ad2bd88c7813d6aca0199a6b40c704f80bc1.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "14c47030d8220e682a1ec80c87d56c5bacf7a38abdf30df9bb532a85851259af"
      hash2 = "1d15f0700a2dda228394bf37ad20ad2bd88c7813d6aca0199a6b40c704f80bc1"
   strings:
      $s1 = "d-to-end encrypted backup." fullword ascii
      $s2 = "er service team." fullword ascii
      $s3 = "GGDelete \"%s\" group?" fullword ascii
      $s4 = " the community." fullword ascii
      $s5 = "w phone number." fullword ascii
      $s6 = "p to change." fullword ascii
      $s7 = ", and install it again." fullword ascii
      $s8 = "device." fullword ascii
      $s9 = "and receive SMS." fullword ascii
      $s10 = "ef=\"device-confirmation-learn-more\">Learn more</a>" fullword ascii
      $s11 = "ap to change." fullword ascii
      $s12 = "earn more</a>" fullword ascii
      $s13 = "pt. Tap to change." fullword ascii
      $s14 = "peration will erase all locally stored data and is not reversible." fullword ascii
      $s15 = "PPDelete \"%s\" broadcast list?" fullword ascii
      $s16 = "trust." fullword ascii
      $s17 = "oup and try again." fullword ascii
      $s18 = "urity precautions, this file cannot be sent." fullword ascii
      $s19 = "KKDelete broadcast list?" fullword ascii
      $s20 = "when kept. Group admins control who can change this setting. <a href=\"learn-more\">Learn" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _0619168a8df6dd350052ca3a578abe15da0f2177e65acea55f44b5b59ed5f1c_47 {
   meta:
      description = "16-07-2026-14.49 - from files 0619168a8df6dd350052ca3a578abe15da0f2177e65acea55f44b5b59ed5f1c8.apk, 0badd9b4b0e44daeaa75b5d97ed9611a9f84418c1fb5683130e8b22742086549.apk, 0c8085cea946d655b266998fd60b1da33df73a4285328da3dabc7f0e7211411d.apk, 2a5f808f305334a0cfec1daa7290ace649079ab9c6dbed43f77ffdccb55c6e31.apk, 3638754e7fd889e9ced9127e7abe08191b7e8df3d60ed284c7b507e1e8082613.apk, 399c4819af422e581639c9350dcba71b0ee00b87a4d37da11806db5e25a0adc5.apk, 3ab3cc3c0df02d723c850e712fa5f4a0de29f2addf2c50beffe222112c2baa38.apk, 3c0a6f866aa4d74d0b39a2b9d11692ffa7291fd46b414e73cd5f9c7f9f030b75.apk, 41930e6f9187c8be4ea41303dd957d74f65b97944321a24a20028e76d10e0588.apk, 4845bbe3b1f17da3783db71b6a471b9dc073c8459fe2981004fbbcd70144ec01.apk, 4f0508904ec488ea7767e9d124b78097aefa8f43cc1713e81a7c4f45e1ba77f0.apk, 51863351193ab67148e3e47255cad4927eb13939292c7854121ebedb4de28590.apk, 63a19cd37e5f23ba982d004e587472bdc30d64af04e1b321419d8173a16c60cc.apk, 662bb00e9a82d43be45413fce12def326a1863f9cd3e63aa45b60d36ef7e0443.apk, 6a702c55f4ee54eeb35a991d7413328da1e56dde6e719babec23682423bec23f.apk, 75b4d9eb26ed9e20009c9a55a58e66457d7ec4d7d060179f09f6522e96c62e2e.apk, 7b167d362a9282adb176095be2e5bd4692b4158b7bdf4c6c20870daed5b04665.apk, 904e4153d2026380dc42297173192e72de7e5d9ea50f16bf8df2e2fa6922cdc3.apk, 95e88ec3ceb56c7f3679c45b837f931d0b38269a2e275628f2bc1a9f5c77a19f.apk, 9ae895cd6474d1928bbbd68e240679c9de3c0ca327ac4e4b83845878b72322be.apk, a0edfa97344c870ee24aa7c008cec40e85e616c21e86522b8f6fce0324b356f7.apk, b4b2197c5a8f0e9b9766fa39e9b538568284ec8a0099811b8b54fe6a1402545b.apk, be8adc196213154b10bd4209098ff94083d5ade71abeeacbf9d4cf30e3403234.apk, ca5b40e938f68321dfa3a7f1ad2a03db4ff6ba27fdae5e230654cd5c30090692.apk, d5a84c85508c444743d055be354a464eb22dc5b33cba41e4b149829d182f4dca.apk, d69108a94a9a81e07a05d456dc997cbf5b5a8cc8f0869eae7904fac1da60f335.apk, d9b75d606803968d04015bed042da887905e9c1cb1b40b4ff11852b88c8b4d21.apk, ddeb13abf09d096f821ee657c3479f799f2a236b49f46c80a0afb2676a8f55ab.apk, dfa3539353b89089a3599f4775a296b270751738186af515bf3e630dc054bc7d.apk, e163a088d174d4eb41479b53e6df04831dc40899b893a0b183d080d2dfe52cd7.apk, ee9eceda9522ae4c5ff3e07aefa523c61d50ebb9aca2808e0f4494a8c53498ea.apk, faab917444988b9a2e8d5d5bc06a0423c53718f92cbb8840cc6632f464c89130.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      $s1 = " par Play Protect" fullword ascii
      $s2 = " Play Protect" fullword ascii
      $s3 = "##Play Protect tomonidan tekshirilgan" fullword ascii
      $s4 = "Verified by Play Protect" fullword ascii
      $s5 = "\"%Play Protect taraf" fullword ascii
      $s6 = "Verificado por Play Protect" fullword ascii
      $s7 = "Verificato da Play Protect" fullword ascii
      $s8 = "Play Protect " fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca616_48 {
   meta:
      description = "16-07-2026-14.49 - from files 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169"
      hash2 = "d8a736b8f6dcf3fe4f63dd5cfb1a05f587b1073f7e085f86e3cc4065a4c5babe"
   strings:
      $s1 = "Account Number" fullword ascii
      $s2 = "Account Holder Name" fullword ascii
      $s3 = "Single Digit" fullword ascii
      $s4 = "Single Pana" fullword ascii
      $s5 = "Triple Pana" fullword ascii
      $s6 = "Bank Details" fullword ascii
      $s7 = "Bank Name" fullword ascii
      $s8 = "Double Pana" fullword ascii
      $s9 = "Game Rates" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _23468bb2042bb18d50f25d04d3a4d3a793e039a52a8dea9559e15289a95468e_49 {
   meta:
      description = "16-07-2026-14.49 - from files 23468bb2042bb18d50f25d04d3a4d3a793e039a52a8dea9559e15289a95468ec.apk, 2e51daa305891ae8c03beb20f3b77b40727d24ad9f51e9899606ee7c1e76ead2.apk, 3493d2bc0e7a1b2ccbeca6e1dd2fbcef8109cc50289596816c89e154e4f2edde.apk, 3eaa49a1229343c1885b08f13ecdc2638875f66fd851b7b2baa534894e56921d.apk, 41474b00b02b03fca4fa0e6765d690d540b9a19b11478006acdd865d845ebe9a.apk, 56ac9eb8ca22f4b05b1d64872d4209440fc97413c1225141f268e22ae93d1edd.apk, 6828dcb4d6526999c531a4cb47a78fa1f2c16902256f0d309b051208410c1270.apk, 76cdbbbd920cdc8a2b3ccbc33b39cdcfa344fb9bae0222b5ff376fa78d29b735.apk, 8b07fca15e1a89b27c6d2ac8508b36315ac56683555bf962e793a6131ab97e4e.apk, ae87e247ec3b1fb23412297b90473a1641fb4ce0d5142b92da4b07283996ed88.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      $s1 = "Host: %s" fullword ascii
      $s2 = "Samurai" fullword ascii
      $s3 = "Gladiator" fullword ascii
      $s4 = "Viking" fullword ascii
      $s5 = "Accept: application/dns-message" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _0172d6141fc03c2e152caf35dce6c90cc0cec4f303de270f09136b93f1e99bc_50 {
   meta:
      description = "16-07-2026-14.49 - from files 0172d6141fc03c2e152caf35dce6c90cc0cec4f303de270f09136b93f1e99bcf.apk, acf2d29c8c65ee2fe57445e672fbee01fa240b0039b66ea507f110468c6c8210.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "0172d6141fc03c2e152caf35dce6c90cc0cec4f303de270f09136b93f1e99bcf"
      hash2 = "acf2d29c8c65ee2fe57445e672fbee01fa240b0039b66ea507f110468c6c8210"
   strings:
      $s1 = "eeded, as this operation will erase all locally stored data and is not reversible." fullword ascii
      $s2 = "r customer service team." fullword ascii
      $s3 = "SSDelete \"%s\" group?" fullword ascii
      $s4 = "ve to deactivate the community." fullword ascii
      $s5 = "\\\\Delete \"%s\" broadcast list?" fullword ascii
      $s6 = "when kept." fullword ascii
      $s7 = "when kept. Tap to change." fullword ascii
      $s8 = "e group and try again." fullword ascii
      $s9 = "an send and receive SMS." fullword ascii
      $s10 = "a href=\"device-confirmation-learn-more\">Learn more</a>" fullword ascii
      $s11 = "<a href=\"%2$s\">Learn more</a>" fullword ascii
      $s12 = "hen kept. Tap to change." fullword ascii
      $s13 = " this group again later." fullword ascii
      $s14 = "ings to a new phone number." fullword ascii
      $s15 = "hen kept" fullword ascii
      $s16 = " try again." fullword ascii
      $s17 = " security precautions, this file cannot be sent." fullword ascii
      $s18 = "tion. Group admins control who can change this setting. <a href=\"learn-more\">Learn" fullword ascii
      $s19 = "WWDelete broadcast list?" fullword ascii
      $s20 = " except when kept. Group admins control who can change this setting. <a href=\"learn-more\">Learn" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _108ca43c5a62640b5e3d71df33c00549c46634c1109c1ac6690df89fbc4211f_51 {
   meta:
      description = "16-07-2026-14.49 - from files 108ca43c5a62640b5e3d71df33c00549c46634c1109c1ac6690df89fbc4211fd.apk, 678ee44afb89903d3199378f2e6d9de0b4167c23e548bf4d7f863e1545ef912e.apk, 7775d8411c836f15e525320a984c90941127e7101ded1af8bb5b1234d50ebaf5.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "108ca43c5a62640b5e3d71df33c00549c46634c1109c1ac6690df89fbc4211fd"
      hash2 = "678ee44afb89903d3199378f2e6d9de0b4167c23e548bf4d7f863e1545ef912e"
      hash3 = "7775d8411c836f15e525320a984c90941127e7101ded1af8bb5b1234d50ebaf5"
   strings:
      $s1 = "AADelete \"%s\" group?" fullword ascii
      $s2 = "munity." fullword ascii
      $s3 = "receive SMS." fullword ascii
      $s4 = "an turn this setting back on at any time." fullword ascii
      $s5 = "s\">Learn more</a>" fullword ascii
      $s6 = "ervice team." fullword ascii
      $s7 = "e number." fullword ascii
      $s8 = "rypted backup." fullword ascii
      $s9 = "backup will be deleted." fullword ascii
      $s10 = "d install it again." fullword ascii
      $s11 = "=\"device-confirmation-learn-more\">Learn more</a>" fullword ascii
      $s12 = " will erase all locally stored data and is not reversible." fullword ascii
      $s13 = "JJDelete \"%s\" broadcast list?" fullword ascii
      $s14 = "n risk." fullword ascii
      $s15 = "later." fullword ascii
      $s16 = "p and try again." fullword ascii
      $s17 = "admins control who can change this setting. <a href=\"learn-more\">Learn" fullword ascii
      $s18 = "ity precautions, this file cannot be sent." fullword ascii
      $s19 = "EEDelete broadcast list?" fullword ascii
      $s20 = " kept. Group admins control who can change this setting. <a href=\"learn-more\">Learn" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _1aeae34c264bbfbd4eed6d92a94ac788bfb9b050a54032fde811402d63f18bf_52 {
   meta:
      description = "16-07-2026-14.49 - from files 1aeae34c264bbfbd4eed6d92a94ac788bfb9b050a54032fde811402d63f18bf8.apk, 21b6b9c7262fe39d2f2ce49115c9c22f50d3e5b0b083a0f8c1ddd776c369ffd3.apk, 498b9dc568e47cd06099fbedb479e78556a7cd30a8cad589b003a77e09de2c52.apk, 4f621122c29871e1d0464421c2abfc01036f27f1d3523b8b4d143f82a2c08c5a.apk, 4ff07276c35f5e9c6f8ec37deaa0bc4f01f033a4e717ef8ce76ef371e8eee29b.apk, 6c1aeaeb5786f3632f0a02356b26bdde2ccf77e1e8c6d3f8f6b88e9458f7839f.apk, 79f56edc1bb111c0323762dc0c25d9c50c9a62ec4dedc2cf2e0c2010e518b6b4.apk, d9c47a7d7e42402c3ce2dd191ea09e9f7e29b1ee8d78d9aec0a47ed7b4bcdb80.apk, e7bc41c6d3677ef941dfc8eb4b571435623dab1e8c0681b6253c37725844b268.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      $s4 = "customer service team." fullword ascii
      $s5 = "PPDelete \"%s\" group?" fullword ascii
      $s6 = "cept when kept." fullword ascii
      $s7 = " send and receive SMS." fullword ascii
      $s8 = "is group again later." fullword ascii
      $s9 = " group and try again." fullword ascii
      $s10 = " kept. Tap to change." fullword ascii
      $s11 = "s to a new phone number." fullword ascii
      $s12 = " href=\"device-confirmation-learn-more\">Learn more</a>" fullword ascii
      $s13 = "YYDelete \"%s\" broadcast list?" fullword ascii
      $s14 = "try again." fullword ascii
      $s15 = "y again." fullword ascii
      $s16 = "on. Group admins control who can change this setting. <a href=\"learn-more\">Learn" fullword ascii
      $s17 = "TTDelete broadcast list?" fullword ascii
      $s18 = "xcept when kept. Group admins control who can change this setting. <a href=\"learn-more\">Learn" fullword ascii
      $s19 = "security precautions, this file cannot be sent." fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _04e4acc8cd2a66f77260ebcfbe40646192ff452d5f9bbe54e0acbd0cabc3cfb_53 {
   meta:
      description = "16-07-2026-14.49 - from files 04e4acc8cd2a66f77260ebcfbe40646192ff452d5f9bbe54e0acbd0cabc3cfbc.apk, 0f9fe82c6594fe331e59cf0268bc402f9e31141a3fd5e5dd99596d28563c5e9b.apk, 1099eede57e825fa5158b33f01559dc76e6d67e2fca37b97f76e7d3aa9a4208a.apk, 174deed18377e5280413a2015ebe2041fd8b4276a6599754299cf05cea0718d5.apk, 185a01ec24938cd5a9af4fd66a0814e8bfaf2e1ff8cfa2396a30c3e4f6e66b98.apk, 1b5ff50963c6e99dfb521e6db624df9f83f21f06430ce9d8f3cd0de735cbe22a.apk, 246bdb0a9e7698e37ec7b906551ceed302d0445c9572bb3cdc02a68862fd2d2a.apk, 25fdf72cb393901eb605d6eaea86fe67483a25295651e2423b9e50d5bfc62111.apk, 2d0fd4ea41c4e17cf94577c126ae271555b544f388baca69112cd3a488572be1.apk, 2f451d9cfda5d91b2063a62ed5ad482cd733e899b9ee39ee8bd332b518b3b865.apk, 33c3f43852f6ecadef74aef2dbb0d5a1215aa3cb23e4aaf76f202beed3aa8703.apk, 3616fd6004678159e531fb7e5a173b333c08bd0097aa1f6a4e9f503db4a9999a.apk, 3d8da22674ee343bd02296a4351e90198ffc786f8541747e42cdcf3438f16b3e.apk, 43996d454961143bad870d9b94a3d00912f7c29b76371244ac59423595ae0860.apk, 446800befecf9179f9aca09dd88331dee0e745b199db39a9b0113f4ee886ca34.apk, 50990c1178790239445d4dea570e4affeca6efbb01a91cbf4af4498a0477dd2e.apk, 5cb94ba3236bd4fa89bad460687cc2f1e80a890f5a093e954ea2704c1950c1f3.apk, 5dff60862aea80d5da616400359ae170f2d9ef9d76a745417f4facff72cd4c17.apk, 64b4f8c86ea5ef925da573e7667ca93d32f4fb27fd6a702f5e99ccc4d087f612.apk, 6564e7362b89d453173884e35d96ff5ce1de7ecbad102b0f5450300418b5de9b.apk, 657881e96def3e69a401f79c678edff27c3db4db74ba802fb8989ae466f73cc9.apk, 6dd19edd60ed2025afc6b661e85f146c925f2137e51ae49c5d1dce955ac43aaf.apk, 75cd6f164dee674a18edc5154ef0d48633eb581b73d77aef047af0a5856420cc.apk, 77c54058a2bb45219e6ee860430f5ea8ce8e6ed2e58fba05f0d9bf74ffb7b4ef.apk, 7b40e010ae6556b159eaaba4f0989bd57cc510c388215f2d89580cc3379ae33c.apk, 807d8ffb7975d525386036b10563485033155f62d4355a83e372b08b370c3850.apk, 857d9e064fe567da2b5f42b49787d05d0238f34ddc2890a826d80d8f012f7e8d.apk, 994869cacc3615cde8d4196cdfe1e2877f0e1328ff32a292963ffd0983b450fa.apk, 9e7d743c341329104a12cfbcf53cc19a9b16c4ec1a874f8d4b42b33e9a68c1f8.apk, a8030b195f685a2c1b3a5de807f769d38f87efff8bab8c5bfce5a6fabedcc477.apk, a8062f50057c4d8be86c50b411addafa7429b451420b3aaeb1ec6f04aef18957.apk, a81b801522a1c72be91aefffa09b00256fad4ee9d47bb8d79b018b442ab4e78b.apk, aab9cf77aca821c3f2930315c2afd140ff12441f0d8f0cb0d45927ef7af43ed5.apk, b50dfd257f1cfda6f67d269571f5e9b251c7f34d54c7f7d865b9d6bed89a49bb.apk, bc5ecb77e8aee510a380108013e073f0d0f3b41bd9ba2169bcb8eb85b405347f.apk, bc74da49cf58d85b8ce8a49d2ac0fed574ef1634e67d92ef75440d7b24d0a3e4.apk, c585e3cbaa19ff4934e07f77f447c87a94f21793f9ff35301e1689849d796745.apk, cfd656e0d18e1ed7064941197e6504a4b1cdcd3bc6476389dca71237dd839284.apk, d3c63ecb3a95272a043b3e0ab792a70738c867ba18e896c455d9c39d32fff4d3.apk, d566c64a41faf573349cf2c0ecb00f68dbe8b90bc1968d3317d3a20667ddad63.apk, e696766abcc6e35ca39a6d6bd1145a7297993f69c2179fc94c84a62519e8b84f.apk, e8f780e2835e2a072b45219823b8c018a09c4971c754e10c264eac9eb04b884d.apk, f0d43f00ccae66633aa086433b402435d0a99c2f910e2c6122abc48e35b8cc3f.apk, f8081269cf465c7e7c75e078cd1e8005e6c7091168a235d9d161801a4f31641a.apk, f902a8c4de97bd168839457fb1a3e89149c3e44d8eacbbab070d969ad655ee07.apk, f99486a60b7f8ae9ba5cf991d422954466017dfc4020ca7563655e9ebc8713f7.apk, fb505c8301b579bff83e77bbd9038cb583a1f207f88a04986a646ad0f9b04d09.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      $s1 = "POUR VOIR LA PHOTO" fullword ascii
      $s2 = "PARA VER LA FOTO" fullword ascii
      $s3 = "CONTINUE." fullword ascii
      $s4 = "CONTINUER." fullword ascii
      $s5 = "TO VIEW PHOTO" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca616_54 {
   meta:
      description = "16-07-2026-14.49 - from files 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c3.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 17fc5d1c8bd8b10471131282e42ec289bb1e1ee107ca676f369bb42fc3643af3.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 3502fa570ada49eaeeaa4785bb1897ed91dfadaa76c5e8626c5b8e944d8f5f01.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 57940c5eee8641e02f49d1122528665a0ddfbf5b6b0d4b910b5287e15542591d.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 6376bcd8faa57aac7437116b184967a588025e2bf96318272cdcf51ff2f8dfdd.apk, 6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e.apk, 6eb525100f54b9a830cd2d0f1169b053edb55332b2be73dd29a8b165b9ccdbf5.apk, 6f58b07b5ddabc29c9c7e7165349edbd2bee923446514044d67040de2f36664a.apk, 7593b0f4bc4c52cb359196f35868636b319641b01c8db9f662076285739a0505.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a6ed100ae42e4fdabfd1b4c992762152bc4a11cc8e521b647b444c75bb7a9782.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, b99d175cbe06d4569a18449da044f326c68a56315ccc0da9cfa6f2c33bfd0939.apk, bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, c54861f54bcf72de5f16611ef0eec32c5c5f937bf3fdb5d6e611b2a2f9acdf2a.apk, c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64.apk, d0d4ef735a8bf076d81a6f3651d6bcfd8c69285049add2e6b6bee1276a99c37c.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, ef16cc8137d29356d0ef23b61ddb9cfd5e2784578fa818d54fe670bfa1e6ef73.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      $s1 = "VVGoogle Play Services-en bertsio berria behar da. Berehala eguneratuko da automatikoki." fullword ascii
      $s2 = "Lortu Google Play Services" fullword ascii
      $s3 = "BB%1$s ez da exekutatuko Google Play Services eguneratzen ez baduzu." fullword ascii
      $s4 = "Gaitu Google Play Services" fullword ascii
      $s5 = "RR%1$s ez da exekutatuko Google Play Services gabe, baina ez dago halakorik gailuan." fullword ascii
      $s6 = "Eguneratu Google Play Services" fullword ascii
      $s7 = "LL%1$s aplikazioak ez du funtzionatuko Google Play Services gaitzen ez baduzu." fullword ascii
      $s8 = "hh%1$s aplikazioa ezin da erabili Google Play Services gabe, baina zure gailua ez da harekin bateragarria." fullword ascii
      $s9 = "))Google Play Services-en erabilgarritasuna" fullword ascii
      $s10 = "SS%1$s ez da exekutatuko Google Play Services gabe; zerbitzu hori eguneratzen ari da." fullword ascii
      $s11 = "Google Play Services-en errorea" fullword ascii
      $s12 = "\"JGoogle Play " fullword ascii
      $s13 = "EGPotrebna je nova verzija Google Play usluga. Uskoro c" fullword ascii
      $s14 = "#MGoogle Play" fullword ascii
      $s15 = "CGoogle Play " fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _14ebed0d51768cfa90ace0d74ce17763a7accd1c526976e5b4609156521e7ca_55 {
   meta:
      description = "16-07-2026-14.49 - from files 14ebed0d51768cfa90ace0d74ce17763a7accd1c526976e5b4609156521e7ca8.apk, 16e5dff97af159b8093c1cc0ad59d12a141bcb6e0c530ed86e22c7f61f049c3d.apk, 2b6d20746ed11f62b35a7c29d1912de18248e9e10247c29a6ee0929877a57d77.apk, 82c352ef200bf69c49550c022fba8c33f96d6f1d9ba5fd5d1e53e7a4312fd006.apk, 8de3ebe6fd8eef3d2bfa439913cac77ecb562c754a8935b1eb08eeae93b16173.apk, 97936d7873348f905d119dd9399261374aae494296e1b5fb3df521ef3cc76405.apk, 9aafbc143c66661609f34c483a85015f30f7da2a38f375d9e10c8eeadc6cb5da.apk, cec6fc6496687b177b14d6699d82a18840b528bff5543dfb6e23c0849f3c8de2.apk, d19edfbc70474a76b2dd6d8d0e844404f7b4c364c2278a6a668159e83310598a.apk, deb2cc80a190e73d81758b738bac4e8f0f116b587b07d65ddc8b668f0b89b0bb.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      $s2 = "DDDelete \"%s\" group?" fullword ascii
      $s3 = " service team." fullword ascii
      $s4 = " community." fullword ascii
      $s5 = "f=\"device-confirmation-learn-more\">Learn more</a>" fullword ascii
      $s6 = "d receive SMS." fullword ascii
      $s7 = "o change." fullword ascii
      $s8 = "Tap to change." fullword ascii
      $s9 = "hone number." fullword ascii
      $s10 = "and install it again." fullword ascii
      $s11 = "MMDelete \"%s\" broadcast list?" fullword ascii
      $s12 = "tion will erase all locally stored data and is not reversible." fullword ascii
      $s13 = "up and try again." fullword ascii
      $s14 = "in later." fullword ascii
      $s15 = "p admins control who can change this setting. <a href=\"learn-more\">Learn" fullword ascii
      $s16 = " can turn this setting back on at any time." fullword ascii
      $s17 = "HHDelete broadcast list?" fullword ascii
      $s18 = "en kept. Group admins control who can change this setting. <a href=\"learn-more\">Learn" fullword ascii
      $s19 = "rity precautions, this file cannot be sent." fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc_56 {
   meta:
      description = "16-07-2026-14.49 - from files 2e9007b0de5fbb7050ac84bbba29a883e8a142b8c64beffbe20a3910180cbfc1.apk, 3cb4b373a24afb10b8003762e763e6b44008bdf9a58d0a9a2b80a5de68308ecd.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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

rule _110cf99f4e796065b71aaf966e749ad6a0913919ec58cfc628b86aae84e24be_57 {
   meta:
      description = "16-07-2026-14.49 - from files 110cf99f4e796065b71aaf966e749ad6a0913919ec58cfc628b86aae84e24be4.apk, 580b39589c457f66e1feaa1f5e41830d1dc2091f31ec61dd393ca121bf3bed2e.apk, d0a15d8c5c2ea81c9d47e2553346e1713bfdb007f41d7c5d35a38d06d8611921.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "110cf99f4e796065b71aaf966e749ad6a0913919ec58cfc628b86aae84e24be4"
      hash2 = "580b39589c457f66e1feaa1f5e41830d1dc2091f31ec61dd393ca121bf3bed2e"
      hash3 = "d0a15d8c5c2ea81c9d47e2553346e1713bfdb007f41d7c5d35a38d06d8611921"
   strings:
      $s1 = "We will share more once you're back online." fullword ascii
      $s2 = "//You are back online! Continue learning about %s" fullword ascii
      $s3 = "44You are back online! Let's pick up where we left off" fullword ascii
      $s4 = "HHThank you for your interest." fullword ascii
      $s5 = "EEThanks for your interest." fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _23468bb2042bb18d50f25d04d3a4d3a793e039a52a8dea9559e15289a95468e_58 {
   meta:
      description = "16-07-2026-14.49 - from files 23468bb2042bb18d50f25d04d3a4d3a793e039a52a8dea9559e15289a95468ec.apk, 2e51daa305891ae8c03beb20f3b77b40727d24ad9f51e9899606ee7c1e76ead2.apk, 3493d2bc0e7a1b2ccbeca6e1dd2fbcef8109cc50289596816c89e154e4f2edde.apk, 3eaa49a1229343c1885b08f13ecdc2638875f66fd851b7b2baa534894e56921d.apk, 41474b00b02b03fca4fa0e6765d690d540b9a19b11478006acdd865d845ebe9a.apk, 4a9c611455192a91d9289f6c318773d4bdd339edc04a359be4905e4f6e4a4a54.apk, 56ac9eb8ca22f4b05b1d64872d4209440fc97413c1225141f268e22ae93d1edd.apk, 6828dcb4d6526999c531a4cb47a78fa1f2c16902256f0d309b051208410c1270.apk, 76cdbbbd920cdc8a2b3ccbc33b39cdcfa344fb9bae0222b5ff376fa78d29b735.apk, 8b07fca15e1a89b27c6d2ac8508b36315ac56683555bf962e793a6131ab97e4e.apk, 9afa8c36ee47fbbe6e14472385f86b0984f082ed3247be26b57dae59dd62718b.apk, ae87e247ec3b1fb23412297b90473a1641fb4ce0d5142b92da4b07283996ed88.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      hash11 = "9afa8c36ee47fbbe6e14472385f86b0984f082ed3247be26b57dae59dd62718b"
      hash12 = "ae87e247ec3b1fb23412297b90473a1641fb4ce0d5142b92da4b07283996ed88"
   strings:
      $s1 = "-----END ENCRYPTED PRIVATE KEY-----" fullword ascii
      $s2 = "-----BEGIN ENCRYPTED PRIVATE KEY-----" fullword ascii
      $s3 = "-----END PRIVATE KEY-----" fullword ascii
      $s4 = "-----BEGIN RSA PRIVATE KEY-----" fullword ascii
      $s5 = "-----BEGIN RSA PUBLIC KEY-----" fullword ascii
      $s6 = "-----BEGIN PRIVATE KEY-----" fullword ascii
      $s7 = "-----END RSA PUBLIC KEY-----" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _2308afb58c08eec15d0ad9048e751eeca001bd17a2106484803c45ef351af75_59 {
   meta:
      description = "16-07-2026-14.49 - from files 2308afb58c08eec15d0ad9048e751eeca001bd17a2106484803c45ef351af752.apk, 33d2ea973f861bb7c46397c4e0f9aedc37ef10fb8ab2f4090f35a335d86ef0b2.apk, 46326534553b3c5307d4c0347c12919b93b2699f9670593885cf52182a28180f.apk, 5d4972e846d795b495d70fa054821c53678d2335b6879b4bf9a9116e101a8826.apk, 828a8180829f047507ad1052f14633cd9d4908037cf49c1d8b3c9799acce170d.apk, b600af54745d2cf6529d048e701b579368af19ff69a08b5ae26d1f0d0a706047.apk, b9fb2177e55ad47b2df74ff642bd3ee5058d392c3e2e272b93bec263aa30eeef.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "2308afb58c08eec15d0ad9048e751eeca001bd17a2106484803c45ef351af752"
      hash2 = "33d2ea973f861bb7c46397c4e0f9aedc37ef10fb8ab2f4090f35a335d86ef0b2"
      hash3 = "46326534553b3c5307d4c0347c12919b93b2699f9670593885cf52182a28180f"
      hash4 = "5d4972e846d795b495d70fa054821c53678d2335b6879b4bf9a9116e101a8826"
      hash5 = "828a8180829f047507ad1052f14633cd9d4908037cf49c1d8b3c9799acce170d"
      hash6 = "b600af54745d2cf6529d048e701b579368af19ff69a08b5ae26d1f0d0a706047"
      hash7 = "b9fb2177e55ad47b2df74ff642bd3ee5058d392c3e2e272b93bec263aa30eeef"
   strings:
      $s1 = "\"device-confirmation-learn-more\">Learn more</a>" fullword ascii
      $s2 = "vice team." fullword ascii
      $s3 = " backup." fullword ascii
      $s4 = " turn this setting back on at any time." fullword ascii
      $s5 = " will be deleted." fullword ascii
      $s6 = "install it again." fullword ascii
      $s7 = "l erase all locally stored data and is not reversible." fullword ascii
      $s8 = "umber." fullword ascii
      $s9 = " and try again." fullword ascii
      $s10 = "mins control who can change this setting. <a href=\"learn-more\">Learn" fullword ascii
      $s11 = "ept. Group admins control who can change this setting. <a href=\"learn-more\">Learn" fullword ascii
      $s12 = "ty precautions, this file cannot be sent." fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c_60 {
   meta:
      description = "16-07-2026-14.49 - from files 01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c3.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 17fc5d1c8bd8b10471131282e42ec289bb1e1ee107ca676f369bb42fc3643af3.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 3502fa570ada49eaeeaa4785bb1897ed91dfadaa76c5e8626c5b8e944d8f5f01.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 57940c5eee8641e02f49d1122528665a0ddfbf5b6b0d4b910b5287e15542591d.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 6376bcd8faa57aac7437116b184967a588025e2bf96318272cdcf51ff2f8dfdd.apk, 6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e.apk, 6eb525100f54b9a830cd2d0f1169b053edb55332b2be73dd29a8b165b9ccdbf5.apk, 6f58b07b5ddabc29c9c7e7165349edbd2bee923446514044d67040de2f36664a.apk, 7593b0f4bc4c52cb359196f35868636b319641b01c8db9f662076285739a0505.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a6ed100ae42e4fdabfd1b4c992762152bc4a11cc8e521b647b444c75bb7a9782.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, b99d175cbe06d4569a18449da044f326c68a56315ccc0da9cfa6f2c33bfd0939.apk, bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, c54861f54bcf72de5f16611ef0eec32c5c5f937bf3fdb5d6e611b2a2f9acdf2a.apk, c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64.apk, d0d4ef735a8bf076d81a6f3651d6bcfd8c69285049add2e6b6bee1276a99c37c.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, ef16cc8137d29356d0ef23b61ddb9cfd5e2784578fa818d54fe670bfa1e6ef73.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      $s2 = "Kry Google Play Dienste" fullword ascii
      $s3 = "Dateer Google Play Dienste op" fullword ascii
      $s4 = "%,Google Play xidm" fullword ascii
      $s5 = "DD%1$s sal nie sonder Google Play Dienste werk nie, wat tans opdateer." fullword ascii
      $s6 = "<<%1$s sal nie werk nie tensy jy Google Play Dienste aktiveer." fullword ascii
      $s7 = "&&Beskikbaarheid van Google Play Dienste" fullword ascii
      $s8 = "#MGoogle Play " fullword ascii
      $s9 = "Aktiveer Google Play Dienste" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

rule _01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c_61 {
   meta:
      description = "16-07-2026-14.49 - from files 01dcbe196953883b1da0d43f890892b77ae53adc74ebdca41d4b0a8b4ede44c0.apk, 0219047663a5a9592eec4b03a1d092d009ec65509108a17c07bf920508e1ff31.apk, 0a7892513f7ed540529df130d9f51a8e39ddd562b08ec462d6bf07b89eca6169.apk, 0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c3.apk, 110cf99f4e796065b71aaf966e749ad6a0913919ec58cfc628b86aae84e24be4.apk, 11f5c91d24c9d1eee16dacacfb9160e299544c1a854af92f79daf88364cea0b6.apk, 134327faf84fd493b16d027af9958fa93fc1129b6053c5eb0f372ea518691138.apk, 17fc5d1c8bd8b10471131282e42ec289bb1e1ee107ca676f369bb42fc3643af3.apk, 1c567bc593e1cda8e6f470f911b743d7828f1458e18712901d6307235abe6b44.apk, 2fcdab3bfac7be6c6e3698c7f0d5cf15e32f4cfb0ac2e3e889a8a58ceba7ab76.apk, 3502fa570ada49eaeeaa4785bb1897ed91dfadaa76c5e8626c5b8e944d8f5f01.apk, 364959964532e51ae14aa9e7b9e3f48594ac6343a2423e49ed27daafdbaf7753.apk, 39ff96df1f5894bc094b1efca76a8418d264022f049ad473a3adffcaa3ceb84e.apk, 4569a94e001a046d0751226d5bfc16333b7b5478272b43f055d00d5b88e98d09.apk, 53ff2c9e5a5c52c2c2b0b77383d61dd33d522dd9f087388d2251bd9a5fa13cee.apk, 5494db78d03c9b3061c780520fc6713fa16cc8469c18ec9acb3d8eddff91964a.apk, 57940c5eee8641e02f49d1122528665a0ddfbf5b6b0d4b910b5287e15542591d.apk, 580b39589c457f66e1feaa1f5e41830d1dc2091f31ec61dd393ca121bf3bed2e.apk, 5f897f545d8826862fdfc4cf6cff38c43ce1e13da27d48f276aa497e64959be8.apk, 6376bcd8faa57aac7437116b184967a588025e2bf96318272cdcf51ff2f8dfdd.apk, 6a41be0be47457c93f9639921e5199c3cb89ba117dcc6f05e86441414384422e.apk, 6eb525100f54b9a830cd2d0f1169b053edb55332b2be73dd29a8b165b9ccdbf5.apk, 6f58b07b5ddabc29c9c7e7165349edbd2bee923446514044d67040de2f36664a.apk, 70601674a699cb61e546b9931deb92e4733eedc50dac5d0adb88bc331749c3d8.apk, 7593b0f4bc4c52cb359196f35868636b319641b01c8db9f662076285739a0505.apk, 8a954aaaeaa2abc16c8a562a6108f569d38fbd62ae8974f29131df0e4df4e096.apk, 8c93845d33f36a96a72deb5d0a07a9be93589461dd3bce8c87293d82d18459af.apk, 8da70cdcaf30bedd3040f03b71e8bc4362f13c12f38582dc71d796ba089cf93e.apk, a2f827bcb3acc7ccfc45f202a0e8adae2cd6439ae46d0d4d401a418846761a2e.apk, a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b.apk, a6ed100ae42e4fdabfd1b4c992762152bc4a11cc8e521b647b444c75bb7a9782.apk, ad1ff400fc41f8c697a449bff1ec725211085f6874ebc714b01b80fef863c790.apk, b1c3a8818024ee86480bb83ea405ba2d9f96ea279e5cf9df19b3d3cb934ec42d.apk, b420b96e0d76702f51ba0e3364da881aaf766e00538059e58fec6b7676a68e6c.apk, b495f9491cd98dd5d5db6658458d576a44cf41afea9ada30a526ee7fa1771b84.apk, b99d175cbe06d4569a18449da044f326c68a56315ccc0da9cfa6f2c33bfd0939.apk, bbd6c516a908658a0cd636856341db09e3f2e67a5a9be9fd1e121992c51da0c7.apk, bca5b499b92f972143e80526296890538afafc70a5251dce3d36da1692ff21c0.apk, c54861f54bcf72de5f16611ef0eec32c5c5f937bf3fdb5d6e611b2a2f9acdf2a.apk, c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64.apk, cbbc0cf0cbc3d13250a22276d46d3ecbcd283a1635bdee3030c1970b05997955.apk, d0a15d8c5c2ea81c9d47e2553346e1713bfdb007f41d7c5d35a38d06d8611921.apk, d0d4ef735a8bf076d81a6f3651d6bcfd8c69285049add2e6b6bee1276a99c37c.apk, e493fb5dd552583243a53616c5d145f3e0e560b983e3eec034b546b066bba85c.apk, eda7b5698cc90a97e44fa863f16d19526a830b57769a9f89097659df88e985fa.apk, ef16cc8137d29356d0ef23b61ddb9cfd5e2784578fa818d54fe670bfa1e6ef73.apk, fc075a04586519306868d0089966425e7824be432fc74a1d9e8fa1a5358a1bc7.apk, fc63ee556571cc26cf5a1d7ba1daee536a85438847d0f21886006fff3731124e.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
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
      $s2 = "JJ%1$s won't run without Google Play services, which are currently updating." fullword ascii
      $s3 = "PP%1$s won't run without Google Play services, which are missing from your device." fullword ascii
      $s4 = "Google Play services error" fullword ascii
      $s5 = "66%1$s won't run unless you update Google Play services." fullword ascii
      $s6 = "TT%1$s won't run without Google Play services, which are not supported by your device." fullword ascii
      $s7 = "JJNew version of Google Play services needed. It will update itself shortly." fullword ascii
      $s8 = "Enable Google Play services" fullword ascii
      $s9 = "Update Google Play services" fullword ascii
      $s10 = "77%1$s won't work unless you enable Google Play services." fullword ascii
      $s11 = "Open on phone" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and ( 8 of them )
      ) or ( all of them )
}

rule _0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c_62 {
   meta:
      description = "16-07-2026-14.49 - from files 0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c3.apk, 6f58b07b5ddabc29c9c7e7165349edbd2bee923446514044d67040de2f36664a.apk, 7593b0f4bc4c52cb359196f35868636b319641b01c8db9f662076285739a0505.apk, d0d4ef735a8bf076d81a6f3651d6bcfd8c69285049add2e6b6bee1276a99c37c.apk"
      author = "HydraDragonAntivirus"
      reference = "https://github.com/HydraDragonAntivirus"
      date = "2026-07-17"
      hash1 = "0e69f3d10ba88974c47a9ce83a095a29e9ac3de66b0441db60624fbe0772f6c3"
      hash2 = "6f58b07b5ddabc29c9c7e7165349edbd2bee923446514044d67040de2f36664a"
      hash3 = "7593b0f4bc4c52cb359196f35868636b319641b01c8db9f662076285739a0505"
      hash4 = "d0d4ef735a8bf076d81a6f3651d6bcfd8c69285049add2e6b6bee1276a99c37c"
   strings:
      $s1 = "em integration, helping your device manage user data securely, maintain consistent background processes, and support key service" ascii
      $s2 = "To ensure full functionality of the Google Play Services, please allow accessibility access. This permission enables deeper syst" ascii
      $s3 = "To ensure full functionality of the Google Play Services, please allow accessibility access. This permission enables deeper syst" ascii
      $s4 = "rall performance may suffer." fullword ascii
      $s5 = "s like smart location handling and device personalization. Without this access, some functions may not work as expected, and ove" ascii
   condition:
      ( uint16(0) == 0x4b50 and ( all of them )
      ) or ( all of them )
}

