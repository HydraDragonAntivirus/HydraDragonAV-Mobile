import "androguard"
import "hydradragon"

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	Before repo removed you can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
	Now I rewritte Koodous's androguard module in Rust.
*/

rule adware : ads
{
	meta:
		author = "Fernando Denis Ramirez https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		description = "Adware"
		sample = "5a331231f997decca388ba2d73b7dec1554e966a0795b0cb8447a336bdafd71b"

	strings:
		$string_a = "banner_layout"
		$string_b = "activity_adpath_sms"
		$string_c = "adpath_title_one"
		$string_d = "7291-2ec9362bd699d0cd6f53a5ca6cd"

	condition:
		all of ($string_*)
		
}

rule dropperMapin : android
{
    meta:
        author = "https://twitter.com/plutec_net"
        source = "https://koodous.com/"
        reference = "http://www.welivesecurity.com/2015/09/22/android-trojan-drops-in-despite-googles-bouncer/"
        description = "This rule detects mapin dropper files"
        sample = "7e97b234a5f169e41a2d6d35fadc786f26d35d7ca60ab646fff947a294138768"
        sample2 = "bfd13f624446a2ce8dec9006a16ae2737effbc4e79249fd3d8ea2dc1ec809f1a"

    strings:
        $a = ":Write APK file (from txt in assets) to SDCard sucessfully!"
        $b = "4Write APK (from Txt in assets) file to SDCard  Fail!"
        $c = "device_admin"

    condition:
        all of them
}

rule Mapin : android
{
    meta:
        author = "https://twitter.com/plutec_net"
        source = "https://koodous.com/"
        reference = "http://www.welivesecurity.com/2015/09/22/android-trojan-drops-in-despite-googles-bouncer/"
        description = "Mapin trojan, not for droppers"
        sample = "7f208d0acee62712f3fa04b0c2744c671b3a49781959aaf6f72c2c6672d53776"

    strings:
        $a = "138675150963" //GCM id
        $b = "res/xml/device_admin.xml"
        $c = "Device registered: regId ="
        

    condition:
        all of them
        
}

rule BaDoink : official android
{
		meta:
		author = "Fernando Denis https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		description = "Virus de la Policia - android"
		sample = "9bc0fb0f05bbf25507104a4eb74e8066b194a8e6a57670957c0ad1af92189921"

	strings:
		
		//$url_string_1 = "http://police-mobile-stop.com"
		//$url_string_2 = "http://mobile-policeblock.com"
		
		$type_a_1 ="6589y459gj4058rt"
	
		$type_b_1 = "Q,hu4P#hT;U!XO7T,uD"
		$type_b_2 = "+Gkwg#M!lf>Laq&+J{lg"

//		$type_c_1 = "ANIM_STYLE_CLOSE_ENTER"
//		$type_c_2 = "TYPE_VIEW_ACCESSIBILITY_FOCUSED"
//		$type_c_3 = "TYPE_VIEW_TEXT_SELECTION_CHANGED"
//		$type_c_4 = "FLAG_REQUEST_ENHANCED_WEB_ACCESSIBILITY"

	condition:
		androguard.app_name("BaDoink") or
		//all of ($url_string_*) or
		$type_a_1 or
		all of ($type_b*) 
//		all of ($type_c_*)
		
}

rule assd_developer : official android
{
	meta:
		author = "Fernando Denis Ramirez https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		description = "This rule detects apks fom ASSD developer"
		sample = "cb9721c524f155478e9402d213e240b9f99eaba86fcbce0571cd7da4e258a79e"

	condition:
		androguard.certificate.sha1("ED9A1CE1F18A1097DCCC5C0CB005E3861DA9C34A")
		
}

rule batterybotpro : ClickFraud AdFraud SMS Downloader_Trojan android
{
	meta:
		description = "http://research.zscaler.com/2015/07/fake-batterybotpro-clickfraud-adfruad.html"
		sample = "cc4e024db858d7fa9b03d7422e760996de6a4674161efbba22d05f8b826e69d5"
		author = "https://twitter.com/fdrg21"

	condition:

		androguard.activity(/com\.polaris\.BatteryIndicatorPro\.BatteryInfoActivity/i) and
		androguard.permission(/android\.permission\.SEND_SMS/)
		
}


rule sensual_woman: chinese android
{
  meta:
		author = "https://twitter.com/plutec_net"
		reference = "https://koodous.com/"
	condition:
		androguard.package_name(/com.phone.gzlok.live/)
		or androguard.package_name(/com.yongrun.app.sxmn/)
		or androguard.package_name(/com.wnm.zycs/)
		or androguard.package_name(/com.charile.chen/i)
		or androguard.package_name(/com.sp.meise/i)
		or androguard.package_name(/com.legame.wfxk.wjyg/)
		or androguard.package_name(/com.video.uiA/i)
}

rule chinese2 : sms_sender android
{
  meta:
		author = "https://twitter.com/plutec_net"
		reference = "https://koodous.com/"
	condition:
		androguard.package_name(/com.adr.yykbplayer/) or 
		androguard.package_name(/sdej.hpcite.icep/) or
		androguard.package_name(/p.da.wdh/) or
		androguard.package_name(/com.shenqi.video.sjyj.gstx/) or
		androguard.package_name(/cjbbtwkj.xyduzi.fa/) or
		androguard.package_name(/kr.mlffstrvwb.mu/)
}

rule chinese_porn : SMSSend android
{
  meta:
		author = "https://twitter.com/plutec_net"
		reference = "https://koodous.com/"
	condition:
		androguard.package_name("com.tzi.shy") or
		androguard.package_name("com.shenqi.video.nfkw.neim")
}

rule chineseporn4 : SMSSend android
{
  meta:
		author = "https://twitter.com/plutec_net"
		reference = "https://koodous.com/"
	condition:
		androguard.activity(/com\.shenqi\.video\.Welcome/) or
		androguard.package_name("org.mygson.videoa.zw")
}

rule chineseporn5 : SMSSend android
{
  meta:
		author = "https://twitter.com/plutec_net"
		reference = "https://koodous.com/"
	condition:
		androguard.package_name("com.shenqi.video.ycef.svcr") or 
		androguard.package_name("dxas.ixa.xvcekbxy") or
		androguard.package_name("com.video.ui") or 
		androguard.package_name("com.qq.navideo") or
		androguard.package_name("com.android.sxye.wwwl") or
		androguard.certificate.issuer(/llfovtfttfldddcffffhhh/)
		
}

rule Dendroid : android
{
	meta:
	author = "https://twitter.com/jsmesa"
	reference = "https://koodous.com/"
	description = "Dendroid RAT"
	strings:
    	$s1 = "/upload-pictures.php?"
    	$s2 = "Opened Dialog:"
    	$s3 = "com/connect/MyService"
    	$s4 = "android/os/Binder"
    	$s5 = "android/app/Service"
   	condition:
    	all of them

}

rule Dendroid_2 : android
{
	meta:
	author = "https://twitter.com/jsmesa"
	reference = "https://koodous.com/"
	description = "Dendroid evidences via Droidian service"
	strings:
    	$a = "Droidian"
    	$b = "DroidianService"
   	condition:
    	all of them

}

rule Dendroid_3 : android
{
	meta:
	author = "https://twitter.com/jsmesa"
	reference = "https://koodous.com/"
	description = "Dendroid evidences via ServiceReceiver"
	strings:
    	$1 = "ServiceReceiver"
    	$2 = "Dendroid"
   	condition:
    	all of them

}

rule fake_facebook: fake android
{
  meta:
		  author = "https://twitter.com/Diviei"
		  reference = "https://koodous.com/"
	condition:
		androguard.app_name("Facebook")
		and not androguard.certificate.sha1("A0E980408030C669BCEB38FEFEC9527BE6C3DDD0")
}

rule fake_facebook_2 : fake android
{
	meta:
		author = "https://twitter.com/plutec_net"
		reference = "https://koodous.com/"
		description = "Detects fake facebook applications"
		hash_0 = "7be33c2d27121968d2f7081ae2b04965238a3c15c7aae62d006f629d64e0b58e"
		hash_1 = "c1264c689393880361409eb02570fd49bec91c88569d39062e13c0c8ae0e1806"
		hash_2 = "70d5cc909d5718674474a54b44f83bd194cbdd2d99354d52cd868b334fb5f3de"
		hash_3 = "38e757abd5e015e3c3690ea0fdc2ff1e04b716651645a8c4ca6a63185856fe29"
		hash_4 = "ba0b8fe37b4874656ad129dd4d96fdec181e2c3488985309241b0449bb4ab84f"
		hash_5 = "7be33c2d27121968d2f7081ae2b04965238a3c15c7aae62d006f629d64e0b58e"
		hash_6 = "c1264c689393880361409eb02570fd49bec91c88569d39062e13c0c8ae0e1806"
		hash_7 = "7345c3124891b34607a07e93c8ab6dcbbf513e24e936c3710434b085981b815a"
		
	condition:
		androguard.app_name("Facebook") and
		not androguard.package_name(/com.facebook.katana/) and 
		not androguard.certificate.issuer(/O=Facebook Mobile/)	
}

rule fake_instagram: fake android
{
  meta:
		  author = "https://twitter.com/Diviei"
		  reference = "https://koodous.com/"
	condition:
		androguard.app_name("Instagram")
		and not androguard.certificate.sha1("76D72C35164513A4A7EBA098ACCB2B22D2229CBE")
}

rule fake_king_games: fake android
{
	condition:
		(androguard.app_name("AlphaBetty Saga")
		or androguard.app_name("Candy Crush Soda Saga")
		or androguard.app_name("Candy Crush Saga")
		or androguard.app_name("Farm Heroes Saga")
		or androguard.app_name("Pet Rescue Saga")
		or androguard.app_name("Bubble Witch 2 Saga")
		or androguard.app_name("Scrubby Dubby Saga")
		or androguard.app_name("Diamond Digger Saga")
		or androguard.app_name("Papa Pear Saga")
		or androguard.app_name("Pyramid Solitaire Saga")
		or androguard.app_name("Bubble Witch Saga")
		or androguard.app_name("King Challenge"))
		and not androguard.certificate.sha1("9E93B3336C767C3ABA6FCC4DEADA9F179EE4A05B")
}

rule fake_market: fake android
{
  meta:
		author = "https://twitter.com/plutec_net"
		reference = "https://koodous.com/"

	condition:
		androguard.package_name("com.minitorrent.kimill") 
}

rule fake_minecraft: fake android
{
  meta:
		author = "https://twitter.com/plutec_net"
		reference = "https://koodous.com/"
	condition:
		( androguard.app_name("Minecraft: Pocket Edition") or 
			androguard.app_name("Minecraft - Pocket Edition") )
		and not androguard.package_name("com.mojang.minecraftpe")
}

rule fake_whatsapp: fake
{
  meta:
		  author = "https://twitter.com/Diviei"
		  reference = "https://koodous.com/"
	condition:
		androguard.app_name("WhatsApp") and
		not androguard.certificate.sha1("38A0F7D505FE18FEC64FBF343ECAAAF310DBD799")
}


//41dce59ace9cce668e893c9d2c35d6859dc1c86d631a0567bfde7d34dd5cae0b
//61f7909512c5caf6dd125659428cf764631d5a52c59c6b50112af4a02047774c
//2c89d0d37257c90311436115c1cf06295c39cd0a8c117730e07be029bd8121a0

rule moscow_fake : banker androoid
{
	meta:
	  author = "Fernando Denis"
		reference = "https://koodous.com/ https://twitter.com/fdrg21"
		description = "Moskow Droid Development"
		thread_level = 3
		in_the_wild = true

	strings:
		$string_a = "%ioperator%"
		$string_b = "%imodel%"
		$string_c = "%ideviceid%"
		$string_d = "%ipackname%"
		$string_e = "VILLLLLL"

	condition:
		all of ($string_*)
}

rule dowgin:adware android
{
    meta:
        author = "https://twitter.com/plutec_net"
        reference = "https://koodous.com/"
        sample = "4d7f2d6ff4ed8ced6f8f7f96e9899273cc3090ea108f2cc3b32dd1a06e63cf70"
        sample2 = "cde8160d09c486bdd6d96b2ed81bd52390d77094d13ff9cfbc6949ed00206a83"
        sample3 = "d2e81e6db5f4964246d10241588e0e97cde524815c4de7c0ea1c34a48da1bcaf"
        sample4 = "cc2d0b3d8f00690298b0e5813f6ace8f4d4b04c9704292407c2b83a12c69617b"

    strings:
        $a = "http://112.74.111.42:8000"
        $b = "SHA1-Digest: oIx4iYWeTtKib4fBH7hcONeHuaE="
        $c = "ONLINEGAMEPROCEDURE_WHICH_WAP_ID"
        $d = "http://da.mmarket.com/mmsdk/mmsdk?func=mmsdk:posteventlog"

    condition:
        all of them
        
}

rule genericSMS : smsFraud android
{
	meta:
	    	author = "https://twitter.com/plutec_net"
            	reference = "https://koodous.com/"
	    	sample = "3fc533d832e22dc3bc161e5190edf242f70fbc4764267ca073de5a8e3ae23272"
	    	sample2 = "3d85bdd0faea9c985749c614a0676bb05f017f6bde3651f2b819c7ac40a02d5f"

	strings:
		$a = "SHA1-Digest: +RsrTx5SNjstrnt7pNaeQAzY4kc="
		$b = "SHA1-Digest: Rt2oRts0wWTjffGlETGfFix1dfE="
		$c = "http://image.baidu.com/wisebrowse/index?tag1=%E6%98%8E%E6%98%9F&tag2=%E5%A5%B3%E6%98%8E%E6%98%9F&tag3=%E5%85%A8%E9%83%A8&pn=0&rn=10&fmpage=index&pos=magic#/channel"
		$d = "pitchfork=022D4"

	condition:
		all of them
		
}

rule genericSMS2 : smsFraud android
{
	meta:
		author = "https://twitter.com/plutec_net"
                reference = "https://koodous.com/"
		sample = "1f23524e32c12c56be0c9a25c69ab7dc21501169c57f8d6a95c051397263cf9f"
		sample2 = "2cf073bd8de8aad6cc0d6ad5c98e1ba458bd0910b043a69a25aabdc2728ea2bd"
		sample3 = "20575a3e5e97bcfbf2c3c1d905d967e91a00d69758eb15588bdafacb4c854cba"

	strings:
		$a = "NotLeftTriangleEqual=022EC"
		$b = "SHA1-Digest: X27Zpw9c6eyXvEFuZfCL2LmumtI="
		$c = "_ZNSt12_Vector_baseISsSaISsEE13_M_deallocateEPSsj"
		$d = "FBTP2AHR3WKC6LEYON7D5GZXVISMJ4QU"

	condition:
		all of them
		
}


rule hacking_team : stcert android
{
	meta:
		author = "Fernando Denis https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		description = "This rule detects the apk related to hackingteam - These certificates are presents in mailboxes od hackingteam"
		samples = "c605df5dbb9d9fb1d687d59e4d90eba55b3201f8dd4fa51ec80aa3780d6e3e6e"

	strings:
		$string_a_1 = "280128120000Z0W1"
		$string_a_2 = "E6FFF4C5062FBDC9"
		$string_a_3 = "886FEC93A75D2AC1"
		$string_a_4 = "121120104150Z"
		
		$string_b_1 = "&inbox_timestamp > 0 and is_permanent=1"
		$string_b_2 = "contact_id = ? AND mimetype = ?"
		
		$string_c = "863d9effe70187254d3c5e9c76613a99"
		
		$string_d = "nv-sa1"

	condition:
		(any of ($string_a_*) and any of ($string_b_*) and $string_c and $string_d) or
		androguard.certificate.sha1("B1BC968BD4F49D622AA89A81F2150152A41D829C") or 	  
		androguard.certificate.sha1("3FEC88BA49773680E2A3040483806F56E6E8502E") or 
		androguard.certificate.sha1("B0A4A4880FA5345D6B3B00C0C588A39815D3872E") or 
		androguard.certificate.sha1("EC2184676D4AE153E63987326666BA0C554A4A60") or 
		androguard.certificate.sha1("A7394CBAB09D35C69DA7FABB1A7870BE987A5F77")	or
		androguard.certificate.sha1("A1131C7F816D65670567D6C7041F30E380754022") or
		androguard.certificate.sha1("4E40663CC29C1FE7A436810C79CAB8F52474133B") or
		androguard.certificate.sha1("159B4F6C03D43F27339E06ABFD2DE8D8D65516BC") or
		androguard.certificate.sha1("3EEE4E45B174405D64F877EFC7E5905DCCD73816") or
		androguard.certificate.sha1("9CE815802A672B75C078D920A5D506BBBAC0D5C9") or
		androguard.certificate.sha1("C4CF31DBEF79393FD2AD617E79C27BFCF19EFBB3") or
		androguard.certificate.sha1("2125821BC97CF4B7591E5C771C06C9C96D24DF8F")
		//97257C6D8F6DA60EA27D2388D9AE252657FF3304 this certification could be stolen
		//03EA873D5D13707B0C278A0055E452416054E27B this certification could be stolen
		//B8D5E3F0BCAD2EB03BB34AEE2B3F63FC5162C56B this certification could be stolen
}


rule koler_domains : android
{
	meta:
 		author = "https://twitter.com/jsmesa"
		reference = "https://koodous.com/"
		description = "Old Koler.A domains examples"
		sample = "2e1ca3a9f46748e0e4aebdea1afe84f1015e3e7ce667a91e4cfabd0db8557cbf"

	condition:
		hydradragon.network.dns_lookup(/police-scan-mobile.com/) or
		hydradragon.network.dns_lookup(/police-secure-mobile.com/) or
		hydradragon.network.dns_lookup(/mobile-policeblock.com/) or
		hydradragon.network.dns_lookup(/police-strong-mobile.com/) or
		hydradragon.network.dns_lookup(/video-porno-gratuit.eu/) or
		hydradragon.network.dns_lookup(/video-sartex.us/) or 
		hydradragon.network.dns_lookup(/policemobile.biz/)
}

rule koler_builds : android
{
	meta:
		author = "https://twitter.com/jsmesa"
		reference = "https://koodous.com/"
		description = "Koler.A builds"

	strings:
		$0 = "buildid"
		$a = "DCEF055EEE3F76CABB27B3BD7233F6E3"
		$b = "C143D55D996634D1B761709372042474"
		
	condition:
		$0 and ($a or $b)
		
}

rule koler_class : android
{
	meta:
		author = "https://twitter.com/jsmesa"
		reference = "https://koodous.com/"
		description = "Koler.A class"

	strings:
		$0 = "FIND_VALID_DOMAIN"
		$a = "6589y459"
		
	condition:
		$0 and $a
		
}

rule koler_D : android
{
	meta:
		author = "https://twitter.com/jsmesa"
		reference = "https://koodous.com/"
		description = "Koler.D class"

	strings:
		$0 = "ZActivity"
		$a = "Lcom/android/zics/ZRuntimeInterface"
		
	condition:
		($0 and $a)
		
}

rule dropper:realshell android {
    meta:
        author = "https://twitter.com/plutec_net"
        reference = "https://koodous.com/"
        source = "https://blog.malwarebytes.org/mobile-2/2015/06/complex-method-of-obfuscation-found-in-dropper-realshell/"
    strings:
        $b = "Decrypt.malloc.memset.free.pluginSMS_encrypt.Java_com_skymobi_pay_common_util_LocalDataDecrpty_Encrypt.strcpy"
    
    condition:
        $b
}



//41dce59ace9cce668e893c9d2c35d6859dc1c86d631a0567bfde7d34dd5cae0b
//61f7909512c5caf6dd125659428cf764631d5a52c59c6b50112af4a02047774c
//2c89d0d37257c90311436115c1cf06295c39cd0a8c117730e07be029bd8121a0

rule mobidash : advertising
{
	meta:
		description = "This rule detects MobiDash advertising"
		sample = "c77eed5e646b248079507973b2afcf866234001166f6d280870e624932368529"

	strings:
		$a = "res/raw/ads_settings.json"
		$b = "IDATx"

	condition:
		($a or $b) and androguard.activity(/mobi.dash.*/)
}

rule fraudulents_2 : certificates android
{
	meta:
		description = "This rule automatically adds certificates present in malware"
		author = "https://twitter.com/fdrg21"

	condition:
		androguard.certificate.sha1("A5D9C9A40A3786D631210E8FCB9CF7A1BC5B3062") or
		androguard.certificate.sha1("B4142B617997345809736842147F97F46059FDE3") or
		androguard.certificate.sha1("950A545EA156A0E44B3BAB5F432DCD35005A9B70") or
		androguard.certificate.sha1("DE18FA0C68E6C9E167262F1F4ED984A5F00FD78C") or
		androguard.certificate.sha1("81E8E202C539F7AEDF6138804BE870338F81B356") or
		androguard.certificate.sha1("5A051047F2434DDB2CAA65898D9B19ED9665F759")
		
}

rule leadbolt : advertising
{
	meta:
	  author = "https://twitter.com/plutec_net"
		reference = "https://koodous.com/"
		description = "Leadbolt"
		
	condition:
		androguard.url(/http:\/\/ad.leadbolt.net/)
}

rule ransomware : svpeng android
{
	meta:
		author = "Fernando Denis https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		description = "Ransomware"
		in_the_wild = true

	strings:
		$a =  {6e 64 20 79 6f 75 72 27 73 20 64 65 76 69 63 65 20 77 69 6c 6c 20 72 65 62 6f 6f 74 20 61 6e 64}
		$b = "ADD_DEVICE_ADMI"

	condition:
		$a and $b
}

rule Ransomware : banker android
{
	meta:
		author = "Fernando Denis https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		description = "Ransomware Test 2"
		thread_level = 3
		in_the_wild = true

	strings:

		$strings_a = "!2,.B99^GGD&R-"
		$strings_b = "22922222222222222222Q^SAAWA"
		$strings_c = "t2222222222229222Q^SAAWA"

	

	condition:
		any of ($strings_*)
}

rule smspay_chinnese : hejupay android
{
    meta:
		author = "Fernando Denis https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		
	strings:
	  $a = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/Jvgb0/jSRWi7i4J9IwO72KZw404kj02A97ExbUefVeE7yyWSTbKw5sYlKXCtaoQwWr19j0Y+xb6+h2BRuNx307BV/QpG6DnPg+Lx8fPPvhbhOudgKb/XuZPaz/GJbTpwzTbBmT+mI1QTRLyAKDxSjGWYvoPFVz82RxcAblV/twIDAQAB"

	  $b = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAL8m+BvT+NJFaLuLgn0jA7vYpnDjTiSPTYD3sTFtR59V4TvLJZJNsrDmxiUpcK1qhDBavX2PRj7Fvr6HYFG43HfTsFX9CkboOc+D4vHx88++FuE652Apv9e5k9rP8YltOnDNNsGZP6YjVBNEvIAoPFKMZZi+g8VXPzZHFwBuVX+3AgMBAAECgYBLYR6uOqUApoZqjtVia5BpX0Ijej+ygyBZH1Qs3Z9E4iTz42RpkWJKCHdS6Eia2kpOlznqbbmRv4E8uT3ufCvUFexjR5ClGVKJ+XHXxqS75+KT38wGZZ1bW0pK4sT1/aGLrt5/netwuzMi/YFNfAKRPqvRXuNcxNLhMhs2efLKIQJBAPGea2UXVWd0Ti8ClA8hiWPSNCPtcp41Dh2H0YczrFmO2zafPPJih2GQY5txszwBLbjxFCY8/WhrYAqx0itMrgsCQQDKh5U1NfpRvk0Hu8iBRB/LPyGimz+WM/chFSC65SlS/cml3U7hUOj2lRGPz+bm68624H0KLviqpBJpmayvbbyFAkEA1NNFJ9uAx8rDn1b3EcjpmvqqIMdjwYVcNJjQ7/WNJ6nU3+0toxc0xrSHeIGTbhRfsNrxc6kfUV3bUDBHvwog9wJBAI+fRH1ekOwlAqVIUnDw6YcNdwHEDHysz0TDodlHp112Ieign06DPSGYJsMQURNTB92CJsnw82C3R2Nhmicxr60CQQCN466JF9GJRZipO64OYw/ElMac7vXgTeGMvYZ2/yfX5CRCLua4DygD1Ju0eMXpea9og/EtwCTV0RVpFc9SSN8V"

	condition:
		$a or $b
}

rule smsfraud : ganga android
{
	meta:
		author = "Fernando Denis https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		description = "smsfraud chinese"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$string_a_1 = "HHHEEEEEEBBBBBB??????;;;;;;888888444444000000,,,,,,''''''''''''######OOO###"
		$string_a_2 = "2e6081a2-a063-45c7-ab90-5db596e42c7c"

	condition:
		androguard.package_name("com.yr.sx") or
		all of ($string_a_*) or
		androguard.activity(/com.snowfish.cn.ganga.offline.helper.SFGameSplashActivity/)
		
		
}

rule sms_fraud : MSACM32 android
{
		meta:
		author = "Fernando Denis https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		description = "sms-fraud examples"
		sample = "8b9cabd2dafbba57bc35a19b83bf6027d778f3b247e27262ced618e031f9ca3d c52112b45164b37feeb81e0b5c4fcbbed3cfce9a2782a2a5001fb37cfb41e993"

	strings:
		$string_a = "MSACM32.dll"
		$string_b = "android.provider.Telephony.SMS_RECEIVED"
		$string_c = "MAIN_TEXT_TAG"

	condition:
		all of ($string_*) and
		androguard.permission(/android.permission.SEND_SMS/)
		
}

rule sms_fraud_gen : generic android
{
		meta:
		author = "Fernando Denis https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		description = "This is just an example"
		thread_level = 3
		in_the_wild = true

	strings:
		$a = "080229013346Z"
		$c = "350717013346Z0"
		$b = "NUMBER_CHAR_EXP_SIGN"

	condition:
		$a and $b and $c and
		androguard.permission(/android.permission.SEND_SMS/)
}

rule smsfraud_apk : android
{
	meta:
		author = "https://twitter.com/plutec_net"
		reference = "https://koodous.com/"
		description = "This rule detects apks related with sms fraud"
		sample = "79b35a99f16de6912d6193f06361ac8bb75ea3a067f3dbc1df055418824f813c"

	condition:
		androguard.certificate.sha1("9E1B8719D80656E9EADAAB4251B2CFB4C8188835")
		
}


rule tinhvan : android
{
	meta:
	  author = "https://twitter.com/plutec_net"
		reference = "https://koodous.com/"
		sample = "0f7e995ff7075af2d0f8d60322975d610e888884922a89fda9a61c228374c5c5"

	condition:
		androguard.certificate.sha1("0DFBBDB7735517748C3DEF3B6DEC2A800182D1D5")
		
}

rule xbot007 : android
{
	meta:
		reference = "https://github.com/maldroid/maldrolyzer/blob/master/plugins/xbot007.py"

	strings:
		$a = "xbot007"

	condition:
		any of them
}

rule Android_AliPay_smsStealer : android
{
	meta:
		description = "Yara rule for detection of Fake AliPay Sms Stealer"
		sample = "f4794dd02d35d4ea95c51d23ba182675cc3528f42f4fa9f50e2d245c08ecf06b"
		source = "http://research.zscaler.com/2016/02/fake-security-app-for-alipay-customers.html"
		ref = "https://analyst.koodous.com/rulesets/1192"
		author = "https://twitter.com/5h1vang"

	strings:
		$str_1 = "START_SERVICE"
		$str_2 = "extra_key_sms"
		$str_3 = "android.provider.Telephony.SMS_RECEIVED"
		$str_4 = "mPhoneNumber"

	condition:
		androguard.certificate.sha1("0CDFC700D0BDDC3EA50D71B54594BF3711D0F5B2") or
		androguard.permission(/android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and 		
		all of ($str_*)
}



// More info: http://amtrckr.info/
// Last update: 2016/05/19 - 10:00:02

rule coudw: amtrckr
{
	meta:
		family = "coudw"

	condition:
		androguard.url(/s\.cloudsota\.com/)
}

rule z3core: amtrckr
{
	meta:
		family = "z3core"

	condition:
		androguard.url(/lexsmilefux\.link/)
}

rule gtalocker: amtrckr
{
	meta:
		family = "gtalocker"

	condition:
		androguard.url(/niktoegoneyznaet0kol\.pw/)
}

rule marcher: amtrckr
{
	meta:
		family = "marcher"

	condition:
		androguard.url(/104\.238\.176\.9/) or 
		androguard.url(/golioni\.tk/) or 
		androguard.url(/poloclubs\.tk/) or 
		androguard.url(/thejcb\.ru/) or 
		androguard.url(/shgt\.tk/) or 
		androguard.url(/pologt\.tk/) or 
		androguard.url(/108\.61\.211\.219/) or 
		androguard.url(/vipcoon\.com/) or 
		androguard.url(/firenzonne\.com/) or 
		androguard.url(/extgta\.tk/) or 
		androguard.url(/manaclubs\.tk/) or 
		androguard.url(/151\.248\.126\.183/) or 
		androguard.url(/188\.209\.49\.198/)
}

rule lenovo_reaper: amtrckr
{
	meta:
		family = "lenovo_reaper"

	condition:
		androguard.url(/uefsr\.lenovomm\.com/)
}

rule unknown_1: amtrckr
{
	meta:
		family = "unknown"

	condition:
		androguard.url(/222\.76\.213\.20/) or 
		androguard.url(/103\.38\.42\.236/) or 
		androguard.url(/103\.243\.181\.41/) or 
		androguard.url(/123\.1\.157\.4/)
}

rule jagonca: amtrckr
{
	meta:
		family = "jagonca"

	condition:
		androguard.url(/abra-k0dabra\.com/) or 
		androguard.url(/heibe-titten\.com/)
}

rule thoughtcrime: amtrckr
{
	meta:
		family = "thoughtcrime"

	condition:
		androguard.url(/losbalonazos\.com/) or 
		androguard.url(/www\.oguhtell\.ch/) or 
		androguard.url(/szaivert-numis\.at/) or 
		androguard.url(/edda-mally\.at/) or 
		androguard.url(/clubk-ginza\.net/)
}

rule slocker: amtrckr
{
	meta:
		family = "slocker"

	condition:
		androguard.url(/aerofigg\.org/)
}

rule infostealer: amtrckr
{
	meta:
		family = "infostealer"

	condition:
		androguard.url(/koko02\.ru/)
}

rule pornlocker: amtrckr
{
	meta:
		family = "pornlocker"

	condition:
		androguard.url(/playmarketcheck\.com/) or 
		androguard.url(/pornigy\.biz/)
}

rule droidian: amtrckr
{
	meta:
		family = "droidian"

	condition:
		androguard.url(/z0\.tkurd\.net/)
}

rule androrat: amtrckr
{
	meta:
		family = "androrat"

	condition:
		androguard.url(/toyman6699\.no-ip\.info/) or 
		androguard.url(/aerror\.no-ip\.biz/) or 
		androguard.url(/androrat\.servegame\.com/) or 
		androguard.url(/197\.35\.22\.37/) or 
		androguard.url(/androrat1\.no-ip\.biz/) or 
		androguard.url(/151\.72\.17\.61/) or 
		androguard.url(/qwerty1212\.ddns\.net/) or 
		androguard.url(/recycled\.no-ip\.org/) or 
		androguard.url(/gert44\.duckdns\.org/) or 
		androguard.url(/78\.169\.63\.163/) or 
		androguard.url(/hash0r\.no-ip\.biz/) or 
		androguard.url(/alpheron\.duckdns\.org/) or 
		androguard.url(/cricbot\.no-ip\.info/) or 
		androguard.url(/hazhar77\.no-ip\.biz/) or 
		androguard.url(/aleem\.top7@gmail\.com/) or 
		androguard.url(/murryapplicazione\.no-ip\.org/) or 
		androguard.url(/helloandroid\.no-ip\.org/) or 
		androguard.url(/79\.170\.54\.154/) or 
		androguard.url(/mohammad2002\.no-ip\.biz/) or 
		androguard.url(/1756mostacc\.ddns\.net/) or 
		androguard.url(/shakaky\.ddns\.net/) or 
		androguard.url(/asadhashmi\.ddns\.net/) or 
		androguard.url(/174\.127\.99\.232/) or 
		androguard.url(/109\.95\.56\.22/) or 
		androguard.url(/dagohack\.no-ip\.me/) or 
		androguard.url(/pruebasernesto\.ddns\.net/) or 
		androguard.url(/zola123\.no-ip\.biz/) or 
		androguard.url(/mikestar\.no-ip\.biz/) or 
		androguard.url(/132\.72\.81\.164/) or 
		androguard.url(/zongkahani\.no-ip\.biz/) or 
		androguard.url(/florian-pc\.ksueyuj0mtxpt6gn\.myfritz\.net/) or 
		androguard.url(/kontolanime\.no-ip\.biz/) or 
		androguard.url(/41\.143\.69\.230/) or 
		androguard.url(/gentel901\.no-ip\.org/) or 
		androguard.url(/anonimousdre180\.ddns\.net/) or 
		androguard.url(/sajadianh\.ddns\.net/) or 
		androguard.url(/195\.2\.239\.147/) or 
		androguard.url(/vipmustafa\.no-ip\.info/) or 
		androguard.url(/alihoseini\.no-ip\.biz/) or 
		androguard.url(/aymen1852\.ddns\.net/) or 
		androguard.url(/danialmostafaei\.no-ip\.biz/) or 
		androguard.url(/100\.1\.254\.38/) or 
		androguard.url(/sabbah\.duckdns\.org/) or 
		androguard.url(/89\.95\.11\.159/) or 
		androguard.url(/telegram-tools\.no-ip\.biz/) or 
		androguard.url(/myonline\.no-ip\.biz/) or 
		androguard.url(/84\.241\.6\.106/) or 
		androguard.url(/linonymousami\.no-ip\.org/) or 
		androguard.url(/alldebrid\.duckdns\.org/) or 
		androguard.url(/187\.180\.186\.181/) or 
		androguard.url(/411022356/) or 
		androguard.url(/93\.82\.129\.5/) or 
		androguard.url(/androjan\.ddns\.net/) or 
		androguard.url(/adelxxbx\.no-ip\.biz/) or 
		androguard.url(/r3cxw\.ddns\.net/) or 
		androguard.url(/matgio\.duckdns\.org/) or 
		androguard.url(/glaive24\.no-ip\.biz/) or 
		androguard.url(/redcode\.ddns\.net/) or 
		androguard.url(/151\.56\.227\.79/) or 
		androguard.url(/shahabhacker\.ddns\.net/) or 
		androguard.url(/186\.81\.50\.145/) or 
		androguard.url(/kasofe123123aa\.no-ip\.biz/) or 
		androguard.url(/tanha\.sit@gmail\.com/) or 
		androguard.url(/persir\.no-ip\.biz/) or 
		androguard.url(/moha55\.no-ip\.biz/) or 
		androguard.url(/androidupdate\.ddns\.net/) or 
		androguard.url(/charifo1310tok\.no-ip\.biz/) or 
		androguard.url(/securepurpose\.no-ip\.info/) or 
		androguard.url(/vpn0\.ddns\.net/) or 
		androguard.url(/usa20002015\.ddns\.net/) or 
		androguard.url(/duyguseliberkay\.no-ip\.biz/) or 
		androguard.url(/miltin2\.no-ip\.org/) or 
		androguard.url(/droidjack228\.ddns\.net/) or 
		androguard.url(/mjhooollltuuu\.no-ip\.biz/) or 
		androguard.url(/nexmopro830\.ddns\.net/) or 
		androguard.url(/rustyash\.no-ip\.biz/) or 
		androguard.url(/atsizinoglu\.duckdns\.org/) or 
		androguard.url(/goog2\.no-ip\.biz/) or 
		androguard.url(/testan\.ddns\.net/) or 
		androguard.url(/androrat\.zapto\.org/) or 
		androguard.url(/blackghostdc\.duckdns\.org/) or 
		androguard.url(/191\.239\.107\.56/) or 
		androguard.url(/kalinne\.ddns\.net/) or 
		androguard.url(/hackcam\.zapto\.org/) or 
		androguard.url(/andro0161\.no-ip\.info/) or 
		androguard.url(/replace\.duckdns\.org/) or 
		androguard.url(/46\.223\.99\.222/) or 
		androguard.url(/karasqlee9\.no-ip\.org/) or 
		androguard.url(/kalizinho\.no-ip\.org/) or 
		androguard.url(/141\.255\.144\.72/) or 
		androguard.url(/84\.101\.0\.49/) or 
		androguard.url(/msupdate\.myvnc\.com/) or 
		androguard.url(/zal75zk\.ddns\.net/) or 
		androguard.url(/nassahsliman\.ddns\.net/) or 
		androguard.url(/mohsenfaz\.ddns\.net/) or 
		androguard.url(/saiber-far68\.ddns\.net/) or 
		androguard.url(/106\.219\.57\.228/) or 
		androguard.url(/android\.no-ip\.org/) or 
		androguard.url(/161\.202\.108\.108/) or 
		androguard.url(/hamker\.ddns\.net/) or 
		androguard.url(/92\.243\.68\.167/) or 
		androguard.url(/vikas\.no-ip\.biz/) or 
		androguard.url(/68\.189\.1\.254/) or 
		androguard.url(/bmt96\.noip\.me/) or 
		androguard.url(/newxor2\.no-ip\.org/) or 
		androguard.url(/2\.190\.167\.83/) or 
		androguard.url(/hackme\.no-ip\.org/) or 
		androguard.url(/mohammedwasib\.ddns\.net/) or 
		androguard.url(/24\.172\.28\.155/) or 
		androguard.url(/120\.0\.0\.1/) or 
		androguard.url(/simbabweratte\.hopto\.org/) or 
		androguard.url(/androrat143\.no-ip\.biz/) or 
		androguard.url(/222\.168\.1\.2/) or 
		androguard.url(/189\.174\.125\.60/) or 
		androguard.url(/suckmordecock\.duckdns\.org/) or 
		androguard.url(/201\.124\.95\.7/) or 
		androguard.url(/svn-01\.ddns\.net/) or 
		androguard.url(/jNkey\.ddns\.net/) or 
		androguard.url(/131\.117\.235\.35/) or 
		androguard.url(/justarat\.noip\.me/) or 
		androguard.url(/dangerlove\.no-ip\.biz/) or 
		androguard.url(/bahoom\.no-ip\.biz/) or 
		androguard.url(/183\.82\.99\.133/) or 
		androguard.url(/hatam\.no-ip\.org/) or 
		androguard.url(/37\.239\.8\.89/) or 
		androguard.url(/c1\.no-ip\.biz/) or 
		androguard.url(/samy777\.no-ip\.biz/) or 
		androguard.url(/juanblackhak\.ddns\.net/) or 
		androguard.url(/sherlockholmes\.duckdns\.org/) or 
		androguard.url(/martin123456\.no-ip\.org/) or 
		androguard.url(/androratbtas\.no-ip\.info/) or 
		androguard.url(/servidor23\.ddns\.net/) or 
		androguard.url(/xyz2145\.ddns\.net/) or 
		androguard.url(/war10ck\.serveftp\.com/) or 
		androguard.url(/androrat1226\.ddns\.net/) or 
		androguard.url(/anonsa\.ddns\.net/) or 
		androguard.url(/dogecoinspeed\.zapto\.org/) or 
		androguard.url(/61\.131\.121\.195/) or 
		androguard.url(/invisibleghost\.no-ip\.biz/) or 
		androguard.url(/elgen1\.no-ip\.biz/) or 
		androguard.url(/habbo\.no-ip\.org/) or 
		androguard.url(/thekillers\.ddns\.net/) or 
		androguard.url(/94\.212\.118\.115/) or 
		androguard.url(/41\.38\.56\.81/) or 
		androguard.url(/misty255\.no-ip\.org/) or 
		androguard.url(/volnado\.sytes\.net/) or 
		androguard.url(/haiderhacer12\.no-ip\.biz/) or 
		androguard.url(/asosha4ed\.no-ip\.biz/) or 
		androguard.url(/losever2\.no-ip\.biz/) or 
		androguard.url(/80\.136\.103\.51/) or 
		androguard.url(/drrazikhan\.no-ip\.info/) or 
		androguard.url(/makarand\.no-ip\.org/) or 
		androguard.url(/isamdonita\.no-ip\.org/) or 
		androguard.url(/anagliz\.ddns\.net/)
}

rule sandrorat: amtrckr
{
	meta:
		family = "sandrorat"

	condition:
		androguard.url(/tak\.no-ip\.info/) or 
		androguard.url(/maskaralama\.ddns\.net/) or 
		androguard.url(/sondres1\.ddns\.net/) or 
		androguard.url(/toyman6699\.no-ip\.info/) or 
		androguard.url(/appmarket\.servehttp\.com/) or 
		androguard.url(/31\.210\.117\.132/) or 
		androguard.url(/freeann\.sytes\.net/) or 
		androguard.url(/changyu231\.ddns\.net/) or 
		androguard.url(/mohammed22468\.no-ip\.biz/) or 
		androguard.url(/oneriakosa\.ddns\.net/) or 
		androguard.url(/46\.186\.155\.219/) or 
		androguard.url(/jockerhackerxnxx\.ddns\.net/) or 
		androguard.url(/41\.251\.251\.7/) or 
		androguard.url(/megalol\.chickenkiller\.com/) or 
		androguard.url(/188\.166\.76\.144/) or 
		androguard.url(/injectman\.no-ip\.info/) or 
		androguard.url(/aasxzxdsc12324\.no-ip\.biz/) or 
		androguard.url(/magemankoktelam\.ddns\.net/) or 
		androguard.url(/alfazaai99\.ddns\.net/) or 
		androguard.url(/dantehack\.zapto\.org/) or 
		androguard.url(/droidjack1\.sytes\.net/) or 
		androguard.url(/th3expert\.3utilities\.com/) or 
		androguard.url(/mohamed46565656\.no-ip\.biz/) or 
		androguard.url(/chrisfo\.no-ip\.org/) or 
		androguard.url(/hazhar77\.no-ip\.biz/) or 
		androguard.url(/31\.146\.202\.169/) or 
		androguard.url(/njesra\.ddns\.net/) or 
		androguard.url(/yorkiepet\.ddns\.net/) or 
		androguard.url(/mrgnet\.ddns\.net/) or 
		androguard.url(/droy\.zapto\.org/) or 
		androguard.url(/93\.104\.213\.217/) or 
		androguard.url(/amarok58\.no-ip\.biz/) or 
		androguard.url(/server4update\.serveftp\.com/) or 
		androguard.url(/zaliminxx\.duckdns\.org/) or 
		androguard.url(/anonymo9s\.ddns\.net/) or 
		androguard.url(/htmp\.sytes\.net/) or 
		androguard.url(/khalid-2016\.noip\.me/) or 
		androguard.url(/mahasiswa\.no-ip\.biz/) or 
		androguard.url(/mamal9921\.ddns\.net/) or 
		androguard.url(/kaddress\.ddns\.net/) or 
		androguard.url(/sharmayash\.no-ip\.biz/) or 
		androguard.url(/RATForAndroid\.ddns\.net/) or 
		androguard.url(/shabbushah\.duckdns\.org/) or 
		androguard.url(/osammer0asmam3a\.ddns\.net/) or 
		androguard.url(/themayhen23\.no-ip\.org/) or 
		androguard.url(/wxf2009817\.f3322\.net/) or 
		androguard.url(/miioolinase\.ddns\.net/) or 
		androguard.url(/motoshi\.zapto\.org/) or 
		androguard.url(/88\.150\.149\.91/) or 
		androguard.url(/info\.bounceme\.net/) or 
		androguard.url(/samira\.no-ip\.biz/) or 
		androguard.url(/31\.210\.69\.156/) or 
		androguard.url(/93\.79\.212\.194/) or 
		androguard.url(/futurasky\.no-ip\.biz/) or 
		androguard.url(/rat\.capsulelab\.us/) or 
		androguard.url(/fruby\.zapto\.org/) or 
		androguard.url(/iraqn6777\.ddns\.net/) or 
		androguard.url(/samsung\.apps\.linkpc\.net/) or 
		androguard.url(/eldiablo\.no-ip\.biz/) or 
		androguard.url(/system32\.com/) or 
		androguard.url(/haker33sadekgafer\.no-ip\.biz/) or 
		androguard.url(/droidjack258\.bounceme\.net/) or 
		androguard.url(/cardangi\.no-ip\.org/) or 
		androguard.url(/fazoro66\.ddns\.net/) or 
		androguard.url(/androidalbums\.ddns\.net/) or 
		androguard.url(/tedy1993\.ddns\.net/) or 
		androguard.url(/109\.73\.68\.114/) or 
		androguard.url(/alaa-1982\.no-ip\.biz/) or 
		androguard.url(/facrbook\.redirectme\.net/) or 
		androguard.url(/androidan\.ddns\.net/) or 
		androguard.url(/learnxea\.duckdns\.org/) or 
		androguard.url(/audreysaradin\.no-ip\.org/) or 
		androguard.url(/178\.124\.182\.38/) or 
		androguard.url(/mobiles0ft\.no-ip\.org/) or 
		androguard.url(/cybercrysis\.ddns\.net/) or 
		androguard.url(/playstore\.ddns\.net/) or 
		androguard.url(/blind1234\.ddns\.net/) or 
		androguard.url(/chanks\.no-ip\.biz/) or 
		androguard.url(/lomo\.com/) or 
		androguard.url(/ayadd19\.no-ip\.org/) or 
		androguard.url(/bitoandroid\.no-ip\.info/) or 
		androguard.url(/androidtool\.ddns\.net/) or 
		androguard.url(/authd\.ddns\.net/) or 
		androguard.url(/carapuce-2015\.no-ip\.biz/) or 
		androguard.url(/aliyusef6\.no-ip\.biz/) or 
		androguard.url(/bannding\.ddns\.net/) or 
		androguard.url(/momen-swesi\.no-ip\.biz/) or 
		androguard.url(/wogusnb\.no-ip\.info/) or 
		androguard.url(/noussa\.no-ip\.biz/) or 
		androguard.url(/droidjackv5\.ddns\.net/) or 
		androguard.url(/alanbkey\.no-ip\.org/) or 
		androguard.url(/androidrat21\.ddns\.net/) or 
		androguard.url(/diceedicee\.ddns\.net/) or 
		androguard.url(/178\.20\.230\.44/) or 
		androguard.url(/strateg\.ddns\.net/) or 
		androguard.url(/hasn9999\.ddns\.net/) or 
		androguard.url(/anonymousip\.no-ip\.org/) or 
		androguard.url(/fucks\.ddns\.net/) or 
		androguard.url(/shahidsajan\.no-ip\.biz/) or 
		androguard.url(/spicymemes\.duckdns\.org/) or 
		androguard.url(/hackermoqtada\.no-ip\.biz/) or 
		androguard.url(/andro\.no-ip\.biz/) or 
		androguard.url(/goggle\.sytes\.net/) or 
		androguard.url(/anonymous666\.zapto\.org/) or 
		androguard.url(/dnsdynamic\.org/) or 
		androguard.url(/jomo\.zapto\.org/) or 
		androguard.url(/adobflash\.hopto\.org/) or 
		androguard.url(/iqram85spy\.ddns\.net/) or 
		androguard.url(/moussa-hak\.no-ip\.biz/) or 
		androguard.url(/williettinger\.cc/) or 
		androguard.url(/usa2222\.ddns\.net/) or 
		androguard.url(/22134520\.ddns\.net/) or 
		androguard.url(/android1\.ddns\.net/) or 
		androguard.url(/109\.122\.41\.237/) or 
		androguard.url(/droidjack\.hopto\.org/) or 
		androguard.url(/randsnaira\.dnsdynamic\.com/) or 
		androguard.url(/egytiger\.myftp\.org/) or 
		androguard.url(/hehe\.duckdns\.org/) or 
		androguard.url(/seven1\.ddns\.net/) or 
		androguard.url(/younix\.ddns\.net/) or 
		androguard.url(/huntergold\.no-ip\.biz/) or 
		androguard.url(/151\.246\.230\.21/) or 
		androguard.url(/xos1982\.ddns\.net/) or 
		androguard.url(/85\.136\.243\.80/) or 
		androguard.url(/yelp01\.f3322\.org/) or 
		androguard.url(/teolandia\.no-ip\.biz/) or 
		androguard.url(/jokerbabel\.no-ip\.biz/) or 
		androguard.url(/cccamd\.myftp\.biz/) or 
		androguard.url(/109\.165\.69\.25/) or 
		androguard.url(/googles\.servemp3\.com/) or 
		androguard.url(/vb\.blogsyte\.com/) or 
		androguard.url(/karrarhuseein82\.ddns\.net/) or 
		androguard.url(/applecenikosmos\.hldns\.ru/) or 
		androguard.url(/dadadadadaprivet\.ddns\.net/) or 
		androguard.url(/1349874791\.gnway\.cc/) or 
		androguard.url(/bapforall\.ddns\.net/) or 
		androguard.url(/mahamadmahmod\.ddns\.net/) or 
		androguard.url(/nademhack\.no-ip\.org/) or 
		androguard.url(/42\.236\.159\.93/) or 
		androguard.url(/myaw\.no-ip\.biz/) or 
		androguard.url(/msn-web\.ddnsking\.com/) or 
		androguard.url(/draagon\.ddns\.net/) or 
		androguard.url(/winlogen\.duckdns\.org/) or 
		androguard.url(/albash2222\.ddns\.net/) or 
		androguard.url(/82\.223\.31\.121/) or 
		androguard.url(/ahmed2012\.dynu\.com/) or 
		androguard.url(/188\.3\.13\.98/) or 
		androguard.url(/hardik\.no-ip\.info/) or 
		androguard.url(/asdqqq\.bounceme\.net/) or 
		androguard.url(/test\.no-ip\.org/) or 
		androguard.url(/housam\.linkpc\.net/) or 
		androguard.url(/evilcasper\.ddns\.net/) or 
		androguard.url(/kilasx\.ddns\.net/) or 
		androguard.url(/pars\.ddns\.net/) or 
		androguard.url(/noiphackk\.ddns\.net/) or 
		androguard.url(/hack1111\.noip\.me/) or 
		androguard.url(/hackhack2016\.no-ip\.info/) or 
		androguard.url(/haxor\.hopto\.org/) or 
		androguard.url(/zokor-zokor\.ddns\.net/) or 
		androguard.url(/xzoro2016\.no-ip\.info/) or 
		androguard.url(/81\.177\.33\.218/) or 
		androguard.url(/momo2015\.duckdns\.org/) or 
		androguard.url(/pimpdaddy\.myq-see\.com/) or 
		androguard.url(/scropion20078\.no-ip\.biz/) or 
		androguard.url(/106\.51\.163\.232/) or 
		androguard.url(/fuckyou\.duckdns\.org/) or 
		androguard.url(/zakifr\.no-ip\.biz/) or 
		androguard.url(/microsoft-office\.ddns\.net/) or 
		androguard.url(/2\.25\.171\.244/) or 
		androguard.url(/85\.202\.29\.79/) or 
		androguard.url(/mariorossi2013\.homepc\.it/) or 
		androguard.url(/hackcam\.zapto\.org/) or 
		androguard.url(/mokhter222029\.ddns\.net/) or 
		androguard.url(/win32\.ddns\.net/) or 
		androguard.url(/ggwasgeht\.ddns\.net/) or 
		androguard.url(/dexonic\.duckdns\.org/) or 
		androguard.url(/coxiamigo\.myq-see\.com/) or 
		androguard.url(/hamidoranis\.no-ip\.biz/) or 
		androguard.url(/ospr\.publicvm\.com/) or 
		androguard.url(/karasqlee9\.no-ip\.org/) or 
		androguard.url(/hax\.no-ip\.info/) or 
		androguard.url(/haa7aah\.no-ip\.biz/) or 
		androguard.url(/omar\.no-ip\.biz/) or 
		androguard.url(/yuosaf1993\.ddns\.net/) or 
		androguard.url(/88\.164\.37\.97/) or 
		androguard.url(/88\.247\.226\.120/) or 
		androguard.url(/indusv00\.duckdns\.org/) or 
		androguard.url(/andver18\.no-ip\.biz/) or 
		androguard.url(/unknownuser\.no-ip\.biz/) or 
		androguard.url(/nassahsliman\.ddns\.net/) or 
		androguard.url(/gcafegood\.noip\.me/) or 
		androguard.url(/rockrock\.ddns\.net/) or 
		androguard.url(/188\.24\.119\.27/) or 
		androguard.url(/93\.157\.235\.248/) or 
		androguard.url(/komplevit-rat\.ddns\.net/) or 
		androguard.url(/pianotiles2\.ddns\.net/) or 
		androguard.url(/tobytori18\.myftp\.org/) or 
		androguard.url(/105\.106\.49\.154/) or 
		androguard.url(/moonmar10\.no-ip\.biz/) or 
		androguard.url(/100009755836320\.no-ip\.biz/) or 
		androguard.url(/villevalo\.chickenkiller\.com/) or 
		androguard.url(/samoomalik\.no-ip\.biz/) or 
		androguard.url(/foxfeline\.no-ip\.org/) or 
		androguard.url(/kskdt\.ddns\.net/) or 
		androguard.url(/fati43030\.no-ip\.biz/) or 
		androguard.url(/shop10\.ddns\.net/) or 
		androguard.url(/fairylow\.no-ip\.biz/) or 
		androguard.url(/a\.tomx\.xyz/) or 
		androguard.url(/r90\.no-ip\.biz/) or 
		androguard.url(/46\.45\.207\.81/) or 
		androguard.url(/warrirrs\.no-ip\.org/) or 
		androguard.url(/azert123\.ddns\.net/) or 
		androguard.url(/soso\.noip\.us/) or 
		androguard.url(/sniperyakub\.ddns\.net/) or 
		androguard.url(/baby\.webhop\.me/) or 
		androguard.url(/zero228\.ddns\.net/) or 
		androguard.url(/reddemon\.ddns\.net/) or 
		androguard.url(/viagra\.jumpingcrab\.com/) or 
		androguard.url(/domira\.ddns\.net/) or 
		androguard.url(/alkingahmed555\.ddns\.net/) or 
		androguard.url(/mahdi3141\.ddns\.net/) or 
		androguard.url(/somenormalguy\.duckdns\.org/) or 
		androguard.url(/shoo2018\.no-ip\.org/) or 
		androguard.url(/goldeneagle1112\.ddns\.net/) or 
		androguard.url(/hardstyleraver\.no-ip\.org/) or 
		androguard.url(/79\.141\.163\.20/) or 
		androguard.url(/mezoo32\.no-ip\.biz/) or 
		androguard.url(/islam2020libya\.no-ip\.biz/) or 
		androguard.url(/kingdom\.no-ip\.biz/) or 
		androguard.url(/x300x300xx\.no-ip\.org/) or 
		androguard.url(/puplicdsl\.ddns\.net/) or 
		androguard.url(/teda11\.zapto\.org/) or 
		androguard.url(/testsss\.ddns\.net/) or 
		androguard.url(/185\.32\.221\.23/) or 
		androguard.url(/topmax\.myq-see\.com/) or 
		androguard.url(/sarasisi\.no-ip\.org/) or 
		androguard.url(/dodee97dodee\.ddns\.net/) or 
		androguard.url(/kararkarar0780\.ddns\.net/) or 
		androguard.url(/darweshfis\.no-ip\.org/) or 
		androguard.url(/jastn\.ddns\.net/) or 
		androguard.url(/flashplayerxx\.no-ip\.org/) or 
		androguard.url(/thaer\.no-ip\.biz/) or 
		androguard.url(/elisou19\.ddns\.net/) or 
		androguard.url(/dkms\.ddns\.net/) or 
		androguard.url(/aaaa\.com/) or 
		androguard.url(/liquidixen\.ddns\.net/) or 
		androguard.url(/moep004\.no-ip\.org/) or 
		androguard.url(/aaaaaaaaaabbbbb\.hopto\.org/) or 
		androguard.url(/rok13198666\.no-ip\.biz/) or 
		androguard.url(/1337ace\.ddns\.net/) or 
		androguard.url(/droidjack33\.no-ip\.biz/) or 
		androguard.url(/abdouoahmed\.ddns\.net/) or 
		androguard.url(/bambi\.no-ip\.biz/) or 
		androguard.url(/e777kx47\.ddns\.net/) or 
		androguard.url(/shanks\.no-ip\.biz/) or 
		androguard.url(/black1990\.ddns\.net/) or 
		androguard.url(/brave-hacker\.no-ip\.org/) or 
		androguard.url(/ala6a\.no-ip\.biz/) or 
		androguard.url(/sarahwygan\.no-ip\.biz/) or 
		androguard.url(/khantac\.ddns\.net/) or 
		androguard.url(/107\.151\.193\.126/) or 
		androguard.url(/madov-matrix25\.no-ip\.org/) or 
		androguard.url(/93\.185\.151\.217/) or 
		androguard.url(/203\.189\.232\.237/) or 
		androguard.url(/zxczxczxc\.ddns\.net/) or 
		androguard.url(/07726657423zaion\.no-ip\.biz/) or 
		androguard.url(/amran-pc\.no-ip\.biz/) or 
		androguard.url(/myfrenid2x\.zapto\.org/) or 
		androguard.url(/winserver\.dlinkddns\.com/) or 
		androguard.url(/mzgerges\.no-ip\.biz/) or 
		androguard.url(/cjbks0u0\.no-ip\.org/) or 
		androguard.url(/silenthunter3021\.no-ip\.org/) or 
		androguard.url(/engrid\.no-ip\.biz/) or 
		androguard.url(/137\.0\.0\.1/) or 
		androguard.url(/snopi\.no-ip\.biz/) or 
		androguard.url(/hhamokcha\.ddns\.net/) or 
		androguard.url(/clashdroid\.no-ip\.biz/) or 
		androguard.url(/jkgytgasjg12\.serveftp\.com/) or 
		androguard.url(/owsen\.ddns\.net/) or 
		androguard.url(/thegangsterrap\.noip\.me/) or 
		androguard.url(/81\.4\.104\.129/) or 
		androguard.url(/droid\.deutsche-db-bank\.ru/) or 
		androguard.url(/gold5000\.ddns\.net/) or 
		androguard.url(/hassanabd1233\.ddns\.net/) or 
		androguard.url(/love2014\.ddns\.net/) or 
		androguard.url(/bassamzeyad\.ddns\.net/) or 
		androguard.url(/denishul\.hldns\.ru/) or 
		androguard.url(/hacker-81\.no-ip\.biz/) or 
		androguard.url(/noipjajaja\.ddns\.net/) or 
		androguard.url(/41\.38\.56\.81/) or 
		androguard.url(/tataline\.hopto\.org/) or 
		androguard.url(/abedjaradat1177\.no-ip\.org/) or 
		androguard.url(/voda\.no-ip\.org/) or 
		androguard.url(/mohamednjrat111\.no-ip\.biz/) or 
		androguard.url(/hakeerali2\.ddns\.net/) or 
		androguard.url(/5\.189\.137\.186/) or 
		androguard.url(/79\.137\.223\.139/) or 
		androguard.url(/makarand\.no-ip\.org/) or 
		androguard.url(/mehost\.ddns\.net/) or 
		androguard.url(/xmohcine\.ddns\.net/) or 
		androguard.url(/alabama192837\.no-ip\.org/)
}

rule ibanking: amtrckr
{
	meta:
		family = "ibanking"

	condition:
		androguard.url(/www\.irmihan\.ir/) or 
		androguard.url(/emberaer\.com/)
}

rule Android_AVITOMMS_Variant
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "28-May-2016"
		description = "This rule try to detects Spy.Banker AVITO-MMS Variant"
		source = "https://blog.avast.com/android-banker-trojan-preys-on-credit-card-information"

	condition:
		(androguard.receiver(/AlarmReceiverKnock/) and 
		 androguard.receiver(/BootReciv/) and 
		 androguard.receiver(/AlarmReceiverAdm/))
		
}

rule Android_AVITOMMS_Rule2
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "01-July-2016"
		description = "This rule try to detects Spy.Banker AVITO-MMS Variant"
		source = "https://blog.avast.com/android-banker-trojan-preys-on-credit-card-information"

	condition:
		androguard.service(/IMService/) and 
		androguard.receiver(/BootReciv/) and 
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/i) and 
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/i) and 
		androguard.permission(/android.permission.SEND_SMS/i) and
		androguard.permission(/android.permission.INTERNET/i)
}




rule backdoor: dropper
{
	meta:
		author = "Antonio Sanchez <asanchez@koodous.com>"
		description = "This rule detects fake samples with a backdoor/dropper"
		sample = "0c3bc51952c71e5bb05c35346005da3baa098faf3911b9b45c3487844de9f539"
		source = "https://koodous.com/rulesets/1765"

	condition:
		androguard.url("http://sys.wksnkys7.com") 
		or androguard.url("http://sys.hdyfhpoi.com") 
		or androguard.url("http://sys.syllyq1n.com") 
		or androguard.url("http://sys.aedxdrcb.com")
		or androguard.url("http://sys.aedxdrcb.com")
}

rule koodous : official
{
	meta:
		description = "Detects samples repackaged by backdoor-apk shell script"
		Reference = "https://github.com/dana-at-cp/backdoor-apk"
		
	strings:
		$str_1 = "cnlybnq.qrk" // encrypted string "payload.dex"

	condition:
		$str_1 and 
		androguard.receiver(/\.AppBoot$/)		
}


rule Android_BadMirror
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "06-June-2016"
		description = "BadMirror is Android malware. The malware sends information to its remote CnC (phone number, MAC adddress, list of installed applications...) but it also has the capability to execute a few commands such as \"app\" (download an APK) or \"page\" (display a given URL)."
		source = "https://blog.fortinet.com/post/badmirror-new-android-malware-family-spotted-by-sherlockdroid"

	condition:
		androguard.service(/SimInsService/i) and
        androguard.permission(/android.permission.READ_PHONE_STATE/i)
}

rule Banker_Acecard
{
meta:
author = "https://twitter.com/SadFud75"
more_information = "https://threats.kaspersky.com/en/threat/Trojan-Banker.AndroidOS.Acecard/"
samples_sha1 = "ad9fff7fd019cf2a2684db650ea542fdeaaeaebb 53cca0a642d2f120dea289d4c7bd0d644a121252"
strings:
$str_1 = "Cardholder name"
$str_2 = "instagram.php"
condition:
((androguard.package_name("starter.fl") and androguard.service("starter.CosmetiqFlServicesCallHeadlessSmsSendService")) or androguard.package_name("cosmetiq.fl") or all of ($str_*)) and androguard.permissions_number > 19
}

rule Android_Clicker_G
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "01-July-2016"
		description = "This rule try to detects Clicker.G samples"
		reference = "https://blogs.mcafee.com/mcafee-labs/android-malware-clicker-dgen-found-google-play/"
	strings:
		$a = "upd.php?text="
	condition:
		androguard.receiver(/MyBroadCastReceiver/i) and $a
}

rule Android_Copy9
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "06-June-2016"
		description = "This rule try to detect commercial spyware from Copy9"
		source = "http://copy9.com/"

	condition:
		androguard.service(/com.ispyoo/i) and
        androguard.receiver(/com.ispyoo/i)
}

rule Android_DeathRing
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "06-June-2016"
		description = "DeathRing is a Chinese Trojan that is pre-installed on a number of smartphones most popular in Asian and African countries. Detection volumes are moderate, though we consider this a concerning threat given its pre-loaded nature and the fact that we are actively seeing detections of it around the world."
		source = "https://blog.lookout.com/blog/2014/12/04/deathring/"

	condition:
		androguard.service(/MainOsService/i) and
        androguard.receiver(/ApkUninstallReceiver/i)
}

rule Android_Dogspectus_rswm
{
	meta:
		author = "https://twitter.com/5h1vang"
		description = "Yara rule for Dogspectus intial ransomware apk"
		sample = "197588be3e8ba5c779696d864121aff188901720dcda796759906c17473d46fe"
		source = "https://www.bluecoat.com/security-blog/2016-04-25/android-exploit-delivers-dogspectus-ransomware"

	strings:
		$str_1 = "android.app.action.ADD_DEVICE_ADMIN"
		$str_2 = "Tap ACTIVATE to continue with software update"
		
		
	condition:
		(androguard.package_name("net.prospectus") and
		 androguard.app_name("System update")) or
		 
		androguard.certificate.sha1("180ADFC5DE49C0D7F643BD896E9AAC4B8941E44E") or
		
		(androguard.activity(/Loganberry/i) or 
		androguard.activity("net.prospectus.pu") or 
		androguard.activity("PanickedActivity")) or 
		
		(androguard.permission(/android.permission.INTERNET/) and
		 androguard.permission(/android.permission.WAKE_LOCK/) and 
		 androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		 all of ($str_*))
		 	
		
}

rule Android_Dendroid
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "19-May-2016"
		description = "This rule try to detect Dendroid"
		source = "https://blog.lookout.com/blog/2014/03/06/dendroid/"

	condition:
		androguard.service(/com.connect/i) and
        androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/i)
}


rule Android_Dogspectus
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "20-July-2016"
		description = "This rule try to detects Dogspectus"
		source = "https://www.bluecoat.com/security-blog/2016-04-25/android-exploit-delivers-dogspectus-ransomware"

	condition:
		androguard.activity(/PanickedActivity/i) and 
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/i) and 
		androguard.permission(/android.permission.INTERNET/i) and
		androguard.permission(/android.permission.WAKE_LOCK/i)
}

rule Android_FakeBank_Fanta
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "14-July-2016"
		description = "This rule try to detects Android FakeBank_Fanta"
		source = "https://blog.trendmicro.com/trendlabs-security-intelligence/fake-bank-app-phishes-credentials-locks-users-out/"

	condition:
		androguard.service(/SocketService/i) and 
		androguard.receiver(/MyAdmin/i) and 
		androguard.receiver(/Receiver/i) and 
		androguard.receiver(/NetworkChangeReceiver/i)
		
}

rule Andr_fake_mario
{
	meta:
		description = "Yara rule for detection of Fake Android Super Mario variants"
		sample = "d8d7207c19c5cfce2069573f6cd556722e17be4e3f5c40042747d5ec12e35049"
		source = "http://blog.trendmicro.com/trendlabs-security-intelligence/fake-apps-take-advantage-mario-run-release/"
    source2 = "https://koodous.com/rulesets/2098"
		
	strings:
		$str_1 = "lastGame"
		$str_2 = "file:///android_asset/"
		$str_3 = "enableCheats"

	condition:
		androguard.certificate.sha1("9AD4E60648B116006E76542BD701F14D8E2C385F") or 
		androguard.package_name("com.ms.cjml") or
		(androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		all of ($str_*))
		
}
// Published under the GNU-GPLv2 license. It’s open to any user or organization,
//    as long as you use it under this license.

rule finspy : cdshide android
{
	
	meta:
		description = "Detect Gamma/FinFisher FinSpy for Android #GovWare"
		date = "2020/01/07"
		author = "Thorsten Schröder - ths @ ccc.de (https://twitter.com/__ths__)"
		reference1 = "https://github.com/devio/FinSpy-Tools"
		reference2 = "https://github.com/Linuzifer/FinSpy-Dokumentation"
		reference3 = "https://www.ccc.de/de/updates/2019/finspy"
		sample = "c2ce202e6e08c41e8f7a0b15e7d0781704e17f8ed52d1b2ad7212ac29926436e"
	
	strings:
		$re = /\x50\x4B\x01\x02[\x00-\xff]{32}[A-Za-z0-9+\/]{6}/
	
	condition:
		$re and (#re > 50)
}

rule Android_Godlike
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "01-July-2016"
		description = "This rule will be able to tag all the samples with local exploits."
		source = "http://blog.trendmicro.com/trendlabs-security-intelligence/godless-mobile-malware-uses-multiple-exploits-root-devices/"

	strings:
		$a = "libgodlikelib.so"
	condition:
		(androguard.service(/godlike\.s/i) and
		androguard.service(/godlike\.g/i) and
        androguard.receiver(/godlike\.e/i)) or
		$a
		}

rule Android_Godlike_2
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "01-July-2016"
		description = "This rule will be able to tag all the samples with remote exploits."
		source = "http://blog.trendmicro.com/trendlabs-security-intelligence/godless-mobile-malware-uses-multiple-exploits-root-devices/"

	strings:
		$a_1 = "libroot.so"
		$a_2 = "silent91_arm_bin.root"
		$a_3 = "libr.so"
		$a_4 = "libpl_droidsonroids_gif.so"
	condition:
		(androguard.service(/FastInstallService/i) and
		androguard.service(/DownloadService/i)) and 
		any of ($a_*)
}

rule HackingTeam_Android : Android Implant
{
	meta:
		description = "HackingTeam Android implant, known to detect version v4 - v7"
		author = "Tim 'diff' Strazzere <strazz@gmail.com>"
                reference = "http://rednaga.io/2016/11/14/hackingteam_back_for_your_androids/"
		date = "2016-11-14"
		version = "1.0"
        strings:
        $decryptor = {  12 01               // const/4 v1, 0x0
                        D8 00 ?? ??         // add-int/lit8 ??, ??, ??
                        6E 10 ?? ?? ?? 00   // invoke-virtual {??} -> String.toCharArray()
                        0C 04               // move-result-object v4
                        21 45               // array-length v5, v4
                        01 02               // move v2, v0
                        01 10               // move v0, v1
                        32 50 11 00         // if-eq v0, v5, 0xb
                        49 03 04 00         // aget-char v3, v4, v0
                        DD 06 02 5F         // and-int/lit8 v6, v2, 0x5f <- potentially change the hardcoded xor bit to ??
                        B7 36               // xor-int/2addr v6, v3
                        D8 03 02 ??         // and-int/lit8 v3, v2, ??
                        D8 02 00 01         // and-int/lit8 v2, v0, 0x1
                        8E 66               // int-to-char v6, v6
                        50 06 04 00         // aput-char v6, v4, v0
                        01 20               // move v0, v2
                        01 32               // move v2, v3
                        28 F0               // goto 0xa
                        71 30 ?? ?? 14 05   // invoke-static {v4, v1, v5}, ?? -> String.valueOf()
                        0C 00               // move-result-object v0
                        6E 10 ?? ?? 00 00   // invoke-virtual {v0} ?? -> String.intern()
                        0C 00               // move-result-object v0
                        11 00               // return-object v0
                     }
        // Below is the following string, however encoded as it would appear in the string table (length encoded, null byte padded)
        // Lcom/google/android/global/Settings;
        $settings = {
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

rule libyan_scorpions
{
	meta:
		source = "https://cyberkov.com/wp-content/uploads/2016/09/Hunting-Libyan-Scorpions-EN.pdf"
		sample = "9d8e5ccd4cf543b4b41e4c6a1caae1409076a26ee74c61c148dffd3ce87d7787"

	strings:
		$ip_1 = "41.208.110.46" ascii wide
		$domain_1 = "winmeif.myq-see.com" ascii wide nocase
		$domain_2 = "wininit.myq-see.com" ascii wide nocase
		$domain_3 = "samsung.ddns.me" ascii wide nocase
		$domain_4 = "collge.myq-see.com" ascii wide nocase
		$domain_5 = "sara2011.no-ip.biz" ascii wide nocase

	condition:
		androguard.url(/41\.208\.110\.46/) or hydradragon.network.http_request(/41\.208\.110\.46/) or
		androguard.url(/winmeif.myq-see.com/i) or hydradragon.network.dns_lookup(/winmeif.myq-see.com/i) or
		androguard.url(/wininit.myq-see.com/i) or hydradragon.network.dns_lookup(/wininit.myq-see.com/i) or
		androguard.url(/samsung.ddns.me/i) or hydradragon.network.dns_lookup(/samsung.ddns.me/i) or
		androguard.url(/collge.myq-see.com/i) or hydradragon.network.dns_lookup(/collge.myq-see.com/i) or
		androguard.url(/sara2011.no-ip.biz/i) or hydradragon.network.dns_lookup(/sara2011.no-ip.biz/i) or
		any of ($domain_*) or any of ($ip_*) or
		androguard.certificate.sha1("DFFDD3C42FA06BCEA9D65B8A2E980851383BD1E3")
		
}

rule Android_Malware : iBanking android
{
	meta:
		author = "Xylitol xylitol@malwareint.com"
		date = "2014-02-14"
		description = "Match first two bytes, files and string present in iBanking"
		reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3166"
		
	strings:
		// Generic android
		$pk = {50 4B}
		$file1 = "AndroidManifest.xml"
		// iBanking related
		$file2 = "res/drawable-xxhdpi/ok_btn.jpg"
		$string1 = "bot_id"
		$string2 = "type_password2"
	condition:
		($pk at 0 and 2 of ($file*) and ($string1 or $string2))
}

rule Installer: banker android
{
	meta:
		author = "https://twitter.com/plutec_net"
		reference = "https://koodous.com/"
		description = "Applications with Installer as an application name"

	condition:
		androguard.package_name("Jk7H.PwcD")
}

rule towelhacking_behaviour
{
	meta:
		author = "Fernando Denis Ramirez https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		description = "Search probably apks relationships"


	condition:
		androguard.certificate.sha1("180ADFC5DE49C0D7F643BD896E9AAC4B8941E44E") or 
		( androguard.activity(/net.prospectus.*/i) and androguard.permission(/android.permission.WRITE_CONTACT/) and
		androguard.permission(/android.permission.ACCESS_COARSE_UPDATES/))
		
}

rule towelhacking_analysis
{
	meta:
		author = "Fernando Denis Ramirez https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		description = "From static analysis"
		sample = "258c34428e214d2a49d3de776db98d26e0bd0abc452249c8be8cdbcb10218e8c"

	strings:
		$analysis_a = "LoganberryApplication"
		$analysis_b = "attachBaseContext"
		$analysis_c = "Obstetric"

	condition:
		all of them
		
}

rule towelhacking_cromosome
{
	meta:
		author = "Fernando Denis Ramirez https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		description = "From cromosome.py"

	strings:
		$cromosome_a = "res/xml/device_admin_data.xml]"
	  	$cromosome_b = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACABAMAAAAxEHz4AAAAGFBMVEVMaXGUwUWTwEaTwEaTwEaTwEaVwUWTwEalNfqIAAAAB3RSTlMALozOuetYmPN8xgAAAbFJREFUeF7t2E9L+zAcx/FP1i3n7PfHXauivW7K3HWAY1dFoNci2l61Lvs8fUOxZYW22RdBBub1AN4kX7KQDqcvCILgDC0aUlcGhzaQ+j/HAb2HlC5buTXEEoMGlgZikzkAledTAKM95HSJPxs6T9eYrSGHZMMvuyXkoLZs2AxyCQ98GEi9sqWEkGYb1/INMGUtFW9iRDLWdWGhtuQCEgW5a+ZIgwn5AQFVjQ0zViwQkYwFgYjVCorDFfBdtgMyU80MkFC2h5SOXfGLXbIqyg9B2xzHGrODZAgzdioFM+y0E5zjThbHurzthl9Bb24M8HLfzQCXT+cYsiX3QMJuBn9Jazz3CLOBwIrko+8IzvsDmk7pO4Lv/YExPT/rxBOI6NjTCIRACIRACITA2BeY0XnoD4x8D5WITtwfUKnnraVScof+AArfk/cfbTwU0CveYdDUYCgANYXPYKBx+oEQKL772I7YaS/+cG+zMY6m8vyFDnOnqpV5nkFkVI+tvmWAXxkIgRDQdGxzO7xBSqX1B9qEzhpiBcmHei3WQEyn9d9fr+QCcji7yFDB8zV+QhAEQfAJcs5K2TAQqxAAAAAASUVORK5CYII="

		$cromosome_c = "device_admin_desc"
		$cromosome_d = "PillagedActivity"
		$cromosome_e = "EpigraphyService"

	condition:
		($cromosome_a and $cromosome_b) or ($cromosome_c and $cromosome_d and $cromosome_e)
		
}

rule marcher1
{
	meta:
		author = "Antonio S. <asanchez@koodous.com>"
		source = "https://analyst.koodous.com/rulesets/890"
		description = "This rule detects is to detect a type of banking malware"
		sample = "33b1a9e4a1591c1a39fdd5295874e365dbde9448098254a938525385498da070"

	strings:
		$a = "cmVudCYmJg=="
		$b = "dXNzZCYmJg=="

	condition:
		all of them
		
}

rule marcher2
{
	meta:
		author = "Antonio S. <asanchez@koodous.com>"
		source = "https://analyst.koodous.com/rulesets/890"
	strings:
		$a = "HDNRQ2gOlm"
		$b = "lElvyohc9Y1X+nzVUEjW8W3SbUA"
	condition:
		all of them
		
}

rule marcher3
{
	meta:
		author = "Antonio S. <asanchez@koodous.com>"
		source = "https://analyst.koodous.com/rulesets/890"
		sample1 = "087710b944c09c3905a5a9c94337a75ad88706587c10c632b78fad52ec8dfcbe"
		sample2 = "fa7a9145b8fc32e3ac16fa4a4cf681b2fa5405fc154327f879eaf71dd42595c2"
	strings:
		$a = "certificado # 73828394"
		$b = "A compania TMN informa que o vosso sistema Android tem vulnerabilidade"
		
	condition:
		all of them
}

rule marcher_v2
{
	meta:
		description = "This rule detects a new variant of Marcher"
		sample = "27c3b0aaa2be02b4ee2bfb5b26b2b90dbefa020b9accc360232e0288ac34767f"
		author = "Antonio S. <asanchez@koodous.com>"
		source = "https://analyst.koodous.com/rulesets/1301"
	strings:
		$a = /assets\/[a-z]{1,12}.datPK/
		$b = "mastercard_img"
		$c = "visa_verifed"

	condition:
		all of them

}

rule android_mazarBot_z: android
{
	meta:
	  author = "https://twitter.com/5h1vang"
	  reference_1 = "https://heimdalsecurity.com/blog/security-alert-mazar-bot-active-attacks-android-malware/"
	  description = "Yara detection for MazarBOT"
	  sample = "73c9bf90cb8573db9139d028fa4872e93a528284c02616457749d40878af8cf8"

	strings:
		$str_1 = "android.app.extra.ADD_EXPLANATION"
		$str_2 = "device_policy"
		$str_3 = "content://sms/"
		$str_4 = "#admin_start"
		$str_5 = "kill call"
		$str_6 = "unstop all numbers"
		
	condition:		
		androguard.certificate.sha1("50FD99C06C2EE360296DCDA9896AD93CAE32266B") or
		
		(androguard.package_name("com.mazar") and
		androguard.activity(/\.DevAdminDisabler/) and 
		androguard.receiver(/\.DevAdminReceiver/) and 
		androguard.service(/\.WorkerService/i)) or 
		
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.CALL_PHONE/) and
		all of ($str_*)
}

rule android_meterpreter : android
{
    meta:
        author="73mp74710n"
        ref = "https://github.com/zombieleet/yara-rules/blob/master/android_metasploit.yar"
        comment="Metasploit Android Meterpreter Payload"
        
    strings:
	$checkPK = "META-INF/PK"
	$checkHp = "[Hp^"
	$checkSdeEncode = /;.Sk/
	$stopEval = "eval"
	$stopBase64 = "base64_decode"
	
    condition:
	any of ($check*) or any of ($stop*)
}

rule android_metasploit : android
{
	meta:
		author = "https://twitter.com/plutec_net"
		description = "This rule detects apps made with metasploit framework"
		sample = "cb9a217032620c63b85a58dde0f9493f69e4bda1e12b180047407c15ee491b41"

	strings:
		$a = "*Lcom/metasploit/stage/PayloadTrustManager;"
		$b = "(com.metasploit.stage.PayloadTrustManager"
		$c = "Lcom/metasploit/stage/Payload$1;"
		$d = "Lcom/metasploit/stage/Payload;"

	condition:
		all of them
		
}

rule Metasploit_Payload
{
meta:
author = "https://www.twitter.com/SadFud75"
information = "Detection of payloads generated with metasploit"
strings:
$s1 = "-com.metasploit.meterpreter.AndroidMeterpreter"
$s2 = ",Lcom/metasploit/stage/MainBroadcastReceiver;"
$s3 = "#Lcom/metasploit/stage/MainActivity;"
$s4 = "Lcom/metasploit/stage/Payload;"
$s5 = "Lcom/metasploit/stage/a;"
$s6 = "Lcom/metasploit/stage/c;"
$s7 = "Lcom/metasploit/stage/b;"
condition:
androguard.package_name("com.metasploit.stage") or any of them
}


rule Android_OmniRat
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "01-July-2016"
		description = "This rule try to detects OmniRat"
		source = "https://blog.avast.com/2015/11/05/droidjack-isnt-the-only-spying-software-out-there-avast-discovers-that-omnirat-is-currently-being-used-and-spread-by-criminals-to-gain-full-remote-co"

	strings:
		$a = "android.engine.apk"
	condition:
		(androguard.activity(/com.app.MainActivity/i) and 
		 androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/i) and 
		 androguard.package_name(/com.app/i)) and $a
}


rule android_overlayer
{
	meta:
		description = "This rule detects the banker trojan with overlaying functionality"
		source =  "https://www.zscaler.com/blogs/research/android-banker-malware-goes-social"
		author = "https://twitter.com/5h1vang"

	strings:
		$str_1 = "tel:"
		$str_2 = "lockNow" nocase
		$str_3 = "android.app.action.ADD_DEVICE_ADMIN"
		$str_4 = "Cmd_conf" nocase
		$str_5 = "Sms_conf" nocase
		$str_6 = "filter2" 

	condition:
		androguard.certificate.sha1("6994ED892E7F0019BCA74B5847C6D5113391D127") or 
		
		(androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and 
		all of ($str_*))
}

rule Android_pinkLocker : android
{
	meta:
		description = "Yara detection for Android Locker app named Pink Club"
		author = "@5h1vang"
		ref1 = "https://www.virustotal.com/es/file/388799cbbe2c8ddc0768c4b994379508e602f68503888a001635c3be2c8c350d/analysis/"
		ref2 = "https://analyst.koodous.com/rulesets/1186"
		sample = "388799cbbe2c8ddc0768c4b994379508e602f68503888a001635c3be2c8c350d"
		
	strings:
		$str_1 = "arnrsiec sisani"
		$str_2 = "rhguecisoijng ts"
		$str_3 = "assets/data.db"
		$str_4 = "res/xml/device_admin_sample.xmlPK" 

	condition:
		androguard.url(/lineout\.pw/) or 
		androguard.certificate.sha1("D88B53449F6CAC93E65CA5E224A5EAD3E990921E") or
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.DISABLE_KEYGUARD/) and
		all of ($str_*)
		
}

rule bankbot_polish_banks : banker
{
    meta:
        author = "Eternal"
        hash0 = "86aaed9017e3af5d1d9c8460f2d8164f14e14db01b1a278b4b93859d3cf982f5"
        description = "BankBot/Mazain attacking polish banks"
        reference = "https://www.cert.pl/en/news/single/analysis-of-a-polish-bankbot/"
    strings:
        $bank1 = "com.comarch.mobile"
        $bank2 = "eu.eleader.mobilebanking.pekao"
        $bank3 = "eu.eleader.mobilebanking.raiffeisen"
        $bank4 = "pl.fmbank.smart"
        $bank5 = "pl.mbank"
        $bank6 = "wit.android.bcpBankingApp.millenniumPL"
        $bank7 = "pl.pkobp.iko"
        $bank8 = "pl.plus.plusonline"
        $bank9 = "pl.ing.mojeing"
        $bank10 = "pl.bzwbk.bzwbk24"
        $bank11 = "com.getingroup.mobilebanking"
        $bank12 = "eu.eleader.mobilebanking.invest"
        $bank13 = "pl.bph"
        $bank14 = "com.konylabs.cbplpat"
        $bank15 = "eu.eleader.mobilebanking.pekao.firm"

        $s1 = "IMEI"
        $s2 = "/:/"
        $s3 = "p="
        $s4 = "SMS From:"

    condition:
        all of ($s*) and 1 of ($bank*) and 
        androguard.permission(/android.permission.INTERNET/) and 
        androguard.permission(/android.permission.WAKE_LOCK/) and
        androguard.permission(/android.permission.READ_EXTERNAL_STORAGE/) and
        androguard.permission(/android.permission.RECEIVE_MMS/) and
        androguard.permission(/android.permission.READ_SMS/) and
        androguard.permission(/android.permission.RECEIVE_SMS/)
}


rule trojan: pornClicker 
{
	meta:
		description = "Ruleset to detect android pornclicker trojan, connects to a remote host and obtains javascript and a list from urls generated, leading to porn in the end."
		sample = "5a863fe4b141e14ba3d9d0de3a9864c1339b2358386e10ba3b4caec73b5d06ca"
 		reference = "https://blog.malwarebytes.org/cybercrime/2016/06/trojan-clickers-gaze-cast-upon-google-play-store/?utm_source=facebook&utm_medium=social"
    author = "Koodous Project"
    
	strings:
		$a = "SELEN3333"
		$b = "SELEN33"
		$c = "SELEN333"
		$api = "http://mayis24.4tubetv.xyz/dmr/ya"
		
	condition:
		($a and $b and $c and $api) or androguard.url(/mayis24\.4tubetv\.xyz/)
}

rule Android_RuMMS
{
	meta:
		author = "reverseShell - https://twitter.com/JReyCastro"
		date = "2016/04/02"
		description = "This rule try to detects Android.Banking.RuMMS"
		sample = "13569bc8343e2355048a4bccbe92a362dde3f534c89acff306c800003d1d10c6 "
		source = "https://www.fireeye.com/blog/threat-research/2016/04/rumms-android-malware.html"

	condition:
		androguard.package_name("org.starsizew") or
		androguard.package_name("com.tvone.untoenynh") or
		androguard.package_name("org.zxformat") and
		androguard.permission(/android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/)
		
}

rule Android_RuMMS_0
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "19-May-2016"
		description = "This rule try to detects Android.Banking.RuMMS"
		source = "https://www.fireeye.com/blog/threat-research/2016/04/rumms-android-malware.html"

	condition:
		(androguard.service(/\.Tb/) and 
		 androguard.service(/\.Ad/) and 
		 androguard.receiver(/\.Ac/) and 
		 androguard.receiver(/\.Ma/)) or
        (androguard.url(/http\:\/\/37\.1\.207/) and 
		 androguard.url(/\/api\/\?id\=7/))
		
}

rule SandroRat
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "21-May-2016"
		description = "This rule detects SandroRat"
		source = "https://blogs.mcafee.com/mcafee-labs/sandrorat-android-rat-targeting-polish-banking-users-via-e-mail-phishing/"

	condition:
		androguard.activity(/net.droidjack.server/i) 
}

rule andr_sk_bank
{
	meta:
		description = "Yara rule for Banking trojan targeting South Korean banks"
		sample = "0af5c4c2f39aba06f6793f26d6caae134564441b2134e0b72536e65a62bcbfad"
		source = "https://www.zscaler.com/blogs/research/android-malware-targeting-south-korean-mobile-users"
		author = "https://twitter.com/5h1vang"

	strings:
		$str_1 = "NPKI"
		$str_2 = "portraitCallBack("
		$str_3 = "android.app.extra.DEVICE_ADMIN"
		$str_4 = "SMSReceiver&imsi="
		$str_5 = "com.ahnlab.v3mobileplus"

	condition:
		androguard.package_name("com.qbjkyd.rhsxa") or
		androguard.certificate.sha1("543382EDDAFC05B435F13BBE97037BB335C2948B") or
		(androguard.permission(/android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.INTERNET/) and 
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and 
		all of ($str_*))
}

rule SlemBunk : android
{
	meta:
		description = "Rule to detect trojans imitating banks of North America, Eurpope and Asia"
		author = "@plutec_net"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
		source = "https://www.fireeye.com/blog/threat-research/2015/12/slembunk_an_evolvin.html"

	strings:
		$a = "#intercept_sms_start"
		$b = "#intercept_sms_stop"
		$c = "#block_numbers"
		$d = "#wipe_data"
		$e = "Visa Electron"

	condition:
		all of them
		
}

rule smsfraud1 : android
{
    meta:
        author = "Antonio Sánchez https://twitter.com/plutec_net"
        reference = "https://koodous.com/"
        description = "This rule detects a kind of SMSFraud trojan"
        sample = "265890c3765d9698091e347f5fcdcf1aba24c605613916820cc62011a5423df2"
        sample2 = "112b61c778d014088b89ace5e561eb75631a35b21c64254e32d506379afc344c"

    strings:
        $a = "E!QQAZXS"
        $b = "__exidx_end"
        $c = "res/layout/notify_apkinstall.xmlPK"

    condition:
    all of them
        
}

rule smsfraud2 : android {
    meta:
        author = "Antonio Sánchez https://twitter.com/plutec_net"
        reference = "https://koodous.com/"
        sample = "0200a454f0de2574db0b58421ea83f0f340bc6e0b0a051fe943fdfc55fea305b"
        sample2 = "bff3881a8096398b2ded8717b6ce1b86a823e307c919916ab792a13f2f5333b6"

    strings:
        $a = "pluginSMS_decrypt"
        $b = "pluginSMS_encrypt"
        $c = "__dso_handle"
        $d = "lib/armeabi/libmylib.soUT"
        $e = "]Diok\"3|"
    condition:
        all of them
}


rule spyAgent
{
	meta:
		description = "This rule detects arabian spyware which records call and gathers user information which is later sent to a remote c&c"
		sample = "7cbf61fbb31c26530cafb46282f5c90bc10fe5c724442b8d1a0b87a8125204cb"
		reference = "https://blogs.mcafee.com/mcafee-labs/android-spyware-targets-security-job-seekers-in-saudi-arabia/"
		author = "@koodous_project"

	strings:
		$phone = "0597794205"
		$caption = "New victim arrived"
		$cc = "http://ksa-sef.com/Hack%20Mobaile/ADDNewSMS.php"
		$cc_alt = "http://ksa-sef.com/Hack%20Mobaile/AddAllLogCall.php"
		$cc_alt2= "http://ksa-sef.com/Hack%20Mobaile/addScreenShot.php"
		$cc_alt3= "http://ksa-sef.com/Hack%20Mobaile/ADDSMS.php"
		$cc_alt4 = "http://ksa-sef.com/Hack%20Mobaile/ADDVCF.php"
		$cc_alt5 = "http://ksa-sef.com/Hack%20Mobaile/ADDIMSI.php"
		$cc_alt6 = "http://ksa-sef.com/Hack%20Mobaile/ADDHISTORYINTERNET.php"
		$cc_alt7 = "http://ksa-sef.com/Hack%20Mobaile/addInconingLogs.php"

	condition:
		androguard.url(/ksa-sef\.com/) or ($phone and $caption) or ($cc and $cc_alt and $cc_alt2 and $cc_alt3 and $cc_alt4 and $cc_alt5 and $cc_alt6 and $cc_alt7)
		
}


rule SpyNet : malware
{
	meta:
		description = "Ruleset to detect SpyNetV2 samples. "
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
	$a = "odNotice.txt"
	$b = "camera This device has camera!"
	$c = "camera This device has Nooo camera!"
	$d = "send|1sBdBBbbBBF|K|"
	$e = "send|372|ScreamSMS|senssd"
	$f = "send|5ms5gs5annc"
	$g = "send|45CLCLCa01"
	$h = "send|999SAnd|TimeStart"
	$i = "!s!c!r!e!a!m!"
	condition:
		4 of them 
}

rule spynote_variants
{
    meta:
        author = "5h1vang https://analyst.koodous.com/analysts/5h1vang"
        description = "Yara rule for detection of different Spynote Variants"
        source = " http://researchcenter.paloaltonetworks.com/2016/07/unit42-spynote-android-trojan-builder-leaked/"
        rule_source = "https://analyst.koodous.com/rulesets/1710"

    strings:
        $str_1 = "SERVER_IP" nocase
        $str_2 = "SERVER_NAME" nocase
        $str_3 = "content://sms/inbox"
        $str_4 = "screamHacker" 
        $str_5 = "screamon"
    condition:
        androguard.package_name("dell.scream.application") or 
        androguard.certificate.sha1("219D542F901D8DB85C729B0F7AE32410096077CB") or
        all of ($str_*)
}

rule android_spywaller : android
{
	meta:
		description = "Rule for detection of Android Spywaller samples"
		sample = "7b31656b9722f288339cb2416557241cfdf69298a749e49f07f912aeb1e5931b"
		source = "http://blog.fortinet.com/post/android-spywaller-firewall-style-antivirus-blocking"

	strings:
		$str_1 = "droid.png"
		$str_2 = "getSrvAddr"
		$str_3 = "getSrvPort"		
		$str_4 = "android.intent.action.START_GOOGLE_SERVICE"

	condition:
		androguard.certificate.sha1("165F84B05BD33DA1BA0A8E027CEF6026B7005978") or
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and 
		all of ($str_*)
}

rule Android_Switcher
{
	meta:
		description = "This rule detects Android wifi Switcher variants"
		sample = "d3aee0e8fa264a33f77bdd59d95759de8f6d4ed6790726e191e39bcfd7b5e150"
		source = "https://securelist.com/blog/mobile/76969/switcher-android-joins-the-attack-the-router-club/"
    source2 = "https://koodous.com/rulesets/2049"
    author = "https://twitter.com/5h1vang"

	strings:
		$str_1 = "javascript:scrollTo"		
		$str_5 = "javascript:document.getElementById('dns1')"
		$str_6 = "admin:"

		$dns_2 = "101.200.147.153"
		$dns_3 = "112.33.13.11"
		$dns_4 = "120.76.249.59"


	condition:
		androguard.certificate.sha1("2421686AE7D976D19AB72DA1BDE273C537D2D4F9") or 
		(androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.ACCESS_WIFI_STATE/) and 
		($dns_2 or $dns_3 or $dns_4) and all of ($str_*))
}

rule tachi : android
{
	meta:
		author = "https://twitter.com/plutec_net"
		source = "https://analyst.koodous.com/rulesets/1332"
		description = "This rule detects tachi apps (not all malware)"
		sample = "10acdf7db989c3acf36be814df4a95f00d370fe5b5fda142f9fd94acf46149ec"

	strings:
		$a = "svcdownload"
		$xml_1 = "<config>"
		$xml_2 = "<apptitle>"
		$xml_3 = "<txinicio>"
		$xml_4 = "<txiniciotitulo>"
		$xml_5 = "<txnored>"
		$xml_6 = "<txnoredtitulo>"
		$xml_7 = "<txnoredretry>"
		$xml_8 = "<txnoredsalir>"
		$xml_9 = "<laurl>"
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

rule android_tempting_cedar_spyware
{
	meta:
    	Author = "@X0RC1SM"
        Date = "2018-03-06"
        Reference = "https://blog.avast.com/avast-tracks-down-tempting-cedar-spyware"
	strings:
		$PK_HEADER = {50 4B 03 04}
		$MANIFEST = "META-INF/MANIFEST.MF"
		$DEX_FILE = "classes.dex"
		$string = "rsdroid.crt"
	
	condition:
    	$PK_HEADER in (0..4) and $MANIFEST and $DEX_FILE and any of ($string*)
}

rule andr_tordow
{
	meta:
		description = "Yara for variants of Trojan-Banker.AndroidOS.Tordow. Test rule"
		source = "https://securelist.com/blog/mobile/76101/the-banker-that-can-steal-anything/"
		author = "https://twitter.com/5h1vang"

	condition:
		androguard.package_name("com.di2.two") or		
		(androguard.activity(/API2Service/i) and
		androguard.activity(/CryptoUtil/i) and
		androguard.activity(/Loader/i) and
		androguard.activity(/Logger/i) and 
		androguard.permission(/android.permission.INTERNET/)) or
		
		//Certificate check based on @stevenchan's comment
		androguard.certificate.sha1("78F162D2CC7366754649A806CF17080682FE538C") or
		androguard.certificate.sha1("BBA26351CE41ACBE5FA84C9CF331D768CEDD768F") or
		androguard.certificate.sha1("0B7C3BC97B6D7C228F456304F5E1B75797B7265E")
}

rule Android_Triada : android
{
	meta:
		author = "reverseShell - https://twitter.com/JReyCastro"
		date = "2016/03/04"
		description = "This rule try to detects Android.Triada.Malware"
		sample = "4656aa68ad30a5cf9bcd2b63f21fba7cfa0b70533840e771bd7d6680ef44794b"
		source = "https://securelist.com/analysis/publications/74032/attack-on-zygote-a-new-twist-in-the-evolution-of-mobile-threats/"
		
	strings:
		$string_1 = "android/system/PopReceiver"
	condition:
		all of ($string_*) and
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) and
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/android.permission.GET_TASKS/)
}

rule Trojan_Dendroid
{
meta:
author = "https://www.twitter.com/SadFud75"
description = "Detection of dendroid trojan"
strings:
$s1 = "/upload-pictures.php?"
$s2 = "/get-functions.php?"
$s3 = "/new-upload.php?"
$s4 = "/message.php?"
$s5 = "/get.php?"
condition:
3 of them
}

rule Trojan_Droidjack
{
meta:
author = "https://twitter.com/SadFud75"
condition:
androguard.package_name("net.droidjack.server") or androguard.activity(/net.droidjack.server/i)
}

rule VikingBotnet
{
	meta:
	  author = "https://twitter.com/koodous_project"
		description = "Rule to detect Viking Order Botnet."
		sample = "85e6d5b3569e5b22a16245215a2f31df1ea3a1eb4d53b4c286a6ad2a46517b0c"

	strings:
		$a = "cv7obBkPVC2pvJmWSfHzXh"
		$b = "http://joyappstech.biz:11111/knock/"
		$c = "I HATE TESTERS onGlobalLayout"
		$d = "http://144.76.70.213:7777/ecspectapatronum/"
		
	condition:
		($a and $c) or ($b and $d) 
}
