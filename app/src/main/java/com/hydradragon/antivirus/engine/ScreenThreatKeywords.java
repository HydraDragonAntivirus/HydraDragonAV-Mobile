package com.hydradragon.antivirus.engine;

/**
 * Multi-language phrase lists for the accessibility screen-text scanner
 * (DynamicAnalysisService). Matching is a plain lowercase substring check —
 * no NLP, no translation lookups — so each phrase is listed per language
 * rather than relying on the device locale (a scam SMS can arrive in any
 * language regardless of the phone's configured language).
 *
 * Languages covered: English, Turkish, Spanish, German, French, Russian,
 * Portuguese, Arabic, Italian, Dutch, Polish, Ukrainian, Chinese (Simplified),
 * Japanese, Korean, Hindi, Indonesian, Vietnamese, Persian, Thai.
 */
public final class ScreenThreatKeywords {
    private ScreenThreatKeywords() {}

    /** Ransomware lock-screen / note text. */
    public static final String[] RANSOMWARE = {
        // English
        "your files are encrypted", "pay bitcoin", "recover your files", "bitcoin address",
        "decrypt your files", "all your files have been encrypted", "your files have been locked",
        // Turkish
        "dosyalarınız şifrelendi", "bitcoin ödeyin", "dosyalarınızı kurtarın", "bitcoin adresi",
        "dosyalarınız kilitlendi",
        // Spanish
        "sus archivos han sido cifrados", "pague bitcoin", "recupere sus archivos", "dirección de bitcoin",
        // German
        "ihre dateien wurden verschlüsselt", "bitcoin bezahlen", "stellen sie ihre dateien wieder her",
        // French
        "vos fichiers ont été chiffrés", "payez en bitcoin", "récupérez vos fichiers",
        // Russian
        "ваши файлы зашифрованы", "оплатите биткоин", "восстановите ваши файлы",
        // Portuguese
        "seus arquivos foram criptografados", "pague em bitcoin", "recupere seus arquivos",
        // Arabic
        "تم تشفير ملفاتك", "ادفع بيتكوين", "استرجع ملفاتك",
        // Italian
        "i tuoi file sono stati crittografati", "paga in bitcoin", "recupera i tuoi file",
        "indirizzo bitcoin",
        // Dutch
        "uw bestanden zijn versleuteld", "betaal bitcoin", "herstel uw bestanden", "bitcoin-adres",
        // Polish
        "twoje pliki zostały zaszyfrowane", "zapłać bitcoinem", "odzyskaj swoje pliki",
        "adres bitcoin",
        // Ukrainian
        "ваші файли зашифровані", "заплатіть біткоїн", "відновіть свої файли",
        // Chinese (Simplified)
        "您的文件已被加密", "支付比特币", "恢复您的文件", "比特币地址",
        // Japanese
        "ファイルは暗号化されました", "ビットコインで支払う", "ファイルを復元する", "ビットコインアドレス",
        // Korean
        "파일이 암호화되었습니다", "비트코인으로 결제하세요", "파일을 복구하세요", "비트코인 주소",
        // Hindi
        "आपकी फ़ाइलें एन्क्रिप्ट कर दी गई हैं", "बिटकॉइन का भुगतान करें", "अपनी फ़ाइलें पुनर्प्राप्त करें",
        // Indonesian
        "file anda telah dienkripsi", "bayar bitcoin", "pulihkan file anda", "alamat bitcoin",
        // Vietnamese
        "các tệp của bạn đã được mã hóa", "thanh toán bằng bitcoin", "khôi phục tệp của bạn",
        // Persian
        "فایل‌های شما رمزگذاری شده‌اند", "بیت‌کوین پرداخت کنید", "فایل‌های خود را بازیابی کنید",
        // Thai
        "ไฟล์ของคุณถูกเข้ารหัสแล้ว", "จ่ายเป็นบิตคอยน์", "กู้คืนไฟล์ของคุณ",
    };

    /** Device-admin activation prompt (used only as an informational log signal). */
    public static final String[] DEVICE_ADMIN = {
        "activate device admin",
        "cihaz yöneticisini etkinleştir", "cihaz yöneticisi",
        "activar administrador del dispositivo",
        "geräteadministrator aktivieren",
        "activer l'administrateur de l'appareil",
        "активировать администратора устройства",
        "ativar administrador do dispositivo",
        "تفعيل مسؤول الجهاز",
        "attiva amministratore dispositivo",
        "apparaatbeheerder activeren",
        "aktywuj administratora urządzenia",
        "активувати адміністратора пристрою",
        "激活设备管理器",
        "デバイス管理者を有効にする",
        "기기 관리자 활성화",
        "डिवाइस एडमिन सक्रिय करें",
        "aktifkan admin perangkat",
        "kích hoạt quản trị viên thiết bị",
        "فعال‌سازی مدیر دستگاه",
        "เปิดใช้งานผู้ดูแลอุปกรณ์",
    };

    /** SMS/smishing + generic phishing lures shown as on-screen text (SMS app, browser, WebView popups). */
    public static final String[] SMS_PHISHING = {
        // English
        "verify your account", "your account has been suspended", "confirm your identity",
        "you have won", "claim your prize", "your package is on hold", "update your payment details",
        "unusual activity detected on your account", "your parcel could not be delivered",
        "click the link below to", "enter your otp", "one time password", "your bank account",
        "suspended due to suspicious activity", "act now to avoid", "final notice",
        // Turkish
        "hesabınızı doğrulayın", "hesabınız askıya alındı", "kimliğinizi doğrulayın",
        "ödül kazandınız", "ödülünüzü talep edin", "kargonuz teslim edilemedi",
        "ödeme bilgilerinizi güncelleyin", "hesabınızda şüpheli işlem tespit edildi",
        "aşağıdaki bağlantıya tıklayın", "tek kullanımlık şifre", "banka hesabınız",
        "son uyarı",
        // Spanish
        "verifique su cuenta", "su cuenta ha sido suspendida", "confirme su identidad",
        "ha ganado un premio", "reclame su premio", "su paquete no pudo ser entregado",
        "actualice sus datos de pago", "actividad inusual detectada en su cuenta",
        "haga clic en el siguiente enlace", "código de un solo uso", "su cuenta bancaria",
        // German
        "bestätigen sie ihr konto", "ihr konto wurde gesperrt", "bestätigen sie ihre identität",
        "sie haben gewonnen", "fordern sie ihren gewinn an", "ihr paket konnte nicht zugestellt werden",
        "aktualisieren sie ihre zahlungsdaten", "verdächtige aktivität auf ihrem konto festgestellt",
        "klicken sie auf den folgenden link", "einmaliges passwort", "ihr bankkonto",
        // French
        "vérifiez votre compte", "votre compte a été suspendu", "confirmez votre identité",
        "vous avez gagné", "réclamez votre prix", "votre colis n'a pas pu être livré",
        "mettez à jour vos informations de paiement", "activité inhabituelle détectée sur votre compte",
        "cliquez sur le lien ci-dessous", "mot de passe à usage unique", "votre compte bancaire",
        // Russian
        "подтвердите свою учетную запись", "ваша учетная запись заблокирована",
        "подтвердите свою личность", "вы выиграли", "получите свой приз",
        "ваша посылка не может быть доставлена", "обновите платежные данные",
        "обнаружена подозрительная активность", "перейдите по ссылке ниже",
        "одноразовый пароль", "ваш банковский счет",
        // Portuguese
        "verifique sua conta", "sua conta foi suspensa", "confirme sua identidade",
        "você ganhou um prêmio", "resgate seu prêmio", "sua encomenda não pôde ser entregue",
        "atualize seus dados de pagamento", "atividade suspeita detectada em sua conta",
        "clique no link abaixo", "senha de uso único", "sua conta bancária",
        // Arabic
        "تحقق من حسابك", "تم تعليق حسابك", "أكد هويتك", "لقد ربحت جائزة", "استلم جائزتك",
        "لم يتم تسليم طردك", "قم بتحديث بيانات الدفع", "تم رصد نشاط غير عادي في حسابك",
        "انقر على الرابط أدناه", "رمز مرور لمرة واحدة", "حسابك المصرفي",
        // Italian
        "verifica il tuo account", "il tuo account è stato sospeso", "confermi la tua identità",
        "hai vinto", "riscatta il tuo premio", "il tuo pacco è in attesa",
        "aggiorna i tuoi dati di pagamento", "attività inusuale rilevata sul tuo account",
        "clicca sul link sottostante", "password usa e getta", "il tuo conto bancario",
        // Dutch
        "verifieer uw account", "uw account is opgeschort", "bevestig uw identiteit",
        "u heeft gewonnen", "claim uw prijs", "uw pakket kon niet worden afgeleverd",
        "update uw betalingsgegevens", "ongewone activiteit gedetecteerd op uw account",
        "klik op de link hieronder", "eenmalig wachtwoord", "uw bankrekening",
        // Polish
        "zweryfikuj swoje konto", "twoje konto zostało zablokowane", "potwierdź swoją tożsamość",
        "wygrałeś nagrodę", "odbierz swoją nagrodę", "twoja przesyłka nie mogła zostać dostarczona",
        "zaktualizuj dane płatności", "wykryto nietypową aktywność na twoim koncie",
        "kliknij poniższy link", "jednorazowe hasło", "twoje konto bankowe",
        // Ukrainian
        "підтвердьте свій рахунок", "ваш рахунок заблоковано", "підтвердьте свою особу",
        "ви виграли", "отримайте свій приз", "вашу посилку не вдалося доставити",
        "оновіть платіжні дані", "виявлено підозрілу активність на вашому рахунку",
        "перейдіть за посиланням нижче", "одноразовий пароль", "ваш банківський рахунок",
        // Chinese (Simplified)
        "请验证您的账户", "您的账户已被暂停", "确认您的身份", "您中奖了", "领取您的奖品",
        "您的包裹无法送达", "请更新您的付款信息", "检测到您账户有异常活动",
        "点击下方链接", "一次性验证码", "您的银行账户",
        // Japanese
        "アカウントを確認してください", "あなたのアカウントは停止されました", "本人確認をしてください",
        "当選しました", "賞品を受け取る", "荷物をお届けできませんでした",
        "支払い情報を更新してください", "アカウントで異常な操作が検出されました",
        "下記のリンクをクリック", "ワンタイムパスワード", "あなたの銀行口座",
        // Korean
        "계정을 인증하세요", "계정이 정지되었습니다", "신원을 확인하세요",
        "당첨되었습니다", "상품을 받으세요", "택배가 배송되지 않았습니다",
        "결제 정보를 업데이트하세요", "계정에서 비정상적인 활동이 감지되었습니다",
        "아래 링크를 클릭하세요", "일회용 비밀번호", "귀하의 은행 계좌",
        // Hindi
        "अपने खाते को सत्यापित करें", "आपका खाता निलंबित कर दिया गया है", "अपनी पहचान की पुष्टि करें",
        "आप जीत गए हैं", "अपना पुरस्कार प्राप्त करें", "आपका पैकेज वितरित नहीं किया जा सका",
        "अपनी भुगतान जानकारी अपडेट करें", "आपके खाते में असामान्य गतिविधि पाई गई",
        "नीचे दिए गए लिंक पर क्लिक करें", "एक बार का पासवर्ड", "आपका बैंक खाता",
        // Indonesian
        "verifikasi akun anda", "akun anda telah ditangguhkan", "konfirmasi identitas anda",
        "anda telah menang", "klaim hadiah anda", "paket anda tidak dapat dikirim",
        "perbarui detail pembayaran anda", "aktivitas tidak biasa terdeteksi pada akun anda",
        "klik tautan di bawah ini", "kata sandi sekali pakai", "rekening bank anda",
        // Vietnamese
        "xác minh tài khoản của bạn", "tài khoản của bạn đã bị tạm ngưng", "xác nhận danh tính của bạn",
        "bạn đã trúng thưởng", "nhận giải thưởng của bạn", "không thể giao gói hàng của bạn",
        "cập nhật thông tin thanh toán của bạn", "phát hiện hoạt động bất thường trên tài khoản của bạn",
        "nhấp vào liên kết dưới đây", "mật khẩu dùng một lần", "tài khoản ngân hàng của bạn",
        // Persian
        "حساب خود را تأیید کنید", "حساب شما مسدود شده است", "هویت خود را تأیید کنید",
        "شما برنده شده‌اید", "جایزه خود را دریافت کنید", "بسته شما تحویل داده نشد",
        "اطلاعات پرداخت خود را به‌روزرسانی کنید", "فعالیت غیرعادی در حساب شما شناسایی شد",
        "روی پیوند زیر کلیک کنید", "رمز یک‌بار مصرف", "حساب بانکی شما",
        // Thai
        "ยืนยันบัญชีของคุณ", "บัญชีของคุณถูกระงับ", "ยืนยันตัวตนของคุณ",
        "คุณได้รับรางวัล", "รับรางวัลของคุณ", "ไม่สามารถจัดส่งพัสดุของคุณได้",
        "อัปเดตข้อมูลการชำระเงินของคุณ", "ตรวจพบกิจกรรมที่ไม่ปกติในบัญชีของคุณ",
        "คลิกลิงก์ด้านล่าง", "รหัสผ่านแบบใช้ครั้งเดียว", "บัญชีธนาคารของคุณ",
    };

    /** Fake antivirus warning / tech-support scam lures — bogus "N viruses found"
     *  full-screen popups pushing a call to a "support" number or a fake cleaner
     *  app install, shown in a browser/WebView (never a real scan result). */
    public static final String[] FAKE_VIRUS_WARNING = {
        // English
        "your device is infected", "virus detected", "system is infected",
        "call this number immediately", "call microsoft support", "call apple support",
        "your phone has been infected", "critical alert", "device infected with",
        "your device is at risk", "malware detected on your device", "system32 has been damaged",
        "do not turn off your phone", "technical support", "your data is at risk",
        // Turkish
        "cihazınız virüs bulaştı", "virüs tespit edildi", "sistem virüs bulaştı",
        "hemen bu numarayı arayın", "microsoft destek hattını arayın", "apple destek hattını arayın",
        "telefonunuza virüs bulaştı", "kritik uyarı", "cihazınız risk altında",
        "cihazınızda kötü amaçlı yazılım tespit edildi", "telefonunuzu kapatmayın", "teknik destek",
        // Spanish
        "su dispositivo está infectado", "virus detectado", "el sistema está infectado",
        "llame a este número inmediatamente", "llame al soporte de microsoft", "llame al soporte de apple",
        "su teléfono ha sido infectado", "alerta crítica", "su dispositivo está en riesgo",
        "malware detectado en su dispositivo", "no apague su teléfono", "soporte técnico",
        // German
        "ihr gerät ist infiziert", "virus erkannt", "das system ist infiziert",
        "rufen sie sofort diese nummer an", "rufen sie den microsoft-support an", "rufen sie den apple-support an",
        "ihr telefon wurde infiziert", "kritischer alarm", "ihr gerät ist gefährdet",
        "malware auf ihrem gerät erkannt", "schalten sie ihr telefon nicht aus", "technischer support",
        // French
        "votre appareil est infecté", "virus détecté", "le système est infecté",
        "appelez ce numéro immédiatement", "appelez le support microsoft", "appelez le support apple",
        "votre téléphone a été infecté", "alerte critique", "votre appareil est en danger",
        "logiciel malveillant détecté sur votre appareil", "n'éteignez pas votre téléphone", "support technique",
        // Russian
        "ваше устройство заражено", "обнаружен вирус", "система заражена",
        "немедленно позвоните по этому номеру", "позвоните в поддержку microsoft", "позвоните в поддержку apple",
        "ваш телефон заражен", "критическое предупреждение", "ваше устройство в опасности",
        "на вашем устройстве обнаружено вредоносное по", "не выключайте телефон", "техническая поддержка",
        // Portuguese
        "seu dispositivo está infectado", "vírus detectado", "o sistema está infectado",
        "ligue para este número imediatamente", "ligue para o suporte da microsoft", "ligue para o suporte da apple",
        "seu telefone foi infectado", "alerta crítico", "seu dispositivo está em risco",
        "malware detectado em seu dispositivo", "não desligue seu telefone", "suporte técnico",
        // Arabic
        "جهازك مصاب", "تم اكتشاف فيروس", "النظام مصاب",
        "اتصل بهذا الرقم فورا", "اتصل بدعم مايكروسوفت", "اتصل بدعم آبل",
        "تم إصابة هاتفك", "تنبيه حرج", "جهازك معرض للخطر",
        "تم اكتشاف برامج ضارة على جهازك", "لا تقم بإيقاف تشغيل هاتفك", "الدعم الفني",
        // Italian
        "il tuo dispositivo è infetto", "virus rilevato", "il sistema è infetto",
        "chiama subito questo numero", "chiama il supporto microsoft", "chiama il supporto apple",
        "il tuo telefono è stato infettato", "avviso critico", "il tuo dispositivo è a rischio",
        "malware rilevato sul tuo dispositivo", "non spegnere il telefono", "supporto tecnico",
        // Dutch
        "uw apparaat is geïnfecteerd", "virus gedetecteerd", "systeem is geïnfecteerd",
        "bel dit nummer onmiddellijk", "bel microsoft-ondersteuning", "bel apple-ondersteuning",
        "uw telefoon is geïnfecteerd", "kritieke waarschuwing", "uw apparaat loopt risico",
        "malware gedetecteerd op uw apparaat", "schakel uw telefoon niet uit", "technische ondersteuning",
        // Polish
        "twoje urządzenie jest zainfekowane", "wykryto wirusa", "system jest zainfekowany",
        "zadzwoń pod ten numer natychmiast", "zadzwoń do pomocy technicznej microsoft", "zadzwoń do pomocy technicznej apple",
        "twój telefon został zainfekowany", "krytyczny alert", "twoje urządzenie jest zagrożone",
        "wykryto złośliwe oprogramowanie na twoim urządzeniu", "nie wyłączaj telefonu", "pomoc techniczna",
        // Ukrainian
        "ваш пристрій заражено", "виявлено вірус", "система заражена",
        "негайно зателефонуйте за цим номером", "зателефонуйте до служби підтримки microsoft", "зателефонуйте до служби підтримки apple",
        "ваш телефон заражено", "критичне попередження", "ваш пристрій під загрозою",
        "на вашому пристрої виявлено шкідливе по", "не вимикайте телефон", "технічна підтримка",
        // Chinese (Simplified)
        "您的设备已感染", "检测到病毒", "系统已感染",
        "请立即拨打此号码", "请致电微软支持", "请致电苹果支持",
        "您的手机已感染", "严重警报", "您的设备处于危险中",
        "在您的设备上检测到恶意软件", "请勿关闭手机", "技术支持",
        // Japanese
        "デバイスが感染しています", "ウイルスが検出されました", "システムが感染しています",
        "今すぐこの番号に電話してください", "マイクロソフトサポートに電話してください", "アップルサポートに電話してください",
        "あなたの携帯電話が感染しました", "緊急警告", "デバイスが危険にさらされています",
        "デバイスでマルウェアが検出されました", "電話の電源を切らないでください", "テクニカルサポート",
        // Korean
        "기기가 감염되었습니다", "바이러스가 감지되었습니다", "시스템이 감염되었습니다",
        "즉시 이 번호로 전화하세요", "마이크로소프트 지원팀에 전화하세요", "애플 지원팀에 전화하세요",
        "휴대폰이 감염되었습니다", "긴급 경고", "기기가 위험에 처해 있습니다",
        "기기에서 악성코드가 감지되었습니다", "휴대폰을 끄지 마세요", "기술 지원",
        // Hindi
        "आपका डिवाइस संक्रमित है", "वायरस का पता चला", "सिस्टम संक्रमित है",
        "तुरंत इस नंबर पर कॉल करें", "माइक्रोसॉफ्ट सपोर्ट को कॉल करें", "एप्पल सपोर्ट को कॉल करें",
        "आपका फोन संक्रमित हो गया है", "गंभीर चेतावनी", "आपका डिवाइस खतरे में है",
        "आपके डिवाइस पर मैलवेयर का पता चला", "अपना फोन बंद न करें", "तकनीकी सहायता",
        // Indonesian
        "perangkat anda terinfeksi", "virus terdeteksi", "sistem terinfeksi",
        "segera hubungi nomor ini", "hubungi dukungan microsoft", "hubungi dukungan apple",
        "ponsel anda telah terinfeksi", "peringatan kritis", "perangkat anda berisiko",
        "malware terdeteksi di perangkat anda", "jangan matikan ponsel anda", "dukungan teknis",
        // Vietnamese
        "thiết bị của bạn bị nhiễm", "phát hiện vi-rút", "hệ thống bị nhiễm",
        "hãy gọi ngay số này", "gọi hỗ trợ microsoft", "gọi hỗ trợ apple",
        "điện thoại của bạn đã bị nhiễm", "cảnh báo nghiêm trọng", "thiết bị của bạn đang gặp rủi ro",
        "phát hiện phần mềm độc hại trên thiết bị của bạn", "không tắt điện thoại", "hỗ trợ kỹ thuật",
        // Persian
        "دستگاه شما آلوده است", "ویروس شناسایی شد", "سیستم آلوده است",
        "فورا با این شماره تماس بگیرید", "با پشتیبانی مایکروسافت تماس بگیرید", "با پشتیبانی اپل تماس بگیرید",
        "تلفن شما آلوده شده است", "هشدار حیاتی", "دستگاه شما در معرض خطر است",
        "بدافزار روی دستگاه شما شناسایی شد", "تلفن خود را خاموش نکنید", "پشتیبانی فنی",
        // Thai
        "อุปกรณ์ของคุณติดไวรัส", "ตรวจพบไวรัส", "ระบบติดไวรัส",
        "โทรหมายเลขนี้ทันที", "โทรหาฝ่ายสนับสนุนไมโครซอฟท์", "โทรหาฝ่ายสนับสนุนแอปเปิล",
        "โทรศัพท์ของคุณติดไวรัสแล้ว", "การแจ้งเตือนที่สำคัญ", "อุปกรณ์ของคุณมีความเสี่ยง",
        "ตรวจพบมัลแวร์บนอุปกรณ์ของคุณ", "อย่าปิดโทรศัพท์ของคุณ", "ฝ่ายสนับสนุนทางเทคนิค",
    };

    public static boolean containsAny(String lowerText, String[] phrases) {
        for (String p : phrases) {
            if (lowerText.contains(p)) return true;
        }
        return false;
    }
}
