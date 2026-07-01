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

    public static boolean containsAny(String lowerText, String[] phrases) {
        for (String p : phrases) {
            if (lowerText.contains(p)) return true;
        }
        return false;
    }
}
