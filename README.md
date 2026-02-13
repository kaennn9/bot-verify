# Double Counter - نظام التحقق المحسّن

## المميزات الجديدة ✨

### 1. تشفير الروابط 🔐
- تم تشفير الـ URL بالكامل
- بدلاً من: `?code=abc123&user=12345`
- الآن: `?t=gAAAAABl8xK7mQ...` (مشفر بالكامل)

### 2. إصلاح مشكلة الزر "Initializing" ✅
- الزر الآن يعمل بشكل صحيح
- يتفعل تلقائياً بعد الفحوصات الأمنية
- **CAPTCHA اختياري تماماً** - لو مفيش مفتاح، الزر يتفعل مباشرة!

### 3. التحقق الأمني المحسّن 🛡️
- VPN/Proxy Detection (اختياري)
- Browser Fingerprinting
- Alt Account Prevention
- Cloudflare Turnstile CAPTCHA (اختياري)

## التثبيت 📥

### 1. تثبيت المتطلبات
```bash
pip install -r requirements.txt --break-system-packages
```

### 2. إنشاء مجلد `web`
```bash
mkdir -p web
mv verify.html web/
mv success.html web/
mv failed.html web/
```

### 3. تشغيل البوت
```bash
python3 bot_fixed.py
```

## الإعدادات المهمة ⚙️

### الإعدادات الأساسية (مطلوبة)
```json
{
  "bot": {
    "token": "YOUR_BOT_TOKEN",
    "verified_role_name": "Verified"  // اسم الرول
  },
  "security": {
    "min_account_age_days": 0,  // 0 = لا يوجد حد أدنى للعمر
    "block_vpns": false,         // false = يسمح بـ VPN
    "block_alts": true           // true = يمنع Alt Accounts
  }
}
```

### الإعدادات الاختيارية (للحماية المتقدمة)
```json
{
  "verification": {
    "require_captcha": false  // true = يطلب CAPTCHA
  },
  "api_keys": {
    "vpnapi_io": "",           // اختياري: VPN Detection API
    "cloudflare_secret": ""    // اختياري: CAPTCHA
  }
}
```

## كيفية عمل النظام 🔄

### النظام الأساسي (بدون CAPTCHA)
```
1. User يضغط Verify في Discord
2. البوت يولد رابط مشفر
3. User يفتح الرابط
4. الصفحة تعمل الفحوصات:
   ✅ IP Check
   ✅ Browser Analysis
   ✅ Fingerprint Generation
5. الزر يتفعل تلقائياً
6. User يضغط Verify
7. البوت يعطي الرول ✅
```

### مع CAPTCHA (اختياري)
إذا أضفت `cloudflare_secret` في config:
```
... نفس الخطوات السابقة ...
5. يظهر CAPTCHA
6. User يحل CAPTCHA
7. الزر يتفعل
8. User يضغط Verify
9. البوت يعطي الرول ✅
```

## كيفية تفعيل الحماية المتقدمة 🔐

### 1. CAPTCHA (Cloudflare Turnstile)
```bash
# احصل على المفاتيح من: https://dash.cloudflare.com/
# في config.json:
"verification": {
  "require_captcha": true
},
"api_keys": {
  "cloudflare_secret": "0x4AAA..."
}

# في verify.html (السطر 398):
sitekey: 'YOUR_SITE_KEY'
```

### 2. VPN Detection
```bash
# احصل على API Key من: https://vpnapi.io
# في config.json:
"security": {
  "block_vpns": true
},
"api_keys": {
  "vpnapi_io": "your-api-key"
}
```

### 3. Alt Account Detection
```json
"security": {
  "block_alts": true,
  "min_account_age_days": 7  // الحساب يجب يكون أقدم من 7 أيام
}
```

## الأوامر 💬

```
!setupverify [#channel]  - إنشاء بانل التحقق
!verifyforce @user       - تحقق يدوي
!unverify @user          - إلغاء التحقق وحظر
!vstats                  - إحصائيات
!logs [عدد]              - عرض السجلات
```

## إصلاح المشاكل 🔧

### الزر معطل؟
**السبب:** النظام بيستنى CAPTCHA
**الحل:** 
1. في `config.json` غير `"require_captcha": false`
2. أو احصل على Cloudflare keys وفعّلها

### الرول لا يتضاف؟
1. تأكد من وجود رول باسم "Verified" في السيرفر
2. البوت role يجب يكون أعلى من Verified role
3. البوت له صلاحية Manage Roles

### الرابط لا يعمل؟
- تأكد من `secret_key` في config ثابت (لا تغيره)
- الرابط صالح لمدة 10 دقائق فقط

## مستويات الحماية 🎚️

### مستوى 1: أساسي (بدون API Keys)
```json
{
  "security": {
    "min_account_age_days": 0,
    "block_vpns": false,
    "block_alts": false
  },
  "verification": {
    "require_captcha": false
  }
}
```
✅ Browser Fingerprinting
✅ URL Encryption
✅ Session Management

### مستوى 2: متوسط
```json
{
  "security": {
    "min_account_age_days": 7,
    "block_alts": true
  }
}
```
✅ كل ما في المستوى 1
✅ Alt Account Detection
✅ Account Age Check

### مستوى 3: متقدم (مع API Keys)
```json
{
  "security": {
    "block_vpns": true
  },
  "verification": {
    "require_captcha": true
  },
  "api_keys": {
    "vpnapi_io": "key",
    "cloudflare_secret": "key"
  }
}
```
✅ كل ما في المستوى 2
✅ VPN/Proxy Detection
✅ CAPTCHA Protection

## الملفات 📁

```
├── bot_fixed.py          # البوت الرئيسي
├── config.json           # الإعدادات (غير هذا حسب احتياجك)
├── requirements.txt      # المكتبات
├── web/
│   ├── verify.html      # صفحة التحقق
│   ├── success.html     # صفحة النجاح
│   └── failed.html      # صفحة الفشل
└── logs/
    └── verification.log # سجل العمليات
```

## أمثلة للاستخدام 📝

### تشغيل بسيط (بدون حماية)
```bash
# في config.json فقط غير:
"bot": { "token": "YOUR_TOKEN" }

# شغل البوت
python3 bot_fixed.py
```

### تشغيل مع حماية Alt Accounts
```json
"security": {
  "min_account_age_days": 7,
  "block_alts": true
}
```

### تشغيل مع كل الحماية
```json
"security": {
  "min_account_age_days": 30,
  "block_alts": true,
  "block_vpns": true
},
"verification": {
  "require_captcha": true
},
"api_keys": {
  "vpnapi_io": "your-key",
  "cloudflare_secret": "your-key"
}
```

## ملاحظات مهمة ⚠️

1. **النظام يشتغل بدون أي API Keys** - كل الحماية اختيارية!
2. الـ CAPTCHA يتفعل فقط لو حطيت `cloudflare_secret`
3. الـ VPN Detection يشتغل فقط لو حطيت `vpnapi_io`
4. **احتفظ** بنسخة احتياطية من `database.json`
5. **لا تشارك** `config.json` مع أحد

---

**صنع بواسطة Claude** 🤖
**النسخة:** 2.2 Optional Features
