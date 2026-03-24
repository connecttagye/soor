# NetGuard — تحليل ملفات المشروع

## نظرة عامة

**NetGuard** هو جدار حماية شبكي مفتوح المصدر لنظام Android، يعترض حركة الشبكة ويفلترها دون الحاجة إلى صلاحيات الجذر (root). يعتمد على واجهة **Android VPN API** لإنشاء نفق (TUN interface) يعترض جميع حزم IP الصادرة من التطبيقات، ثم يطبق سياسات السماح أو الحجب بناءً على هوية التطبيق (UID).

المصدر الأصلي: [M66B/NetGuard](https://github.com/M66B/NetGuard) — حقوق النشر 2015–2025 بواسطة Marcel Bokhorst (M66B)، مرخّص بموجب [GNU GPL v3](https://www.gnu.org/licenses/gpl-3.0.html).

---

## بنية المشروع

```
soor/
├── CMakeLists.txt   # تكوين البناء باستخدام CMake
├── netguard.h       # الترويسة الرئيسية: الثوابت، الهياكل، النماذج الأولية
├── netguard.c       # واجهة JNI الرئيسية وحلقة الأحداث
├── session.c        # إدارة الجلسات وحلقة epoll
├── ip.c             # معالجة حزم IP (IPv4/IPv6) وجدول UID
├── tcp.c            # آلة حالة TCP الكاملة + دعم SOCKS5
├── udp.c            # معالجة جلسات UDP + تحليل DNS
├── icmp.c           # معالجة ICMP / ICMPv6
├── dns.c            # تحليل استجابات DNS وحجب النطاقات
├── dhcp.c           # اكتشاف حزم DHCP
├── tls.c            # استخراج SNI من TLS ClientHello
├── pcap.c           # كتابة ملفات PCAP لالتقاط حركة الشبكة
└── util.c           # دوال مساعدة: المجاميع الاختبارية، JNI، إدارة الذاكرة
```

---

## وصف الملفات

### `CMakeLists.txt`
ملف تكوين البناء. يُنشئ مكتبة مشتركة (`netguard.so`) تُضمَّن في تطبيق Android. يربط المكتبة بـ `log` من Android NDK، ويُفعِّل محاذاة حجم الصفحة (`max-page-size=16384`) لدعم أجهزة ARM64 الحديثة.

---

### `netguard.h` — الترويسة الرئيسية

تحتوي على جميع تعريفات المشروع:

#### الثوابت الرئيسية

| الثابت | القيمة | الوصف |
|--------|--------|-------|
| `EPOLL_TIMEOUT` | 3600 ث | مهلة انتظار epoll |
| `SESSION_LIMIT` | 40% | نسبة حد الجلسات من الحد الأقصى لفتح الملفات |
| `TCP_IDLE_TIMEOUT` | 3600 ث | مهلة خمول TCP |
| `UDP_TIMEOUT_53` | 15 ث | مهلة UDP للمنفذ 53 (DNS) |
| `UDP_TIMEOUT_ANY` | 300 ث | مهلة UDP للمنافذ الأخرى |
| `ICMP_TIMEOUT` | 5 ث | مهلة ICMP |
| `TLS_SNI_LENGTH` | 255 | الحد الأقصى لطول اسم خادم TLS |

#### الهياكل الرئيسية

| الهيكل | الوصف |
|--------|-------|
| `context` | السياق الكلي: mutex، أنبوب التوقف، حالة الإيقاف، إصدار SDK، قائمة الجلسات |
| `arguments` | معطيات الخيط: بيئة JNI، كائن Java، واصف TUN، إعادة توجيه DNS، السياق |
| `ng_session` | جلسة شبكية: البروتوكول، بيانات الجلسة (icmp/udp/tcp)، المقبس، حدث epoll |
| `tcp_session` | حالة جلسة TCP: UID، توقيت، أرقام تسلسل، نوافذ، حالة SOCKS5، بيانات التراكم |
| `udp_session` | حالة جلسة UDP: UID، توقيت، MSS، بيانات الإرسال/الاستقبال |
| `icmp_session` | حالة جلسة ICMP: UID، المعرف، عناوين المصدر والوجهة |
| `uid_cache_entry` | مدخل ذاكرة التخزين المؤقت لـ UID: البروتوكول، العناوين، المنافذ، الوقت |
| `dns_header` | رأس رسالة DNS مع دعم كلا ترتيبَي البايت |
| `dhcp_packet` | هيكل حزمة DHCP |
| `pcap_hdr_s` / `pcaprec_hdr_s` | تنسيق رأس ملف PCAP وسجل الحزمة |

---

### `netguard.c` — الواجهة الرئيسية مع JNI

**الوظائف الرئيسية:**

- **`JNI_OnLoad`**: تُنفَّذ عند تحميل المكتبة. تُهيئ المراجع العالمية لفئات Java (`Packet`, `Allowed`, `ResourceRecord`, `Usage`)، وترفع حد الملفات المفتوحة.
- **`JNI_OnUnload`**: تُحرر المراجع العالمية عند تفريغ المكتبة.
- **`Java_eu_faircode_netguard_ServiceSinkhole_jni_init`**: تُهيئ السياق وتُعيد مؤشراً إليه.
- **`Java_eu_faircode_netguard_ServiceSinkhole_jni_start`**: تبدأ خيط معالجة الأحداث مع واصف TUN.
- **`Java_eu_faircode_netguard_ServiceSinkhole_jni_stop`**: تُوقف معالجة الأحداث عبر الأنبوب.
- **`Java_eu_faircode_netguard_ServiceSinkhole_jni_done`**: تُحرر الذاكرة وتُغلق الموارد.

**المتغيرات العامة:**
```c
char socks5_addr[INET6_ADDRSTRLEN + 1];  // عنوان خادم SOCKS5
int  socks5_port = 0;                    // منفذ SOCKS5
char socks5_username[128];               // اسم مستخدم SOCKS5
char socks5_password[128];               // كلمة مرور SOCKS5
int  loglevel = ANDROID_LOG_WARN;        // مستوى السجلات
```

---

### `session.c` — إدارة الجلسات

يُطبّق حلقة الأحداث الرئيسية القائمة على **epoll**:

- **`clear`**: يُحرر جميع الجلسات النشطة ويُغلق مقابسها.
- **`handle_events`**: خيط يستمر في العمل طالما التطبيق نشط:
  1. ينتظر أحداث epoll على مقابس الجلسات وواصف TUN.
  2. يتحقق من انتهاء مهل الجلسات ويُنظفها.
  3. يعالج البيانات الواردة من TUN ويوزعها على معالجات البروتوكول.
  4. يُراقب المقابس الخارجية ويُعيد البيانات عبر TUN إلى التطبيقات.

---

### `ip.c` — معالجة حزم IP

**`handle_ip`**: نقطة الدخول لجميع حزم IP من TUN:
1. يُحدد إصدار IP (4 أو 6) وبروتوكول الطبقة العليا.
2. يُحلل رؤوس IPv6 الامتدادية.
3. يُحدد UID التطبيق المُرسِل عبر `/proc/net/tcp|udp|tcp6|udp6|icmp|icmp6`.
4. يستخرج SNI من تدفقات TLS.
5. يستدعي `is_address_allowed` عبر JNI لفحص السياسة.
6. يُوجه الحزمة إلى `handle_tcp`، `handle_udp`، أو `handle_icmp`.

**`get_uid` / `get_uid_sub`**: يُحدد UID التطبيق من ملفات `/proc/net/` مع ذاكرة تخزين مؤقت لتحسين الأداء (`uid_cache`).

---

### `tcp.c` — معالجة TCP

يُطبق آلة حالة TCP الكاملة:

**حالات TCP:**
```
TCP_LISTEN → TCP_SYN_RECV → TCP_ESTABLISHED → TCP_CLOSE_WAIT → TCP_LAST_ACK → TCP_CLOSE
                                             → TCP_FIN_WAIT1  → TCP_FIN_WAIT2 → TCP_TIME_WAIT
```

**دعم SOCKS5** (لتوجيه الاتصالات عبر بروكسي):
```
SOCKS5_NONE → SOCKS5_HELLO → SOCKS5_AUTH → SOCKS5_CONNECT → SOCKS5_CONNECTED
```

**الوظائف الرئيسية:**
- **`handle_tcp`**: يُعالج الحزم الواردة ويُدير الاتصال.
- **`check_tcp_socket`**: يُراقب بيانات epoll على المقبس ويُعيد البيانات إلى TUN.
- **`write_syn_ack`**, **`write_ack`**, **`write_fin_ack`**, **`write_rst`**: تُرسل حزم TCP التحكمية.
- **`queue_tcp`**: يضع البيانات في قائمة انتظار لإعادة التجميع.
- **`open_tcp_socket`**: يفتح اتصالاً خارجياً (مباشراً أو عبر SOCKS5).

---

### `udp.c` — معالجة UDP

- **`handle_udp`**: يُعالج حزم UDP الواردة، يُنشئ جلسات جديدة أو يُضيف إلى جلسات قائمة.
- **`check_udp_socket`**: يُراقب الردود الواردة من الخوادم الخارجية ويُعيدها إلى TUN.
- **`block_udp`**: يُسجل جلسات UDP المحجوبة لتجنب معالجة الحزم اللاحقة.
- **`has_udp_session`**: يتحقق من وجود جلسة UDP نشطة لحزمة معينة.

يدعم إعادة توجيه DNS (`fwd53`) لاعتراض طلبات DNS وتحويلها.

---

### `icmp.c` — معالجة ICMP

- **`handle_icmp`**: يُنشئ مقباساً خاماً (RAW socket) لإعادة توجيه حزم ICMP/ICMPv6.
- **`check_icmp_socket`**: يستقبل ردود ICMP ويُعيدها عبر TUN.
- **`open_icmp_socket`**: يفتح مقباساً خاماً لبروتوكول ICMP مع الحماية من تكرار مسار VPN.

---

### `dns.c` — تحليل DNS

- **`parse_dns_response`**: يُحلل استجابات DNS ليستخرج:
  - سجلات **A** (IPv4)
  - سجلات **AAAA** (IPv6)
  - سجلات **SVCB/HTTPS** (البروتوكولات الحديثة)
  - يُبلّغ Java بأسماء النطاقات المحلولة عبر `dns_resolved`.
- **`get_qname`**: يُحلل اسم النطاق (QNAME) من البيانات الثنائية مع دعم ضغط الرسائل.

---

### `dhcp.c` — اكتشاف DHCP

- **`check_dhcp`**: يكتشف حزم DHCP على المنفذ 67 ويُسجلها بدون معالجة فعلية.

---

### `tls.c` — استخراج SNI من TLS

- **`get_sni`**: يُحلل رسالة **TLS ClientHello** لاستخراج اسم الخادم (SNI — Server Name Indication) من الامتداد `server_name` (النوع 0).

يدعم:
- TLS 1.0 – 1.3
- التحقق من المعرف `TLS_HANDSHAKE_RECORD (22)` ونوع الرسالة `CLIENT_HELLO (1)`
- التحقق من الأطوال للحماية من تجاوز المخزن

---

### `pcap.c` — التقاط حركة الشبكة

- **`write_pcap_hdr`**: يكتب رأس ملف PCAP عند فتحه لأول مرة.
- **`write_pcap_rec`**: يكتب سجل حزمة بطابع زمني دقيق.
- **`write_pcap`**: دالة كتابة ذرية (Atomic write) للملف.

المتغيرات القابلة للتكوين:
```c
size_t pcap_record_size = 64;          // بايت لكل سجل
long   pcap_file_size   = 2 * 1024 * 1024; // الحجم الأقصى للملف (2 MB)
```

---

### `util.c` — الدوال المساعدة

| الدالة | الوصف |
|--------|-------|
| `calc_checksum` | حساب مجموع التحقق لـ IP/TCP/UDP/ICMP |
| `hex2bytes` | تحويل سلسلة hex إلى مصفوفة بايت |
| `char2nibble` | تحويل حرف hex إلى قيمة رقمية |
| `get_ms` | الوقت الحالي بالميلي ثانية |
| `is_readable` / `is_writable` | فحص جاهزية واصف الملف |
| `strstate` | تحويل حالة TCP إلى نص قابل للقراءة |
| `hex` | تحويل بيانات ثنائية إلى تمثيل hex للتصحيح |
| `log_android` | تسجيل الرسائل عبر `__android_log_print` |
| `jniGlobalRef` | إنشاء مرجع JNI عالمي |
| `jniFindClass` | البحث عن فئة Java مع معالجة الأخطاء |
| `jniGetMethodID` | الحصول على معرف طريقة Java |
| `jniNewObject` | إنشاء كائن Java جديد |
| `sdk_int` | الحصول على إصدار Android SDK |
| `ng_malloc` / `ng_calloc` / `ng_realloc` / `ng_free` | إدارة الذاكرة مع تتبع التسريبات (عند تفعيل `PROFILE_MEMORY`) |

---

## المعمارية والتدفق

```
┌─────────────────────────────────────────────────────┐
│                  تطبيق Android (Java)                │
│  ServiceSinkhole ──── JNI ────► netguard.c           │
│       │                              │               │
│  is_address_allowed ◄──────── create_packet          │
│  dns_resolved       ◄──────── parse_dns_response     │
│  log_packet         ◄──────── IP/TCP/UDP events      │
└─────────────────────────────────────────────────────┘
                         │
               واجهة TUN (VPN)
                         │
┌─────────────────────────────────────────────────────┐
│              حلقة الأحداث (session.c)                │
│                   epoll_wait                         │
│         ┌──────────┴──────────┐                     │
│    TUN_IN                  SOCKET_IN                 │
│         │                      │                    │
│    handle_ip (ip.c)        check_tcp_socket          │
│    ┌────┼────┐             check_udp_socket           │
│  TCP   UDP  ICMP           check_icmp_socket          │
│  (tcp.c)(udp.c)(icmp.c)                              │
│         │                      │                    │
│    open socket ───────► الإنترنت/الشبكة             │
└─────────────────────────────────────────────────────┘
```

### تدفق حزمة TCP نموذجية:

1. التطبيق يرسل حزمة TCP → TUN
2. `handle_events` يكتشف EPOLLIN على TUN
3. `check_tun` يقرأ الحزمة → `handle_ip`
4. `handle_ip` يستخرج UID من `/proc/net/tcp`، يستخرج SNI إذا كانت TLS
5. يستدعي `is_address_allowed` عبر JNI ← Java تُقرر السماح/الحجب
6. إذا مسموح: `handle_tcp` ينشئ جلسة جديدة أو يُتابع قائمة
7. `open_tcp_socket` يفتح اتصالاً بالخادم الوجهة (مباشر أو SOCKS5)
8. `check_tcp_socket` يُعيد بيانات الخادم إلى التطبيق عبر TUN

---

## تكوين البناء

```cmake
cmake_minimum_required(VERSION 3.4.1)
project(netguard)

add_library(netguard SHARED [...ملفات المصدر...])
include_directories(src/main/jni/netguard/)
find_library(log-lib log)
target_link_libraries(netguard ${log-lib})
target_link_options(netguard PRIVATE "-Wl,-z,max-page-size=16384")
```

**المتطلبات:**
- Android NDK
- CMake ≥ 3.4.1

---

## الاعتماديات

| المكتبة | الاستخدام |
|---------|-----------|
| `liblog` (Android NDK) | `__android_log_print` للتسجيل |
| `jni.h` (Android NDK) | واجهة JNI مع Java |
| مقابس POSIX | TCP/UDP/ICMP النقل الشبكي |
| `epoll` (Linux) | مراقبة الأحداث غير المتزامن |
| `/proc/net/` (Linux) | البحث عن UID التطبيق |

---

## الملاحظات والتحسينات المحتملة

1. **IPv6 Checksum**: يحتوي الكود على تعليق `// TODO checksum (IPv6)` في معالجة UDP، مما يعني أن مجموع التحقق لـ UDP/IPv6 غير مُتحقق منه حالياً.
2. **ذاكرة التخزين المؤقت لـ UID** (`uid_cache`): تنمو دون حد أقصى محدد وتستند إلى انتهاء الوقت فقط للتنظيف.
3. **تحليل DNS**: لا يدعم حالياً سجلات CNAME المتسلسلة بشكل كامل.
4. **PCAP**: حجم ملف PCAP محدود بـ 2 MB، وعند الوصول للحد يُوقف التسجيل.
