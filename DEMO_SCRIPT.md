# Final Demo Akisi

## Hazirlik

- Iki ESP32-C6 ayni Wi-Fi agina bagli olmali.
- Node 1 ve Node 2 seri monitorleri 115200 baud ile acik olmali.
- Wireshark'ta aktif Wi-Fi arayuzu dinlenmeli.
- Wireshark filtresi:

```text
udp.port == 4210
```

## 1. Guvensiz haberlesme

Node 1 seri monitorunde:

```text
i
```

Beklenen Node 2 ciktisi:

```text
ACCEPT INSECURE plaintext: Node1 sicaklik=24.7C batarya=91% ...
Replay/tamper status: not protected
METRIC rxProcessUs=...
```

Anlatim:

> Bu kisimda klasik UDP payload plaintext olarak gidiyor. Wireshark uzerinden uygulama verisi dogrudan okunabiliyor.

Wireshark'ta paketin byte alaninda `Node1 sicaklik` metnini goster.

## 2. Session key handshake

Node 1 seri monitorunde:

```text
k
```

Beklenen Node 1 ciktisi:

```text
HELLO sent, bytes=22
SESSION READY, ackSeq=... AES/HMAC keys derived from nonce1||nonce2
```

Beklenen Node 2 ciktisi:

```text
SESSION READY with 192.168.x.x deriveUs=...
```

Anlatim:

> Burada statik master key dogrudan veri sifrelemek icin kullanilmiyor. Iki cihaz nonce degisimi yapiyor ve bu oturum icin ayri AES/HMAC anahtarlari turetiyor.

## 3. Guvenli haberlesme

Node 1 seri monitorunde:

```text
s
```

Beklenen Node 2 ciktisi:

```text
ACCEPT SECURE plaintext: Node1 sicaklik=24.7C batarya=91% ...
Ciphertext preview for Wireshark comparison: ...
METRIC hmacUs=... decryptUs=... rxProcessUs=...
```

Anlatim:

> Bu pakette payload AES-CTR ile sifreli. HMAC-SHA256 header ve ciphertext uzerinden hesaplandigi icin hem butunluk hem de anahtari bilen cihazdan geldigine dair kimlik dogrulama sagliyor.

Wireshark'ta UDP payload'in okunabilir metin olmadigini goster.

## 4. Tampering saldirisi

Once guvenli paket gonderildiginden emin ol. Sonra Node 1 seri monitorunde:

```text
t
```

Beklenen Node 2 ciktisi:

```text
REJECT: HMAC mismatch
```

Anlatim:

> Saldirgan pakette tek bit bile degistirse HMAC dogrulamasi bozuluyor. Node 2 decrypt etmeye gecmeden paketi reddediyor.

## 5. Replay saldirisi

Once guvenli paket gonderildiginden emin ol. Sonra Node 1 seri monitorunde:

```text
r
```

Beklenen Node 2 ciktisi:

```text
REJECT: replay detected
```

Anlatim:

> HMAC paketin gercek oldugunu dogrulasa bile eski sequence number tekrar geldiginde Node 2 bunu replay olarak reddediyor.

## 6. Forged packet / authentication saldirisi

Node 1 seri monitorunde:

```text
f
```

Beklenen Node 2 ciktisi:

```text
REJECT: HMAC mismatch
```

Anlatim:

> Bu kez paket bozulmus degil; saldirgan yanlis anahtarla yeni paket uretmeye calisiyor. Node 2 ayni session HMAC key'e sahip olmadigi icin paketi kimlik dogrulamadan reddediyor.

## 7. Performans karsilastirmasi

Node 1 ve Node 2 seri ekranindaki `METRIC` satirlarini goster.

Anlatim:

> Guvenli modda paket boyutu HMAC tag nedeniyle artiyor ve kripto islemleri mikro saniye seviyesinde ek maliyet getiriyor. Bu maliyeti guvensiz ve guvenli paketler uzerinden karsilastiriyorum.

## Kapanis cumlesi

> Bu demo resource-constrained iki ESP32-C6 uzerinde hafif bir guvenli haberlesme katmani gosteriyor. Nonce handshake ile session key turetildi, AES gizlilik, HMAC-SHA256 butunluk ve kimlik dogrulama, sequence number ise replay saldirisi onleme icin kullanildi. Wireshark ile guvensiz ve guvenli trafik arasindaki fark canli olarak dogrulandi.
