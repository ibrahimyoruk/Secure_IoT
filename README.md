# ESP32-C6 Secure Communication Demo

Bu proje final demosu icin iki ESP32-C6 DevKitC-1 arasinda UDP tabanli guvenli ve guvensiz haberlesme karsilastirmasi yapar.

## Demo fikri

- Node 1 mesaj gonderir.
- Node 2 mesajlari alir ve seri ekrana kabul/red nedenini yazar.
- Guvensiz modda payload plaintext gider.
- Guvenli moddan once nonce tabanli handshake yapilir.
- Handshake sonrasi iki cihaz `MASTER_KEY`, `clientNonce` ve `serverNonce` ile session AES/HMAC key turetir.
- Guvenli modda payload AES-CTR ile sifrelenir.
- Guvenli modda header + ciphertext uzerinden HMAC-SHA256 uretilir.
- Guvenli modda sequence number eski veya ayniysa replay olarak reddedilir.
- Node 1 seri komutlari ile normal, forged, tamper ve replay paketleri canli gonderilir.
- Laptop attacker scripti ile PC'den forged plaintext/secure/replay denemeleri yapilir.
- Node 2 her PC denemesine UDP cevap doner: `ACCEPTED` veya `BLOCKED` ve sebebi.
- PC tarafinda attack/defense dashboard toplam gonderilen, kabul edilen, bloklanan ve cevapsiz kalan denemeleri sayar.
- Node 2 kritik saldirilarda saldirgan IP/port/sequence bilgisini seri ekrana yazar.
- Kritik saldiri sonrasi Node 2 mevcut session'i gecersiz sayar ve Node 1'e otomatik `REKEY_REQUIRED` alarmi yollar.
- Node 1 bu alarmi alinca otomatik yeni handshake baslatir.
- Iki tarafta da basit performans metrikleri seri ekrana yazilir.

## Dosyalar

- `node_1/node_1/node_1.ino`: sender ve saldiri tetikleme konsolu
- `node_2/node_2/node_2.ino`: receiver, handshake, HMAC dogrulama, decrypt ve replay kontrolu
- `attacker_laptop/attacker.py`: PC'den insecure/secure/replay saldiri denemeleri ve dashboard
- `DEMO_SCRIPT.md`: hocaya gosterilecek canli demo akisi

## Kurulum

1. Arduino IDE'de ESP32 board destegini kur.
2. Board olarak `ESP32C6 Dev Module` veya kullandigin ESP32-C6 DevKitC-1 profilini sec.
3. Iki dosyada da `WIFI_SSID` ve `WIFI_PASS` degerlerini kendi agina gore degistir.
4. Once `node_2/node_2/node_2.ino` dosyasini ikinci karta yukle.
5. Sonra `node_1/node_1/node_1.ino` dosyasini birinci karta yukle.
6. Iki seri monitoru de `115200` baud ile ac.

Not: Node 1 varsayilan olarak `255.255.255.255` broadcast adresine yollar. Ag broadcast'i engellerse Node 2 seri ekraninda yazan IP adresini Node 1'deki `RECEIVER_IP` alanina yaz.

Komut satiri ile derleme icin board kimligi:

```bash
arduino-cli compile --fqbn esp32:esp32:esp32c6 node_1/node_1
arduino-cli compile --fqbn esp32:esp32:esp32c6 node_2/node_2
```

Kart portunu gordukten sonra yukleme ornegi:

```bash
arduino-cli board list
arduino-cli upload -p /dev/cu.usbmodemXXXX --fqbn esp32:esp32:esp32c6 node_1/node_1
arduino-cli upload -p /dev/cu.usbmodemYYYY --fqbn esp32:esp32:esp32c6 node_2/node_2
```

## Node 1 seri komutlari

- `k`: nonce handshake baslatir ve session key turetir
- `i`: guvensiz plaintext paket gonderir
- `o`: guvensiz plaintext close paketi gonderir
- `s`: AES-CTR + HMAC-SHA256 korumali paket gonderir
- `c`: AES-CTR + HMAC-SHA256 korumali close paketi gonderir
- `f`: yanlis HMAC key ile forged paket gonderir
- `r`: son paketi aynen tekrar yollar, yani replay yapar
- `t`: son paketin payload bolgesinde bit cevirip yollar, yani tamper yapar
- `b`: benchmark paketleri gonderir
- `h`: yardim menusu

## Laptop attacker dashboard

PC tarafindan saldiri menusu:

```bash
python3 attacker_laptop/attacker.py
```

Menu:

- `1`: plaintext `OPEN_LOCK` yollar
- `2`: plaintext `CLOSE_LOCK` yollar
- `3`: secure gibi gorunen ama HMAC'i yanlis forged paket yollar
- `4`: UDP broadcast paketlerini dinler
- `5`: Wireshark'tan alinan UDP payload hex degerini replay eder
- `8`: insecure ve secure mod saldiri setini sirayla calistirir
- `9`: dashboard sayaclarini gosterir
- `10`: dashboard sayaclarini sifirlar

Node 2 her paketten sonra laptopa karar cevabi yollar:

```text
NODE2 BLOCKED PLAINTEXT_IN_SECURE_MODE mode=SECURE session=NOT_READY lock=CLOSED
NODE2 BLOCKED HMAC_MISMATCH mode=SECURE session=NOT_READY lock=CLOSED
NODE2 ACCEPTED INSECURE_COMMAND mode=INSECURE session=NOT_READY lock=OPEN
```

Sunumdaki mesaj: guvensiz modda PC komutu kilidi acabilir, guvenli modda ayni PC denemesi cihaz tarafindan gerekcesiyle bloklanir.

Kritik saldirida Node 2 seri monitorunde beklenen alarm:

```text
!!! SECURITY ALERT !!!
attackNo=1 attacker=172.20.10.3:53421 reason=HMAC_MISMATCH mode=SECURE seq=9001 bytes=72
DEFENSE ACTION: session invalidated, re-handshake required
DEFENSE: rekey request sent to trusted peer 172.20.10.4:4210
```

Node 1 seri monitorunde beklenen otomatik savunma:

```text
DEFENSE ALERT FROM NODE2: NODE2_ALERT REKEY_REQUIRED reason=HMAC_MISMATCH attacker=172.20.10.3
AUTO ACTION: starting new handshake
HELLO sent, bytes=22
SESSION READY, ackSeq=...
```

## Wireshark

Filtre:

```text
udp.port == 4210
```

Gosterilecek noktalar:

1. `i` komutundan sonra Wireshark packet bytes/UDP payload kisminda `Node1 sicaklik...` metni okunur.
2. `k` komutundan sonra iki kisa handshake paketi gorulur: HELLO ve HELLO_ACK.
3. `s` komutundan sonra payload okunamaz; sadece rastgele gorunen ciphertext gorulur.
4. `s` ardindan `t` yapilinca Node 2 `REJECT: HMAC mismatch` yazar.
5. `s` ardindan `r` yapilinca Node 2 `REJECT: replay detected` yazar.
6. `f` yapilinca Node 2 `REJECT: HMAC mismatch` yazar; bu kimlik dogrulama demosudur.

## Paket formati

| Alan | Boyut | Aciklama |
| --- | ---: | --- |
| magic | 1 byte | `0x53` |
| version | 1 byte | `1` |
| mode | 1 byte | `0=insecure`, `1=secure`, `2=hello`, `3=hello_ack` |
| reserved | 1 byte | ayrildi |
| sequence number | 4 byte | replay onleme veya handshake id |
| nonce | 12 byte | data paketinde AES-CTR nonce, handshake paketinde client/server nonce |
| payload length | 2 byte | payload boyutu |
| payload | degisken | plaintext veya ciphertext |
| hmac tag | 32 byte | sadece secure modda |

## Session key turetme

Demo statik `MASTER_KEY` ile baslar; bu anahtar cihaz provisioning anahtari gibi dusunulur. Her oturumda:

1. Node 1 `clientNonce` uretir ve `HELLO` yollar.
2. Node 2 `serverNonce` uretir ve `HELLO_ACK` yollar.
3. Iki taraf da su mantikla oturum anahtarlari turetir:

```text
sessionAesKey  = HMAC-SHA256(MASTER_KEY, "ENC" || clientNonce || serverNonce)[0..15]
sessionHmacKey = HMAC-SHA256(MASTER_KEY, "MAC" || clientNonce || serverNonce)
```

Bu sayede her calismada farkli AES/HMAC key kullanilir.

## Performans metrikleri

Seri ekranda su tip satirlar gorulur:

```text
METRIC txSize=93 buildCryptoUs=...
METRIC hmacUs=... decryptUs=... rxProcessUs=...
SESSION READY ... deriveUs=...
```

## Sinirlar

Bu demo `MASTER_KEY` degerini kod icinde tutar. Gercek urunde master key cihaza guvenli provision edilmeli, nonce tekrar kullanimi kalici sayacla garanti edilmeli ve daha gelismis pencere tabanli replay kontrolu eklenmelidir.
