#include <WiFi.h>
#include <WiFiUdp.h>
#include "esp_system.h"
#include "mbedtls/aes.h"
#include "mbedtls/md.h"

// Node 2: receiver + verifier.
const char *WIFI_SSID = "İbrahim ayfonu";
const char *WIFI_PASS = "ibo123456";

const uint16_t UDP_PORT = 4210;
const uint8_t MAGIC = 0x53;
const uint8_t VERSION = 1;
const uint8_t MODE_INSECURE = 0;
const uint8_t MODE_SECURE = 1;
const uint8_t MODE_HELLO = 2;
const uint8_t MODE_HELLO_ACK = 3;
const size_t HEADER_LEN = 22;
const size_t TAG_LEN = 32;
const size_t MAX_PACKET = 512;
const uint8_t LOCK_LED_PIN = 8; // ESP32-C6 DevKitC-1 onboard RGB LED data pin.

const uint8_t MASTER_KEY[32] = {
  0x72, 0x11, 0xd4, 0x09, 0x4a, 0xee, 0x33, 0x80,
  0x19, 0xa2, 0x5b, 0xc6, 0x7f, 0x0d, 0x91, 0x6a,
  0xe5, 0x28, 0x3c, 0xfa, 0x44, 0xbb, 0x10, 0x09,
  0x63, 0x8e, 0x2d, 0x70, 0x51, 0xc4, 0xaf, 0x12
};

WiFiUDP udp;
uint8_t packet[MAX_PACKET];
uint8_t plaintext[MAX_PACKET];
uint8_t clientNonce[12];
uint8_t serverNonce[12];
uint8_t sessionAesKey[16];
uint8_t sessionHmacKey[32];
bool sessionReady = false;
uint32_t lastAcceptedSecureSeq = 0;
bool secureMode = false;

uint16_t getU16(const uint8_t *buf) {
  return ((uint16_t)buf[0] << 8) | buf[1];
}

uint32_t getU32(const uint8_t *buf) {
  return ((uint32_t)buf[0] << 24) |
         ((uint32_t)buf[1] << 16) |
         ((uint32_t)buf[2] << 8) |
         buf[3];
}

void putU32(uint8_t *buf, uint32_t value) {
  buf[0] = (value >> 24) & 0xff;
  buf[1] = (value >> 16) & 0xff;
  buf[2] = (value >> 8) & 0xff;
  buf[3] = value & 0xff;
}

void fillRandom(uint8_t *buf, size_t len) {
  for (size_t i = 0; i < len; i += 4) {
    uint32_t r = esp_random();
    for (size_t j = 0; j < 4 && i + j < len; j++) {
      buf[i + j] = (r >> (j * 8)) & 0xff;
    }
  }
}

bool hmacWithKey(const uint8_t *key, size_t keyLen, const uint8_t *data, size_t len, uint8_t *tag) {
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  return info != nullptr && mbedtls_md_hmac(info, key, keyLen, data, len, tag) == 0;
}

bool deriveSessionKeys() {
  uint8_t input[3 + 12 + 12];
  uint8_t digest[32];

  memcpy(input, "ENC", 3);
  memcpy(input + 3, clientNonce, 12);
  memcpy(input + 15, serverNonce, 12);
  if (!hmacWithKey(MASTER_KEY, sizeof(MASTER_KEY), input, sizeof(input), digest)) {
    return false;
  }
  memcpy(sessionAesKey, digest, sizeof(sessionAesKey));

  memcpy(input, "MAC", 3);
  if (!hmacWithKey(MASTER_KEY, sizeof(MASTER_KEY), input, sizeof(input), sessionHmacKey)) {
    return false;
  }

  sessionReady = true;
  lastAcceptedSecureSeq = 0;
  return true;
}

bool aesCtrCrypt(const uint8_t *input, uint8_t *output, size_t len, const uint8_t *nonce12) {
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);

  uint8_t nonceCounter[16] = {0};
  uint8_t streamBlock[16] = {0};
  size_t ncOff = 0;
  memcpy(nonceCounter, nonce12, 12);

  int rc = mbedtls_aes_setkey_enc(&aes, sessionAesKey, 128);
  if (rc == 0) {
    rc = mbedtls_aes_crypt_ctr(&aes, len, &ncOff, nonceCounter, streamBlock, input, output);
  }

  mbedtls_aes_free(&aes);
  return rc == 0;
}

bool constantTimeEqual(const uint8_t *a, const uint8_t *b, size_t len) {
  uint8_t diff = 0;
  for (size_t i = 0; i < len; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

void printHexPreview(const uint8_t *data, size_t len) {
  const size_t previewLen = min(len, (size_t)24);
  for (size_t i = 0; i < previewLen; i++) {
    if (data[i] < 16) {
      Serial.print("0");
    }
    Serial.print(data[i], HEX);
    Serial.print(" ");
  }
  if (len > previewLen) {
    Serial.print("...");
  }
}

void printMode() {
  Serial.print("DEVICE MODE: ");
  Serial.println(secureMode ? "SECURE_MODE (plaintext commands rejected)" : "INSECURE_MODE (plaintext commands accepted)");
}

void printHelp() {
  Serial.println();
  Serial.println("Node 2 mode commands:");
  Serial.println("  0 -> INSECURE_MODE: plaintext OPEN_LOCK accepted");
  Serial.println("  1 -> SECURE_MODE: only handshake + HMAC verified packets accepted");
  Serial.println("  h -> help/status");
  printMode();
}

void applyLockCommand(const char *message, bool secure) {
  if (strncmp(message, "OPEN_LOCK", 9) == 0) {
    neopixelWrite(LOCK_LED_PIN, 0, 40, 0);
    Serial.print("LOCK ACTION: OPEN accepted via ");
    Serial.println(secure ? "SECURE channel" : "INSECURE channel");
  } else if (strncmp(message, "CLOSE_LOCK", 10) == 0) {
    neopixelWrite(LOCK_LED_PIN, 0, 0, 0);
    Serial.print("LOCK ACTION: CLOSE accepted via ");
    Serial.println(secure ? "SECURE channel" : "INSECURE channel");
  } else {
    Serial.println("LOCK ACTION: no actuator command in payload");
  }
}

void sendHelloAck(IPAddress remoteIp, uint16_t remotePort, uint32_t seq) {
  uint8_t ack[HEADER_LEN] = {0};
  ack[0] = MAGIC;
  ack[1] = VERSION;
  ack[2] = MODE_HELLO_ACK;
  putU32(ack + 4, seq);
  memcpy(ack + 8, serverNonce, 12);

  udp.beginPacket(remoteIp, remotePort);
  udp.write(ack, sizeof(ack));
  udp.endPacket();
}

void handleHello(size_t len, IPAddress remoteIp, uint16_t remotePort) {
  if (len != HEADER_LEN) {
    Serial.println("REJECT: bad HELLO length");
    return;
  }

  uint32_t seq = getU32(packet + 4);
  memcpy(clientNonce, packet + 8, 12);
  fillRandom(serverNonce, sizeof(serverNonce));

  uint32_t t0 = micros();
  if (!deriveSessionKeys()) {
    Serial.println("SESSION FAILED: key derivation error");
    return;
  }
  uint32_t deriveUs = micros() - t0;

  sendHelloAck(remoteIp, remotePort, seq);
  Serial.print("SESSION READY with ");
  Serial.print(remoteIp);
  Serial.print(" deriveUs=");
  Serial.println(deriveUs);
}

void handleData(size_t len, IPAddress remoteIp, uint16_t remotePort) {
  uint32_t packetStart = micros();
  const uint8_t mode = packet[2];
  const uint32_t seq = getU32(packet + 4);
  const uint16_t payloadLen = getU16(packet + 20);

  Serial.println();
  Serial.print("Packet from ");
  Serial.print(remoteIp);
  Serial.print(":");
  Serial.print(remotePort);
  Serial.print(" bytes=");
  Serial.println(len);

  Serial.print("mode=");
  Serial.print(mode == MODE_SECURE ? "SECURE" : "INSECURE");
  Serial.print(" seq=");
  Serial.print(seq);
  Serial.print(" payloadLen=");
  Serial.println(payloadLen);

  if (mode == MODE_INSECURE) {
    if (secureMode) {
      Serial.println("REJECT: plaintext command blocked because device is in SECURE_MODE");
      Serial.println("LOCK ACTION: unchanged");
      return;
    }
    if (HEADER_LEN + payloadLen != len) {
      Serial.println("REJECT: insecure length mismatch");
      return;
    }
    memcpy(plaintext, packet + HEADER_LEN, payloadLen);
    plaintext[payloadLen] = '\0';
    Serial.print("ACCEPT INSECURE plaintext: ");
    Serial.println((char *)plaintext);
    applyLockCommand((char *)plaintext, false);
    Serial.println("Replay/tamper status: not protected");
    Serial.print("METRIC rxProcessUs=");
    Serial.println(micros() - packetStart);
    return;
  }

  if (mode != MODE_SECURE) {
    Serial.println("REJECT: unknown mode");
    return;
  }

  if (!secureMode) {
    Serial.println("REJECT: secure packet received while device is in INSECURE_MODE");
    Serial.println("Switch Node 2 to SECURE_MODE with serial command: 1");
    return;
  }

  if (!sessionReady) {
    Serial.println("REJECT: no session. Run handshake first.");
    return;
  }

  if (HEADER_LEN + payloadLen + TAG_LEN != len) {
    Serial.println("REJECT: secure length mismatch");
    return;
  }

  uint8_t expectedTag[TAG_LEN];
  uint32_t verifyStart = micros();
  if (!hmacWithKey(sessionHmacKey, sizeof(sessionHmacKey), packet, HEADER_LEN + payloadLen, expectedTag)) {
    Serial.println("REJECT: HMAC calculation failed");
    return;
  }
  uint32_t hmacUs = micros() - verifyStart;

  const uint8_t *receivedTag = packet + HEADER_LEN + payloadLen;
  if (!constantTimeEqual(expectedTag, receivedTag, TAG_LEN)) {
    Serial.print("REJECT: HMAC mismatch, ciphertext preview=");
    printHexPreview(packet + HEADER_LEN, payloadLen);
    Serial.println();
    Serial.print("METRIC hmacUs=");
    Serial.println(hmacUs);
    return;
  }

  if (seq <= lastAcceptedSecureSeq) {
    Serial.print("REJECT: replay detected, lastAcceptedSecureSeq=");
    Serial.println(lastAcceptedSecureSeq);
    return;
  }

  uint32_t decryptStart = micros();
  if (!aesCtrCrypt(packet + HEADER_LEN, plaintext, payloadLen, packet + 8)) {
    Serial.println("REJECT: AES decrypt failed");
    return;
  }
  uint32_t decryptUs = micros() - decryptStart;

  plaintext[payloadLen] = '\0';
  lastAcceptedSecureSeq = seq;

  Serial.print("ACCEPT SECURE plaintext: ");
  Serial.println((char *)plaintext);
  applyLockCommand((char *)plaintext, true);
  Serial.print("Ciphertext preview for Wireshark comparison: ");
  printHexPreview(packet + HEADER_LEN, payloadLen);
  Serial.println();
  Serial.print("METRIC hmacUs=");
  Serial.print(hmacUs);
  Serial.print(" decryptUs=");
  Serial.print(decryptUs);
  Serial.print(" rxProcessUs=");
  Serial.println(micros() - packetStart);
}

void handlePacket(size_t len, IPAddress remoteIp, uint16_t remotePort) {
  if (len < HEADER_LEN) {
    Serial.println("REJECT: packet too short");
    return;
  }

  if (packet[0] != MAGIC || packet[1] != VERSION) {
    Serial.println("REJECT: bad magic/version");
    return;
  }

  if (packet[2] == MODE_HELLO) {
    handleHello(len, remoteIp, remotePort);
    return;
  }

  handleData(len, remoteIp, remotePort);
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  neopixelWrite(LOCK_LED_PIN, 0, 0, 0);

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.print("Connecting WiFi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println();
  Serial.print("Node 2 IP: ");
  Serial.println(WiFi.localIP());

  udp.begin(UDP_PORT);
  Serial.print("Listening UDP port ");
  Serial.println(UDP_PORT);
  Serial.println("Wireshark filter: udp.port == 4210");
  printHelp();
}

void loop() {
  if (Serial.available()) {
    char c = Serial.read();
    if (c == '0') {
      secureMode = false;
      sessionReady = false;
      lastAcceptedSecureSeq = 0;
      neopixelWrite(LOCK_LED_PIN, 0, 0, 0);
      Serial.println("Switched to INSECURE_MODE. LED off.");
      printMode();
    } else if (c == '1') {
      secureMode = true;
      sessionReady = false;
      lastAcceptedSecureSeq = 0;
      neopixelWrite(LOCK_LED_PIN, 0, 0, 0);
      Serial.println("Switched to SECURE_MODE. Run Node 1 command k before secure OPEN_LOCK.");
      printMode();
    } else if (c == 'h') {
      printHelp();
    }
  }

  int packetLen = udp.parsePacket();
  if (packetLen <= 0) {
    return;
  }

  if ((size_t)packetLen > sizeof(packet)) {
    Serial.println("REJECT: packet exceeds buffer");
    while (udp.available()) {
      udp.read();
    }
    return;
  }

  int readLen = udp.read(packet, sizeof(packet));
  if (readLen > 0) {
    handlePacket((size_t)readLen, udp.remoteIP(), udp.remotePort());
  }
}
