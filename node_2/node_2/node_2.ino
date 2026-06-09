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
bool lockOpen = false;
IPAddress trustedPeerIp;
uint16_t trustedPeerPort = UDP_PORT;
bool trustedPeerKnown = false;
uint32_t attackCounter = 0;

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

void sendDecision(IPAddress remoteIp, uint16_t remotePort, const char *status, const char *reason) {
  char response[128];
  snprintf(response, sizeof(response), "NODE2 %s %s mode=%s session=%s lock=%s",
           status,
           reason,
           secureMode ? "SECURE" : "INSECURE",
           sessionReady ? "READY" : "NOT_READY",
           lockOpen ? "OPEN" : "CLOSED");
  udp.beginPacket(remoteIp, remotePort);
  udp.write((const uint8_t *)response, strlen(response));
  udp.endPacket();
}

void rememberTrustedPeer(IPAddress remoteIp, uint16_t remotePort) {
  trustedPeerIp = remoteIp;
  trustedPeerPort = remotePort;
  trustedPeerKnown = true;
}

void sendRekeyRequestToTrustedPeer(const char *reason, IPAddress attackerIp) {
  if (!trustedPeerKnown) {
    Serial.println("DEFENSE: trusted peer unknown, cannot request automatic rekey");
    return;
  }

  char alert[128];
  snprintf(alert, sizeof(alert), "NODE2_ALERT REKEY_REQUIRED reason=%s attacker=%u.%u.%u.%u",
           reason,
           attackerIp[0], attackerIp[1], attackerIp[2], attackerIp[3]);
  udp.beginPacket(trustedPeerIp, trustedPeerPort);
  udp.write((const uint8_t *)alert, strlen(alert));
  udp.endPacket();
  Serial.print("DEFENSE: rekey request sent to trusted peer ");
  Serial.print(trustedPeerIp);
  Serial.print(":");
  Serial.println(trustedPeerPort);
}

void logAttackAndRekey(IPAddress remoteIp, uint16_t remotePort, const char *reason, uint8_t mode, uint32_t seq, size_t len) {
  attackCounter++;
  Serial.println();
  Serial.println("!!! SECURITY ALERT !!!");
  Serial.print("attackNo=");
  Serial.print(attackCounter);
  Serial.print(" attacker=");
  Serial.print(remoteIp);
  Serial.print(":");
  Serial.print(remotePort);
  Serial.print(" reason=");
  Serial.print(reason);
  Serial.print(" mode=");
  Serial.print(mode == MODE_SECURE ? "SECURE" : (mode == MODE_INSECURE ? "INSECURE" : "OTHER"));
  Serial.print(" seq=");
  Serial.print(seq);
  Serial.print(" bytes=");
  Serial.println(len);
  Serial.println("DEFENSE ACTION: session invalidated, re-handshake required");

  sessionReady = false;
  lastAcceptedSecureSeq = 0;
  sendRekeyRequestToTrustedPeer(reason, remoteIp);
}

void setRgb(uint8_t red, uint8_t green, uint8_t blue) {
  neopixelWrite(LOCK_LED_PIN, red, green, blue);
}

void showIdleStatus() {
  if (lockOpen) {
    setRgb(0, 40, 0);        // Green: lock open.
  } else if (secureMode) {
    setRgb(0, 0, 35);        // Blue: secure mode ready/closed.
  } else {
    setRgb(35, 25, 0);       // Yellow: insecure mode/closed.
  }
}

void flashRejected() {
  setRgb(45, 0, 0);          // Red: blocked attack or rejected packet.
  delay(250);
  showIdleStatus();
}

void printMode() {
  Serial.print("DEVICE MODE: ");
  Serial.println(secureMode ? "SECURE_MODE (plaintext commands rejected)" : "INSECURE_MODE (plaintext commands accepted)");
  Serial.print("SESSION: ");
  Serial.println(sessionReady ? "READY" : "NOT_READY");
  Serial.print("LOCK: ");
  Serial.println(lockOpen ? "OPEN" : "CLOSED");
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
    lockOpen = true;
    showIdleStatus();
    Serial.print("LOCK ACTION: OPEN accepted via ");
    Serial.println(secure ? "SECURE channel" : "INSECURE channel");
  } else if (strncmp(message, "CLOSE_LOCK", 10) == 0) {
    lockOpen = false;
    showIdleStatus();
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
    sendDecision(remoteIp, remotePort, "BLOCKED", "BAD_HELLO_LENGTH");
    flashRejected();
    return;
  }

  uint32_t seq = getU32(packet + 4);
  rememberTrustedPeer(remoteIp, remotePort);
  memcpy(clientNonce, packet + 8, 12);
  fillRandom(serverNonce, sizeof(serverNonce));

  uint32_t t0 = micros();
  if (!deriveSessionKeys()) {
    Serial.println("SESSION FAILED: key derivation error");
    sendDecision(remoteIp, remotePort, "BLOCKED", "KEY_DERIVATION_FAILED");
    flashRejected();
    return;
  }
  uint32_t deriveUs = micros() - t0;

  sendHelloAck(remoteIp, remotePort, seq);
  Serial.print("SESSION READY with ");
  Serial.print(remoteIp);
  Serial.print(" deriveUs=");
  Serial.println(deriveUs);
  sendDecision(remoteIp, remotePort, "ACCEPTED", "SESSION_READY");
  showIdleStatus();
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
      logAttackAndRekey(remoteIp, remotePort, "PLAINTEXT_IN_SECURE_MODE", mode, seq, len);
      sendDecision(remoteIp, remotePort, "BLOCKED", "PLAINTEXT_IN_SECURE_MODE");
      flashRejected();
      return;
    }
    if (HEADER_LEN + payloadLen != len) {
      Serial.println("REJECT: insecure length mismatch");
      sendDecision(remoteIp, remotePort, "BLOCKED", "INSECURE_LENGTH_MISMATCH");
      flashRejected();
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
    sendDecision(remoteIp, remotePort, "ACCEPTED", "INSECURE_COMMAND");
    return;
  }

  if (mode != MODE_SECURE) {
    Serial.println("REJECT: unknown mode");
    sendDecision(remoteIp, remotePort, "BLOCKED", "UNKNOWN_MODE");
    flashRejected();
    return;
  }

  if (!secureMode) {
    Serial.println("REJECT: secure packet received while device is in INSECURE_MODE");
    Serial.println("Switch Node 2 to SECURE_MODE with serial command: 1");
    sendDecision(remoteIp, remotePort, "BLOCKED", "SECURE_PACKET_IN_INSECURE_MODE");
    flashRejected();
    return;
  }

  if (!sessionReady) {
    Serial.println("REJECT: no session. Run handshake first.");
    logAttackAndRekey(remoteIp, remotePort, "NO_SESSION", mode, seq, len);
    sendDecision(remoteIp, remotePort, "BLOCKED", "NO_SESSION");
    flashRejected();
    return;
  }

  if (HEADER_LEN + payloadLen + TAG_LEN != len) {
    Serial.println("REJECT: secure length mismatch");
    logAttackAndRekey(remoteIp, remotePort, "SECURE_LENGTH_MISMATCH", mode, seq, len);
    sendDecision(remoteIp, remotePort, "BLOCKED", "SECURE_LENGTH_MISMATCH");
    flashRejected();
    return;
  }

  uint8_t expectedTag[TAG_LEN];
  uint32_t verifyStart = micros();
  if (!hmacWithKey(sessionHmacKey, sizeof(sessionHmacKey), packet, HEADER_LEN + payloadLen, expectedTag)) {
    Serial.println("REJECT: HMAC calculation failed");
    logAttackAndRekey(remoteIp, remotePort, "HMAC_CALC_FAILED", mode, seq, len);
    sendDecision(remoteIp, remotePort, "BLOCKED", "HMAC_CALC_FAILED");
    flashRejected();
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
    logAttackAndRekey(remoteIp, remotePort, "HMAC_MISMATCH", mode, seq, len);
    sendDecision(remoteIp, remotePort, "BLOCKED", "HMAC_MISMATCH");
    flashRejected();
    return;
  }

  if (seq <= lastAcceptedSecureSeq) {
    Serial.print("REJECT: replay detected, lastAcceptedSecureSeq=");
    Serial.println(lastAcceptedSecureSeq);
    logAttackAndRekey(remoteIp, remotePort, "REPLAY_DETECTED", mode, seq, len);
    sendDecision(remoteIp, remotePort, "BLOCKED", "REPLAY_DETECTED");
    flashRejected();
    return;
  }

  uint32_t decryptStart = micros();
  if (!aesCtrCrypt(packet + HEADER_LEN, plaintext, payloadLen, packet + 8)) {
    Serial.println("REJECT: AES decrypt failed");
    logAttackAndRekey(remoteIp, remotePort, "AES_DECRYPT_FAILED", mode, seq, len);
    sendDecision(remoteIp, remotePort, "BLOCKED", "AES_DECRYPT_FAILED");
    flashRejected();
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
  sendDecision(remoteIp, remotePort, "ACCEPTED", "SECURE_COMMAND");
}

void handlePacket(size_t len, IPAddress remoteIp, uint16_t remotePort) {
  if (len < HEADER_LEN) {
    Serial.println("REJECT: packet too short");
    sendDecision(remoteIp, remotePort, "BLOCKED", "PACKET_TOO_SHORT");
    flashRejected();
    return;
  }

  if (packet[0] != MAGIC || packet[1] != VERSION) {
    Serial.println("REJECT: bad magic/version");
    sendDecision(remoteIp, remotePort, "BLOCKED", "BAD_MAGIC_VERSION");
    flashRejected();
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
  setRgb(0, 0, 0);

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
  showIdleStatus();
}

void loop() {
  if (Serial.available()) {
    char c = Serial.read();
    if (c == '0') {
      secureMode = false;
      sessionReady = false;
      lastAcceptedSecureSeq = 0;
      lockOpen = false;
      showIdleStatus();
      Serial.println("Switched to INSECURE_MODE. LED off.");
      printMode();
    } else if (c == '1') {
      secureMode = true;
      sessionReady = false;
      lastAcceptedSecureSeq = 0;
      lockOpen = false;
      showIdleStatus();
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
    sendDecision(udp.remoteIP(), udp.remotePort(), "BLOCKED", "PACKET_EXCEEDS_BUFFER");
    flashRejected();
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
