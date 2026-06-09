#include <WiFi.h>
#include <WiFiUdp.h>
#include "esp_system.h"
#include "mbedtls/aes.h"
#include "mbedtls/md.h"

// Node 1: sender + attack console.
const char *WIFI_SSID = "İbrahim ayfonu";
const char *WIFI_PASS = "ibo123456";

IPAddress RECEIVER_IP(255, 255, 255, 255);
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

// Demo provisioning key. Session keys are derived from this after nonce exchange.
const uint8_t MASTER_KEY[32] = {
  0x72, 0x11, 0xd4, 0x09, 0x4a, 0xee, 0x33, 0x80,
  0x19, 0xa2, 0x5b, 0xc6, 0x7f, 0x0d, 0x91, 0x6a,
  0xe5, 0x28, 0x3c, 0xfa, 0x44, 0xbb, 0x10, 0x09,
  0x63, 0x8e, 0x2d, 0x70, 0x51, 0xc4, 0xaf, 0x12
};

const uint8_t FORGED_HMAC_KEY[32] = {
  0x10, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
  0x90, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf0, 0x01,
  0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79, 0x8a,
  0x9b, 0xac, 0xbd, 0xce, 0xdf, 0xe1, 0xf2, 0x03
};

WiFiUDP udp;
uint32_t sequenceNumber = 1;
uint32_t handshakeId = 1;
uint8_t clientNonce[12];
uint8_t serverNonce[12];
uint8_t sessionAesKey[16];
uint8_t sessionHmacKey[32];
bool sessionReady = false;

uint8_t lastPacket[MAX_PACKET];
size_t lastPacketLen = 0;

void putU32(uint8_t *buf, uint32_t value) {
  buf[0] = (value >> 24) & 0xff;
  buf[1] = (value >> 16) & 0xff;
  buf[2] = (value >> 8) & 0xff;
  buf[3] = value & 0xff;
}

void putU16(uint8_t *buf, uint16_t value) {
  buf[0] = (value >> 8) & 0xff;
  buf[1] = value & 0xff;
}

uint32_t getU32(const uint8_t *buf) {
  return ((uint32_t)buf[0] << 24) |
         ((uint32_t)buf[1] << 16) |
         ((uint32_t)buf[2] << 8) |
         buf[3];
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
  sequenceNumber = 1;
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

void sendRaw(const uint8_t *packet, size_t len, const char *label) {
  udp.beginPacket(RECEIVER_IP, UDP_PORT);
  udp.write(packet, len);
  udp.endPacket();
  Serial.print(label);
  Serial.print(" sent, bytes=");
  Serial.println(len);
}

void startHandshake() {
  uint8_t packet[HEADER_LEN] = {0};
  fillRandom(clientNonce, sizeof(clientNonce));

  packet[0] = MAGIC;
  packet[1] = VERSION;
  packet[2] = MODE_HELLO;
  putU32(packet + 4, handshakeId++);
  memcpy(packet + 8, clientNonce, 12);

  sessionReady = false;
  sendRaw(packet, sizeof(packet), "HELLO");
}

void handleIncomingHandshake() {
  int packetLen = udp.parsePacket();
  if (packetLen < (int)HEADER_LEN || packetLen > (int)MAX_PACKET) {
    return;
  }

  uint8_t packet[MAX_PACKET];
  int readLen = udp.read(packet, sizeof(packet));
  if (readLen < (int)HEADER_LEN || packet[0] != MAGIC || packet[1] != VERSION) {
    return;
  }

  if (packet[2] != MODE_HELLO_ACK) {
    return;
  }

  memcpy(serverNonce, packet + 8, 12);
  if (!deriveSessionKeys()) {
    Serial.println("SESSION FAILED: key derivation error");
    return;
  }

  Serial.print("SESSION READY, ackSeq=");
  Serial.print(getU32(packet + 4));
  Serial.println(" AES/HMAC keys derived from nonce1||nonce2");
}

size_t buildDataPacket(uint8_t mode, const char *message, bool forged, uint8_t *packet, size_t packetCap, uint32_t *cryptoUs) {
  const size_t messageLen = strlen(message);
  const bool secure = mode == MODE_SECURE;
  const size_t needed = HEADER_LEN + messageLen + (secure ? TAG_LEN : 0);
  if (needed > packetCap || messageLen > 255) {
    Serial.println("Packet too large.");
    return 0;
  }
  if (secure && !sessionReady) {
    Serial.println("No session. Press k first and wait for SESSION READY.");
    return 0;
  }

  uint32_t t0 = micros();
  memset(packet, 0, needed);
  packet[0] = MAGIC;
  packet[1] = VERSION;
  packet[2] = mode;
  putU32(packet + 4, sequenceNumber++);
  fillRandom(packet + 8, 12);
  putU16(packet + 20, messageLen);

  if (secure) {
    if (!aesCtrCrypt((const uint8_t *)message, packet + HEADER_LEN, messageLen, packet + 8)) {
      Serial.println("AES failed.");
      return 0;
    }
    const uint8_t *macKey = forged ? FORGED_HMAC_KEY : sessionHmacKey;
    if (!hmacWithKey(macKey, TAG_LEN, packet, HEADER_LEN + messageLen, packet + HEADER_LEN + messageLen)) {
      Serial.println("HMAC failed.");
      return 0;
    }
  } else {
    memcpy(packet + HEADER_LEN, message, messageLen);
  }

  *cryptoUs = micros() - t0;
  return needed;
}

void sendDemoMessage(uint8_t mode, bool forged, const char *command) {
  char message[96];
  uint32_t cryptoUs = 0;
  uint32_t totalStart = micros();
  snprintf(message, sizeof(message), "%s seq=%lu", command, (unsigned long)sequenceNumber);

  lastPacketLen = buildDataPacket(mode, message, forged, lastPacket, sizeof(lastPacket), &cryptoUs);
  if (lastPacketLen == 0) {
    return;
  }

  sendRaw(lastPacket, lastPacketLen, forged ? "FORGED" : (mode == MODE_SECURE ? "SECURE" : "INSECURE"));
  Serial.print("METRIC txSize=");
  Serial.print(lastPacketLen);
  Serial.print(" buildCryptoUs=");
  Serial.print(cryptoUs);
  Serial.print(" totalUs=");
  Serial.println(micros() - totalStart);
}

void replayLastPacket() {
  if (lastPacketLen == 0) {
    Serial.println("No packet to replay. Send one first.");
    return;
  }
  sendRaw(lastPacket, lastPacketLen, "REPLAY");
}

void tamperLastPacket() {
  if (lastPacketLen == 0) {
    Serial.println("No packet to tamper. Send one first.");
    return;
  }

  uint8_t tampered[MAX_PACKET];
  memcpy(tampered, lastPacket, lastPacketLen);
  tampered[min((size_t)HEADER_LEN + 4, lastPacketLen - 1)] ^= 0x55;
  sendRaw(tampered, lastPacketLen, "TAMPERED");
}

void printHelp() {
  Serial.println();
  Serial.println("Commands:");
  Serial.println("  k -> perform nonce handshake and derive session keys");
  Serial.println("  i -> send insecure OPEN_LOCK plaintext packet");
  Serial.println("  o -> send insecure CLOSE_LOCK plaintext packet");
  Serial.println("  s -> send secure OPEN_LOCK AES-CTR + HMAC-SHA256 packet");
  Serial.println("  c -> send secure CLOSE_LOCK packet");
  Serial.println("  f -> send forged OPEN_LOCK packet with wrong HMAC key");
  Serial.println("  r -> replay the last packet");
  Serial.println("  t -> tamper with the last packet and send it");
  Serial.println("  h -> help");
  Serial.println();
  Serial.println("Wireshark filter: udp.port == 4210");
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.print("Connecting WiFi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println();
  Serial.print("Node 1 IP: ");
  Serial.println(WiFi.localIP());

  udp.begin(UDP_PORT);
  printHelp();
}

void loop() {
  handleIncomingHandshake();

  if (!Serial.available()) {
    return;
  }

  char c = Serial.read();
  if (c == 'k') {
    startHandshake();
  } else if (c == 'i') {
    sendDemoMessage(MODE_INSECURE, false, "OPEN_LOCK");
  } else if (c == 'o') {
    sendDemoMessage(MODE_INSECURE, false, "CLOSE_LOCK");
  } else if (c == 's') {
    sendDemoMessage(MODE_SECURE, false, "OPEN_LOCK");
  } else if (c == 'c') {
    sendDemoMessage(MODE_SECURE, false, "CLOSE_LOCK");
  } else if (c == 'f') {
    sendDemoMessage(MODE_SECURE, true, "OPEN_LOCK");
  } else if (c == 'r') {
    replayLastPacket();
  } else if (c == 't') {
    tamperLastPacket();
  } else if (c == 'h') {
    printHelp();
  }
}
