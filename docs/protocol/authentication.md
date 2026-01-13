╔════════════════════════════════════════════════════════╗
║  OURA RING GEN 3 - AUTHENTICATION PROTOCOL SPEC      ║
╚════════════════════════════════════════════════════════╝

Auth Key: 00426ed816dcece48dd9968c1f36c0b5 (16 bytes, from cloud sync)

══════════════════════════════════════════════════════════

STEP 1: GetAuthNonce - Request random nonce from ring
------------------------------------------------------
Phone → Ring: 2f 01 2b (3 bytes)

Ring → Phone: 2f <subcmd> 2c <15-byte-nonce> (18 bytes)
  - Byte 0: 0x2f (tag)
  - Byte 1: <subcmd> (NOT VALIDATED by official app!)
  - Byte 2: 0x2c (extended tag)
  - Bytes 3-17: Random 15-byte nonce

══════════════════════════════════════════════════════════

STEP 2: Encrypt Nonce
---------------------
Algorithm: AES/ECB/PKCS5Padding
  - Input: 15-byte nonce
  - Key: Auth key (16 bytes)
  - Output: 16 bytes (PKCS5 pads 15→16)

══════════════════════════════════════════════════════════

STEP 3: Authenticate - Send encrypted nonce
--------------------------------------------
Phone → Ring: 2f 11 2d <16-byte-encrypted> (19 bytes)
  - Byte 0: 0x2f (tag)
  - Byte 1: 0x11 (subcmd)
  - Byte 2: 0x2d (extended tag)
  - Bytes 3-18: Encrypted nonce (16 bytes)

Ring → Phone: 2f <subcmd> 2e <status> (4 bytes)
  - Byte 0: 0x2f (tag)
  - Byte 1: <subcmd>
  - Byte 2: 0x2e (extended tag)
  - Byte 3: Status code
    * 0x00 = SUCCESS ✅
    * 0x01 = FAILURE ❌

══════════════════════════════════════════════════════════

TEST RESULTS:
  Wrong nonce → Status 0x01 (FAILED) ✅ Confirmed
  Correct nonce → Status 0x00 (SUCCESS) ✅ Expected

══════════════════════════════════════════════════════════
