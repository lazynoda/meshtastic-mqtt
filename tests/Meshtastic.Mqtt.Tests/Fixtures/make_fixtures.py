#!/usr/bin/env python3
"""Generate the binary ServiceEnvelope fixtures used by the tests and the smoke test.

Deliberately independent of the broker's C# code: protobuf is hand-encoded here and
AES-CTR comes from the `openssl` CLI, so a bug in the broker's crypto cannot hide behind
fixtures produced by the same code.

Wire facts mirrored from meshtastic/firmware:
- 1-byte PSK expansion: src/mesh/Channels.cpp getKey() (index N -> defaultpsk with the
  last byte incremented by N-1).
- Nonce: src/mesh/CryptoEngine.cpp initNonce(): packet id as uint64 LE, then `from` as
  uint32 LE, then 4 zero bytes. AES-CTR over the serialised `Data` message.
- Channel hash: Channels::generateHash(): XOR of the name bytes XOR the XOR of the key.
- Topic: <root>/2/e/<channel_id>/<gateway_id> (src/mqtt/MQTT.cpp onSend()).

Run from this directory: python3 make_fixtures.py
"""
import base64
import os
import subprocess

DEFAULT_PSK = bytes([0xD4, 0xF1, 0xBB, 0x3A, 0x20, 0x29, 0x07, 0x59,
                     0xF0, 0xBC, 0xFF, 0xAB, 0xCF, 0x4E, 0x69, 0x01])
BROADCAST = 0xFFFFFFFF


def expand(psk_b64):
    raw = base64.b64decode(psk_b64, validate=True)
    if len(raw) == 1:
        if raw[0] == 0:
            return b""
        key = bytearray(DEFAULT_PSK)
        key[-1] = (key[-1] + raw[0] - 1) & 0xFF
        return bytes(key)
    if len(raw) == 0 or len(raw) in (16, 32):
        return raw
    return raw.ljust(16 if len(raw) < 16 else 32, b"\0")


def xor_all(data):
    h = 0
    for b in data:
        h ^= b
    return h


def channel_hash(name, key):
    return xor_all(name.encode()) ^ xor_all(key)


def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def f_varint(field, value):
    return varint(field << 3) + varint(value)


def f_bytes(field, value):
    return varint(field << 3 | 2) + varint(len(value)) + value


def f_fixed32(field, value):
    return varint(field << 3 | 5) + value.to_bytes(4, "little")


def data_msg(portnum, payload):
    return f_varint(1, portnum) + f_bytes(2, payload)


def aes_ctr(key, packet_id, sender, plaintext):
    if not key:
        return plaintext
    nonce = packet_id.to_bytes(8, "little") + sender.to_bytes(4, "little") + b"\0" * 4
    cipher = "-aes-128-ctr" if len(key) == 16 else "-aes-256-ctr"
    return subprocess.run(["openssl", "enc", cipher, "-K", key.hex(), "-iv", nonce.hex(), "-nosalt"],
                          input=plaintext, capture_output=True, check=True).stdout


def mesh_packet(sender, to, channel, encrypted, packet_id, hop_limit=3, hop_start=3):
    return (f_fixed32(1, sender) + f_fixed32(2, to) + f_varint(3, channel) + f_bytes(5, encrypted)
            + f_fixed32(6, packet_id) + f_varint(9, hop_limit) + f_varint(15, hop_start))


def envelope(packet, channel_id, gateway_id):
    return f_bytes(1, packet) + f_bytes(2, channel_id.encode()) + f_bytes(3, gateway_id.encode())


def encrypted_envelope(channel, psk_b64, sender, packet_id, portnum, payload, gateway):
    key = expand(psk_b64)
    enc = aes_ctr(key, packet_id, sender, data_msg(portnum, payload))
    pkt = mesh_packet(sender, BROADCAST, channel_hash(channel, key), enc, packet_id)
    return envelope(pkt, channel, gateway)


FIXTURES = {
    # Text messages on the Spanish channels, each with its own key (TEXT_MESSAGE_APP = 1).
    "sfnarrow_aq.bin": encrypted_envelope("SFNarrow", "AQ==", 0x1A2B3C4D, 0x10000001, 1,
                                          b"fixture-payload-sfnarrow", "!1a2b3c4d"),
    "test_ag.bin": encrypted_envelope("Test", "Ag==", 0x1A2B3C4D, 0x10000002, 1,
                                      b"fixture-payload-test", "!1a2b3c4d"),
    "valencia_va.bin": encrypted_envelope("Valencia", "VA==", 0x1A2B3C4D, 0x10000003, 1,
                                          b"fixture-payload-valencia", "!1a2b3c4d"),
    # Channel `test` (lower case) keyed with Ag==. Channel names are case-sensitive (the firmware hashes the
    # exact name), so a broker configured with `Test: Ag==` reads this one with default_psk: undecryptable.
    "test_lower_ag.bin": encrypted_envelope("test", "Ag==", 0x1A2B3C4D, 0x10000004, 1,
                                            b"fixture-payload-test-lower", "!1a2b3c4d"),
    # Channel `test` (lower case) on the default key: a different channel from `Test`, decryptable with AQ==.
    # Used by the integration and smoke tests for the user allowed msh/ES/2/e/test/#.
    "test_lower_aq.bin": encrypted_envelope("test", "AQ==", 0x1A2B3C4D, 0x10000008, 1,
                                            b"fixture-payload-test-lower-aq", "!1a2b3c4d"),
    # A `Test` packet encrypted with the wrong key (AQ== instead of Ag==): must be undecryptable.
    "test_wrong_key_aq.bin": encrypted_envelope("Test", "AQ==", 0x1A2B3C4D, 0x10000005, 1,
                                                b"fixture-payload-wrong-key", "!1a2b3c4d"),
    # A PKI DM as the firmware uplinks it: channel_id "PKI", channel hash 0, unicast, opaque
    # AES-CCM ciphertext + 8-byte tag + 4-byte extra nonce (the broker can never decrypt it).
    "pki_dm.bin": envelope(mesh_packet(0x1A2B3C4D, 0x55667788, 0, bytes(range(1, 41)), 0x10000006),
                           "PKI", "!1a2b3c4d"),
    # Packet carried in plaintext (`decoded` instead of `encrypted`): firmware never uplinks this on /2/e/.
    "plaintext_decoded.bin": envelope(
        f_fixed32(1, 0x1A2B3C4D) + f_fixed32(2, BROADCAST) + f_bytes(4, data_msg(1, b"plain"))
        + f_fixed32(6, 0x10000007), "SFNarrow", "!1a2b3c4d"),
    # Not a protobuf at all.
    "garbage.bin": b"\xff\xff\xff\xff this is not a protobuf \x00\x01\x02",
}

# Real envelope captured from the public mesh (LongFast, default key), taken from the test
# vector in meshtastic/c-sharp Meshtastic.Test/Crypto/PacketCryptoTests.cs. Decrypts to a
# NODEINFO_APP packet whose User.long_name is "Meshtastic 65a4".
REAL_ENC = base64.b64decode("kiDV39nDDsi8AON+Czei6zUpy+F/7E+lyIpicxJR40KXBFmPkqFUEnobI5voQadha+s=")
FIXTURES["longfast_real.bin"] = envelope(
    mesh_packet(4202784164, BROADCAST, 8, REAL_ENC, 1777428186), "LongFast", "!fa8165a4")

if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    for name, blob in FIXTURES.items():
        with open(os.path.join(here, name), "wb") as fh:
            fh.write(blob)
        print(f"{name}: {len(blob)} bytes")
    print("hash LongFast/AQ== =", channel_hash("LongFast", expand("AQ==")), "(real packet carries 8)")
    for psk in ("AQ==", "Ag==", "VA=="):
        print(psk, expand(psk).hex())
