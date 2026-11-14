// BCH <-> Nostr self-sovereign identity binding (PoC).
// One person proves they control BOTH a Bitcoin Cash key and a Nostr key,
// with no server, no registry, and no trusted third party.
//
// Binding = two signatures, each pointing at the other identity:
//   1. BCH side: the BCH key signs the message
//        "bch-nostr-binding:<nostr_pubkey_hex>"
//      in standard Bitcoin signed-message format. Anyone can recover the
//      signer pubkey from the signature and check it owns the BCH address.
//   2. Nostr side: the Nostr key signs a Nostr event (kind 1) whose
//      content carries the BCH address and the BCH signature, tagged ["bch", addr].
//
// verifyBinding() passes only when both directions check out: the Nostr
// event is genuinely signed by the claimed Nostr key AND contains a BCH
// signature that recovers to the claimed BCH address over the message
// naming that Nostr key. Forging either half requires the other's key.

import { randomBytes } from 'node:crypto';
import { sha256 } from '@noble/hashes/sha2.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { generateSecretKey, getPublicKey, finalizeEvent, verifyEvent } from 'nostr-tools';
import cashaddr from 'cashaddrjs';

export const BINDING_PREFIX = 'bch-nostr-binding:';

// ---------- helpers ----------

function hash160(bytes) {
  return ripemd160(sha256(bytes));
}

function bytesToHex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

function hexToBytes(hex) {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

// Bitcoin signed-message payload: "\x18Bitcoin Signed Message:\n" + varint(len) + message,
// hashed twice with SHA-256.
function signedMessageHash(message) {
  const msg = Buffer.from(message, 'utf8');
  const prefix = Buffer.from('\x18Bitcoin Signed Message:\n', 'latin1');
  const len = msg.length < 253 ? Buffer.from([msg.length]) : Buffer.from([253, msg.length & 0xff, (msg.length >> 8) & 0xff]);
  const payload = Buffer.concat([prefix, len, msg]);
  return sha256(sha256(payload));
}

// ---------- key generation ----------

export function newBchIdentity() {
  const privkey = randomBytes(32);
  const pubkey = secp256k1.getPublicKey(privkey, true); // compressed 33 bytes
  const pkh = hash160(pubkey);
  const cashAddress = cashaddr.encode('bitcoincash', 'P2PKH', pkh);
  return { privkeyHex: bytesToHex(privkey), pubkeyHex: bytesToHex(pubkey), cashAddress };
}

export function newNostrIdentity() {
  const secretKey = generateSecretKey(); // 32 random bytes
  const pubkey = getPublicKey(secretKey); // 32-byte hex
  return { secretKeyHex: bytesToHex(secretKey), pubkey };
}

// ---------- BCH message signing (Bitcoin signed-message format) ----------

export function bchSignBinding(bchPrivkeyHex, nostrPubkeyHex) {
  const message = BINDING_PREFIX + nostrPubkeyHex;
  const hash = signedMessageHash(message);
  const priv = hexToBytes(bchPrivkeyHex);
  const compact = secp256k1.sign(hash, priv, { prehash: false }); // Uint8Array(64), r||s; hash is already the digest
  const pubkey = secp256k1.getPublicKey(priv, true);
  // noble v2 does not return the recovery id; find it by trial (0 or 1).
  const sigObj = secp256k1.Signature.fromBytes(compact);
  let recovery = -1;
  for (const rec of [0, 1]) {
    const recPub = sigObj.addRecoveryBit(rec).recoverPublicKey(hash);
    if (Buffer.from(recPub.toBytes(true)).equals(Buffer.from(pubkey))) {
      recovery = rec;
      break;
    }
  }
  if (recovery < 0) throw new Error('could not determine signature recovery id');
  const out = new Uint8Array(65);
  out[0] = 27 + recovery + 4; // 4 = compressed pubkey
  out.set(compact, 1);
  return { message, signatureBase64: Buffer.from(out).toString('base64') };
}

export function bchVerifyBinding(bchCashAddress, nostrPubkeyHex, signatureBase64) {
  try {
    const compact = new Uint8Array(Buffer.from(signatureBase64, 'base64'));
    if (compact.length !== 65) return { ok: false, reason: 'bad signature length' };
    const header = compact[0];
    if (header < 27 || header > 34) return { ok: false, reason: 'bad signature header' };
    const recovery = (header - 27) & 3;
    const message = BINDING_PREFIX + nostrPubkeyHex;
    const hash = signedMessageHash(message);
    const sig = secp256k1.Signature.fromBytes(compact.slice(1, 65));
    const recovered = sig.addRecoveryBit(recovery).recoverPublicKey(hash).toBytes(true);
    const recoveredAddress = cashaddr.encode('bitcoincash', 'P2PKH', hash160(recovered));
    if (recoveredAddress !== bchCashAddress) {
      return { ok: false, reason: 'recovered address does not match claimed BCH address' };
    }
    return { ok: true, recoveredPubkeyHex: bytesToHex(recovered) };
  } catch (e) {
    return { ok: false, reason: `verify error: ${e.message}` };
  }
}

// ---------- Nostr attestation event ----------

export function nostrAttest(nostrSecretKeyHex, bchCashAddress, bchSignatureBase64) {
  const content = JSON.stringify({ bch: bchCashAddress, bch_sig: bchSignatureBase64 });
  const event = finalizeEvent(
    {
      kind: 1,
      created_at: Math.floor(Date.now() / 1000),
      tags: [['bch', bchCashAddress]],
      content,
    },
    hexToBytes(nostrSecretKeyHex),
  );
  return event;
}

// ---------- full binding ----------

export function createBinding(bchIdentity, nostrIdentity) {
  const { message, signatureBase64 } = bchSignBinding(bchIdentity.privkeyHex, nostrIdentity.pubkey);
  const event = nostrAttest(nostrIdentity.secretKeyHex, bchIdentity.cashAddress, signatureBase64);
  return {
    bchAddress: bchIdentity.cashAddress,
    bchPubkeyHex: bchIdentity.pubkeyHex,
    nostrPubkey: nostrIdentity.pubkey,
    message,
    bchSignatureBase64: signatureBase64,
    nostrEvent: event,
  };
}

export function verifyBinding(binding) {
  const { bchAddress, nostrPubkey, bchSignatureBase64, nostrEvent } = binding;

  // Direction 1: the Nostr event must be genuinely signed by the claimed Nostr key.
  if (!verifyEvent(nostrEvent)) return { ok: false, reason: 'Nostr event signature invalid' };
  if (nostrEvent.pubkey !== nostrPubkey) {
    return { ok: false, reason: 'Nostr event pubkey does not match claimed Nostr pubkey' };
  }

  // The event must carry the claimed BCH address, in tag and in content.
  let content;
  try {
    content = JSON.parse(nostrEvent.content);
  } catch {
    return { ok: false, reason: 'Nostr event content is not valid JSON' };
  }
  const tag = nostrEvent.tags.find((t) => t[0] === 'bch');
  if (!tag || tag[1] !== bchAddress) return { ok: false, reason: 'Nostr event bch tag missing or mismatched' };
  if (content.bch !== bchAddress) return { ok: false, reason: 'Nostr event content bch field mismatched' };
  if (content.bch_sig !== bchSignatureBase64) {
    return { ok: false, reason: 'Nostr event content bch_sig mismatched' };
  }

  // Direction 2: the BCH signature must recover to the claimed BCH address
  // over the message naming the claimed Nostr key.
  const bch = bchVerifyBinding(bchAddress, nostrPubkey, bchSignatureBase64);
  if (!bch.ok) return { ok: false, reason: `BCH side failed: ${bch.reason}` };

  return { ok: true, bchPubkeyHex: bch.recoveredPubkeyHex, nostrPubkey, bchAddress };
}
