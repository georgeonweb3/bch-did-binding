# BCH <-> Nostr Identity Binding — Decentralized Identity bounty PoC

**Hook:** one person, two chains of identity, zero trusted parties — prove you own a Bitcoin Cash address and a Nostr pubkey with two signatures that point at each other.

## What it proves

A BCH address and a Nostr pubkey belong to the same person when:

1. The BCH key signs the message `bch-nostr-binding:<nostr_pubkey_hex>` in standard Bitcoin signed-message format. Anyone can recover the signer pubkey from the signature and check it owns the claimed BCH address.
2. The Nostr key signs a Nostr event (kind 1) whose content carries that BCH address and the BCH signature, tagged `["bch", "<address>"]`.

`verifyBinding()` passes only when **both** directions check out. Forging either half requires the other key. No server, no registry, no Paytaca account, no on-chain transaction — the binding is pure cryptography, verifiable offline by anyone holding the four values (BCH address, Nostr pubkey, BCH signature, Nostr event).

## Run it

```sh
npm install
node demo.mjs
```

Expected: `8 passed, 0 failed.` — the valid binding verifies, and all six tamper cases fail: wrong BCH address, wrong Nostr pubkey, BCH signature from another key, tampered Nostr event content, Nostr event from another key, garbage signature.

## Files

- `src/bind.js` — `newBchIdentity`, `newNostrIdentity`, `bchSignBinding`, `bchVerifyBinding`, `nostrAttest`, `createBinding`, `verifyBinding`.
- `demo.mjs` — end-to-end demo + negative test suite.

Dependencies: `nostr-tools`, `@noble/curves`, `@noble/hashes`, `cashaddrjs`. All local crypto; no network, no wallet, no relay needed for verification.

## What it is not (yet)

- Publishing the attestation event to Nostr relays is the obvious next step (one `relay.publish(event)` call); verification as written works off a relay too, since `verifyEvent` needs no network.
- A dedicated Nostr event kind for identity attestations (instead of kind 1 + JSON content) would be cleaner for wallets to index; kind 1 was chosen for the PoC because every client already renders it.
- This binds *keys*, not real-world identity — it is self-sovereign in exactly the sense the bounty asks: cryptographic linkage, not KYC.

## Bounty fit

BCH BLAZE 2026 — Decentralized Identity, $500 PUSD (Paytaca): "Build a proof of concept for self-sovereign identity that cryptographically links Bitcoin Cash and Nostr identities." This is that PoC, with a runnable demo and a negative test suite as the quantified proof (8/8 checks).
