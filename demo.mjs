// Demo + test suite for the BCH <-> Nostr identity binding PoC.
// Run: node demo.mjs
// Exit 0 only if the valid binding verifies AND every tamper case fails.

import {
  newBchIdentity,
  newNostrIdentity,
  createBinding,
  verifyBinding,
  bchVerifyBinding,
} from './src/bind.js';

let passed = 0;
let failed = 0;
function check(name, cond, extra = '') {
  if (cond) {
    passed++;
    console.log(`  PASS  ${name}`);
  } else {
    failed++;
    console.log(`  FAIL  ${name} ${extra}`);
  }
}

console.log('BCH <-> Nostr identity binding — PoC demo\n');

const bch = newBchIdentity();
const nostr = newNostrIdentity();
console.log(`BCH address : ${bch.cashAddress}`);
console.log(`BCH pubkey  : ${bch.pubkeyHex.slice(0, 20)}...`);
console.log(`Nostr pubkey: ${nostr.pubkey.slice(0, 20)}...\n`);

const binding = createBinding(bch, nostr);
console.log(`BCH signed message: "${binding.message}"`);
console.log(`BCH signature (base64): ${binding.bchSignatureBase64.slice(0, 32)}...`);
console.log(`Nostr event id: ${binding.nostrEvent.id.slice(0, 20)}...\n`);

console.log('Valid binding:');
const good = verifyBinding(binding);
check('full binding verifies', good.ok, JSON.stringify(good));
check(
  'BCH signature alone recovers the claimed address',
  bchVerifyBinding(binding.bchAddress, binding.nostrPubkey, binding.bchSignatureBase64).ok,
);

console.log('\nTamper cases (all must FAIL verification):');
const otherBch = newBchIdentity();
const otherNostr = newNostrIdentity();

// 1. Wrong BCH address claimed.
check(
  'wrong BCH address rejected',
  !verifyBinding({ ...binding, bchAddress: otherBch.cashAddress }).ok,
);
// 2. Wrong Nostr pubkey claimed.
check(
  'wrong Nostr pubkey rejected',
  !verifyBinding({ ...binding, nostrPubkey: otherNostr.pubkey }).ok,
);
// 3. BCH signature made by a different key.
const { signatureBase64: wrongSig } = await import('./src/bind.js').then((m) =>
  m.bchSignBinding(otherBch.privkeyHex, binding.nostrPubkey),
);
check(
  'BCH signature from another key rejected',
  !verifyBinding({ ...binding, bchSignatureBase64: wrongSig }).ok,
);
// 4. Nostr event content tampered (address swapped inside the signed event).
const tamperedEvent = {
  ...binding.nostrEvent,
  content: JSON.stringify({ bch: otherBch.cashAddress, bch_sig: binding.bchSignatureBase64 }),
};
check(
  'tampered Nostr event content rejected',
  !verifyBinding({ ...binding, nostrEvent: tamperedEvent }).ok,
);
// 5. Nostr event signed by a different key.
const { nostrAttest } = await import('./src/bind.js');
const forgedEvent = nostrAttest(otherNostr.secretKeyHex, binding.bchAddress, binding.bchSignatureBase64);
check(
  'Nostr event from another key rejected',
  !verifyBinding({ ...binding, nostrEvent: forgedEvent }).ok,
);
// 6. Garbage signature.
check(
  'garbage BCH signature rejected',
  !verifyBinding({ ...binding, bchSignatureBase64: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==' }).ok,
);

console.log(`\n${passed} passed, ${failed} failed.`);
process.exit(failed === 0 ? 0 : 1);
