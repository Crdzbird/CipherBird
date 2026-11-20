import { row, mustRefuse, timed } from '../kit.js';
import { same, utf8, flipBit, hex } from '../bytes.js';

const INTERACTIVE = 0;
const SLOT_NAMES = { 0: 'passphrase', 1: 'device', 2: 'hardware' };

function withKeyring(cb, make, fn) {
  const kr = make();
  try {
    return fn(kr);
  } finally {
    cb.call('keyring_free', kr);
  }
}

function slotTypes(cb, kr) {
  const n = cb.call('keyring_slot_count', kr);
  const names = [];
  for (let i = 0; i < n; i++) names.push(SLOT_NAMES[cb.call('keyring_slot_type', kr, i)]);
  return names;
}

export default {
  id: 'keyring',
  title: 'Keyring: one key, many ways in',
  lead: 'A keyring wraps one random master key in slots, each opened by a different factor: a device key, a passphrase or a key held by a secure element. Slots can be added and revoked without changing the master key.',
  demos: [
    {
      id: 'slots',
      title: 'A device slot and a passphrase slot',
      statement: 'The default is one device slot; a passphrase slot adds a way in from another device. Either factor unwraps the same master key, and anything else is refused.',
      inputs: [{ name: 'passphrase', label: 'Passphrase', kind: 'text', value: 'orbit lantern velvet seven' }],
      run(cb, { passphrase }) {
        return withKeyring(cb, () => cb.call('keyring_create'), (kr) => {
          const device = cb.call('random_bytes', 32);
          const added = cb.call('keyring_add_device_slot', kr, device);
          const slow = timed(() => cb.call('keyring_add_passphrase_slot', kr, passphrase, INTERACTIVE));
          const viaDevice = cb.call('keyring_unlock_with_device', kr, device);
          const viaPass = cb.call('keyring_unlock_with_passphrase', kr, passphrase);
          const note = cb.call('xchacha20_encrypt', 'notes, photos and keys', viaDevice, null);
          return [
            row.bytes('Device factor (stand-in for a Keystore or Enclave key)', device),
            row.text('Slots', `${cb.call('keyring_slot_count', kr)}: ${slotTypes(cb, kr).join(', ')}`),
            row.text('Passphrase slot cost', `${slow.ms.toFixed(0)} ms of Argon2id (interactive preset)`),
            row.check('Both slots were added', added === 1 && slow.value === 1, 'returned 1, 1'),
            row.bytes('Master key via the device', viaDevice),
            row.check('The passphrase unwraps the same master key', same(viaDevice, viaPass), 'identical'),
            row.check('Data sealed under the master key opens with either factor',
              utf8.decode(cb.call('xchacha20_decrypt', note, viaPass, null)) === 'notes, photos and keys', 'valid'),
            mustRefuse('A wrong passphrase is refused', () => cb.call('keyring_unlock_with_passphrase', kr, `${passphrase}s`)),
            mustRefuse('Another device key is refused', () => cb.call('keyring_unlock_with_device', kr, cb.call('random_bytes', 32))),
            mustRefuse('A device factor under 32 bytes is refused', () => cb.call('keyring_add_device_slot', kr, cb.call('random_bytes', 16))),
            row.check('An index past the last slot has type -1', cb.call('keyring_slot_type', kr, 9) === -1, '-1'),
          ];
        });
      },
    },
    {
      id: 'envelope',
      title: 'Store the envelope, not the key',
      statement: 'keyring_serialise writes the slots and nothing else; the master key is never in the blob. Read back, the keyring is locked until a factor opens it.',
      inputs: [{ name: 'passphrase', label: 'Passphrase', kind: 'text', value: 'harbor nine copper fields' }],
      run(cb, { passphrase }) {
        const device = cb.call('random_bytes', 32);
        let master;
        const blob = withKeyring(cb, () => cb.call('keyring_create'), (kr) => {
          cb.call('keyring_add_passphrase_slot', kr, passphrase, INTERACTIVE);
          cb.call('keyring_add_device_slot', kr, device);
          master = cb.call('keyring_unlock_with_device', kr, device);
          return cb.call('keyring_serialise', kr);
        });
        return withKeyring(cb, () => cb.call('keyring_deserialise', blob), (kr) => {
          const lockedAdd = cb.call('keyring_add_device_slot', kr, cb.call('random_bytes', 32));
          const back = cb.call('keyring_unlock_with_device', kr, device);
          const again = cb.call('keyring_serialise', kr);
          return [
            row.bytes('Envelope', blob, `${blob.length} bytes`),
            row.text('Magic', utf8.decode(blob.subarray(0, 4))),
            row.check('The master key does not appear in the envelope', !hex(blob).includes(hex(master)), 'not found'),
            row.check('Slots survive the round trip', slotTypes(cb, kr).join(',') === 'passphrase,device', slotTypes(cb, kr).join(', ')),
            row.check('A locked keyring refuses a new slot', lockedAdd === 0, 'returned 0'),
            row.check('The device factor recovers the master key', same(back, master), 'identical'),
            row.check('The passphrase does too', same(cb.call('keyring_unlock_with_passphrase', kr, passphrase), master), 'identical'),
            row.check('Serialised again, the envelope is unchanged', same(again, blob), 'byte for byte'),
            mustRefuse('A flipped bit in the wrapped key is refused', () => withKeyring(cb,
              () => cb.call('keyring_deserialise', flipBit(blob)), (bad) => cb.call('keyring_unlock_with_device', bad, device))),
            mustRefuse('A truncated envelope is refused', () => cb.call('keyring_deserialise', blob.subarray(0, 12))),
          ];
        });
      },
    },
    {
      id: 'revoke',
      title: 'Revoke a lost phone',
      statement: 'Removing a slot means that factor no longer opens the envelope, while every other slot still does and the master key stays the same. A copy saved before the removal still has the slot.',
      inputs: [],
      run(cb) {
        const phone = cb.call('random_bytes', 32);
        const laptop = cb.call('random_bytes', 32);
        const passphrase = 'river stone amber nine';
        return withKeyring(cb, () => cb.call('keyring_create'), (kr) => {
          cb.call('keyring_add_device_slot', kr, phone);
          cb.call('keyring_add_device_slot', kr, laptop);
          cb.call('keyring_add_passphrase_slot', kr, passphrase, INTERACTIVE);
          const master = cb.call('keyring_unlock_with_device', kr, phone);
          const before = cb.call('keyring_serialise', kr);
          const removed = cb.call('keyring_remove_slot', kr, 0);
          const after = cb.call('keyring_serialise', kr);
          return withKeyring(cb, () => cb.call('keyring_deserialise', after), (stored) => {
            const oldCopy = withKeyring(cb, () => cb.call('keyring_deserialise', before),
              (old) => same(cb.call('keyring_unlock_with_device', old, phone), master));
            return [
              row.text('Slots after removing index 0', `${cb.call('keyring_slot_count', stored)}: ${slotTypes(cb, stored).join(', ')}`),
              row.check('The slot was removed', removed === 1, 'returned 1'),
              mustRefuse('The lost phone no longer unlocks', () => cb.call('keyring_unlock_with_device', stored, phone)),
              row.check('The laptop still unlocks the same master key', same(cb.call('keyring_unlock_with_device', stored, laptop), master), 'identical'),
              row.check('The passphrase still unlocks it', same(cb.call('keyring_unlock_with_passphrase', stored, passphrase), master), 'identical'),
              mustRefuse('Removing an index past the end is refused', () => cb.call('keyring_remove_slot', stored, 7)),
              row.text('An envelope saved before the removal', oldCopy ? 'still opens with the phone: delete old copies, or rotate the master key' : 'no longer opens with the phone'),
            ];
          });
        });
      },
    },
    {
      id: 'hardware',
      title: 'A slot held by a secure element',
      statement: 'A hardware slot hands out a fresh factor for the secure element to wrap, and the keyring stores only the wrapped blob and the key id. Here an XChaCha20 key plays the secure element.',
      inputs: [{ name: 'keyId', label: 'Secure element key id', kind: 'text', value: 'enclave:alice-phone:2026' }],
      run(cb, { keyId }) {
        const element = cb.call('sym_keygen');
        const device = cb.call('random_bytes', 32);
        let master;
        let factor;
        const blob = withKeyring(cb, () => cb.call('keyring_create'), (kr) => {
          cb.call('keyring_add_device_slot', kr, device);
          factor = cb.call('keyring_add_hardware_slot', kr, keyId);
          const wrapped = cb.call('xchacha20_encrypt', factor, element, keyId);
          cb.call('keyring_set_hardware_blob', kr, 1, wrapped);
          master = cb.call('keyring_unlock_with_device', kr, device);
          return cb.call('keyring_serialise', kr);
        });
        return withKeyring(cb, () => cb.call('keyring_deserialise', blob), (kr) => {
          const id = cb.Out.buffer();
          const stored = cb.Out.buffer();
          const found = cb.call('keyring_hardware_slot', kr, 1, id, stored);
          const unwrapped = cb.call('xchacha20_decrypt', stored.value, element, id.value);
          const opened = cb.call('keyring_unlock_with_hardware', kr, 1, unwrapped);
          return [
            row.bytes('Fresh factor from keyring_add_hardware_slot', factor, 'the element wraps it; only the wrapped blob is stored'),
            row.text('Slots', slotTypes(cb, kr).join(', ')),
            row.text('Envelope version', `${blob[4]} (a hardware slot needs version 2)`),
            row.check('Key id and wrapped blob read back from the envelope', found === 1 && utf8.decode(id.value) === keyId,
              `${utf8.decode(id.value)}, ${stored.value.length}-byte blob`),
            row.check('The element unwraps the factor and it opens the slot', same(opened, master), 'same master key as the device slot'),
            mustRefuse('A different factor is refused', () => cb.call('keyring_unlock_with_hardware', kr, 1, cb.call('random_bytes', 32))),
            mustRefuse('A blob for a device slot is refused', () => cb.call('keyring_set_hardware_blob', kr, 0, stored.value)),
            mustRefuse('Reading a device slot as hardware is refused', () => cb.call('keyring_hardware_slot', kr, 0, cb.Out.buffer(), cb.Out.buffer())),
          ];
        });
      },
    },
  ],
};
