/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  CryptoLib — Recipes: composition in practice                              ║
 * ║                                                                            ║
 * ║  The primitives are LEGO bricks. These recipes snap them together into     ║
 * ║  real-world flows to show the library's flexibility. No new cryptography — ║
 * ║  just composition of vetted parts.                                         ║
 * ║                                                                            ║
 * ║   1. File-as-key vault      media entropy → master → MolecularVault        ║
 * ║   2. Post-quantum message   hybrid KEM → shared secret → MolecularVault    ║
 * ║   3. Sign-then-seal         hybrid signature inside a MolecularVault        ║
 * ║   4. Threshold vault        MolecularVault key split via Shamir (3-of-5)    ║
 * ║   5. EVM wallet             secp256k1 → Keccak address → sign → ecrecover   ║
 * ║   6. Keyring-guarded vault  Keyring unlock → MolecularVault master key      ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */
#include <cryptolib/cryptolib.hpp>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <vector>

using crypto::SecureBuffer;

namespace {

int g_pass = 0, g_fail = 0;
void ck(const char* label, bool ok) {
  std::printf("   %s %s\n", ok ? "\033[32m✓\033[0m" : "\033[31m✗\033[0m", label);
  ok ? ++g_pass : ++g_fail;
}
void section(const char* n) { std::printf("\n\033[1;36m%s\033[0m\n", n); }

// Unwrap a Result<T> or abort loudly (recipes assume the happy path).
// value() returns T&; move it out so move-only types (SecureBuffer, KeyPair, …)
// come through by move.
template <class R>
auto must(R&& r, const char* what) {
  if (r.is_err()) { std::printf("FATAL %s: %s\n", what, r.error().message.c_str()); std::exit(1); }
  return std::move(r.value());
}

std::span<const uint8_t> sp(const SecureBuffer& b) { return b.span(); }
std::span<const uint8_t> sp(const std::vector<uint8_t>& v) { return {v.data(), v.size()}; }
std::span<const uint8_t> sp(std::string_view s) {
  return {reinterpret_cast<const uint8_t*>(s.data()), s.size()};
}
bool eq(std::span<const uint8_t> a, std::span<const uint8_t> b) {
  return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
}

} // namespace

int main() {
  crypto::init();
  std::printf("CryptoLib — Recipes (composition in practice)\n");

  const auto aad = sp(std::string_view{"recipe/v1"});

  // ── 1. File-as-key vault ──────────────────────────────────────────────────
  // "Your file is your key." Derive a deterministic master from a file, then
  // seal with MolecularVault. Anyone with the same file re-derives and opens it.
  section("1. File-as-key vault  (media entropy → MolecularVault)");
  {
    auto tmp = std::filesystem::temp_directory_path() / "cryptolib_recipe_key.bin";
    { std::ofstream f(tmp, std::ios::binary); for (int i = 0; i < 4096; ++i) f.put(char(i * 37 + 11)); }

    auto e1 = must(crypto::entropy::MediaEntropy::from_file_deterministic(tmp), "entropy");
    auto master = e1.derive_all().vault_master_key;               // 32-byte master
    auto env = must(crypto::MolecularVault::seal_with_key(sp(std::string_view{"launch codes"}), sp(master), aad), "seal");

    // Re-derive from the SAME file on the "other side" and open.
    auto e2 = must(crypto::entropy::MediaEntropy::from_file_deterministic(tmp), "entropy2");
    auto master2 = e2.derive_all().vault_master_key;
    auto opened = must(crypto::MolecularVault::open_with_key(sp(env), sp(master2), aad), "open");
    ck("same file re-derives the key and opens the vault", eq(sp(opened), sp(std::string_view{"launch codes"})));
    std::filesystem::remove(tmp);
  }

  // ── 2. Post-quantum message ───────────────────────────────────────────────
  // Agree a shared secret with the hybrid KEM (safe if EITHER X25519 or ML-KEM
  // survives), then seal with MolecularVault. Harvest-now-decrypt-later resistant.
  section("2. Post-quantum message  (hybrid KEM → MolecularVault)");
  {
    auto bob = must(crypto::pq::HybridKem::generate_keypair(), "kem keygen");
    auto enc = must(crypto::pq::HybridKem::encapsulate(sp(bob.public_key)), "encaps"); // sender
    auto env = must(crypto::MolecularVault::seal_with_key(sp(std::string_view{"see you at dawn"}), sp(enc.shared_secret), aad), "seal");

    auto ss = must(crypto::pq::HybridKem::decapsulate(sp(enc.ciphertext), sp(bob.secret_key)), "decaps"); // recipient
    auto opened = must(crypto::MolecularVault::open_with_key(sp(env), sp(ss), aad), "open");
    ck("hybrid-KEM secret opens the PQ-sealed message", eq(sp(opened), sp(std::string_view{"see you at dawn"})));
  }

  // ── 3. Sign-then-seal ─────────────────────────────────────────────────────
  // Prove authorship AND keep it confidential: hybrid-sign the plaintext, put
  // (plaintext ‖ signature) inside a MolecularVault. Recipient opens, then
  // verifies. Both the classical and PQ signature must check out.
  section("3. Sign-then-seal  (hybrid signature inside MolecularVault)");
  {
    auto signer = must(crypto::pq::HybridSig::generate_keypair(), "sig keygen");
    std::string_view msg = "transfer 100 to acct #42";
    auto sig = must(crypto::pq::HybridSig::sign(sp(msg), sp(signer.secret_key)), "sign");

    std::vector<uint8_t> bundle(msg.begin(), msg.end());
    bundle.insert(bundle.end(), sig.span().begin(), sig.span().end());  // plaintext ‖ sig

    auto env = must(crypto::MolecularVault::seal(sp(bundle), "outer passphrase", aad,
                    {2, 1u << 20}), "seal");
    auto opened = must(crypto::MolecularVault::open(sp(env), "outer passphrase", aad), "open");

    auto os = opened.span();
    auto got_msg = os.subspan(0, msg.size());
    auto got_sig = os.subspan(msg.size());
    bool verified = crypto::pq::HybridSig::verify(got_msg, got_sig, sp(signer.public_key)).is_ok();
    ck("opened → both Ed25519 and ML-DSA signatures verify", verified && eq(got_msg, sp(msg)));
  }

  // ── 4. Threshold vault ────────────────────────────────────────────────────
  // Split the vault's master key into 5 shares; any 3 reconstruct it. No single
  // custodian (or lost share) can open — or block — the secret.
  section("4. Threshold vault  (MolecularVault key split 3-of-5 via Shamir)");
  {
    auto master = crypto::random_bytes(32);
    auto env = must(crypto::MolecularVault::seal_with_key(sp(std::string_view{"board resolution"}), sp(master), aad), "seal");

    auto shares = must(crypto::Shamir::split(sp(master), 5, 3), "split");
    // Reconstruct from only shares #1, #3, #5.
    std::vector<crypto::Shamir::Share> quorum;
    quorum.push_back(std::move(shares[0]));
    quorum.push_back(std::move(shares[2]));
    quorum.push_back(std::move(shares[4]));
    auto recovered = must(crypto::Shamir::combine({quorum.data(), quorum.size()}), "combine");

    auto opened = must(crypto::MolecularVault::open_with_key(sp(env), sp(recovered), aad), "open");
    ck("any 3 of 5 shares reconstruct the key and open the vault",
       eq(sp(opened), sp(std::string_view{"board resolution"})) && eq(sp(recovered), sp(master)));
  }

  // ── 5. EVM wallet ─────────────────────────────────────────────────────────
  // A minimal Ethereum-style flow: derive the 20-byte address from the public
  // key via Keccak-256, sign a transaction digest, and ecrecover the signer.
  section("5. EVM wallet  (secp256k1 → Keccak address → sign → ecrecover)");
  {
    auto w = crypto::ec::Secp256k1::generate_keypair();
    // address = last 20 bytes of Keccak-256( uncompressed pubkey without 0x04 )
    auto pub = w.public_key.span();
    auto addrHash = must(crypto::hash::Keccak256::digest(pub.subspan(1)), "keccak");
    auto address = addrHash.span().subspan(12, 20);
    std::printf("      address 0x");
    for (auto byte : address) std::printf("%02x", byte);
    std::printf("\n");

    auto txDigest = must(crypto::hash::Keccak256::digest(sp(std::string_view{"transfer 1 ETH → 0xBEEF"})), "digest");
    auto sig = must(crypto::ec::Secp256k1::sign(sp(txDigest), sp(w.secret_key)), "sign"); // 65B r‖s‖v
    auto recovered = must(crypto::ec::Secp256k1::recover(sp(txDigest), sp(sig)), "recover");
    ck("ecrecover returns the signer's public key (65B, v included)",
       sig.span().size() == 65 && eq(sp(recovered), pub));
  }

  // ── 6. Keyring-guarded vault ──────────────────────────────────────────────
  // The vault's master key never lives in plaintext at rest: a Keyring wraps it
  // under a device factor AND a passphrase. Either unlocks it; then it keys a
  // MolecularVault. Revoke a slot → re-serialise → that factor no longer opens.
  section("6. Keyring-guarded vault  (Keyring unlock → MolecularVault key)");
  {
    auto deviceKey = crypto::random_bytes(32);
    auto kr = crypto::Keyring::create();                        // random master inside
    (void) kr.add_device_slot(sp(deviceKey));
    (void) kr.add_passphrase_slot("cross-device pass", crypto::KdfParams::interactive());
    auto blob = kr.serialise();                                 // no plaintext key at rest

    auto kr2 = must(crypto::Keyring::deserialise(sp(blob)), "deserialise");
    auto master = must(kr2.unlock_with_device(sp(deviceKey)), "unlock");
    auto env = must(crypto::MolecularVault::seal_with_key(sp(std::string_view{"root secret"}), sp(master), aad), "seal");

    // Later / on another device: unlock via the passphrase slot instead.
    auto master2 = must(kr2.unlock_with_passphrase("cross-device pass"), "unlock-pass");
    auto opened = must(crypto::MolecularVault::open_with_key(sp(env), sp(master2), aad), "open");
    ck("either keyring factor unlocks the same MolecularVault master",
       eq(sp(opened), sp(std::string_view{"root secret"})) && eq(sp(master), sp(master2)));
  }

  std::printf("\n\033[1m%d passed, %d failed\033[0m — recipes %s\n",
              g_pass, g_fail, g_fail == 0 ? "OK" : "FAILED");
  return g_fail == 0 ? 0 : 1;
}
