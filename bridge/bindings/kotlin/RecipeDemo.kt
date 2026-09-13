// CryptoLib Kotlin — security profiles + composable recipes.
//
// Kotlin consumes the `cryptolib` Java package (cryptolib-jvm) rather than
// re-declaring the FFM bindings: same JVM, same native library, one binding to
// maintain. Everything below is the shared Recipe API.
//
// Build/run (see Makefile target `kotlin-security`):
//   kotlinc RecipeDemo.kt -cp ../cryptolib-jvm/out -include-runtime -d recipe.jar
//   java --enable-native-access=ALL-UNNAMED -cp recipe.jar:../cryptolib-jvm/out RecipeDemoKt
import cryptolib.CryptoLib
import cryptolib.FecScheme
import cryptolib.CascadeLayer
import cryptolib.KeySource
import cryptolib.ProtectionLayer
import cryptolib.SignatureScheme
import cryptolib.SecurityProfile
import cryptolib.SignatureAlgorithm
import java.nio.file.Files
import kotlin.system.exitProcess

private var pass = 0
private var fail = 0

private fun ck(label: String, ok: Boolean) {
    println(if (ok) "  ok   $label" else " FAIL  $label")
    if (ok) pass++ else fail++
}

private fun throwsErr(body: () -> Unit): Boolean =
    try { body(); false } catch (_: Throwable) { true }

private fun noisePpm(w: Int, h: Int, seed: Int): ByteArray {
    val head = "P6\n$w $h\n255\n".toByteArray(Charsets.US_ASCII)
    val body = ByteArray(w * h * 3)
    var s = if (seed == 0) 1 else seed
    for (i in body.indices) {
        s = s xor (s shl 13); s = s xor (s ushr 17); s = s xor (s shl 5)
        body[i] = s.toByte()
    }
    return head + body
}

// ── Custom parts: the same interfaces the library's own layers implement ─────

/** A user layer: a real AEAD (the library's XChaCha20) under its own identity. */
class MyLayer : ProtectionLayer {
    override fun id() = 200
    override fun wireName() = "my-xchacha"
    override fun seal(lib: CryptoLib, key: ByteArray, aad: ByteArray, pt: ByteArray) = lib.xchacha20Encrypt(pt, key, aad)
    override fun open(lib: CryptoLib, key: ByteArray, aad: ByteArray, ct: ByteArray) = lib.xchacha20Decrypt(ct, key, aad)
}

/** Three ciphers as ONE layer, by extending CascadeLayer. */
class BeltAndBraces : CascadeLayer(201, "belt-and-braces",
    listOf(ProtectionLayer.XCHACHA20_POLY1305, ProtectionLayer.AES256_GCM, MyLayer()))

/** A key that comes from somewhere else entirely — a token, a KMS, a keyring. */
class TokenSource(private val token: ByteArray) : KeySource {
    override fun id() = 210
    override fun label() = "token"
    override fun deriveRoot(lib: CryptoLib, salt: ByteArray, ops: Long, mem: Long) = token
}

/** A custom signature scheme: Ed25519 over a domain-separated message. */
class PrefixedEd25519(private val sk: ByteArray? = null, private val pk: ByteArray? = null) : SignatureScheme {
    override fun id() = 220
    override fun label() = "prefixed-ed25519"
    private fun tag(m: ByteArray) = "custom:".toByteArray() + m
    override fun sign(lib: CryptoLib, m: ByteArray) = lib.ed25519Sign(tag(m), sk!!)
    override fun verify(lib: CryptoLib, m: ByteArray, sig: ByteArray) = lib.ed25519Verify(tag(m), sig, pk!!)
}

class Impostor : ProtectionLayer {
    override fun id() = 3
    override fun wireName() = "committing"
    override fun seal(lib: CryptoLib, key: ByteArray, aad: ByteArray, pt: ByteArray) = pt
    override fun open(lib: CryptoLib, key: ByteArray, aad: ByteArray, ct: ByteArray) = ct
}

fun main() {
    CryptoLib().use { lib ->
        lib.init()
        println("CryptoLib ${lib.version()} — security profiles + recipes (Kotlin)")

        val dir = Files.createTempDirectory("cl_sec_kt_")
        val secret = "the treaty text nobody may read".toByteArray()
        fun cheap(r: cryptolib.Recipe) = r.argon2Cost(1, 8L * 1024 * 1024)

        val max = SecurityProfile.MAXIMUM
        ck("maximum picks the strongest options",
            max.mlKemLevel() == 2 && max.mlDsaLevel() == 2 && max.slhDsaHash() == 1 && max.kdfPreset() == 1)
        ck("maximum cascade ends key-committing",
            max.cascade().size == 3 && max.cascade()[2] == ProtectionLayer.COMMITTING)

        val key = lib.randomBytes(32)
        val r = lib.recipe(SecurityProfile.HIGH).withKey(key)
        ck("raw key round-trip", r.open(r.seal(secret)).contentEquals(secret))

        val pr = cheap(lib.maximumSecurity().withPassphrase("correct horse battery staple"))
        ck("maximum + passphrase round-trip", pr.open(pr.seal(secret)).contentEquals(secret))

        val keyFile = dir.resolve("key.ppm")
        Files.write(keyFile, noisePpm(96, 96, 0x5EED))
        val byFile = lib.recipe(SecurityProfile.BALANCED).withKeyFile(keyFile.toString()).seal(secret)
        ck("key file reproducible across recipe objects",
            lib.recipe(SecurityProfile.BALANCED).withKeyFile(keyFile.toString()).open(byFile).contentEquals(secret))

        val mol = lib.recipe(SecurityProfile.BALANCED).withKey(key).withLayers(listOf(ProtectionLayer.MOLECULAR))
        ck("MolecularVault as one layer", mol.open(mol.seal(secret)).contentEquals(secret))

        val id = lib.ed25519Keygen()
        val signed = lib.recipe(SecurityProfile.HIGH).withKey(key)
            .signedBy(id.secretKey(), SignatureAlgorithm.ED25519).verifiedBy(id.publicKey())
        val senv = signed.seal(secret)
        ck("signed round-trip", signed.open(senv).contentEquals(secret))

        val impostor = lib.ed25519Keygen()
        ck("wrong signer rejected", throwsErr {
            lib.recipe(SecurityProfile.HIGH).withKey(key).verifiedBy(impostor.publicKey()).open(senv)
        })
        ck("signed envelope refuses to open unverified", throwsErr {
            lib.recipe(SecurityProfile.HIGH).withKey(key).open(senv)
        })

        val fr = lib.recipe(SecurityProfile.BALANCED).withKey(key).withFec(FecScheme.REPETITION3)
        val fenv = fr.seal(secret)
        fenv[fenv.size / 2] = (fenv[fenv.size / 2].toInt() xor 1).toByte()
        ck("FEC corrects a flipped bit", fr.open(fenv).contentEquals(secret))

        val cover = dir.resolve("cover.ppm")
        val carrier = dir.resolve("carrier.ppm")
        Files.write(cover, noisePpm(256, 256, 0x0FF1CE))
        val cr = cheap(lib.maximumSecurity().withPassphrase("a long passphrase here"))
        cr.sealIntoCarrier(secret, cover.toString(), carrier.toString())
        ck("pipeline hides itself in a carrier", cr.openFromCarrier(carrier.toString()).contentEquals(secret))

        val tenv = r.seal(secret)
        tenv[tenv.size - 1] = (tenv[tenv.size - 1].toInt() xor 1).toByte()
        ck("flipped ciphertext byte rejected", throwsErr { r.open(tenv) })
        val henv = r.seal(secret)
        henv[7] = 1
        ck("tampered header rejected (descriptor is AAD)", throwsErr { r.open(henv) })
        ck("wrong key rejected", throwsErr {
            lib.recipe(SecurityProfile.HIGH).withKey(lib.randomBytes(32)).open(r.seal(secret))
        })
        ck("short key refused", throwsErr { lib.recipe(SecurityProfile.BALANCED).withKey(ByteArray(31)) })

        // Extension points
        ProtectionLayer.register(MyLayer())
        ProtectionLayer.register(BeltAndBraces())
        val br = lib.recipe(SecurityProfile.BALANCED).withKey(key).withLayers(listOf(BeltAndBraces()))
        val benv = br.seal(secret)
        ck("custom cascade subclass round-trips via the registry",
            lib.recipe(SecurityProfile.BALANCED).withKey(key).open(benv).contentEquals(secret))
        benv[benv.size - 1] = (benv[benv.size - 1].toInt() xor 1).toByte()
        ck("custom cascade fails closed", throwsErr { br.open(benv) })
        ck("reserved id refused", throwsErr { ProtectionLayer.register(Impostor()) })

        val token = lib.randomBytes(32)
        val tenv2 = lib.recipe(SecurityProfile.HIGH).withKeySource(TokenSource(token)).seal(secret)
        ck("custom key source round-trips",
            lib.recipe(SecurityProfile.HIGH).withKeySource(TokenSource(token)).open(tenv2).contentEquals(secret))
        ck("header pins the custom source id", throwsErr { lib.recipe(SecurityProfile.HIGH).withKey(key).open(tenv2) })

        val sid = lib.ed25519Keygen()
        val senv3 = lib.recipe(SecurityProfile.BALANCED).withKey(key).signedWith(PrefixedEd25519(sk = sid.secretKey())).seal(secret)
        ck("custom signature scheme round-trips",
            lib.recipe(SecurityProfile.BALANCED).withKey(key).verifiedWith(PrefixedEd25519(pk = sid.publicKey())).open(senv3).contentEquals(secret))
        ck("key-only verifier cannot serve a custom scheme",
            throwsErr { lib.recipe(SecurityProfile.BALANCED).withKey(key).verifiedBy(sid.publicKey()).open(senv3) })

        dir.toFile().deleteRecursively()
        println("\n$pass passed, $fail failed — recipes ${if (fail == 0) "OK" else "FAILED"}")
        exitProcess(if (fail == 0) 0 else 1)
    }
}
