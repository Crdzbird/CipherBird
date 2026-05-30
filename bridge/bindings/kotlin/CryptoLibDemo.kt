// CryptoLib Kotlin/JVM demo using the Foreign Function & Memory API (JDK 22+).
//
// Kotlin calls java.lang.foreign directly — the same binding strategy as the
// Java demo, no JNI. On Android, prefer the prebuilt .so (see `make android`)
// loaded via JNI/JNA, since Android's runtime does not expose the FFM API.
//
// Build/run (needs kotlinc 2.x + JDK 22+; see Makefile target `kotlin`):
//   kotlinc CryptoLibDemo.kt -include-runtime -d demo.jar
//   java --enable-native-access=ALL-UNNAMED -jar demo.jar <path-to-libcryptolib_c.dylib>

import java.lang.foreign.*
import java.lang.foreign.ValueLayout.*
import java.lang.invoke.MethodHandle
import java.nio.file.Path

private val CRYPTO_BUFFER: GroupLayout = MemoryLayout.structLayout(
    ADDRESS.withName("data"), JAVA_LONG.withName("len"))
private val CRYPTO_BUFFER_RESULT: GroupLayout = MemoryLayout.structLayout(
    CRYPTO_BUFFER.withName("buf"), ADDRESS.withName("error"))
private val CRYPTO_PACKET: GroupLayout = MemoryLayout.structLayout(
    CRYPTO_BUFFER.withName("ciphertext"),
    CRYPTO_BUFFER.withName("signature"),
    CRYPTO_BUFFER.withName("kdf_salt"))

class CryptoLib(libPath: String) {
    private val arena: Arena = Arena.ofConfined()
    private val linker = Linker.nativeLinker()
    private val lib = SymbolLookup.libraryLookup(Path.of(libPath), arena)

    private fun h(name: String, fd: FunctionDescriptor): MethodHandle =
        linker.downcallHandle(lib.find(name).orElseThrow { RuntimeException("missing: $name") }, fd)

    private val init        = h("cryptolib_init",         FunctionDescriptor.of(JAVA_INT))
    private val version     = h("cryptolib_version",      FunctionDescriptor.of(ADDRESS))
    private val randomBytes = h("cryptolib_random_bytes", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, JAVA_LONG))
    private val sha256      = h("cryptolib_sha256",       FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, JAVA_LONG))
    private val vaultCreate = h("cryptolib_vault_create", FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_LONG, JAVA_INT))
    private val vaultSeal    = h("cryptolib_vault_seal",  FunctionDescriptor.of(CRYPTO_PACKET, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS))
    private val vaultOpen    = h("cryptolib_vault_open",  FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, ADDRESS, ADDRESS))
    private val bufferFree  = h("cryptolib_buffer_free",  FunctionDescriptor.ofVoid(ADDRESS))
    private val packetFree  = h("cryptolib_packet_free",  FunctionDescriptor.ofVoid(ADDRESS))
    private val vaultFree   = h("cryptolib_vault_free",   FunctionDescriptor.ofVoid(ADDRESS))
    private val krCreate    = h("cryptolib_keyring_create",   FunctionDescriptor.of(ADDRESS))
    private val krAddDev    = h("cryptolib_keyring_add_device_slot", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_LONG))
    private val krAddPw     = h("cryptolib_keyring_add_passphrase_slot", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_INT))
    private val krCount     = h("cryptolib_keyring_slot_count", FunctionDescriptor.of(JAVA_LONG, ADDRESS))
    private val krSer       = h("cryptolib_keyring_serialise", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS))
    private val krDeser     = h("cryptolib_keyring_deserialise", FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_LONG, ADDRESS))
    private val krUnlockDev = h("cryptolib_keyring_unlock_with_device", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, ADDRESS, JAVA_LONG))
    private val krUnlockPw  = h("cryptolib_keyring_unlock_with_passphrase", FunctionDescriptor.of(CRYPTO_BUFFER_RESULT, ADDRESS, ADDRESS))
    private val krFree      = h("cryptolib_keyring_free",     FunctionDescriptor.ofVoid(ADDRESS))

    private fun consume(result: MemorySegment): ByteArray {
        val data = result.get(ADDRESS, 0)
        val len = result.get(JAVA_LONG, ADDRESS.byteSize())
        if (data == MemorySegment.NULL || len == 0L) return ByteArray(0)
        val out = data.reinterpret(len).toArray(JAVA_BYTE)
        bufferFree.invoke(result)
        return out
    }

    fun run() {
        check(init.invoke() as Int == 0) { "init failed" }
        val ver = (version.invoke() as MemorySegment).reinterpret(Long.MAX_VALUE).getString(0)
        println("CryptoLib version: $ver")

        val rnd = consume(randomBytes.invoke(arena, 32L) as MemorySegment)
        println("random(32):  " + rnd.joinToString("") { "%02x".format(it) })

        val msg = arena.allocateFrom(JAVA_BYTE, *"abc".toByteArray())
        val digest = consume(sha256.invoke(arena, msg, 3L) as MemorySegment)
        println("sha256(abc): " + digest.joinToString("") { "%02x".format(it) })

        val key = arena.allocateFrom(JAVA_BYTE, *consume(randomBytes.invoke(arena, 32L) as MemorySegment))
        val vault = vaultCreate.invoke(key, key.byteSize(), 0) as MemorySegment
        val pt = "hello from kotlin".toByteArray()
        val ptSeg = arena.allocateFrom(JAVA_BYTE, *pt)
        val aad = arena.allocateFrom("ctx")
        val errOut = arena.allocate(ADDRESS)
        val packet = vaultSeal.invoke(arena, vault, ptSeg, pt.size.toLong(), aad, errOut) as MemorySegment
        check(errOut.get(ADDRESS, 0) == MemorySegment.NULL) { "seal failed" }
        val opened = consume(vaultOpen.invoke(arena, vault, packet, aad) as MemorySegment)
        println("vault roundtrip: \"${String(opened)}\"")
        packetFree.invoke(packet)
        vaultFree.invoke(vault)

        // Keyring: default device slot + opt-in passphrase slot → cross-device.
        val factor = consume(randomBytes.invoke(arena, 32L) as MemorySegment)
        val factorSeg = arena.allocateFrom(JAVA_BYTE, *factor)
        val kr = krCreate.invoke() as MemorySegment
        krAddDev.invoke(kr, factorSeg, factor.size.toLong())
        krAddPw.invoke(kr, arena.allocateFrom("cross-device pass"), 0)
        val blob = consume(krSer.invoke(arena, kr) as MemorySegment)
        val blobSeg = arena.allocateFrom(JAVA_BYTE, *blob)
        val krErr = arena.allocate(ADDRESS)
        val kr2 = krDeser.invoke(blobSeg, blob.size.toLong(), krErr) as MemorySegment
        val mDev  = consume(krUnlockDev.invoke(arena, kr2, factorSeg, factor.size.toLong()) as MemorySegment)
        val mPass = consume(krUnlockPw.invoke(arena, kr2, arena.allocateFrom("cross-device pass")) as MemorySegment)
        println("keyring slots: ${krCount.invoke(kr) as Long} · device==passphrase master: ${mDev.contentEquals(mPass)}")
        krFree.invoke(kr)
        krFree.invoke(kr2)

        println("Kotlin demo OK")
    }
}

fun main(args: Array<String>) {
    val path = if (args.isNotEmpty()) args[0] else "build/release/libcryptolib_c.dylib"
    CryptoLib(path).run()
}
