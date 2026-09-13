package cryptolib;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * A layer that is itself a mixture of layers — the way to compose several
 * encryptions into one custom type. Extend it, or instantiate it directly:
 *
 * <pre>{@code
 * final class BeltAndBraces extends CascadeLayer {
 *     BeltAndBraces() {
 *         super(201, "belt-and-braces",
 *               List.of(ProtectionLayer.XCHACHA20_POLY1305, new MyLayer()));
 *     }
 * }
 * }</pre>
 *
 * <p>Each inner layer receives its own sub-key, HKDF-derived from this layer's
 * key under the inner index and wire name, so nesting never collapses two
 * ciphers onto one key. The AAD is bound by every inner layer. Cascades nest.
 */
public class CascadeLayer implements ProtectionLayer {
    private final int id;
    private final String wireName;
    private final List<ProtectionLayer> layers;

    /** @param layers innermost first; must not be empty */
    public CascadeLayer(int id, String wireName, List<ProtectionLayer> layers) {
        if (layers.isEmpty()) throw new IllegalArgumentException("cryptolib: CascadeLayer '" + wireName + "' has no layers");
        this.id = id;
        this.wireName = wireName;
        this.layers = List.copyOf(layers);
    }

    @Override public final int id() { return id; }
    @Override public final String wireName() { return wireName; }
    /** The inner layers, innermost first. */
    public final List<ProtectionLayer> layers() { return layers; }

    private byte[] subKey(CryptoLib lib, byte[] key, int i) {
        byte[] info = (wireName + "/" + i + "/" + layers.get(i).wireName()).getBytes(StandardCharsets.UTF_8);
        return lib.hkdfDerive(key, new byte[0], info, 32);
    }

    @Override
    public byte[] seal(CryptoLib lib, byte[] key, byte[] aad, byte[] plaintext) {
        byte[] body = plaintext;
        for (int i = 0; i < layers.size(); i++) body = layers.get(i).seal(lib, subKey(lib, key, i), aad, body);
        return body;
    }

    @Override
    public byte[] open(CryptoLib lib, byte[] key, byte[] aad, byte[] ciphertext) {
        byte[] body = ciphertext;
        for (int i = layers.size() - 1; i >= 0; i--) body = layers.get(i).open(lib, subKey(lib, key, i), aad, body);
        return body;
    }

    @Override public String toString() { return wireName; }
}
