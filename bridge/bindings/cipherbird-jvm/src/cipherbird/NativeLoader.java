package cipherbird;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * Extracts the platform-appropriate CipherBird native library bundled inside the
 * JAR (under /native/&lt;os&gt;-&lt;arch&gt;/) to a temp file at runtime, so consumers
 * never provide a path. This is the standard "native-in-JAR" pattern.
 */
public final class NativeLoader {
    private NativeLoader() {}

    public static Path extract() {
        String os = System.getProperty("os.name", "").toLowerCase();
        String arch = System.getProperty("os.arch", "").toLowerCase();
        String osTag = os.contains("mac") ? "darwin" : os.contains("win") ? "windows" : "linux";
        String archTag = (arch.contains("aarch64") || arch.contains("arm64")) ? "arm64" : "x64";
        String ext = osTag.equals("darwin") ? "dylib" : osTag.equals("windows") ? "dll" : "so";
        String resource = "/native/" + osTag + "-" + archTag + "/libcipherbird." + ext;

        // Dev override: an explicit path wins (useful for local builds).
        String env = System.getenv("CIPHERBIRD_LIBRARY");
        if (env == null || env.isEmpty()) env = System.getenv("CRYPTOLIB_DYLIB");
        String override = System.getProperty("cipherbird.path", env);
        if (override != null && !override.isEmpty()) return Path.of(override);

        try (InputStream in = NativeLoader.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException("Bundled native library not found on classpath: "
                        + resource + " (os=" + os + ", arch=" + arch + ")");
            }
            Path tmp = Files.createTempFile("libcipherbird", "." + ext);
            tmp.toFile().deleteOnExit();
            Files.copy(in, tmp, StandardCopyOption.REPLACE_EXISTING);
            return tmp;
        } catch (IOException e) {
            throw new RuntimeException("Failed to extract bundled native library", e);
        }
    }
}
