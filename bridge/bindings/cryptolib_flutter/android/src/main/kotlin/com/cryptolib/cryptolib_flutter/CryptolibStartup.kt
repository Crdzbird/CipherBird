package com.cryptolib.cryptolib_flutter

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import kotlin.concurrent.thread

/**
 * Auto-registered startup hook for the CryptoLib FFI plugin.
 *
 * This is an `ffiPlugin` (no method channel / plugin class), so there is no
 * natural place for native code to run at launch. Android instantiates
 * manifest-declared [ContentProvider]s very early in the app-start sequence —
 * before the first frame — which makes [onCreate] an ideal, dependency-free
 * place to warm the native library off the main thread.
 *
 * [System.loadLibrary] performs a process-global `dlopen`, so by the time Dart
 * calls `DynamicLibrary.open("libcryptolib_c.so")` the library is already
 * mapped and the first crypto call pays no load cost. The warm-up runs on a
 * background daemon thread so it never blocks startup, and is best-effort: if
 * it fails, the Dart-side lazy load still works on first use.
 */
class CryptolibStartup : ContentProvider() {

    override fun onCreate(): Boolean {
        thread(name = "cryptolib-preload", isDaemon = true) {
            runCatching { System.loadLibrary("cryptolib_c") }
        }
        return true
    }

    // ── Unused ContentProvider surface (this provider exists only for onCreate). ──
    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor? = null

    override fun getType(uri: Uri): String? = null

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0

    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?,
    ): Int = 0
}
