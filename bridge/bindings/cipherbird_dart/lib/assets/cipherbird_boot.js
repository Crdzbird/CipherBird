// Optional page-side boot for the CipherBird engine. Load it from index.html
// after cipherbird.js and the engine is instantiated while Flutter is still
// bootstrapping; the Dart side adopts the finished module synchronously, so
// no await is needed before the first use once this has completed.
//
//   <script src="assets/packages/cipherbird/assets/cipherbird.js" defer></script>
//   <script src="assets/packages/cipherbird/assets/cipherbird_boot.js" defer></script>
'use strict';

(function () {
  if (typeof createCipherBird !== 'function' || self.cipherbirdEnginePromise) {
    return;
  }
  var src = document.currentScript && document.currentScript.src;
  var base = src ? src.substring(0, src.lastIndexOf('/') + 1) : '';
  self.cipherbirdEnginePromise = createCipherBird({
    locateFile: function (file) { return base + file; }
  }).then(function (module) {
    self.cipherbirdEngine = { module: module, base: base };
    return module;
  });
})();
