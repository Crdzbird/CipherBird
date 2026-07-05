/** @type {import('next').NextConfig} */
const nextConfig = {
  // koffi is a native addon and cryptolib-node is loaded at runtime via
  // createRequire (see lib/cryptolib.js), so nothing native is bundled by webpack.
  serverExternalPackages: ['koffi'],
};
export default nextConfig;
