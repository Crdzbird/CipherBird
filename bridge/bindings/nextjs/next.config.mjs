/** @type {import('next').NextConfig} */
const nextConfig = {
  // The native binding is loaded lazily via a webpackIgnore dynamic import
  // (see lib/cryptolib.js), so nothing native is bundled. Marking koffi external
  // is belt-and-suspenders.
  serverExternalPackages: ['koffi'],
};
export default nextConfig;
