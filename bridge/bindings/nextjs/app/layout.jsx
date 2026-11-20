export const metadata = {
  title: 'CipherBird · Next.js',
  description: 'Native CipherBird crypto from a Next.js route handler',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body style={{ margin: 0 }}>{children}</body>
    </html>
  );
}
