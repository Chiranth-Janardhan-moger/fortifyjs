import './globals.css';

export const metadata = {
  title: 'FortifyJS — Zero-Dependency WAF & AI Security Suite',
  description: 'Interactive security inspector and live testing playground for FortifyJS',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet" />
      </head>
      <body className="min-h-screen flex flex-col justify-between">
        {children}
      </body>
    </html>
  );
}
