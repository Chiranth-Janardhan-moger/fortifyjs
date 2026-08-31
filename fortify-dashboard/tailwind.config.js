/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './app/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        apple: {
          bg: '#F5F5F7',
          card: '#FFFFFF',
          subtle: '#FBFBFD',
          border: 'rgba(0, 0, 0, 0.08)',
          cardBorder: 'rgba(0, 0, 0, 0.06)',
          blue: '#0071E3',
          blueHover: '#0077ED',
          blueLight: '#EBF4FF',
          green: '#34C759',
          greenLight: '#EDFAF1',
          greenBorder: '#C8F0D4',
          red: '#FF3B30',
          redLight: '#FDF1F0',
          redBorder: '#FBCDCB',
          amber: '#FF9500',
          amberLight: '#FFF8EB',
          amberBorder: '#FEE4B7',
          text: '#1D1D1F',
          secondary: '#86868B',
          tertiary: '#A1A1A6',
        }
      },
      fontFamily: {
        sans: [
          '-apple-system',
          'BlinkMacSystemFont',
          '"SF Pro Display"',
          '"SF Pro Text"',
          '"Helvetica Neue"',
          'Arial',
          'sans-serif'
        ],
        mono: [
          '"JetBrains Mono"',
          'SFMono-Regular',
          'Menlo',
          'Monaco',
          'Consolas',
          'monospace'
        ]
      },
      boxShadow: {
        'apple-sm': '0 2px 8px rgba(0, 0, 0, 0.04)',
        'apple-card': '0 4px 24px rgba(0, 0, 0, 0.06)',
        'apple-hover': '0 8px 30px rgba(0, 0, 0, 0.08)',
      },
      borderRadius: {
        'apple-sm': '8px',
        'apple-md': '12px',
        'apple-lg': '18px',
        'apple-pill': '9999px',
      }
    },
  },
  plugins: [],
}
