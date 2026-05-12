/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'monospace'],
      },
      colors: {
        // Trading-terminal palette.
        kaiju: {
          bg: '#09090b',
          panel: '#111114',
          border: '#27272a',
          text: '#e4e4e7',
          muted: '#71717a',
          accent: '#60a5fa',
          warn: '#fbbf24',
          danger: '#f43f5e',
          ok: '#10b981',
          claude: '#a78bfa',
          codex: '#34d399',
        },
      },
    },
  },
  plugins: [],
};
