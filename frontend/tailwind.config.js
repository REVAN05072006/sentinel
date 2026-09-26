/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        sentinel: {
          bg: 'var(--bg-primary)',
          card: 'var(--bg-card)',
          panel: 'var(--bg-panel)',
          border: 'var(--border-color)',
          'border-bright': 'var(--border-bright)',
          accent: 'var(--accent-primary)',
          'accent-glow': 'var(--accent-secondary)',
        }
      },
      spacing: {
        '4.5': '1.125rem',
      },
      boxShadow: {
        '2xs': '0 1px rgba(0, 0, 0, 0.04)',
        'xs': '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
        'glow-sm': '0 0 8px rgba(59, 130, 246, 0.15)',
        'glow-accent': '0 0 12px rgba(59, 130, 246, 0.2)',
        'glow-red': '0 0 12px rgba(239, 68, 68, 0.2)',
      },
      backdropBlur: {
        xs: '2px',
      },
      animation: {
        pulseSlow: 'pulseSlow 3s ease-in-out infinite',
      },
      keyframes: {
        pulseSlow: {
          '0%, 100%': { opacity: 0.6 },
          '50%': { opacity: 1 },
        },
      }
    },
  },
  plugins: [],
}
