/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Core surfaces — a very dark navy/charcoal forensic theme.
        base: '#080b12',
        surface: '#0f1521',
        surface2: '#151d2c',
        surface3: '#1b2436',
        line: '#212c40',
        'line-soft': '#1a2233',
        // Text hierarchy.
        fg: {
          DEFAULT: '#e7edf7',
          muted: '#93a1b8',
          faint: '#61708a',
        },
        // Restrained accents.
        brand: {
          DEFAULT: '#4c8dff',
          soft: '#12203c',
          strong: '#2f6fe0',
        },
        cyan: { DEFAULT: '#22d3ee', soft: '#0c2b34' },
        violet: { DEFAULT: '#8b5cf6', soft: '#1d1638' },
        // Severity scale (maps to backend severities).
        sev: {
          info: '#38bdf8',
          low: '#2dd4bf',
          warning: '#f59e0b',
          medium: '#fb923c',
          error: '#f87171',
          high: '#ef4444',
          critical: '#f43f5e',
        },
        // Status semantics.
        status: {
          ok: '#22c55e',
          warn: '#eab308',
          danger: '#ef4444',
          legacy: '#64748b',
          unknown: '#64748b',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
      },
      borderRadius: {
        card: '14px',
      },
      boxShadow: {
        card: '0 1px 2px rgba(0,0,0,0.35), 0 12px 28px -18px rgba(0,0,0,0.65)',
        pop: '0 20px 50px -20px rgba(0,0,0,0.75)',
        'glow-brand': '0 0 0 1px rgba(76,141,255,0.35), 0 0 24px -6px rgba(76,141,255,0.45)',
      },
      backgroundImage: {
        'grid-faint':
          'linear-gradient(rgba(255,255,255,0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.025) 1px, transparent 1px)',
      },
      backgroundSize: {
        grid: '44px 44px',
      },
      keyframes: {
        fadeIn: { '0%': { opacity: '0' }, '100%': { opacity: '1' } },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        shimmer: {
          '0%': { backgroundPosition: '-500px 0' },
          '100%': { backgroundPosition: '500px 0' },
        },
        pulseSoft: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.35' },
        },
      },
      animation: {
        fadeIn: 'fadeIn 0.3s ease-out both',
        slideUp: 'slideUp 0.35s cubic-bezier(0.22,1,0.36,1) both',
        shimmer: 'shimmer 1.6s linear infinite',
        pulseSoft: 'pulseSoft 2s ease-in-out infinite',
      },
    },
  },
  plugins: [],
}
