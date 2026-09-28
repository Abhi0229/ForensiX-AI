/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // All colors are driven by CSS variables (RGB triples) defined per
        // theme in src/index.css under the .dark / .light selectors. The
        // `<alpha-value>` function form preserves Tailwind opacity modifiers
        // (e.g. bg-surface/80, bg-brand/10) across both themes.
        // Core surfaces.
        base: 'rgb(var(--color-base) / <alpha-value>)',
        surface: 'rgb(var(--color-surface) / <alpha-value>)',
        surface2: 'rgb(var(--color-surface2) / <alpha-value>)',
        surface3: 'rgb(var(--color-surface3) / <alpha-value>)',
        line: 'rgb(var(--color-line) / <alpha-value>)',
        'line-soft': 'rgb(var(--color-line-soft) / <alpha-value>)',
        // Text hierarchy.
        fg: {
          DEFAULT: 'rgb(var(--color-fg) / <alpha-value>)',
          muted: 'rgb(var(--color-fg-muted) / <alpha-value>)',
          faint: 'rgb(var(--color-fg-faint) / <alpha-value>)',
        },
        // Restrained accents.
        brand: {
          DEFAULT: 'rgb(var(--color-brand) / <alpha-value>)',
          soft: 'rgb(var(--color-brand-soft) / <alpha-value>)',
          strong: 'rgb(var(--color-brand-strong) / <alpha-value>)',
        },
        cyan: {
          DEFAULT: 'rgb(var(--color-cyan) / <alpha-value>)',
          soft: 'rgb(var(--color-cyan-soft) / <alpha-value>)',
        },
        violet: {
          DEFAULT: 'rgb(var(--color-violet) / <alpha-value>)',
          soft: 'rgb(var(--color-violet-soft) / <alpha-value>)',
        },
        // Severity scale (maps to backend severities). Hues are preserved
        // across themes; light-theme values are shifted darker for contrast.
        sev: {
          info: 'rgb(var(--color-sev-info) / <alpha-value>)',
          low: 'rgb(var(--color-sev-low) / <alpha-value>)',
          warning: 'rgb(var(--color-sev-warning) / <alpha-value>)',
          medium: 'rgb(var(--color-sev-medium) / <alpha-value>)',
          error: 'rgb(var(--color-sev-error) / <alpha-value>)',
          high: 'rgb(var(--color-sev-high) / <alpha-value>)',
          critical: 'rgb(var(--color-sev-critical) / <alpha-value>)',
        },
        // Status semantics.
        status: {
          ok: 'rgb(var(--color-status-ok) / <alpha-value>)',
          warn: 'rgb(var(--color-status-warn) / <alpha-value>)',
          danger: 'rgb(var(--color-status-danger) / <alpha-value>)',
          legacy: 'rgb(var(--color-status-legacy) / <alpha-value>)',
          unknown: 'rgb(var(--color-status-unknown) / <alpha-value>)',
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
