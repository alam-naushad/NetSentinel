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
        soc: {
          bg: '#0a0e17',
          surface: '#111827',
          card: '#1e293b',
          border: '#334155',
          hover: '#293548',
          accent: '#3b82f6',
          normal: '#10b981',
          anomaly: '#f59e0b',
          attack: '#ef4444',
          critical: '#dc2626',
        }
      }
    },
  },
  plugins: [],
}
