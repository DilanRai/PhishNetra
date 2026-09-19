/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      fontFamily: {
        sans: [
          "Geist",
          "-apple-system",
          "BlinkMacSystemFont",
          "system-ui",
          "sans-serif",
        ],
        mono: ["Geist Mono", "JetBrains Mono", "Fira Code", "monospace"],
      },
      colors: {
        // Design system tokens mapped to Tailwind
        accent: "#34d399",
        danger: "#f87171",
        warning: "#fbbf24",
        info: "#60a5fa",
        surface: "#0c1119",
        elevated: "#101620",
        card: "#131b28",
        border: "#1c2840",
      },
      borderRadius: {
        "4xl": "2rem",
      },
      screens: {
        xs: "480px",
      },
      // Allow dvh unit
      height: {
        dvh: "100dvh",
      },
      minHeight: {
        dvh: "100dvh",
      },
      // Custom ease curves
      transitionTimingFunction: {
        "out-expo": "cubic-bezier(0.23, 1, 0.32, 1)",
        "in-out-expo": "cubic-bezier(0.77, 0, 0.175, 1)",
        spring: "cubic-bezier(0.34, 1.56, 0.64, 1)",
      },
      animation: {
        shimmer: "shimmer 1.6s ease-in-out infinite",
        "status-pulse": "status-pulse 2s ease-in-out infinite",
        "threat-ring": "threat-ring 2s ease-out infinite",
        "safe-ring": "safe-ring 2.5s ease-out infinite",
        "scan-sweep": "scan-sweep 3s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};
