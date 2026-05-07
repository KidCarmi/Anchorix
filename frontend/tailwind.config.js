/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        anchor: {
          50: "#f4f7fb",
          100: "#e6ecf5",
          500: "#2f5d8c",
          700: "#1f3f63",
          900: "#0e2238",
        },
      },
    },
  },
  plugins: [],
};
