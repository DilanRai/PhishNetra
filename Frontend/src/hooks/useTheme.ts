import { useState, useEffect, useCallback } from "react";

export type Theme = "dark" | "light";

export function useTheme() {
  const [theme, setThemeState] = useState<Theme>(() => {
    // 1. Check localStorage first (user preference)
    const stored = localStorage.getItem("phishnetra-theme") as Theme | null;
    if (stored === "light" || stored === "dark") return stored;

    // 2. Fall back to system preference
    if (window.matchMedia?.("(prefers-color-scheme: light)").matches)
      return "light";

    // 3. Default to dark (SOC product)
    return "dark";
  });

  // Apply theme to <html> element
  useEffect(() => {
    const html = document.documentElement;

    // Brief no-transition window to avoid flash on initial load
    html.classList.add("theme-transitioning");
    html.setAttribute("data-theme", theme);

    requestAnimationFrame(() => {
      html.classList.remove("theme-transitioning");
    });

    localStorage.setItem("phishnetra-theme", theme);
  }, [theme]);

  const toggleTheme = useCallback(() => {
    setThemeState((t) => (t === "dark" ? "light" : "dark"));
  }, []);

  const setTheme = useCallback((t: Theme) => {
    setThemeState(t);
  }, []);

  return {
    theme,
    toggleTheme,
    setTheme,
    isDark: theme === "dark",
    isLight: theme === "light",
  };
}
