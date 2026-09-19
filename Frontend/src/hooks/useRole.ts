// FILE: src/hooks/useRole.ts
import { useState, useEffect } from "react";

type Role = "admin" | "analyst" | "viewer";

export function useRole() {
  const readRole = (): Role => {
    const token = localStorage.getItem("pg_token");
    if (token) {
      try {
        const payload = token.split(".")[1];
        const json = JSON.parse(
          atob(payload.replace(/-/g, "+").replace(/_/g, "/"))
        );
        // Check expiry
        if (json?.exp && json.exp * 1000 < Date.now()) {
          localStorage.removeItem("pg_token");
          localStorage.removeItem("pg_user");
          return "viewer";
        }
        if (json?.role) return json.role as Role;
      } catch {}
    }
    const user = JSON.parse(localStorage.getItem("pg_user") || "null");
    return (user?.role as Role) || "viewer";
  };

  const [role, setRole] = useState<Role>(readRole);

  useEffect(() => {
    const sync = () => setRole(readRole());
    window.addEventListener("storage", sync);
    window.addEventListener("focus", sync);
    return () => {
      window.removeEventListener("storage", sync);
      window.removeEventListener("focus", sync);
    };
  }, []);

  return {
    role,
    isAdmin:   role === "admin",
    isAnalyst: role === "analyst",
    isViewer:  role === "viewer",
    canWrite:  role === "admin" || role === "analyst",
    canDelete: role === "admin",
  };
}
