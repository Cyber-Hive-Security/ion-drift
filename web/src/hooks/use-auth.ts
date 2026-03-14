import { useAuthStatus } from "@/api/queries";
import { useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "@/api/client";

export function useAuth() {
  const { data, isLoading } = useAuthStatus();
  const queryClient = useQueryClient();

  const logout = async () => {
    try {
      await apiFetch("/auth/logout", { method: "POST" });
    } catch {
      // Clear local auth state even if server is unreachable
    }
    queryClient.setQueryData(["auth", "status"], {
      authenticated: false,
    });
  };

  const login = async (username: string, password: string) => {
    const res = await fetch("/auth/local-login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({ error: "Login failed" }));
      throw new Error(data.error || "Login failed");
    }
    // Invalidate auth status to trigger re-render
    queryClient.invalidateQueries({ queryKey: ["auth", "status"] });
  };

  return {
    isAuthenticated: data?.authenticated ?? false,
    user: data?.user ?? null,
    isLoading,
    login,
    logout,
  };
}
