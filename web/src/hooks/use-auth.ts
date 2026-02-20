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

  return {
    isAuthenticated: data?.authenticated ?? false,
    user: data?.user ?? null,
    isLoading,
    logout,
  };
}
