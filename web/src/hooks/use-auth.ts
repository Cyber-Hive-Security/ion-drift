import { useAuthStatus } from "@/api/queries";
import { useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "@/api/client";

export function useAuth() {
  const { data, isLoading } = useAuthStatus();
  const queryClient = useQueryClient();

  const logout = async () => {
    await apiFetch("/auth/logout", { method: "POST" });
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
