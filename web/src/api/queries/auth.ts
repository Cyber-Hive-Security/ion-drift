import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "../client";
import type {
  AuthConfig,
  AuthStatus,
  RegenerateSessionResponse,
} from "../types";

// Auth

export function useAuthStatus() {
  return useQuery({
    queryKey: ["auth", "status"],
    queryFn: () => apiFetch<AuthStatus>("/auth/status"),
    staleTime: Infinity,
    retry: false,
  });
}

export function useAuthConfig() {
  return useQuery({
    queryKey: ["auth", "config"],
    queryFn: () => apiFetch<AuthConfig>("/auth/config"),
    staleTime: Infinity,
    retry: false,
  });
}

export function useRegenerateSession() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiFetch<RegenerateSessionResponse>(
        "/api/settings/secrets/session/regenerate",
        { method: "POST" },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["settings", "secrets"] });
    },
  });
}
