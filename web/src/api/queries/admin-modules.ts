import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "../client";

// ── Types (mirror crates/ion-drift-module-api wire types) ─────────────

export interface ApiVersion {
  major: number;
  minor: number;
}

export interface RouteDescriptor {
  path: string;
  method: string;
  description?: string | null;
}

export interface Manifest {
  name: string;
  version: string;
  api_version: ApiVersion;
  protocol: "http";
  description?: string | null;
  subscribed_events: string[];
  exposed_routes: RouteDescriptor[];
}

export interface RegisteredModule {
  id: number;
  name: string;
  url: string;
  enabled: boolean;
  manifest: Manifest;
  last_seen_at: number | null;
  registered_at: number;
  updated_at: number;
}

export interface RegisterModuleRequest {
  url: string;
  shared_secret: string;
  api_token: string;
}

// ── Queries ───────────────────────────────────────────────────────────

const MODULES_KEY = ["admin", "modules"] as const;

export function useAdminModules() {
  return useQuery({
    queryKey: MODULES_KEY,
    queryFn: () => apiFetch<{ modules: RegisteredModule[] }>("/api/admin/modules"),
    refetchInterval: 15_000,
  });
}

export function useRegisterModule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: RegisterModuleRequest) =>
      apiFetch<{ module: RegisteredModule }>("/api/admin/modules", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: MODULES_KEY });
    },
  });
}

export function useUnregisterModule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (name: string) =>
      apiFetch<{ ok: boolean }>(`/api/admin/modules/${encodeURIComponent(name)}`, {
        method: "DELETE",
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: MODULES_KEY });
    },
  });
}

export function useSetModuleEnabled() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ name, enabled }: { name: string; enabled: boolean }) =>
      apiFetch<{ ok: boolean }>(
        `/api/admin/modules/${encodeURIComponent(name)}/${enabled ? "enable" : "disable"}`,
        { method: "POST" },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: MODULES_KEY });
    },
  });
}

/**
 * Probe a registered module's /manifest endpoint. Returns the fresh
 * manifest on success. Does not mutate the stored manifest —
 * refreshing is a separate endpoint if we need it later.
 */
export function useTestModuleConnection() {
  return useMutation({
    mutationFn: (name: string) =>
      apiFetch<{ manifest: Manifest }>(
        `/api/admin/modules/${encodeURIComponent(name)}/test`,
        { method: "POST" },
      ),
  });
}
