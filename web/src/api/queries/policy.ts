import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "../client";
import type {
  PolicyDeviation,
  PolicyDeviationCounts,
  AttackTechniqueDb,
} from "../types";

export function usePolicyDeviations(params?: {
  status?: string;
  mac?: string;
  type?: string;
  limit?: number;
}) {
  const qs = new URLSearchParams();
  if (params?.status) qs.set("status", params.status);
  if (params?.mac) qs.set("mac", params.mac);
  if (params?.type) qs.set("type", params.type);
  if (params?.limit) qs.set("limit", String(params.limit));
  const q = qs.toString();
  return useQuery({
    queryKey: ["policy-deviations", params],
    queryFn: () =>
      apiFetch<PolicyDeviation[]>(
        `/api/policy/deviations${q ? `?${q}` : ""}`,
      ),
    refetchInterval: 60_000,
  });
}

export function useDevicePolicyDeviations(mac: string | null) {
  return useQuery({
    queryKey: ["policy-deviations", "device", mac],
    queryFn: () =>
      apiFetch<PolicyDeviation[]>(
        `/api/policy/deviations/device/${encodeURIComponent(mac!)}`,
      ),
    enabled: mac != null,
    refetchInterval: 60_000,
  });
}

export function usePolicyDeviationCounts() {
  return useQuery({
    queryKey: ["policy-deviations", "counts"],
    queryFn: () =>
      apiFetch<PolicyDeviationCounts>("/api/policy/deviations/counts"),
    refetchInterval: 60_000,
  });
}

export function useResolvePolicyDeviation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, action }: { id: number; action: string }) =>
      apiFetch<{ ok: boolean }>(`/api/policy/deviations/${id}/resolve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["policy-deviations"] });
      qc.invalidateQueries({ queryKey: ["policy"] });
    },
  });
}

export function useDeleteAllDeviations() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiFetch<{ ok: boolean; deleted: number }>("/api/policy/deviations", {
        method: "DELETE",
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["policy-deviations"] });
      qc.invalidateQueries({ queryKey: ["policy"] });
      qc.invalidateQueries({ queryKey: ["behavior"] });
    },
  });
}

export interface CreatePolicyRequest {
  service: string;
  protocol: string | null;
  port: number | null;
  authorized_targets: string[];
  vlan_scope: number[] | null;
  priority: string;
  force?: boolean;
}

export interface UpdatePolicyRequest {
  authorized_targets: string[];
  vlan_scope: number[] | null;
  priority: string;
}

export function useCreatePolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: CreatePolicyRequest) =>
      apiFetch<{ ok: boolean; id: number }>("/api/policy", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(req),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["policy"] });
    },
  });
}

export function useUpdatePolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...req }: UpdatePolicyRequest & { id: number }) =>
      apiFetch<{ ok: boolean }>(`/api/policy/${id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(req),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["policy"] });
    },
  });
}

export function useDeletePolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiFetch<{ ok: boolean }>(`/api/policy/${id}`, {
        method: "DELETE",
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["policy"] });
    },
  });
}

export function useAttackTechniques() {
  return useQuery({
    queryKey: ["attack-techniques"],
    queryFn: () => apiFetch<AttackTechniqueDb>("/api/attack-techniques"),
    staleTime: Infinity,
  });
}
