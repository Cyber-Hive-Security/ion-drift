import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "../client";
import type {
  NetworkIdentity,
  PortRoleEntry,
  IdentityStats,
  ClientBandwidth,
  UpdateIdentityRequest,
  ObservedService,
  DeviceDisposition,
  PortMacBinding,
  PortViolation,
} from "../types";

// Network-wide correlation queries

export function useNetworkIdentities() {
  return useQuery({
    queryKey: ["network", "identities"],
    queryFn: () => apiFetch<NetworkIdentity[]>("/api/network/identities"),
    refetchInterval: 60_000,
  });
}

export function useNetworkPortRoles() {
  return useQuery({
    queryKey: ["network", "port-roles"],
    queryFn: () => apiFetch<PortRoleEntry[]>("/api/network/port-roles"),
    refetchInterval: 60_000,
  });
}

// Identity management

export function useIdentityStats() {
  return useQuery({
    queryKey: ["network", "identities", "stats"],
    queryFn: () => apiFetch<IdentityStats>("/api/network/identities/stats"),
    refetchInterval: 30_000,
  });
}

export function useClientBandwidth() {
  return useQuery({
    queryKey: ["network", "identities", "bandwidth"],
    queryFn: () => apiFetch<ClientBandwidth[]>("/api/network/identities/bandwidth"),
    refetchInterval: 30_000,
  });
}

export function useReviewQueue(limit = 50, offset = 0) {
  return useQuery({
    queryKey: ["network", "identities", "review-queue", limit, offset],
    queryFn: () =>
      apiFetch<NetworkIdentity[]>(
        `/api/network/identities/review-queue?limit=${limit}&offset=${offset}`
      ),
    refetchInterval: 30_000,
  });
}

export function useUpdateIdentity() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ mac, data }: { mac: string; data: UpdateIdentityRequest }) =>
      apiFetch<{ updated: boolean }>(
        `/api/network/identities/${encodeURIComponent(mac)}`,
        { method: "PUT", body: JSON.stringify(data) }
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "identities"] });
    },
  });
}

export function useBulkConfirmIdentities() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (macs: string[]) =>
      apiFetch<{ confirmed: number }>("/api/network/identities/bulk-confirm", {
        method: "POST",
        body: JSON.stringify({ macs }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "identities"] });
    },
  });
}

export function useResetIdentityField() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ mac, field }: { mac: string; field: string }) =>
      apiFetch<{ reset: boolean }>(
        `/api/network/identities/${encodeURIComponent(mac)}/fields/${encodeURIComponent(field)}`,
        { method: "DELETE" }
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "identities"] });
    },
  });
}

// Observed services (passive discovery)

export function useObservedServices(ip?: string) {
  const params = ip ? `?ip=${encodeURIComponent(ip)}` : "";
  return useQuery({
    queryKey: ["network", "services", ip ?? "all"],
    queryFn: () => apiFetch<ObservedService[]>(`/api/network/services${params}`),
    refetchInterval: 60_000,
  });
}

// Disposition

export function useSetDisposition() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ mac, disposition }: { mac: string; disposition: DeviceDisposition }) =>
      apiFetch<{ updated: boolean }>(
        `/api/network/identities/${encodeURIComponent(mac)}/disposition`,
        { method: "PUT", body: JSON.stringify({ disposition }) }
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "identities"] });
      queryClient.invalidateQueries({ queryKey: ["network", "topology"] });
    },
  });
}

export function useBulkDisposition() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ macs, disposition }: { macs: string[]; disposition: DeviceDisposition }) =>
      apiFetch<{ updated: number }>("/api/network/identities/bulk-disposition", {
        method: "POST",
        body: JSON.stringify({ macs, disposition }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "identities"] });
    },
  });
}

// Port MAC bindings

export function usePortBindings(deviceId?: string) {
  const params = deviceId ? `?device_id=${encodeURIComponent(deviceId)}` : "";
  return useQuery({
    queryKey: ["network", "port-bindings", deviceId ?? "all"],
    queryFn: () => apiFetch<PortMacBinding[]>(`/api/network/port-bindings${params}`),
    refetchInterval: 60_000,
  });
}

export function usePortBindingsForDevice(deviceId: string) {
  return useQuery({
    queryKey: ["network", "port-bindings", deviceId],
    queryFn: () =>
      apiFetch<PortMacBinding[]>(
        `/api/network/port-bindings/${encodeURIComponent(deviceId)}`
      ),
    refetchInterval: 60_000,
  });
}

export function useCreatePortBinding() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: { device_id: string; port_name: string; expected_mac: string }) =>
      apiFetch<{ created: boolean }>("/api/network/port-bindings", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "port-bindings"] });
      queryClient.invalidateQueries({ queryKey: ["network", "port-violations"] });
    },
  });
}

export function useUpdatePortBinding() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      device_id,
      port_name,
      expected_mac,
    }: {
      device_id: string;
      port_name: string;
      expected_mac: string;
    }) =>
      apiFetch<{ updated: boolean }>(
        `/api/network/port-bindings/${encodeURIComponent(device_id)}/${encodeURIComponent(port_name)}`,
        { method: "PUT", body: JSON.stringify({ expected_mac }) }
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "port-bindings"] });
      queryClient.invalidateQueries({ queryKey: ["network", "port-violations"] });
    },
  });
}

export function useDeletePortBinding() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ device_id, port_name }: { device_id: string; port_name: string }) =>
      apiFetch<{ deleted: boolean }>(
        `/api/network/port-bindings/${encodeURIComponent(device_id)}/${encodeURIComponent(port_name)}`,
        { method: "DELETE" }
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "port-bindings"] });
      queryClient.invalidateQueries({ queryKey: ["network", "port-violations"] });
    },
  });
}

// Port violations

export function usePortViolations(deviceId?: string) {
  const params = deviceId ? `?device_id=${encodeURIComponent(deviceId)}` : "";
  return useQuery({
    queryKey: ["network", "port-violations", deviceId ?? "all"],
    queryFn: () => apiFetch<PortViolation[]>(`/api/network/port-violations${params}`),
    refetchInterval: 30_000,
  });
}

export function usePortViolationsForDevice(deviceId: string) {
  return useQuery({
    queryKey: ["network", "port-violations", deviceId],
    queryFn: () =>
      apiFetch<PortViolation[]>(
        `/api/network/port-violations/${encodeURIComponent(deviceId)}`
      ),
    refetchInterval: 30_000,
  });
}

export function useResolvePortViolation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiFetch<{ resolved: boolean }>(
        `/api/network/port-violations/${id}/resolve`,
        { method: "PUT" }
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "port-violations"] });
    },
  });
}
