import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "../client";
import type {
  NetworkDevice,
  CreateDeviceRequest,
  UpdateDeviceRequest,
  TestConnectionRequest,
  TestConnectionResponse,
  PortMetricsTuple,
  MacTableEntry,
  NeighborEntry,
  RouterInterface,
  SystemResource,
  VlanMembershipEntry,
  PortRoleEntry,
  DevicePort,
  NetworkTopologyResponse,
  TopologyPosition,
  SectorPosition,
  BackboneLink,
  CreateBackboneLinkRequest,
  UpdateBackboneLinkRequest,
  NeighborAlias,
  CreateNeighborAliasRequest,
  InferenceStatus,
  InferenceMacDetail,
  ObservationStats,
  ProvisionInterface,
  PortUtilization,
  NetworkIdentity,
} from "../types";

// ── Network Devices ──────────────────────────────────────────────

export function useDevices() {
  return useQuery({
    queryKey: ["devices"],
    queryFn: () => apiFetch<NetworkDevice[]>("/api/devices"),
    refetchInterval: 30_000,
  });
}

export function useCreateDevice() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: CreateDeviceRequest) =>
      apiFetch<{ id: string; identity: string; message: string }>(
        "/api/devices",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(data),
        },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["devices"] });
    },
  });
}

export function useUpdateDevice() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: UpdateDeviceRequest }) =>
      apiFetch<{ message: string; restart_required?: boolean }>(`/api/devices/${encodeURIComponent(id)}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["devices"] });
    },
  });
}

export function useDeleteDevice() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<{ message: string }>(
        `/api/devices/${encodeURIComponent(id)}`,
        { method: "DELETE" },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["devices"] });
    },
  });
}

export function useTestDeviceConnection() {
  return useMutation({
    mutationFn: (data: TestConnectionRequest) =>
      apiFetch<TestConnectionResponse>("/api/devices/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      }),
  });
}

// ── Device-specific data queries ─────────────────────────────

export function useDeviceResources(deviceId: string | undefined) {
  return useQuery({
    queryKey: ["devices", deviceId, "resources"],
    queryFn: () =>
      apiFetch<SystemResource>(
        `/api/devices/${encodeURIComponent(deviceId!)}/resources`,
      ),
    refetchInterval: 30_000,
    enabled: !!deviceId,
  });
}

export function useDeviceInterfaces(deviceId: string | undefined) {
  return useQuery({
    queryKey: ["devices", deviceId, "interfaces"],
    queryFn: () =>
      apiFetch<RouterInterface[]>(
        `/api/devices/${encodeURIComponent(deviceId!)}/interfaces`,
      ),
    refetchInterval: 30_000,
    enabled: !!deviceId,
  });
}

export function useDevicePorts(deviceId: string | undefined) {
  return useQuery({
    queryKey: ["devices", deviceId, "ports"],
    queryFn: () =>
      apiFetch<PortMetricsTuple[]>(
        `/api/devices/${encodeURIComponent(deviceId!)}/ports`,
      ),
    refetchInterval: 30_000,
    enabled: !!deviceId,
  });
}

export function useDeviceMacTable(deviceId: string | undefined) {
  return useQuery({
    queryKey: ["devices", deviceId, "mac-table"],
    queryFn: () =>
      apiFetch<MacTableEntry[]>(
        `/api/devices/${encodeURIComponent(deviceId!)}/mac-table`,
      ),
    refetchInterval: 60_000,
    enabled: !!deviceId,
  });
}

export function useDeviceNeighbors(deviceId: string | undefined) {
  return useQuery({
    queryKey: ["devices", deviceId, "neighbors"],
    queryFn: () =>
      apiFetch<NeighborEntry[]>(
        `/api/devices/${encodeURIComponent(deviceId!)}/neighbors`,
      ),
    refetchInterval: 60_000,
    enabled: !!deviceId,
  });
}

export function useDeviceVlans(deviceId: string | undefined) {
  return useQuery({
    queryKey: ["devices", deviceId, "vlans"],
    queryFn: () =>
      apiFetch<VlanMembershipEntry[]>(
        `/api/devices/${encodeURIComponent(deviceId!)}/vlans`,
      ),
    refetchInterval: 120_000,
    enabled: !!deviceId,
  });
}

export function useDevicePortRoles(deviceId: string | undefined) {
  return useQuery({
    queryKey: ["devices", deviceId, "port-roles"],
    queryFn: () =>
      apiFetch<PortRoleEntry[]>(
        `/api/devices/${encodeURIComponent(deviceId!)}/port-roles`,
      ),
    refetchInterval: 60_000,
    enabled: !!deviceId,
  });
}

export function useDevicePortList(deviceId: string | undefined) {
  return useQuery({
    queryKey: ["devices", deviceId, "port-list"],
    queryFn: () =>
      apiFetch<DevicePort[]>(
        `/api/devices/${encodeURIComponent(deviceId!)}/port-list`,
      ),
    refetchInterval: 60_000,
    enabled: !!deviceId,
  });
}

// ── Network Topology ─────────────────────────────────────────

export function useNetworkTopology() {
  return useQuery({
    queryKey: ["network", "topology"],
    queryFn: () => apiFetch<NetworkTopologyResponse>("/api/network/topology"),
    refetchInterval: 30_000,
  });
}

export function useTopologyPositions() {
  return useQuery({
    queryKey: ["network", "topology", "positions"],
    queryFn: () => apiFetch<TopologyPosition[]>("/api/network/topology/positions"),
    staleTime: 60_000,
  });
}

export function useRefreshTopology() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiFetch<{ status: string; nodes: number }>("/api/network/topology/refresh", {
        method: "POST",
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "topology"] });
    },
  });
}

export function useUpdateNodePosition() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ nodeId, x, y }: { nodeId: string; x: number; y: number }) =>
      apiFetch<{ status: string }>(
        `/api/network/topology/positions/${encodeURIComponent(nodeId)}`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ x, y }),
        },
      ),
    onSuccess: (_data, { nodeId, x, y }) => {
      // Optimistic cache patch — avoids refetch from stale topology cache
      queryClient.setQueryData<NetworkTopologyResponse>(["network", "topology"], (old) => {
        if (!old) return old;
        return {
          ...old,
          nodes: old.nodes.map((n) =>
            n.id === nodeId ? { ...n, x, y, position_source: "human" } : n,
          ),
        };
      });
    },
  });
}

export function useResetNodePosition() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (nodeId: string) =>
      apiFetch<{ removed: boolean }>(
        `/api/network/topology/positions/${encodeURIComponent(nodeId)}`,
        { method: "DELETE" },
      ),
    onSuccess: (_data, nodeId) => {
      // Optimistic cache patch — mark as auto-positioned
      queryClient.setQueryData<NetworkTopologyResponse>(["network", "topology"], (old) => {
        if (!old) return old;
        return {
          ...old,
          nodes: old.nodes.map((n) =>
            n.id === nodeId ? { ...n, position_source: "auto" } : n,
          ),
        };
      });
    },
  });
}

export function useSectorPositions() {
  return useQuery({
    queryKey: ["network", "topology", "sectors"],
    queryFn: () => apiFetch<SectorPosition[]>("/api/network/topology/sectors"),
    staleTime: 60_000,
  });
}

export function useUpdateSectorPosition() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      vlanId,
      x,
      y,
      width,
      height,
    }: {
      vlanId: number;
      x: number;
      y: number;
      width?: number;
      height?: number;
    }) =>
      apiFetch<{ status: string }>(
        `/api/network/topology/sectors/${vlanId}`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ x, y, width, height }),
        },
      ),
    onSuccess: (_data, { vlanId, x, y, width, height }) => {
      // Optimistic cache patch
      queryClient.setQueryData<NetworkTopologyResponse>(["network", "topology"], (old) => {
        if (!old) return old;
        return {
          ...old,
          vlan_groups: old.vlan_groups.map((g) =>
            g.vlan_id === vlanId
              ? {
                  ...g,
                  bbox_x: x,
                  bbox_y: y,
                  bbox_w: width ?? g.bbox_w,
                  bbox_h: height ?? g.bbox_h,
                  position_source: "human",
                }
              : g,
          ),
        };
      });
    },
  });
}

export function useResetSectorPosition() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (vlanId: number) =>
      apiFetch<{ removed: boolean }>(
        `/api/network/topology/sectors/${vlanId}`,
        { method: "DELETE" },
      ),
    onSuccess: (_data, vlanId) => {
      queryClient.setQueryData<NetworkTopologyResponse>(["network", "topology"], (old) => {
        if (!old) return old;
        return {
          ...old,
          vlan_groups: old.vlan_groups.map((g) =>
            g.vlan_id === vlanId ? { ...g, position_source: "auto" } : g,
          ),
        };
      });
    },
  });
}

export function useBatchUpdateNodePositions() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (positions: { node_id: string; x: number; y: number }[]) =>
      apiFetch<{ status: string; count: number }>(
        "/api/network/topology/positions",
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ positions }),
        },
      ),
    onSuccess: (_data, positions) => {
      // Optimistic cache update — mark all moved nodes as human-positioned
      const posMap = new Map(positions.map((p) => [p.node_id, p]));
      queryClient.setQueryData<NetworkTopologyResponse>(["network", "topology"], (old) => {
        if (!old) return old;
        return {
          ...old,
          nodes: old.nodes.map((n) => {
            const p = posMap.get(n.id);
            return p ? { ...n, x: p.x, y: p.y, position_source: "human" } : n;
          }),
        };
      });
    },
  });
}

// ── Backbone Links ──────────────────────────────────────────────

export function useBackboneLinks() {
  return useQuery({
    queryKey: ["network", "backbone-links"],
    queryFn: () => apiFetch<BackboneLink[]>("/api/network/backbone-links"),
    refetchInterval: 60_000,
  });
}

export function useCreateBackboneLink() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateBackboneLinkRequest) =>
      apiFetch<{ id: number }>("/api/network/backbone-links", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "backbone-links"] });
      queryClient.invalidateQueries({ queryKey: ["network", "topology"] });
    },
  });
}

export function useDeleteBackboneLink() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiFetch<{ removed: boolean }>(`/api/network/backbone-links/${id}`, {
        method: "DELETE",
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "backbone-links"] });
      queryClient.invalidateQueries({ queryKey: ["network", "topology"] });
    },
  });
}

export function useUpdateBackboneLink() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...body }: { id: number } & UpdateBackboneLinkRequest) =>
      apiFetch<{ updated: boolean }>(`/api/network/backbone-links/${id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "backbone-links"] });
      queryClient.invalidateQueries({ queryKey: ["network", "topology"] });
    },
  });
}

// ── Neighbor Aliases ────────────────────────────────────────────

export function useNeighborAliases() {
  return useQuery({
    queryKey: ["network", "neighbor-aliases"],
    queryFn: () => apiFetch<NeighborAlias[]>("/api/network/neighbor-aliases"),
    refetchInterval: 60_000,
  });
}

export function useCreateNeighborAlias() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateNeighborAliasRequest) =>
      apiFetch<{ id: number }>("/api/network/neighbor-aliases", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "neighbor-aliases"] });
      queryClient.invalidateQueries({ queryKey: ["network", "topology"] });
    },
  });
}

export function useDeleteNeighborAlias() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiFetch<{ removed: boolean }>(`/api/network/neighbor-aliases/${id}`, {
        method: "DELETE",
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network", "neighbor-aliases"] });
      queryClient.invalidateQueries({ queryKey: ["network", "topology"] });
    },
  });
}

// ── Infrastructure Identities ───────────────────────────────────

export function useInfrastructureIdentities() {
  return useQuery({
    queryKey: ["network", "identities", "infrastructure"],
    queryFn: () => apiFetch<NetworkIdentity[]>("/api/network/identities/infrastructure"),
    refetchInterval: 60_000,
  });
}

// ── Topology Inference ──────────────────────────────────────────

export function useInferenceStatus() {
  return useQuery({
    queryKey: ["network", "inference", "status"],
    queryFn: () => apiFetch<InferenceStatus>("/api/network/inference/status"),
    refetchInterval: 30_000,
  });
}

export function useInferenceMacDetail(mac: string | null) {
  return useQuery({
    queryKey: ["network", "inference", "mac", mac],
    queryFn: () =>
      apiFetch<InferenceMacDetail>(
        `/api/network/inference/mac/${encodeURIComponent(mac!)}`,
      ),
    enabled: !!mac,
    refetchInterval: 30_000,
  });
}

export function useInferenceObservations() {
  return useQuery({
    queryKey: ["network", "inference", "observations"],
    queryFn: () =>
      apiFetch<ObservationStats>("/api/network/inference/observations"),
    refetchInterval: 30_000,
  });
}

// ── Port Utilization ─────────────────────────────────────────

export function usePortUtilization(deviceId: string | undefined) {
  return useQuery({
    queryKey: ["devices", deviceId, "port-utilization"],
    queryFn: () => apiFetch<PortUtilization[]>(`/api/devices/${encodeURIComponent(deviceId!)}/port-utilization`),
    enabled: !!deviceId,
    refetchInterval: 10_000,
    staleTime: 8_000,
  });
}

// ── Provision / Setup Wizard ────────────────────────────────────

export function useProvisionInterfaces(deviceId: string | null) {
  return useQuery({
    queryKey: ["provision", "interfaces", deviceId],
    queryFn: () =>
      apiFetch<ProvisionInterface[]>(
        `/api/devices/${encodeURIComponent(deviceId!)}/provision/interfaces`,
      ),
    enabled: !!deviceId,
  });
}
