// ============================================================
//  Network Map — TypeScript Interfaces
// ============================================================

import type { DeviceStatus, InterfaceStatus } from "@/api/types";

export interface VlanConfig {
  name: string;
  code: string;
  color: string;
  subnet: string;
}

export interface NodeTypeConfig {
  icon: string;
  color: string;
  label: string;
}

export interface ContainerInfo {
  id: string;
  name: string;
  ports: string;
  role: string;
}

export interface NetworkNode {
  id: string;
  hostname: string;
  ip: string;
  vlan: number;
  type: string;
  role: string;
  status?: "up" | "down" | "planned";
  parent?: string;
  isHub?: boolean;
  specs: Record<string, string>;
  details: string[];
  containers?: ContainerInfo[];
  // Mutable layout positions — set at runtime
  x: number;
  y: number;
  // Live status data — populated by updateDeviceStatuses
  liveStatus?: DeviceStatus;
}

/** Raw node data without x/y (as authored in data.ts) */
export type NetworkNodeRaw = Omit<NetworkNode, "x" | "y">;

export interface Connection {
  source: string;
  target: string;
  type: string;
}

export interface ConnectionStyle {
  color: string;
  width: number;
  dash: string | null;
  label: string;
}

export interface VlanLayout {
  cx: number;
  cy: number;
  w: number;
  h: number;
}

export interface MapCallbacks {
  onSelectNode: (node: NetworkNode, container?: ContainerInfo) => void;
  onHoverNode: (event: MouseEvent, node: NetworkNode) => void;
  onMoveHover: (event: MouseEvent) => void;
  onLeaveNode: () => void;
  onBackgroundClick: () => void;
}

export interface MapInstance {
  destroy: () => void;
  setShowContainers: (show: boolean) => void;
  search: (term: string) => void;
  highlightNode: (nodeId: string) => void;
  clearSelection: () => void;
  resetView: () => void;
  updateDeviceStatuses: (devices: DeviceStatus[], anomalyMacs?: Set<string>) => void;
  updateInterfaceStatuses: (interfaces: InterfaceStatus[]) => void;
}
