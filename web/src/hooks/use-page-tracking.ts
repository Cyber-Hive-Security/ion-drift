import { useEffect, useRef } from "react";
import { useRouterState } from "@tanstack/react-router";
import { useRecordPageView } from "@/api/queries";

const routeMap: Record<string, string> = {
  "/": "dashboard",
  "/interfaces": "interfaces",
  "/ip": "ip",
  "/firewall": "firewall",
  "/connections": "connections",
  "/logs": "logs",
  "/behavior": "behavior",
  "/policy": "policy",
  "/history": "history",
  "/settings": "settings",
  "/statistics": "statistics",
  "/topology": "topology",
  "/network/identities": "identity",
  "/network/backbone": "backbone",
  "/network/inference": "inference",
  "/sankey": "investigation",
  "/setup-wizard": "setup-wizard",
};

function resolvePageName(pathname: string): string {
  // Exact match first
  if (routeMap[pathname]) return routeMap[pathname];

  // Prefix match for parameterized routes
  if (pathname.startsWith("/switches/")) return "switch-detail";
  if (pathname.startsWith("/ip")) return "ip";

  // Fallback: first path segment
  const segment = pathname.split("/").filter(Boolean)[0];
  return segment ?? "unknown";
}

function extractContext(pathname: string, search: Record<string, unknown>): string {
  // Switch detail: device ID from path
  if (pathname.startsWith("/switches/")) {
    const parts = pathname.split("/");
    return parts[2] ?? "";
  }

  // Investigation: vlan or mac from search params
  if (pathname === "/sankey") {
    if (search.mac) return `mac:${search.mac}`;
    if (search.vlan) return `vlan:${search.vlan}`;
  }

  // Behavior: mac from search params
  if (pathname === "/behavior" && search.mac) {
    return `mac:${search.mac}`;
  }

  return "";
}

export function usePageTracking(enabled = true) {
  const routerState = useRouterState();
  const pathname = routerState.location.pathname;
  const search = routerState.location.search as Record<string, unknown>;
  const recordPageView = useRecordPageView();
  const lastTracked = useRef("");

  useEffect(() => {
    const page = resolvePageName(pathname);
    const context = extractContext(pathname, search);
    const key = `${page}:${context}`;

    // Don't track when not authenticated or same page
    if (!enabled) return;
    if (key === lastTracked.current) return;
    lastTracked.current = key;

    // Fire and forget — don't await, don't show errors
    recordPageView.mutate({ page, context });
  }, [pathname, search]); // eslint-disable-line react-hooks/exhaustive-deps
}
