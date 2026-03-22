import React from "react";
import {
  createRouter,
  createRoute,
  createRootRoute,
} from "@tanstack/react-router";
import { RootLayout } from "./__root";
import { DashboardPage } from "./index";
import { InterfacesPage } from "./interfaces";
import { IpPage } from "./ip";
import { FirewallPage } from "./firewall";
import { ConnectionsPage } from "./connections";
import { LogsPage } from "./logs";
import { BehaviorPage } from "./behavior";
import { PolicyPage } from "./policy";
import { HistoryPage } from "./history";
import { SettingsPage } from "./settings";
import { NotFoundPage } from "./__root";
import { SwitchDetailPageWrapper } from "@/features/switch-detail/switch-detail-page";
import IdentityManagerPage from "@/features/identity/identity-manager-page";
import BackboneLinksPage from "@/features/backbone/backbone-links-page";
import { InferencePage } from "@/features/inference/inference-page";
import { SetupWizard } from "@/features/provision/setup-wizard";
import { SankeyInvestigationPage } from "@/features/sankey/sankey-investigation-page";
import { StatisticsPage } from "@/features/statistics/statistics-page";

// Lazy-load the auto-generated topology page (separate D3 chunk).
const LazyTopologyPage = React.lazy(
  () => import("@/features/topology/topology-page").then((m) => ({ default: m.TopologyPage })),
);

const rootRoute = createRootRoute({
  component: RootLayout,
  notFoundComponent: NotFoundPage,
});

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: DashboardPage,
});

const interfacesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/interfaces",
  component: InterfacesPage,
});

const ipRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/ip",
  component: IpPage,
});

const firewallRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/firewall",
  component: FirewallPage,
});

const connectionsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/connections",
  component: ConnectionsPage,
  validateSearch: (search: Record<string, unknown>): {
    tab?: string;
    country?: string;
    city?: string;
    protocol?: string;
    dst_port?: string;
    src_ip?: string;
    dst_ip?: string;
  } => ({
    tab: (search.tab as string) || undefined,
    country: (search.country as string) || undefined,
    city: (search.city as string) || undefined,
    protocol: (search.protocol as string) || undefined,
    dst_port: (search.dst_port as string) || undefined,
    src_ip: (search.src_ip as string) || undefined,
    dst_ip: (search.dst_ip as string) || undefined,
  }),
});

const logsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/logs",
  component: LogsPage,
});

const behaviorRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/behavior",
  component: BehaviorPage,
  validateSearch: (search: Record<string, unknown>): { mac?: string } => ({
    mac: (search.mac as string) || undefined,
  }),
});

const policyRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/policy",
  component: PolicyPage,
});

const historyRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/history",
  component: HistoryPage,
  validateSearch: (search: Record<string, unknown>): {
    country?: string;
  } => ({
    country: (search.country as string) || undefined,
  }),
});

class TopologyErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { error: Error | null }
> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error("[Topology] Load failed:", error.message, error.stack);
    console.error("[Topology] Component stack:", info.componentStack);
  }
  render() {
    if (this.state.error) {
      return React.createElement("div", { className: "flex h-full flex-col items-center justify-center gap-4 text-muted-foreground" },
        React.createElement("p", null, "Failed to load Topology."),
        React.createElement("p", { className: "text-xs text-destructive max-w-md text-center" }, this.state.error.message),
        React.createElement("button", {
          className: "rounded border border-border px-4 py-2 text-sm hover:bg-accent",
          onClick: () => this.setState({ error: null }),
        }, "Retry"),
      );
    }
    return this.props.children;
  }
}

function TopologyWrapper() {
  return React.createElement(
    TopologyErrorBoundary, null,
    React.createElement(
      React.Suspense,
      { fallback: React.createElement("div", { className: "flex h-full items-center justify-center text-muted-foreground" }, "Loading Topology\u2026") },
      React.createElement(LazyTopologyPage),
    ),
  );
}

const topologyRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/topology",
  component: TopologyWrapper,
});

const switchDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/switches/$deviceId",
  component: SwitchDetailPageWrapper,
});

const identitiesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/network/identities",
  component: IdentityManagerPage,
});

const backboneRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/network/backbone",
  component: BackboneLinksPage,
});

const inferenceRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/network/inference",
  component: InferencePage,
});

const sankeyRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sankey",
  component: SankeyInvestigationPage,
  validateSearch: (search: Record<string, unknown>): {
    vlan?: string;
    dest?: string;
    mac?: string;
    country?: string;
  } => ({
    vlan: (search.vlan as string) || undefined,
    dest: (search.dest as string) || undefined,
    mac: (search.mac as string) || undefined,
    country: (search.country as string) || undefined,
  }),
});

const settingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/settings",
  component: SettingsPage,
  validateSearch: (search: Record<string, unknown>): { tab?: string } => ({
    tab: (search.tab as string) || undefined,
  }),
});

const statisticsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/statistics",
  component: StatisticsPage,
});

const setupWizardRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/setup-wizard",
  component: SetupWizard,
});

const routeTree = rootRoute.addChildren([
  indexRoute,
  interfacesRoute,
  ipRoute,
  firewallRoute,
  connectionsRoute,
  logsRoute,
  behaviorRoute,
  policyRoute,
  historyRoute,
  topologyRoute,
  switchDetailRoute,
  identitiesRoute,
  backboneRoute,
  inferenceRoute,
  sankeyRoute,
  settingsRoute,
  statisticsRoute,
  setupWizardRoute,
]);

export const router = createRouter({ routeTree });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
