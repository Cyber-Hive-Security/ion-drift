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
import { SpeedtestPage } from "./speedtest";
import { BehaviorPage } from "./behavior";
import { SettingsPage } from "./settings";
import { NotFoundPage } from "./__root";

// Lazy-load the network map page — it pulls in D3 and heavy SVG rendering
// that benefits from being in a separate chunk.
const LazyNetworkMapPage = React.lazy(
  () => import("@/features/network-map/network-map-page").then((m) => ({ default: m.NetworkMapPage })),
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
});

const logsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/logs",
  component: LogsPage,
});

const speedtestRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/speedtest",
  component: SpeedtestPage,
});

const behaviorRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/behavior",
  component: BehaviorPage,
});

class NetworkMapErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { error: Error | null }
> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error("[NetworkMap] Load failed:", error.message, error.stack);
    console.error("[NetworkMap] Component stack:", info.componentStack);
  }
  render() {
    if (this.state.error) {
      return React.createElement("div", { className: "flex h-full flex-col items-center justify-center gap-4 text-muted-foreground" },
        React.createElement("p", null, "Failed to load Network Map."),
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

function NetworkMapWrapper() {
  return React.createElement(
    NetworkMapErrorBoundary, null,
    React.createElement(
      React.Suspense,
      { fallback: React.createElement("div", { className: "flex h-full items-center justify-center text-muted-foreground" }, "Loading Network Map\u2026") },
      React.createElement(LazyNetworkMapPage),
    ),
  );
}

const networkMapRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/network-map",
  component: NetworkMapWrapper,
});

const settingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/settings",
  component: SettingsPage,
});

const routeTree = rootRoute.addChildren([
  indexRoute,
  interfacesRoute,
  ipRoute,
  firewallRoute,
  connectionsRoute,
  logsRoute,
  speedtestRoute,
  behaviorRoute,
  networkMapRoute,
  settingsRoute,
]);

export const router = createRouter({ routeTree });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
