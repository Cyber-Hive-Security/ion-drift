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
import { NotFoundPage } from "./__root";

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

const routeTree = rootRoute.addChildren([
  indexRoute,
  interfacesRoute,
  ipRoute,
  firewallRoute,
  connectionsRoute,
  logsRoute,
  speedtestRoute,
]);

export const router = createRouter({ routeTree });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
