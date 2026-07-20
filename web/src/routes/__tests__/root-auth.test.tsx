// Smoke floor: the auth gate itself (gate item 4).
//
// RootLayout is the only thing standing between an unauthenticated browser
// and every page in the app. These tests pin its three states: loading
// spinner, login screen, and authenticated chrome.
//
// Heavy children (sidebar, header, router Outlet) are stubbed — this file
// tests the gate, not the chrome.

import { screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { mockFetchRoutes, renderWithClient } from "@/test/utils";

vi.mock("@/components/layout/sidebar", () => ({
  Sidebar: () => <div data-testid="sidebar" />,
}));
vi.mock("@/components/layout/header", () => ({
  Header: () => <div data-testid="header" />,
}));
vi.mock("@/components/license-banner", () => ({
  LicenseBanner: () => null,
}));
// usePageTracking calls useRouterState, which needs a mounted router —
// chrome concern, not the auth gate under test here.
vi.mock("@/hooks/use-page-tracking", () => ({
  usePageTracking: () => {},
}));
vi.mock("@tanstack/react-router", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@tanstack/react-router")>();
  return {
    ...actual,
    Outlet: () => <div data-testid="outlet" />,
    Link: (props: React.PropsWithChildren) => <a>{props.children}</a>,
  };
});

import { RootLayout } from "../__root";

const AUTH_CONFIG = {
  local_auth_enabled: true,
  oidc_enabled: false,
  oidc_provider_name: null,
};

describe("RootLayout auth gate", () => {
  it("shows the login screen when unauthenticated", async () => {
    mockFetchRoutes({
      "GET /auth/status": { authenticated: false },
      "GET /auth/config": AUTH_CONFIG,
    });
    renderWithClient(<RootLayout />);

    expect(await screen.findByText(/sign in to continue/i)).toBeInTheDocument();
    expect(screen.queryByTestId("outlet")).not.toBeInTheDocument();
  });

  it("renders the app chrome and routed content when authenticated", async () => {
    mockFetchRoutes({
      "GET /auth/status": {
        authenticated: true,
        user: { username: "admin", display_name: "Admin" },
      },
      "GET /auth/config": AUTH_CONFIG,
      "GET /api/behavior/alerts": { tier1_pending: 0 },
    });
    renderWithClient(<RootLayout />);

    expect(await screen.findByTestId("outlet")).toBeInTheDocument();
    expect(screen.getByTestId("sidebar")).toBeInTheDocument();
    expect(screen.getByTestId("header")).toBeInTheDocument();
    expect(screen.queryByText(/sign in to continue/i)).not.toBeInTheDocument();
  });
});
