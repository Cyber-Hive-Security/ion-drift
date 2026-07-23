// Smoke floor: module admin page (gate item 4).
//
// This page is the owner-auditability surface for the egress-declaration
// promise: if it silently breaks, module capabilities stop being visible
// and the sovereignty story stops being verifiable. The floor pins:
// list rendering from registry data, capability/egress info display
// (subscribed events, exposed routes, secret fingerprint), the
// enable/disable interaction hitting the right endpoint, and the
// register form posting the right payload.

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { AdminModulesPage } from "../modules-page";
import { mockFetchRoutes, renderWithClient } from "@/test/utils";
import type { RegisteredModule } from "@/api/queries/admin-modules";

function sampleModule(overrides: Partial<RegisteredModule> = {}): RegisteredModule {
  return {
    id: 1,
    name: "drift-watchlist",
    url: "http://127.0.0.1:8991",
    enabled: true,
    manifest: {
      name: "drift-watchlist",
      version: "0.1.0",
      api_version: { major: 1, minor: 1 },
      protocol: "http",
      description: "Passive anomaly watchlist.",
      subscribed_events: ["anomaly_detected"],
      declared_publish: [],
      exposed_routes: [
        { path: "/watchlist", method: "GET", description: null },
      ],
    },
    last_seen_at: null,
    registered_at: 1_750_000_000,
    updated_at: 1_750_000_000,
    secret_fingerprint: "33146f86",
    ...overrides,
  };
}

describe("AdminModulesPage", () => {
  it("renders the empty state when no modules are registered", async () => {
    mockFetchRoutes({ "GET /api/admin/modules": { modules: [] } });
    renderWithClient(<AdminModulesPage />);

    expect(
      await screen.findByText(/no modules registered yet/i),
    ).toBeInTheDocument();
  });

  it("renders registered modules from registry data", async () => {
    mockFetchRoutes({
      "GET /api/admin/modules": { modules: [sampleModule()] },
    });
    renderWithClient(<AdminModulesPage />);

    expect(await screen.findByText("drift-watchlist")).toBeInTheDocument();
    expect(screen.getByText("http://127.0.0.1:8991")).toBeInTheDocument();
    expect(screen.getByText(/enabled/i)).toBeInTheDocument();
  });

  it("displays capability/egress info: subscribed events, exposed routes, secret fingerprint", async () => {
    mockFetchRoutes({
      "GET /api/admin/modules": { modules: [sampleModule()] },
    });
    renderWithClient(<AdminModulesPage />);

    // Subscribed events — what the module is allowed to receive.
    expect(await screen.findByText("anomaly_detected")).toBeInTheDocument();
    // Exposed routes — what the module offers back.
    expect(screen.getByText("/watchlist")).toBeInTheDocument();
    // Secret fingerprint — the divergence-detection primitive.
    expect(screen.getByText("33146f86")).toBeInTheDocument();
    expect(screen.getByText(/secret fingerprint/i)).toBeInTheDocument();
  });

  it("disable button fires POST /api/admin/modules/{name}/disable", async () => {
    const calls = mockFetchRoutes({
      "GET /api/admin/modules": { modules: [sampleModule()] },
      "POST /api/admin/modules/drift-watchlist/disable": { ok: true },
    });
    renderWithClient(<AdminModulesPage />);
    const user = userEvent.setup();

    await user.click(await screen.findByTitle("Disable"));

    await waitFor(() => {
      expect(
        calls.some(
          (c) =>
            c.method === "POST" &&
            c.url === "/api/admin/modules/drift-watchlist/disable",
        ),
      ).toBe(true);
    });
  });

  it("register form POSTs url + shared_secret + api_token to the registry", async () => {
    const secret = "shared-secret-at-least-32-chars-long!";
    const token = "api-token-at-least-32-chars-long-xyz0";
    const calls = mockFetchRoutes({
      "GET /api/admin/modules": { modules: [] },
      "POST /api/admin/modules": { module: sampleModule() },
    });
    renderWithClient(<AdminModulesPage />);
    const user = userEvent.setup();

    await user.click(
      await screen.findByRole("button", { name: /register module/i }),
    );
    await user.type(
      screen.getByPlaceholderText("http://host:port"),
      "http://127.0.0.1:8991",
    );
    const [secretInput, tokenInput] = Array.from(
      document.querySelectorAll<HTMLInputElement>('input[type="password"]'),
    );
    await user.type(secretInput, secret);
    await user.type(tokenInput, token);
    await user.click(screen.getByRole("button", { name: /^register$/i }));

    await waitFor(() => {
      const reg = calls.find(
        (c) => c.method === "POST" && c.url === "/api/admin/modules",
      );
      expect(reg).toBeDefined();
      expect(reg!.body).toEqual({
        url: "http://127.0.0.1:8991",
        shared_secret: secret,
        api_token: token,
      });
    });
  });
});
