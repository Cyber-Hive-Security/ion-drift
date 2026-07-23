// Smoke floor: findings / investigation views (gate item 4).
//
// FindingsPage against a fetch-mocked /api/findings. Pins: the list renders
// module findings, the empty state renders, a finding's detail view opens
// on row click without error, and acknowledging fires the right API call.

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { FindingsPage } from "../findings";
import { mockFetchRoutes, renderWithClient } from "@/test/utils";
import type { Finding } from "@/api/queries/findings";

function sampleFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 7,
    module_name: "drift-watchlist",
    finding_id: "wl-0007",
    title: "Repeated anomalies from workstation",
    narrative: "Device tripped the anomaly detector 4 times inside the retention window.",
    severity: "medium",
    category: "behavior",
    recommended_actions: ["Review the device's recent connections"],
    evidence: [],
    // Empty on purpose: DeviceLink needs router context the smoke floor
    // doesn't mount.
    device_macs: [],
    metadata: null,
    timestamp: 1_750_000_000,
    received_at: 1_750_000_000,
    envelope_event_id: null,
    envelope_nonce: null,
    status: "open",
    acknowledged_at: null,
    acknowledged_by: null,
    resolved_at: null,
    resolved_by: null,
    resolution_note: null,
    ...overrides,
  };
}

describe("FindingsPage", () => {
  it("renders findings from the API", async () => {
    mockFetchRoutes({
      "GET /api/findings": [sampleFinding()],
      "GET /api/findings/summary": { open: 1, acknowledged: 0, resolved: 0 },
    });
    renderWithClient(<FindingsPage />);

    expect(
      await screen.findByText("Repeated anomalies from workstation"),
    ).toBeInTheDocument();
    // Appears in both the module filter dropdown and the table row.
    expect(screen.getAllByText("drift-watchlist").length).toBeGreaterThan(0);
  });

  it("renders the empty state when there are no findings", async () => {
    mockFetchRoutes({
      "GET /api/findings": [],
      "GET /api/findings/summary": { open: 0, acknowledged: 0, resolved: 0 },
    });
    renderWithClient(<FindingsPage />);

    expect(
      await screen.findByText(/no findings match the current filters/i),
    ).toBeInTheDocument();
  });

  it("opens the detail view on row click without error", async () => {
    mockFetchRoutes({
      "GET /api/findings": [sampleFinding()],
      "GET /api/findings/summary": { open: 1, acknowledged: 0, resolved: 0 },
    });
    renderWithClient(<FindingsPage />);
    const user = userEvent.setup();

    await user.click(
      await screen.findByText("Repeated anomalies from workstation"),
    );

    // Detail view = narrative + recommended actions.
    expect(
      await screen.findByText(/tripped the anomaly detector 4 times/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/review the device's recent connections/i),
    ).toBeInTheDocument();
  });

  it("acknowledge fires POST /api/findings/{id}/acknowledge", async () => {
    const calls = mockFetchRoutes({
      "GET /api/findings": [sampleFinding()],
      "GET /api/findings/summary": { open: 1, acknowledged: 0, resolved: 0 },
      "POST /api/findings/7/acknowledge": { id: 7, status: "acknowledged" },
    });
    renderWithClient(<FindingsPage />);
    const user = userEvent.setup();

    await user.click(
      await screen.findByText("Repeated anomalies from workstation"),
    );
    // Exact match: the status filter bar also has an "Acknowledged" button.
    await user.click(
      await screen.findByRole("button", { name: /^acknowledge$/i }),
    );

    await waitFor(() => {
      expect(
        calls.some(
          (c) =>
            c.method === "POST" && c.url === "/api/findings/7/acknowledge",
        ),
      ).toBe(true);
    });
  });
});
