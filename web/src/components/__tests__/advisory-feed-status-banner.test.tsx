import { screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AdvisoryFeedStatusBanner } from "../advisory-feed-status-banner";
import { mockFetchRoutes, renderWithClient } from "@/test/utils";

const base = { set_by: "scott", set_at: 1_758_700_000, sources: [], stale: false };

describe("AdvisoryFeedStatusBanner", () => {
  it("feed off: says checks continue against the newest downloaded data", async () => {
    mockFetchRoutes({
      "GET /api/advisory/feed": {
        ...base,
        consent: "off",
        sources: [
          { source: "nvd", last_success_at: 1_758_000_000, last_attempt_at: 1_758_000_000, last_error: null, records: 83 },
          { source: "kev", last_success_at: 1_758_600_000, last_attempt_at: 1_758_600_000, last_error: null, records: 4 },
        ],
      },
    });
    renderWithClient(<AdvisoryFeedStatusBanner />);
    const banner = await screen.findByRole("status");
    expect(banner).toHaveTextContent(/vulnerability feed is off/i);
    expect(banner).toHaveTextContent(
      `Checks continue against vulnerability data last downloaded on ${new Date(1_758_600_000 * 1000).toLocaleDateString()}`,
    );
    expect(banner).toHaveTextContent(/new vulnerabilities are not learned/i);
    expect(banner).toHaveTextContent("An administrator can change this in Settings → Security.");
    expect(banner).not.toHaveTextContent(/only advisories bundled/i);
  });

  it("feed off with nothing ever downloaded: only bundled advisories are evaluated", async () => {
    mockFetchRoutes({
      "GET /api/advisory/feed": {
        ...base,
        consent: "off",
        sources: [{ source: "nvd", last_success_at: null, last_attempt_at: 1_758_000_000, last_error: "HTTP 503", records: 0 }],
      },
    });
    renderWithClient(<AdvisoryFeedStatusBanner />);
    const banner = await screen.findByRole("status");
    expect(banner).toHaveTextContent(/vulnerability feed is off/i);
    expect(banner).toHaveTextContent(/only advisories bundled with this release are evaluated/i);
    expect(banner).toHaveTextContent(/nothing was ever downloaded/i);
    expect(banner).toHaveTextContent(/new vulnerabilities are not learned/i);
    expect(banner).toHaveTextContent("An administrator can change this in Settings → Security.");
  });

  it("warns when data is stale and shows the last error", async () => {
    mockFetchRoutes({
      "GET /api/advisory/feed": {
        ...base,
        consent: "on",
        stale: true,
        sources: [{ source: "nvd", last_success_at: 1_758_000_000, last_attempt_at: 1_758_700_000, last_error: "HTTP 503", records: 83 }],
      },
    });
    renderWithClient(<AdvisoryFeedStatusBanner />);
    const banner = await screen.findByRole("status");
    expect(banner).toHaveTextContent(/stale since/i);
    expect(banner).toHaveTextContent("HTTP 503");
  });

  it("says 'first fetch' when any source has never succeeded", async () => {
    mockFetchRoutes({
      "GET /api/advisory/feed": {
        ...base,
        consent: "on",
        stale: true,
        sources: [
          { source: "nvd", last_success_at: null, last_attempt_at: 1_758_700_000, last_error: "HTTP 503", records: 0 },
          { source: "kev", last_success_at: 1_758_699_400, last_attempt_at: 1_758_699_400, last_error: null, records: 4 },
        ],
      },
    });
    renderWithClient(<AdvisoryFeedStatusBanner />);
    const banner = await screen.findByRole("status");
    expect(banner).toHaveTextContent(/stale since first fetch/i);
    expect(banner).toHaveTextContent("NVD last error: HTTP 503");
  });

  it("is silent when the feed is on and fresh", async () => {
    mockFetchRoutes({ "GET /api/advisory/feed": { ...base, consent: "on" } });
    const { container } = renderWithClient(<AdvisoryFeedStatusBanner />);
    await waitFor(() => expect(container).toBeEmptyDOMElement());
  });
});
