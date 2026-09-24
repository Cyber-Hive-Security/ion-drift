// Vulnerability feed consent: the dialog blocks admins until answered, cannot
// be dismissed, and "off" requires a second, warned confirmation.

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { AdvisoryFeedConsentGate } from "../advisory-feed-consent";
import { SettingsAdvisoryFeed } from "@/features/settings/settings-advisory-feed";
import { mockFetchRoutes, renderWithClient } from "@/test/utils";
import type { AdvisoryFeedStatus, FeedConsent } from "@/api/queries/advisory";

const admin = { authenticated: true, user: { user_id: "1", username: "scott", email: null, is_admin: true } };
const viewer = { authenticated: true, user: { user_id: "2", username: "viewer", email: null, is_admin: false } };

function status(consent: FeedConsent): AdvisoryFeedStatus {
  return { consent, set_by: consent === "unanswered" ? null : "scott", set_at: consent === "unanswered" ? null : 1_758_700_000, sources: [], stale: false };
}

function consentPosts(calls: ReturnType<typeof mockFetchRoutes>) {
  return calls.filter((c) => c.method === "POST" && c.url.endsWith("/api/advisory/feed/consent"));
}

describe("AdvisoryFeedConsentGate", () => {
  it("blocks admins and cannot be dismissed", async () => {
    mockFetchRoutes({ "GET /auth/status": admin, "GET /api/advisory/feed": status("unanswered") });
    renderWithClient(<AdvisoryFeedConsentGate />);
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent("services.nvd.nist.gov");
    expect(dialog).toHaveTextContent("www.cisa.gov");
    expect(screen.queryByRole("button", { name: /close|dismiss|cancel/i })).toBeNull();
    await userEvent.keyboard("{Escape}");
    await userEvent.click(screen.getByTestId("feed-consent-backdrop"));
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("keep on records consent on", async () => {
    const calls = mockFetchRoutes({
      "GET /auth/status": admin,
      "GET /api/advisory/feed": status("unanswered"),
      "POST /api/advisory/feed/consent": status("on"),
    });
    renderWithClient(<AdvisoryFeedConsentGate />);
    await userEvent.click(await screen.findByRole("button", { name: /keep on/i }));
    await waitFor(() => expect(consentPosts(calls).map((c) => c.body)).toEqual([{ consent: "on" }]));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("turn off requires a warned second confirmation", async () => {
    const calls = mockFetchRoutes({
      "GET /auth/status": admin,
      "GET /api/advisory/feed": status("unanswered"),
      "POST /api/advisory/feed/consent": status("off"),
    });
    renderWithClient(<AdvisoryFeedConsentGate />);
    await userEvent.click(await screen.findByRole("button", { name: /^turn off$/i }));
    expect(screen.getByRole("dialog")).toHaveTextContent(/will not learn about new vulnerabilities/i);
    expect(consentPosts(calls)).toHaveLength(0);
    await userEvent.click(screen.getByRole("button", { name: /back/i }));
    expect(screen.getByRole("button", { name: /keep on/i })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /^turn off$/i }));
    await userEvent.click(screen.getByRole("button", { name: /turn off anyway/i }));
    await waitFor(() => expect(consentPosts(calls).map((c) => c.body)).toEqual([{ consent: "off" }]));
  });

  it("traps keyboard focus inside the dialog in both steps", async () => {
    mockFetchRoutes({ "GET /auth/status": admin, "GET /api/advisory/feed": status("unanswered") });
    renderWithClient(
      <>
        <button type="button">outside before</button>
        <AdvisoryFeedConsentGate />
        <button type="button">outside after</button>
      </>,
    );
    const dialog = await screen.findByRole("dialog");
    const assertTrapped = async () => {
      for (let i = 0; i < 5; i++) {
        await userEvent.tab();
        expect(dialog.contains(document.activeElement)).toBe(true);
      }
      for (let i = 0; i < 5; i++) {
        await userEvent.tab({ shift: true });
        expect(dialog.contains(document.activeElement)).toBe(true);
      }
    };
    await assertTrapped();
    await userEvent.click(screen.getByRole("button", { name: /^turn off$/i }));
    expect(dialog).toHaveTextContent(/will not learn about new vulnerabilities/i);
    await assertTrapped();
  });

  it("non-admins see a banner instead of the dialog", async () => {
    mockFetchRoutes({ "GET /auth/status": viewer, "GET /api/advisory/feed": status("unanswered") });
    renderWithClient(<AdvisoryFeedConsentGate />);
    expect(await screen.findByRole("status")).toHaveTextContent(/awaiting administrator confirmation/i);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("renders nothing once answered", async () => {
    mockFetchRoutes({ "GET /auth/status": admin, "GET /api/advisory/feed": status("on") });
    const { container } = renderWithClient(<AdvisoryFeedConsentGate />);
    await waitFor(() => expect(container).toBeEmptyDOMElement());
  });
});

describe("SettingsAdvisoryFeed", () => {
  it("turning off from settings warns before saving", async () => {
    const calls = mockFetchRoutes({
      "GET /auth/status": admin,
      "GET /api/advisory/feed": status("on"),
      "POST /api/advisory/feed/consent": status("off"),
    });
    renderWithClient(<SettingsAdvisoryFeed />);
    expect(await screen.findByText(/set by scott/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /^turn off$/i }));
    expect(screen.getByText(/will not learn about new vulnerabilities/i)).toBeInTheDocument();
    expect(consentPosts(calls)).toHaveLength(0);
    await userEvent.click(screen.getByRole("button", { name: /turn off anyway/i }));
    await waitFor(() => expect(consentPosts(calls).map((c) => c.body)).toEqual([{ consent: "off" }]));
  });

  it("turning on from settings needs no warning", async () => {
    const calls = mockFetchRoutes({
      "GET /auth/status": admin,
      "GET /api/advisory/feed": status("off"),
      "POST /api/advisory/feed/consent": status("on"),
    });
    renderWithClient(<SettingsAdvisoryFeed />);
    await userEvent.click(await screen.findByRole("button", { name: /^turn on$/i }));
    await waitFor(() => expect(consentPosts(calls).map((c) => c.body)).toEqual([{ consent: "on" }]));
  });

  it("shows an alert when saving from settings fails", async () => {
    mockFetchRoutes({
      "GET /auth/status": admin,
      "GET /api/advisory/feed": status("off"),
      "POST /api/advisory/feed/consent": { status: 500, body: { error: "boom" } },
    });
    renderWithClient(<SettingsAdvisoryFeed />);
    await userEvent.click(await screen.findByRole("button", { name: /^turn on$/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/could not save/i);
  });
});
