// Smoke floor: auth flows (gate item 4).
//
// LoginPage against a fetch-mocked /auth/config + /auth/local-login.
// Covers: local form renders, OIDC redirect link mounts, successful login
// posts credentials with the session cookie flag, failure renders the
// server's error.

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { LoginPage } from "../login";
import { mockFetchRoutes, renderWithClient } from "@/test/utils";

const BOTH_PROVIDERS = {
  "GET /auth/config": {
    local_auth_enabled: true,
    oidc_enabled: true,
    oidc_provider_name: "TheHolonet",
  },
  "GET /auth/status": { authenticated: false },
};

describe("LoginPage", () => {
  it("renders the local login form when local auth is enabled", async () => {
    mockFetchRoutes(BOTH_PROVIDERS);
    renderWithClient(<LoginPage />);

    expect(await screen.findByLabelText(/username/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /sign in/i })).toBeInTheDocument();
  });

  it("mounts the OIDC redirect link with the provider name", async () => {
    mockFetchRoutes(BOTH_PROVIDERS);
    renderWithClient(<LoginPage />);

    const link = await screen.findByRole("link", {
      name: /sign in with TheHolonet/i,
    });
    expect(link).toHaveAttribute("href", "/auth/login");
  });

  it("hides the local form when only OIDC is enabled", async () => {
    mockFetchRoutes({
      "GET /auth/config": {
        local_auth_enabled: false,
        oidc_enabled: true,
        oidc_provider_name: "SSO",
      },
    });
    renderWithClient(<LoginPage />);

    await screen.findByRole("link", { name: /sign in with SSO/i });
    expect(screen.queryByLabelText(/username/i)).not.toBeInTheDocument();
  });

  it("successful login POSTs credentials to /auth/local-login with cookies enabled", async () => {
    const calls = mockFetchRoutes({
      ...BOTH_PROVIDERS,
      "POST /auth/local-login": { status: "ok" },
    });
    renderWithClient(<LoginPage />);
    const user = userEvent.setup();

    await user.type(await screen.findByLabelText(/username/i), "admin");
    await user.type(screen.getByLabelText(/password/i), "hunter2hunter2");
    await user.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() => {
      const login = calls.find((c) => c.url === "/auth/local-login");
      expect(login).toBeDefined();
      expect(login!.method).toBe("POST");
      // The session cookie only sticks if credentials ride along.
      expect(login!.credentials).toBe("include");
      expect(login!.body).toEqual({ username: "admin", password: "hunter2hunter2" });
    });
    expect(screen.queryByText(/login failed/i)).not.toBeInTheDocument();
  });

  it("failed login renders the server's error message", async () => {
    mockFetchRoutes({
      ...BOTH_PROVIDERS,
      "POST /auth/local-login": {
        status: 401,
        body: { error: "invalid username or password" },
      },
    });
    renderWithClient(<LoginPage />);
    const user = userEvent.setup();

    await user.type(await screen.findByLabelText(/username/i), "admin");
    await user.type(screen.getByLabelText(/password/i), "wrong-password");
    await user.click(screen.getByRole("button", { name: /sign in/i }));

    expect(
      await screen.findByText(/invalid username or password/i),
    ).toBeInTheDocument();
  });
});
