// Register-form inline validation (v0.5.2a smoke-test follow-up item 2).
//
// The form must render PERSISTENT inline error text under each required
// field on an invalid submit — not rely on transient native browser
// tooltips — and must not fire any request while invalid.

import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { RegisterModuleForm } from "../register-form";
import { mockFetchRoutes, renderWithClient } from "@/test/utils";

describe("RegisterModuleForm validation", () => {
  it("shows an inline error under every empty required field and fires no request", async () => {
    const calls = mockFetchRoutes({});
    const user = userEvent.setup();
    renderWithClient(<RegisterModuleForm onDone={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: /register/i }));

    const alerts = await screen.findAllByRole("alert");
    const messages = alerts.map((a) => a.textContent ?? "");
    expect(messages).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/module url is required/i),
        expect.stringMatching(/shared secret is required/i),
        expect.stringMatching(/api token is required/i),
      ]),
    );
    // Errors are persistent DOM text, still present after the click settles.
    expect(screen.getAllByRole("alert").length).toBe(3);
    // No network request fired for an invalid form.
    expect(calls.length).toBe(0);
  });

  it("flags a malformed URL and too-short secrets with specific messages", async () => {
    const calls = mockFetchRoutes({});
    const user = userEvent.setup();
    renderWithClient(<RegisterModuleForm onDone={vi.fn()} />);

    await user.type(screen.getByPlaceholderText("http://host:port"), "not a url");
    const [secret, token] = screen
      .getAllByDisplayValue("")
      .filter((el) => (el as HTMLInputElement).type === "password");
    await user.type(secret, "short");
    await user.type(token, "also-short");
    await user.click(screen.getByRole("button", { name: /register/i }));

    expect(await screen.findByText(/not a valid url/i)).toBeInTheDocument();
    expect(
      screen.getByText(/shared secret must be at least 32 characters/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/api token must be at least 32 characters/i),
    ).toBeInTheDocument();
    expect(calls.length).toBe(0);
  });

  it("clears a field's error as soon as the field is edited", async () => {
    mockFetchRoutes({});
    const user = userEvent.setup();
    renderWithClient(<RegisterModuleForm onDone={vi.fn()} />);

    await user.click(screen.getByRole("button", { name: /register/i }));
    expect(await screen.findByText(/module url is required/i)).toBeInTheDocument();

    await user.type(screen.getByPlaceholderText("http://host:port"), "h");
    expect(screen.queryByText(/module url is required/i)).not.toBeInTheDocument();
    // Other fields' errors remain until they are edited.
    expect(screen.getByText(/shared secret is required/i)).toBeInTheDocument();
  });
});
