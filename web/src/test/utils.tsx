import type { ReactElement } from "react";
import { render } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { vi } from "vitest";

/**
 * Render with a fresh TanStack Query client per test: no retries, no
 * refetch intervals, so tests are deterministic and failures surface
 * immediately instead of being retried into timeouts.
 */
export function renderWithClient(ui: ReactElement) {
  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, refetchInterval: false, staleTime: Infinity },
      mutations: { retry: false },
    },
  });
  return {
    client,
    ...render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>),
  };
}

export interface RecordedCall {
  method: string;
  url: string;
  body: unknown;
  credentials?: RequestCredentials;
}

/**
 * Stub global fetch with a route table keyed by `"METHOD /path"`.
 *
 * Values: a JSON-serializable body (→ 200), or `{ status, body }` for
 * error paths. Query strings are stripped before lookup. Unmatched
 * requests return 404 with a body naming the route, so a typo'd mock
 * key fails the test loudly rather than hanging it.
 *
 * Returns the recorded call list for asserting on method/url/body/
 * credentials (the session-cookie seam).
 */
export function mockFetchRoutes(
  routes: Record<string, unknown | { status: number; body: unknown }>,
): RecordedCall[] {
  const calls: RecordedCall[] = [];

  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const path = url.replace(/^https?:\/\/[^/]+/, "").split("?")[0];
      const method = (init?.method ?? "GET").toUpperCase();
      let body: unknown = null;
      if (typeof init?.body === "string") {
        try {
          body = JSON.parse(init.body);
        } catch {
          body = init.body;
        }
      }
      calls.push({ method, url, body, credentials: init?.credentials });

      const entry = routes[`${method} ${path}`];
      if (entry === undefined) {
        return jsonResponse(404, { error: `no mock for ${method} ${path}` });
      }
      if (
        entry !== null &&
        typeof entry === "object" &&
        "status" in entry &&
        "body" in entry &&
        typeof (entry as { status: unknown }).status === "number"
      ) {
        const e = entry as { status: number; body: unknown };
        return jsonResponse(e.status, e.body);
      }
      return jsonResponse(200, entry);
    }),
  );

  return calls;
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
