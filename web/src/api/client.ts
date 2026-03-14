export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export async function apiFetch<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  // Auto-set Content-Type for JSON bodies when not explicitly provided.
  const headers = new Headers(init?.headers);
  if (init?.body && typeof init.body === "string" && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(path, {
    credentials: "include",
    ...init,
    headers,
  });

  if (response.status === 401) {
    // Check auth config to determine redirect target
    try {
      const config = await fetch("/auth/config", { credentials: "include" }).then(r => r.json());
      if (config.oidc_enabled && !config.local_auth_enabled) {
        // OIDC only — redirect straight to OIDC login
        window.location.href = "/auth/login";
      } else {
        // Local auth available — show login page
        window.location.href = "/";
      }
    } catch {
      window.location.href = "/";
    }
    throw new ApiError(401, "Session expired");
  }

  if (!response.ok) {
    const body = await response
      .json()
      .catch(() => ({ error: "Unknown error" }));
    throw new ApiError(
      response.status,
      body.error || `HTTP ${response.status}`,
    );
  }

  return response.json();
}
