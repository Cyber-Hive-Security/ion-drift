export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public code?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export async function apiFetch<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  // Set Content-Type: application/json on ALL mutating requests (not just
  // ones with a body). The backend CSRF guard requires this header on every
  // POST/PUT/DELETE/PATCH — including no-body requests — because a cross-site
  // HTML form cannot set it without a (CORS-blocked) preflight (WSTG-N02).
  const headers = new Headers(init?.headers);
  const method = (init?.method ?? "GET").toUpperCase();
  const mutating = method !== "GET" && method !== "HEAD" && method !== "OPTIONS";
  if (mutating && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(path, {
    credentials: "include",
    ...init,
    headers,
  });

  if (response.status === 401) {
    window.location.href = "/";
    throw new ApiError(401, "Session expired");
  }

  if (!response.ok) {
    const body = await response
      .json()
      .catch(() => ({ error: "Unknown error" }));
    throw new ApiError(
      response.status,
      body.error || `HTTP ${response.status}`,
      body.code,
    );
  }

  return response.json();
}
