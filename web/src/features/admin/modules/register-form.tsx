import { useState } from "react";
import { useRegisterModule } from "@/api/queries/admin-modules";

interface Props {
  onDone: () => void;
}

const MIN_SECRET_LEN = 32; // must match the backend's MIN_SECRET_LEN

interface FieldErrors {
  url?: string;
  sharedSecret?: string;
  apiToken?: string;
}

function validate(url: string, sharedSecret: string, apiToken: string): FieldErrors {
  const errors: FieldErrors = {};
  const trimmed = url.trim();
  if (!trimmed) {
    errors.url = "Module URL is required.";
  } else {
    try {
      const parsed = new URL(trimmed);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        errors.url = "URL must use http or https.";
      }
    } catch {
      errors.url = "Not a valid URL (expected e.g. http://host:port).";
    }
  }
  if (!sharedSecret) {
    errors.sharedSecret = "Shared secret is required.";
  } else if (sharedSecret.length < MIN_SECRET_LEN) {
    errors.sharedSecret = `Shared secret must be at least ${MIN_SECRET_LEN} characters (currently ${sharedSecret.length}).`;
  }
  if (!apiToken) {
    errors.apiToken = "API token is required.";
  } else if (apiToken.length < MIN_SECRET_LEN) {
    errors.apiToken = `API token must be at least ${MIN_SECRET_LEN} characters (currently ${apiToken.length}).`;
  }
  return errors;
}

export function RegisterModuleForm({ onDone }: Props) {
  const [url, setUrl] = useState("");
  const [sharedSecret, setSharedSecret] = useState("");
  const [apiToken, setApiToken] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});
  const register = useRegisterModule();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const errors = validate(url, sharedSecret, apiToken);
    setFieldErrors(errors);
    if (Object.keys(errors).length > 0) return;
    try {
      await register.mutateAsync({
        url: url.trim(),
        shared_secret: sharedSecret,
        api_token: apiToken,
      });
      setUrl("");
      setSharedSecret("");
      setApiToken("");
      onDone();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <form
      onSubmit={handleSubmit}
      // noValidate: validation is rendered as persistent inline errors below
      // each field instead of transient native browser tooltips.
      noValidate
      className="rounded-lg border border-border bg-card p-4 space-y-4"
    >
      <div className="space-y-1">
        <h3 className="text-base font-semibold">Register a module</h3>
        <p className="text-xs text-muted-foreground">
          Drift will fetch <code className="font-mono">/manifest</code> at the
          URL below to validate the module, then store both secrets encrypted
          with Drift's KEK.
        </p>
      </div>

      <Field label="Module URL" hint="e.g. http://10.20.25.50:3099" error={fieldErrors.url}>
        <input
          type="url"
          required
          value={url}
          onChange={(e) => {
            setUrl(e.target.value);
            setFieldErrors((prev) => ({ ...prev, url: undefined }));
          }}
          placeholder="http://host:port"
          aria-invalid={fieldErrors.url ? true : undefined}
          className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-ring aria-[invalid]:border-destructive"
        />
      </Field>

      <Field
        label="Shared secret"
        hint="HMAC-SHA256 key the module uses to verify outbound event deliveries. Minimum 32 chars."
        error={fieldErrors.sharedSecret}
      >
        <input
          type="password"
          required
          minLength={32}
          value={sharedSecret}
          onChange={(e) => {
            setSharedSecret(e.target.value);
            setFieldErrors((prev) => ({ ...prev, sharedSecret: undefined }));
          }}
          aria-invalid={fieldErrors.sharedSecret ? true : undefined}
          className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-ring aria-[invalid]:border-destructive"
        />
      </Field>

      <Field
        label="API token"
        hint="Bearer token Drift sends when reverse-proxying admin UI requests to this module. Minimum 32 chars."
        error={fieldErrors.apiToken}
      >
        <input
          type="password"
          required
          minLength={32}
          value={apiToken}
          onChange={(e) => {
            setApiToken(e.target.value);
            setFieldErrors((prev) => ({ ...prev, apiToken: undefined }));
          }}
          aria-invalid={fieldErrors.apiToken ? true : undefined}
          className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-ring aria-[invalid]:border-destructive"
        />
      </Field>

      {error && (
        <div className="rounded-md border border-destructive/30 bg-destructive/5 p-2 text-xs text-destructive">
          {error}
        </div>
      )}

      <div className="flex gap-2">
        <button
          type="submit"
          disabled={register.isPending}
          className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
        >
          {register.isPending ? "Registering..." : "Register"}
        </button>
        <button
          type="button"
          onClick={onDone}
          className="rounded-md border border-border px-4 py-2 text-sm font-medium hover:bg-accent"
        >
          Cancel
        </button>
      </div>
    </form>
  );
}

function Field({
  label,
  hint,
  error,
  children,
}: {
  label: string;
  hint?: string;
  error?: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block space-y-1">
      <span className="text-sm font-medium">{label}</span>
      {children}
      {error && (
        <span role="alert" className="block text-xs text-destructive">
          {error}
        </span>
      )}
      {hint && <span className="block text-xs text-muted-foreground">{hint}</span>}
    </label>
  );
}
