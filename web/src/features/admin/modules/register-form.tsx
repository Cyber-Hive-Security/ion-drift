import { useState } from "react";
import { useRegisterModule } from "@/api/queries/admin-modules";

interface Props {
  onDone: () => void;
}

export function RegisterModuleForm({ onDone }: Props) {
  const [url, setUrl] = useState("");
  const [sharedSecret, setSharedSecret] = useState("");
  const [apiToken, setApiToken] = useState("");
  const [error, setError] = useState<string | null>(null);
  const register = useRegisterModule();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
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

      <Field label="Module URL" hint="e.g. http://10.20.25.50:3099">
        <input
          type="url"
          required
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="http://host:port"
          className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-ring"
        />
      </Field>

      <Field
        label="Shared secret"
        hint="HMAC-SHA256 key the module uses to verify outbound event deliveries. Minimum 32 chars."
      >
        <input
          type="password"
          required
          minLength={32}
          value={sharedSecret}
          onChange={(e) => setSharedSecret(e.target.value)}
          className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-ring"
        />
      </Field>

      <Field
        label="API token"
        hint="Bearer token Drift sends when reverse-proxying admin UI requests to this module. Minimum 32 chars."
      >
        <input
          type="password"
          required
          minLength={32}
          value={apiToken}
          onChange={(e) => setApiToken(e.target.value)}
          className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-ring"
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
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block space-y-1">
      <span className="text-sm font-medium">{label}</span>
      {children}
      {hint && <span className="block text-xs text-muted-foreground">{hint}</span>}
    </label>
  );
}
