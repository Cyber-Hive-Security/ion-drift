export function LoginPage() {
  return (
    <div className="flex h-screen items-center justify-center bg-background">
      <div className="flex flex-col items-center gap-6 rounded-lg border border-border bg-card p-10 shadow-lg">
        <img src="/logo-icon.png" alt="Ion Drift" className="h-16 w-16" />
        <div className="text-center">
          <h1 className="text-2xl font-bold">Ion Drift</h1>
          <p className="text-xs text-muted-foreground">
            by Cyber Hive Security
          </p>
          <p className="mt-1 text-sm text-muted-foreground">
            Mikrotik Router Management
          </p>
        </div>
        <a
          href="/auth/login"
          className="rounded-md bg-primary px-6 py-2.5 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
        >
          Sign in with Keycloak
        </a>
      </div>
    </div>
  );
}
