import { Router } from "lucide-react";

export function LoginPage() {
  return (
    <div className="flex h-screen items-center justify-center bg-background">
      <div className="flex flex-col items-center gap-6 rounded-lg border border-border bg-card p-10 shadow-lg">
        <Router className="h-12 w-12 text-primary" />
        <div className="text-center">
          <h1 className="text-2xl font-bold">ion-drift</h1>
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
