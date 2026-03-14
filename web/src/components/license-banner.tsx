import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import { useLicenseStatus } from "@/api/queries";

export function LicenseBanner() {
  const { data: license } = useLicenseStatus();
  const queryClient = useQueryClient();
  const [acknowledging, setAcknowledging] = useState(false);

  if (!license) return null;
  if (license.mode !== "community" || license.acknowledged !== false) return null;

  const handleAcknowledge = async () => {
    setAcknowledging(true);
    try {
      await fetch("/api/license/acknowledge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
      });
      queryClient.invalidateQueries({ queryKey: ["license"] });
    } finally {
      setAcknowledging(false);
    }
  };

  return (
    <div className="w-full border-b border-amber-600/30 bg-amber-900/40 px-4 py-3 text-sm text-amber-200">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="flex-1 min-w-0">
          Ion Drift is licensed under PolyForm Shield 1.0.0 with the Cyber Hive
          Security Use Agreement. Personal home use is free. Business,
          government, education, and organizational use requires a commercial
          license.
        </p>
        <div className="flex flex-shrink-0 items-center gap-2">
          <a
            href="https://cyberhivesecurity.com/license"
            target="_blank"
            rel="noopener noreferrer"
            className="rounded-md border border-amber-600/50 bg-amber-800/50 px-3 py-1.5 text-xs font-medium text-amber-100 hover:bg-amber-700/50 transition-colors"
          >
            Purchase License
          </a>
          <Link
            to="/settings"
            search={{ tab: "license" }}
            className="rounded-md border border-amber-600/50 bg-amber-800/50 px-3 py-1.5 text-xs font-medium text-amber-100 hover:bg-amber-700/50 transition-colors"
          >
            Enter License Key
          </Link>
          <button
            onClick={handleAcknowledge}
            disabled={acknowledging}
            className="rounded-md border border-amber-600/50 bg-amber-800/50 px-3 py-1.5 text-xs font-medium text-amber-100 hover:bg-amber-700/50 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {acknowledging ? "Acknowledging..." : "Acknowledge \u2014 Personal Home Use"}
          </button>
        </div>
      </div>
    </div>
  );
}
