import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import { useLicenseStatus } from "@/api/queries";

export function LicenseBanner() {
  const { data: license } = useLicenseStatus();
  const queryClient = useQueryClient();
  const [acknowledging, setAcknowledging] = useState(false);

  if (!license) return null;

  // Determine which banner to show
  const showCommunityBanner = license.mode === "community" && license.acknowledged === false;
  const showExpiredBanner = license.mode === "expired";
  const showExpiryWarning = license.mode === "licensed" && license.expiry_warning_days != null;

  if (!showCommunityBanner && !showExpiredBanner && !showExpiryWarning) return null;

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

  // Expired license banner
  if (showExpiredBanner) {
    return (
      <div className="w-full border-b border-red-600/30 bg-red-900/40 px-4 py-3 text-sm text-red-200">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="flex-1 min-w-0">
            Your commercial license ({license.licensee}, {license.tier}) expired
            on {license.expired_on}. Please renew to maintain compliance.
            Ion Drift will continue to function normally.
          </p>
          <div className="flex flex-shrink-0 items-center gap-2">
            <a
              href="https://cyberhivesecurity.com/license"
              target="_blank"
              rel="noopener noreferrer"
              className="rounded-md border border-red-600/50 bg-red-800/50 px-3 py-1.5 text-xs font-medium text-red-100 hover:bg-red-700/50 transition-colors"
            >
              Renew License
            </a>
            <Link
              to="/settings"
              search={{ tab: "license" }}
              className="rounded-md border border-red-600/50 bg-red-800/50 px-3 py-1.5 text-xs font-medium text-red-100 hover:bg-red-700/50 transition-colors"
            >
              Enter New Key
            </Link>
          </div>
        </div>
      </div>
    );
  }

  // Expiry warning banner (within 30 days of expiration)
  if (showExpiryWarning) {
    return (
      <div className="w-full border-b border-yellow-600/30 bg-yellow-900/30 px-4 py-3 text-sm text-yellow-200">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="flex-1 min-w-0">
            Your commercial license ({license.licensee}) expires in{" "}
            {license.expiry_warning_days} day{license.expiry_warning_days === 1 ? "" : "s"}.
            Renew to avoid interruption.
          </p>
          <div className="flex flex-shrink-0 items-center gap-2">
            <a
              href="https://cyberhivesecurity.com/license"
              target="_blank"
              rel="noopener noreferrer"
              className="rounded-md border border-yellow-600/50 bg-yellow-800/50 px-3 py-1.5 text-xs font-medium text-yellow-100 hover:bg-yellow-700/50 transition-colors"
            >
              Renew License
            </a>
          </div>
        </div>
      </div>
    );
  }

  // Community banner (30-day nag)
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
