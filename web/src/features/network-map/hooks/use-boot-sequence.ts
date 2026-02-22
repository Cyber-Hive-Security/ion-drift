import { useState, useEffect, useRef } from "react";
import { BOOT_LINES } from "../constants";

type BootPhase = "booting" | "fading" | "done";

const SESSION_KEY = "nm-boot-done";

export function useBootSequence() {
  const alreadyBooted = sessionStorage.getItem(SESSION_KEY) === "1";
  const [phase, setPhase] = useState<BootPhase>(alreadyBooted ? "done" : "booting");
  const [visibleLines, setVisibleLines] = useState(alreadyBooted ? BOOT_LINES.length : 0);
  const intervalRef = useRef<ReturnType<typeof setInterval>>(undefined);

  useEffect(() => {
    if (alreadyBooted) return;

    let i = 0;
    intervalRef.current = setInterval(() => {
      i++;
      setVisibleLines(i);
      if (i >= BOOT_LINES.length) {
        clearInterval(intervalRef.current);
        setTimeout(() => {
          setPhase("fading");
          setTimeout(() => {
            setPhase("done");
            sessionStorage.setItem(SESSION_KEY, "1");
          }, 800);
        }, 600);
      }
    }, 180);

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [alreadyBooted]);

  const progress = BOOT_LINES.length > 0 ? (visibleLines / BOOT_LINES.length) * 100 : 0;

  return { phase, visibleLines, progress, bootLines: BOOT_LINES };
}
