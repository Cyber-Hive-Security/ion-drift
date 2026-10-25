import { describe, it, expect } from "vitest";
import { formatUptime } from "../format";

describe("formatUptime", () => {
  it("parses RouterOS uptime strings", () => {
    expect(formatUptime("14d03:22:01")).toBe("14d 3h 22m");
    expect(formatUptime("3w2d03:22:01")).toBe("3w 2d 3h 22m");
    expect(formatUptime("03:22:01")).toBe("3h 22m");
  });
});
