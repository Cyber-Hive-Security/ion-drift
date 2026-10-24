import { describe, it, expect } from "vitest";
import { portSortKey } from "../utils";

describe("cisco port names", () => {
  it("parses nested slots", () => {
    expect(portSortKey("TenGigabitEthernet1/0/2")).toBe(2);
    expect(portSortKey("Gi1/0/48")).toBe(48);
    expect(portSortKey("Fa0/1")).toBe(1);
  });
});

describe("trailing-number port names", () => {
  it("uses the trailing digit run", () => {
    expect(portSortKey("vlan-uplink12")).toBe(12);
    expect(portSortKey("sfp-sfpplus3")).toBe(3);
  });
});
