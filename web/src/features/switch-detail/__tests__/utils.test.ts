import { describe, it, expect } from "vitest";
import { physicalPortNames, portSortKey } from "../utils";

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

describe("physicalPortNames", () => {
  const iface = (name: string, type: string) =>
    ({ name, type, running: true }) as unknown as import("@/api/types").RouterInterface;

  it("keeps metered ports and ethernet interfaces, drops logical ones", () => {
    // Map keys, as the table passes them; ether1 is both metered and listed.
    const metered = new Map([["ether1", 1], ["sfp-sfpplus1", 1]]).keys();
    const names = physicalPortNames(metered, [
      iface("ether1", "ether"),
      iface("ether2", "ether"),
      iface("bridge1", "bridge"),
      iface("vlan2-mgmt", "vlan"),
      iface("bond1", "bond"),
      iface("lo", "loopback"),
    ]);
    expect([...names].sort()).toEqual(["ether1", "ether2", "sfp-sfpplus1"]);
  });
});
