import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { DataTable, type Column } from "../data-table";

type Row = { id: string; name: string };
const columns: Column<Row>[] = [{ key: "name", header: "Name", render: (r) => r.name }];
const rows: Row[] = [{ id: "1", name: "ether1" }];

describe("DataTable row activation", () => {
  it("a clickable row is focusable and activates on Enter and Space", () => {
    const onRowClick = vi.fn();
    render(<DataTable columns={columns} data={rows} rowKey={(r) => r.id} onRowClick={onRowClick} />);
    const row = screen.getByText("ether1").closest("tr")!;
    expect(row).toHaveAttribute("tabindex", "0");
    fireEvent.keyDown(row, { key: "Enter" });
    fireEvent.keyDown(row, { key: " " });
    expect(onRowClick).toHaveBeenCalledTimes(2);
  });

  it("a row without a click handler is not focusable", () => {
    render(<DataTable columns={columns} data={rows} rowKey={(r) => r.id} />);
    expect(screen.getByText("ether1").closest("tr")).not.toHaveAttribute("tabindex");
  });
});
