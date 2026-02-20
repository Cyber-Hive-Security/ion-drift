import { useState, useMemo, type ReactNode } from "react";
import { cn } from "@/lib/utils";
import { ArrowUpDown } from "lucide-react";

export interface Column<T> {
  key: string;
  header: string;
  render: (row: T) => ReactNode;
  sortValue?: (row: T) => string | number | boolean;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  rowKey: (row: T) => string;
  emptyMessage?: string;
  defaultSort?: { key: string; asc?: boolean };
}

export function DataTable<T>({
  columns,
  data,
  rowKey,
  emptyMessage = "No data",
  defaultSort,
}: DataTableProps<T>) {
  const [sortCol, setSortCol] = useState<string | null>(defaultSort?.key ?? null);
  const [sortAsc, setSortAsc] = useState(defaultSort?.asc ?? true);

  const sorted = useMemo(() => {
    if (!sortCol) return data;
    const col = columns.find((c) => c.key === sortCol);
    if (!col?.sortValue) return data;
    return [...data].sort((a, b) => {
      const av = col.sortValue!(a);
      const bv = col.sortValue!(b);
      if (av < bv) return sortAsc ? -1 : 1;
      if (av > bv) return sortAsc ? 1 : -1;
      return 0;
    });
  }, [data, sortCol, sortAsc, columns]);

  const toggleSort = (key: string) => {
    if (sortCol === key) {
      setSortAsc(!sortAsc);
    } else {
      setSortCol(key);
      setSortAsc(true);
    }
  };

  return (
    <div className="overflow-x-auto rounded-lg border border-border">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border bg-muted/50">
            {columns.map((col) => (
              <th
                key={col.key}
                className={cn(
                  "px-3 py-2 text-left font-medium text-muted-foreground",
                  col.sortValue && "cursor-pointer select-none hover:text-foreground",
                )}
                onClick={col.sortValue ? () => toggleSort(col.key) : undefined}
              >
                <span className="inline-flex items-center gap-1">
                  {col.header}
                  {col.sortValue && (
                    <ArrowUpDown className="h-3 w-3 opacity-50" />
                  )}
                </span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.length === 0 ? (
            <tr>
              <td
                colSpan={columns.length}
                className="px-3 py-8 text-center text-muted-foreground"
              >
                {emptyMessage}
              </td>
            </tr>
          ) : (
            sorted.map((row) => (
              <tr
                key={rowKey(row)}
                className="border-b border-border/50 hover:bg-muted/30"
              >
                {columns.map((col) => (
                  <td key={col.key} className="px-3 py-2">
                    {col.render(row)}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
