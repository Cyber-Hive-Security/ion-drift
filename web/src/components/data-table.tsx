import { useState, useMemo, type CSSProperties, type ReactNode } from "react";
import { cn } from "@/lib/utils";
import { ArrowUpDown, Search } from "lucide-react";

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
  searchable?: boolean;
  searchPlaceholder?: string;
  rowStyle?: (row: T) => CSSProperties | undefined;
}

export function DataTable<T>({
  columns,
  data,
  rowKey,
  emptyMessage = "No data",
  defaultSort,
  searchable,
  searchPlaceholder = "Search...",
  rowStyle,
}: DataTableProps<T>) {
  const [sortCol, setSortCol] = useState<string | null>(defaultSort?.key ?? null);
  const [sortAsc, setSortAsc] = useState(defaultSort?.asc ?? true);
  const [search, setSearch] = useState("");

  const filteredAndSorted = useMemo(() => {
    let result = data;

    // Filter by search term using sortValue columns
    if (searchable && search) {
      const lower = search.toLowerCase();
      result = result.filter((row) =>
        columns.some((col) => {
          if (!col.sortValue) return false;
          return String(col.sortValue(row)).toLowerCase().includes(lower);
        }),
      );
    }

    // Sort
    if (sortCol) {
      const col = columns.find((c) => c.key === sortCol);
      if (col?.sortValue) {
        result = [...result].sort((a, b) => {
          const av = col.sortValue!(a);
          const bv = col.sortValue!(b);
          if (av < bv) return sortAsc ? -1 : 1;
          if (av > bv) return sortAsc ? 1 : -1;
          return 0;
        });
      }
    }

    return result;
  }, [data, search, sortCol, sortAsc, columns, searchable]);

  const toggleSort = (key: string) => {
    if (sortCol === key) {
      setSortAsc(!sortAsc);
    } else {
      setSortCol(key);
      setSortAsc(true);
    }
  };

  return (
    <div>
      {searchable && (
        <div className="mb-3 flex items-center gap-2">
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={searchPlaceholder}
              className="rounded-md border border-border bg-background py-1.5 pl-8 pr-3 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>
          {search && (
            <span className="text-xs text-muted-foreground">
              {filteredAndSorted.length} of {data.length}
            </span>
          )}
        </div>
      )}
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
            {filteredAndSorted.length === 0 ? (
              <tr>
                <td
                  colSpan={columns.length}
                  className="px-3 py-8 text-center text-muted-foreground"
                >
                  {search ? "No matching results" : emptyMessage}
                </td>
              </tr>
            ) : (
              filteredAndSorted.map((row) => (
                <tr
                  key={rowKey(row)}
                  className="border-b border-border/50 hover:bg-muted/30"
                  style={rowStyle?.(row)}
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
    </div>
  );
}
