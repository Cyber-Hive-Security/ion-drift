import React, { useState, useMemo, useRef, type CSSProperties, type ReactNode } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { cn } from "@/lib/utils";
import { ArrowUpDown, Search } from "lucide-react";

export interface Column<T> {
  key: string;
  header: string;
  headerTitle?: string;
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
  onRowClick?: (row: T) => void;
  /** Enable row virtualization for large datasets. Renders only visible rows. */
  virtualize?: boolean;
  /** Height of each row in pixels when virtualized. Default: 37 */
  estimateRowHeight?: number;
  /** Max height of the virtualized table body in pixels. Default: 600 */
  virtualMaxHeight?: number;
  /** Render expanded content below a row (return null to collapse) */
  expandedRow?: (row: T) => ReactNode | null;
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
  onRowClick,
  virtualize = false,
  estimateRowHeight = 37,
  virtualMaxHeight = 600,
  expandedRow,
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

  const shouldVirtualize = virtualize && filteredAndSorted.length > 50;

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
      {shouldVirtualize ? (
        <div className="rounded-lg border border-border">
          {/* Sticky header */}
          <table className="w-full text-sm" style={{ tableLayout: "fixed" }}>
            <thead>
              <tr className="border-b border-border bg-muted/50">
                {columns.map((col) => (
                  <th
                    key={col.key}
                    className={cn(
                      "px-3 py-2 text-left font-medium text-muted-foreground",
                      col.sortValue && "cursor-pointer select-none hover:text-foreground",
                    )}
                    title={col.headerTitle}
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
          </table>
          {/* Scrollable virtualized body */}
          <VirtualizedBody
            rows={filteredAndSorted}
            columns={columns}
            rowKey={rowKey}
            rowStyle={rowStyle}
            onRowClick={onRowClick}
            estimateRowHeight={estimateRowHeight}
            maxHeight={virtualMaxHeight}
          />
        </div>
      ) : (
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
                    title={col.headerTitle}
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
            {filteredAndSorted.length === 0 ? (
              <tbody>
                <tr>
                  <td
                    colSpan={columns.length}
                    className="px-3 py-8 text-center text-muted-foreground"
                  >
                    {search ? "No matching results" : emptyMessage}
                  </td>
                </tr>
              </tbody>
            ) : (
              <tbody>
                {filteredAndSorted.map((row) => {
                  const expanded = expandedRow?.(row);
                  return (
                    <React.Fragment key={rowKey(row)}>
                      <tr
                        className={cn("border-b border-border/50 hover:bg-muted/30", onRowClick && "cursor-pointer")}
                        style={rowStyle?.(row)}
                        onClick={onRowClick ? () => onRowClick(row) : undefined}
                      >
                        {columns.map((col) => (
                          <td key={col.key} className="px-3 py-2">
                            {col.render(row)}
                          </td>
                        ))}
                      </tr>
                      {expanded && (
                        <tr>
                          <td colSpan={columns.length} className="p-0">
                            {expanded}
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            )}
          </table>
        </div>
      )}
    </div>
  );
}

/** Virtualized table body using @tanstack/react-virtual */
function VirtualizedBody<T>({
  rows,
  columns,
  rowKey,
  rowStyle,
  onRowClick,
  estimateRowHeight,
  maxHeight,
}: {
  rows: T[];
  columns: Column<T>[];
  rowKey: (row: T) => string;
  rowStyle?: (row: T) => CSSProperties | undefined;
  onRowClick?: (row: T) => void;
  estimateRowHeight: number;
  maxHeight: number;
}) {
  const parentRef = useRef<HTMLDivElement>(null);

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => estimateRowHeight,
    overscan: 20,
  });

  return (
    <div
      ref={parentRef}
      style={{ maxHeight: `${maxHeight}px`, overflow: "auto" }}
    >
      <div
        style={{
          height: `${virtualizer.getTotalSize()}px`,
          position: "relative",
        }}
      >
        {virtualizer.getVirtualItems().map((virtualRow) => {
          const row = rows[virtualRow.index];
          return (
            <table
              key={rowKey(row)}
              ref={virtualizer.measureElement}
              data-index={virtualRow.index}
              className="w-full text-sm"
              style={{
                position: "absolute",
                top: 0,
                left: 0,
                transform: `translateY(${virtualRow.start}px)`,
                tableLayout: "fixed",
              }}
            >
              <tbody>
                <tr
                  className={cn("border-b border-border/50 hover:bg-muted/30", onRowClick && "cursor-pointer")}
                  style={rowStyle?.(row)}
                  onClick={onRowClick ? () => onRowClick(row) : undefined}
                >
                  {columns.map((col) => (
                    <td key={col.key} className="px-3 py-2">
                      {col.render(row)}
                    </td>
                  ))}
                </tr>
              </tbody>
            </table>
          );
        })}
      </div>
    </div>
  );
}
