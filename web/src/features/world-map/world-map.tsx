import { useEffect, useRef, useMemo, useState } from "react";
import * as d3 from "d3";
import * as topojson from "topojson-client";
import type { Topology, GeometryCollection } from "topojson-specification";
import type { GeoSummaryEntry } from "@/api/types";
import { formatBytes, formatNumber } from "@/lib/format";

// Flagged countries — same list as backend geo.rs FLAGGED_COUNTRIES
const FLAGGED_COUNTRIES = new Set([
  "CN", "RU", "KP", "IR", "SY", "VE", "CU", "BY", "MM", "SD",
]);

// Home location (Ogden, UT)
const HOME: [number, number] = [-111.97, 41.22];

interface WorldMapProps {
  data: GeoSummaryEntry[];
  onCountryClick?: (code: string) => void;
  timeRange: string;
}

export function WorldMap({ data, onCountryClick, timeRange }: WorldMapProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const tooltipRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 960, height: 500 });

  // Observe container size
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    const container = svg.parentElement;
    if (!container) return;

    const ro = new ResizeObserver((entries) => {
      const { width } = entries[0].contentRect;
      if (width > 0) {
        setDimensions({ width, height: Math.max(400, width * 0.5) });
      }
    });
    ro.observe(container);
    return () => ro.disconnect();
  }, []);

  // Index data by country_code for O(1) lookup
  const countryIndex = useMemo(() => {
    const idx = new Map<string, GeoSummaryEntry>();
    for (const entry of data) {
      idx.set(entry.country_code, entry);
    }
    return idx;
  }, [data]);

  // Max connection count for color scale
  const maxCount = useMemo(
    () => Math.max(1, ...data.map((d) => d.connection_count)),
    [data],
  );

  // Color scale: green → amber → red
  const colorScale = useMemo(() => {
    return d3
      .scaleLog()
      .domain([1, Math.max(10, maxCount)])
      .range([0, 1] as any)
      .clamp(true);
  }, [maxCount]);

  function countryColor(code: string, count: number): string {
    if (count === 0) return "oklch(0.2 0.01 285)";
    if (FLAGGED_COUNTRIES.has(code)) {
      // Red scale for flagged countries
      const t = colorScale(count) as unknown as number;
      return `oklch(${0.35 + t * 0.15} ${0.15 + t * 0.1} 25)`;
    }
    // Green to amber scale for normal countries
    const t = colorScale(count) as unknown as number;
    const hue = 145 - t * 100; // green → amber
    return `oklch(${0.35 + t * 0.15} ${0.1 + t * 0.1} ${hue})`;
  }

  useEffect(() => {
    const svg = d3.select(svgRef.current);
    const tooltip = tooltipRef.current;
    if (!svg.node() || !tooltip) return;

    const { width, height } = dimensions;

    svg.selectAll("*").remove();

    const projection = d3
      .geoNaturalEarth1()
      .fitSize([width, height], { type: "Sphere" });

    const path = d3.geoPath(projection);

    // Background
    svg
      .append("path")
      .datum({ type: "Sphere" } as any)
      .attr("d", path as any)
      .attr("fill", "oklch(0.15 0.01 285)")
      .attr("stroke", "oklch(0.25 0.01 285)");

    // Load and render world map
    d3.json<Topology>("/world-110m.json").then((world) => {
      if (!world) return;

      const countries = topojson.feature(
        world,
        world.objects.countries as GeometryCollection,
      );

      // ISO 3166-1 numeric to alpha-2 mapping (most common)
      const numericToAlpha2: Record<string, string> = {
        "004": "AF", "008": "AL", "012": "DZ", "020": "AD", "024": "AO",
        "028": "AG", "032": "AR", "036": "AU", "040": "AT", "031": "AZ",
        "044": "BS", "048": "BH", "050": "BD", "051": "AM", "052": "BB",
        "056": "BE", "060": "BM", "064": "BT", "068": "BO", "070": "BA",
        "072": "BW", "076": "BR", "084": "BZ", "090": "SB", "092": "VG",
        "096": "BN", "100": "BG", "104": "MM", "108": "BI", "112": "BY",
        "116": "KH", "120": "CM", "124": "CA", "132": "CV", "140": "CF",
        "144": "LK", "148": "TD", "152": "CL", "156": "CN", "158": "TW",
        "170": "CO", "174": "KM", "178": "CG", "180": "CD", "184": "CK",
        "188": "CR", "191": "HR", "192": "CU", "196": "CY", "203": "CZ",
        "204": "BJ", "208": "DK", "212": "DM", "214": "DO", "218": "EC",
        "222": "SV", "226": "GQ", "231": "ET", "232": "ER", "233": "EE",
        "242": "FJ", "246": "FI", "250": "FR", "258": "PF", "262": "DJ",
        "266": "GA", "268": "GE", "270": "GM", "275": "PS", "276": "DE",
        "288": "GH", "296": "KI", "300": "GR", "304": "GL", "308": "GD",
        "320": "GT", "324": "GN", "328": "GY", "332": "HT", "336": "VA",
        "340": "HN", "344": "HK", "348": "HU", "352": "IS", "356": "IN",
        "360": "ID", "364": "IR", "368": "IQ", "372": "IE", "376": "IL",
        "380": "IT", "384": "CI", "388": "JM", "392": "JP", "398": "KZ",
        "400": "JO", "404": "KE", "408": "KP", "410": "KR", "414": "KW",
        "417": "KG", "418": "LA", "422": "LB", "426": "LS", "428": "LV",
        "430": "LR", "434": "LY", "438": "LI", "440": "LT", "442": "LU",
        "450": "MG", "454": "MW", "458": "MY", "462": "MV", "466": "ML",
        "470": "MT", "478": "MR", "480": "MU", "484": "MX", "492": "MC",
        "496": "MN", "498": "MD", "499": "ME", "504": "MA", "508": "MZ",
        "512": "OM", "516": "NA", "520": "NR", "524": "NP", "528": "NL",
        "540": "NC", "548": "VU", "554": "NZ", "558": "NI", "562": "NE",
        "566": "NG", "578": "NO", "586": "PK", "591": "PA", "598": "PG",
        "600": "PY", "604": "PE", "608": "PH", "616": "PL", "620": "PT",
        "624": "GW", "626": "TL", "630": "PR", "634": "QA", "642": "RO",
        "643": "RU", "646": "RW", "659": "KN", "662": "LC", "670": "VC",
        "674": "SM", "678": "ST", "682": "SA", "686": "SN", "688": "RS",
        "690": "SC", "694": "SL", "702": "SG", "703": "SK", "704": "VN",
        "705": "SI", "706": "SO", "710": "ZA", "716": "ZW", "720": "YE",
        "724": "ES", "728": "SS", "729": "SD", "740": "SR", "748": "SZ",
        "752": "SE", "756": "CH", "760": "SY", "762": "TJ", "764": "TH",
        "768": "TG", "776": "TO", "780": "TT", "784": "AE", "788": "TN",
        "792": "TR", "795": "TM", "800": "UG", "804": "UA", "807": "MK",
        "818": "EG", "826": "GB", "834": "TZ", "840": "US", "854": "BF",
        "858": "UY", "860": "UZ", "862": "VE", "887": "YE", "894": "ZM",
        "010": "AQ", "-99": "XK",
      };

      // Country polygons
      svg
        .selectAll(".country")
        .data((countries as any).features)
        .join("path")
        .attr("class", "country")
        .attr("d", path as any)
        .attr("fill", (d: any) => {
          const alpha2 = numericToAlpha2[d.id] || "";
          const entry = countryIndex.get(alpha2);
          return countryColor(alpha2, entry?.connection_count ?? 0);
        })
        .attr("stroke", "oklch(0.25 0.01 285)")
        .attr("stroke-width", 0.5)
        .attr("cursor", "pointer")
        .on("mouseenter", function (_event: MouseEvent, d: any) {
          d3.select(this).attr("stroke", "oklch(0.7 0.15 200)").attr("stroke-width", 1.5);
          const alpha2 = numericToAlpha2[(d as any).id] || "";
          const entry = countryIndex.get(alpha2);
          if (entry) {
            tooltip.style.display = "block";
            tooltip.innerHTML = `
              <div style="font-weight:600;margin-bottom:4px">${entry.country} (${entry.country_code})</div>
              <div>Connections: ${formatNumber(entry.connection_count)}</div>
              <div>Sources: ${formatNumber(entry.unique_sources)} / Destinations: ${formatNumber(entry.unique_destinations)}</div>
              <div>TX: ${formatBytes(entry.total_tx)} / RX: ${formatBytes(entry.total_rx)}</div>
              ${entry.top_orgs.length > 0 ? `<div style="margin-top:4px;font-size:10px;color:oklch(0.6 0.01 285)">Top: ${entry.top_orgs.slice(0, 3).join(", ")}</div>` : ""}
            `;
          }
        })
        .on("mousemove", (event: MouseEvent) => {
          tooltip.style.left = `${event.clientX + 14}px`;
          tooltip.style.top = `${event.clientY - 12}px`;
        })
        .on("mouseleave", function () {
          d3.select(this).attr("stroke", "oklch(0.25 0.01 285)").attr("stroke-width", 0.5);
          tooltip.style.display = "none";
        })
        .on("click", (_event: any, d: any) => {
          const alpha2 = numericToAlpha2[(d as any).id] || "";
          onCountryClick?.(alpha2);
        });

      // Arc lines from home to countries with data
      const arcs = data.filter((d) => d.lat !== 0 && d.lon !== 0);
      for (const entry of arcs) {
        const dest: [number, number] = [entry.lon, entry.lat];
        const lineGeo: GeoJSON.Feature<GeoJSON.LineString> = {
          type: "Feature",
          properties: {},
          geometry: { type: "LineString", coordinates: [HOME, dest] },
        };

        const isFlagged = FLAGGED_COUNTRIES.has(entry.country_code);
        const t = colorScale(entry.connection_count) as unknown as number;

        svg
          .append("path")
          .datum(lineGeo)
          .attr("d", path as any)
          .attr("fill", "none")
          .attr("stroke", isFlagged ? `oklch(0.55 0.2 25)` : `oklch(0.55 0.15 200)`)
          .attr("stroke-width", 0.5 + t * 1.5)
          .attr("stroke-opacity", 0.3 + t * 0.4)
          .attr("pointer-events", "none");

        // Destination circle marker
        const projected = projection(dest);
        if (projected) {
          const radius = Math.max(2, Math.log2(entry.connection_count + 1) * 1.5);
          svg
            .append("circle")
            .attr("cx", projected[0])
            .attr("cy", projected[1])
            .attr("r", radius)
            .attr("fill", isFlagged ? "oklch(0.55 0.2 25)" : "oklch(0.6 0.15 200)")
            .attr("fill-opacity", 0.7)
            .attr("stroke", isFlagged ? "oklch(0.7 0.2 25)" : "oklch(0.7 0.15 200)")
            .attr("stroke-width", 0.5)
            .attr("pointer-events", "none");
        }
      }

      // Home marker
      const homeProj = projection(HOME);
      if (homeProj) {
        svg
          .append("circle")
          .attr("cx", homeProj[0])
          .attr("cy", homeProj[1])
          .attr("r", 4)
          .attr("fill", "oklch(0.7 0.2 145)")
          .attr("stroke", "oklch(0.9 0.1 145)")
          .attr("stroke-width", 1.5);
      }
    });
  }, [data, dimensions, countryIndex, colorScale, onCountryClick, timeRange]);

  // Summary stats
  const totalCountries = data.length;
  const totalConnections = data.reduce((s, d) => s + d.connection_count, 0);
  const flaggedCountries = data.filter((d) =>
    FLAGGED_COUNTRIES.has(d.country_code),
  );

  return (
    <div className="space-y-3">
      {/* Summary bar */}
      <div className="flex flex-wrap gap-4 text-xs text-muted-foreground">
        <span>
          <span className="font-medium text-foreground">{totalCountries}</span>{" "}
          countries
        </span>
        <span>
          <span className="font-medium text-foreground">
            {formatNumber(totalConnections)}
          </span>{" "}
          connections
        </span>
        {flaggedCountries.length > 0 && (
          <span className="text-destructive">
            <span className="font-medium">
              {flaggedCountries.length}
            </span>{" "}
            flagged countries
          </span>
        )}
      </div>

      {/* Map */}
      <div className="relative overflow-hidden rounded-lg border border-border bg-[oklch(0.13_0.01_285)]">
        <svg
          ref={svgRef}
          width={dimensions.width}
          height={dimensions.height}
          viewBox={`0 0 ${dimensions.width} ${dimensions.height}`}
          className="w-full"
        />
      </div>

      {/* Tooltip */}
      <div
        ref={tooltipRef}
        style={{
          display: "none",
          position: "fixed",
          pointerEvents: "none",
          zIndex: 50,
          backgroundColor: "oklch(0.175 0.015 285)",
          border: "1px solid oklch(0.3 0.015 285)",
          color: "oklch(0.95 0.01 285)",
          borderRadius: "6px",
          padding: "8px 12px",
          fontSize: "12px",
          lineHeight: "1.5",
          maxWidth: "300px",
        }}
      />

      {/* Legend */}
      <div className="flex items-center gap-4 text-[10px] text-muted-foreground">
        <div className="flex items-center gap-1.5">
          <span
            className="inline-block h-2.5 w-2.5 rounded-full"
            style={{ background: "oklch(0.7 0.2 145)" }}
          />
          Home
        </div>
        <div className="flex items-center gap-1.5">
          <span
            className="inline-block h-2.5 w-2.5 rounded-full"
            style={{ background: "oklch(0.6 0.15 200)" }}
          />
          Normal
        </div>
        <div className="flex items-center gap-1.5">
          <span
            className="inline-block h-2.5 w-2.5 rounded-full"
            style={{ background: "oklch(0.55 0.2 25)" }}
          />
          Flagged
        </div>
      </div>
    </div>
  );
}
