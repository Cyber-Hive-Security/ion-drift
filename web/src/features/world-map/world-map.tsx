import { useEffect, useRef, useMemo, useState, useCallback } from "react";
import * as d3 from "d3";
import * as topojson from "topojson-client";
import type { Topology, GeometryCollection } from "topojson-specification";
import type { GeoSummaryEntry, CitySummaryEntry } from "@/api/types";
import { formatBytes, formatNumber } from "@/lib/format";
import { escHtml } from "@/lib/utils";

// Home location (Ogden, UT) and home country
const HOME: [number, number] = [-111.97, 41.22];
const HOME_COUNTRY = "US";

// Distance threshold (in projected pixels) to suppress city dots near home
const HOME_EXCLUSION_PX = 30;

// Country centroid fallbacks — approximate [lon, lat] for countries
// that may have lat=0, lon=0 from the backend (no MaxMind data yet).
const COUNTRY_CENTROIDS: Record<string, [number, number]> = {
  AF: [67.71, 33.94], AL: [20.17, 41.15], DZ: [1.66, 28.03],
  AO: [-11.2, -8.84], AR: [-63.62, -38.42], AM: [45.04, 40.07],
  AU: [133.78, -25.27], AT: [14.55, 47.52], AZ: [47.58, 40.14],
  BS: [-77.4, 25.03], BH: [50.56, 26.07], BD: [90.36, 23.68],
  BY: [27.95, 53.71], BE: [4.47, 50.5], BZ: [-88.5, 17.19],
  BJ: [2.32, 9.31], BT: [90.43, 27.51], BO: [-63.59, -16.29],
  BA: [17.68, 43.92], BW: [24.68, -22.33], BR: [-51.93, -14.24],
  BN: [114.73, 4.54], BG: [25.49, 42.73], BF: [-1.56, 12.24],
  BI: [29.92, -3.37], KH: [104.99, 12.57], CM: [12.35, 7.37],
  CA: [-106.35, 56.13], CF: [20.94, 6.61], TD: [18.73, 15.45],
  CL: [-71.54, -35.68], CN: [104.2, 35.86], CO: [-74.3, 4.57],
  CD: [21.76, -4.04], CG: [15.83, -0.23], CR: [-83.75, 9.75],
  CI: [-5.55, 7.54], HR: [15.2, 45.1], CU: [-77.78, 21.52],
  CY: [33.43, 35.13], CZ: [15.47, 49.82], DK: [9.5, 56.26],
  DJ: [42.59, 11.83], DO: [-70.16, 18.74], EC: [-78.18, -1.83],
  EG: [30.8, 26.82], SV: [-88.9, 13.79], GQ: [10.27, 1.65],
  ER: [39.78, 15.18], EE: [25.01, 58.6], ET: [40.49, 9.15],
  FI: [25.75, 61.92], FR: [2.21, 46.23], GA: [11.61, -0.8],
  GM: [-15.31, 13.44], GE: [43.36, 42.32], DE: [10.45, 51.17],
  GH: [-1.02, 7.95], GR: [21.82, 39.07], GL: [-42.6, 71.71],
  GT: [-90.23, 15.78], GN: [-9.68, 9.95], GW: [-15.18, 11.8],
  GY: [-58.93, 4.86], HT: [-72.29, 18.97], HN: [-86.24, 15.2],
  HU: [19.5, 47.16], IS: [-18.9, 64.96], IN: [78.96, 20.59],
  ID: [113.92, -0.79], IR: [53.69, 32.43], IQ: [43.68, 33.22],
  IE: [-8.24, 53.41], IL: [34.85, 31.05], IT: [12.57, 41.87],
  JM: [-77.3, 18.11], JP: [138.25, 36.2], JO: [36.24, 30.59],
  KZ: [66.92, 48.02], KE: [37.91, -0.02], KP: [127.51, 40.34],
  KR: [127.77, 35.91], KW: [47.48, 29.31], KG: [74.77, 41.2],
  LA: [102.5, 19.86], LV: [24.6, 56.88], LB: [35.86, 33.87],
  LS: [28.23, -29.61], LR: [-9.43, 6.43], LY: [17.23, 26.34],
  LT: [23.88, 55.17], LU: [6.13, 49.82], MG: [46.87, -18.77],
  MW: [34.3, -13.25], MY: [101.98, 4.21], MV: [73.22, 3.2],
  ML: [-3.99, 17.57], MR: [-10.94, 21.01], MU: [57.55, -20.35],
  MX: [-102.55, 23.63], MD: [28.37, 47.41], MN: [103.85, 46.86],
  ME: [19.37, 42.71], MA: [-7.09, 31.79], MZ: [35.53, -18.67],
  MM: [95.96, 21.91], NA: [18.49, -22.96], NP: [84.12, 28.39],
  NL: [5.29, 52.13], NZ: [174.89, -40.9], NI: [-85.21, 12.87],
  NE: [8.08, 17.61], NG: [8.68, 9.08], NO: [8.47, 60.47],
  OM: [55.92, 21.51], PK: [69.35, 30.38], PA: [-80.78, 8.54],
  PG: [143.96, -6.31], PY: [-58.44, -23.44], PE: [-75.02, -9.19],
  PH: [121.77, 12.88], PL: [19.15, 51.92], PT: [-8.22, 39.4],
  QA: [51.18, 25.35], RO: [24.97, 45.94], RU: [105.32, 61.52],
  RW: [29.87, -1.94], SA: [45.08, 23.89], SN: [-14.45, 14.5],
  RS: [21.01, 44.02], SL: [-11.78, 8.46], SG: [103.82, 1.35],
  SK: [19.7, 48.67], SI: [14.97, 46.15], SO: [46.2, 5.15],
  ZA: [22.94, -30.56], SS: [31.31, 6.88], ES: [-3.75, 40.46],
  LK: [80.77, 7.87], SD: [30.22, 12.86], SR: [-56.03, 3.92],
  SE: [18.64, 60.13], CH: [8.23, 46.82], SY: [38.99, 34.8],
  TW: [120.96, 23.7], TJ: [71.28, 38.86], TZ: [34.89, -6.37],
  TH: [100.99, 15.87], TG: [0.82, 8.62], TT: [-61.22, 10.69],
  TN: [9.54, 33.89], TR: [35.24, 38.96], TM: [59.56, 38.97],
  UG: [32.29, 1.37], UA: [31.17, 48.38], AE: [53.85, 23.42],
  GB: [-3.44, 55.38], US: [-95.71, 37.09], UY: [-55.77, -32.52],
  UZ: [64.59, 41.38], VE: [-66.59, 6.42], VN: [108.28, 14.06],
  YE: [48.52, 15.55], ZM: [27.85, -13.13], ZW: [29.15, -19.02],
  PS: [35.23, 31.95], XK: [20.9, 42.6], HK: [114.17, 22.32],
  MK: [21.75, 41.51], MT: [14.38, 35.94], SC: [55.49, -4.68],
};

// Convert country code to flag emoji
function countryFlag(code: string): string {
  if (code.length !== 2) return "";
  const offset = 0x1f1e6 - 65; // 'A' = 65
  return String.fromCodePoint(
    code.charCodeAt(0) + offset,
    code.charCodeAt(1) + offset,
  );
}

// Determine destination coordinates for a country entry
function getDestination(entry: GeoSummaryEntry): [number, number] | null {
  if (entry.lat !== 0 || entry.lon !== 0) return [entry.lon, entry.lat];
  return COUNTRY_CENTROIDS[entry.country_code] ?? null;
}

// Normalized log scale: maps values in [minVal, maxVal] to [outMin, outMax]
function logScale(
  value: number,
  minVal: number,
  maxVal: number,
  outMin: number,
  outMax: number,
): number {
  if (minVal >= maxVal || value <= 0) return outMin;
  const logMin = Math.log(Math.max(1, minVal));
  const logMax = Math.log(Math.max(2, maxVal));
  if (logMax <= logMin) return (outMin + outMax) / 2;
  const t = (Math.log(Math.max(1, value)) - logMin) / (logMax - logMin);
  return outMin + (outMax - outMin) * Math.max(0, Math.min(1, t));
}

interface WorldMapProps {
  data: GeoSummaryEntry[];
  cityData?: CitySummaryEntry[];
  isLoading?: boolean;
  onCountryClick?: (code: string) => void;
  onCityClick?: (city: string, countryCode: string) => void;
  timeRange: string;
}

export function WorldMap({
  data,
  cityData = [],
  isLoading = false,
  onCountryClick,
  onCityClick,
  timeRange,
}: WorldMapProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const tooltipRef = useRef<HTMLDivElement>(null);
  const zoomRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);
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
        setDimensions({ width, height: Math.max(500, width * 0.6) });
      }
    });
    ro.observe(container);
    return () => ro.disconnect();
  }, []);

  // Index data by country_code for O(1) lookup
  const countryIndex = useMemo(() => {
    const idx = new Map<string, GeoSummaryEntry>();
    for (const entry of data) idx.set(entry.country_code, entry);
    return idx;
  }, [data]);

  // Pre-compute scaling ranges for arcs and dots
  const { minBytes, maxBytes, minCount, maxCount } = useMemo(() => {
    const nonHome = data.filter((d) => d.country_code !== HOME_COUNTRY);
    const bytes = nonHome.map((d) => d.total_tx + d.total_rx).filter((b) => b > 0);
    const counts = nonHome.map((d) => d.connection_count).filter((c) => c > 0);
    return {
      minBytes: bytes.length > 0 ? Math.min(...bytes) : 1,
      maxBytes: bytes.length > 0 ? Math.max(...bytes) : 1,
      minCount: counts.length > 0 ? Math.min(...counts) : 1,
      maxCount: counts.length > 0 ? Math.max(...counts) : 1,
    };
  }, [data]);

  // City dot scaling ranges
  const { minCityCount, maxCityCount, minCityBytes, maxCityBytes } = useMemo(() => {
    const counts = cityData.map((d) => d.connection_count).filter((c) => c > 0);
    const bytes = cityData.map((d) => d.bytes_tx + d.bytes_rx).filter((b) => b > 0);
    return {
      minCityCount: counts.length > 0 ? Math.min(...counts) : 1,
      maxCityCount: counts.length > 0 ? Math.max(...counts) : 1,
      minCityBytes: bytes.length > 0 ? Math.min(...bytes) : 1,
      maxCityBytes: bytes.length > 0 ? Math.max(...bytes) : 1,
    };
  }, [cityData]);

  // Country fill color
  function countryColor(code: string, entry: GeoSummaryEntry | undefined): string {
    if (!entry || entry.connection_count === 0) return "#141A21";
    if (code === HOME_COUNTRY) return "#21D07A";
    if (entry.flagged_count > 0) return "#FF4D4F";
    return "#2FA4FF";
  }

  function arcColor(entry: { flagged_count: number }): string {
    if (entry.flagged_count > 0) return "#FF4D4F";
    return "#2FA4FF";
  }

  // Cache the TopoJSON so we don't re-fetch on every effect run
  const worldTopoRef = useRef<Topology | null>(null);

  // Zoom controls
  const handleZoomIn = useCallback(() => {
    const svg = svgRef.current;
    const zoom = zoomRef.current;
    if (svg && zoom) {
      d3.select(svg).transition().duration(300).call(zoom.scaleBy, 1.5);
    }
  }, []);

  const handleZoomOut = useCallback(() => {
    const svg = svgRef.current;
    const zoom = zoomRef.current;
    if (svg && zoom) {
      d3.select(svg).transition().duration(300).call(zoom.scaleBy, 1 / 1.5);
    }
  }, []);

  const handleZoomReset = useCallback(() => {
    const svg = svgRef.current;
    const zoom = zoomRef.current;
    if (svg && zoom) {
      d3.select(svg)
        .transition()
        .duration(500)
        .call(zoom.transform, d3.zoomIdentity);
    }
  }, []);

  // D3 rendering effect — only runs when data is ready
  useEffect(() => {
    const svgEl = svgRef.current;
    const svg = d3.select(svgEl);
    const tooltip = tooltipRef.current;
    if (!svgEl || !tooltip) return;

    // Don't render until we have data (but still render base map)
    const hasData = data.length > 0;

    const { width, height } = dimensions;

    // Track whether this effect invocation has been superseded
    let cancelled = false;

    const projection = d3
      .geoNaturalEarth1()
      .fitSize([width, height], { type: "Sphere" });

    const path = d3.geoPath(projection);

    const esc = escHtml;

    // Tooltip helpers
    const isMobile = width < 768;
    function showTooltip(html: string) {
      tooltip!.style.display = "block";
      tooltip!.innerHTML = html;
    }
    function moveTooltip(event: MouseEvent) {
      if (isMobile) {
        // On mobile, anchor tooltip to bottom-center of the map container
        // to avoid finger occlusion
        const container = svgEl!.parentElement;
        if (container) {
          const rect = container.getBoundingClientRect();
          tooltip!.style.left = `${rect.left + rect.width / 2}px`;
          tooltip!.style.top = `${rect.bottom - 8}px`;
          tooltip!.style.transform = "translate(-50%, -100%)";
        }
      } else {
        tooltip!.style.left = `${event.clientX + 14}px`;
        tooltip!.style.top = `${event.clientY - 12}px`;
        tooltip!.style.transform = "";
      }
    }
    function hideTooltip() {
      tooltip!.style.display = "none";
      tooltip!.style.transform = "";
    }

    function renderMap(world: Topology) {
      if (cancelled) return;

      // Clear previous render
      svg.selectAll("*").remove();

      // Create a group that will be transformed by zoom
      const zoomGroup = svg.append("g").attr("class", "zoom-group");

      // Set up zoom behavior
      const zoom = d3
        .zoom<SVGSVGElement, unknown>()
        .scaleExtent([1, 12])
        .on("zoom", (event) => {
          zoomGroup.attr("transform", event.transform);
        });
      (svg as d3.Selection<SVGSVGElement, unknown, null, undefined>).call(zoom);
      zoomRef.current = zoom;

      // Background sphere
      zoomGroup
        .append("path")
        .datum({ type: "Sphere" } as any)
        .attr("d", path as any)
        .attr("fill", "#0B0F14")
        .attr("stroke", "#1C232C");

      const countries = topojson.feature(
        world,
        world.objects.countries as GeometryCollection,
      );

      // ISO 3166-1 numeric to alpha-2 mapping
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

      // ── Country polygons ──────────────────────────────────────
      zoomGroup
        .selectAll(".country")
        .data((countries as any).features)
        .join("path")
        .attr("class", "country")
        .attr("d", path as any)
        .attr("fill", (d: any) => {
          const alpha2 = numericToAlpha2[d.id] || "";
          return countryColor(alpha2, countryIndex.get(alpha2));
        })
        .attr("stroke", "#1C232C")
        .attr("stroke-width", 0.5)
        .attr("cursor", "pointer")
        .on("mouseenter", function (_event: MouseEvent, d: any) {
          d3.select(this).attr("stroke", "#00E5FF").attr("stroke-width", 1.5);
          const alpha2 = numericToAlpha2[(d as any).id] || "";
          const entry = countryIndex.get(alpha2);
          if (entry) {
            const flagged = entry.flagged_count > 0
              ? `<div style="color:#FF4D4F;margin-top:2px">Flagged: ${formatNumber(entry.flagged_count)}</div>`
              : "";
            showTooltip(`
              <div style="font-weight:600;margin-bottom:4px">${countryFlag(entry.country_code)} ${esc(entry.country)} (${esc(entry.country_code)})</div>
              <div>Connections: ${formatNumber(entry.connection_count)}</div>
              <div>Sources: ${formatNumber(entry.unique_sources)} / Destinations: ${formatNumber(entry.unique_destinations)}</div>
              <div>TX: ${formatBytes(entry.total_tx)} / RX: ${formatBytes(entry.total_rx)}</div>
              ${flagged}
              ${entry.top_orgs.length > 0 ? `<div style="margin-top:4px;font-size:10px;color:#6B7785">Top: ${entry.top_orgs.slice(0, 3).map(esc).join(", ")}</div>` : ""}
            `);
          }
        })
        .on("mousemove", (event: MouseEvent) => moveTooltip(event))
        .on("mouseleave", function () {
          d3.select(this).attr("stroke", "#1C232C").attr("stroke-width", 0.5);
          hideTooltip();
        })
        .on("click", (_event: any, d: any) => {
          const alpha2 = numericToAlpha2[(d as any).id] || "";
          onCountryClick?.(alpha2);
        });

      // ── Arc lines, dots, cities — only when data is loaded ──
      if (!hasData) return;

      const arcsGroup = zoomGroup.append("g").attr("class", "arcs");
      const countryDotsGroup = zoomGroup.append("g").attr("class", "country-dots");

      for (const entry of data) {
        if (entry.country_code === HOME_COUNTRY) continue;
        const dest = getDestination(entry);
        if (!dest) continue;

        const color = arcColor(entry);
        const totalBytes = entry.total_tx + entry.total_rx;
        const strokeWidth = logScale(totalBytes, minBytes, maxBytes, 1, 6);
        const opacity = Math.min(0.85, 0.3 + strokeWidth * 0.08);

        const lineGeo: GeoJSON.Feature<GeoJSON.LineString> = {
          type: "Feature",
          properties: {},
          geometry: { type: "LineString", coordinates: [HOME, dest] },
        };

        // Arc line — interactive
        arcsGroup
          .append("path")
          .datum(lineGeo)
          .attr("d", path as any)
          .attr("fill", "none")
          .attr("stroke", color)
          .attr("stroke-width", strokeWidth)
          .attr("stroke-opacity", opacity)
          .attr("cursor", "pointer")
          .on("mouseenter", function (event: MouseEvent) {
            d3.select(this)
              .attr("stroke-width", strokeWidth + 2)
              .attr("stroke-opacity", 1);
            showTooltip(`
              <div style="font-weight:600;margin-bottom:4px">Ogden, UT &rarr; ${countryFlag(entry.country_code)} ${esc(entry.country)}</div>
              <div>Connections: ${formatNumber(entry.connection_count)}</div>
              <div>TX: ${formatBytes(entry.total_tx)} / RX: ${formatBytes(entry.total_rx)}</div>
              ${entry.flagged_count > 0 ? `<div style="color:#FF4D4F">Flagged: ${formatNumber(entry.flagged_count)}</div>` : ""}
              ${entry.top_orgs.length > 0 ? `<div style="font-size:10px;color:#6B7785">Top: ${entry.top_orgs.slice(0, 3).map(esc).join(", ")}</div>` : ""}
            `);
            moveTooltip(event);
          })
          .on("mousemove", (event: MouseEvent) => moveTooltip(event))
          .on("mouseleave", function () {
            d3.select(this)
              .attr("stroke-width", strokeWidth)
              .attr("stroke-opacity", opacity);
            hideTooltip();
          })
          .on("click", () => onCountryClick?.(entry.country_code));

        // Country destination dot — scaled by connection count
        const projected = projection(dest);
        if (projected) {
          const radius = logScale(entry.connection_count, minCount, maxCount, 4, 16);
          countryDotsGroup
            .append("circle")
            .attr("cx", projected[0])
            .attr("cy", projected[1])
            .attr("r", radius)
            .attr("fill", color)
            .attr("fill-opacity", 0.6)
            .attr("stroke", color)
            .attr("stroke-width", 0.5)
            .attr("cursor", "pointer")
            .on("mouseenter", function (event: MouseEvent) {
              d3.select(this).attr("r", radius + 2).attr("fill-opacity", 1);
              showTooltip(`
                <div style="font-weight:600;margin-bottom:4px">${countryFlag(entry.country_code)} ${esc(entry.country)} (${esc(entry.country_code)})</div>
                <div>Connections: ${formatNumber(entry.connection_count)}</div>
                <div>Sources: ${formatNumber(entry.unique_sources)} / Destinations: ${formatNumber(entry.unique_destinations)}</div>
                <div>TX: ${formatBytes(entry.total_tx)} / RX: ${formatBytes(entry.total_rx)}</div>
                ${entry.flagged_count > 0 ? `<div style="color:#FF4D4F">Flagged: ${formatNumber(entry.flagged_count)}</div>` : ""}
              `);
              moveTooltip(event);
            })
            .on("mousemove", (event: MouseEvent) => moveTooltip(event))
            .on("mouseleave", function () {
              d3.select(this).attr("r", radius).attr("fill-opacity", 0.6);
              hideTooltip();
            })
            .on("click", () => onCountryClick?.(entry.country_code));
        }
      }

      // ── City-level arcs and dots ───────────────────────────────
      const homeProj = projection(HOME);
      const cityArcsGroup = zoomGroup.append("g").attr("class", "city-arcs");
      const cityDotsGroup = zoomGroup.append("g").attr("class", "city-dots");

      for (const city of cityData) {
        const cityCoords: [number, number] = [city.lon, city.lat];
        const projected = projection(cityCoords);
        if (!projected) continue;

        // Skip cities too close to home dot
        if (homeProj) {
          const dx = projected[0] - homeProj[0];
          const dy = projected[1] - homeProj[1];
          if (Math.sqrt(dx * dx + dy * dy) < HOME_EXCLUSION_PX) continue;
        }

        const color = arcColor(city);
        // City dots: 2px to 10px (always smaller than country dots' 4-16px range)
        const radius = logScale(city.connection_count, minCityCount, maxCityCount, 2, 10);

        // Arc line from home to city
        const cityBytes = city.bytes_tx + city.bytes_rx;
        const arcWidth = logScale(cityBytes, minCityBytes, maxCityBytes, 0.5, 3);
        const arcOpacity = Math.min(0.7, 0.15 + arcWidth * 0.06);

        const lineGeo: GeoJSON.Feature<GeoJSON.LineString> = {
          type: "Feature",
          properties: {},
          geometry: { type: "LineString", coordinates: [HOME, cityCoords] },
        };

        cityArcsGroup
          .append("path")
          .datum(lineGeo)
          .attr("d", path as any)
          .attr("fill", "none")
          .attr("stroke", color)
          .attr("stroke-width", arcWidth)
          .attr("stroke-opacity", arcOpacity)
          .attr("pointer-events", "none");

        // Outer halo ring
        cityDotsGroup
          .append("circle")
          .attr("cx", projected[0])
          .attr("cy", projected[1])
          .attr("r", radius + 2)
          .attr("fill", "none")
          .attr("stroke", color)
          .attr("stroke-width", 0.5)
          .attr("stroke-opacity", 0.3)
          .attr("pointer-events", "none");

        // Inner filled dot
        cityDotsGroup
          .append("circle")
          .attr("cx", projected[0])
          .attr("cy", projected[1])
          .attr("r", radius)
          .attr("fill", color)
          .attr("fill-opacity", 0.5)
          .attr("stroke", color)
          .attr("stroke-width", 0.75)
          .attr("cursor", "pointer")
          .on("mouseenter", function (event: MouseEvent) {
            d3.select(this).attr("r", radius + 1.5).attr("fill-opacity", 0.9);
            const orgsLine = city.top_orgs.length > 0
              ? `<div style="font-size:10px;color:#6B7785">Top: ${city.top_orgs.slice(0, 3).map(esc).join(" &middot; ")}</div>`
              : "";
            showTooltip(`
              <div style="font-weight:600;margin-bottom:4px">${esc(city.city)}, ${esc(city.country_code)}</div>
              <div>${formatNumber(city.connection_count)} connections &middot; ${formatNumber(city.unique_ips)} unique IPs</div>
              <div>${formatBytes(city.bytes_tx)} tx &middot; ${formatBytes(city.bytes_rx)} rx</div>
              ${city.flagged_count > 0 ? `<div style="color:#FF4D4F">Flagged: ${formatNumber(city.flagged_count)}</div>` : ""}
              ${orgsLine}
            `);
            moveTooltip(event);
          })
          .on("mousemove", (event: MouseEvent) => moveTooltip(event))
          .on("mouseleave", function () {
            d3.select(this).attr("r", radius).attr("fill-opacity", 0.5);
            hideTooltip();
          })
          .on("click", () => onCityClick?.(city.city, city.country_code));
      }

      // ── Home marker (on top of everything, fixed size) ────────
      if (homeProj) {
        zoomGroup
          .append("circle")
          .attr("cx", homeProj[0])
          .attr("cy", homeProj[1])
          .attr("r", 4.5)
          .attr("fill", "#21D07A")
          .attr("stroke", "#21D07A")
          .attr("stroke-width", 1.5);
      }
    }

    // Load TopoJSON once, then render synchronously on subsequent updates
    if (worldTopoRef.current) {
      renderMap(worldTopoRef.current);
    } else {
      d3.json<Topology>("/world-110m.json").then((world) => {
        if (!world || cancelled) return;
        worldTopoRef.current = world;
        renderMap(world);
      });
    }

    return () => {
      cancelled = true;
    };
  }, [data, cityData, dimensions, countryIndex, minBytes, maxBytes, minCount, maxCount, minCityCount, maxCityCount, minCityBytes, maxCityBytes, onCountryClick, onCityClick, timeRange]);

  // Summary: per-country breakdown sorted by connection count
  const sortedCountries = useMemo(
    () => [...data].sort((a, b) => b.connection_count - a.connection_count),
    [data],
  );
  const totalConnections = useMemo(
    () => data.reduce((s, d) => s + d.connection_count, 0),
    [data],
  );
  const flaggedTotal = useMemo(
    () => data.filter((d) => d.flagged_count > 0).length,
    [data],
  );

  const TOP_N = 5;
  const topCountries = sortedCountries.slice(0, TOP_N);
  const remaining = sortedCountries.length - TOP_N;

  return (
    <div className="space-y-3">
      {/* Summary bar */}
      <div className="flex flex-wrap items-center gap-x-1.5 gap-y-1 text-xs text-muted-foreground">
        <span className="font-medium text-foreground mr-1">
          {data.length} countries
        </span>
        <span className="mr-1">&middot;</span>
        <span className="font-medium text-foreground mr-1">
          {formatNumber(totalConnections)} connections
        </span>
        {flaggedTotal > 0 && (
          <>
            <span className="mr-1">&middot;</span>
            <span className="text-destructive font-medium mr-2">
              {flaggedTotal} flagged
            </span>
          </>
        )}
        {topCountries.length > 0 && (
          <>
            <span className="mr-1">&middot;</span>
            {topCountries.map((c, i) => (
              <span key={c.country_code}>
                <button
                  type="button"
                  className="hover:underline cursor-pointer"
                  onClick={() => onCountryClick?.(c.country_code)}
                >
                  {countryFlag(c.country_code)} {c.country_code} ({formatNumber(c.connection_count)})
                </button>
                {i < topCountries.length - 1 && <span className="mx-0.5">&middot;</span>}
              </span>
            ))}
            {remaining > 0 && (
              <span className="text-muted-foreground ml-0.5">
                + {remaining} more
              </span>
            )}
          </>
        )}
      </div>

      {/* Map */}
      <div className="relative overflow-hidden rounded-lg border border-border bg-[#0B0F14]">
        {isLoading && data.length === 0 ? (
          <div
            className="flex items-center justify-center text-sm text-muted-foreground"
            style={{ width: dimensions.width, height: dimensions.height }}
          >
            Loading map data...
          </div>
        ) : (
          <>
            <svg
              ref={svgRef}
              width={dimensions.width}
              height={dimensions.height}
              viewBox={`0 0 ${dimensions.width} ${dimensions.height}`}
              className="w-full"
            />
            {/* Zoom controls */}
            <div className="absolute top-3 right-3 flex flex-col gap-1">
              <button
                type="button"
                onClick={handleZoomIn}
                className="flex h-11 w-11 items-center justify-center rounded bg-card/80 text-base font-bold text-foreground backdrop-blur hover:bg-card border border-border md:h-7 md:w-7 md:text-sm"
                title="Zoom in"
              >
                +
              </button>
              <button
                type="button"
                onClick={handleZoomOut}
                className="flex h-11 w-11 items-center justify-center rounded bg-card/80 text-base font-bold text-foreground backdrop-blur hover:bg-card border border-border md:h-7 md:w-7 md:text-sm"
                title="Zoom out"
              >
                &minus;
              </button>
              <button
                type="button"
                onClick={handleZoomReset}
                className="flex h-11 w-11 items-center justify-center rounded bg-card/80 text-xs font-medium text-muted-foreground backdrop-blur hover:bg-card hover:text-foreground border border-border md:h-7 md:w-7 md:text-[10px]"
                title="Reset zoom"
              >
                1:1
              </button>
            </div>
          </>
        )}
      </div>

      {/* Tooltip */}
      <div
        ref={tooltipRef}
        style={{
          display: "none",
          position: "fixed",
          pointerEvents: "none",
          zIndex: 50,
          backgroundColor: "#141A21",
          border: "1px solid #2A323D",
          color: "#E6EDF3",
          borderRadius: "6px",
          padding: "8px 12px",
          fontSize: "12px",
          lineHeight: "1.5",
          maxWidth: "300px",
        }}
      />

      {/* Legend */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground md:text-[10px]">
        <div className="flex items-center gap-1.5">
          <span
            className="inline-block h-2.5 w-2.5 rounded-full"
            style={{ background: "#21D07A" }}
          />
          Home (US)
        </div>
        <div className="flex items-center gap-1.5">
          <span
            className="inline-block h-2.5 w-2.5 rounded-full"
            style={{ background: "#2FA4FF" }}
          />
          Normal
        </div>
        <div className="flex items-center gap-1.5">
          <span
            className="inline-block h-2.5 w-2.5 rounded-full"
            style={{ background: "#FF4D4F" }}
          />
          Flagged
        </div>
        {cityData.length > 0 && (
          <div className="flex items-center gap-1.5">
            <span
              className="inline-block h-1.5 w-1.5 rounded-full ring-1"
              style={{ background: "#2FA4FF", boxShadow: "0 0 0 2px rgba(47, 164, 255, 0.3)" }}
            />
            City
          </div>
        )}
        <div className="ml-auto text-[11px] md:text-[9px]">Scroll to zoom &middot; Drag to pan</div>
      </div>
    </div>
  );
}
