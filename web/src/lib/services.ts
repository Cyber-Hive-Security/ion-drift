const WELL_KNOWN_PORTS: Record<number, string> = {
  20: "FTP-Data",
  21: "FTP",
  22: "SSH",
  25: "SMTP",
  53: "DNS",
  67: "DHCP-S",
  68: "DHCP-C",
  80: "HTTP",
  110: "POP3",
  123: "NTP",
  143: "IMAP",
  161: "SNMP",
  443: "HTTPS",
  465: "SMTPS",
  587: "Submission",
  993: "IMAPS",
  995: "POP3S",
  1433: "MSSQL",
  1883: "MQTT",
  3000: "Dev",
  3306: "MySQL",
  3389: "RDP",
  5432: "PostgreSQL",
  5672: "AMQP",
  6379: "Redis",
  8080: "HTTP-Alt",
  8443: "HTTPS-Alt",
  8554: "RTSP",
  8883: "MQTT-TLS",
  9001: "Portainer",
  9090: "Prometheus",
  9443: "Alt-HTTPS",
  27017: "MongoDB",
  32400: "Plex",
};

export function portLabel(port: string): string {
  const n = parseInt(port, 10);
  if (isNaN(n)) return port;
  const name = WELL_KNOWN_PORTS[n];
  return name ? `${port} / ${name}` : port;
}
