pub mod system;
pub mod interfaces;
pub mod ip;
pub mod firewall;
pub mod logs;
pub mod speedtest;
pub mod traffic;

use serde::Serialize;

/// Output format for CLI results.
#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
pub enum OutputFormat {
    #[default]
    Table,
    Json,
    Csv,
}

/// Print a Vec of items in the requested format.
/// `headers` and `row_fn` are used for table/CSV output.
pub fn print_rows<T: Serialize>(
    items: &[T],
    format: OutputFormat,
    headers: &[&str],
    row_fn: impl Fn(&T) -> Vec<String>,
) {
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(items).unwrap());
        }
        OutputFormat::Csv => {
            println!("{}", headers.join(","));
            for item in items {
                let cols = row_fn(item);
                let escaped: Vec<String> = cols.into_iter().map(|c| csv_escape(&c)).collect();
                println!("{}", escaped.join(","));
            }
        }
        OutputFormat::Table => {
            if items.is_empty() {
                println!("(no results)");
                return;
            }
            print_table(headers, items.iter().map(row_fn).collect());
        }
    }
}

/// Print a single item in the requested format.
/// `fields` is a list of (label, value) pairs for table/CSV.
pub fn print_single<T: Serialize>(
    item: &T,
    format: OutputFormat,
    fields: &[(&str, String)],
) {
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(item).unwrap());
        }
        OutputFormat::Csv => {
            let headers: Vec<&str> = fields.iter().map(|(k, _)| *k).collect();
            let values: Vec<String> = fields.iter().map(|(_, v)| csv_escape(v)).collect();
            println!("{}", headers.join(","));
            println!("{}", values.join(","));
        }
        OutputFormat::Table => {
            let max_label = fields.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
            for (label, value) in fields {
                println!("  {:<width$}  {}", label, value, width = max_label);
            }
        }
    }
}

fn print_table(headers: &[&str], rows: Vec<Vec<String>>) {
    // Calculate column widths
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(strip_ansi(cell).len());
            }
        }
    }

    // Header
    let header: String = headers
        .iter()
        .enumerate()
        .map(|(i, h)| format!("{:<w$}", h, w = widths[i]))
        .collect::<Vec<_>>()
        .join("  ");
    println!("{header}");
    let separator: String = widths.iter().map(|w| "─".repeat(*w)).collect::<Vec<_>>().join("──");
    println!("{separator}");

    // Rows
    for row in &rows {
        let line: String = row
            .iter()
            .enumerate()
            .map(|(i, cell)| {
                let visible_len = strip_ansi(cell).len();
                let w = widths.get(i).copied().unwrap_or(0);
                let padding = w.saturating_sub(visible_len);
                format!("{cell}{}", " ".repeat(padding))
            })
            .collect::<Vec<_>>()
            .join("  ");
        println!("{line}");
    }
}

/// Strip ANSI escape codes for width calculation.
fn strip_ansi(s: &str) -> String {
    let mut result = String::new();
    let mut in_escape = false;
    for ch in s.chars() {
        if ch == '\x1b' {
            in_escape = true;
        } else if in_escape {
            if ch.is_ascii_alphabetic() {
                in_escape = false;
            }
        } else {
            result.push(ch);
        }
    }
    result
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Format a boolean status with color.
pub fn status_colored(running: bool, no_color: bool) -> String {
    if no_color {
        return if running { "UP".into() } else { "down".into() };
    }
    if running {
        format!("\x1b[32mUP\x1b[0m")
    } else {
        format!("\x1b[90mdown\x1b[0m")
    }
}

/// Format a firewall action with color.
pub fn action_colored(action: &str, no_color: bool) -> String {
    if no_color {
        return action.to_string();
    }
    match action {
        "accept" => format!("\x1b[32m{action}\x1b[0m"),
        "drop" | "reject" => format!("\x1b[31m{action}\x1b[0m"),
        "fasttrack-connection" => format!("\x1b[33m{action}\x1b[0m"),
        "passthrough" => format!("\x1b[90m{action}\x1b[0m"),
        _ => action.to_string(),
    }
}

/// Format bytes into human-readable form.
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    const TB: u64 = 1024 * GB;

    if bytes >= TB {
        format!("{:.1}T", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1}G", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1}M", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}K", bytes as f64 / KB as f64)
    } else {
        format!("{bytes}B")
    }
}
