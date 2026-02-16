use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, Tabs, Wrap};

use super::app::{App, DnsInput, SpooferState, Tab};

const ACCENT: Color = Color::Magenta;
const SUCCESS: Color = Color::Green;
const ERROR: Color = Color::Red;
const DIM: Color = Color::DarkGray;

pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // tabs header
            Constraint::Min(10),  // body
            Constraint::Length(3), // footer
        ])
        .split(f.area());

    draw_tabs(f, app, chunks[0]);
    draw_body(f, app, chunks[1]);
    draw_footer(f, app, chunks[2]);
}

fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = Tab::ALL.iter().map(|t| Line::from(t.title())).collect();

    let idx = Tab::ALL.iter().position(|t| *t == app.tab).unwrap_or(0);

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(ACCENT))
                .title(" Haunter ")
                .title_style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
        )
        .select(idx)
        .style(Style::default().fg(DIM))
        .highlight_style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD));

    f.render_widget(tabs, area);
}

fn draw_body(f: &mut Frame, app: &App, area: Rect) {
    match app.tab {
        Tab::Interfaces => draw_interfaces(f, app, area),
        Tab::Scanner => draw_scanner(f, app, area),
        Tab::Spoofer => draw_spoofer(f, app, area),
        Tab::Dns => draw_dns(f, app, area),
    }
}

fn draw_interfaces(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(5)])
        .split(area);

    // Help text
    let help = Paragraph::new(Line::from(vec![
        Span::styled(
            " Select the network interface to use for scanning and spoofing.",
            Style::default().fg(DIM),
        ),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(ACCENT)),
    );
    f.render_widget(help, chunks[0]);

    let header = Row::new(vec![
        Cell::from("Name").style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
        Cell::from("MAC").style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
        Cell::from("IPs").style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
    ])
    .height(1);

    let rows: Vec<Row> = app
        .interfaces
        .iter()
        .enumerate()
        .map(|(i, iface)| {
            let mac = iface
                .mac
                .map(|m| m.to_string())
                .unwrap_or_else(|| "N/A".into());
            let ips: Vec<String> = iface.ips.iter().map(|ip| ip.to_string()).collect();
            let ip_str = if ips.is_empty() {
                "none".to_string()
            } else {
                ips.join(", ")
            };

            let style = if Some(&iface.name) == app.selected_iface.as_ref().map(|i| &i.name) {
                Style::default().fg(SUCCESS)
            } else if i == app.iface_index {
                Style::default().fg(Color::White)
            } else {
                Style::default().fg(DIM)
            };

            Row::new(vec![
                Cell::from(iface.name.clone()),
                Cell::from(mac),
                Cell::from(ip_str),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(16),
        Constraint::Length(20),
        Constraint::Min(20),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(ACCENT))
                .title(" Interfaces ")
                .title_style(Style::default().fg(ACCENT)),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_stateful_widget(
        table,
        chunks[1],
        &mut ratatui::widgets::TableState::default().with_selected(Some(app.iface_index)),
    );
}

fn draw_scanner(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(5)])
        .split(area);

    // Status bar
    let status = if app.scanning {
        Span::styled("Scanning...", Style::default().fg(Color::Yellow))
    } else if app.scan_results.is_empty() {
        Span::styled("Press Enter to scan", Style::default().fg(DIM))
    } else {
        Span::styled(
            format!("{} device(s) found", app.scan_results.len()),
            Style::default().fg(SUCCESS),
        )
    };

    let iface_name = app
        .selected_iface
        .as_ref()
        .map(|i| i.name.as_str())
        .unwrap_or("none");

    let status_line = Line::from(vec![
        Span::styled(" Interface: ", Style::default().fg(DIM)),
        Span::styled(iface_name, Style::default().fg(ACCENT)),
        Span::raw("  |  "),
        status,
    ]);

    let status_para = Paragraph::new(status_line).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(ACCENT)),
    );
    f.render_widget(status_para, chunks[0]);

    // Results table
    let header = Row::new(vec![
        Cell::from("#").style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
        Cell::from("IP Address").style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
        Cell::from("MAC Address")
            .style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
        Cell::from("Role").style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
    ])
    .height(1);

    let rows: Vec<Row> = app
        .scan_results
        .iter()
        .enumerate()
        .map(|(i, device)| {
            let role = if Some(device.ip) == app.gateway_ip {
                "Gateway"
            } else if Some(device.ip) == app.target_ip {
                "Target"
            } else {
                ""
            };

            let role_style = match role {
                "Gateway" => Style::default().fg(Color::Yellow),
                "Target" => Style::default().fg(ERROR),
                _ => Style::default().fg(DIM),
            };

            let style = if i == app.scan_index {
                Style::default().fg(Color::White)
            } else {
                Style::default().fg(DIM)
            };

            Row::new(vec![
                Cell::from(format!("{}", i + 1)),
                Cell::from(device.ip.to_string()),
                Cell::from(device.mac.to_string()),
                Cell::from(role).style(role_style),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(4),
        Constraint::Length(16),
        Constraint::Length(20),
        Constraint::Length(8),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(ACCENT))
                .title(" Scan Results ")
                .title_style(Style::default().fg(ACCENT)),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_stateful_widget(
        table,
        chunks[1],
        &mut ratatui::widgets::TableState::default().with_selected(
            if app.scan_results.is_empty() {
                None
            } else {
                Some(app.scan_index)
            },
        ),
    );
}

fn draw_spoofer(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(10), // config panel
            Constraint::Min(5),    // log panel
        ])
        .split(area);

    // Config panel
    let gw_text = match (app.gateway_ip, app.gateway_mac) {
        (Some(ip), Some(mac)) => format!("{ip} ({mac})"),
        _ => "not set  -  use 'g' in Scanner tab".to_string(),
    };

    let tgt_text = match (app.target_ip, app.target_mac) {
        (Some(ip), Some(mac)) => format!("{ip} ({mac})"),
        _ => "all devices on subnet".to_string(),
    };

    let iface_text = app
        .selected_iface
        .as_ref()
        .map(|i| i.name.clone())
        .unwrap_or_else(|| "not set  -  select in Interfaces tab".to_string());

    let fwd_label = if app.forward { "ON " } else { "OFF" };
    let fwd_detail = if app.forward {
        " (MITM - traffic is relayed between target and gateway)"
    } else {
        " (traffic is dropped - target loses connectivity)"
    };

    let state_text = match app.spoofer_state {
        SpooferState::Idle => Span::styled("IDLE", Style::default().fg(DIM)),
        SpooferState::Running => Span::styled(
            "RUNNING",
            Style::default().fg(SUCCESS).add_modifier(Modifier::BOLD),
        ),
        SpooferState::Stopping => {
            Span::styled("STOPPING...", Style::default().fg(Color::Yellow))
        }
    };

    let config_lines = vec![
        Line::from(Span::styled(
            " ARP spoofing poisons the target's ARP cache so its traffic flows through this machine.",
            Style::default().fg(DIM),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Interface:  ", Style::default().fg(DIM)),
            Span::styled(&iface_text, Style::default().fg(ACCENT)),
        ]),
        Line::from(vec![
            Span::styled("  Gateway:    ", Style::default().fg(DIM)),
            Span::styled(&gw_text, Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            Span::styled("  Target:     ", Style::default().fg(DIM)),
            Span::styled(&tgt_text, Style::default().fg(ERROR)),
        ]),
        Line::from(vec![
            Span::styled("  Forwarding: ", Style::default().fg(DIM)),
            Span::styled(
                fwd_label,
                Style::default().fg(if app.forward { SUCCESS } else { ERROR }),
            ),
            Span::styled(fwd_detail, Style::default().fg(DIM)),
        ]),
        Line::from(vec![
            Span::styled("  Status:     ", Style::default().fg(DIM)),
            state_text,
        ]),
    ];

    let config = Paragraph::new(config_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(ACCENT))
            .title(" Spoofer ")
            .title_style(Style::default().fg(ACCENT)),
    );
    f.render_widget(config, chunks[0]);

    // Log panel
    let max_lines = chunks[1].height.saturating_sub(2) as usize;
    let skip = app.logs.len().saturating_sub(max_lines);
    let log_lines: Vec<Line> = app.logs[skip..]
        .iter()
        .map(|msg| {
            let color = if msg.starts_with("[!]") {
                ERROR
            } else if msg.starts_with("[*]") {
                SUCCESS
            } else {
                Color::White
            };
            Line::from(Span::styled(msg.as_str(), Style::default().fg(color)))
        })
        .collect();

    let log_panel = Paragraph::new(log_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(ACCENT))
                .title(" Log ")
                .title_style(Style::default().fg(ACCENT)),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(log_panel, chunks[1]);
}

fn draw_dns(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(5)])
        .split(area);

    // Input bar / instructions
    let input_line = match &app.dns_input {
        DnsInput::Inactive => {
            if app.dns_rules.is_empty() {
                Line::from(Span::styled(
                    " Press 'a' to add a DNS spoofing rule.",
                    Style::default().fg(DIM),
                ))
            } else {
                Line::from(vec![
                    Span::styled(
                        format!(" {} rule(s) configured", app.dns_rules.len()),
                        Style::default().fg(SUCCESS),
                    ),
                    Span::styled(
                        "  |  These rules are applied when the spoofer runs with forwarding ON.",
                        Style::default().fg(DIM),
                    ),
                ])
            }
        }
        DnsInput::Domain(s) => Line::from(vec![
            Span::styled(" Domain: ", Style::default().fg(ACCENT)),
            Span::styled(s.as_str(), Style::default().fg(Color::White)),
            Span::styled("_", Style::default().fg(ACCENT)),
        ]),
        DnsInput::Ip { domain, ip } => Line::from(vec![
            Span::styled(
                format!(" {domain} -> IP: "),
                Style::default().fg(ACCENT),
            ),
            Span::styled(ip.as_str(), Style::default().fg(Color::White)),
            Span::styled("_", Style::default().fg(ACCENT)),
        ]),
    };

    let input_bar = Paragraph::new(input_line).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(ACCENT)),
    );
    f.render_widget(input_bar, chunks[0]);

    // Rules table
    let header = Row::new(vec![
        Cell::from("#").style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
        Cell::from("Domain").style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
        Cell::from("Spoof IP").style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
    ])
    .height(1);

    let rows: Vec<Row> = app
        .dns_rules
        .iter()
        .enumerate()
        .map(|(i, rule)| {
            let style = if i == app.dns_index {
                Style::default().fg(Color::White)
            } else {
                Style::default().fg(DIM)
            };

            Row::new(vec![
                Cell::from(format!("{}", i + 1)),
                Cell::from(rule.domain.clone()),
                Cell::from(rule.spoof_ip.to_string()),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(4),
        Constraint::Min(20),
        Constraint::Length(16),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(ACCENT))
                .title(" DNS Rules ")
                .title_style(Style::default().fg(ACCENT)),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_stateful_widget(
        table,
        chunks[1],
        &mut ratatui::widgets::TableState::default().with_selected(
            if app.dns_rules.is_empty() {
                None
            } else {
                Some(app.dns_index)
            },
        ),
    );
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let hints = match app.tab {
        Tab::Interfaces => vec![
            key_hint("Enter", "select"),
            sep(),
            key_hint("Tab", "next tab"),
            sep(),
            key_hint("q", "quit"),
        ],
        Tab::Scanner => vec![
            key_hint("Enter", "scan"),
            sep(),
            key_hint("g", "set as gateway"),
            sep(),
            key_hint("t", "set as target"),
            sep(),
            key_hint("Tab", "next tab"),
            sep(),
            key_hint("q", "quit"),
        ],
        Tab::Dns => match &app.dns_input {
            DnsInput::Inactive => vec![
                key_hint("a", "add rule"),
                sep(),
                key_hint("d", "delete rule"),
                sep(),
                key_hint("Tab", "next tab"),
                sep(),
                key_hint("q", "quit"),
            ],
            DnsInput::Domain(_) => vec![
                key_hint("Enter", "confirm domain"),
                sep(),
                key_hint("Esc", "cancel"),
            ],
            DnsInput::Ip { .. } => vec![
                key_hint("Enter", "confirm IP"),
                sep(),
                key_hint("Esc", "cancel"),
            ],
        },
        Tab::Spoofer => match app.spoofer_state {
            SpooferState::Idle => vec![
                key_hint("Enter", "start"),
                sep(),
                key_hint("f", "toggle forwarding"),
                sep(),
                key_hint("c", "clear target"),
                sep(),
                key_hint("Tab", "next tab"),
                sep(),
                key_hint("q", "quit"),
            ],
            SpooferState::Running => vec![
                key_hint("Esc", "stop"),
                sep(),
                key_hint("Tab", "next tab"),
            ],
            SpooferState::Stopping => vec![Span::styled(
                "restoring ARP tables...",
                Style::default().fg(Color::Yellow),
            )],
        },
    };

    let footer = Paragraph::new(Line::from(hints)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(ACCENT)),
    );
    f.render_widget(footer, area);
}

fn key_hint<'a>(key: &'a str, desc: &'a str) -> Span<'a> {
    Span::styled(
        format!(" {key}: {desc} "),
        Style::default().fg(DIM),
    )
}

fn sep<'a>() -> Span<'a> {
    Span::styled("|", Style::default().fg(Color::Indexed(237)))
}
