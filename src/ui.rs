use crate::app::App;

use ratatui::{
    buffer::Buffer,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Style, Stylize},
    symbols::border,
    text::{Line, Span, Text},
    widgets::{
        block::{Position, Title},
        Block, Row, Table,
    },
    Frame,
};

/// Renders the user interface widgets.
pub fn render(app: &mut App, frame: &mut Frame) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints(vec![Constraint::Min(0), Constraint::Length(1)])
        .split(frame.size());

    let rows = app
        .entries_to_render()
        .map(|entry| {
            if let Some(domain) = entry.domain {
                Row::new(vec![
                    Line::styled(entry.ip.to_string(), Color::White),
                    Line::styled(entry.info.num_packets.to_string(), Color::Green)
                        .alignment(Alignment::Right),
                    Line::styled(domain.clone(), Color::White),
                ])
            } else {
                Row::new(vec![
                    Line::styled(entry.ip.to_string(), Color::DarkGray),
                    Line::styled(entry.info.num_packets.to_string(), Color::DarkGray)
                        .alignment(Alignment::Right),
                    Line::styled(entry.ip.to_string(), Color::DarkGray),
                ])
            }
            .style(Style::new().fg(Color::Gray))
        })
        .collect::<Vec<_>>();

    let widths = [
        Constraint::Length(40),
        Constraint::Length(6),
        Constraint::Min(20),
    ];
    let table = Table::new(rows, widths)
        .column_spacing(2)
        .header(
            Row::new(vec![" IP", "# PKTS", "HOST"])
                .style(Style::new().bg(Color::Green).fg(Color::Black))
                .bottom_margin(1),
        )
        .highlight_style(Style::new().bg(Color::LightCyan).fg(Color::Black));

    frame.render_stateful_widget(table, areas[0], &mut app.state);
    render_bottom_bar(app, areas[1], frame);
}

#[allow(unused)]
pub fn render_bottom_bar(app: &mut App, area: Rect, frame: &mut Frame) {
    let areas = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(vec![
            Constraint::Length(2),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Min(0),
        ])
        .split(area);

    frame.render_widget(Span::from("C"), areas[0]);
    frame.render_widget(
        Span::from("Clear ").bg(Color::LightCyan).fg(Color::Black),
        areas[1],
    );
    frame.render_widget(Span::from("Esc/Q"), areas[2]);
    frame.render_widget(
        Line::from("Quit").bg(Color::LightCyan).fg(Color::Black),
        areas[3],
    );
}
