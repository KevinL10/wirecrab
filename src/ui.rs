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

    // let inner_layout = Layout::default()
    //     .direction(Direction::Horizontal)
    //     .constraints(vec![Constraint::Length(100)])
    //     .split(outer_layout[0]);

    let title = Title::from(" Wirecrab ".bold());
    // let block = Block::bordered()
    //     .title(title.alignment(Alignment::Center))
    //     .title(
    //         instructions
    //             .alignment(Alignment::Center)
    //             .position(Position::Bottom),
    //     )
    //     .border_set(border::THICK);

    // iterate through app.hosts instead of app.entries.values() to maintain insert order
    let rows = app
        .hosts
        .iter()
        .map(|host| {
            let entry = app
                .entries
                .get(host)
                .expect("missing host from entries map");

            // if we could not resolve the entry host
            let should_ignore = entry.host.len() < 2;

            Row::new(vec![
                Line::from(entry.ip.to_string()).style(Style::new().fg(if should_ignore {
                    Color::DarkGray
                } else {
                    Color::White
                })),
                Line::from(entry.num_packets.to_string())
                    .alignment(Alignment::Right)
                    .style(Style::new().fg(if should_ignore {
                        Color::DarkGray
                    } else {
                        Color::Green
                    })),
                Line::from(entry.host.clone()).style(Style::new().fg(if should_ignore {
                    Color::DarkGray
                } else {
                    Color::White
                })),
            ])
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
        .constraints(vec![Constraint::Length(6), Constraint::Min(0)])
        .split(area);

    frame.render_widget(Span::from("Esc/Q"), areas[0]);
    frame.render_widget(
        Line::from("Quit").bg(Color::LightCyan).fg(Color::Black),
        areas[1],
    );
}
