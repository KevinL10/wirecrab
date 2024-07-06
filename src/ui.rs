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
            Row::new(vec![
                entry.ip.to_string(),
                entry.host.clone(),
                entry.num_packets.to_string(),
            ])
        })
        .collect::<Vec<_>>();

    let widths = [
        Constraint::Percentage(50),
        Constraint::Percentage(80),
        Constraint::Percentage(20),
    ];
    let table = Table::new(rows, widths)
        .column_spacing(2)
        .header(
            Row::new(vec!["SOURCE", "HOST", "NUM PACKETS"])
                // .style(Style::new().bold())
                .style(Style::new().bg(Color::Green))
                // To add space between the header and the rest of the rows, specify the margin
                .bottom_margin(1),
        )
        // .block(block)
        .highlight_style(Style::new().green());

    frame.render_stateful_widget(table, areas[0], &mut app.state);
    // render_bottom_bar(app, areas[1], frame);
}

#[allow(unused)]
pub fn render_bottom_bar(app: &mut App, area: Rect, frame: &mut Frame) {
    let instructions = Line::from(vec![" Quit ".into(), "<Q> ".black().bold()]);
    frame.render_widget(instructions, area);
}
