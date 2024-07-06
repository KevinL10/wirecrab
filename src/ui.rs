use crate::app::App;

use ratatui::{
    buffer::Buffer,
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind},
    layout::{self, Alignment, Constraint, Direction, Layout, Rect},
    style::{Style, Stylize},
    symbols::border,
    text::{Line, Text},
    widgets::{
        block::{Position, Title},
        Block, Paragraph, Row, Table, Widget,
    },
    Frame,
};

/// Renders the user interface widgets.
pub fn render(app: &mut App, frame: &mut Frame) {
    let outer_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(vec![Constraint::Length(30)])
        .split(frame.size());

    // let inner_layout = Layout::default()
    //     .direction(Direction::Horizontal)
    //     .constraints(vec![Constraint::Length(100)])
    //     .split(outer_layout[0]);

    let title = Title::from(" Wirecrab ".bold());
    let instructions = Title::from(Line::from(vec![" Quit ".into(), "<Q> ".black().bold()]));
    let block = Block::bordered()
        .title(title.alignment(Alignment::Center))
        .title(
            instructions
                .alignment(Alignment::Center)
                .position(Position::Bottom),
        )
        .border_set(border::THICK);

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
        Constraint::Percentage(70),
        Constraint::Percentage(30),
    ];
    let table = Table::new(rows, widths)
        .column_spacing(2)
        .header(
            Row::new(vec!["Source", "Host", "Num Packets"])
                // .style(Style::new().bold())
                // To add space between the header and the rest of the rows, specify the margin
                .bottom_margin(1),
        )
        .block(block)
        .highlight_style(Style::new().green());

    frame.render_stateful_widget(table, outer_layout[0], &mut app.state)
}
