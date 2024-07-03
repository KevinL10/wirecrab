use crate::app::App;

use ratatui::{
    buffer::Buffer,
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind},
    layout::{Alignment, Rect},
    style::Stylize,
    symbols::border,
    text::{Line, Text},
    widgets::{
        block::{Position, Title},
        Block, Paragraph, Widget,
    },
    Frame,
};

/// Renders the user interface widgets.
pub fn render(app: &mut App, frame: &mut Frame) {
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

    let text = Text::from(
        app.hosts
            .iter()
            .map(|host| Line::from(vec!["host: ".into(), host.clone().into()]))
            .collect::<Vec<Line>>(),
    );

    frame.render_widget(Paragraph::new(text).block(block).centered(), frame.size())
}
