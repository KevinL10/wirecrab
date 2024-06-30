use core::time;
use std::{
    io,
    sync::{Arc, Mutex},
    thread,
};

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

mod dns;
mod ethernet;
mod ip;
mod sniffer;
mod tui;
mod utils;

#[derive(Debug, Default)]
pub struct App {
    hosts: Arc<Mutex<Vec<String>>>,
    exit: bool,
}

impl App {
    /// runs the application's main loop until the user quits
    pub fn run(&mut self, terminal: &mut tui::Tui) -> io::Result<()> {
        // initialize hosts
        let hosts: Vec<String> = Vec::new();
        self.hosts = Arc::new(Mutex::new(hosts));

        let hosts_cloned = self.hosts.clone();
        thread::spawn(move || {
            sniffer::start_packet_capture(hosts_cloned);
        });

        while !self.exit {
            terminal.draw(|frame| self.render_frame(frame))?;
            self.handle_events()?;

            thread::sleep(time::Duration::from_millis(100));
        }
        Ok(())
    }

    fn render_frame(&self, frame: &mut Frame) {
        frame.render_widget(self, frame.size());
    }

    fn handle_events(&mut self) -> io::Result<()> {
        match event::read()? {
            // it's important to check that the event is a key press event as
            // crossterm also emits key release and repeat events on Windows.
            Event::Key(key_event) if key_event.kind == KeyEventKind::Press => {
                self.handle_key_event(key_event)
            }
            _ => {}
        };
        Ok(())
    }

    fn handle_key_event(&mut self, key_event: KeyEvent) {
        match key_event.code {
            KeyCode::Char('q') => self.exit(),
            _ => {}
        }
    }

    fn exit(&mut self) {
        self.exit = true;
    }
}

impl Widget for &App {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let title = Title::from(" Wirecrab ".bold());
        let instructions = Title::from(Line::from(vec![" Quit ".into(), "<Q> ".blue().bold()]));
        let block = Block::bordered()
            .title(title.alignment(Alignment::Center))
            .title(
                instructions
                    .alignment(Alignment::Center)
                    .position(Position::Bottom),
            )
            .border_set(border::THICK);

        let host_text: Text;
        {
            let hosts = self.hosts.lock().unwrap();
            host_text = Text::from(
                (*hosts)
                    .iter()
                    .map(|host| Line::from(vec!["host: ".into(), host.clone().into()]))
                    .collect::<Vec<Line>>(),
            );
        }

        Paragraph::new(host_text)
            .centered()
            .block(block)
            .render(area, buf);
    }
}

fn main() -> io::Result<()> {
    let mut terminal = tui::init()?;
    let app_result = App::default().run(&mut terminal);
    tui::restore()?;
    app_result
}
