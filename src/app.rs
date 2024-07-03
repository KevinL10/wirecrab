use std::error;

/// Application result type.
pub type AppResult<T> = std::result::Result<T, Box<dyn error::Error>>;

/// Application.
#[derive(Debug)]
pub struct App {
    // TODO: replace String with full data structure (e.g. ip, # packets sent/received)
    pub hosts: Vec<String>,
    pub running: bool,
}

impl Default for App {
    fn default() -> Self {
        Self {
            running: true,
            hosts: vec!["0.0.0.0".into()],
        }
    }
}

impl App {
    /// Constructs a new instance of [`App`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Handles the tick event of the terminal.
    pub fn tick(&self) {}

    /// Set running to false to quit the application.
    pub fn quit(&mut self) {
        self.running = false;
    }

    pub fn update(&mut self, data: String) {
        self.hosts.push(data);
    }
}
