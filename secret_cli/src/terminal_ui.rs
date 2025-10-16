use crate::types::{Secret, SecretStore, AuditEntry, AuditOperation};
use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        Block, Borders, Clear, List, ListItem, ListState, Paragraph, Row, Table, TableState, Wrap,
    },
    Frame, Terminal,
};
use std::{
    io::{self, Stdout},
    time::{Duration, Instant},
};
use uuid::Uuid;

pub struct App {
    pub secrets: Vec<Secret>,
    pub filtered_secrets: Vec<usize>,
    pub selected_index: usize,
    pub table_state: TableState,
    pub list_state: ListState,
    pub current_view: AppView,
    pub search_mode: bool,
    pub search_query: String,
    pub show_details: bool,
    pub selected_secret_id: Option<Uuid>,
    pub show_help: bool,
    pub show_add_form: bool,
    pub add_form_state: AddSecretForm,
    pub status_message: Option<(String, StatusType)>,
    pub last_update: Instant,
}

#[derive(Debug, Clone)]
pub struct AddSecretForm {
    pub name: String,
    pub value: String,
    pub category: String,
    pub description: String,
    pub tags: String,
    pub current_field: usize,
}

impl Default for AddSecretForm {
    fn default() -> Self {
        Self {
            name: String::new(),
            value: String::new(),
            category: String::new(),
            description: String::new(),
            tags: String::new(),
            current_field: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum AppView {
    SecretsList,
    SearchResults,
    SecretDetails,
}

#[derive(Debug, Clone)]
pub enum StatusType {
    Info,
    Success,
    Warning,
    Error,
}

impl App {
    pub fn new(secrets: Vec<Secret>) -> Self {
        let filtered_secrets: Vec<usize> = (0..secrets.len()).collect();
        let mut table_state = TableState::default();
        let mut list_state = ListState::default();
        
        if !secrets.is_empty() {
            table_state.select(Some(0));
            list_state.select(Some(0));
        }

        Self {
            secrets,
            filtered_secrets,
            selected_index: 0,
            table_state,
            list_state,
            current_view: AppView::SecretsList,
            search_mode: false,
            search_query: String::new(),
            show_details: false,
            selected_secret_id: None,
            show_help: false,
            show_add_form: false,
            add_form_state: AddSecretForm::default(),
            status_message: None,
            last_update: Instant::now(),
        }
    }

    pub fn update_secrets(&mut self, secrets: Vec<Secret>) {
        self.secrets = secrets;
        self.apply_filter();
    }

    pub fn next_secret(&mut self) {
        if !self.filtered_secrets.is_empty() {
            let i = match self.table_state.selected() {
                Some(i) => (i + 1) % self.filtered_secrets.len(),
                None => 0,
            };
            self.table_state.select(Some(i));
            self.list_state.select(Some(i));
            self.selected_index = i;
        }
    }

    pub fn previous_secret(&mut self) {
        if !self.filtered_secrets.is_empty() {
            let i = match self.table_state.selected() {
                Some(i) => {
                    if i == 0 {
                        self.filtered_secrets.len() - 1
                    } else {
                        i - 1
                    }
                }
                None => 0,
            };
            self.table_state.select(Some(i));
            self.list_state.select(Some(i));
            self.selected_index = i;
        }
    }

    pub fn get_selected_secret(&self) -> Option<&Secret> {
        if let Some(selected) = self.table_state.selected() {
            if let Some(&secret_index) = self.filtered_secrets.get(selected) {
                return self.secrets.get(secret_index);
            }
        }
        None
    }

    pub fn enter_search_mode(&mut self) {
        self.search_mode = true;
        self.search_query.clear();
    }

    pub fn exit_search_mode(&mut self) {
        self.search_mode = false;
        self.search_query.clear();
        self.current_view = AppView::SecretsList;
        self.apply_filter();
    }

    pub fn apply_filter(&mut self) {
        if self.search_query.is_empty() {
            self.filtered_secrets = (0..self.secrets.len()).collect();
            self.current_view = AppView::SecretsList;
        } else {
            let query_lower = self.search_query.to_lowercase();
            self.filtered_secrets = self
                .secrets
                .iter()
                .enumerate()
                .filter(|(_, secret)| {
                    secret.name.to_lowercase().contains(&query_lower)
                        || secret.category.as_ref().map_or(false, |c| c.to_lowercase().contains(&query_lower))
                        || secret.description.as_ref().map_or(false, |d| d.to_lowercase().contains(&query_lower))
                        || secret.tags.iter().any(|t| t.to_lowercase().contains(&query_lower))
                })
                .map(|(i, _)| i)
                .collect();
            self.current_view = AppView::SearchResults;
        }

        // Reset selection
        if !self.filtered_secrets.is_empty() {
            self.table_state.select(Some(0));
            self.list_state.select(Some(0));
            self.selected_index = 0;
        } else {
            self.table_state.select(None);
            self.list_state.select(None);
        }
    }

    pub fn show_secret_details(&mut self) {
        if let Some(secret) = self.get_selected_secret() {
            self.selected_secret_id = Some(secret.id);
            self.current_view = AppView::SecretDetails;
            self.show_details = true;
        }
    }

    pub fn hide_secret_details(&mut self) {
        self.show_details = false;
        self.selected_secret_id = None;
        self.current_view = if self.search_query.is_empty() {
            AppView::SecretsList
        } else {
            AppView::SearchResults
        };
    }

    pub fn set_status(&mut self, message: String, status_type: StatusType) {
        self.status_message = Some((message, status_type));
        self.last_update = Instant::now();
    }

    pub fn clear_status_if_old(&mut self) {
        if let Some(_) = &self.status_message {
            if self.last_update.elapsed() > Duration::from_secs(5) {
                self.status_message = None;
            }
        }
    }
}

pub fn run_tui(mut store: SecretStore) -> Result<SecretStore> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let secrets = store.list_secrets().into_iter().cloned().collect();
    let mut app = App::new(secrets);
    app.set_status("Welcome to Secret CLI!".to_string(), StatusType::Info);

    let result = run_app(&mut terminal, &mut app, &mut store);

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result?;
    Ok(store)
}

fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    store: &mut SecretStore,
) -> Result<()> {
    loop {
        terminal.draw(|f| ui(f, app))?;
        app.clear_status_if_old();

        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Release {
                continue;
            }

            if app.show_add_form {
                match key.code {
                    KeyCode::Esc => app.show_add_form = false,
                    KeyCode::Tab | KeyCode::Down => {
                        app.add_form_state.current_field =
                            (app.add_form_state.current_field + 1) % 5;
                    }
                    KeyCode::BackTab | KeyCode::Up => {
                        app.add_form_state.current_field = if app.add_form_state.current_field == 0 {
                            4
                        } else {
                            app.add_form_state.current_field - 1
                        };
                    }
                    KeyCode::Char(c) => {
                        match app.add_form_state.current_field {
                            0 => app.add_form_state.name.push(c),
                            1 => app.add_form_state.value.push(c),
                            2 => app.add_form_state.category.push(c),
                            3 => app.add_form_state.description.push(c),
                            4 => app.add_form_state.tags.push(c),
                            _ => {}
                        }
                    }
                    KeyCode::Backspace => {
                        match app.add_form_state.current_field {
                            0 => { app.add_form_state.name.pop(); },
                            1 => { app.add_form_state.value.pop(); },
                            2 => { app.add_form_state.category.pop(); },
                            3 => { app.add_form_state.description.pop(); },
                            4 => { app.add_form_state.tags.pop(); },
                            _ => {}
                        }
                    }
                    KeyCode::Enter => {
                        if !app.add_form_state.name.is_empty() && !app.add_form_state.value.is_empty() {
                            let mut secret = Secret::new(
                                app.add_form_state.name.clone(),
                                app.add_form_state.value.clone(),
                            );

                            if !app.add_form_state.category.is_empty() {
                                secret = secret.with_category(app.add_form_state.category.clone());
                            }

                            if !app.add_form_state.description.is_empty() {
                                secret = secret.with_description(app.add_form_state.description.clone());
                            }

                            if !app.add_form_state.tags.is_empty() {
                                let tags: Vec<String> = app.add_form_state.tags
                                    .split(',')
                                    .map(|s| s.trim().to_string())
                                    .filter(|s| !s.is_empty())
                                    .collect();
                                secret = secret.with_tags(tags);
                            }

                            store.add_secret(secret);
                            let secrets = store.list_secrets().into_iter().cloned().collect();
                            app.update_secrets(secrets);
                            
                            app.show_add_form = false;
                            app.add_form_state = AddSecretForm::default();
                            app.set_status("Secret added successfully!".to_string(), StatusType::Success);
                        }
                    }
                    _ => {}
                }
            } else if app.search_mode {
                match key.code {
                    KeyCode::Esc => app.exit_search_mode(),
                    KeyCode::Enter => {
                        app.search_mode = false;
                        app.apply_filter();
                    }
                    KeyCode::Char(c) => {
                        app.search_query.push(c);
                        app.apply_filter();
                    }
                    KeyCode::Backspace => {
                        app.search_query.pop();
                        app.apply_filter();
                    }
                    _ => {}
                }
            } else {
                match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Char('h') | KeyCode::F(1) => app.show_help = !app.show_help,
                    KeyCode::Char('/') => app.enter_search_mode(),
                    KeyCode::Char('a') => app.show_add_form = true,
                    KeyCode::Down | KeyCode::Char('j') => app.next_secret(),
                    KeyCode::Up | KeyCode::Char('k') => app.previous_secret(),
                    KeyCode::Enter | KeyCode::Char(' ') => {
                        if app.show_details {
                            app.hide_secret_details();
                        } else {
                            app.show_secret_details();
                        }
                    }
                    KeyCode::Esc => {
                        if app.show_help {
                            app.show_help = false;
                        } else if app.show_details {
                            app.hide_secret_details();
                        }
                    }
                    KeyCode::Char('d') => {
                        if let Some(selected) = app.table_state.selected() {
                            if let Some(&secret_index) = app.filtered_secrets.get(selected) {
                                if let Some(secret) = app.secrets.get(secret_index) {
                                    store.remove_secret(&secret.id);
                                    let secrets = store.list_secrets().into_iter().cloned().collect();
                                    app.update_secrets(secrets);
                                    app.set_status("Secret deleted!".to_string(), StatusType::Warning);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(0),    // Main content
            Constraint::Length(3), // Footer
        ])
        .split(f.size());

    // Header
    render_header(f, chunks[0], app);

    // Main content
    if app.show_help {
        render_help(f, chunks[1]);
    } else if app.show_details {
        render_secret_details(f, chunks[1], app);
    } else {
        render_secrets_table(f, chunks[1], app);
    }

    // Footer
    render_footer(f, chunks[2], app);

    // Overlays
    if app.show_add_form {
        render_add_form(f, app);
    }
}

fn render_header(f: &mut Frame, area: Rect, app: &App) {
    let title = match app.current_view {
        AppView::SecretsList => format!("Secrets ({})", app.secrets.len()),
        AppView::SearchResults => format!("Search Results ({}) - '{}'", app.filtered_secrets.len(), app.search_query),
        AppView::SecretDetails => "Secret Details".to_string(),
    };

    let header = Paragraph::new(title)
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));

    f.render_widget(header, area);
}

fn render_secrets_table(f: &mut Frame, area: Rect, app: &App) {
    let rows: Vec<Row> = app
        .filtered_secrets
        .iter()
        .filter_map(|&i| app.secrets.get(i))
        .map(|secret| {
            let value_display = if secret.value.len() > 20 {
                "***••••••".to_string()
            } else {
                "*".repeat(secret.value.len().min(10))
            };

            let category = secret.category.as_deref().unwrap_or("-");
            let age = {
                let duration = chrono::Utc::now() - secret.created_at;
                if duration.num_days() > 0 {
                    format!("{}d", duration.num_days())
                } else if duration.num_hours() > 0 {
                    format!("{}h", duration.num_hours())
                } else {
                    format!("{}m", duration.num_minutes())
                }
            };

            let status = if secret.is_expired() {
                "EXPIRED"
            } else if secret.expires_at.is_some() {
                "TEMP"
            } else {
                "OK"
            };

            Row::new(vec![
                secret.name.clone(),
                value_display,
                category.to_string(),
                age,
                status.to_string(),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(30),
            Constraint::Percentage(25),
            Constraint::Percentage(20),
            Constraint::Percentage(15),
            Constraint::Percentage(10),
        ],
    )
    .header(Row::new(vec!["Name", "Value", "Category", "Age", "Status"])
        .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))
    .block(Block::default().borders(Borders::ALL))
    .highlight_style(Style::default().bg(Color::DarkGray))
    .highlight_symbol("► ");

    f.render_stateful_widget(table, area, &mut app.table_state.clone());

    // Search input overlay
    if app.search_mode {
        let search_area = Rect {
            x: area.x + 2,
            y: area.y + area.height - 3,
            width: area.width - 4,
            height: 3,
        };

        let search_input = Paragraph::new(format!("Search: {}", app.search_query))
            .style(Style::default().fg(Color::Yellow))
            .block(Block::default().borders(Borders::ALL).title("Search"));

        f.render_widget(Clear, search_area);
        f.render_widget(search_input, search_area);
    }
}

fn render_secret_details(f: &mut Frame, area: Rect, app: &App) {
    if let Some(secret) = app.get_selected_secret() {
        let details = vec![
            Line::from(vec![
                Span::styled("Name: ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::raw(&secret.name),
            ]),
            Line::from(vec![
                Span::styled("Value: ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::raw("***••••••"), // Always hide in UI
            ]),
            Line::from(vec![
                Span::styled("Category: ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::raw(secret.category.as_deref().unwrap_or("None")),
            ]),
            Line::from(vec![
                Span::styled("Description: ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::raw(secret.description.as_deref().unwrap_or("None")),
            ]),
            Line::from(vec![
                Span::styled("Created: ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::raw(secret.created_at.format("%Y-%m-%d %H:%M UTC").to_string()),
            ]),
            Line::from(vec![
                Span::styled("Updated: ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::raw(secret.updated_at.format("%Y-%m-%d %H:%M UTC").to_string()),
            ]),
            Line::from(vec![
                Span::styled("Tags: ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::raw(if secret.tags.is_empty() { 
                    "None".to_string() 
                } else { 
                    secret.tags.join(", ") 
                }),
            ]),
        ];

        let paragraph = Paragraph::new(details)
            .block(Block::default().borders(Borders::ALL).title("Secret Details"))
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    }
}

fn render_help(f: &mut Frame, area: Rect) {
    let help_text = vec![
        Line::from(vec![Span::styled("Navigation:", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))]),
        Line::from("  ↑/k     - Move up"),
        Line::from("  ↓/j     - Move down"),
        Line::from("  Enter   - View secret details"),
        Line::from("  Esc     - Go back"),
        Line::from(""),
        Line::from(vec![Span::styled("Actions:", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))]),
        Line::from("  a       - Add new secret"),
        Line::from("  d       - Delete selected secret"),
        Line::from("  /       - Search secrets"),
        Line::from("  h/F1    - Toggle this help"),
        Line::from("  q       - Quit"),
        Line::from(""),
        Line::from(vec![Span::styled("Search Mode:", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))]),
        Line::from("  Type to search, Enter to confirm, Esc to cancel"),
    ];

    let help = Paragraph::new(help_text)
        .block(Block::default().borders(Borders::ALL).title("Help"))
        .wrap(Wrap { trim: true });

    f.render_widget(help, area);
}

fn render_add_form(f: &mut Frame, app: &App) {
    let area = centered_rect(60, 50, f.size());

    f.render_widget(Clear, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Name
            Constraint::Length(3), // Value
            Constraint::Length(3), // Category
            Constraint::Length(3), // Description
            Constraint::Length(3), // Tags
            Constraint::Length(2), // Help
        ])
        .split(area);

    let fields = [
        (&app.add_form_state.name, "Name"),
        (&app.add_form_state.value, "Value"),
        (&app.add_form_state.category, "Category"),
        (&app.add_form_state.description, "Description"),
        (&app.add_form_state.tags, "Tags"),
    ];

    for (i, (value, label)) in fields.iter().enumerate() {
        let style = if app.add_form_state.current_field == i {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };

        let input = Paragraph::new(value.as_str())
            .style(style)
            .block(Block::default().borders(Borders::ALL).title(*label));

        f.render_widget(input, chunks[i]);
    }

    let help = Paragraph::new("Tab: Next field, Enter: Save, Esc: Cancel")
        .style(Style::default().fg(Color::Gray));
    f.render_widget(help, chunks[5]);
}

fn render_footer(f: &mut Frame, area: Rect, app: &App) {
    let footer_text = if let Some((message, status_type)) = &app.status_message {
        let style = match status_type {
            StatusType::Info => Style::default().fg(Color::Cyan),
            StatusType::Success => Style::default().fg(Color::Green),
            StatusType::Warning => Style::default().fg(Color::Yellow),
            StatusType::Error => Style::default().fg(Color::Red),
        };
        Text::from(Line::from(Span::styled(message, style)))
    } else {
        Text::from("Press 'h' for help, 'q' to quit")
    };

    let footer = Paragraph::new(footer_text)
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));

    f.render_widget(footer, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}