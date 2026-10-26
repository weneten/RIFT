//! Small in-process tail of the structured stderr log. Secrets are never log fields.
use std::{
    collections::VecDeque,
    io::{self, Write},
    sync::{Mutex, OnceLock},
};

static RECENT: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();
pub struct LogWriter {
    buffer: Vec<u8>,
}
pub fn writer() -> LogWriter {
    LogWriter { buffer: Vec::new() }
}
impl Write for LogWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        io::stderr().write_all(bytes)?;
        let remaining = 8192_usize.saturating_sub(self.buffer.len());
        self.buffer
            .extend_from_slice(&bytes[..bytes.len().min(remaining)]);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        io::stderr().flush()
    }
}
impl Drop for LogWriter {
    fn drop(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        if let Ok(mut log) = RECENT.get_or_init(|| Mutex::new(VecDeque::new())).lock() {
            if log.len() >= 1000 {
                log.pop_front();
            }
            log.push_back(String::from_utf8_lossy(&self.buffer).trim_end().to_string());
        }
    }
}
pub fn recent(lines: usize) -> Vec<String> {
    RECENT
        .get_or_init(|| Mutex::new(VecDeque::new()))
        .lock()
        .map(|log| {
            log.iter()
                .skip(log.len().saturating_sub(lines.min(1000)))
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}
