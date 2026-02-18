//! Terminal key encoding for sending keystrokes to a PTY.
//!
//! Provides a [`Key`] enum that maps logical key names to the byte sequences
//! that terminals expect (ANSI escape codes, control characters, etc.).

/// A key that can be sent to a terminal session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Key {
    /// A regular character.
    Char(char),
    /// The Enter/Return key (carriage return).
    Enter,
    /// The Escape key.
    Escape,
    /// The Tab key.
    Tab,
    /// The Backspace key.
    Backspace,
    /// Arrow up.
    Up,
    /// Arrow down.
    Down,
    /// Arrow left.
    Left,
    /// Arrow right.
    Right,
    /// The Home key.
    Home,
    /// The End key.
    End,
    /// Page Up.
    PageUp,
    /// Page Down.
    PageDown,
    /// The Delete key.
    Delete,
    /// A function key (F1 through F12).
    F(u8),
    /// Ctrl + a character (e.g., `Ctrl('c')` for Ctrl-C).
    Ctrl(char),
    /// Alt/Meta + a character.
    Alt(char),
}

impl Key {
    /// Encode this key as the byte sequence a terminal expects.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Key::Char(c) => {
                let mut buf = [0u8; 4];
                let s = c.encode_utf8(&mut buf);
                s.as_bytes().to_vec()
            }
            Key::Enter => vec![b'\r'],
            Key::Escape => vec![0x1b],
            Key::Tab => vec![b'\t'],
            Key::Backspace => vec![0x7f],
            Key::Up => vec![0x1b, b'[', b'A'],
            Key::Down => vec![0x1b, b'[', b'B'],
            Key::Right => vec![0x1b, b'[', b'C'],
            Key::Left => vec![0x1b, b'[', b'D'],
            Key::Home => vec![0x1b, b'[', b'H'],
            Key::End => vec![0x1b, b'[', b'F'],
            Key::PageUp => vec![0x1b, b'[', b'5', b'~'],
            Key::PageDown => vec![0x1b, b'[', b'6', b'~'],
            Key::Delete => vec![0x1b, b'[', b'3', b'~'],
            Key::F(n) => f_key_bytes(*n),
            Key::Ctrl(c) => {
                // Ctrl+letter: subtract 'a' and add 1 to get control code.
                // Ctrl+A = 0x01, Ctrl+Z = 0x1A, etc.
                let lower = c.to_ascii_lowercase();
                if lower.is_ascii_lowercase() {
                    vec![lower as u8 - b'a' + 1]
                } else {
                    // Fallback: just send the character
                    vec![*c as u8]
                }
            }
            Key::Alt(c) => {
                let mut bytes = vec![0x1b];
                let mut buf = [0u8; 4];
                let s = c.encode_utf8(&mut buf);
                bytes.extend_from_slice(s.as_bytes());
                bytes
            }
        }
    }
}

/// Encode a function key number to its ANSI escape sequence.
fn f_key_bytes(n: u8) -> Vec<u8> {
    match n {
        1 => b"\x1bOP".to_vec(),
        2 => b"\x1bOQ".to_vec(),
        3 => b"\x1bOR".to_vec(),
        4 => b"\x1bOS".to_vec(),
        5 => b"\x1b[15~".to_vec(),
        6 => b"\x1b[17~".to_vec(),
        7 => b"\x1b[18~".to_vec(),
        8 => b"\x1b[19~".to_vec(),
        9 => b"\x1b[20~".to_vec(),
        10 => b"\x1b[21~".to_vec(),
        11 => b"\x1b[23~".to_vec(),
        12 => b"\x1b[24~".to_vec(),
        // Unknown function key: send nothing meaningful
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enter_is_carriage_return() {
        assert_eq!(Key::Enter.to_bytes(), vec![b'\r']);
    }

    #[test]
    fn escape_is_0x1b() {
        assert_eq!(Key::Escape.to_bytes(), vec![0x1b]);
    }

    #[test]
    fn tab_is_0x09() {
        assert_eq!(Key::Tab.to_bytes(), vec![b'\t']);
    }

    #[test]
    fn backspace_is_0x7f() {
        assert_eq!(Key::Backspace.to_bytes(), vec![0x7f]);
    }

    #[test]
    fn arrow_keys() {
        assert_eq!(Key::Up.to_bytes(), vec![0x1b, b'[', b'A']);
        assert_eq!(Key::Down.to_bytes(), vec![0x1b, b'[', b'B']);
        assert_eq!(Key::Right.to_bytes(), vec![0x1b, b'[', b'C']);
        assert_eq!(Key::Left.to_bytes(), vec![0x1b, b'[', b'D']);
    }

    #[test]
    fn home_and_end() {
        assert_eq!(Key::Home.to_bytes(), vec![0x1b, b'[', b'H']);
        assert_eq!(Key::End.to_bytes(), vec![0x1b, b'[', b'F']);
    }

    #[test]
    fn page_up_and_down() {
        assert_eq!(Key::PageUp.to_bytes(), vec![0x1b, b'[', b'5', b'~']);
        assert_eq!(Key::PageDown.to_bytes(), vec![0x1b, b'[', b'6', b'~']);
    }

    #[test]
    fn delete_key() {
        assert_eq!(Key::Delete.to_bytes(), vec![0x1b, b'[', b'3', b'~']);
    }

    #[test]
    fn ctrl_c() {
        // Ctrl+C = ETX = 0x03
        assert_eq!(Key::Ctrl('c').to_bytes(), vec![3]);
    }

    #[test]
    fn ctrl_a() {
        // Ctrl+A = SOH = 0x01
        assert_eq!(Key::Ctrl('a').to_bytes(), vec![1]);
    }

    #[test]
    fn ctrl_z() {
        // Ctrl+Z = SUB = 0x1A
        assert_eq!(Key::Ctrl('z').to_bytes(), vec![26]);
    }

    #[test]
    fn alt_x() {
        assert_eq!(Key::Alt('x').to_bytes(), vec![0x1b, b'x']);
    }

    #[test]
    fn char_key() {
        assert_eq!(Key::Char('a').to_bytes(), vec![b'a']);
        assert_eq!(Key::Char('Z').to_bytes(), vec![b'Z']);
    }

    #[test]
    fn function_keys() {
        assert_eq!(Key::F(1).to_bytes(), b"\x1bOP".to_vec());
        assert_eq!(Key::F(5).to_bytes(), b"\x1b[15~".to_vec());
        assert_eq!(Key::F(12).to_bytes(), b"\x1b[24~".to_vec());
    }

    #[test]
    fn multibyte_char() {
        let bytes = Key::Char('\u{00e9}').to_bytes(); // e-acute
        assert_eq!(bytes, "\u{00e9}".as_bytes());
    }
}
