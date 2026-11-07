//! Pure-Rust RFC 8259 JSON and NDJSON (Newline-Delimited JSON) Parser.
//!
//! Enables `cluster_correlator` and `remote_fingerprinter` to ingest Phase-1/2/3
//! forensic reports as well as Shodan, Censys, and TLS telemetry NDJSON streams
//! without `serde` or `serde_json`.

use fsr_deep_audit::schema::JsonValue;

/// Parses a single RFC 8259 JSON document into [`JsonValue`].
pub fn parse_json_str(input: &str) -> Result<JsonValue, String> {
    let bytes = input.as_bytes();
    let mut parser = JsonParser { bytes, pos: 0 };
    parser.skip_ws();
    // Strip optional UTF-8 BOM
    if parser.bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        parser.pos = 3;
        parser.skip_ws();
    }
    let val = parser.parse_value()?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() {
        return Err(format!(
            "unexpected trailing characters at byte offset {}",
            parser.pos
        ));
    }
    Ok(val)
}

/// Parses either a single JSON document (Object or Array of Objects) OR a multi-line
/// NDJSON stream into a flat vector of JSON Objects.
pub fn parse_json_or_ndjson_records(content: &str) -> Result<Vec<JsonValue>, String> {
    let trimmed = content.trim_start_matches('\u{feff}').trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    // Attempt full-document JSON parse first (handles pretty-printed JSON & `[...]` arrays)
    if let Ok(doc) = parse_json_str(trimmed) {
        return match doc {
            JsonValue::Array(items) => Ok(items),
            other => Ok(vec![other]),
        };
    }

    // Otherwise parse line-by-line as NDJSON
    let mut out = Vec::new();
    for (line_no, raw_line) in trimmed.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        let val = parse_json_str(line)
            .map_err(|e| format!("NDJSON parse error on line {}: {}", line_no + 1, e))?;
        match val {
            JsonValue::Array(items) => out.extend(items),
            other => out.push(other),
        }
    }
    Ok(out)
}

/// Ergonomic read helpers on [`JsonValue`].
pub fn json_get<'a>(val: &'a JsonValue, key: &str) -> Option<&'a JsonValue> {
    match val {
        JsonValue::OrderedObject(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        JsonValue::MapObject(map) => map.get(key),
        _ => None,
    }
}

pub fn json_get_path<'a>(mut cur: &'a JsonValue, path: &[&str]) -> Option<&'a JsonValue> {
    for &seg in path {
        cur = json_get(cur, seg)?;
    }
    Some(cur)
}

pub fn json_as_str(val: &JsonValue) -> Option<&str> {
    match val {
        JsonValue::Str(s) => Some(s.as_str()),
        _ => None,
    }
}

pub fn json_as_u64(val: &JsonValue) -> Option<u64> {
    match val {
        JsonValue::Uint(v) => Some(*v),
        JsonValue::Int(v) if *v >= 0 => Some(*v as u64),
        JsonValue::Str(s) => s.trim().parse::<u64>().ok(),
        _ => None,
    }
}

pub fn json_as_i64(val: &JsonValue) -> Option<i64> {
    match val {
        JsonValue::Int(v) => Some(*v),
        JsonValue::Uint(v) => i64::try_from(*v).ok(),
        JsonValue::Str(s) => s.trim().parse::<i64>().ok(),
        _ => None,
    }
}

pub fn json_as_array(val: &JsonValue) -> Option<&[JsonValue]> {
    match val {
        JsonValue::Array(arr) => Some(arr.as_slice()),
        _ => None,
    }
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b' ' | b'\t' | b'\r' | b'\n' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn parse_value(&mut self) -> Result<JsonValue, String> {
        self.skip_ws();
        let Some(b) = self.peek() else {
            return Err("unexpected end of JSON input".to_string());
        };
        match b {
            b'{' => self.parse_object(),
            b'[' => self.parse_array(),
            b'"' => self.parse_string().map(JsonValue::Str),
            b't' => self.parse_literal(b"true", JsonValue::Bool(true)),
            b'f' => self.parse_literal(b"false", JsonValue::Bool(false)),
            b'n' => self.parse_literal(b"null", JsonValue::Null),
            b'-' | b'0'..=b'9' => self.parse_number(),
            other => Err(format!(
                "unexpected byte 0x{:02x} ('{}') at offset {}",
                other,
                other as char,
                self.pos
            )),
        }
    }

    fn parse_literal(&mut self, expected: &[u8], out: JsonValue) -> Result<JsonValue, String> {
        if self.bytes.get(self.pos..self.pos + expected.len()) == Some(expected) {
            self.pos += expected.len();
            Ok(out)
        } else {
            Err(format!("invalid JSON literal at offset {}", self.pos))
        }
    }

    fn parse_object(&mut self) -> Result<JsonValue, String> {
        self.pos += 1; // '{'
        self.skip_ws();
        let mut entries = Vec::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(JsonValue::OrderedObject(entries));
        }

        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(format!("expected object string key at offset {}", self.pos));
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(format!("expected ':' after key at offset {}", self.pos));
            }
            self.pos += 1;
            let val = self.parse_value()?;
            entries.push((key, val));

            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                _ => {
                    return Err(format!(
                        "expected ',' or '}}' in object at offset {}",
                        self.pos
                    ));
                }
            }
        }
        Ok(JsonValue::OrderedObject(entries))
    }

    fn parse_array(&mut self) -> Result<JsonValue, String> {
        self.pos += 1; // '['
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(JsonValue::Array(items));
        }

        loop {
            let item = self.parse_value()?;
            items.push(item);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                _ => {
                    return Err(format!(
                        "expected ',' or ']' in array at offset {}",
                        self.pos
                    ));
                }
            }
        }
        Ok(JsonValue::Array(items))
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.pos += 1; // '"'
        let mut out = String::new();

        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            if b == b'"' {
                self.pos += 1;
                return Ok(out);
            }
            if b == b'\\' {
                self.pos += 1;
                let Some(esc) = self.peek() else {
                    return Err("unterminated escape sequence in JSON string".to_string());
                };
                self.pos += 1;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{0008}'),
                    b'f' => out.push('\u{000c}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let hi = self.read_hex4()?;
                        if (0xD800..=0xDBFF).contains(&hi) {
                            if self.bytes.get(self.pos..self.pos + 2) != Some(b"\\u") {
                                return Err("unpaired UTF-16 high surrogate in JSON".to_string());
                            }
                            self.pos += 2;
                            let lo = self.read_hex4()?;
                            if !(0xDC00..=0xDFFF).contains(&lo) {
                                return Err("invalid UTF-16 low surrogate in JSON".to_string());
                            }
                            let codepoint =
                                0x10000 + (((hi as u32 - 0xD800) << 10) | (lo as u32 - 0xDC00));
                            if let Some(ch) = char::from_u32(codepoint) {
                                out.push(ch);
                            }
                        } else if let Some(ch) = char::from_u32(hi as u32) {
                            out.push(ch);
                        } else {
                            return Err("invalid Unicode escape scalar in JSON".to_string());
                        }
                    }
                    other => {
                        return Err(format!("invalid JSON escape '\\{}'", other as char));
                    }
                }
            } else {
                // Decode valid UTF-8 sequence starting at `self.pos`
                let start = self.pos;
                self.pos += 1;
                while self.pos < self.bytes.len() && (self.bytes[self.pos] & 0xC0) == 0x80 {
                    self.pos += 1;
                }
                let s = std::str::from_utf8(&self.bytes[start..self.pos])
                    .map_err(|_| format!("invalid UTF-8 bytes in JSON string at {}", start))?;
                out.push_str(s);
            }
        }

        Err("unterminated JSON string".to_string())
    }

    fn read_hex4(&mut self) -> Result<u16, String> {
        let Some(slice) = self.bytes.get(self.pos..self.pos + 4) else {
            return Err("truncated \\uXXXX escape in JSON".to_string());
        };
        let s = std::str::from_utf8(slice).map_err(|_| "invalid hex in \\uXXXX".to_string())?;
        let val = u16::from_str_radix(s, 16).map_err(|_| "invalid hex in \\uXXXX".to_string())?;
        self.pos += 4;
        Ok(val)
    }

    fn parse_number(&mut self) -> Result<JsonValue, String> {
        let start = self.pos;
        let is_neg = if self.peek() == Some(b'-') {
            self.pos += 1;
            true
        } else {
            false
        };

        let mut is_float = false;
        while let Some(b) = self.peek() {
            match b {
                b'0'..=b'9' => self.pos += 1,
                b'.' | b'e' | b'E' | b'+' | b'-' => {
                    is_float = true;
                    self.pos += 1;
                }
                _ => break,
            }
        }

        let token = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| "invalid UTF-8 in JSON number".to_string())?;

        if !is_float {
            if is_neg {
                if let Ok(v) = token.parse::<i64>() {
                    return Ok(JsonValue::Int(v));
                }
            } else if let Ok(v) = token.parse::<u64>() {
                return Ok(JsonValue::Uint(v));
            }
        }

        // Preserve non-integer float telemetry fields losslessly as rounded i64 or string if huge
        if let Ok(f) = token.parse::<f64>() {
            if f.fract() == 0.0 && f >= 0.0 && f <= (u64::MAX as f64) {
                return Ok(JsonValue::Uint(f as u64));
            }
            return Ok(JsonValue::Str(token.to_string()));
        }

        Err(format!("invalid JSON number '{}' at offset {}", token, start))
    }
}
