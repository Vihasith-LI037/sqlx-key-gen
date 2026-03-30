// use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn infer_type(hint: &str) -> &'static str {
    match hint {
        h if h.contains("uuid") || h.contains("agent_id") => "Uuid",
        h if h.contains("key") || h.contains("name") || h.contains("text") || h.contains("str") => {
            "Text"
        }
        h if h.contains("i32") || h.contains("int4") => "Int4",
        h if h.contains("i64") || h.contains("int8") => "Int8",
        h if h.contains("f32") || h.contains("float4") => "Float4",
        h if h.contains("f64") || h.contains("float8") => "Float8",
        h if h.contains("bool") => "Bool",
        h if h.contains("timestamp") || h.contains("datetime") => "Timestamptz",
        h if h.contains("date") => "Date",
        h if h.contains("json") => "Jsonb",
        _ => "Text",
    }
}

fn count_params(sql: &str) -> usize {
    let mut max = 0usize;
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' {
            let mut num_str = String::new();
            while let Some(&d) = chars.peek() {
                if d.is_ascii_digit() {
                    num_str.push(d);
                    chars.next();
                } else {
                    break;
                }
            }
            if let Ok(n) = num_str.parse::<usize>() {
                if n > max {
                    max = n;
                }
            }
        }
    }
    max
}

fn extract_sql(input: &str) -> Option<String> {
    if let Some(start) = input.find("r#\"") {
        let inner_start = start + 3;
        if let Some(end) = input[inner_start..].find("\"#") {
            return Some(input[inner_start..inner_start + end].to_string());
        }
    }
    // Try plain "..."
    if let Some(start) = input.find('"') {
        let inner_start = start + 1;
        if let Some(end) = input[inner_start..].find('"') {
            return Some(input[inner_start..inner_start + end].to_string());
        }
    }
    None
}

fn extract_param_vars(input: &str) -> Vec<String> {
    let after_sql = if let Some(pos) = input.find("\"#") {
        &input[pos + 2..]
    } else {
        input
    };

    let mut params = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    let mut started = false;

    for c in after_sql.chars() {
        match c {
            ',' if !started => {
                started = true;
                current.clear();
            }
            '(' => {
                depth += 1;
                current.push(c);
            }
            ')' => {
                if depth == 0 {
                    let trimmed = current.trim().to_string();
                    if !trimmed.is_empty() {
                        params.push(trimmed);
                    }
                    break;
                }
                depth -= 1;
                current.push(c);
            }
            ',' if depth == 0 => {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    params.push(trimmed);
                }
                current.clear();
            }
            _ => {
                current.push(c);
            }
        }
    }

    params
}

/// Computes SHA-256 of the SQL query string (as sqlx does).
fn sha256_hex(sql: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sql.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Generates the sqlx query cache JSON entry.
fn generate_query_entry(sql: &str, param_vars: &[String]) -> Value {
    let param_types: Vec<Value> = param_vars
        .iter()
        .map(|v| {
            // Use the last segment of a field access (e.g. "agent.agent_id" -> "agent_id")
            let name = v.split('.').last().unwrap_or(v).to_lowercase();
            json!(infer_type(&name))
        })
        .collect();

    json!({
        "describe": {
            "columns": [],
            "nullable": [],
            "parameters": {
                "Left": param_types
            }
        },
        "query": sql
    })
}

fn main() {
    let input = r##"
        sqlx::query!(
        sqlx-query
    )
    "##;
    let sql = extract_sql(input).expect("Could not find SQL string in input");
    let param_vars = extract_param_vars(input);
    let expected_params = count_params(&sql);
    if param_vars.len() != expected_params {
        eprintln!(
            "Warning: SQL has {} parameter(s) ($1..${}), but {} variable(s) were found: {:?}",
            expected_params,
            expected_params,
            param_vars.len(),
            param_vars
        );
    }
    let hash = sha256_hex(&sql);
    let entry = generate_query_entry(&sql, &param_vars);

    let mut output: BTreeMap<String, Value> = BTreeMap::new();
    output.insert(hash, entry);

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_params() {
        let sql = "SELECT * FROM t WHERE id = $1 AND key = $2";
        assert_eq!(count_params(sql), 2);
    }

    #[test]
    fn test_extract_sql() {
        // let input = r##"sqlx::query!(r#"SELECT 1"#, foo)"##;
        let s = "r#\"SELECT 1\"#";
        let result = extract_sql(s);
        assert_eq!(result, Some("SELECT 1".to_string()));
    }

    #[test]
    fn test_sha256() {
        let h = sha256_hex("hello");
        assert_eq!(
            h,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_infer_type() {
        assert_eq!(infer_type("agent_id"), "Uuid");
        assert_eq!(infer_type("agent_key"), "Text");
        assert_eq!(infer_type("count_i32"), "Int4");
    }
}
