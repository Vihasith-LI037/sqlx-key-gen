use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPool;
use std::collections::BTreeMap;

/// Maps PostgreSQL type OIDs to SQLx parameter types
fn postgres_type_to_sqlx(pg_type: &str) -> &'static str {
    match pg_type {
        "uuid" => "Uuid",
        "text" | "varchar" | "character varying" | "character" | "char" | "name" => "Text",
        "int4" | "integer" => "Int4",
        "int8" | "bigint" => "Int8",
        "float4" | "real" => "Float4",
        "float8" | "double precision" => "Float8",
        "bool" | "boolean" => "Bool",
        "timestamp" | "timestamp without time zone" => "Timestamp",
        "timestamptz" | "timestamp with time zone" => "Timestamptz",
        "date" => "Date",
        "time" | "time without time zone" => "Time",
        "timetz" | "time with time zone" => "Timetz",
        "bytea" => "Bytea",
        "json" => "Json",
        "jsonb" => "Jsonb",
        "numeric" | "decimal" => "Numeric",
        "bit" | "bit varying" => "BitVec",
        _ => "Text", // default fallback
    }
}

/// Fallback type inference when database is not available
fn infer_type(hint: &str) -> &'static str {
    match hint {
        h if h.contains("uuid") || h.contains("agent_id") => "Uuid",
        h if h.contains("bool") => "Bool",
        h if h.contains("i32") || h.contains("int4") => "Int4",
        h if h.contains("i64") || h.contains("int8") => "Int8",
        h if h.contains("f32") || h.contains("float4") => "Float4",
        h if h.contains("f64") || h.contains("float8") => "Float8",
        h if h.contains("timestamp") || h.contains("datetime") => "Timestamptz",
        h if (h.ends_with("_date") || h.ends_with("date")) && 
             !h.contains("from") && !h.contains("to") && !h.contains("created") => "Date",
        h if h.contains("json") => "Jsonb",
        h if h.contains("key") || h.contains("name") || h.contains("text") || h.contains("str") => {
            "Text"
        }
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

    // Clean up parameters: remove method calls and get base variable
    params
        .iter()
        .map(|p| {
            // Remove method calls: data_json["field"].clone() -> data_json["field"]
            if let Some(dot_pos) = p.find('.') {
                p[..dot_pos].to_string()
            } else {
                p.clone()
            }
        })
        .collect()
}

/// Computes SHA-256 of the SQL query string (as sqlx does).
fn sha256_hex(sql: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sql.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Extracts table name from INSERT/UPDATE/SELECT/DELETE query
/// and function name from SELECT function_name(...) queries
fn extract_table_name(sql: &str) -> Option<String> {
    let sql_upper = sql.to_uppercase();
    
    // Handle INSERT INTO
    if let Some(pos) = sql_upper.find("INSERT INTO") {
        let after = &sql[pos + 11..];
        let table = after
            .split(|c: char| c.is_whitespace() || c == '(')
            .find(|s| !s.is_empty())?;
        return Some(table.trim().to_string());
    }
    
    // Handle UPDATE
    if let Some(pos) = sql_upper.find("UPDATE") {
        let after = &sql[pos + 6..];
        let table = after
            .split(|c: char| c.is_whitespace())
            .find(|s| !s.is_empty())?;
        return Some(table.trim().to_string());
    }
    
    // Handle DELETE FROM
    if let Some(pos) = sql_upper.find("DELETE FROM") {
        let after = &sql[pos + 11..];
        let table = after
            .split(|c: char| c.is_whitespace())
            .find(|s| !s.is_empty())?;
        return Some(table.trim().to_string());
    }
    
    None
}

/// Extracts function name from SELECT function_name(...) queries
fn extract_function_name(sql: &str) -> Option<String> {
    let sql_trimmed = sql.trim();
    let sql_upper = sql_trimmed.to_uppercase();
    
    // Look for pattern: SELECT ... function_name(
    if sql_upper.contains("SELECT") {
        if let Some(paren_pos) = sql_trimmed.find('(') {
            // Get everything before the opening paren and extract the function name
            let before_paren = &sql_trimmed[..paren_pos].trim();
            
            // Split by whitespace and get the last token (the function name)
            if let Some(func_name) = before_paren.split_whitespace().last() {
                // Make sure it looks like a function name (not a keyword)
                if !func_name.is_empty() && !func_name.contains(',') {
                    return Some(func_name.to_lowercase());
                }
            }
        }
    }
    
    None
}

/// Extracts the column name from parameter variable
/// Handles cases like:
/// - simple_var -> simple_var
/// - data_json["field_name"] -> field_name  
/// - obj.field -> field
fn extract_column_name(var: &str) -> String {
    if let Some(bracket_start) = var.find('[') {
        if let Some(bracket_end) = var.find(']') {
            let inside = &var[bracket_start + 1..bracket_end];
            // Remove quotes if present
            let cleaned = inside.trim_matches(|c| c == '"' || c == '\'');
            return cleaned.to_lowercase();
        }
    }
    
    // Handle field access: obj.field -> field
    var.split('.').last().unwrap_or(var).to_lowercase()
}

/// Attempts to infer parameter types from database schema
/// First tries to detect if it's a function call, then falls back to table columns
/// Queries information_schema for actual column/parameter types
/// Handles case-insensitive and underscore-flexible matching
async fn infer_types_from_schema(
    pool: &PgPool,
    sql: &str,
    param_vars: &[String],
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut inferred_types = Vec::new();
    
    // First, check if this is a function call
    if let Some(func_name) = extract_function_name(sql) {
        println!("Querying schema for function: '{}'", func_name);
        
        // Query function parameters using PostgreSQL system catalogs
        // This is more reliable than information_schema
        for (idx, _var) in param_vars.iter().enumerate() {
            let query = r#"
                SELECT pg_catalog.format_type(p.proargtypes[($1 - 1)], null)
                FROM pg_catalog.pg_proc p
                WHERE p.proname = $2
                  AND pg_catalog.pg_function_is_visible(p.oid)
                LIMIT 1
            "#;
            
            let result = sqlx::query_scalar::<_, String>(query)
                .bind((idx + 1) as i32)
                .bind(&func_name)
                .fetch_optional(pool)
                .await?;
            
            match result {
                Some(pg_type) => {
                    let sqlx_type = postgres_type_to_sqlx(&pg_type);
                    println!("Parameter ${}: {} → {} ({})", idx + 1, func_name, sqlx_type, pg_type);
                    inferred_types.push(sqlx_type.to_string());
                }
                None => {
                    println!("Parameter ${}: No function parameter found at position {}", idx + 1, idx + 1);
                    inferred_types.push("Text".to_string());
                }
            }
        }
        
        return Ok(inferred_types);
    }
    
    // If not a function, try to extract table name and query columns
    let table_name = extract_table_name(sql)
        .ok_or("Could not extract table name or function name from SQL")?;
    
    println!("Querying schema for table: '{}'", table_name);
    
    for (idx, var) in param_vars.iter().enumerate() {
        // Extract the actual column name from the variable
        let column_name = extract_column_name(var);
        
        // Try exact match first
        let query_exact = r#"
            SELECT data_type 
            FROM information_schema.columns 
            WHERE table_name = $1 
              AND column_name = $2
            LIMIT 1
        "#;
        
        let mut result = sqlx::query_scalar::<_, String>(query_exact)
            .bind(&table_name)
            .bind(&column_name)
            .fetch_optional(pool)
            .await?;
        
        // If exact match fails, try case-insensitive + underscore-flexible match
        if result.is_none() {
            let query_flexible = r#"
                SELECT data_type 
                FROM information_schema.columns 
                WHERE table_name = $1 
                  AND REPLACE(LOWER(column_name), '_', '') = REPLACE(LOWER($2), '_', '')
                LIMIT 1
            "#;
            
            result = sqlx::query_scalar::<_, String>(query_flexible)
                .bind(&table_name)
                .bind(&column_name)
                .fetch_optional(pool)
                .await?;
        }
        
        match result {
            Some(pg_type) => {
                let sqlx_type = postgres_type_to_sqlx(&pg_type);
                println!("Parameter ${}: '{}' → {} ({})", idx + 1, column_name, sqlx_type, pg_type);
                inferred_types.push(sqlx_type.to_string());
            }
            None => {
                // Fallback to heuristic if not found in schema
                let fallback_type = infer_type(&column_name);
                println!("Parameter ${}: '{}' → {} (not in schema, using heuristic)", idx + 1, column_name, fallback_type);
                inferred_types.push(fallback_type.to_string());
            }
        }
    }
    
    Ok(inferred_types)
}

/// Generates the sqlx query cache JSON entry.
fn generate_query_entry(sql: &str, param_types: &[String]) -> Value {
    let param_types_json: Vec<Value> = param_types
        .iter()
        .map(|t| Value::String(t.clone()))
        .collect();

    json!({
        "describe": {
            "columns": [],
            "nullable": [],
            "parameters": {
                "Left": param_types_json
            }
        },
        "query": sql
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables from .env
    dotenv::dotenv().ok();
    
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| {
            eprintln!("DATABASE_URL not set in .env file");
            eprintln!("Will fall back to variable name heuristics for type inference");
            String::new()
        });
    
    // Try to create a database pool if DATABASE_URL is available
    let pool = if !database_url.is_empty() {
        match PgPool::connect(&database_url).await {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!("Failed to connect to database: {}", e);
                eprintln!("Will fall back to variable name heuristics for type inference");
                None
            }
        }
    } else {
        None
    };

    let input = r##"
        sqlx::query!()
    "##;
    
    let sql = extract_sql(input).expect("Could not find SQL string in input");
    let param_vars = extract_param_vars(input);
    let expected_params = count_params(&sql);
    
    if param_vars.len() != expected_params {
        eprintln!(
            "Warning: SQL has {} parameter(s), but {} variable(s) were found: {:?}",
            expected_params,
            param_vars.len(),
            param_vars
        );
    }
    
    // Determine parameter types: use database schema if available, fallback to heuristics
    let param_types = if let Some(ref p) = pool {
        match infer_types_from_schema(p, &sql, &param_vars).await {
            Ok(types) => {
                println!("Successfully inferred types from database schema\n");
                types
            }
            Err(e) => {
                eprintln!("Failed to infer types from schema: {}", e);
                eprintln!("Falling back to variable name heuristics\n");
                param_vars
                    .iter()
                    .enumerate()
                    .map(|(idx, v)| {
                        let col_name = extract_column_name(v);
                        let typ = infer_type(&col_name);
                        println!("Parameter ${}: {} → {}", idx + 1, col_name, typ);
                        typ.to_string()
                    })
                    .collect()
            }
        }
    } else {
        eprintln!("Database not available - using variable name heuristics\n");
        param_vars
            .iter()
            .enumerate()
            .map(|(idx, v)| {
                let col_name = extract_column_name(v);
                let typ = infer_type(&col_name);
                println!("Parameter ${}: {} → {}", idx + 1, col_name, typ);
                typ.to_string()
            })
            .collect()
    };
    
    let hash = sha256_hex(&sql);
    let entry = generate_query_entry(&sql, &param_types);

    let mut output: BTreeMap<String, Value> = BTreeMap::new();
    output.insert(hash, entry);

    println!("\n{}", serde_json::to_string_pretty(&output).unwrap());
    
    Ok(())
}
