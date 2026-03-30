# sqlx-key-gen
SQLX-Key-Generation

`sqlx-key-gen` is a Rust utility that parses `sqlx::query!` macros and manually generates the `sqlx` query cache JSON entries (similar to `.sqlx/query-*.json`). This is particularly useful for generating offline cache keys ahead of time or handling macro generation scenarios where the standard `cargo sqlx prepare` might fall short.

## Features

- **SQL Extraction**: Extracts the raw SQL query string from `sqlx::query!(...)` blocks.
- **SHA-256 Hashing**: Hashes the extracted SQL query string using SHA-256 to generate the exact same cache key hash as `sqlx`.
- **Parameter Extraction & Type Inference**: Parses passed parameter variables and predicts their PostgreSQL data types (e.g., `Uuid`, `Text`, `Int4`, `Timestamptz`) purely based on variable name semantics.
- **Cache JSON Generation**: Outputs a JSON structure that cleanly maps to `sqlx`'s internal offline query metadata cache format.

## Example

Given the Rust macro input:
```rust
sqlx::query!(r#"SELECT * FROM test WHERE agent_id = $1"#, agent.agent_id)
```

The tool will:
1. Extract the SQL: `SELECT * FROM test WHERE agent_id = $1`
2. Extract the parameter variable: `agent.agent_id`
3. Infer the database type from the suffix `agent_id` ➔ `Uuid`
4. Calculate the SHA-256 hash of the query string.
5. Generate a JSON payload matching the `sqlx` expected offline cache format.

### Type Inference Rules

Parameter type inference works by analyzing common semantic substrings within variable names:
- `uuid` / `agent_id` ➔ `Uuid`
- `key` / `name` / `text` / `str` ➔ `Text`
- `i32` / `int4` ➔ `Int4`
- `i64` / `int8` ➔ `Int8`
- `f32` / `float4` ➔ `Float4`
- `timestamp` / `datetime` ➔ `Timestamptz`
- `date` ➔ `Date`
- `bool` ➔ `Bool`
- `json` ➔ `Jsonb`

*(Defaults to `Text` if no matching pattern is found.)*

## Usage

This project functions as a binary standalone tool. In its current iteration, it parses input directly inside `main.rs` and outputs the resulting generated `sqlx` JSON structure to standard output.

Run the tool using Cargo:
```bash
cargo run
```

## Testing

The project includes built-in unit tests verifying SQL string extraction, type inference matching, parameter counting, and hashing functionalities. To run the test suite:

```bash
cargo test
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
