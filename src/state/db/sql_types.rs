use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DbText(pub String);

impl DbText {
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl From<&str> for DbText {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<String> for DbText {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<DbText> for String {
    fn from(value: DbText) -> Self {
        value.0
    }
}

impl ToSql for DbText {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(self.0.clone()))
    }
}

impl FromSql for DbText {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value {
            ValueRef::Text(bytes) => {
                let text =
                    std::str::from_utf8(bytes).map_err(|err| FromSqlError::Other(Box::new(err)))?;
                Ok(Self(text.to_string()))
            }
            ValueRef::Null | ValueRef::Integer(_) | ValueRef::Real(_) | ValueRef::Blob(_) => {
                Err(FromSqlError::InvalidType)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbBlob(pub Vec<u8>);

impl DbBlob {
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for DbBlob {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<&[u8]> for DbBlob {
    fn from(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}

impl From<DbBlob> for Vec<u8> {
    fn from(value: DbBlob) -> Self {
        value.0
    }
}

impl ToSql for DbBlob {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(self.0.clone()))
    }
}

impl FromSql for DbBlob {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value {
            ValueRef::Blob(bytes) => Ok(Self(bytes.to_vec())),
            ValueRef::Null | ValueRef::Integer(_) | ValueRef::Real(_) | ValueRef::Text(_) => {
                Err(FromSqlError::InvalidType)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DbBlob32(pub [u8; 32]);

impl DbBlob32 {
    pub fn into_inner(self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for DbBlob32 {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl From<&[u8; 32]> for DbBlob32 {
    fn from(value: &[u8; 32]) -> Self {
        Self(*value)
    }
}

impl From<DbBlob32> for [u8; 32] {
    fn from(value: DbBlob32) -> Self {
        value.0
    }
}

impl ToSql for DbBlob32 {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(self.0.to_vec()))
    }
}

impl FromSql for DbBlob32 {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value {
            ValueRef::Blob(bytes) if bytes.len() == 32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(bytes);
                Ok(Self(out))
            }
            ValueRef::Blob(_) => Err(FromSqlError::Other(
                "expected a 32-byte BLOB".to_string().into(),
            )),
            ValueRef::Null | ValueRef::Integer(_) | ValueRef::Real(_) | ValueRef::Text(_) => {
                Err(FromSqlError::InvalidType)
            }
        }
    }
}

pub fn get_text(row: &rusqlite::Row<'_>, idx: usize) -> rusqlite::Result<String> {
    Ok(row.get::<_, DbText>(idx)?.into_inner())
}

pub fn get_opt_text(row: &rusqlite::Row<'_>, idx: usize) -> rusqlite::Result<Option<String>> {
    Ok(row.get::<_, Option<DbText>>(idx)?.map(DbText::into_inner))
}

pub fn get_blob(row: &rusqlite::Row<'_>, idx: usize) -> rusqlite::Result<Vec<u8>> {
    Ok(row.get::<_, DbBlob>(idx)?.into_inner())
}

pub fn get_opt_blob(row: &rusqlite::Row<'_>, idx: usize) -> rusqlite::Result<Option<Vec<u8>>> {
    Ok(row.get::<_, Option<DbBlob>>(idx)?.map(DbBlob::into_inner))
}

pub fn get_blob32(row: &rusqlite::Row<'_>, idx: usize) -> rusqlite::Result<[u8; 32]> {
    Ok(row.get::<_, DbBlob32>(idx)?.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn db_text_round_trips() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute("CREATE TABLE demo (value TEXT NOT NULL)", [])
            .unwrap();
        conn.execute(
            "INSERT INTO demo (value) VALUES (?1)",
            rusqlite::params![DbText::from("hello")],
        )
        .unwrap();
        let value: DbText = conn
            .query_row("SELECT value FROM demo", [], |row| row.get(0))
            .unwrap();
        assert_eq!(value.into_inner(), "hello");
    }

    #[test]
    fn db_blob_32_rejects_wrong_length() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute("CREATE TABLE demo (value BLOB NOT NULL)", [])
            .unwrap();
        conn.execute(
            "INSERT INTO demo (value) VALUES (?1)",
            rusqlite::params![DbBlob::from(vec![7u8; 31])],
        )
        .unwrap();
        let err = conn
            .query_row("SELECT value FROM demo", [], |row| {
                row.get::<_, DbBlob32>(0)
            })
            .unwrap_err();
        assert!(
            err.to_string().contains("32-byte"),
            "unexpected error: {err}"
        );
    }
}
