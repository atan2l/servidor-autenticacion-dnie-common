use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::bb8;

pub mod models;
pub(crate) mod schema;
pub type Pool = bb8::Pool<AsyncPgConnection>;
