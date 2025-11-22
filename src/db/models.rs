use diesel::{Associations, Identifiable, Insertable, Queryable, Selectable};
use uuid::Uuid;

#[derive(Debug, Queryable, Identifiable, Selectable, Insertable, PartialEq)]
#[diesel(table_name = crate::db::schema::auth_clients)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AuthClient {
    pub id: Uuid,
    pub client_secret_hash: Option<String>,
    pub default_scope: String,
    pub confidential: bool,
}

#[derive(Debug, Queryable, Identifiable, Selectable, Insertable, Associations, PartialEq)]
#[diesel(table_name = crate::db::schema::auth_client_allowed_scopes)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(belongs_to(AuthClient, foreign_key = client_id))]
pub struct AuthClientAllowedScope {
    pub id: Uuid,
    pub client_id: Uuid,
    pub scope: String,
}

#[derive(Debug, Queryable, Identifiable, Selectable, Insertable, Associations, PartialEq)]
#[diesel(table_name = crate::db::schema::auth_client_redirect_uris)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(belongs_to(AuthClient, foreign_key = client_id))]
pub struct AuthClientRedirectUri {
    pub id: Uuid,
    pub client_id: Uuid,
    pub uri: String,
}
