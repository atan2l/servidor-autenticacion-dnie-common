use chrono::{DateTime, Utc};
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

#[derive(Debug, Queryable, Identifiable, Selectable, Insertable, PartialEq)]
#[diesel(primary_key(code_hash))]
#[diesel(table_name = crate::db::schema::oauth_grants)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct OAuthGrant {
    pub code_hash: String,
    pub client_id: Uuid,
    pub owner_id: Uuid,
    pub redirect_uri: String,
    pub scope: String,
    pub until: DateTime<Utc>,
}

#[derive(Debug, Queryable, Identifiable, Selectable, Insertable, Associations, PartialEq)]
#[diesel(primary_key(code_hash, name))]
#[diesel(table_name = crate::db::schema::oauth_grant_extensions)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(belongs_to(OAuthGrant, foreign_key = code_hash))]
pub struct OAuthGrantExtension {
    pub code_hash: String,
    pub name: String,
    pub value: String,
}
