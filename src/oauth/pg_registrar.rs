use crate::db;
use crate::db::models::{AuthClient, AuthClientAllowedScope, AuthClientRedirectUri};
use crate::db::schema::auth_client_redirect_uris::uri;
use crate::db::schema::auth_clients::dsl::auth_clients;
use crate::db::schema::auth_clients::id;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use async_trait::async_trait;
use diesel::{BelongingToDsl, QueryDsl};
use diesel::{ExpressionMethods, SelectableHelper};
use diesel_async::RunQueryDsl;
use oxide_auth::endpoint::{PreGrant, Scope};
use oxide_auth::primitives::prelude::ClientUrl;
use oxide_auth::primitives::registrar::{BoundClient, RegisteredUrl, RegistrarError};
use oxide_auth_async::primitives::Registrar;
use std::borrow::Cow;
use std::sync::Arc;
use uuid::Uuid;

pub struct PgRegistrar {
    pool: Arc<db::Pool>,
}

impl PgRegistrar {
    fn new(pool: Arc<db::Pool>) -> Self {
        Self { pool }
    }

    async fn get_auth_client(&self, client_id: &Uuid) -> Option<AuthClient> {
        let mut conn = self.pool.get().await.ok()?;
        auth_clients
            .filter(id.eq(client_id))
            .select(AuthClient::as_select())
            .first(&mut conn)
            .await
            .ok()
    }

    async fn get_matching_client_redirect_uri(
        &self,
        client: &AuthClient,
        redirect_uri: &str,
    ) -> Option<AuthClientRedirectUri> {
        let mut conn = self.pool.get().await.ok()?;
        AuthClientRedirectUri::belonging_to(client)
            .filter(uri.eq(redirect_uri))
            .select(AuthClientRedirectUri::as_select())
            .first(&mut conn)
            .await
            .ok()
    }

    async fn get_client_scopes(&self, client: &AuthClient) -> Option<Vec<AuthClientAllowedScope>> {
        let mut conn = self.pool.get().await.ok()?;
        AuthClientAllowedScope::belonging_to(client)
            .select(AuthClientAllowedScope::as_select())
            .load(&mut conn)
            .await
            .ok()
    }
}

#[async_trait]
impl Registrar for PgRegistrar {
    async fn bound_redirect<'a>(
        &self,
        bound: ClientUrl<'a>,
    ) -> Result<BoundClient<'a>, RegistrarError> {
        let client_id = &bound
            .client_id
            .parse::<Uuid>()
            .map_err(|_| RegistrarError::PrimitiveError)?;
        let client = self
            .get_auth_client(client_id)
            .await
            .ok_or(RegistrarError::Unspecified)?;
        let client_uri = bound.redirect_uri.ok_or(RegistrarError::PrimitiveError)?;

        let matching_client_uri = self
            .get_matching_client_redirect_uri(&client, client_uri.as_str())
            .await
            .ok_or(RegistrarError::PrimitiveError)?;

        let registered_uri = RegisteredUrl::Exact(
            matching_client_uri
                .uri
                .parse()
                .map_err(|_| RegistrarError::PrimitiveError)?,
        );

        Ok(BoundClient {
            client_id: bound.client_id,
            redirect_uri: Cow::Owned(registered_uri),
        })
    }

    async fn negotiate<'a>(
        &self,
        client: BoundClient<'a>,
        scope: Option<Scope>,
    ) -> Result<PreGrant, RegistrarError> {
        let client_id = &client
            .client_id
            .parse::<Uuid>()
            .map_err(|_| RegistrarError::PrimitiveError)?;
        let auth_client = self
            .get_auth_client(client_id)
            .await
            .ok_or(RegistrarError::Unspecified)?;

        let scope = if let Some(scope) = scope {
            &scope.to_string()
        } else {
            &auth_client.default_scope
        };

        let client_scopes = self
            .get_client_scopes(&auth_client)
            .await
            .ok_or(RegistrarError::PrimitiveError)?;

        if client_scopes.iter().map(|x| &x.scope).any(|x| x == scope) {
            Ok(PreGrant {
                client_id: client.client_id.into_owned(),
                redirect_uri: client.redirect_uri.into_owned(),
                scope: scope.parse().map_err(|_| RegistrarError::PrimitiveError)?,
            })
        } else {
            Err(RegistrarError::Unspecified)
        }
    }

    async fn check(
        &self,
        client_id: &str,
        passphrase: Option<&[u8]>,
    ) -> Result<(), RegistrarError> {
        let client_id = client_id
            .parse::<Uuid>()
            .map_err(|_| RegistrarError::PrimitiveError)?;
        let client = self
            .get_auth_client(&client_id)
            .await
            .ok_or(RegistrarError::Unspecified)?;

        if !client.confidential {
            return Ok(());
        }

        if let Some(passphrase) = passphrase
            && let Some(secret_hash) = &client.client_secret_hash
        {
            let argon2 = Argon2::default();
            let secret_hash =
                PasswordHash::new(secret_hash).map_err(|_| RegistrarError::PrimitiveError)?;
            argon2
                .verify_password(passphrase, &secret_hash)
                .map_err(|_| RegistrarError::PrimitiveError)
        } else {
            Err(RegistrarError::Unspecified)
        }
    }
}
