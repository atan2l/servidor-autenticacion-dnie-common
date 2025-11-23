// @generated automatically by Diesel CLI.

diesel::table! {
    auth_client_allowed_scopes (id) {
        id -> Uuid,
        client_id -> Uuid,
        scope -> Text,
    }
}

diesel::table! {
    auth_client_redirect_uris (id) {
        id -> Uuid,
        client_id -> Uuid,
        uri -> Text,
    }
}

diesel::table! {
    auth_clients (id) {
        id -> Uuid,
        client_secret_hash -> Nullable<Text>,
        default_scope -> Text,
        confidential -> Bool,
    }
}

diesel::table! {
    oauth_grant_extensions (code_hash, name) {
        code_hash -> Text,
        name -> Text,
        value -> Text,
    }
}

diesel::table! {
    oauth_grants (code_hash) {
        code_hash -> Text,
        client_id -> Uuid,
        owner_id -> Uuid,
        redirect_uri -> Text,
        scope -> Text,
        until -> Timestamptz,
    }
}

diesel::joinable!(auth_client_allowed_scopes -> auth_clients (client_id));
diesel::joinable!(auth_client_redirect_uris -> auth_clients (client_id));
diesel::joinable!(oauth_grant_extensions -> oauth_grants (code_hash));

diesel::allow_tables_to_appear_in_same_query!(
    auth_client_allowed_scopes,
    auth_client_redirect_uris,
    auth_clients,
    oauth_grant_extensions,
    oauth_grants,
);
