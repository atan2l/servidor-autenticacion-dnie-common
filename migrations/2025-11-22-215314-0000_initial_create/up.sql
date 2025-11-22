-- Your SQL goes here
CREATE TABLE "auth_clients"(
	"id" UUID NOT NULL PRIMARY KEY,
	"client_secret_hash" TEXT,
	"default_scope" TEXT NOT NULL,
	"confidential" BOOL NOT NULL
);

CREATE TABLE "auth_client_allowed_scopes"(
    "id" UUID NOT NULL PRIMARY KEY,
    "client_id" UUID NOT NULL,
    "scope" TEXT NOT NULL,
    FOREIGN KEY ("client_id") REFERENCES "auth_clients"("id")
);

CREATE TABLE "auth_client_redirect_uris"(
	"id" UUID NOT NULL PRIMARY KEY,
	"client_id" UUID NOT NULL,
	"uri" TEXT NOT NULL,
	FOREIGN KEY ("client_id") REFERENCES "auth_clients"("id")
);

