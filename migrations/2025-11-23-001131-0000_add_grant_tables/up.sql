-- Your SQL goes here



CREATE TABLE "oauth_grants"(
	"code_hash" TEXT NOT NULL PRIMARY KEY,
	"client_id" UUID NOT NULL,
	"owner_id" UUID NOT NULL,
	"redirect_uri" TEXT NOT NULL,
	"scope" TEXT NOT NULL,
	"until" TIMESTAMPTZ NOT NULL
);

CREATE TABLE "oauth_grant_extensions"(
	"code_hash" TEXT NOT NULL,
	"name" TEXT NOT NULL,
	"value" TEXT NOT NULL,
	PRIMARY KEY("code_hash", "name"),
	FOREIGN KEY ("code_hash") REFERENCES "oauth_grants"("code_hash")
);

