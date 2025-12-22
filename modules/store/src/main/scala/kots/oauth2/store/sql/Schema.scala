package kots.oauth2.store.sql

object Schema {

  val migrations: List[Migration] = List(
    Migration(
      1,
      "CREATE TABLE tokens(" +
        "access_hash VARCHAR(64) PRIMARY KEY, refresh_hash VARCHAR(64), " +
        "grant_id VARCHAR(512) NOT NULL, client_id VARCHAR(512) NOT NULL, " +
        "subject VARCHAR(512) NOT NULL, scopes VARCHAR(2048) NOT NULL, " +
        "issued_at TIMESTAMP NOT NULL, access_expires_at TIMESTAMP NOT NULL, " +
        "refresh_expires_at TIMESTAMP, audience VARCHAR(512), actor VARCHAR(512));" +
        "CREATE INDEX tokens_refresh ON tokens(refresh_hash);" +
        "CREATE INDEX tokens_grant ON tokens(grant_id);" +
        "CREATE TABLE token_details(" +
        "access_hash VARCHAR(64) NOT NULL, ord INT NOT NULL, detail_type VARCHAR(512) NOT NULL, " +
        "locations VARCHAR(2048) NOT NULL, actions VARCHAR(2048) NOT NULL, " +
        "fields VARCHAR(4096) NOT NULL, PRIMARY KEY(access_hash, ord));" +
        "CREATE TABLE retired_tokens(" +
        "refresh_hash VARCHAR(64) PRIMARY KEY, grant_id VARCHAR(512) NOT NULL)"
    ),
    Migration(
      2,
      "CREATE TABLE codes(" +
        "code VARCHAR(512) PRIMARY KEY, client_id VARCHAR(512) NOT NULL, " +
        "redirect_uri VARCHAR(512) NOT NULL, subject VARCHAR(512) NOT NULL, " +
        "scopes VARCHAR(2048) NOT NULL, challenge VARCHAR(512), challenge_method VARCHAR(32), " +
        "expires_at TIMESTAMP NOT NULL, resource VARCHAR(512));" +
        "CREATE TABLE code_details(" +
        "code VARCHAR(512) NOT NULL, ord INT NOT NULL, detail_type VARCHAR(512) NOT NULL, " +
        "locations VARCHAR(2048) NOT NULL, actions VARCHAR(2048) NOT NULL, " +
        "fields VARCHAR(4096) NOT NULL, PRIMARY KEY(code, ord));" +
        "CREATE TABLE redeemed_codes(" +
        "code VARCHAR(512) PRIMARY KEY, grant_id VARCHAR(512) NOT NULL);" +
        "CREATE TABLE grants(" +
        "grant_id VARCHAR(512) PRIMARY KEY, client_id VARCHAR(512) NOT NULL, " +
        "subject VARCHAR(512) NOT NULL, scopes VARCHAR(2048) NOT NULL, " +
        "revoked BOOLEAN NOT NULL);" +
        "CREATE TABLE grant_details(" +
        "grant_id VARCHAR(512) NOT NULL, ord INT NOT NULL, detail_type VARCHAR(512) NOT NULL, " +
        "locations VARCHAR(2048) NOT NULL, actions VARCHAR(2048) NOT NULL, " +
        "fields VARCHAR(4096) NOT NULL, PRIMARY KEY(grant_id, ord))"
    )
  )
}
