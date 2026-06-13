import * as Effect from "effect/Effect";
import * as SqlClient from "effect/unstable/sql/SqlClient";

import { columnExists } from "./schemaHelpers.ts";

export default Effect.gen(function* () {
  const sql = yield* SqlClient.SqlClient;

  if (yield* columnExists(sql, "auth_sessions", "client_identity_public_key")) {
    return;
  }

  yield* sql`
    ALTER TABLE auth_sessions
    ADD COLUMN client_identity_public_key TEXT
  `;
});
