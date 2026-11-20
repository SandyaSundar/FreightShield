import { execFileSync } from "node:child_process";
import { mkdirSync } from "node:fs";

const testSecret = "test-only-freightshield-e2e-secret-32";
const databasePath = "/tmp/freightshield-e2e.sqlite3";
const sessionDirectory = "/tmp/freightshield-playwright";

export default function globalSetup() {
  mkdirSync(sessionDirectory, { recursive: true });
  const python = `
import json, os
os.environ['AUTH_JWT_SECRET'] = ${JSON.stringify(testSecret)}
os.environ['DATABASE_PATH'] = ${JSON.stringify(databasePath)}
from app.core.config import get_settings
from app.core.db import connect
from app.core.security import issue_token
from app.services import users
with connect(): pass
sessions = {}
for role in ('admin', 'vendor', 'user'):
    email = role + '@freightshield-e2e.local'
    user = users.get_by_email(email) or users.create(email, role)
    sessions[role] = issue_token(user, get_settings())
with open(${JSON.stringify(`${sessionDirectory}/sessions.json`)}, 'w') as output:
    json.dump(sessions, output)
`;
  execFileSync("python3", ["-c", python], {
    cwd: "backend",
    env: { ...process.env, AUTH_JWT_SECRET: testSecret, DATABASE_PATH: databasePath },
    stdio: "pipe",
  });
}