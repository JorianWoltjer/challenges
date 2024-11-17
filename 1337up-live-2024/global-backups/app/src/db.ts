import { Database } from "bun:sqlite";

const db = new Database("/tmp/db.sqlite");

export type User = {
  username: string;
  password: string;
};

export async function createUser(username: string, password: string): Promise<void> {
  if (await getUser(username)) {
    throw new Error("User already exists");
  }

  const hash = await Bun.password.hash(password);
  db.run("INSERT INTO users VALUES (?, ?)", [username, hash]);
}

export async function getUser(username: string): Promise<User | null> {
  return db.query("SELECT * FROM users WHERE username = ?").get(username) as User;
}

db.run(`CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY,
  password TEXT
)`);
try {
  await createUser("admin", Bun.env.ADMIN_PASSWORD);
  console.log("Created admin user");
} catch (e) {
  console.log("Admin user already exists");
}

export default db;
