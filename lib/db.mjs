import {createClient} from '@libsql/client';
export const db=createClient({url:process.env.TURSO_DATABASE_URL||'file:local.db',authToken:process.env.TURSO_AUTH_TOKEN});
let ready;
export function init(){return ready ||= db.batch([
`CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, created_at INTEGER NOT NULL)`,
`CREATE TABLE IF NOT EXISTS credentials(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,public_key TEXT NOT NULL,counter INTEGER NOT NULL,transports TEXT NOT NULL,name TEXT NOT NULL,storage TEXT NOT NULL,created_at INTEGER NOT NULL)`,
`CREATE TABLE IF NOT EXISTS challenges(id TEXT PRIMARY KEY,binding TEXT NOT NULL,kind TEXT NOT NULL,value TEXT NOT NULL,payload TEXT NOT NULL,expires_at INTEGER NOT NULL)`,
`CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY,user_id TEXT NOT NULL,credential_id TEXT NOT NULL,expires_at INTEGER NOT NULL)`,
`CREATE TABLE IF NOT EXISTS notes(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,title TEXT NOT NULL,body TEXT NOT NULL)`,
`CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id TEXT NOT NULL,at INTEGER NOT NULL,action TEXT NOT NULL,status INTEGER NOT NULL,detail TEXT NOT NULL)`,
`CREATE INDEX IF NOT EXISTS notes_owner ON notes(user_id)`,
`CREATE INDEX IF NOT EXISTS credentials_owner ON credentials(user_id)`
],'write');}
export const sql=(text,args=[])=>db.execute({sql:text,args});
