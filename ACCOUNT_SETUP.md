# Rider's 67 Games — optional cloud accounts

The site remains usable without signing in. The Account desktop icon opens optional
username/password registration and login. Accounts are stored in a Neon Postgres
database and sessions use an HttpOnly, SameSite cookie.

## One-time setup

1. Create a free Neon Postgres project at https://neon.tech/ and copy its pooled
   connection string.
2. In the Neon SQL Editor, run the contents of `schema.sql`.
3. In the Vercel project, open Settings → Environment Variables and add:
   - `DATABASE_URL` = your Neon pooled connection string
   - `SESSION_SECRET` = a random secret of at least 32 characters
4. Redeploy the Vercel project after adding the variables.

You can generate a secret locally with Node.js:
`node -e "console.log(require('node:crypto').randomBytes(48).toString('hex'))"`

## Account rules

- No email address is requested or stored.
- Username: 3–20 letters, numbers, or underscores.
- Password: 10–128 characters; passwords are hashed with scrypt and are never
  stored in plain text.
- Accounts are optional. Users can browse and play without registering.
- There is no email-based password recovery. If a user forgets their password,
  they will not be able to recover that account with the current setup.
