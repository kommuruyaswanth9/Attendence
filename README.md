# Attendance Tracker — Resend OTP Login

This version keeps the existing attendance tracker and adds a server-side OTP login.

## Files

- `index.html` — login page + attendance tracker UI
- `script.js` — attendance logic + OTP login flow
- `style.css` — tracker and login styling
- `server.js` — Express backend, OTP generation/verification, session cookie, Resend email sending
- `package.json` — Node dependencies
- `.env.example` — environment-variable template
- `.gitignore` — keeps the private `.env` and `node_modules` out of Git

## Setup

1. Install Node.js 18 or newer.
2. Open a terminal in this folder.
3. Run:

   `npm install`

4. Copy `.env.example` to a new file named `.env`.
5. Put your Resend API key in `.env`:

   `RESEND_API_KEY=re_...`

6. Keep the sender as `onboarding@resend.dev` for initial testing if your Resend account permits it. For production sending, verify a domain in Resend and change `RESEND_FROM` to that verified sender.
7. Create a long random value for `SESSION_SECRET`.
8. Start the app:

   `npm start`

9. Open `http://localhost:3000`.

## OTP behavior

- OTP is generated on the server with a cryptographically secure random generator.
- OTP is stored only as a SHA-256 hash.
- OTP expires after 60 seconds.
- A challenge is limited to 5 verification attempts.
- A new OTP request is rate-limited to once every 30 seconds per client IP.
- Successful verification creates an HttpOnly session cookie.
- The Resend API key is never sent to the browser.

## Important

The attendance records remain in browser `localStorage`, just as in the original tracker. The OTP protects access to the web interface, but it does not turn localStorage into a server-side multi-user database.

For a production multi-user system, move attendance records to a database and associate them with the authenticated user.
