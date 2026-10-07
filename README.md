# Attendance Tracker — Mobile SMS OTP Login

This version keeps the existing attendance tracker and adds a server-side OTP login.

## Files

- `index.html` — login page + attendance tracker UI
- `script.js` — attendance logic + OTP login flow
- `style.css` — tracker and login styling
- `server.js` — Express backend, Twilio Verify SMS OTP, session cookie
- `package.json` — Node dependencies
- `.env.example` — environment-variable template
- `.gitignore` — keeps the private `.env` and `node_modules` out of Git

## Setup

1. Install Node.js 18 or newer.
2. Open a terminal in this folder.
3. Run:

   `npm install`

4. Copy `.env.example` to a new file named `.env`.
5. Create a Twilio Verify Service and put these values in `.env`: `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, and `TWILIO_VERIFY_SERVICE_SID`.
6. Create a long random value for `SESSION_SECRET`.
8. Start the app:

   `npm start`

9. Open `http://localhost:3000`.

## Mobile OTP behavior

- Twilio Verify generates and validates the OTP; the application never stores the OTP itself.
- OTP expires after 60 seconds.
- A challenge is limited to 5 verification attempts.
- A new OTP request is rate-limited to once every 30 seconds per client IP.
- Successful verification creates an HttpOnly session cookie.
- Twilio credentials are used only on the server and are never sent to the browser.

## Important

The attendance records remain in browser `localStorage`, just as in the original tracker. The mobile OTP protects access to the web interface, but it does not turn localStorage into a server-side multi-user database.

For a production multi-user system, move attendance records to a database and associate them with the authenticated user.
