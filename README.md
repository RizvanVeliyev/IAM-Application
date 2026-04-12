# AccessIQ — Identity & Access Management Platform

AccessIQ is a self-hosted IAM dashboard built with Node.js, Express, MongoDB, and EJS. It gives you a central place to manage users, roles, permissions, and security policies for your organisation without depending on third-party identity providers or paying for enterprise SaaS subscriptions.

## What it does

At its core, AccessIQ handles the everyday things an IAM system needs to do — creating users, assigning roles, and tracking what happened and when. On top of that foundation, there are several security layers that make it more than just a CRUD app.

**Risk-Based Authentication** watches each login attempt and calculates a risk score based on things like whether the IP address is new, the time of day, the device, and recent failed attempts. If the score is low, the user goes straight through. If it's medium, they have to complete MFA. If it's high, the login is blocked outright.

**Multi-Factor Authentication** uses TOTP (Google Authenticator, Authy, etc.). Users enrol by scanning a QR code, and the system generates backup codes in case they lose access to their authenticator app.

**Attribute-Based Access Control** lets you define policies that go beyond simple role checks. You can say things like "Managers in Engineering can read reports only on weekdays between 9am and 6pm" and the system enforces that automatically.

**Privileged Access Management** handles temporary role escalation. Users request elevated access, an admin approves it, and access automatically expires after the requested duration. No one has to remember to revoke it manually.

**Identity Lifecycle** covers the full employee journey — onboarding (creates the account and sends a temp password), department transfers, and offboarding (revokes all access, disables MFA, clears known devices).

**AI Anomaly Detection** runs in the background every 15 minutes looking for suspicious patterns like brute-force attempts, unusual login spikes, mass data changes, and after-hours logins. You can also trigger a manual scan whenever you like.

**Password Policy Manager** lets admins define and enforce password rules organisation-wide without needing any external service. Set minimum length, complexity requirements, how often passwords must change, how many failed attempts trigger a lockout, and how long that lockout lasts. Everything is enforced internally — no API keys, no third-party integrations needed.

## Requirements

- Node.js 18 or higher
- MongoDB 6 or higher (running locally or on Atlas)

That's it. No Redis, no external auth providers, no cloud dependencies.

## Getting started

Clone the repo and install dependencies:

```bash
npm install
```

Copy the environment file and adjust if needed:

```bash
cp .env.example .env
```

The defaults in `.env` point to a local MongoDB instance on port 27017. If your database is elsewhere, update `MONGO_URI`.

Seed the database with demo users and sample data:

```bash
node seed.js
```

Start the server:

```bash
node server.js
```

Open your browser at `http://localhost:3000` and sign in with:

- Email: `admin@company.com`
- Password: `admin123`

## Project layout

```
iam-enhanced/
├── models/
│   ├── User.js          User schema with MFA, risk, lifecycle, and PAM fields
│   └── index.js         All other schemas — roles, policies, logs, anomalies, etc.
├── routes/
│   ├── auth.js          Login, logout, MFA verification
│   ├── users.js         User CRUD
│   ├── roles.js         Role management
│   ├── permissions.js   Permission matrix per role
│   ├── abac.js          ABAC policy editor
│   ├── pam.js           Privileged access requests and approvals
│   ├── mfa.js           MFA setup, confirmation, disable
│   ├── lifecycle.js     Onboarding, transfer, offboarding
│   ├── anomaly.js       Anomaly alerts and manual scan
│   ├── password-policy.js  Password rule configuration
│   ├── policies.js      General security policy records
│   ├── logs.js          Audit log viewer
│   └── dashboard.js     Dashboard stats aggregation
├── middleware/
│   ├── riskEngine.js    Risk score computation
│   ├── abacEngine.js    ABAC policy evaluation
│   └── anomalyDetector.js  Background anomaly detection rules
├── views/
│   ├── pages/           One EJS template per page
│   └── partials/        Shared layout and helpers
├── public/              CSS and client-side JS
├── server.js            App entry point and route registration
├── seed.js              Database seeder
└── .env                 Environment configuration
```

## Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MONGO_URI` | MongoDB connection string | `mongodb://localhost:27017/iam_db` |
| `SESSION_SECRET` | Secret used to sign session cookies | `accessiq_v2_secret_2024` |
| `PORT` | Port the server listens on | `3000` |
| `APP_URL` | Base URL of the app (used in emails and links) | `http://localhost:3000` |

Change `SESSION_SECRET` to something long and random before running in production.

## Demo accounts

The seeder creates several accounts so you can test different permission levels straight away:

| Name          | Email               | Password  | Role    | Status    | Department   |
|---------------|---------------------|-----------|---------|-----------|--------------|
| Alex Owen     | admin@company.com   | admin123  | Owner   | Active    | IT           |
| Sarah Connor  | sarah@company.com   | admin123  | Admin   | Active    | IT           |
| John Blake    | john@company.com    | pass123   | Editor  | Active    | Marketing    |
| Maria Chen    | maria@company.com   | pass123   | Manager | Active    | Finance      |
| Tom Haze      | tom@company.com     | pass123   | Viewer  | Active    | HR           |
| Lisa Park     | lisa@company.com    | pass123   | Auditor | Active    | Legal        |
| Dev Ghost     | ghost@company.com   | pass123   | Viewer  | Suspended | Engineering  |

## A note on the risk engine

The first time you log in from a new browser or IP address, the risk engine will flag it as medium risk and force MFA. Once you complete MFA, that device and IP are remembered. Subsequent logins from the same place go straight through unless something else looks suspicious.

This means the admin account will almost always prompt for MFA on a fresh install. That's by design — it's proving the system works. To skip MFA during development, you can temporarily disable the risk engine check in `routes/auth.js` or set a high threshold in `middleware/riskEngine.js`.

## Password Policy

The Password Policy feature lives at `/password-policy` and is accessible to Admins and Owners. It stores one active policy at a time in the database — updating the policy creates a new active record and archives the old one. Every change is logged to the audit trail.

The policy controls minimum password length, which character classes are required, how frequently passwords must change, how many failed login attempts trigger an account lockout, and how long that lockout lasts. Unlike SSO or OAuth integrations, this feature needs no external configuration — it works out of the box.

## Running in production

A few things worth doing before you put this on a real server:

- Set a strong random `SESSION_SECRET`
- Put it behind a reverse proxy (nginx or Caddy) with HTTPS
- Use a proper MongoDB Atlas cluster or a secured self-hosted instance
- Set up log rotation or point your MongoDB audit logs somewhere persistent
- Review the lockout and risk thresholds in `middleware/riskEngine.js` for your threat model

This project is intended as a solid starting point, not a hardened production deployment. The risk engine rules, anomaly thresholds, and ABAC enforcement are all tunable — dig into the middleware files to adjust them for your environment.
