require('dotenv').config();
const mongoose = require('mongoose');
const User = require('./models/User');
const { Role, Policy, AuditLog, AbacPolicy, AnomalyAlert } = require('./models/index');

mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/iam_db')
  .then(async () => {
    console.log('Connected — seeding v2.0 data...');

    await User.deleteMany({});
    await Role.deleteMany({});
    await Policy.deleteMany({});
    await AbacPolicy.deleteMany({});
    await AuditLog.deleteMany({});
    await AnomalyAlert.deleteMany({});

    // ── Users — use .save() so pre('save') bcrypt hook fires ──────────────
    const userData = [
      { name: 'Alex Owen',    email: 'admin@company.com', password: 'admin123', role: 'Owner',   status: 'Active',    department: 'IT',          knownIPs: ['::1','::ffff:127.0.0.1','127.0.0.1'] },
      { name: 'Sarah Connor', email: 'sarah@company.com', password: 'admin123', role: 'Admin',   status: 'Active',    department: 'IT',          mfaEnabled: false, knownIPs: ['::1','127.0.0.1'] },
      { name: 'John Blake',   email: 'john@company.com',  password: 'pass123',  role: 'Editor',  status: 'Active',    department: 'Marketing',   knownIPs: ['127.0.0.1'] },
      { name: 'Maria Chen',   email: 'maria@company.com', password: 'pass123',  role: 'Manager', status: 'Active',    department: 'Finance',     knownIPs: ['127.0.0.1'] },
      { name: 'Tom Haze',     email: 'tom@company.com',   password: 'pass123',  role: 'Viewer',  status: 'Active',    department: 'HR',          knownIPs: [] },
      { name: 'Lisa Park',    email: 'lisa@company.com',  password: 'pass123',  role: 'Auditor', status: 'Active',    department: 'Legal',       knownIPs: ['127.0.0.1'] },
      { name: 'Dev Ghost',    email: 'ghost@company.com', password: 'pass123',  role: 'Viewer',  status: 'Suspended', department: 'Engineering', knownIPs: [] },
    ];

    for (const data of userData) {
      const user = new User(data);
      await user.save(); // triggers bcrypt hashing
    }
    console.log(`✅ ${userData.length} users created (passwords hashed)`);

    // ── Roles ─────────────────────────────────────────────────────────────
    await Role.insertMany([
      { name: 'Owner',   description: 'Full system control',          isSystem: true,  permissions: [{ resource: '*',       actions: ['read','write','delete','admin'] }] },
      { name: 'Admin',   description: 'User and policy management',   isSystem: true,  permissions: [{ resource: 'users',   actions: ['read','write','delete'] }, { resource: 'roles', actions: ['read','write'] }] },
      { name: 'Manager', description: 'Team and report access',       isSystem: false, permissions: [{ resource: 'reports', actions: ['read','export'] }, { resource: 'users', actions: ['read'] }] },
      { name: 'Editor',  description: 'Content management',           isSystem: false, permissions: [{ resource: 'content', actions: ['read','write'] }] },
      { name: 'Viewer',  description: 'Read-only access',             isSystem: true,  permissions: [{ resource: '*',       actions: ['read'] }] },
      { name: 'Auditor', description: 'Log and audit access',         isSystem: false, permissions: [{ resource: 'logs',    actions: ['read'] }, { resource: 'audit', actions: ['read'] }] },
    ]);

    // ── Policies ──────────────────────────────────────────────────────────
    await Policy.insertMany([
      { name: 'MFA Required for Admins',    type: 'MFA',            description: 'All Admin/Owner accounts must enable MFA',          status: 'Active' },
      { name: 'Risk-Based Step-Up Auth',    type: 'Authentication', description: 'Require MFA when risk score ≥ 35',                  status: 'Active' },
      { name: 'Session Timeout 8h',         type: 'Session',        description: 'Auto-logout after 8 hours of inactivity',           status: 'Active' },
      { name: 'PAM Approval Required',      type: 'Authorization',  description: 'Privilege escalation requires admin approval',      status: 'Active' },
      { name: 'ABAC Finance Hours',         type: 'Authorization',  description: 'Finance dept access 08:00–18:00 weekdays only',     status: 'Active' },
      { name: 'Anomaly Auto-Lock',          type: 'Risk',           description: 'Lock account on score ≥ 70',                       status: 'Active' },
      { name: 'Password Rotation Policy',        type: 'Authentication', description: 'Enforce 90-day password expiry for all users',        status: 'Active' },
    ]);

    // ── ABAC Policies ─────────────────────────────────────────────────────
    await AbacPolicy.insertMany([
      { name: 'Finance Hours Only', role: 'Manager', department: 'Finance', allowedHoursStart: 8, allowedHoursEnd: 18, allowedDays: [1,2,3,4,5], resource: 'reports', actions: ['read','export'], status: 'Active' },
      { name: 'HR Data Access',     role: 'Editor',  department: 'HR',      allowedHoursStart: 9, allowedHoursEnd: 17, allowedDays: [1,2,3,4,5], resource: 'users',   actions: ['read'],          status: 'Active' },
    ]);

    // ── Audit Logs ────────────────────────────────────────────────────────
    await AuditLog.insertMany([
      { action: 'User login',             category: 'login',     performedBy: 'Alex Owen',    details: 'Risk: 0/100',             ip: '127.0.0.1', riskScore: 0 },
      { action: 'User created',           category: 'change',    performedBy: 'Sarah Connor', targetUser: 'Tom Haze',  details: 'Role: Viewer',  ip: '127.0.0.1' },
      { action: 'Failed login attempt',   category: 'error',     performedBy: 'Unknown',      details: 'ghost@company.com',       ip: '10.0.0.99' },
      { action: 'Failed login attempt',   category: 'error',     performedBy: 'Unknown',      details: 'ghost@company.com',       ip: '10.0.0.99' },
      { action: 'Failed login attempt',   category: 'error',     performedBy: 'Unknown',      details: 'ghost@company.com',       ip: '10.0.0.99' },
      { action: 'MFA enabled',            category: 'mfa',       performedBy: 'Maria Chen',   details: 'TOTP configured',         ip: '127.0.0.1' },
      { action: 'PAM request approved',   category: 'pam',       performedBy: 'Sarah Connor', targetUser: 'John Blake', details: 'Admin for 2h', ip: '127.0.0.1' },
      { action: 'User offboarded',        category: 'lifecycle', performedBy: 'Alex Owen',    targetUser: 'Dev Ghost',  details: 'Contractor ended', ip: '127.0.0.1' },
    ]);

    // ── Anomaly Alerts ────────────────────────────────────────────────────
    await AnomalyAlert.insertMany([
      { type: 'brute_force',  severity: 'Critical', description: '6 failed logins from IP 10.0.0.99 in 1 hour',                  ip: '10.0.0.99',      resolved: false },
      { type: 'new_location', severity: 'High',     userName: 'Tom Haze', description: 'Risk score 55/100 — New IP, After-hours', ip: '185.220.101.5',  resolved: false },
      { type: 'after_hours',  severity: 'Medium',   userName: 'John Blake', description: 'Login at 23:00 (outside working hours)', ip: '127.0.0.1',   resolved: true, resolvedBy: 'Sarah Connor', resolvedAt: new Date() },
    ]);

    console.log('✅ All seed data inserted.');
    console.log('');
    console.log('  🔑 Login:  admin@company.com');
    console.log('  🔑 Pass:   admin123');
    console.log('');
    process.exit(0);
  })
  .catch(err => { console.error('Seed error:', err); process.exit(1); });
