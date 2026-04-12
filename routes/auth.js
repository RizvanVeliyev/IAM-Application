const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { AuditLog } = require('../models/index');

function getRiskEngine() {
  try { return require('../middleware/riskEngine'); }
  catch(e) { return null; }
}

router.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.render('pages/login', { title: 'Sign in' });
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const ip = (req.headers['x-forwarded-for'] || req.ip || '127.0.0.1').split(',')[0].trim();
  const ua  = req.headers['user-agent'] || '';

  try {
    const user = await User.findOne({ email: email.toLowerCase().trim() });

    if (!user || !(await user.comparePassword(password))) {
      if (user) {
        await User.findByIdAndUpdate(user._id, { $inc: { failedLoginAttempts: 1 } });
      }
      await AuditLog.create({
        action: 'Failed login attempt', category: 'error',
        performedBy: 'Unknown', details: email, ip
      }).catch(() => {});
      req.flash('error', 'Invalid email or password.');
      return res.redirect('/login');
    }

    if (user.status === 'Suspended' || user.status === 'Offboarded') {
      req.flash('error', `Account is ${user.status.toLowerCase()}.`);
      return res.redirect('/login');
    }

    if (user.lockedUntil && new Date() < user.lockedUntil) {
      req.flash('error', `Account locked until ${user.lockedUntil.toLocaleTimeString()} (too many failed attempts).`);
      return res.redirect('/login');
    }

    let riskScore = 0;
    let riskOutcome = 'Allowed';
    let riskFactors = [];

    const engine = getRiskEngine();
    if (engine) {
      try {
        const result = await engine.computeRiskScore(user, ip, ua);
        riskScore   = result.score;
        riskOutcome = result.outcome;
        riskFactors = result.factors;
      } catch (e) {
        console.warn('Risk engine error (non-fatal):', e.message);
      }
    }

    if (riskOutcome === 'Blocked') {
      await AuditLog.create({
        action: 'Login blocked by risk engine', category: 'security',
        performedBy: user.name, details: `Score: ${riskScore} — ${riskFactors.join(', ')}`,
        ip, riskScore
      }).catch(() => {});
      req.flash('error', `Login blocked — high risk score (${riskScore}/100). Factors: ${riskFactors.join(', ')}.`);
      return res.redirect('/login');
    }

    if (user.mfaEnabled || riskOutcome === 'MFA_Required') {
      req.session.pendingMFA = {
        userId: user._id.toString(),
        riskScore,
        riskFactors,
        ip,
        ua
      };
      return res.redirect('/mfa/verify');
    }

    await finalizeLogin(req, res, user, ip, ua, riskScore);

  } catch (err) {
    console.error('Login error:', err);
    req.flash('error', 'Something went wrong. Please try again.');
    res.redirect('/login');
  }
});

router.get('/mfa/verify', (req, res) => {
  if (!req.session.pendingMFA) return res.redirect('/login');
  const { riskScore, riskFactors } = req.session.pendingMFA;
  res.render('pages/mfa-verify', {
    title: 'Two-Factor Authentication',
    riskScore: riskScore || 0,
    riskFactors: riskFactors || [],
    error: req.flash('error')
  });
});

router.post('/mfa/verify', async (req, res) => {
  if (!req.session.pendingMFA) return res.redirect('/login');
  const { token } = req.body;
  const { userId, ip, ua, riskScore } = req.session.pendingMFA;

  try {
    const user = await User.findById(userId);
    if (!user) return res.redirect('/login');

    if (user.mfaEnabled && user.mfaSecret) {
      let valid = false;
      try {
        const speakeasy = require('speakeasy');
        valid = speakeasy.totp.verify({ secret: user.mfaSecret, encoding: 'base32', token: token.trim(), window: 2 });
      } catch(e) { console.warn('speakeasy error:', e.message); }

      if (!valid) {
        const codeIdx = (user.mfaBackupCodes || []).indexOf(token.trim().toUpperCase());
        if (codeIdx === -1) {
          req.flash('error', 'Invalid verification code. Please try again.');
          return res.redirect('/mfa/verify');
        }
        user.mfaBackupCodes.splice(codeIdx, 1);
        await user.save();
      }
    }

    delete req.session.pendingMFA;
    await AuditLog.create({
      action: 'MFA verified', category: 'mfa',
      performedBy: user.name, details: `Risk was ${riskScore}`, ip
    }).catch(() => {});

    await finalizeLogin(req, res, user, ip, ua, riskScore);

  } catch (err) {
    console.error('MFA error:', err);
    req.flash('error', 'MFA verification failed.');
    res.redirect('/mfa/verify');
  }
});

async function finalizeLogin(req, res, user, ip, ua, riskScore) {
  user.lastLogin = new Date();
  user.failedLoginAttempts = 0;
  await user.save();

  req.session.user = {
    id:         user._id.toString(),
    name:       user.name,
    email:      user.email,
    role:       user.role,
    department: user.department || ''
  };

  const engine = getRiskEngine();
  if (engine) engine.recordSuccessfulDevice(user._id, ip, ua).catch(() => {});

  await AuditLog.create({
    action: 'User login', category: 'login',
    performedBy: user.name,
    details: `Risk: ${riskScore}/100`,
    ip, riskScore
  }).catch(() => {});

  res.redirect('/dashboard');
}

router.post('/logout', (req, res) => {
  const name = req.session.user?.name;
  const ip   = (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();
  if (name) AuditLog.create({ action: 'User logged out', category: 'login', performedBy: name, ip }).catch(() => {});
  req.session.destroy(() => res.redirect('/login'));
});

module.exports = router;
