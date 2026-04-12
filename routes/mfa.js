const express = require('express');
const router = express.Router();
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const User = require('../models/User');
const { AuditLog } = require('../models/index');

router.get('/', async (req, res) => {
  const user = await User.findById(req.session.user.id);
  res.render('pages/mfa', { title: 'MFA Settings', user, qrCode: null, secret: null });
});

router.post('/setup', async (req, res) => {
  const user = await User.findById(req.session.user.id);
  const secret = speakeasy.generateSecret({ name: `AccessIQ (${user.email})`, length: 20 });
  req.session.mfaTempSecret = secret.base32;
  const qrCode = await QRCode.toDataURL(secret.otpauth_url);
  res.render('pages/mfa', { title: 'MFA Settings', user, qrCode, secret: secret.base32 });
});

router.post('/confirm', async (req, res) => {
  const { token } = req.body;
  const secret = req.session.mfaTempSecret;
  if (!secret) { req.flash('error', 'Session expired. Try again.'); return res.redirect('/mfa'); }

  const valid = speakeasy.totp.verify({ secret, encoding: 'base32', token, window: 1 });
  if (!valid) { req.flash('error', 'Invalid code — please try again.'); return res.redirect('/mfa'); }

  const backupCodes = Array.from({ length: 8 }, () =>
    Math.random().toString(36).substring(2, 8).toUpperCase()
  );

  await User.findByIdAndUpdate(req.session.user.id, {
    mfaEnabled: true,
    mfaSecret: secret,
    mfaBackupCodes: backupCodes,
    $addToSet: { mfaMethods: 'totp' }
  });
  delete req.session.mfaTempSecret;

  await AuditLog.create({ action: 'MFA enabled', category: 'mfa', performedBy: req.session.user.name, ip: req.ip });
  req.flash('success', `MFA enabled! Save your backup codes: ${backupCodes.join('  ')}`);
  res.redirect('/mfa');
});

router.post('/disable', async (req, res) => {
  await User.findByIdAndUpdate(req.session.user.id, {
    mfaEnabled: false, mfaSecret: null, mfaBackupCodes: [], mfaMethods: []
  });
  await AuditLog.create({ action: 'MFA disabled', category: 'mfa', performedBy: req.session.user.name, ip: req.ip });
  req.flash('success', 'MFA has been disabled.');
  res.redirect('/mfa');
});

module.exports = router;
