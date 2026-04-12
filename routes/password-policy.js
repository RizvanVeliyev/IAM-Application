const express = require('express');
const router = express.Router();
const { PasswordPolicy, AuditLog } = require('../models/index');

router.get('/', async (req, res) => {
  let policy = await PasswordPolicy.findOne({ status: 'Active' });
  if (!policy) {
    policy = await PasswordPolicy.create({ updatedBy: 'System' });
  }
  const history = await AuditLog.find({ category: 'password_policy' }).sort({ createdAt: -1 }).limit(10);
  res.render('pages/password-policy', { title: 'Password Policy', policy, history });
});

router.post('/update', async (req, res) => {
  const {
    minLength, requireUppercase, requireLowercase, requireNumbers,
    requireSpecialChars, maxAgeDays, maxFailedAttempts,
    lockoutDurationMinutes, preventReuseCount, enforceFor
  } = req.body;

  await PasswordPolicy.updateMany({}, { status: 'Inactive' });

  await PasswordPolicy.create({
    minLength: parseInt(minLength) || 8,
    requireUppercase: !!requireUppercase,
    requireLowercase: !!requireLowercase,
    requireNumbers: !!requireNumbers,
    requireSpecialChars: !!requireSpecialChars,
    maxAgeDays: parseInt(maxAgeDays) || 90,
    maxFailedAttempts: parseInt(maxFailedAttempts) || 5,
    lockoutDurationMinutes: parseInt(lockoutDurationMinutes) || 15,
    preventReuseCount: parseInt(preventReuseCount) || 3,
    enforceFor: enforceFor || 'All Users',
    status: 'Active',
    updatedBy: req.session.user.name,
    updatedAt: new Date()
  });

  await AuditLog.create({
    action: 'Password policy updated',
    category: 'password_policy',
    performedBy: req.session.user.name,
    details: `Min length: ${minLength}, Max age: ${maxAgeDays} days, Lockout after: ${maxFailedAttempts} attempts`,
    ip: req.ip
  });

  req.flash('success', 'Password policy saved and now active.');
  res.redirect('/password-policy');
});

router.post('/reset', async (req, res) => {
  await PasswordPolicy.updateMany({}, { status: 'Inactive' });
  await PasswordPolicy.create({
    name: 'Default Policy',
    updatedBy: req.session.user.name,
    status: 'Active'
  });

  await AuditLog.create({
    action: 'Password policy reset to defaults',
    category: 'password_policy',
    performedBy: req.session.user.name,
    ip: req.ip
  });

  req.flash('success', 'Password policy reset to defaults.');
  res.redirect('/password-policy');
});

module.exports = router;
