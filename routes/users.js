const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { AuditLog, PasswordPolicy } = require('../models/index');

function validatePasswordAgainstPolicy(password, policy, role) {
  if (!policy) return [];

  let applies = true;
  if (policy.enforceFor === 'Admins Only' && !['Admin', 'Owner'].includes(role)) applies = false;
  if (policy.enforceFor === 'Non-Admins' && ['Admin', 'Owner'].includes(role)) applies = false;
  if (!applies) return [];

  const errors = [];
  if (password.length < policy.minLength) errors.push(`at least ${policy.minLength} characters`);
  if (policy.requireUppercase && !/[A-Z]/.test(password)) errors.push('at least one uppercase letter');
  if (policy.requireLowercase && !/[a-z]/.test(password)) errors.push('at least one lowercase letter');
  if (policy.requireNumbers && !/[0-9]/.test(password)) errors.push('at least one number');
  if (policy.requireSpecialChars && !/[^a-zA-Z0-9]/.test(password)) errors.push('at least one special character');
  return errors;
}

router.get('/', async (req, res) => {
  const { search, role, status } = req.query;
  const filter = {};
  if (search) filter.$or = [{ name: new RegExp(search, 'i') }, { email: new RegExp(search, 'i') }];
  if (role) filter.role = role;
  if (status) filter.status = status;
  const users = await User.find(filter).sort({ createdAt: -1 });
  res.render('pages/users', { title: 'Users', users, search, role, status });
});

router.get('/new', (req, res) => res.render('pages/user-form', { title: 'Add User', user: null }));

router.post('/', async (req, res) => {
  try {
    const { password, role } = req.body;

    const policy = await PasswordPolicy.findOne({ status: 'Active' });
    const policyErrors = validatePasswordAgainstPolicy(password, policy, role);

    if (policyErrors.length > 0) {
      req.flash('error', 'Password must contain: ' + policyErrors.join(', ') + '.');
      return res.redirect('/users/new');
    }

    const user = await User.create(req.body);

    await AuditLog.create({
      action: 'User created',
      category: 'change',
      performedBy: req.session.user.name,
      targetUser: user.name,
      details: 'Role: ' + user.role,
      ip: req.ip
    });

    req.flash('success', 'User created successfully.');
    res.redirect('/users');
  } catch (err) {
    req.flash('error', err.code === 11000 ? 'Email already exists.' : 'Error creating user.');
    res.redirect('/users/new');
  }
});

router.get('/:id/edit', async (req, res) => {
  const user = await User.findById(req.params.id);
  if (!user) { req.flash('error', 'User not found.'); return res.redirect('/users'); }
  res.render('pages/user-form', { title: 'Edit User', user });
});

router.put('/:id', async (req, res) => {
  const { name, email, role, status } = req.body;
  const user = await User.findByIdAndUpdate(req.params.id, { name, email, role, status }, { new: true });
  await AuditLog.create({
    action: 'User updated',
    category: 'change',
    performedBy: req.session.user.name,
    targetUser: user.name,
    details: 'Role: ' + role + ', Status: ' + status,
    ip: req.ip
  });
  req.flash('success', 'User updated.');
  res.redirect('/users');
});

router.delete('/:id', async (req, res) => {
  const user = await User.findByIdAndDelete(req.params.id);
  if (user) await AuditLog.create({
    action: 'User deleted',
    category: 'delete',
    performedBy: req.session.user.name,
    targetUser: user.name,
    ip: req.ip
  });
  req.flash('success', 'User removed.');
  res.redirect('/users');
});

module.exports = router;
