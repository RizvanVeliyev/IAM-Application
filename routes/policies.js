const express = require('express');
const router = express.Router();
const { Policy, AuditLog } = require('../models/index');

router.get('/', async (req, res) => {
  const policies = await Policy.find().sort({ createdAt: -1 });
  res.render('pages/policies', { title: 'Policies', policies });
});

router.post('/', async (req, res) => {
  await Policy.create(req.body);
  await AuditLog.create({ action: 'Policy created', category: 'change', performedBy: req.session.user.name, details: req.body.name, ip: req.ip });
  req.flash('success', 'Policy created.');
  res.redirect('/policies');
});

router.put('/:id/toggle', async (req, res) => {
  const policy = await Policy.findById(req.params.id);
  if (policy) {
    policy.status = policy.status === 'Active' ? 'Inactive' : 'Active';
    await policy.save();
    await AuditLog.create({ action: 'Policy toggled', category: 'change', performedBy: req.session.user.name, details: `${policy.name} → ${policy.status}`, ip: req.ip });
    req.flash('success', `Policy ${policy.status.toLowerCase()}.`);
  }
  res.redirect('/policies');
});

router.delete('/:id', async (req, res) => {
  const p = await Policy.findByIdAndDelete(req.params.id);
  if (p) await AuditLog.create({ action: 'Policy deleted', category: 'delete', performedBy: req.session.user.name, details: p.name, ip: req.ip });
  req.flash('success', 'Policy deleted.');
  res.redirect('/policies');
});

module.exports = router;
