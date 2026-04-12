const express = require('express');
const router = express.Router();
const { AbacPolicy, AuditLog } = require('../models/index');

router.get('/', async (req, res) => {
  const policies = await AbacPolicy.find().sort({ createdAt: -1 });
  res.render('pages/abac', { title: 'ABAC Policies', policies });
});

router.post('/', async (req, res) => {
  const { name, description, role, department, allowedHoursStart, allowedHoursEnd, allowedDays, resource, actions, requireVPN } = req.body;
  await AbacPolicy.create({
    name, description, role, department,
    allowedHoursStart: parseInt(allowedHoursStart) || 0,
    allowedHoursEnd: parseInt(allowedHoursEnd) || 23,
    allowedDays: (allowedDays || []).map(Number),
    resource, actions: Array.isArray(actions) ? actions : [actions],
    requireVPN: !!requireVPN
  });
  await AuditLog.create({ action: 'ABAC policy created', category: 'change', performedBy: req.session.user.name, details: name, ip: req.ip });
  req.flash('success', 'ABAC policy created.');
  res.redirect('/abac');
});

router.post('/:id/toggle', async (req, res) => {
  const policy = await AbacPolicy.findById(req.params.id);
  if (policy) {
    policy.status = policy.status === 'Active' ? 'Inactive' : 'Active';
    await policy.save();
  }
  res.redirect('/abac');
});

router.delete('/:id', async (req, res) => {
  await AbacPolicy.findByIdAndDelete(req.params.id);
  req.flash('success', 'Policy removed.');
  res.redirect('/abac');
});

module.exports = router;
