const express = require('express');
const router = express.Router();
const { Role, Policy, AuditLog } = require('../models/index');

router.get('/', async (req, res) => {
  const roles = await Role.find().sort({ createdAt: 1 });
  res.render('pages/roles', { title: 'Roles', roles });
});

router.post('/', async (req, res) => {
  const { name, description } = req.body;
  try {
    await Role.create({ name, description, permissions: [] });
    await AuditLog.create({ action: 'Role created', category: 'change', performedBy: req.session.user.name, details: name, ip: req.ip });
    req.flash('success', 'Role created.');
  } catch { req.flash('error', 'Role name already exists.'); }
  res.redirect('/roles');
});

router.delete('/:id', async (req, res) => {
  const role = await Role.findById(req.params.id);
  if (role?.isSystem) { req.flash('error', 'Cannot delete system role.'); return res.redirect('/roles'); }
  await Role.findByIdAndDelete(req.params.id);
  req.flash('success', 'Role deleted.');
  res.redirect('/roles');
});

module.exports = router;
