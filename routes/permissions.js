const express = require('express');
const router = express.Router();
const { Role, AuditLog } = require('../models/index');

const RESOURCES = ['Users', 'Roles', 'Logs', 'Reports', 'Settings'];
const ACTIONS = ['read', 'create', 'edit', 'delete', 'export'];

router.get('/', async (req, res) => {
  const roles = await Role.find().sort({ createdAt: 1 });
  res.render('pages/permissions', { title: 'Permissions', roles, RESOURCES, ACTIONS });
});

router.post('/:roleId', async (req, res) => {
  const role = await Role.findById(req.params.roleId);
  if (!role) return res.redirect('/permissions');
  const permissions = RESOURCES.map(resource => ({
    resource,
    actions: ACTIONS.filter(action => req.body[`${resource}_${action}`] === 'on')
  }));
  role.permissions = permissions;
  await role.save();
  await AuditLog.create({ action: 'Permissions updated', category: 'change', performedBy: req.session.user.name, details: `Role: ${role.name}`, ip: req.ip });
  req.flash('success', `Permissions updated for ${role.name}.`);
  res.redirect('/permissions');
});

module.exports = router;
