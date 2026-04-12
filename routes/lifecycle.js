const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { LifecycleEvent, AuditLog, Role } = require('../models/index');

router.get('/', async (req, res) => {
  const events = await LifecycleEvent.find().sort({ createdAt: -1 }).limit(50);
  const users = await User.find().sort({ name: 1 });
  const pending = await LifecycleEvent.countDocuments({ status: 'Pending' });
  const roles = await Role.find();
  res.render('pages/lifecycle', { title: 'Identity Lifecycle', events, users, pending, roles });
});

router.post('/onboard', async (req, res) => {
  const { name, email, department, role, manager } = req.body;
  try {
    const tempPassword = Math.random().toString(36).slice(2, 10) + 'A1!';
    const user = await User.create({
      name, email,
      password: tempPassword,
      department,
      role: role || 'Viewer',
      status: 'Active',
      lifecycleStage: 'Active',
      onboardedAt: new Date(),
      manager: manager || undefined
    });
    await LifecycleEvent.create({
      userId: user._id, userName: user.name, eventType: 'Onboarding',
      toDepartment: department, toRole: role,
      performedBy: req.session.user.name, status: 'Completed', completedAt: new Date(),
      notes: `Auto-provisioned. Temp password: ${tempPassword}`
    });
    await AuditLog.create({ action: 'User onboarded', category: 'lifecycle', performedBy: req.session.user.name, targetUser: user.name, details: `Dept: ${department}, Role: ${role}`, ip: req.ip });
    req.flash('success', `${name} onboarded. Temp password: ${tempPassword}`);
    res.redirect('/lifecycle');
  } catch (err) {
    req.flash('error', err.code === 11000 ? 'Email already exists.' : 'Onboarding failed.');
    res.redirect('/lifecycle');
  }
});

router.post('/transfer', async (req, res) => {
  const { userId, newDepartment, newRole, notes } = req.body;
  const user = await User.findById(userId);
  if (!user) { req.flash('error', 'User not found.'); return res.redirect('/lifecycle'); }

  const evt = await LifecycleEvent.create({
    userId: user._id, userName: user.name, eventType: 'Transfer',
    fromDepartment: user.department, toDepartment: newDepartment,
    fromRole: user.role, toRole: newRole,
    performedBy: req.session.user.name, status: 'Pending', notes,
    scheduledAt: new Date()
  });

  await User.findByIdAndUpdate(userId, { department: newDepartment, role: newRole, lifecycleStage: 'Transfer' });
  evt.status = 'Completed'; evt.completedAt = new Date(); await evt.save();

  await AuditLog.create({ action: 'User transferred', category: 'lifecycle', performedBy: req.session.user.name, targetUser: user.name, details: `${user.department}→${newDepartment}, ${user.role}→${newRole}`, ip: req.ip });
  req.flash('success', `${user.name} transferred to ${newDepartment} as ${newRole}.`);
  res.redirect('/lifecycle');
});

router.post('/offboard', async (req, res) => {
  const { userId, notes } = req.body;
  const user = await User.findById(userId);
  if (!user) { req.flash('error', 'User not found.'); return res.redirect('/lifecycle'); }

  await User.findByIdAndUpdate(userId, {
    status: 'Offboarded', lifecycleStage: 'Offboarded', offboardedAt: new Date(),
    mfaEnabled: false, mfaSecret: null, knownIPs: [], knownDevices: []
  });

  await LifecycleEvent.create({
    userId: user._id, userName: user.name, eventType: 'Offboarding',
    fromDepartment: user.department, fromRole: user.role,
    performedBy: req.session.user.name, status: 'Completed', completedAt: new Date(), notes
  });

  await AuditLog.create({ action: 'User offboarded', category: 'lifecycle', performedBy: req.session.user.name, targetUser: user.name, details: notes || 'Access revoked', ip: req.ip });
  req.flash('success', `${user.name} has been offboarded. All access revoked.`);
  res.redirect('/lifecycle');
});

module.exports = router;
