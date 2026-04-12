const express = require('express');
const router = express.Router();
const { PAMRequest, AuditLog } = require('../models/index');
const User = require('../models/User');

router.get('/', async (req, res) => {
  const isAdmin = ['Admin', 'Owner'].includes(req.session.user.role);
  const filter = isAdmin ? {} : { requestedBy: req.session.user.id };
  const requests = await PAMRequest.find(filter).populate('requestedBy', 'name email').sort({ createdAt: -1 });
  const now = new Date();
  for (const r of requests) {
    if (r.status === 'Approved' && r.expiresAt && r.expiresAt < now) {
      r.status = 'Expired';
      await r.save();
      await User.findByIdAndUpdate(r.requestedBy, { role: '$baseRole' });
    }
  }
  res.render('pages/pam', { title: 'Privileged Access', requests, isAdmin });
});

router.post('/request', async (req, res) => {
  const { targetRole, justification, durationHours } = req.body;
  await PAMRequest.create({
    requestedBy: req.session.user.id,
    requestedByName: req.session.user.name,
    targetRole,
    justification,
    durationHours: parseInt(durationHours) || 1
  });
  await AuditLog.create({ action: 'PAM request submitted', category: 'pam', performedBy: req.session.user.name, details: `Requested: ${targetRole} for ${durationHours}h`, ip: req.ip });
  req.flash('success', 'Privilege escalation request submitted for approval.');
  res.redirect('/pam');
});

router.post('/:id/approve', async (req, res) => {
  if (!['Admin', 'Owner'].includes(req.session.user.role)) {
    req.flash('error', 'Admin access required.'); return res.redirect('/pam');
  }
  const pamReq = await PAMRequest.findById(req.params.id);
  if (!pamReq) { req.flash('error', 'Request not found.'); return res.redirect('/pam'); }

  const expiresAt = new Date(Date.now() + pamReq.durationHours * 3600000);
  pamReq.status = 'Approved';
  pamReq.approvedBy = req.session.user.id;
  pamReq.approvedByName = req.session.user.name;
  pamReq.approvedAt = new Date();
  pamReq.expiresAt = expiresAt;
  await pamReq.save();

  const targetUser = await User.findById(pamReq.requestedBy);
  await User.findByIdAndUpdate(pamReq.requestedBy, {
    baseRole: targetUser.role,
    role: pamReq.targetRole,
    privilegedRole: pamReq.targetRole,
    privilegedUntil: expiresAt
  });

  await AuditLog.create({ action: 'PAM request approved', category: 'pam', performedBy: req.session.user.name, targetUser: pamReq.requestedByName, details: `${pamReq.targetRole} until ${expiresAt.toLocaleString()}`, ip: req.ip });
  req.flash('success', `Approved. ${pamReq.requestedByName} now has ${pamReq.targetRole} until ${expiresAt.toLocaleTimeString()}.`);
  res.redirect('/pam');
});

router.post('/:id/deny', async (req, res) => {
  if (!['Admin', 'Owner'].includes(req.session.user.role)) {
    req.flash('error', 'Admin access required.'); return res.redirect('/pam');
  }
  await PAMRequest.findByIdAndUpdate(req.params.id, { status: 'Denied', approvedByName: req.session.user.name, approvedAt: new Date() });
  await AuditLog.create({ action: 'PAM request denied', category: 'pam', performedBy: req.session.user.name, ip: req.ip });
  req.flash('success', 'Request denied.');
  res.redirect('/pam');
});

router.post('/:id/revoke', async (req, res) => {
  if (!['Admin', 'Owner'].includes(req.session.user.role)) {
    req.flash('error', 'Admin access required.'); return res.redirect('/pam');
  }
  const pamReq = await PAMRequest.findByIdAndUpdate(req.params.id, { status: 'Revoked' }, { new: true });
  if (pamReq) {
    const user = await User.findById(pamReq.requestedBy);
    if (user) await User.findByIdAndUpdate(user._id, { role: user.baseRole || 'Viewer', $unset: { privilegedRole: 1, privilegedUntil: 1, baseRole: 1 } });
  }
  await AuditLog.create({ action: 'PAM access revoked', category: 'pam', performedBy: req.session.user.name, ip: req.ip });
  req.flash('success', 'Privileged access revoked.');
  res.redirect('/pam');
});

module.exports = router;
