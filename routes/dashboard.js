const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { Role, Policy, AuditLog, AnomalyAlert, PAMRequest, LifecycleEvent } = require('../models/index');

router.get('/', async (req, res) => {
  const [totalUsers, totalRoles, totalPolicies, recentLogs] = await Promise.all([
    User.countDocuments({ status: { $ne: 'Offboarded' } }),
    Role.countDocuments(),
    Policy.countDocuments(),
    AuditLog.find().sort({ createdAt: -1 }).limit(8)
  ]);
  const failedLogins = await AuditLog.countDocuments({ category: 'error', createdAt: { $gte: new Date(Date.now() - 86400000) } });
  const roleCounts = await User.aggregate([{ $group: { _id: '$role', count: { $sum: 1 } } }]);
  const reviewPolicies = await Policy.countDocuments({ status: 'Review' });

  
  const unresolvedAlerts = await AnomalyAlert.countDocuments({ resolved: false });
  const criticalAlerts = await AnomalyAlert.countDocuments({ severity: 'Critical', resolved: false });
  const recentAlerts = await AnomalyAlert.find({ resolved: false }).sort({ createdAt: -1 }).limit(5);

  
  const pamPending = await PAMRequest.countDocuments({ status: 'Pending' });

  
  const pendingOffboard = await User.countDocuments({ lifecycleStage: 'Offboarding' });

  res.render('pages/dashboard', {
    title: 'Dashboard',
    totalUsers, totalRoles, totalPolicies, failedLogins, recentLogs, roleCounts, reviewPolicies,
    unresolvedAlerts, criticalAlerts, recentAlerts, pamPending, pendingOffboard
  });
});

module.exports = router;
