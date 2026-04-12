const { AuditLog, AnomalyAlert, RiskSession } = require('../models/index');
const User = require('../models/User');

async function runAnomalyDetection() {
  const results = [];
  const windowMs = 60 * 60 * 1000;
  const since = new Date(Date.now() - windowMs);

  const failedByIP = await AuditLog.aggregate([
    { $match: { category: 'error', action: /Failed login/i, createdAt: { $gte: since } } },
    { $group: { _id: '$ip', count: { $sum: 1 } } },
    { $match: { count: { $gte: 5 } } }
  ]);
  for (const { _id: ip, count } of failedByIP) {
    const existing = await AnomalyAlert.findOne({ type: 'brute_force', ip, resolved: false, createdAt: { $gte: since } });
    if (!existing) {
      await AnomalyAlert.create({ type: 'brute_force', severity: 'Critical', description: `${count} failed logins from IP ${ip}`, ip });
      results.push({ type: 'brute_force', ip });
    }
  }

  const loginSpike = await AuditLog.aggregate([
    { $match: { category: 'login', action: 'User login', createdAt: { $gte: since } } },
    { $group: { _id: '$performedBy', count: { $sum: 1 } } },
    { $match: { count: { $gte: 5 } } }
  ]);
  for (const { _id: name, count } of loginSpike) {
    const existing = await AnomalyAlert.findOne({ type: 'login_spike', userName: name, resolved: false, createdAt: { $gte: since } });
    if (!existing) {
      await AnomalyAlert.create({ type: 'login_spike', severity: 'High', userName: name, description: `${name} logged in ${count} times in 1 hour` });
      results.push({ type: 'login_spike', name });
    }
  }

  const massAction = await AuditLog.aggregate([
    { $match: { category: { $in: ['delete', 'change'] }, createdAt: { $gte: since } } },
    { $group: { _id: '$performedBy', count: { $sum: 1 } } },
    { $match: { count: { $gte: 10 } } }
  ]);
  for (const { _id: name, count } of massAction) {
    const existing = await AnomalyAlert.findOne({ type: 'mass_action', userName: name, resolved: false, createdAt: { $gte: since } });
    if (!existing) {
      await AnomalyAlert.create({ type: 'mass_action', severity: 'High', userName: name, description: `${name} performed ${count} changes in 1 hour` });
      results.push({ type: 'mass_action', name });
    }
  }

  const hour = new Date().getHours();
  if (hour < 6 || hour >= 22) {
    const recentLogins = await AuditLog.find({ category: 'login', createdAt: { $gte: new Date(Date.now() - 15 * 60 * 1000) } });
    for (const log of recentLogins) {
      const existing = await AnomalyAlert.findOne({ type: 'after_hours', userName: log.performedBy, resolved: false, createdAt: { $gte: new Date(Date.now() - 15 * 60 * 1000) } });
      if (!existing) {
        await AnomalyAlert.create({ type: 'after_hours', severity: 'Medium', userName: log.performedBy, ip: log.ip, description: `Login at ${new Date().getHours()}:00 (outside working hours)` });
        results.push({ type: 'after_hours', name: log.performedBy });
      }
    }
  }

  return results;
}

module.exports = { runAnomalyDetection };
