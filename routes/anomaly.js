const express = require('express');
const router = express.Router();
const { AnomalyAlert, AuditLog, RiskSession } = require('../models/index');
const { runAnomalyDetection } = require('../middleware/anomalyDetector');

router.get('/', async (req, res) => {
  const alerts = await AnomalyAlert.find().sort({ createdAt: -1 }).limit(100);
  const riskSessions = await RiskSession.find().sort({ createdAt: -1 }).limit(20);
  const stats = {
    total: await AnomalyAlert.countDocuments(),
    unresolved: await AnomalyAlert.countDocuments({ resolved: false }),
    critical: await AnomalyAlert.countDocuments({ severity: 'Critical', resolved: false }),
    high: await AnomalyAlert.countDocuments({ severity: 'High', resolved: false }),
  };
  res.render('pages/anomaly', { title: 'Anomaly Detection', alerts, riskSessions, stats });
});

router.post('/scan', async (req, res) => {
  const results = await runAnomalyDetection();
  await AuditLog.create({ action: 'Manual anomaly scan triggered', category: 'security', performedBy: req.session.user.name, details: `Found ${results.length} new anomalies`, ip: req.ip });
  req.flash('success', `Scan complete. ${results.length} new anomalies detected.`);
  res.redirect('/anomaly');
});

router.post('/:id/resolve', async (req, res) => {
  await AnomalyAlert.findByIdAndUpdate(req.params.id, { resolved: true, resolvedBy: req.session.user.name, resolvedAt: new Date() });
  await AuditLog.create({ action: 'Anomaly alert resolved', category: 'security', performedBy: req.session.user.name, ip: req.ip });
  req.flash('success', 'Alert marked as resolved.');
  res.redirect('/anomaly');
});

router.post('/resolve-all', async (req, res) => {
  await AnomalyAlert.updateMany({ resolved: false }, { resolved: true, resolvedBy: req.session.user.name, resolvedAt: new Date() });
  req.flash('success', 'All alerts resolved.');
  res.redirect('/anomaly');
});

router.get('/api/stats', async (req, res) => {
  const last24h = new Date(Date.now() - 86400000);
  const byType = await AnomalyAlert.aggregate([
    { $match: { createdAt: { $gte: last24h } } },
    { $group: { _id: '$type', count: { $sum: 1 } } }
  ]);
  const bySeverity = await AnomalyAlert.aggregate([
    { $match: { resolved: false } },
    { $group: { _id: '$severity', count: { $sum: 1 } } }
  ]);
  res.json({ byType, bySeverity });
});

module.exports = router;
