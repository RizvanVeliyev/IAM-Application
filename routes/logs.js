const express = require('express');
const router = express.Router();
const { AuditLog } = require('../models/index');

router.get('/', async (req, res) => {
  const { category, search } = req.query;
  const filter = {};
  if (category) filter.category = category;
  if (search) filter.$or = [{ action: new RegExp(search,'i') }, { performedBy: new RegExp(search,'i') }, { targetUser: new RegExp(search,'i') }];
  const logs = await AuditLog.find(filter).sort({ createdAt: -1 }).limit(200);
  res.render('pages/logs', { title: 'Audit Log', logs, category, search });
});

module.exports = router;
