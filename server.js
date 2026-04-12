require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const flash = require('connect-flash');
const methodOverride = require('method-override');
const path = require('path');
const cron = require('node-cron');

const app = express();

mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/iam_db')
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('MongoDB error:', err));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(methodOverride('_method'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'iam_secret_key_2024',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 8 }
}));
app.use(flash());

app.use((req, res, next) => {
  res.locals.success = req.flash('success');
  res.locals.error = req.flash('error');
  res.locals.currentUser = req.session.user || null;
  next();
});

const requireAuth = (req, res, next) => {
  if (!req.session.user) return res.redirect('/login');
  const user = req.session.user;
  if (user.privilegedUntil && new Date() > new Date(user.privilegedUntil)) {
    const User = require('./models/User');
    User.findByIdAndUpdate(user.id, { role: user.baseRole || 'Viewer', $unset: { privilegedRole: 1, privilegedUntil: 1, baseRole: 1 } }).catch(() => {});
    req.session.user.role = user.baseRole || 'Viewer';
  }
  next();
};

const requireAdmin = (req, res, next) => {
  if (!req.session.user) return res.redirect('/login');
  if (!['Admin', 'Owner'].includes(req.session.user.role)) {
    req.flash('error', 'Admin access required.');
    return res.redirect('/dashboard');
  }
  next();
};

app.locals.requireAuth = requireAuth;
app.locals.requireAdmin = requireAdmin;

app.use('/', require('./routes/auth'));
app.use('/dashboard', requireAuth, require('./routes/dashboard'));
app.use('/users', requireAuth, requireAdmin, require('./routes/users'));
app.use('/roles', requireAuth, requireAdmin, require('./routes/roles'));
app.use('/permissions', requireAuth, requireAdmin, require('./routes/permissions'));
app.use('/policies', requireAuth, requireAdmin, require('./routes/policies'));
app.use('/logs', requireAuth, require('./routes/logs'));
app.use('/mfa', requireAuth, require('./routes/mfa'));
app.use('/abac', requireAuth, requireAdmin, require('./routes/abac'));
app.use('/lifecycle', requireAuth, requireAdmin, require('./routes/lifecycle'));
app.use('/pam', requireAuth, require('./routes/pam'));
app.use('/anomaly', requireAuth, requireAdmin, require('./routes/anomaly'));
app.use('/password-policy', requireAuth, requireAdmin, require('./routes/password-policy'));

cron.schedule('*/15 * * * *', async () => {
  const { runAnomalyDetection } = require('./middleware/anomalyDetector');
  const results = await runAnomalyDetection().catch(() => []);
  if (results.length) console.log(`🚨 ${results.length} new anomalies detected`);
});

cron.schedule('*/5 * * * *', async () => {
  const { PAMRequest } = require('./models/index');
  const User = require('./models/User');
  const expired = await PAMRequest.find({ status: 'Approved', expiresAt: { $lt: new Date() } });
  for (const r of expired) {
    const user = await User.findById(r.requestedBy);
    if (user) await User.findByIdAndUpdate(user._id, { role: user.baseRole || 'Viewer', $unset: { privilegedRole: 1, privilegedUntil: 1, baseRole: 1 } });
    r.status = 'Expired'; await r.save();
    console.log(`⏰ PAM expired for ${r.requestedByName}`);
  }
});

app.get('/', (req, res) => res.redirect(req.session.user ? '/dashboard' : '/login'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 AccessIQ running at http://localhost:${PORT}`));
