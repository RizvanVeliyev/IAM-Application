const mongoose = require('mongoose');

const roleSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true, trim: true },
  description: { type: String, default: '' },
  permissions: [{ resource: String, actions: [String] }],
  isSystem: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const abacPolicySchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, default: '' },
  role: { type: String },
  department: { type: String },
  allowedHoursStart: { type: Number, default: 0 },
  allowedHoursEnd: { type: Number, default: 23 },
  allowedDays: [{ type: Number }],
  requireVPN: { type: Boolean, default: false },
  allowedDeviceTypes: [String],
  resource: { type: String, required: true },
  actions: [String],
  status: { type: String, enum: ['Active', 'Inactive'], default: 'Active' },
  createdAt: { type: Date, default: Date.now }
});

const pamRequestSchema = new mongoose.Schema({
  requestedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  requestedByName: String,
  targetRole: { type: String, required: true },
  justification: { type: String, required: true },
  durationHours: { type: Number, default: 1 },
  status: { type: String, enum: ['Pending', 'Approved', 'Denied', 'Expired', 'Revoked'], default: 'Pending' },
  approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  approvedByName: String,
  approvedAt: { type: Date },
  expiresAt: { type: Date },
  sessionLog: [{ timestamp: Date, action: String }],
  createdAt: { type: Date, default: Date.now }
});

const anomalyAlertSchema = new mongoose.Schema({
  type: { type: String, enum: ['login_spike', 'after_hours', 'new_location', 'brute_force', 'privilege_abuse', 'mass_action', 'suspicious_ip'], required: true },
  severity: { type: String, enum: ['Low', 'Medium', 'High', 'Critical'], default: 'Medium' },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  userName: String,
  description: String,
  ip: String,
  resolved: { type: Boolean, default: false },
  resolvedBy: String,
  resolvedAt: Date,
  createdAt: { type: Date, default: Date.now }
});

const lifecycleEventSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  userName: String,
  eventType: { type: String, enum: ['Onboarding', 'Transfer', 'Role Change', 'Offboarding', 'Reactivation'], required: true },
  fromDepartment: String,
  toDepartment: String,
  fromRole: String,
  toRole: String,
  performedBy: String,
  notes: String,
  status: { type: String, enum: ['Pending', 'Completed', 'Cancelled'], default: 'Pending' },
  scheduledAt: Date,
  completedAt: Date,
  createdAt: { type: Date, default: Date.now }
});

const riskSessionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  email: String,
  ip: String,
  userAgent: String,
  deviceType: String,
  riskScore: { type: Number, default: 0 },
  riskFactors: [String],
  mfaRequired: { type: Boolean, default: false },
  mfaCompleted: { type: Boolean, default: false },
  outcome: { type: String, enum: ['Allowed', 'Blocked', 'MFA_Required', 'Pending'], default: 'Pending' },
  createdAt: { type: Date, default: Date.now }
});

const policySchema = new mongoose.Schema({
  name: { type: String, required: true },
  type: { type: String, enum: ['Authentication', 'Authorization', 'Data access', 'Session', 'MFA', 'Risk', 'PAM'], default: 'Authorization' },
  description: { type: String, default: '' },
  status: { type: String, enum: ['Active', 'Inactive', 'Review'], default: 'Active' },
  createdAt: { type: Date, default: Date.now }
});

const auditLogSchema = new mongoose.Schema({
  action: { type: String, required: true },
  category: { type: String, enum: ['login', 'change', 'error', 'delete', 'security', 'pam', 'lifecycle', 'mfa', 'password_policy'], default: 'change' },
  performedBy: { type: String, default: 'System' },
  targetUser: { type: String },
  details: { type: String },
  ip: { type: String },
  riskScore: { type: Number },
  createdAt: { type: Date, default: Date.now }
});

const passwordPolicySchema = new mongoose.Schema({
  name: { type: String, required: true, default: 'Default Policy' },
  minLength: { type: Number, default: 8 },
  requireUppercase: { type: Boolean, default: true },
  requireLowercase: { type: Boolean, default: true },
  requireNumbers: { type: Boolean, default: true },
  requireSpecialChars: { type: Boolean, default: false },
  maxAgeDays: { type: Number, default: 90 },
  maxFailedAttempts: { type: Number, default: 5 },
  lockoutDurationMinutes: { type: Number, default: 15 },
  preventReuseCount: { type: Number, default: 3 },
  enforceFor: { type: String, enum: ['All Users', 'Admins Only', 'Non-Admins'], default: 'All Users' },
  status: { type: String, enum: ['Active', 'Inactive'], default: 'Active' },
  updatedBy: { type: String },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

module.exports = {
  Role: mongoose.model('Role', roleSchema),
  AbacPolicy: mongoose.model('AbacPolicy', abacPolicySchema),
  PAMRequest: mongoose.model('PAMRequest', pamRequestSchema),
  AnomalyAlert: mongoose.model('AnomalyAlert', anomalyAlertSchema),
  LifecycleEvent: mongoose.model('LifecycleEvent', lifecycleEventSchema),
  RiskSession: mongoose.model('RiskSession', riskSessionSchema),
  Policy: mongoose.model('Policy', policySchema),
  AuditLog: mongoose.model('AuditLog', auditLogSchema),
  PasswordPolicy: mongoose.model('PasswordPolicy', passwordPolicySchema)
};
