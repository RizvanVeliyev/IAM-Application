const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['Owner', 'Admin', 'Manager', 'Editor', 'Viewer', 'Auditor'], default: 'Viewer' },
  status: { type: String, enum: ['Active', 'Inactive', 'Suspended', 'Pending', 'Offboarded'], default: 'Active' },

  department: { type: String, default: 'General' },
  location: { type: String, default: 'Office' },
  employeeType: { type: String, enum: ['Full-time', 'Contractor', 'Intern', 'External'], default: 'Full-time' },

  mfaEnabled: { type: Boolean, default: false },
  mfaSecret: { type: String },
  mfaBackupCodes: [String],
  mfaMethods: [{ type: String, enum: ['totp', 'email', 'sms'] }],

  knownIPs: [String],
  knownDevices: [String],
  riskScore: { type: Number, default: 0 },
  lockedUntil: { type: Date },
  failedLoginAttempts: { type: Number, default: 0 },

  onboardedAt: { type: Date },
  offboardedAt: { type: Date },
  lifecycleStage: { type: String, enum: ['Pending', 'Active', 'Transfer', 'Offboarding', 'Offboarded'], default: 'Active' },
  manager: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },

  privilegedUntil: { type: Date },
  privilegedRole: { type: String },
  baseRole: { type: String },

  passwordChangedAt: { type: Date },
  mustChangePassword: { type: Boolean, default: false },

  lastLogin: { type: Date },
  createdAt: { type: Date, default: Date.now }
});

userSchema.pre('save', async function () {
  if (!this.isModified('password')) return;
  this.password = await bcrypt.hash(this.password, 10);
  this.passwordChangedAt = new Date();
});

userSchema.methods.comparePassword = function (plain) {
  return bcrypt.compare(plain, this.password);
};

module.exports = mongoose.model('User', userSchema);
