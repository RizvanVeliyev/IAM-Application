const RISK_WEIGHTS = {
  newIP: 25,
  newDevice: 20,
  afterHours: 15,
  failedAttempts: 30,
  weekendLogin: 10,
};

async function computeRiskScore(user, ip, userAgent) {
  const { RiskSession, AnomalyAlert } = require('../models/index');
  let score = 0;
  const factors = [];

  if (!user.knownIPs || !user.knownIPs.includes(ip)) {
    score += RISK_WEIGHTS.newIP;
    factors.push('New IP address');
  }

  const deviceSig = (userAgent || '').slice(0, 100);
  if (!user.knownDevices || !user.knownDevices.includes(deviceSig)) {
    score += RISK_WEIGHTS.newDevice;
    factors.push('Unrecognised device');
  }

  const hour = new Date().getHours();
  if (hour < 8 || hour >= 20) {
    score += RISK_WEIGHTS.afterHours;
    factors.push('After-hours access');
  }

  const day = new Date().getDay();
  if (day === 0 || day === 6) {
    score += RISK_WEIGHTS.weekendLogin;
    factors.push('Weekend login');
  }

  if ((user.failedLoginAttempts || 0) >= 3) {
    score += RISK_WEIGHTS.failedAttempts;
    factors.push('Multiple recent failures');
  }

  score = Math.min(score, 100);

  let outcome = 'Allowed';
  if (score >= 70) outcome = 'Blocked';
  else if (score >= 35) outcome = 'MFA_Required';

  await RiskSession.create({
    userId: user._id,
    email: user.email,
    ip,
    userAgent: deviceSig,
    riskScore: score,
    riskFactors: factors,
    mfaRequired: score >= 35,
    outcome
  });

  if (score >= 50) {
    const severity = score >= 70 ? 'Critical' : 'High';
    await AnomalyAlert.create({
      type: factors.includes('Multiple recent failures') ? 'brute_force' : 'new_location',
      severity,
      userId: user._id,
      userName: user.name,
      description: `Risk score ${score}/100 — ${factors.join(', ')}`,
      ip
    }).catch(() => {});
  }

  return { score, factors, outcome };
}

async function recordSuccessfulDevice(userId, ip, userAgent) {
  const User = require('../models/User');
  const deviceSig = (userAgent || '').slice(0, 100);
  await User.findByIdAndUpdate(userId, {
    $addToSet: { knownIPs: ip, knownDevices: deviceSig },
    $set: { failedLoginAttempts: 0 }
  });
}

module.exports = { computeRiskScore, recordSuccessfulDevice };
