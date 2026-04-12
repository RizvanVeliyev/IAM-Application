const { AbacPolicy } = require('../models/index');

async function checkAbacAccess(user, resource, action) {
  const policies = await AbacPolicy.find({ status: 'Active', resource, role: user.role });
  if (!policies.length) return { allowed: true, reason: 'No ABAC policy — RBAC applies' };

  const now = new Date();
  const hour = now.getHours();
  const day = now.getDay();

  for (const policy of policies) {
    if (policy.department && policy.department !== user.department) {
      return { allowed: false, reason: `Department '${user.department}' not allowed for this resource` };
    }
    if (hour < policy.allowedHoursStart || hour > policy.allowedHoursEnd) {
      return { allowed: false, reason: `Access only allowed ${policy.allowedHoursStart}:00–${policy.allowedHoursEnd}:00` };
    }
    if (policy.allowedDays && policy.allowedDays.length && !policy.allowedDays.includes(day)) {
      return { allowed: false, reason: 'Access not allowed today' };
    }
    if (policy.actions && policy.actions.length && !policy.actions.includes(action)) {
      return { allowed: false, reason: `Action '${action}' not permitted by policy` };
    }
  }

  return { allowed: true, reason: 'ABAC policy satisfied' };
}

module.exports = { checkAbacAccess };
