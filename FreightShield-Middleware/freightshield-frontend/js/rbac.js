// UI-side RBAC: only hides/disables things. The BACKEND must enforce every permission (least privilege).
export const ROLES = {
  admin:   ["view_alerts", "view_agents", "manage_incidents", "use_ai", "manage_users"],
  analyst: ["view_alerts", "view_agents", "manage_incidents", "use_ai"],
  viewer:  ["view_alerts", "view_agents"],
};
export const can = (user, perm) => !!user && (ROLES[user.role] || []).includes(perm);
