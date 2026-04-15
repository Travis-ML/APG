// =============================================================================
// APG Example Policy
// =============================================================================
// This is a starting point. Customize for your environment.
// All files in this directory are loaded and evaluated together.
// Cedar uses deny-by-default: if no permit matches, the request is denied.
// Forbid rules override permit rules unconditionally.

// Allow any agent to perform read actions in dev
permit(
  principal,
  action == Action::"toolCall",
  resource
) when {
  context.action_type == "read" &&
  context.environment == "dev"
};

// Allow writes to code files in dev
permit(
  principal,
  action == Action::"toolCall",
  resource
) when {
  context.action_type == "write" &&
  context.environment == "dev" &&
  (
    context.resource_path like "*.py" ||
    context.resource_path like "*.js" ||
    context.resource_path like "*.ts" ||
    context.resource_path like "*.md" ||
    context.resource_path like "*.yaml"
  )
};

// Block shell execution in prod unconditionally
forbid(
  principal,
  action == Action::"toolCall",
  resource
) when {
  context.action_type == "execute" &&
  context.environment == "prod"
};

// Block delete actions everywhere
forbid(
  principal,
  action == Action::"toolCall",
  resource
) when {
  context.action_type == "delete"
};

// Block anything classified as critical risk
forbid(
  principal,
  action == Action::"toolCall",
  resource
) when {
  context.risk_level == "critical"
};
