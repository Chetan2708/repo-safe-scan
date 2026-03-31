import type { Finding, RiskScore } from "./types";

export function calculateRiskScore(findings: Finding[]): RiskScore {
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lifecycleBonusPoints = 0;
  let newDepBonusPoints = 0;

  for (const f of findings) {
    if (f.rule.severity === "critical") criticalCount++;
    else if (f.rule.severity === "high") highCount++;
    else if (f.rule.severity === "medium") mediumCount++;

    if (f.lifecycle) {
      if (f.rule.severity === "critical") lifecycleBonusPoints += 10;
      else if (f.rule.severity === "high") lifecycleBonusPoints += 10;
      // medium lifecycle doesn't get explicit bonus in the plan, but we can add 0 or adjust if needed.
    }

    if (f.isNewDep) {
      newDepBonusPoints += 5;
    }
  }

  const rawScore = 
    (criticalCount * 25) + 
    (highCount * 10) + 
    (mediumCount * 4) + 
    lifecycleBonusPoints +
    newDepBonusPoints;

  const score = Math.min(rawScore / 10, 10);
  const formattedScore = Number(score.toFixed(1));

  let label: RiskScore["label"] = "CLEAN";
  if (formattedScore > 8.0) label = "CRITICAL";
  else if (formattedScore > 6.0) label = "HIGH";
  else if (formattedScore > 4.0) label = "MODERATE";
  else if (formattedScore > 2.0) label = "LOW";
  else if (formattedScore > 0) label = "LOW"; // Any finding should probably be at least low

  if (formattedScore === 0) label = "CLEAN";

  return {
    score: formattedScore,
    label,
    breakdown: {
      critical: criticalCount,
      high: highCount,
      medium: mediumCount,
      lifecycleBonus: lifecycleBonusPoints,
      newDepBonus: newDepBonusPoints,
    }
  };
}
