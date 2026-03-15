import type { Rule } from "../types";
import executionRules from "./execution.rules";
import exfiltrationRules from "./exfiltration.rules";
import obfuscationRules from "./obfuscation.rules";
import destructiveRules from "./destructive.rules";

const rules: Rule[] = [
  ...executionRules,
  ...exfiltrationRules,
  ...obfuscationRules,
  ...destructiveRules,
];

export default rules;
