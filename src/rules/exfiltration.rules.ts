import type { Rule } from "../types";

const exfiltrationRules: Rule[] = [
  {
    id: "ssh-key-access",
    description: "Accessing SSH private keys from ~/.ssh",
    pattern: /~\/\.ssh\/|%USERPROFILE%\\\.ssh\\/i,
    severity: "critical",
    category: "credential-theft",
  },
  {
    id: "aws-credentials",
    description: "Accessing AWS credential files",
    pattern: /~\/\.aws\/credentials|%USERPROFILE%\\\.aws\\/i,
    severity: "critical",
    category: "credential-theft",
  },
  {
    id: "aws-dir-access",
    description: "Accessing broader ~/.aws directory",
    pattern: /~\/\.aws\/|%USERPROFILE%\\\.aws\\/i,
    severity: "critical",
    category: "credential-theft",
  },
  {
    id: "env-exfil",
    description: "Environment variables piped out — potential credential exfiltration",
    pattern: /\benv\b.*\|\s*(curl|wget|nc|ncat)/i,
    severity: "critical",
    category: "credential-theft",
  },
  {
    id: "gitconfig-access",
    description: "Reading git config — may target tokens stored there",
    pattern: /git\s+config\s+--global|~\/\.gitconfig/i,
    severity: "high",
    category: "credential-theft",
  },
  {
    id: "npmrc-access",
    description: "Accessing .npmrc which may contain auth tokens",
    pattern: /~\/\.npmrc|%USERPROFILE%\\\.npmrc/i,
    severity: "high",
    category: "credential-theft",
  },
  {
    id: "dotenv-access",
    description: "Accessing .env file to extract localized secrets",
    pattern: /\b(cat|type|curl|less|head|tail)\s+.*\.env\b/i,
    severity: "high",
    category: "credential-theft",
  },
  {
    id: "npmtoken-env",
    description: "Direct usage of NPM_TOKEN or NODE_AUTH_TOKEN in command",
    pattern: /NPM_TOKEN|NODE_AUTH_TOKEN/,
    severity: "high",
    category: "credential-theft",
  },
  {
    id: "github-token-env",
    description: "Direct usage of GITHUB_TOKEN or GH_TOKEN in command",
    pattern: /GITHUB_TOKEN|GH_TOKEN/,
    severity: "high",
    category: "credential-theft",
  },
];

export default exfiltrationRules;
