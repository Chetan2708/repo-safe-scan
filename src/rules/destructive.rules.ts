import type { Rule } from "../types";

const destructiveRules: Rule[] = [
  {
    id: "rm-rf",
    description: "Recursive force-delete — can destroy files",
    pattern: /\brm\s+(-\w*f\w*r\w*|-\w*r\w*f\w*)\b|rm\s+--force.*--recursive/i,
    severity: "high",
    category: "destructive",
  },
  {
    id: "windows-del",
    description: "Windows del /f /q — silent recursive delete",
    pattern: /\bdel\s+\/[fqs]/i,
    severity: "high",
    category: "destructive",
  },
  {
    id: "format-disk",
    description: "Disk format command detected",
    pattern: /\bformat\s+[a-z]:\\/i,
    severity: "critical",
    category: "destructive",
  },
  {
    id: "sudo",
    description: "sudo used in an npm script — scripts should not require elevated privileges",
    pattern: /\bsudo\b/i,
    severity: "high",
    category: "privilege-escalation",
  },
  {
    id: "chmod-exec",
    description: "Making files executable after download — dropper pattern",
    pattern: /chmod\s+\+x/i,
    severity: "medium",
    category: "privilege-escalation",
  },
  {
    id: "curl-insecure",
    description: "curl -k / --insecure disables TLS verification",
    pattern: /\bcurl\b.*(\s-k\b|\s--insecure\b)/i,
    severity: "high",
    category: "tls-bypass",
  },
  {
    id: "wget-no-check-cert",
    description: "wget --no-check-certificate disables TLS verification",
    pattern: /\bwget\b.*--no-check-certificate/i,
    severity: "high",
    category: "tls-bypass",
  },
  {
    id: "whoami",
    description: "whoami / id — enumerating the current user",
    pattern: /\b(whoami|id)\b\s*(\||>|;|&&)/i,
    severity: "medium",
    category: "reconnaissance",
  },
  {
    id: "ifconfig-ipconfig",
    description: "Network interface enumeration piped out",
    pattern: /\b(ifconfig|ipconfig)\b.*(curl|wget|nc|ncat)/i,
    severity: "medium",
    category: "reconnaissance",
  },
  {
    id: "child-process",
    description: "child_process.exec/spawn in a script string — shell injection risk",
    pattern: /child_process\.(exec|spawn|execsync|spawnsync)\s*\(/i,
    severity: "high",
    category: "code-execution",
  },
];

export default destructiveRules;
