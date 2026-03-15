import type { Rule } from "../types";

/**
 * Security rules for repo-safe-scan.
 *
 * Each rule has:
 *   id          – unique kebab-case identifier
 *   description – human-readable explanation
 *   regex       – RegExp tested against command strings
 *   severity    – 'critical' | 'high' | 'medium'
 *   category    – grouping label for output / filtering
 */
const rules: Rule[] = [
  // ── Remote code execution ────────────────────────────────────────────────
  {
    id: "curl-pipe-shell",
    description: "Downloads and pipes content directly into a shell",
    regex: /curl\s+.+\|\s*(ba|z|da|fi)?sh/i,
    severity: "critical",
    category: "remote-execution",
  },
  {
    id: "wget-pipe-shell",
    description: "Downloads and pipes content directly into a shell",
    regex: /wget\s+.+\|\s*(ba|z|da|fi)?sh/i,
    severity: "critical",
    category: "remote-execution",
  },
  {
    id: "curl-exec",
    description: "curl used to fetch remote content — common dropper pattern",
    regex: /\bcurl\b/i,
    severity: "high",
    category: "remote-execution",
  },
  {
    id: "wget-exec",
    description: "wget used to download remote content",
    regex: /\bwget\b/i,
    severity: "high",
    category: "remote-execution",
  },
  {
    id: "invoke-webrequest",
    description: "PowerShell web request — can download payloads",
    regex: /Invoke-WebRequest|iwr\b/i,
    severity: "high",
    category: "remote-execution",
  },
  {
    id: "invoke-expression",
    description: "PowerShell Invoke-Expression executes arbitrary strings",
    regex: /Invoke-Expression|iex\b/i,
    severity: "critical",
    category: "remote-execution",
  },
  {
    id: "powershell-exec",
    description: "PowerShell launched — often used to bypass execution policy",
    regex: /\bpowershell(\.exe)?\b/i,
    severity: "high",
    category: "remote-execution",
  },
  {
    id: "inline-node",
    description: "node -e executes an arbitrary inline JavaScript string",
    regex: /\bnode\s+-e\b/i,
    severity: "high",
    category: "remote-execution",
  },
  {
    id: "inline-python",
    description: "python -c executes an arbitrary inline Python string",
    regex: /\bpython[23]?\s+-c\b/i,
    severity: "high",
    category: "remote-execution",
  },
  {
    id: "inline-perl",
    description: "perl -e executes arbitrary inline Perl",
    regex: /\bperl\s+-e\b/i,
    severity: "high",
    category: "remote-execution",
  },
  {
    id: "inline-ruby",
    description: "ruby -e executes arbitrary inline Ruby",
    regex: /\bruby\s+-e\b/i,
    severity: "high",
    category: "remote-execution",
  },

  // ── Obfuscation ──────────────────────────────────────────────────────────
  {
    id: "base64-decode",
    description: "Base64 decoding — classic payload obfuscation technique",
    regex: /base64\s+-d|base64\s+--decode|atob\s*\(/i,
    severity: "high",
    category: "obfuscation",
  },
  {
    id: "eval-usage",
    description: "eval() executes arbitrary strings — dangerous obfuscation vector",
    regex: /\beval\s*\(/,
    severity: "critical",
    category: "obfuscation",
  },
  {
    id: "function-constructor",
    description: "new Function() is equivalent to eval",
    regex: /new\s+Function\s*\(/,
    severity: "critical",
    category: "obfuscation",
  },
  {
    id: "fromcharcode",
    description: "String.fromCharCode used to build strings — payload hiding technique",
    regex: /fromCharCode\s*\(/i,
    severity: "high",
    category: "obfuscation",
  },
  {
    id: "hex-encoded-exec",
    description: "\\x-encoded string passed to shell — obfuscation of commands",
    regex: /\\x[0-9a-f]{2}/i,
    severity: "medium",
    category: "obfuscation",
  },

  // ── Reverse shells ───────────────────────────────────────────────────────
  {
    id: "netcat",
    description: "netcat / ncat / nc used — common reverse shell utility",
    regex: /\b(netcat|ncat|nc)\s+-/i,
    severity: "critical",
    category: "reverse-shell",
  },
  {
    id: "socat",
    description: "socat can create reverse shell tunnels",
    regex: /\bsocat\b/i,
    severity: "high",
    category: "reverse-shell",
  },
  {
    id: "bash-tcp",
    description: "bash /dev/tcp reverse shell technique",
    regex: /\/dev\/tcp\//i,
    severity: "critical",
    category: "reverse-shell",
  },
  {
    id: "ssh-remote",
    description: "SSH with -R (remote forwarding) can exfiltrate data or create tunnels",
    regex: /\bssh\b.*-R\b/i,
    severity: "high",
    category: "reverse-shell",
  },

  // ── Credential / secret theft ────────────────────────────────────────────
  {
    id: "ssh-key-access",
    description: "Accessing SSH private keys from ~/.ssh",
    regex: /~\/\.ssh\/|%USERPROFILE%\\\.ssh\\/i,
    severity: "critical",
    category: "credential-theft",
  },
  {
    id: "aws-credentials",
    description: "Accessing AWS credential files",
    regex: /~\/\.aws\/credentials|%USERPROFILE%\\\.aws\\/i,
    severity: "critical",
    category: "credential-theft",
  },
  {
    id: "env-exfil",
    description: "Environment variables piped out — potential credential exfiltration",
    regex: /\benv\b.*\|\s*(curl|wget|nc|ncat)/i,
    severity: "critical",
    category: "credential-theft",
  },
  {
    id: "git-config-email",
    description: "Reading git global config — may target tokens stored there",
    regex: /git\s+config\s+--global/i,
    severity: "medium",
    category: "credential-theft",
  },
  {
    id: "npmrc-access",
    description: "Accessing .npmrc which may contain auth tokens",
    regex: /~\/\.npmrc|%USERPROFILE%\\\.npmrc/i,
    severity: "high",
    category: "credential-theft",
  },

  // ── Destructive commands ─────────────────────────────────────────────────
  {
    id: "rm-rf",
    description: "Recursive force-delete — can destroy files",
    regex: /\brm\s+(-\w*f\w*r\w*|-\w*r\w*f\w*)\b|rm\s+--force.*--recursive/i,
    severity: "high",
    category: "destructive",
  },
  {
    id: "windows-del",
    description: "Windows del /f /q — silent recursive delete",
    regex: /\bdel\s+\/[fqs]/i,
    severity: "high",
    category: "destructive",
  },
  {
    id: "format-disk",
    description: "Disk format command detected",
    regex: /\bformat\s+[a-z]:\\/i,
    severity: "critical",
    category: "destructive",
  },

  // ── Privilege escalation ─────────────────────────────────────────────────
  {
    id: "sudo",
    description: "sudo used in an npm script — scripts should not require elevated privileges",
    regex: /\bsudo\b/i,
    severity: "high",
    category: "privilege-escalation",
  },
  {
    id: "chmod-exec",
    description: "Making files executable after download — dropper pattern",
    regex: /chmod\s+\+x/i,
    severity: "medium",
    category: "privilege-escalation",
  },

  // ── TLS bypass ───────────────────────────────────────────────────────────
  {
    id: "curl-insecure",
    description: "curl -k / --insecure disables TLS verification",
    regex: /\bcurl\b.*(\s-k\b|\s--insecure\b)/i,
    severity: "high",
    category: "tls-bypass",
  },
  {
    id: "wget-no-check-cert",
    description: "wget --no-check-certificate disables TLS verification",
    regex: /\bwget\b.*--no-check-certificate/i,
    severity: "high",
    category: "tls-bypass",
  },

  // ── System info gathering ────────────────────────────────────────────────
  {
    id: "whoami",
    description: "whoami / id — enumerating the current user",
    regex: /\b(whoami|id)\b\s*(\||>|;|&&)/i,
    severity: "medium",
    category: "reconnaissance",
  },
  {
    id: "ifconfig-ipconfig",
    description: "Network interface enumeration piped out",
    regex: /\b(ifconfig|ipconfig)\b.*(curl|wget|nc|ncat)/i,
    severity: "medium",
    category: "reconnaissance",
  },

  // ── child_process (JS-specific) ──────────────────────────────────────────
  {
    id: "child-process",
    description: "child_process.exec/spawn in a script string — shell injection risk",
    regex: /child_process\.(exec|spawn|execSync|spawnSync)\s*\(/,
    severity: "high",
    category: "code-execution",
  },
];

export default rules;
