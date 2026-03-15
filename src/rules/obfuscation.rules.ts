import type { Rule } from "../types";

const obfuscationRules: Rule[] = [
  {
    id: "base64-decode",
    description: "Base64 decoding — classic payload obfuscation technique",
    pattern: /base64\s+-d|base64\s+--decode|atob\s*\(/i,
    severity: "high",
    category: "obfuscation",
  },
  {
    id: "eval-usage",
    description: "eval() executes arbitrary strings — dangerous obfuscation vector",
    pattern: /\beval\s*\(/,
    severity: "critical",
    category: "obfuscation",
  },
  {
    id: "function-constructor",
    description: "new Function() is equivalent to eval",
    pattern: /new\s+function\s*\(/i,
    severity: "critical",
    category: "obfuscation",
  },
  {
    id: "fromcharcode",
    description: "String.fromCharCode used to build strings — payload hiding technique",
    pattern: /fromcharcode\s*\(/i,
    severity: "high",
    category: "obfuscation",
  },
  {
    id: "hex-encoded-exec",
    description: "\\x-encoded string passed to shell — obfuscation of commands",
    pattern: /\\x[0-9a-f]{2}/i,
    severity: "medium",
    category: "obfuscation",
  },
  {
    id: "netcat",
    description: "netcat / ncat / nc used — common reverse shell utility",
    pattern: /\b(netcat|ncat|nc)\s+-/i,
    severity: "critical",
    category: "reverse-shell",
  },
  {
    id: "socat",
    description: "socat can create reverse shell tunnels",
    pattern: /\bsocat\b/i,
    severity: "high",
    category: "reverse-shell",
  },
  {
    id: "bash-tcp",
    description: "bash /dev/tcp reverse shell technique",
    pattern: /\/dev\/tcp\//i,
    severity: "critical",
    category: "reverse-shell",
  },
  {
    id: "ssh-remote",
    description: "SSH with -R (remote forwarding) can exfiltrate data or create tunnels",
    pattern: /\bssh\b.*-r\b/i,
    severity: "high",
    category: "reverse-shell",
  },
];

export default obfuscationRules;
