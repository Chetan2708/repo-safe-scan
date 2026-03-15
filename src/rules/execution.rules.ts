import type { Rule } from "../types";

const executionRules: Rule[] = [
  {
    id: "curl-pipe-shell",
    description: "Downloads and pipes content directly into a shell",
    pattern: /curl\s+.+\|\s*(ba|z|da|fi)?sh/i,
    severity: "critical",
    category: "remote-execution",
  },
  {
    id: "wget-pipe-shell",
    description: "Downloads and pipes content directly into a shell",
    pattern: /wget\s+.+\|\s*(ba|z|da|fi)?sh/i,
    severity: "critical",
    category: "remote-execution",
  },
  {
    id: "curl-exec",
    description: "curl used to fetch remote content — common dropper pattern",
    pattern: /\bcurl\b/i,
    severity: "high",
    category: "remote-execution",
  },
  {
    id: "wget-exec",
    description: "wget used to download remote content",
    pattern: /\bwget\b/i,
    severity: "high",
    category: "remote-execution",
  },
  {
    id: "invoke-webrequest",
    description: "PowerShell web request — can download payloads",
    pattern: /invoke-webrequest|iwr\b/i,
    severity: "high",
    category: "remote-execution",
  },
  {
    id: "invoke-expression",
    description: "PowerShell Invoke-Expression executes arbitrary strings",
    pattern: /invoke-expression|iex\b/i,
    severity: "critical",
    category: "remote-execution",
  },
  {
    id: "powershell-exec",
    description: "PowerShell launched — often used to bypass execution policy",
    pattern: /\bpowershell(\.exe)?\b/i,
    severity: "high",
    category: "remote-execution",
  },
  {
    id: "inline-node",
    description: "node -e executes an arbitrary inline JavaScript string",
    pattern: /\bnode\s+-e\b/i,
    severity: "high",
    category: "remote-execution",
  },
  {
    id: "inline-python",
    description: "python -c executes an arbitrary inline Python string",
    pattern: /\bpython[23]?\s+-c\b/i,
    severity: "high",
    category: "remote-execution",
  },
  {
    id: "inline-perl",
    description: "perl -e executes arbitrary inline Perl",
    pattern: /\bperl\s+-e\b/i,
    severity: "high",
    category: "remote-execution",
  },
  {
    id: "inline-ruby",
    description: "ruby -e executes arbitrary inline Ruby",
    pattern: /\bruby\s+-e\b/i,
    severity: "high",
    category: "remote-execution",
  },
];

export default executionRules;
