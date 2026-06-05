// IOC extractor for SOC Copilot chat responses.
// Detects security artifacts in plain text / HTML and wraps them in
// <span data-ioc="..." data-ioc-type="..."> elements.

const PRIVATE_CIDR = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0$|::1$|fe80:)/i;

const PATTERNS: { type: string; re: RegExp }[] = [
  // SHA-256 (64 hex) — must come before SHA-1 to avoid false sub-matches
  { type: "sha256", re: /\b[0-9a-f]{64}\b/gi },
  // SHA-512 (128 hex)
  { type: "sha512", re: /\b[0-9a-f]{128}\b/gi },
  // SHA-1 (40 hex)
  { type: "sha1", re: /\b[0-9a-f]{40}\b/gi },
  // MD5 (32 hex)
  { type: "md5", re: /\b[0-9a-f]{32}\b/gi },
  // CVE
  { type: "cve", re: /\bCVE-\d{4}-\d{4,7}\b/gi },
  // IPv4 — exclude private/loopback after match
  { type: "ipv4", re: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g },
  // IPv6 (simplified — full groups or compressed)
  { type: "ipv6", re: /\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:)*::(?:[0-9a-f]{1,4}:)*[0-9a-f]{1,4}\b/gi },
  // Domain — at least two labels, known TLDs, not version strings
  { type: "domain", re: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|gov|edu|mil|int|xyz|co|uk|de|br|ru|cn|jp|fr|it|nl|info|biz|me|tv|cc|eu|us|au|ca|in|nz|sg|za|app|dev|ai|security|cloud|tech)\b/gi },
];

// Semver-like sequences that should NOT be detected as hashes
const FALSE_POSITIVE_HASH = /^\d+\.\d+/;

function isPrivateIP(ip: string): boolean {
  return PRIVATE_CIDR.test(ip);
}

function isFalsePositiveHash(value: string, type: string): boolean {
  if ((type === "md5" || type === "sha1") && FALSE_POSITIVE_HASH.test(value)) return true;
  return false;
}

interface IocMatch {
  value: string;
  type: string;
  start: number;
  end: number;
}

export function extractIocs(text: string): IocMatch[] {
  const matches: IocMatch[] = [];
  const seen = new Set<string>();

  for (const { type, re } of PATTERNS) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const value = m[0];
      const key = `${type}:${value.toLowerCase()}`;
      if (seen.has(key)) continue;
      if (type === "ipv4" && isPrivateIP(value)) continue;
      if (isFalsePositiveHash(value, type)) continue;
      seen.add(key);
      matches.push({ value, type, start: m.index, end: m.index + value.length });
    }
  }

  return matches.sort((a, b) => a.start - b.start);
}

// Post-processes an HTML string: wraps detected IOCs in text nodes with
// <span data-ioc data-ioc-type> elements. Skips content inside <code>/<pre>
// (those are handled separately) and inside existing spans.
export function highlightIocsInHtml(html: string): string {
  // Work in a detached DOM tree to avoid reflow
  const div = document.createElement("div");
  div.innerHTML = html;
  walkTextNodes(div);
  return div.innerHTML;
}

function walkTextNodes(node: Node): void {
  if (
    node.nodeType === Node.ELEMENT_NODE &&
    ["SCRIPT", "STYLE"].includes((node as Element).tagName)
  ) return;

  if (node.nodeType === Node.TEXT_NODE) {
    const text = node.textContent ?? "";
    const matches = extractIocs(text);
    if (matches.length === 0) return;

    const frag = document.createDocumentFragment();
    let cursor = 0;
    for (const { value, type, start, end } of matches) {
      if (start > cursor) {
        frag.appendChild(document.createTextNode(text.slice(cursor, start)));
      }
      const span = document.createElement("span");
      span.dataset.ioc = value;
      span.dataset.iocType = type;
      span.textContent = value;
      span.className = "socc-ioc";
      frag.appendChild(span);
      cursor = end;
    }
    if (cursor < text.length) {
      frag.appendChild(document.createTextNode(text.slice(cursor)));
    }
    node.parentNode?.replaceChild(frag, node);
    return;
  }

  // Recurse into children (snapshot to avoid mutation issues)
  const children = Array.from(node.childNodes);
  for (const child of children) walkTextNodes(child);
}
