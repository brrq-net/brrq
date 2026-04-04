/**
 * Format satoshis to BTC-like display with appropriate units.
 * Accepts number or string (from API) to handle large values safely.
 */
export function formatSats(sats: number | string): string {
  const n = typeof sats === 'string' ? Number(sats) : sats;
  // Guard against NaN/Infinity from huge or malformed strings
  if (!Number.isFinite(n)) {
    return typeof sats === 'string' ? `${sats} sats` : '0 sats';
  }
  if (n >= 100_000_000) {
    return `${(n / 100_000_000).toLocaleString(undefined, {
      minimumFractionDigits: 2,
      maximumFractionDigits: 8,
    })} brqBTC`;
  }
  if (n >= 1_000_000) {
    return `${(n / 1_000_000).toLocaleString(undefined, {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    })}M sats`;
  }
  if (n >= 1_000) {
    return `${(n / 1_000).toLocaleString(undefined, {
      minimumFractionDigits: 1,
      maximumFractionDigits: 1,
    })}K sats`;
  }
  return `${n.toLocaleString()} sats`;
}

/**
 * Convert a Unix timestamp (seconds) to a human-readable "time ago" string.
 */
export function timeAgo(timestamp: number): string {
  if (!Number.isFinite(timestamp) || timestamp <= 0) return 'unknown';
  const now = Math.floor(Date.now() / 1000);
  const diff = now - timestamp;

  if (diff < 0) return 'just now';
  if (diff < 5) return 'just now';
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  if (diff < 2592000) return `${Math.floor(diff / 86400)}d ago`;
  return new Date(timestamp * 1000).toLocaleDateString();
}

/**
 * Shorten a hex hash for display: 0xabcdef...1234
 */
export function shortenHash(hash: string, prefixLen = 10, suffixLen = 6): string {
  if (!hash) return '';
  if (hash.length <= prefixLen + suffixLen + 3) return hash;
  return `${hash.slice(0, prefixLen)}...${hash.slice(-suffixLen)}`;
}

/**
 * Shorten an address for display.
 */
export function shortenAddress(address: string): string {
  return shortenHash(address, 8, 6);
}

/**
 * Format a number with comma separators.
 */
export function formatNumber(n: number): string {
  return n.toLocaleString();
}

/**
 * Format gas amount.
 */
export function formatGas(gas: number): string {
  if (gas >= 1_000_000) {
    return `${(gas / 1_000_000).toFixed(2)}M`;
  }
  if (gas >= 1_000) {
    return `${(gas / 1_000).toFixed(1)}K`;
  }
  return gas.toString();
}

/**
 * Format a Unix timestamp to a readable date string.
 */
export function formatTimestamp(timestamp: number): string {
  return new Date(timestamp * 1000).toLocaleString();
}

/**
 * Copy text to clipboard.
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
