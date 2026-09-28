export const QR_NUMBER_PATTERN = /^[A-Za-z0-9_-]+$/
export const SERIES_PREFIX_PATTERN = /^[A-Za-z0-9]{1,10}$/

/** Mirrors the server-side check in the Postgres RPC functions: http/https only. */
export function isValidDestinationUrl(value: string): boolean {
  if (!value || value.length > 2048) return false
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return false
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return false
  return /^https?:\/\/[^\s]+\.[^\s]+/i.test(value)
}

export function normalizeQrNumber(value: string): string {
  return value.trim().toUpperCase()
}

export function isValidQrNumber(value: string): boolean {
  const normalized = normalizeQrNumber(value)
  return normalized.length > 0 && normalized.length <= 64 && QR_NUMBER_PATTERN.test(normalized)
}

export function isValidPassword(value: string): boolean {
  return value.length >= 4 && value.length <= 128
}

/**
 * Best-effort check that a URL actually resolves before we let anyone save it
 * as a QR destination. Runs client-side with `mode: 'no-cors'` deliberately —
 * this still performs the real DNS/TCP/TLS handshake (so a dead domain
 * rejects), but the response is opaque so we never see or leak its contents.
 * A server-side check would need the database itself to fetch arbitrary
 * admin/customer-supplied URLs, which is a textbook SSRF vector; checking
 * from the browser keeps it in the same trust boundary as the person simply
 * clicking the link themselves.
 */
export async function isUrlReachable(url: string, timeoutMs = 6000): Promise<boolean> {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs)
  try {
    await fetch(url, { mode: 'no-cors', signal: controller.signal, redirect: 'follow' })
    return true
  } catch {
    return false
  } finally {
    clearTimeout(timeoutId)
  }
}
