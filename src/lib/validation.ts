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
