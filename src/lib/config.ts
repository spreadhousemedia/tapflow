export const APP_BASE_URL = (import.meta.env.VITE_APP_BASE_URL || window.location.origin).replace(/\/$/, '')

export function qrPublicUrl(qrNumber: string): string {
  return `${APP_BASE_URL}/q/${encodeURIComponent(qrNumber)}`
}
