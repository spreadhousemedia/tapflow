export type QrStatus = 'active' | 'inactive'

/** Never includes password_hash — admin queries always select an explicit column list. */
export interface QrCode {
  id: string
  qr_number: string
  qr_name: string
  destination_url: string | null
  status: QrStatus
  batch_id: string | null
  created_at: string
  updated_at: string
}

export interface Batch {
  id: string
  batch_name: string
  series_prefix: string
  start_number: string
  end_number: string
  total_qr_codes: number
  created_at: string
  updated_at: string
}

export type PasswordMode = 'common' | 'unique'

export const RPC_ERROR_MESSAGES: Record<string, string> = {
  not_found: 'QR code not found. Please check the QR number and try again.',
  inactive: 'This QR code is inactive. Please contact the administrator.',
  invalid_url: 'Please enter a valid URL.',
  wrong_password: 'Incorrect password. Please enter the correct password.',
  rate_limited: 'Too many attempts. Please try again later.',
  duplicate_qr_number: 'This QR number already exists.',
  invalid_qr_number: 'QR numbers may only contain letters, numbers, hyphens and underscores.',
  missing_qr_name: 'QR name is required.',
  password_too_short: 'Password must be at least 4 characters.',
  invalid_status: 'Invalid status.',
  batch_name_required: 'Batch name is required.',
  invalid_range_format: 'Start and end numbers must be numeric.',
  start_after_end: 'Start number must not be greater than the end number.',
  range_too_large: 'That range is too large (max 5000 QR codes per batch).',
  invalid_prefix: 'Series prefix must be 1-10 letters/numbers.',
  invalid_password_mode: 'Invalid password mode.',
  invalid_default_url: 'Please enter a valid default destination URL.',
  duplicates: 'Some QR numbers in this range already exist.',
  unauthorized: 'You are not authorized to perform this action.',
}

export function rpcErrorMessage(code: string | undefined | null): string {
  if (!code) return 'Something went wrong. Please try again.'
  return RPC_ERROR_MESSAGES[code] ?? 'Something went wrong. Please try again.'
}
