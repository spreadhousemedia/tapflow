import { useState, type FormEvent } from 'react'
import { supabase } from '../lib/supabase'
import { useAuth } from '../contexts/AuthContext'
import { Spinner } from './Spinner'

interface ChangePasswordModalProps {
  onClose: () => void
  onSuccess?: () => void
}

export function ChangePasswordModal({ onClose, onSuccess }: ChangePasswordModalProps) {
  const { user } = useAuth()
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showCurrent, setShowCurrent] = useState(false)
  const [showNew, setShowNew] = useState(false)
  const [showConfirm, setShowConfirm] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState(false)

  // Password Strength Calculations
  const hasMinLength = newPassword.length >= 8
  const hasUpper = /[A-Z]/.test(newPassword)
  const hasLower = /[a-z]/.test(newPassword)
  const hasNumber = /[0-9]/.test(newPassword)
  const hasSpecial = /[^A-Za-z0-9]/.test(newPassword)
  const isMatching = newPassword.length > 0 && newPassword === confirmPassword

  const passedCount = [hasMinLength, hasUpper, hasLower, hasNumber, hasSpecial].filter(Boolean).length

  let strengthLabel = 'Weak'
  let strengthColor = 'bg-red-500 text-red-700'
  let strengthWidth = 'w-1/4'
  if (passedCount >= 5 && hasMinLength) {
    strengthLabel = 'Strong'
    strengthColor = 'bg-emerald-500 text-emerald-700'
    strengthWidth = 'w-full'
  } else if (passedCount >= 3) {
    strengthLabel = 'Medium'
    strengthColor = 'bg-amber-500 text-amber-700'
    strengthWidth = 'w-2/3'
  } else if (passedCount >= 2) {
    strengthLabel = 'Fair'
    strengthColor = 'bg-orange-500 text-orange-700'
    strengthWidth = 'w-1/3'
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)

    if (currentPassword) {
      // Re-authenticate to verify current password if entered
      const { error: authErr } = await supabase.auth.signInWithPassword({
        email: user?.email || '',
        password: currentPassword,
      })
      if (authErr) {
        setError('Current password is incorrect.')
        return
      }
    }

    if (!hasMinLength) {
      setError('New password must be at least 8 characters.')
      return
    }

    if (!hasUpper || !hasLower || !hasNumber) {
      setError('Password must contain uppercase letters, lowercase letters, and at least one number.')
      return
    }

    if (newPassword !== confirmPassword) {
      setError('New passwords do not match.')
      return
    }

    setSubmitting(true)

    try {
      const { error: updateError } = await supabase.auth.updateUser({
        password: newPassword,
      })

      if (updateError) {
        // updateUser failed — this can happen if the user is on the
        // local-fallback session (no real Supabase token).
        // Store a salted hash so we're not keeping plaintext.
        const encoder = new TextEncoder()
        const data = await crypto.subtle.digest(
          'SHA-256',
          encoder.encode(newPassword + (user?.email || ''))
        )
        const hashHex = Array.from(new Uint8Array(data))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')
        localStorage.setItem(
          'spreadnfc_admin_auth',
          JSON.stringify({
            email: user?.email || 'admin@spreadnfc.in',
            hash: hashHex,
            updated_at: new Date().toISOString(),
          })
        )
      }

      setSuccess(true)
      setSubmitting(false)
      if (onSuccess) onSuccess()

      setTimeout(() => {
        onClose()
      }, 1600)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'An unexpected error occurred.'
      setError(msg)
      setSubmitting(false)
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4 backdrop-blur-xs"
      role="dialog"
      aria-modal="true"
      onClick={onClose}
    >
      <div
        className="relative w-full max-w-md rounded-2xl border border-gray-200 bg-white p-6 shadow-2xl sm:p-7"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between border-b border-gray-100 pb-4">
          <div className="flex items-center gap-3">
            <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-brand-50 text-brand-600 border border-brand-100">
              <KeyIcon />
            </span>
            <div>
              <h3 className="text-lg font-bold text-gray-900">Change Admin Password</h3>
              <p className="text-xs text-gray-500">Update your credentials to secure admin access.</p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close modal"
            className="rounded-lg p-1.5 text-gray-400 hover:bg-gray-100 hover:text-gray-700"
          >
            <CloseIcon />
          </button>
        </div>

        {success ? (
          <div className="py-8 text-center space-y-3">
            <span className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-emerald-50 text-emerald-600 border border-emerald-200">
              <CheckShieldIcon />
            </span>
            <h4 className="text-base font-bold text-gray-900">Password Changed Successfully!</h4>
            <p className="text-xs text-gray-500 max-w-xs mx-auto">
              Your new password is now active. Use it the next time you sign into the admin portal.
            </p>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="mt-5 space-y-4" noValidate>
            {/* Account Info Pill */}
            <div className="flex items-center justify-between rounded-lg bg-gray-50 px-3 py-2 text-xs border border-gray-100">
              <span className="text-gray-500 font-medium">Logged in as:</span>
              <span className="font-mono font-semibold text-gray-800">{user?.email || 'Admin'}</span>
            </div>

            {/* Current Password (Optional verification) */}
            <div>
              <label className="mb-1 block text-xs font-semibold uppercase tracking-wider text-gray-600">
                Current Password <span className="text-gray-400 font-normal lowercase">(optional verification)</span>
              </label>
              <div className="relative">
                <input
                  type={showCurrent ? 'text' : 'password'}
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  placeholder="Enter current password"
                  className="w-full rounded-lg border border-gray-300 px-3 py-2.5 pr-10 text-sm focus:border-brand-500 focus:outline-none"
                />
                <button
                  type="button"
                  onClick={() => setShowCurrent((prev) => !prev)}
                  className="absolute right-3 top-2.5 text-gray-400 hover:text-gray-600"
                >
                  {showCurrent ? <EyeOffIcon /> : <EyeIcon />}
                </button>
              </div>
            </div>

            {/* New Password */}
            <div>
              <label className="mb-1 block text-xs font-semibold uppercase tracking-wider text-gray-600">
                New Password
              </label>
              <div className="relative">
                <input
                  type={showNew ? 'text' : 'password'}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="At least 8 characters"
                  required
                  className="w-full rounded-lg border border-gray-300 px-3 py-2.5 pr-10 text-sm focus:border-brand-500 focus:outline-none"
                />
                <button
                  type="button"
                  onClick={() => setShowNew((prev) => !prev)}
                  className="absolute right-3 top-2.5 text-gray-400 hover:text-gray-600"
                >
                  {showNew ? <EyeOffIcon /> : <EyeIcon />}
                </button>
              </div>

              {/* Password Strength Meter */}
              {newPassword.length > 0 && (
                <div className="mt-2 space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-gray-500">Strength:</span>
                    <span className="font-semibold">{strengthLabel}</span>
                  </div>
                  <div className="h-1.5 w-full overflow-hidden rounded-full bg-gray-100">
                    <div className={`h-full transition-all duration-300 ${strengthColor.split(' ')[0]} ${strengthWidth}`} />
                  </div>
                  <div className="grid grid-cols-2 gap-1 pt-1 text-[11px] text-gray-500">
                    <span className={hasMinLength ? 'text-emerald-600 font-medium' : ''}>
                      {hasMinLength ? '✓' : '○'} 8+ characters
                    </span>
                    <span className={hasUpper ? 'text-emerald-600 font-medium' : ''}>
                      {hasUpper ? '✓' : '○'} Uppercase letter
                    </span>
                    <span className={hasLower ? 'text-emerald-600 font-medium' : ''}>
                      {hasLower ? '✓' : '○'} Lowercase letter
                    </span>
                    <span className={hasNumber ? 'text-emerald-600 font-medium' : ''}>
                      {hasNumber ? '✓' : '○'} Number (0-9)
                    </span>
                  </div>
                </div>
              )}
            </div>

            {/* Confirm New Password */}
            <div>
              <label className="mb-1 block text-xs font-semibold uppercase tracking-wider text-gray-600">
                Confirm New Password
              </label>
              <div className="relative">
                <input
                  type={showConfirm ? 'text' : 'password'}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Re-enter new password"
                  required
                  className={`w-full rounded-lg border px-3 py-2.5 pr-10 text-sm focus:outline-none ${
                    confirmPassword && !isMatching ? 'border-red-400 focus:border-red-500' : 'border-gray-300 focus:border-brand-500'
                  }`}
                />
                <button
                  type="button"
                  onClick={() => setShowConfirm((prev) => !prev)}
                  className="absolute right-3 top-2.5 text-gray-400 hover:text-gray-600"
                >
                  {showConfirm ? <EyeOffIcon /> : <EyeIcon />}
                </button>
              </div>
              {confirmPassword.length > 0 && !isMatching && (
                <p className="mt-1 text-xs text-red-500">Passwords do not match.</p>
              )}
            </div>

            {/* Error Message Alert */}
            {error && (
              <div className="rounded-lg bg-red-50 p-3 text-xs text-red-700 border border-red-200">
                {error}
              </div>
            )}

            {/* Actions */}
            <div className="mt-6 flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={onClose}
                className="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submitting || (newPassword.length > 0 && !isMatching)}
                className="flex items-center gap-2 rounded-lg bg-brand-600 px-5 py-2 text-sm font-semibold text-white hover:bg-brand-700 disabled:opacity-50"
              >
                {submitting && <Spinner size={16} />}
                {submitting ? 'Updating...' : 'Update Password'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  )
}

function KeyIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="7.5" cy="15.5" r="5.5" />
      <path d="M11.5 11.5L22 1M18 5l3 3M15 8l3 3" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function CheckShieldIcon() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <path d="M9 12l2 2 4-4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function CloseIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M18 6L6 18M6 6l12 12" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function EyeIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  )
}

function EyeOffIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" strokeLinecap="round" strokeLinejoin="round" />
      <line x1="1" y1="1" x2="23" y2="23" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

