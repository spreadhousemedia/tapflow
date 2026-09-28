import { useState, type FormEvent } from 'react'
import { supabase } from '../../lib/supabase'
import { isValidDestinationUrl, normalizeQrNumber } from '../../lib/validation'
import { rpcErrorMessage } from '../../types'
import { Spinner } from '../../components/Spinner'

type Step = 'form' | 'password' | 'success'

export function UpdatePage() {
  const [step, setStep] = useState<Step>('form')
  const [qrNumber, setQrNumber] = useState('')
  const [newUrl, setNewUrl] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  async function handleStepOneSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)

    if (!qrNumber.trim()) {
      setError('Please enter a QR number.')
      return
    }
    if (!isValidDestinationUrl(newUrl.trim())) {
      setError('Please enter a valid URL.')
      return
    }

    setSubmitting(true)
    const { data, error: rpcError } = await supabase.rpc('request_qr_update', {
      p_qr_number: normalizeQrNumber(qrNumber),
      p_new_url: newUrl.trim(),
    })
    setSubmitting(false)

    if (rpcError || !data?.ok) {
      setError(rpcErrorMessage(data?.error ?? rpcError?.message))
      return
    }
    setStep('password')
  }

  async function handlePasswordSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)

    if (!password) {
      setError('Please enter the password.')
      return
    }

    setSubmitting(true)
    const { data, error: rpcError } = await supabase.rpc('confirm_qr_update', {
      p_qr_number: normalizeQrNumber(qrNumber),
      p_new_url: newUrl.trim(),
      p_password: password,
    })
    setSubmitting(false)

    if (rpcError || !data?.ok) {
      setError(rpcErrorMessage(data?.error ?? rpcError?.message))
      return
    }
    setStep('success')
  }

  function reset() {
    setStep('form')
    setQrNumber('')
    setNewUrl('')
    setPassword('')
    setShowPassword(false)
    setError(null)
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-50 px-4 py-10">
      <div className="w-full max-w-sm rounded-2xl border border-gray-200 bg-white p-6 shadow-sm sm:p-8">
        {step === 'form' && (
          <form onSubmit={handleStepOneSubmit} noValidate>
            <HeaderIcon>
              <path d="M10 13a5 5 0 007.07 0l1.93-1.93a5 5 0 00-7.07-7.07L10.5 5.43" strokeLinecap="round" strokeLinejoin="round" />
              <path d="M14 11a5 5 0 00-7.07 0L5 12.93a5 5 0 007.07 7.07l1.43-1.43" strokeLinecap="round" strokeLinejoin="round" />
            </HeaderIcon>
            <h1 className="text-center text-xl font-bold text-gray-900">Update QR Link</h1>
            <p className="mt-2 text-center text-sm text-gray-500">
              Enter your QR number and new link to update the content in this QR code.
            </p>

            <div className="mt-6 space-y-4">
              <div>
                <label htmlFor="qrNumber" className="mb-1 block text-sm font-medium text-gray-700">
                  QR Number
                </label>
                <input
                  id="qrNumber"
                  value={qrNumber}
                  onChange={(e) => setQrNumber(e.target.value)}
                  placeholder="Enter QR number"
                  className="w-full rounded-lg border border-gray-300 px-3 py-3 text-base focus:border-brand-500"
                  autoCapitalize="characters"
                />
              </div>
              <div>
                <label htmlFor="newUrl" className="mb-1 block text-sm font-medium text-gray-700">
                  New Link / URL
                </label>
                <input
                  id="newUrl"
                  value={newUrl}
                  onChange={(e) => setNewUrl(e.target.value)}
                  placeholder="https://example.com"
                  inputMode="url"
                  className="w-full rounded-lg border border-gray-300 px-3 py-3 text-base focus:border-brand-500"
                />
              </div>

              {error && (
                <p role="alert" className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">
                  {error}
                </p>
              )}

              <button
                type="submit"
                disabled={submitting}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-brand-600 px-4 py-3 text-base font-semibold text-white hover:bg-brand-700 disabled:opacity-60"
              >
                {submitting && <Spinner size={16} />}
                {submitting ? 'Checking...' : 'Save'}
              </button>
            </div>

            <p className="mt-5 text-center text-xs text-gray-400">
              Incase you entered a wrong link, contact the support team.
            </p>
          </form>
        )}

        {step === 'password' && (
          <form onSubmit={handlePasswordSubmit} noValidate>
            <HeaderIcon>
              <rect x="5" y="11" width="14" height="9" rx="2" />
              <path d="M8 11V7a4 4 0 018 0v4" strokeLinecap="round" />
            </HeaderIcon>
            <h1 className="text-center text-xl font-bold text-gray-900">Enter Password</h1>
            <p className="mt-2 text-center text-sm text-gray-500">
              Enter the password for this QR to save the new link.
            </p>

            <div className="mt-6 space-y-4">
              <div>
                <label htmlFor="password" className="mb-1 block text-sm font-medium text-gray-700">
                  Password
                </label>
                <div className="relative">
                  <input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••"
                    className="w-full rounded-lg border border-gray-300 px-3 py-3 pr-10 text-base focus:border-brand-500"
                    autoFocus
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((s) => !s)}
                    className="absolute inset-y-0 right-0 flex items-center px-3 text-gray-400"
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                  >
                    <EyeIcon open={showPassword} />
                  </button>
                </div>
              </div>

              {error && (
                <p role="alert" className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">
                  {error}
                </p>
              )}

              <button
                type="submit"
                disabled={submitting}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-brand-600 px-4 py-3 text-base font-semibold text-white hover:bg-brand-700 disabled:opacity-60"
              >
                {submitting && <Spinner size={16} />}
                {submitting ? 'Saving...' : 'Save'}
              </button>

              <button
                type="button"
                onClick={() => {
                  setStep('form')
                  setPassword('')
                  setError(null)
                }}
                className="flex w-full items-center justify-center gap-1 text-sm font-medium text-gray-500 hover:text-gray-700"
              >
                ← Back
              </button>
            </div>

            <p className="mt-5 text-center text-xs text-gray-400">
              Incase you entered a wrong link, contact the support team.
            </p>
          </form>
        )}

        {step === 'success' && (
          <div>
            <span className="mx-auto flex h-14 w-14 items-center justify-center rounded-full bg-green-100 text-green-600">
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <path d="M5 13l4 4L19 7" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </span>
            <h1 className="mt-4 text-center text-xl font-bold text-gray-900">Link Saved Successfully!</h1>
            <p className="mt-2 text-center text-sm text-gray-500">
              The new URL has been updated in this QR code.
            </p>

            <div className="mt-5 space-y-2 rounded-lg bg-gray-50 p-4 text-sm">
              <div className="flex justify-between gap-2">
                <span className="text-gray-500">QR Number</span>
                <span className="font-medium text-gray-900">{normalizeQrNumber(qrNumber)}</span>
              </div>
              <div className="flex justify-between gap-2 break-all">
                <span className="shrink-0 text-gray-500">New URL</span>
                <span className="text-right font-medium text-gray-900">{newUrl.trim()}</span>
              </div>
            </div>

            <button
              type="button"
              onClick={reset}
              className="mt-6 flex w-full items-center justify-center gap-2 rounded-lg bg-brand-600 px-4 py-3 text-base font-semibold text-white hover:bg-brand-700"
            >
              Done
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

function HeaderIcon({ children }: { children: React.ReactNode }) {
  return (
    <span className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-brand-100 text-brand-600">
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        {children}
      </svg>
    </span>
  )
}

function EyeIcon({ open }: { open: boolean }) {
  if (open) {
    return (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M3 3l18 18M10.6 10.6a2 2 0 002.8 2.8" strokeLinecap="round" />
        <path d="M9.5 5.3A10.4 10.4 0 0112 5c5 0 9 4 10 7-0.4 1.1-1.2 2.4-2.3 3.6M6.2 6.7C4.2 8 2.8 9.9 2 12c1 3 5 7 10 7 1.3 0 2.5-.2 3.6-.6" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    )
  }
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7z" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  )
}
