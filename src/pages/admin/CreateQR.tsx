import { useEffect, useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { supabase } from '../../lib/supabase'
import { isValidDestinationUrl, isValidPassword, isValidQrNumber, normalizeQrNumber } from '../../lib/validation'
import { rpcErrorMessage } from '../../types'
import { downloadSingleQr, generateQrDataUrl } from '../../lib/qr'
import { qrPublicUrl } from '../../lib/config'
import { Spinner } from '../../components/Spinner'

export function CreateQR() {
  const [qrNumber, setQrNumber] = useState('')
  const [qrName, setQrName] = useState('')
  const [destinationUrl, setDestinationUrl] = useState('')
  const [password, setPassword] = useState('')
  const [status, setStatus] = useState<'active' | 'inactive'>('active')
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})
  const [formError, setFormError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [created, setCreated] = useState<{ qr_number: string } | null>(null)
  const [previewDataUrl, setPreviewDataUrl] = useState<string | null>(null)

  useEffect(() => {
    if (!created) {
      setPreviewDataUrl(null)
      return
    }
    generateQrDataUrl(created.qr_number).then(setPreviewDataUrl)
  }, [created])

  function validate(): boolean {
    const errors: Record<string, string> = {}
    if (!isValidQrNumber(qrNumber)) errors.qrNumber = 'Use letters, numbers, hyphens or underscores only.'
    if (!qrName.trim()) errors.qrName = 'QR name is required.'
    if (!isValidDestinationUrl(destinationUrl.trim())) errors.destinationUrl = 'Please enter a valid URL.'
    if (!isValidPassword(password)) errors.password = 'Password must be at least 4 characters.'
    setFieldErrors(errors)
    return Object.keys(errors).length === 0
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setFormError(null)
    setCreated(null)
    if (!validate()) return

    setSubmitting(true)
    const { data, error } = await supabase.rpc('admin_create_single_qr', {
      p_qr_number: normalizeQrNumber(qrNumber),
      p_qr_name: qrName.trim(),
      p_destination_url: destinationUrl.trim(),
      p_password: password,
      p_status: status,
    })
    setSubmitting(false)

    if (error || !data?.ok) {
      setFormError(rpcErrorMessage(data?.error ?? error?.message))
      return
    }
    setCreated({ qr_number: data.qr_number })
  }

  function resetForm() {
    setQrNumber('')
    setQrName('')
    setDestinationUrl('')
    setPassword('')
    setStatus('active')
    setFieldErrors({})
    setFormError(null)
    setCreated(null)
  }

  if (created) {
    return (
      <div className="mx-auto max-w-md">
        <div className="rounded-xl border border-gray-200 bg-white p-6 text-center">
          <span className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-green-100 text-green-600">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <path d="M5 13l4 4L19 7" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </span>
          <h1 className="mt-3 text-lg font-bold text-gray-900">QR Code Created</h1>
          <p className="mt-1 text-sm text-gray-500">{created.qr_number} is ready to use.</p>

          {previewDataUrl && (
            <img src={previewDataUrl} alt={`QR code for ${created.qr_number}`} className="mx-auto mt-4 h-40 w-40 rounded-lg border border-gray-200 p-2" />
          )}
          <p className="mt-2 break-all text-xs text-gray-400">{qrPublicUrl(created.qr_number)}</p>

          <div className="mt-5 flex justify-center gap-3">
            <button
              type="button"
              onClick={() => downloadSingleQr(created.qr_number, 'png')}
              className="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
            >
              Download PNG
            </button>
            <button
              type="button"
              onClick={() => downloadSingleQr(created.qr_number, 'svg')}
              className="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
            >
              Download SVG
            </button>
          </div>

          <div className="mt-6 flex justify-center gap-4 text-sm">
            <button type="button" onClick={resetForm} className="font-medium text-brand-600 hover:text-brand-700">
              Create Another
            </button>
            <Link to="/admin/manage" className="font-medium text-gray-500 hover:text-gray-700">
              Go to Manage QR
            </Link>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-lg">
      <h1 className="text-2xl font-bold text-gray-900">Create Single QR</h1>
      <p className="mt-1 text-sm text-gray-500">Create a dynamic QR code with a custom link.</p>

      <form onSubmit={handleSubmit} noValidate className="mt-6 space-y-4 rounded-xl border border-gray-200 bg-white p-6">
        <Field label="QR Number" error={fieldErrors.qrNumber}>
          <input
            value={qrNumber}
            onChange={(e) => setQrNumber(e.target.value)}
            placeholder="e.g. Z100"
            className={inputClass(!!fieldErrors.qrNumber)}
          />
        </Field>
        <Field label="QR Name" error={fieldErrors.qrName}>
          <input
            value={qrName}
            onChange={(e) => setQrName(e.target.value)}
            placeholder="e.g. Restaurant Menu"
            className={inputClass(!!fieldErrors.qrName)}
          />
        </Field>
        <Field label="Destination Link" error={fieldErrors.destinationUrl}>
          <input
            value={destinationUrl}
            onChange={(e) => setDestinationUrl(e.target.value)}
            placeholder="https://example.com"
            inputMode="url"
            className={inputClass(!!fieldErrors.destinationUrl)}
          />
        </Field>
        <Field label="Password" error={fieldErrors.password}>
          <input
            type="text"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Password to update this QR later"
            className={inputClass(!!fieldErrors.password)}
          />
        </Field>
        <Field label="Status">
          <select value={status} onChange={(e) => setStatus(e.target.value as 'active' | 'inactive')} className={inputClass(false)}>
            <option value="active">Active</option>
            <option value="inactive">Inactive</option>
          </select>
        </Field>

        {formError && <p role="alert" className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">{formError}</p>}

        <button
          type="submit"
          disabled={submitting}
          className="flex w-full items-center justify-center gap-2 rounded-lg bg-brand-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-brand-700 disabled:opacity-60"
        >
          {submitting && <Spinner size={16} />}
          {submitting ? 'Creating QR...' : 'Create QR'}
        </button>
      </form>
    </div>
  )
}

function Field({ label, error, children }: { label: string; error?: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="mb-1 block text-sm font-medium text-gray-700">{label}</label>
      {children}
      {error && <p className="mt-1 text-xs text-red-600">{error}</p>}
    </div>
  )
}

function inputClass(hasError: boolean) {
  return `w-full rounded-lg border px-3 py-2.5 text-sm focus:border-brand-500 ${hasError ? 'border-red-400' : 'border-gray-300'}`
}
