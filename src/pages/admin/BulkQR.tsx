import { useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { supabase } from '../../lib/supabase'
import { isValidDestinationUrl, isValidPassword, SERIES_PREFIX_PATTERN } from '../../lib/validation'
import { rpcErrorMessage, type PasswordMode } from '../../types'
import { downloadBulkQrZip } from '../../lib/qr'
import { downloadPasswordsCsv } from '../../lib/csv'
import { Spinner } from '../../components/Spinner'

type Stage = 'form' | 'preview' | 'result'

interface PreviewData {
  total: number
  first: string
  last: string
}

interface ResultData {
  batch_id: string
  total: number
  password_mode: PasswordMode
  passwords: { qr_number: string; password: string }[] | null
}

export function BulkQR() {
  const [stage, setStage] = useState<Stage>('form')
  const [batchName, setBatchName] = useState('')
  const [seriesPrefix, setSeriesPrefix] = useState('')
  const [startNumber, setStartNumber] = useState('')
  const [endNumber, setEndNumber] = useState('')
  const [passwordMode, setPasswordMode] = useState<PasswordMode>('common')
  const [commonPassword, setCommonPassword] = useState('')
  const [defaultUrl, setDefaultUrl] = useState('')

  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})
  const [formError, setFormError] = useState<string | null>(null)
  const [conflicts, setConflicts] = useState<string[] | null>(null)
  const [preview, setPreview] = useState<PreviewData | null>(null)
  const [result, setResult] = useState<ResultData | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [downloadProgress, setDownloadProgress] = useState<{ done: number; total: number } | null>(null)

  function validate(): boolean {
    const errors: Record<string, string> = {}
    if (!batchName.trim()) errors.batchName = 'Batch name is required.'
    if (!SERIES_PREFIX_PATTERN.test(seriesPrefix.trim())) errors.seriesPrefix = '1-10 letters/numbers only.'
    if (!/^\d+$/.test(startNumber.trim())) errors.startNumber = 'Numbers only.'
    if (!/^\d+$/.test(endNumber.trim())) errors.endNumber = 'Numbers only.'
    if (
      /^\d+$/.test(startNumber.trim()) &&
      /^\d+$/.test(endNumber.trim()) &&
      parseInt(startNumber, 10) > parseInt(endNumber, 10)
    ) {
      errors.endNumber = 'End number must be greater than or equal to start number.'
    }
    if (passwordMode === 'common' && !isValidPassword(commonPassword)) {
      errors.commonPassword = 'Password must be at least 4 characters.'
    }
    if (defaultUrl.trim() && !isValidDestinationUrl(defaultUrl.trim())) {
      errors.defaultUrl = 'Please enter a valid URL.'
    }
    setFieldErrors(errors)
    return Object.keys(errors).length === 0
  }

  async function runBatch(dryRun: boolean) {
    const { data, error } = await supabase.rpc('admin_create_batch', {
      p_batch_name: batchName.trim(),
      p_series_prefix: seriesPrefix.trim().toUpperCase(),
      p_start_number: startNumber.trim(),
      p_end_number: endNumber.trim(),
      p_password_mode: passwordMode,
      p_common_password: passwordMode === 'common' ? commonPassword : null,
      p_default_url: defaultUrl.trim() || null,
      p_dry_run: dryRun,
    })
    return { data, error }
  }

  async function handlePreviewSubmit(e: FormEvent) {
    e.preventDefault()
    setFormError(null)
    setConflicts(null)
    if (!validate()) return

    setSubmitting(true)
    const { data, error } = await runBatch(true)
    setSubmitting(false)

    if (error || !data?.ok) {
      if (data?.error === 'duplicates') {
        setConflicts(data.conflicts ?? [])
        setFormError(`${data.conflicts?.length ?? 0} QR number(s) in this range already exist.`)
      } else {
        setFormError(rpcErrorMessage(data?.error ?? error?.message))
      }
      return
    }
    setPreview({ total: data.total, first: data.first, last: data.last })
    setStage('preview')
  }

  async function handleConfirmGenerate() {
    setSubmitting(true)
    setFormError(null)
    const { data, error } = await runBatch(false)
    setSubmitting(false)

    if (error || !data?.ok) {
      setFormError(rpcErrorMessage(data?.error ?? error?.message))
      setStage('form')
      return
    }
    setResult({
      batch_id: data.batch_id,
      total: data.total,
      password_mode: data.password_mode,
      passwords: data.passwords ?? null,
    })
    setStage('result')
  }

  async function getBatchQrNumbers(): Promise<string[]> {
    if (!result) return []
    const { data } = await supabase
      .from('qr_codes')
      .select('qr_number')
      .eq('batch_id', result.batch_id)
      .order('qr_number')
    return (data ?? []).map((r) => r.qr_number as string)
  }

  async function handleBulkDownload(format: 'png' | 'svg') {
    const numbers = await getBatchQrNumbers()
    if (numbers.length === 0) return
    setDownloadProgress({ done: 0, total: numbers.length })
    await downloadBulkQrZip(numbers, format, `${batchName.trim().replace(/\s+/g, '_')}_${format}.zip`, (done, total) =>
      setDownloadProgress({ done, total }),
    )
    setDownloadProgress(null)
  }

  function resetAll() {
    setStage('form')
    setBatchName('')
    setSeriesPrefix('')
    setStartNumber('')
    setEndNumber('')
    setPasswordMode('common')
    setCommonPassword('')
    setDefaultUrl('')
    setFieldErrors({})
    setFormError(null)
    setConflicts(null)
    setPreview(null)
    setResult(null)
  }

  if (stage === 'result' && result) {
    return (
      <div className="mx-auto max-w-lg">
        <div className="rounded-xl border border-gray-200 bg-white p-6 text-center">
          <span className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-green-100 text-green-600">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <path d="M5 13l4 4L19 7" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </span>
          <h1 className="mt-3 text-lg font-bold text-gray-900">{result.total} QR Codes Generated</h1>
          <p className="mt-1 text-sm text-gray-500">Batch "{batchName}" is ready.</p>

          {result.password_mode === 'unique' && result.passwords && (
            <button
              type="button"
              onClick={() => downloadPasswordsCsv(result.passwords!, `${batchName.trim().replace(/\s+/g, '_')}_passwords.csv`)}
              className="mt-4 w-full rounded-lg border border-amber-300 bg-amber-50 px-4 py-2.5 text-sm font-semibold text-amber-800 hover:bg-amber-100"
            >
              Download Passwords CSV (one-time export)
            </button>
          )}

          <div className="mt-5 flex justify-center gap-3">
            <button
              type="button"
              onClick={() => handleBulkDownload('png')}
              disabled={!!downloadProgress}
              className="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-60"
            >
              Download PNG ZIP
            </button>
            <button
              type="button"
              onClick={() => handleBulkDownload('svg')}
              disabled={!!downloadProgress}
              className="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-60"
            >
              Download SVG ZIP
            </button>
          </div>

          {downloadProgress && (
            <p className="mt-3 flex items-center justify-center gap-2 text-xs text-gray-500">
              <Spinner size={12} />
              Generating {downloadProgress.done}/{downloadProgress.total}...
            </p>
          )}

          <div className="mt-6 flex justify-center gap-4 text-sm">
            <button type="button" onClick={resetAll} className="font-medium text-brand-600 hover:text-brand-700">
              Create Another Batch
            </button>
            <Link to="/admin/manage" className="font-medium text-gray-500 hover:text-gray-700">
              Go to Manage QR
            </Link>
          </div>
        </div>
      </div>
    )
  }

  if (stage === 'preview' && preview) {
    return (
      <div className="mx-auto max-w-lg">
        <h1 className="text-2xl font-bold text-gray-900">Confirm Bulk Generation</h1>
        <p className="mt-1 text-sm text-gray-500">Review the details before generating QR codes.</p>

        <div className="mt-6 space-y-3 rounded-xl border border-gray-200 bg-white p-6 text-sm">
          <SummaryRow label="Batch Name" value={batchName} />
          <SummaryRow label="Series" value={`${preview.first} - ${preview.last}`} />
          <SummaryRow label="Total QR Codes" value={String(preview.total)} />
          <SummaryRow label="Password Mode" value={passwordMode === 'common' ? 'Same Password For All' : 'Auto Generate Unique Passwords'} />
          <SummaryRow label="Default URL" value={defaultUrl.trim() || 'https://example.com'} />

          {formError && <p role="alert" className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">{formError}</p>}

          <div className="flex gap-3 pt-2">
            <button
              type="button"
              onClick={() => setStage('form')}
              disabled={submitting}
              className="flex-1 rounded-lg border border-gray-300 px-4 py-2.5 text-sm font-medium text-gray-700 hover:bg-gray-50"
            >
              Back
            </button>
            <button
              type="button"
              onClick={handleConfirmGenerate}
              disabled={submitting}
              className="flex flex-1 items-center justify-center gap-2 rounded-lg bg-brand-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-brand-700 disabled:opacity-60"
            >
              {submitting && <Spinner size={16} />}
              {submitting ? `Generating ${preview.total} QR codes...` : 'Confirm & Generate'}
            </button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-lg">
      <h1 className="text-2xl font-bold text-gray-900">Create Bulk QR</h1>
      <p className="mt-1 text-sm text-gray-500">Generate multiple QR codes at once from a numbered series.</p>

      <form onSubmit={handlePreviewSubmit} noValidate className="mt-6 space-y-4 rounded-xl border border-gray-200 bg-white p-6">
        <Field label="Batch Name" error={fieldErrors.batchName}>
          <input value={batchName} onChange={(e) => setBatchName(e.target.value)} placeholder="e.g. September Restaurant Batch" className={inputClass(!!fieldErrors.batchName)} />
        </Field>

        <div className="grid grid-cols-3 gap-3">
          <Field label="Series Prefix" error={fieldErrors.seriesPrefix}>
            <input value={seriesPrefix} onChange={(e) => setSeriesPrefix(e.target.value)} placeholder="Z" className={inputClass(!!fieldErrors.seriesPrefix)} />
          </Field>
          <Field label="Start Number" error={fieldErrors.startNumber}>
            <input value={startNumber} onChange={(e) => setStartNumber(e.target.value)} placeholder="100" className={inputClass(!!fieldErrors.startNumber)} />
          </Field>
          <Field label="End Number" error={fieldErrors.endNumber}>
            <input value={endNumber} onChange={(e) => setEndNumber(e.target.value)} placeholder="400" className={inputClass(!!fieldErrors.endNumber)} />
          </Field>
        </div>
        {seriesPrefix && startNumber && endNumber && !fieldErrors.seriesPrefix && !fieldErrors.startNumber && !fieldErrors.endNumber && (
          <p className="text-xs text-gray-400">
            Preview: {seriesPrefix.toUpperCase()}{startNumber.padStart(startNumber.length, '0')} … {seriesPrefix.toUpperCase()}{endNumber}
          </p>
        )}

        <Field label="Password Mode">
          <div className="flex gap-4">
            <label className="flex items-center gap-2 text-sm text-gray-700">
              <input type="radio" checked={passwordMode === 'common'} onChange={() => setPasswordMode('common')} />
              Same Password For All
            </label>
            <label className="flex items-center gap-2 text-sm text-gray-700">
              <input type="radio" checked={passwordMode === 'unique'} onChange={() => setPasswordMode('unique')} />
              Auto Generate Unique Passwords
            </label>
          </div>
        </Field>

        {passwordMode === 'common' && (
          <Field label="Password" error={fieldErrors.commonPassword}>
            <input
              value={commonPassword}
              onChange={(e) => setCommonPassword(e.target.value)}
              placeholder="Applied to every QR in this batch"
              className={inputClass(!!fieldErrors.commonPassword)}
            />
          </Field>
        )}
        {passwordMode === 'unique' && (
          <p className="rounded-lg bg-brand-50 px-3 py-2 text-xs text-brand-700">
            A unique password will be generated for every QR code. You'll get a one-time CSV export after generation — save it securely.
          </p>
        )}

        <Field label="Default Destination URL (optional)" error={fieldErrors.defaultUrl}>
          <input
            value={defaultUrl}
            onChange={(e) => setDefaultUrl(e.target.value)}
            placeholder="https://example.com"
            inputMode="url"
            className={inputClass(!!fieldErrors.defaultUrl)}
          />
        </Field>

        {formError && (
          <div className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">
            <p>{formError}</p>
            {conflicts && conflicts.length > 0 && (
              <ul className="mt-1 list-inside list-disc text-xs">
                {conflicts.slice(0, 10).map((c) => (
                  <li key={c}>{c} already exists</li>
                ))}
                {conflicts.length > 10 && <li>and {conflicts.length - 10} more…</li>}
              </ul>
            )}
          </div>
        )}

        <button
          type="submit"
          disabled={submitting}
          className="flex w-full items-center justify-center gap-2 rounded-lg bg-brand-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-brand-700 disabled:opacity-60"
        >
          {submitting && <Spinner size={16} />}
          {submitting ? 'Checking range...' : 'Review Batch'}
        </button>
      </form>
    </div>
  )
}

function SummaryRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-3 border-b border-gray-100 pb-3 last:border-0 last:pb-0">
      <span className="text-gray-500">{label}</span>
      <span className="text-right font-medium text-gray-900">{value}</span>
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
