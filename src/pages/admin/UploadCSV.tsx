import { useRef, useState, type DragEvent } from 'react'
import { Link } from 'react-router-dom'
import { supabase } from '../../lib/supabase'
import { parseCsvFile, downloadSampleCsv, type CsvRawRow } from '../../lib/csv'
import { Spinner } from '../../components/Spinner'

type Stage = 'upload' | 'preview' | 'result'

interface CsvError {
  row: number
  qr_number?: string
  error: string
}

interface PreviewData {
  total: number
  valid_count: number
  error_count: number
  errors: CsvError[]
}

interface ResultData {
  created: number
  error_count: number
  errors: CsvError[]
}

const ERROR_LABELS: Record<string, string> = {
  missing_qr_number: 'Missing QR number',
  missing_qr_name: 'Missing QR name',
  invalid_url: 'Invalid URL',
  invalid_password: 'Password too short (min 4 characters)',
  duplicate_in_file: 'Duplicate QR number within this file',
  already_exists: 'QR number already exists',
}

export function UploadCSV() {
  const [stage, setStage] = useState<Stage>('upload')
  const [fileName, setFileName] = useState<string | null>(null)
  const [rows, setRows] = useState<CsvRawRow[]>([])
  const [preview, setPreview] = useState<PreviewData | null>(null)
  const [result, setResult] = useState<ResultData | null>(null)
  const [loading, setLoading] = useState(false)
  const [dragOver, setDragOver] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  async function handleFile(file: File) {
    setError(null)
    if (!/\.(csv)$/i.test(file.name)) {
      setError('Please upload a .csv file.')
      return
    }
    setFileName(file.name)
    setLoading(true)
    try {
      const parsed = await parseCsvFile(file)
      setRows(parsed)
      const { data, error: rpcError } = await supabase.rpc('admin_process_qr_csv', { p_rows: parsed, p_dry_run: true })
      if (rpcError || !data?.ok) {
        setError('Could not validate this file. Please check its format and try again.')
        setLoading(false)
        return
      }
      setPreview(data)
      setStage('preview')
    } catch {
      setError('Could not parse this CSV file. Please check its format and try again.')
    }
    setLoading(false)
  }

  async function handleCreate() {
    setLoading(true)
    const { data, error: rpcError } = await supabase.rpc('admin_process_qr_csv', { p_rows: rows, p_dry_run: false })
    setLoading(false)
    if (rpcError || !data?.ok) {
      setError('Import failed. Please try again.')
      return
    }
    setResult(data)
    setStage('result')
  }

  function reset() {
    setStage('upload')
    setFileName(null)
    setRows([])
    setPreview(null)
    setResult(null)
    setError(null)
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  function onDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault()
    setDragOver(false)
    const file = e.dataTransfer.files?.[0]
    if (file) handleFile(file)
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
          <h1 className="mt-3 text-lg font-bold text-gray-900">{result.created} QR Codes Created</h1>
          {result.error_count > 0 && (
            <p className="mt-1 text-sm text-gray-500">{result.error_count} row(s) were skipped due to validation errors.</p>
          )}
          <div className="mt-6 flex justify-center gap-4 text-sm">
            <button type="button" onClick={reset} className="font-medium text-brand-600 hover:text-brand-700">
              Upload Another File
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
      <div className="mx-auto max-w-2xl">
        <h1 className="text-2xl font-bold text-gray-900">Review CSV Import</h1>
        <p className="mt-1 text-sm text-gray-500">{fileName}</p>

        <div className="mt-6 grid grid-cols-2 gap-4 sm:grid-cols-4">
          <StatCard label="Total Rows" value={preview.total} />
          <StatCard label="Valid" value={preview.valid_count} tone="green" />
          <StatCard label="Errors" value={preview.error_count} tone="red" />
          <StatCard
            label="Duplicates"
            value={preview.errors.filter((e) => e.error === 'duplicate_in_file' || e.error === 'already_exists').length}
            tone="amber"
          />
        </div>

        {preview.errors.length > 0 && (
          <div className="mt-6 overflow-hidden rounded-xl border border-gray-200 bg-white">
            <div className="border-b border-gray-200 bg-gray-50 px-4 py-2 text-xs font-semibold uppercase text-gray-500">
              Errors
            </div>
            <ul className="max-h-64 divide-y divide-gray-100 overflow-y-auto text-sm">
              {preview.errors.map((err, i) => (
                <li key={i} className="flex items-center justify-between px-4 py-2">
                  <span className="text-gray-600">
                    Row {err.row}
                    {err.qr_number ? ` (${err.qr_number})` : ''}
                  </span>
                  <span className="text-red-600">{ERROR_LABELS[err.error] ?? err.error}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {error && <p role="alert" className="mt-4 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>}

        <div className="mt-6 flex gap-3">
          <button
            type="button"
            onClick={reset}
            disabled={loading}
            className="flex-1 rounded-lg border border-gray-300 px-4 py-2.5 text-sm font-medium text-gray-700 hover:bg-gray-50"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleCreate}
            disabled={loading || preview.valid_count === 0}
            className="flex flex-1 items-center justify-center gap-2 rounded-lg bg-brand-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-brand-700 disabled:opacity-60"
          >
            {loading && <Spinner size={16} />}
            {loading ? 'Creating QR codes...' : `Create ${preview.valid_count} Valid QR Codes`}
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-lg">
      <h1 className="text-2xl font-bold text-gray-900">Upload CSV</h1>
      <p className="mt-1 text-sm text-gray-500">Upload a CSV file to create QR codes in bulk.</p>

      <div className="mt-6 rounded-xl border border-gray-200 bg-white p-6">
        <div
          onDragOver={(e) => {
            e.preventDefault()
            setDragOver(true)
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={onDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed px-6 py-12 text-center transition-colors ${
            dragOver ? 'border-brand-500 bg-brand-50' : 'border-gray-300 bg-gray-50'
          }`}
        >
          {loading ? (
            <Spinner size={28} className="text-brand-600" />
          ) : (
            <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-gray-400">
              <path d="M12 16V4M12 4l-4 4M12 4l4 4" strokeLinecap="round" strokeLinejoin="round" />
              <path d="M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2" strokeLinecap="round" />
            </svg>
          )}
          <p className="mt-3 text-sm font-medium text-gray-700">
            {loading ? 'Validating CSV...' : 'Drag & drop your CSV file here'}
          </p>
          {!loading && <p className="mt-1 text-xs text-gray-400">or click to browse (.csv)</p>}
          <input
            ref={fileInputRef}
            type="file"
            accept=".csv"
            className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0]
              if (file) handleFile(file)
            }}
          />
        </div>

        {error && <p role="alert" className="mt-4 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>}

        <button
          type="button"
          onClick={downloadSampleCsv}
          className="mt-4 w-full rounded-lg border border-gray-300 px-4 py-2.5 text-sm font-medium text-gray-700 hover:bg-gray-50"
        >
          Download Sample CSV
        </button>
        <p className="mt-2 text-center text-xs text-gray-400">
          destination_url can be left blank — that QR will prompt whoever scans it first to set it.
        </p>
      </div>
    </div>
  )
}

function StatCard({ label, value, tone = 'gray' }: { label: string; value: number; tone?: 'gray' | 'green' | 'red' | 'amber' }) {
  const tones: Record<string, string> = {
    gray: 'text-gray-900',
    green: 'text-green-600',
    red: 'text-red-600',
    amber: 'text-amber-600',
  }
  return (
    <div className="rounded-xl border border-gray-200 bg-white p-4 text-center">
      <p className={`text-2xl font-bold ${tones[tone]}`}>{value}</p>
      <p className="mt-1 text-xs text-gray-500">{label}</p>
    </div>
  )
}
