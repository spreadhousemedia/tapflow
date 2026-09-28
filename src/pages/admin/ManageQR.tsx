import { useCallback, useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { supabase } from '../../lib/supabase'
import { isUrlReachable, isValidDestinationUrl, isValidPassword, normalizeDestinationUrl } from '../../lib/validation'
import { qrPublicUrl } from '../../lib/config'
import { downloadBulkQrZip } from '../../lib/qr'
import { StatusBadge } from '../../components/StatusBadge'
import { ConfirmDialog } from '../../components/ConfirmDialog'
import { Spinner } from '../../components/Spinner'
import { ViewQrModal } from '../../components/ViewQrModal'
import type { QrCode, QrStatus, Batch } from '../../types'

const PAGE_SIZE = 20

interface Row extends QrCode {
  batches: { batch_name: string } | null
}

export function ManageQR() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [search, setSearch] = useState(searchParams.get('q') ?? '')
  const [statusFilter, setStatusFilter] = useState<'' | QrStatus>('')
  const [batchFilter, setBatchFilter] = useState('')
  const [batches, setBatches] = useState<Batch[]>([])
  const [rows, setRows] = useState<Row[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(0)
  const [loading, setLoading] = useState(true)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<Row | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [editTarget, setEditTarget] = useState<Row | null>(null)
  const [viewTarget, setViewTarget] = useState<Row | null>(null)

  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [selectAllMatching, setSelectAllMatching] = useState(false)
  const [bulkProgress, setBulkProgress] = useState<{ done: number; total: number } | null>(null)
  const [bulkDeleteConfirm, setBulkDeleteConfirm] = useState(false)
  const [bulkDeleting, setBulkDeleting] = useState(false)

  const applyFilters = useCallback(
    <T,>(query: T): T => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      let q: any = query
      if (search.trim()) {
        const term = search.trim().replace(/[%,]/g, '')
        q = q.or(`qr_number.ilike.%${term}%,qr_name.ilike.%${term}%,destination_url.ilike.%${term}%`)
      }
      if (statusFilter) q = q.eq('status', statusFilter)
      if (batchFilter) q = q.eq('batch_id', batchFilter)
      return q
    },
    [search, statusFilter, batchFilter],
  )

  const load = useCallback(async () => {
    setLoading(true)
    setSelectedIds(new Set())
    setSelectAllMatching(false)

    let query = supabase
      .from('qr_codes')
      .select('id, qr_number, qr_name, destination_url, status, batch_id, created_at, updated_at, batches(batch_name)', {
        count: 'exact',
      })
    query = applyFilters(query)

    const from = page * PAGE_SIZE
    const { data, count } = await query.order('created_at', { ascending: false }).range(from, from + PAGE_SIZE - 1)

    setRows(((data as unknown) as Row[]) ?? [])
    setTotal(count ?? 0)
    setLoading(false)
  }, [applyFilters, page])

  useEffect(() => {
    supabase
      .from('batches')
      .select('id, batch_name, series_prefix, start_number, end_number, total_qr_codes, created_at, updated_at')
      .order('batch_name')
      .then(({ data }) => setBatches((data as Batch[]) ?? []))
  }, [])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    setPage(0)
  }, [search, statusFilter, batchFilter])

  useEffect(() => {
    const next = new URLSearchParams(searchParams)
    if (search) next.set('q', search)
    else next.delete('q')
    setSearchParams(next, { replace: true })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search])

  async function handleCopy(qrNumber: string, id: string) {
    await navigator.clipboard.writeText(qrPublicUrl(qrNumber))
    setCopiedId(id)
    setTimeout(() => setCopiedId((c) => (c === id ? null : c)), 1500)
  }

  async function handleDelete() {
    if (!deleteTarget) return
    setDeleting(true)
    await supabase.from('qr_codes').delete().eq('id', deleteTarget.id)
    setDeleting(false)
    setDeleteTarget(null)
    load()
  }

  const allOnPageSelected = rows.length > 0 && rows.every((r) => selectedIds.has(r.id))
  const selectionCount = selectAllMatching ? total : selectedIds.size

  function toggleSelectAllOnPage() {
    setSelectAllMatching(false)
    if (allOnPageSelected) {
      setSelectedIds(new Set())
    } else {
      setSelectedIds(new Set(rows.map((r) => r.id)))
    }
  }

  function toggleRow(id: string) {
    setSelectAllMatching(false)
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  function clearSelection() {
    setSelectedIds(new Set())
    setSelectAllMatching(false)
  }

  async function getSelectedQrNumbers(): Promise<string[]> {
    if (selectAllMatching) {
      let query = supabase.from('qr_codes').select('qr_number')
      query = applyFilters(query)
      const { data } = await query.order('qr_number')
      return (data ?? []).map((r) => r.qr_number as string)
    }
    return rows.filter((r) => selectedIds.has(r.id)).map((r) => r.qr_number)
  }

  async function handleBulkDownload(format: 'png' | 'svg') {
    const numbers = await getSelectedQrNumbers()
    if (numbers.length === 0) return
    setBulkProgress({ done: 0, total: numbers.length })
    await downloadBulkQrZip(numbers, format, `qr_codes_${format}.zip`, (done, t) => setBulkProgress({ done, total: t }))
    setBulkProgress(null)
  }

  async function handleBulkDelete() {
    setBulkDeleting(true)
    if (selectAllMatching) {
      let query = supabase.from('qr_codes').delete()
      query = applyFilters(query)
      await query
    } else {
      await supabase.from('qr_codes').delete().in('id', Array.from(selectedIds))
    }
    setBulkDeleting(false)
    setBulkDeleteConfirm(false)
    clearSelection()
    load()
  }

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  return (
    <div>
      <h1 className="text-2xl font-bold text-gray-900">Manage QR</h1>
      <p className="mt-1 text-sm text-gray-500">Search, filter and update your dynamic QR codes.</p>

      <div className="mt-6 flex flex-col gap-3 sm:flex-row">
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search by QR number, name or link..."
          className="flex-1 rounded-lg border border-gray-300 px-3 py-2.5 text-sm focus:border-brand-500"
        />
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value as '' | QrStatus)}
          className="rounded-lg border border-gray-300 px-3 py-2.5 text-sm focus:border-brand-500"
        >
          <option value="">All Status</option>
          <option value="active">Active</option>
          <option value="inactive">Inactive</option>
        </select>
        <select
          value={batchFilter}
          onChange={(e) => setBatchFilter(e.target.value)}
          className="rounded-lg border border-gray-300 px-3 py-2.5 text-sm focus:border-brand-500"
        >
          <option value="">All Batches</option>
          {batches.map((b) => (
            <option key={b.id} value={b.id}>
              {b.batch_name}
            </option>
          ))}
        </select>
      </div>

      {selectionCount > 0 && (
        <div className="mt-4 flex flex-wrap items-center gap-3 rounded-lg border border-brand-200 bg-brand-50 px-4 py-3 text-sm">
          <span className="font-medium text-brand-800">{selectionCount} selected</span>
          {!selectAllMatching && allOnPageSelected && total > rows.length && (
            <button type="button" onClick={() => setSelectAllMatching(true)} className="text-brand-700 underline hover:text-brand-900">
              Select all {total} matching QR codes
            </button>
          )}
          <div className="ml-auto flex items-center gap-2">
            <button
              type="button"
              onClick={() => handleBulkDownload('png')}
              disabled={!!bulkProgress}
              className="rounded-lg border border-brand-300 bg-white px-3 py-1.5 font-medium text-brand-700 hover:bg-brand-100 disabled:opacity-60"
            >
              Download PNG ZIP
            </button>
            <button
              type="button"
              onClick={() => handleBulkDownload('svg')}
              disabled={!!bulkProgress}
              className="rounded-lg border border-brand-300 bg-white px-3 py-1.5 font-medium text-brand-700 hover:bg-brand-100 disabled:opacity-60"
            >
              Download SVG ZIP
            </button>
            <button
              type="button"
              onClick={() => setBulkDeleteConfirm(true)}
              disabled={!!bulkProgress}
              className="rounded-lg border border-red-300 bg-white px-3 py-1.5 font-medium text-red-600 hover:bg-red-50 disabled:opacity-60"
            >
              Delete
            </button>
            <button type="button" onClick={clearSelection} className="px-2 py-1.5 text-gray-500 hover:text-gray-700">
              Clear
            </button>
          </div>
          {bulkProgress && (
            <span className="flex w-full items-center gap-2 text-xs text-brand-700">
              <Spinner size={12} />
              Generating {bulkProgress.done}/{bulkProgress.total}...
            </span>
          )}
        </div>
      )}

      <div className="mt-4 overflow-hidden rounded-xl border border-gray-200 bg-white">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[800px] text-left text-sm">
            <thead className="border-b border-gray-200 bg-gray-50 text-xs uppercase text-gray-500">
              <tr>
                <th className="w-10 px-4 py-3">
                  <input
                    type="checkbox"
                    checked={allOnPageSelected}
                    onChange={toggleSelectAllOnPage}
                    aria-label="Select all on this page"
                    className="h-4 w-4 rounded border-gray-300 text-brand-600"
                  />
                </th>
                <th className="px-4 py-3 font-medium">QR Number</th>
                <th className="px-4 py-3 font-medium">QR Name</th>
                <th className="px-4 py-3 font-medium">Batch</th>
                <th className="px-4 py-3 font-medium">Destination Link</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Created At</th>
                <th className="px-4 py-3 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {loading && (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-gray-400">
                    <Spinner size={20} className="mx-auto" />
                  </td>
                </tr>
              )}
              {!loading && rows.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-gray-400">
                    No QR codes match your filters.
                  </td>
                </tr>
              )}
              {rows.map((row) => (
                <tr key={row.id} className={`hover:bg-gray-50 ${selectedIds.has(row.id) ? 'bg-brand-50/60' : ''}`}>
                  <td className="px-4 py-3">
                    <input
                      type="checkbox"
                      checked={selectAllMatching || selectedIds.has(row.id)}
                      onChange={() => toggleRow(row.id)}
                      aria-label={`Select ${row.qr_number}`}
                      className="h-4 w-4 rounded border-gray-300 text-brand-600"
                    />
                  </td>
                  <td className="px-4 py-3 font-medium text-gray-900">{row.qr_number}</td>
                  <td className="px-4 py-3 text-gray-600">{row.qr_name}</td>
                  <td className="px-4 py-3 text-gray-500">{row.batches?.batch_name ?? '—'}</td>
                  <td className="max-w-[220px] truncate px-4 py-3 text-brand-600">
                    {row.destination_url ? (
                      <a href={row.destination_url} target="_blank" rel="noreferrer" title={row.destination_url}>
                        {row.destination_url}
                      </a>
                    ) : (
                      <span className="italic text-gray-400">Not set yet</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge status={row.status} />
                  </td>
                  <td className="px-4 py-3 text-gray-500">{new Date(row.created_at).toLocaleDateString()}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1">
                      <button type="button" title="View QR" onClick={() => setViewTarget(row)} className="rounded-md p-1.5 text-gray-500 hover:bg-gray-100">
                        <QrIcon />
                      </button>
                      <button type="button" title="Edit" onClick={() => setEditTarget(row)} className="rounded-md p-1.5 text-gray-500 hover:bg-gray-100">
                        <EditIcon />
                      </button>
                      <button type="button" title="Copy QR URL" onClick={() => handleCopy(row.qr_number, row.id)} className="rounded-md p-1.5 text-gray-500 hover:bg-gray-100">
                        {copiedId === row.id ? <CheckIcon /> : <CopyIcon />}
                      </button>
                      <button type="button" title="Delete" onClick={() => setDeleteTarget(row)} className="rounded-md p-1.5 text-red-500 hover:bg-red-50">
                        <TrashIcon />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="flex items-center justify-between border-t border-gray-200 px-4 py-3 text-sm text-gray-500">
          <span>
            {total === 0 ? 0 : page * PAGE_SIZE + 1}-{Math.min(total, (page + 1) * PAGE_SIZE)} of {total}
          </span>
          <div className="flex gap-2">
            <button
              type="button"
              disabled={page === 0}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              className="rounded-md border border-gray-300 px-3 py-1.5 disabled:opacity-40"
            >
              Previous
            </button>
            <button
              type="button"
              disabled={page >= totalPages - 1}
              onClick={() => setPage((p) => p + 1)}
              className="rounded-md border border-gray-300 px-3 py-1.5 disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </div>
      </div>

      <ConfirmDialog
        open={!!deleteTarget}
        title={`Delete QR ${deleteTarget?.qr_number}?`}
        description="This will permanently remove this QR record. This cannot be undone."
        confirmLabel="Delete"
        danger
        loading={deleting}
        onConfirm={handleDelete}
        onCancel={() => setDeleteTarget(null)}
      />

      <ConfirmDialog
        open={bulkDeleteConfirm}
        title={`Delete ${selectionCount} QR codes?`}
        description="This will permanently remove all selected QR records and their links. This cannot be undone."
        confirmLabel={`Delete ${selectionCount}`}
        danger
        loading={bulkDeleting}
        onConfirm={handleBulkDelete}
        onCancel={() => setBulkDeleteConfirm(false)}
      />

      {editTarget && (
        <EditQrModal
          row={editTarget}
          onClose={() => setEditTarget(null)}
          onSaved={() => {
            setEditTarget(null)
            load()
          }}
        />
      )}

      {viewTarget && <ViewQrModal qrNumber={viewTarget.qr_number} onClose={() => setViewTarget(null)} />}
    </div>
  )
}

function EditQrModal({ row, onClose, onSaved }: { row: Row; onClose: () => void; onSaved: () => void }) {
  const [qrName, setQrName] = useState(row.qr_name)
  const [destinationUrl, setDestinationUrl] = useState(row.destination_url ?? '')
  const [status, setStatus] = useState<QrStatus>(row.status)
  const [newPassword, setNewPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [passwordMessage, setPasswordMessage] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [resettingPassword, setResettingPassword] = useState(false)

  async function handleSave() {
    setError(null)
    if (!qrName.trim()) {
      setError('QR name is required.')
      return
    }
    const trimmedUrl = normalizeDestinationUrl(destinationUrl)
    if (trimmedUrl && !isValidDestinationUrl(trimmedUrl)) {
      setError('Please enter a valid URL.')
      return
    }
    setDestinationUrl(trimmedUrl)
    setSaving(true)

    if (trimmedUrl && trimmedUrl !== (row.destination_url ?? '')) {
      const reachable = await isUrlReachable(trimmedUrl)
      if (!reachable) {
        setSaving(false)
        setError("We couldn't open this link. Please double-check it.")
        return
      }
    }

    const { error: updateError } = await supabase
      .from('qr_codes')
      .update({ qr_name: qrName.trim(), destination_url: trimmedUrl || null, status })
      .eq('id', row.id)
    setSaving(false)
    if (updateError) {
      setError('Could not save changes. Please try again.')
      return
    }
    onSaved()
  }

  async function handleResetPassword() {
    setPasswordMessage(null)
    if (!isValidPassword(newPassword)) {
      setPasswordMessage('Password must be at least 4 characters.')
      return
    }
    setResettingPassword(true)
    const { data, error: rpcError } = await supabase.rpc('admin_reset_qr_password', {
      p_qr_id: row.id,
      p_new_password: newPassword,
    })
    setResettingPassword(false)
    if (rpcError || !data?.ok) {
      setPasswordMessage('Could not reset password. Please try again.')
      return
    }
    setNewPassword('')
    setPasswordMessage('Password updated.')
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4" role="dialog" aria-modal="true">
      <div className="max-h-[90vh] w-full max-w-md overflow-y-auto rounded-xl bg-white p-6 shadow-lg">
        <h3 className="text-lg font-semibold text-gray-900">Edit {row.qr_number}</h3>
        <p className="mt-1 text-xs text-gray-400">QR number cannot be changed — it's baked into the physical QR code.</p>

        <div className="mt-4 space-y-4">
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700">QR Name</label>
            <input value={qrName} onChange={(e) => setQrName(e.target.value)} className="w-full rounded-lg border border-gray-300 px-3 py-2.5 text-sm focus:border-brand-500" />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700">Destination Link</label>
            <input
              value={destinationUrl}
              onChange={(e) => setDestinationUrl(e.target.value)}
              placeholder="Not set — first scan will prompt for it"
              className="w-full rounded-lg border border-gray-300 px-3 py-2.5 text-sm focus:border-brand-500"
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700">Status</label>
            <select value={status} onChange={(e) => setStatus(e.target.value as QrStatus)} className="w-full rounded-lg border border-gray-300 px-3 py-2.5 text-sm focus:border-brand-500">
              <option value="active">Active</option>
              <option value="inactive">Inactive</option>
            </select>
          </div>

          {error && <p role="alert" className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>}

          <div className="flex justify-end gap-3 border-t border-gray-100 pt-4">
            <button type="button" onClick={onClose} disabled={saving} className="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50">
              Cancel
            </button>
            <button
              type="button"
              onClick={handleSave}
              disabled={saving}
              className="flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-sm font-semibold text-white hover:bg-brand-700 disabled:opacity-60"
            >
              {saving && <Spinner size={14} />}
              Save Changes
            </button>
          </div>

          <div className="border-t border-gray-100 pt-4">
            <label className="mb-1 block text-sm font-medium text-gray-700">Reset Password</label>
            <div className="flex gap-2">
              <input
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="New password"
                className="flex-1 rounded-lg border border-gray-300 px-3 py-2.5 text-sm focus:border-brand-500"
              />
              <button
                type="button"
                onClick={handleResetPassword}
                disabled={resettingPassword}
                className="flex items-center gap-2 rounded-lg border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-60"
              >
                {resettingPassword && <Spinner size={14} />}
                Reset
              </button>
            </div>
            {passwordMessage && <p className="mt-1 text-xs text-gray-500">{passwordMessage}</p>}
          </div>
        </div>
      </div>
    </div>
  )
}

function QrIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <rect x="3" y="3" width="7" height="7" rx="1" />
      <rect x="14" y="3" width="7" height="7" rx="1" />
      <rect x="3" y="14" width="7" height="7" rx="1" />
      <path d="M14 14h3v3h-3zM19 14h2v2h-2zM14 19h2v2h-2zM19 19h2v2h-2z" />
    </svg>
  )
}
function EditIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M11 4H6a2 2 0 00-2 2v12a2 2 0 002 2h12a2 2 0 002-2v-5" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}
function CopyIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <rect x="9" y="9" width="12" height="12" rx="2" />
      <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" />
    </svg>
  )
}
function CheckIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M5 13l4 4L19 7" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}
function TrashIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M3 6h18M8 6V4a2 2 0 012-2h4a2 2 0 012 2v2m3 0v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6h14z" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}
