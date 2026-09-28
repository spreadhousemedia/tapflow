import { useEffect, useState, useCallback } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { supabase } from '../../lib/supabase'
import { useAuth } from '../../contexts/AuthContext'
import { StatusBadge } from '../../components/StatusBadge'
import { ConfirmDialog } from '../../components/ConfirmDialog'
import { Spinner } from '../../components/Spinner'
import { ViewQrModal } from '../../components/ViewQrModal'
import { qrPublicUrl } from '../../lib/config'
import type { QrStatus } from '../../types'

interface RecentRow {
  id: string
  qr_number: string
  qr_name: string
  destination_url: string
  status: QrStatus
  created_at: string
  batches: { batch_name: string } | null
}

interface Counts {
  total: number
  active: number
  inactive: number
  batches: number
}

export function Dashboard() {
  const { user } = useAuth()
  const navigate = useNavigate()
  const [counts, setCounts] = useState<Counts | null>(null)
  const [recent, setRecent] = useState<RecentRow[]>([])
  const [loading, setLoading] = useState(true)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<RecentRow | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [viewTarget, setViewTarget] = useState<RecentRow | null>(null)

  const displayName = (user?.user_metadata?.full_name as string | undefined) || user?.email?.split('@')[0] || 'Admin'

  const load = useCallback(async () => {
    setLoading(true)
    const [totalRes, activeRes, inactiveRes, batchesRes, recentRes] = await Promise.all([
      supabase.from('qr_codes').select('*', { count: 'exact', head: true }),
      supabase.from('qr_codes').select('*', { count: 'exact', head: true }).eq('status', 'active'),
      supabase.from('qr_codes').select('*', { count: 'exact', head: true }).eq('status', 'inactive'),
      supabase.from('batches').select('*', { count: 'exact', head: true }),
      supabase
        .from('qr_codes')
        .select('id, qr_number, qr_name, destination_url, status, created_at, batches(batch_name)')
        .order('created_at', { ascending: false })
        .limit(8),
    ])

    setCounts({
      total: totalRes.count ?? 0,
      active: activeRes.count ?? 0,
      inactive: inactiveRes.count ?? 0,
      batches: batchesRes.count ?? 0,
    })
    setRecent(((recentRes.data as unknown) as RecentRow[]) ?? [])
    setLoading(false)
  }, [])

  useEffect(() => {
    load()
  }, [load])

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

  return (
    <div>
      <h1 className="text-2xl font-bold text-gray-900">Welcome Back, {displayName}</h1>
      <p className="mt-1 text-sm text-gray-500">Create, manage and update all your dynamic QR codes.</p>

      <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <SummaryCard label="Total QR Codes" value={counts?.total} color="brand" loading={loading} />
        <SummaryCard label="Active QR Codes" value={counts?.active} color="green" loading={loading} />
        <SummaryCard label="Inactive QR Codes" value={counts?.inactive} color="red" loading={loading} />
        <SummaryCard label="Total Batches" value={counts?.batches} color="amber" loading={loading} />
      </div>

      <div className="mt-8">
        <h2 className="mb-3 text-sm font-semibold text-gray-700">Quick Actions</h2>
        <div className="flex flex-wrap gap-3">
          <Link to="/admin/create" className="rounded-lg bg-brand-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-brand-700">
            Create QR
          </Link>
          <Link to="/admin/bulk" className="rounded-lg border border-gray-300 bg-white px-4 py-2.5 text-sm font-semibold text-gray-700 hover:bg-gray-50">
            Create Bulk QR
          </Link>
          <Link to="/admin/upload" className="rounded-lg border border-gray-300 bg-white px-4 py-2.5 text-sm font-semibold text-gray-700 hover:bg-gray-50">
            Upload CSV
          </Link>
        </div>
      </div>

      <div className="mt-8">
        <h2 className="mb-3 text-sm font-semibold text-gray-700">Recent QR Codes</h2>
        <div className="overflow-hidden rounded-xl border border-gray-200 bg-white">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px] text-left text-sm">
              <thead className="border-b border-gray-200 bg-gray-50 text-xs uppercase text-gray-500">
                <tr>
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
                    <td colSpan={7} className="px-4 py-8 text-center text-gray-400">
                      <Spinner size={20} className="mx-auto" />
                    </td>
                  </tr>
                )}
                {!loading && recent.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-4 py-8 text-center text-gray-400">
                      No QR codes yet. Create your first one to get started.
                    </td>
                  </tr>
                )}
                {recent.map((row) => (
                  <tr key={row.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3 font-medium text-gray-900">{row.qr_number}</td>
                    <td className="px-4 py-3 text-gray-600">{row.qr_name}</td>
                    <td className="px-4 py-3 text-gray-500">{row.batches?.batch_name ?? '—'}</td>
                    <td className="max-w-[220px] truncate px-4 py-3 text-brand-600">
                      <a href={row.destination_url} target="_blank" rel="noreferrer" title={row.destination_url}>
                        {row.destination_url}
                      </a>
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge status={row.status} />
                    </td>
                    <td className="px-4 py-3 text-gray-500">{new Date(row.created_at).toLocaleDateString()}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1">
                        <button
                          type="button"
                          title="View QR"
                          onClick={() => setViewTarget(row)}
                          className="rounded-md p-1.5 text-gray-500 hover:bg-gray-100"
                        >
                          <QrIcon />
                        </button>
                        <button
                          type="button"
                          title="Edit"
                          onClick={() => navigate(`/admin/manage?q=${encodeURIComponent(row.qr_number)}`)}
                          className="rounded-md p-1.5 text-gray-500 hover:bg-gray-100"
                        >
                          <EditIcon />
                        </button>
                        <button
                          type="button"
                          title="Copy QR URL"
                          onClick={() => handleCopy(row.qr_number, row.id)}
                          className="rounded-md p-1.5 text-gray-500 hover:bg-gray-100"
                        >
                          {copiedId === row.id ? <CheckIcon /> : <CopyIcon />}
                        </button>
                        <button
                          type="button"
                          title="Delete"
                          onClick={() => setDeleteTarget(row)}
                          className="rounded-md p-1.5 text-red-500 hover:bg-red-50"
                        >
                          <TrashIcon />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
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

      {viewTarget && <ViewQrModal qrNumber={viewTarget.qr_number} onClose={() => setViewTarget(null)} />}
    </div>
  )
}

function SummaryCard({
  label,
  value,
  color,
  loading,
}: {
  label: string
  value?: number
  color: 'brand' | 'green' | 'red' | 'amber'
  loading: boolean
}) {
  const colors: Record<string, string> = {
    brand: 'bg-brand-100 text-brand-600',
    green: 'bg-green-100 text-green-600',
    red: 'bg-red-100 text-red-600',
    amber: 'bg-amber-100 text-amber-600',
  }
  return (
    <div className="rounded-xl border border-gray-200 bg-white p-5">
      <div className={`mb-3 flex h-9 w-9 items-center justify-center rounded-lg ${colors[color]}`}>
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <rect x="3" y="3" width="7" height="7" rx="1.5" />
          <rect x="14" y="3" width="7" height="7" rx="1.5" />
          <rect x="3" y="14" width="7" height="7" rx="1.5" />
          <rect x="14" y="14" width="7" height="7" rx="1.5" />
        </svg>
      </div>
      <p className="text-2xl font-bold text-gray-900">{loading ? '—' : value ?? 0}</p>
      <p className="text-sm text-gray-500">{label}</p>
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
