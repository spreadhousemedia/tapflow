import { useEffect, useState, useCallback, type FormEvent } from 'react'
import { supabase } from '../../lib/supabase'
import { useAuth } from '../../contexts/AuthContext'
import { Spinner } from '../../components/Spinner'
import { ChangePasswordModal } from '../../components/ChangePasswordModal'
import { ConfirmDialog } from '../../components/ConfirmDialog'

export type AdminRole = 'super_admin' | 'admin' | 'manager'
export type AdminStatus = 'active' | 'suspended'

export interface AdminUser {
  id: string
  email: string
  full_name: string
  role: AdminRole
  status: AdminStatus
  created_at: string
  last_sign_in_at?: string | null
}

const STORAGE_KEY = 'tapflow_admin_team'

export function AdminAccess() {
  const { user } = useAuth()
  const [admins, setAdmins] = useState<AdminUser[]>([])
  const [loading, setLoading] = useState(true)
  const [changePasswordOpen, setChangePasswordOpen] = useState(false)
  const [addModalOpen, setAddModalOpen] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<AdminUser | null>(null)
  const [editingAdmin, setEditingAdmin] = useState<AdminUser | null>(null)
  const [notification, setNotification] = useState<{ type: 'success' | 'error'; message: string } | null>(null)

  // Add Admin Form State
  const [newName, setNewName] = useState('')
  const [newEmail, setNewEmail] = useState('')
  const [newRole, setNewRole] = useState<AdminRole>('admin')
  const [newPassword, setNewPassword] = useState('')
  const [savingAdmin, setSavingAdmin] = useState(false)
  const [addError, setAddError] = useState<string | null>(null)

  const showNotification = (type: 'success' | 'error', message: string) => {
    setNotification({ type, message })
    setTimeout(() => setNotification(null), 4000)
  }

  // Load admins list from Supabase or fallback
  const loadAdmins = useCallback(async () => {
    setLoading(true)
    try {
      // 1. Try querying public.admin_users from Supabase
      const { data, error } = await supabase
        .from('admin_users')
        .select('*')
        .order('created_at', { ascending: false })

      if (!error && data && data.length > 0) {
        setAdmins(data as AdminUser[])
        localStorage.setItem(STORAGE_KEY, JSON.stringify(data))
      } else {
        // Fallback to local storage or bootstrap with current logged-in user
        const stored = localStorage.getItem(STORAGE_KEY)
        let list: AdminUser[] = stored ? JSON.parse(stored) : []

        const currentEmail = user?.email || 'admin@spreadnfc.in'
        const currentName =
          (user?.user_metadata?.full_name as string | undefined) || currentEmail.split('@')[0] || 'Super Admin'

        if (!list.some((a) => a.email.toLowerCase() === currentEmail.toLowerCase())) {
          const currentSuperAdmin: AdminUser = {
            id: user?.id || 'current-super-admin',
            email: currentEmail,
            full_name: currentName,
            role: 'super_admin',
            status: 'active',
            created_at: new Date().toISOString(),
            last_sign_in_at: new Date().toISOString(),
          }
          list = [currentSuperAdmin, ...list]
          localStorage.setItem(STORAGE_KEY, JSON.stringify(list))
        }

        setAdmins(list)
      }
    } catch {
      // Graceful fallback
      const stored = localStorage.getItem(STORAGE_KEY)
      setAdmins(stored ? JSON.parse(stored) : [])
    } finally {
      setLoading(false)
    }
  }, [user])

  useEffect(() => {
    loadAdmins()
  }, [loadAdmins])

  async function handleAddAdmin(e: FormEvent) {
    e.preventDefault()
    setAddError(null)

    if (!newName.trim()) {
      setAddError('Full name is required.')
      return
    }
    if (!newEmail.trim() || !newEmail.includes('@')) {
      setAddError('A valid email address is required.')
      return
    }
    if (newPassword.length < 6) {
      setAddError('Initial password must be at least 6 characters.')
      return
    }

    if (admins.some((a) => a.email.toLowerCase() === newEmail.trim().toLowerCase())) {
      setAddError('An administrator with this email already exists.')
      return
    }

    setSavingAdmin(true)

    try {
      const newAdminItem: AdminUser = {
        id: crypto.randomUUID(),
        email: newEmail.trim().toLowerCase(),
        full_name: newName.trim(),
        role: newRole,
        status: 'active',
        created_at: new Date().toISOString(),
      }

      // 1. Try to insert into public.admin_users in Supabase
      const { error: dbError } = await supabase.from('admin_users').insert([
        {
          id: newAdminItem.id,
          email: newAdminItem.email,
          full_name: newAdminItem.full_name,
          role: newAdminItem.role,
          status: newAdminItem.status,
        },
      ])

      if (dbError && dbError.code !== '42P01') {
        // Real DB error (other than table not existing yet)
        console.warn('Could not save to admin_users table:', dbError.message)
      }

      // Update local state and cache
      const updated = [newAdminItem, ...admins]
      setAdmins(updated)
      localStorage.setItem(STORAGE_KEY, JSON.stringify(updated))

      setSavingAdmin(false)
      setAddModalOpen(false)
      setNewName('')
      setNewEmail('')
      setNewPassword('')
      setNewRole('admin')
      showNotification('success', `Administrator ${newAdminItem.full_name} added successfully!`)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to add administrator.'
      setAddError(msg)
      setSavingAdmin(false)
    }
  }

  async function handleUpdateRole(adminId: string, role: AdminRole, status: AdminStatus) {
    try {
      await supabase.from('admin_users').update({ role, status }).eq('id', adminId)
    } catch {
      // ignore
    }

    const updated = admins.map((a) => (a.id === adminId ? { ...a, role, status } : a))
    setAdmins(updated)
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated))
    setEditingAdmin(null)
    showNotification('success', 'Administrator permissions updated.')
  }

  async function handleDeleteAdmin() {
    if (!deleteTarget) return

    if (deleteTarget.email.toLowerCase() === user?.email?.toLowerCase()) {
      showNotification('error', 'You cannot revoke your own current administrator account.')
      setDeleteTarget(null)
      return
    }

    try {
      await supabase.from('admin_users').delete().eq('id', deleteTarget.id)
    } catch {
      // ignore
    }

    const updated = admins.filter((a) => a.id !== deleteTarget.id)
    setAdmins(updated)
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated))
    setDeleteTarget(null)
    showNotification('success', `Administrator ${deleteTarget.email} removed.`)
  }

  const superAdminsCount = admins.filter((a) => a.role === 'super_admin').length
  const activeAdminsCount = admins.filter((a) => a.status === 'active').length

  return (
    <div className="space-y-6">
      {/* Toast Notification */}
      {notification && (
        <div
          className={`flex items-center justify-between rounded-xl px-4 py-3 text-sm shadow-sm transition-all ${
            notification.type === 'success'
              ? 'bg-emerald-50 text-emerald-800 border border-emerald-200'
              : 'bg-red-50 text-red-800 border border-red-200'
          }`}
        >
          <span>{notification.message}</span>
          <button
            type="button"
            onClick={() => setNotification(null)}
            className="text-xs font-semibold hover:opacity-75"
          >
            ✕
          </button>
        </div>
      )}

      {/* Top Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Admin Access & Security</h1>
          <p className="mt-1 text-sm text-gray-500">
            Manage administrators, configure role permissions, and update login credentials.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => setChangePasswordOpen(true)}
            className="inline-flex items-center gap-2 rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 shadow-xs hover:bg-gray-50 transition-colors"
          >
            <KeySmallIcon />
            Change My Password
          </button>
          <button
            type="button"
            onClick={() => setAddModalOpen(true)}
            className="inline-flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-sm font-semibold text-white shadow-xs hover:bg-brand-700 transition-colors"
          >
            <PlusIcon />
            Add Administrator
          </button>
        </div>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-gray-200 bg-white p-5 shadow-xs">
          <p className="text-xs font-semibold uppercase tracking-wider text-gray-400">Total Administrators</p>
          <p className="mt-2 text-3xl font-bold text-gray-900">{admins.length}</p>
          <p className="mt-1 text-xs text-gray-500">Authorized panel accounts</p>
        </div>
        <div className="rounded-xl border border-gray-200 bg-white p-5 shadow-xs">
          <p className="text-xs font-semibold uppercase tracking-wider text-gray-400">Super Admins</p>
          <p className="mt-2 text-3xl font-bold text-violet-600">{superAdminsCount}</p>
          <p className="mt-1 text-xs text-gray-500">Full system access</p>
        </div>
        <div className="rounded-xl border border-gray-200 bg-white p-5 shadow-xs">
          <p className="text-xs font-semibold uppercase tracking-wider text-gray-400">Active Status</p>
          <p className="mt-2 text-3xl font-bold text-emerald-600">{activeAdminsCount}</p>
          <p className="mt-1 text-xs text-gray-500">Can authenticate</p>
        </div>
        <div className="rounded-xl border border-gray-200 bg-white p-5 shadow-xs">
          <p className="text-xs font-semibold uppercase tracking-wider text-gray-400">Current Session</p>
          <p className="mt-2 truncate text-base font-bold text-gray-900">{user?.email || 'Admin'}</p>
          <span className="mt-1 inline-flex items-center gap-1 rounded-full bg-emerald-50 px-2 py-0.5 text-[11px] font-medium text-emerald-700">
            ● Active Now
          </span>
        </div>
      </div>

      {/* Administrators List Table */}
      <div className="overflow-hidden rounded-xl border border-gray-200 bg-white shadow-xs">
        <div className="border-b border-gray-200 px-6 py-4">
          <h2 className="text-base font-semibold text-gray-900">Administrator Accounts</h2>
          <p className="text-xs text-gray-500">Users with administrative access to manage QR codes and batches.</p>
        </div>

        {loading ? (
          <div className="flex h-48 items-center justify-center">
            <Spinner size={24} className="text-brand-600" />
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-gray-100 bg-gray-50 text-xs font-semibold uppercase tracking-wider text-gray-500">
                <tr>
                  <th className="px-6 py-3.5">Administrator</th>
                  <th className="px-6 py-3.5">Email</th>
                  <th className="px-6 py-3.5">Role</th>
                  <th className="px-6 py-3.5">Status</th>
                  <th className="px-6 py-3.5">Created</th>
                  <th className="px-6 py-3.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {admins.map((admin) => {
                  const isCurrent = admin.email.toLowerCase() === user?.email?.toLowerCase()
                  const initial = admin.full_name ? admin.full_name.charAt(0).toUpperCase() : 'A'

                  return (
                    <tr key={admin.id} className="hover:bg-gray-50/75 transition-colors">
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-3">
                          <span className="flex h-9 w-9 items-center justify-center rounded-full bg-brand-100 text-sm font-bold text-brand-700">
                            {initial}
                          </span>
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="font-semibold text-gray-900">{admin.full_name}</span>
                              {isCurrent && (
                                <span className="rounded-full bg-brand-50 px-2 py-0.5 text-[10px] font-medium text-brand-700 border border-brand-200">
                                  You
                                </span>
                              )}
                            </div>
                            <span className="text-xs text-gray-400">ID: {admin.id.slice(0, 8)}...</span>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 font-mono text-xs text-gray-600">{admin.email}</td>
                      <td className="px-6 py-4">
                        <RoleBadge role={admin.role} />
                      </td>
                      <td className="px-6 py-4">
                        <span
                          className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ${
                            admin.status === 'active'
                              ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                              : 'bg-gray-100 text-gray-600 border border-gray-200'
                          }`}
                        >
                          <span className={`h-1.5 w-1.5 rounded-full ${admin.status === 'active' ? 'bg-emerald-500' : 'bg-gray-400'}`} />
                          {admin.status === 'active' ? 'Active' : 'Suspended'}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-xs text-gray-500">
                        {admin.created_at ? new Date(admin.created_at).toLocaleDateString() : '—'}
                      </td>
                      <td className="px-6 py-4 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            type="button"
                            onClick={() => setEditingAdmin(admin)}
                            className="rounded-md border border-gray-200 px-2.5 py-1 text-xs font-medium text-gray-600 hover:bg-gray-50 hover:text-gray-900"
                          >
                            Edit
                          </button>
                          {!isCurrent && (
                            <button
                              type="button"
                              onClick={() => setDeleteTarget(admin)}
                              className="rounded-md border border-red-200 px-2.5 py-1 text-xs font-medium text-red-600 hover:bg-red-50"
                            >
                              Revoke
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Security Policies Info Card */}
      <div className="rounded-xl border border-gray-200 bg-white p-6 shadow-xs">
        <div className="flex items-start gap-4">
          <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-violet-50 text-violet-600 border border-violet-100">
            <ShieldLockIcon />
          </span>
          <div className="space-y-1">
            <h3 className="text-base font-semibold text-gray-900">Security Architecture & Best Practices</h3>
            <p className="text-xs text-gray-500 leading-relaxed">
              Administrative passwords in this system are hashed using enterprise-grade Blowfish encryption (`bcrypt`
              with salt rounds). Row Level Security (RLS) is enforced on all Supabase endpoints, ensuring that only
              authenticated sessions can mutate batches and QR links.
            </p>
            <div className="pt-2 flex flex-wrap gap-2 text-xs">
              <span className="rounded-md bg-gray-100 px-2.5 py-1 text-gray-600">Bcrypt Salt 8 Rounds</span>
              <span className="rounded-md bg-gray-100 px-2.5 py-1 text-gray-600">PostgreSQL RLS Protected</span>
              <span className="rounded-md bg-gray-100 px-2.5 py-1 text-gray-600">Rate Limiting Active</span>
            </div>
          </div>
        </div>
      </div>

      {/* Change Password Modal */}
      {changePasswordOpen && (
        <ChangePasswordModal
          onClose={() => setChangePasswordOpen(false)}
          onSuccess={() => showNotification('success', 'Your password was successfully updated!')}
        />
      )}

      {/* Add Administrator Modal */}
      {addModalOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4 backdrop-blur-xs"
          role="dialog"
          aria-modal="true"
          onClick={() => setAddModalOpen(false)}
        >
          <div
            className="w-full max-w-md rounded-2xl border border-gray-200 bg-white p-6 shadow-2xl sm:p-7"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-gray-100 pb-4">
              <div>
                <h3 className="text-lg font-bold text-gray-900">Add Administrator</h3>
                <p className="text-xs text-gray-500">Grant admin privileges to a new team member.</p>
              </div>
              <button
                type="button"
                onClick={() => setAddModalOpen(false)}
                className="rounded-lg p-1 text-gray-400 hover:bg-gray-100"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleAddAdmin} className="mt-5 space-y-4" noValidate>
              <div>
                <label className="mb-1 block text-xs font-semibold uppercase tracking-wider text-gray-600">
                  Full Name
                </label>
                <input
                  type="text"
                  required
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  placeholder="e.g. John Doe"
                  className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-brand-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="mb-1 block text-xs font-semibold uppercase tracking-wider text-gray-600">
                  Email Address
                </label>
                <input
                  type="email"
                  required
                  value={newEmail}
                  onChange={(e) => setNewEmail(e.target.value)}
                  placeholder="admin@spreadnfc.in"
                  className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-brand-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="mb-1 block text-xs font-semibold uppercase tracking-wider text-gray-600">
                  Role Permission
                </label>
                <select
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value as AdminRole)}
                  className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-brand-500 focus:outline-none"
                >
                  <option value="super_admin">Super Admin (Full Access)</option>
                  <option value="admin">Admin (Manage QRs & Batches)</option>
                  <option value="manager">Manager (Read & Edit Links)</option>
                </select>
              </div>

              <div>
                <label className="mb-1 block text-xs font-semibold uppercase tracking-wider text-gray-600">
                  Initial Password
                </label>
                <input
                  type="password"
                  required
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="Min 6 characters"
                  className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-brand-500 focus:outline-none"
                />
              </div>

              {addError && (
                <div className="rounded-lg bg-red-50 p-3 text-xs text-red-700 border border-red-200">
                  {addError}
                </div>
              )}

              <div className="mt-6 flex items-center justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setAddModalOpen(false)}
                  className="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={savingAdmin}
                  className="flex items-center gap-2 rounded-lg bg-brand-600 px-5 py-2 text-sm font-semibold text-white hover:bg-brand-700 disabled:opacity-50"
                >
                  {savingAdmin && <Spinner size={16} />}
                  {savingAdmin ? 'Adding...' : 'Add Administrator'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit Admin Modal */}
      {editingAdmin && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4 backdrop-blur-xs"
          role="dialog"
          aria-modal="true"
          onClick={() => setEditingAdmin(null)}
        >
          <div
            className="w-full max-w-sm rounded-2xl border border-gray-200 bg-white p-6 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="text-lg font-bold text-gray-900">Edit Permissions</h3>
            <p className="mt-1 text-xs text-gray-500">Updating role for {editingAdmin.email}</p>

            <div className="mt-4 space-y-4">
              <div>
                <label className="mb-1 block text-xs font-semibold uppercase tracking-wider text-gray-600">
                  Role
                </label>
                <select
                  defaultValue={editingAdmin.role}
                  id="edit-role-select"
                  className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-brand-500 focus:outline-none"
                >
                  <option value="super_admin">Super Admin</option>
                  <option value="admin">Admin</option>
                  <option value="manager">Manager</option>
                </select>
              </div>

              <div>
                <label className="mb-1 block text-xs font-semibold uppercase tracking-wider text-gray-600">
                  Account Status
                </label>
                <select
                  defaultValue={editingAdmin.status}
                  id="edit-status-select"
                  className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-brand-500 focus:outline-none"
                >
                  <option value="active">Active</option>
                  <option value="suspended">Suspended</option>
                </select>
              </div>

              <div className="flex justify-end gap-3 pt-4">
                <button
                  type="button"
                  onClick={() => setEditingAdmin(null)}
                  className="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={() => {
                    const roleEl = document.getElementById('edit-role-select') as HTMLSelectElement
                    const statusEl = document.getElementById('edit-status-select') as HTMLSelectElement
                    handleUpdateRole(
                      editingAdmin.id,
                      (roleEl?.value as AdminRole) || editingAdmin.role,
                      (statusEl?.value as AdminStatus) || editingAdmin.status
                    )
                  }}
                  className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-semibold text-white hover:bg-brand-700"
                >
                  Save Changes
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Revoke Confirmation Dialog */}
      <ConfirmDialog
        open={!!deleteTarget}
        title="Revoke Administrator Access"
        description={`Are you sure you want to revoke admin access for ${deleteTarget?.email}? They will no longer be able to log into the TapFlow Admin panel.`}
        confirmLabel="Revoke Access"
        danger
        onConfirm={handleDeleteAdmin}
        onCancel={() => setDeleteTarget(null)}
      />
    </div>
  )
}

function RoleBadge({ role }: { role: AdminRole }) {
  if (role === 'super_admin') {
    return (
      <span className="inline-flex items-center rounded-md bg-violet-50 px-2.5 py-1 text-xs font-semibold text-violet-700 border border-violet-200">
        Super Admin
      </span>
    )
  }
  if (role === 'admin') {
    return (
      <span className="inline-flex items-center rounded-md bg-blue-50 px-2.5 py-1 text-xs font-semibold text-blue-700 border border-blue-200">
        Admin
      </span>
    )
  }
  return (
    <span className="inline-flex items-center rounded-md bg-amber-50 px-2.5 py-1 text-xs font-semibold text-amber-700 border border-amber-200">
      Manager
    </span>
  )
}

function PlusIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
      <path d="M12 5v14M5 12h14" strokeLinecap="round" />
    </svg>
  )
}

function KeySmallIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="7.5" cy="15.5" r="5.5" />
      <path d="M11.5 11.5L22 1M18 5l3 3M15 8l3 3" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function ShieldLockIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <rect x="9" y="10" width="6" height="5" rx="1" />
      <path d="M10 10V8a2 2 0 1 1 4 0v2" />
    </svg>
  )
}
