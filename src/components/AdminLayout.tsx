import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { useState } from 'react'
import { useAuth } from '../contexts/AuthContext'

const NAV_ITEMS = [
  { to: '/admin', label: 'Dashboard', end: true, icon: DashboardIcon },
  { to: '/admin/create', label: 'Create QR', end: false, icon: CreateIcon },
  { to: '/admin/bulk', label: 'Bulk QR', end: false, icon: BulkIcon },
  { to: '/admin/upload', label: 'Upload CSV', end: false, icon: UploadIcon },
  { to: '/admin/manage', label: 'Manage QR', end: false, icon: ManageIcon },
]

export function AdminLayout() {
  const { user, signOut } = useAuth()
  const navigate = useNavigate()
  const [menuOpen, setMenuOpen] = useState(false)
  const [mobileNavOpen, setMobileNavOpen] = useState(false)

  const displayName =
    (user?.user_metadata?.full_name as string | undefined) || user?.email?.split('@')[0] || 'Admin'
  const initial = displayName.charAt(0).toUpperCase()

  async function handleLogout() {
    await signOut()
    navigate('/login', { replace: true })
  }

  return (
    <div className="flex h-screen bg-gray-50">
      {/* Sidebar (desktop) */}
      <aside className="hidden w-64 shrink-0 flex-col border-r border-gray-200 bg-white md:flex">
        <SidebarContent onNavigate={() => {}} onLogout={handleLogout} />
      </aside>

      {/* Sidebar (mobile drawer) */}
      {mobileNavOpen && (
        <div className="fixed inset-0 z-40 flex md:hidden">
          <div className="absolute inset-0 bg-black/40" onClick={() => setMobileNavOpen(false)} />
          <aside className="relative z-50 flex w-64 flex-col bg-white shadow-xl">
            <SidebarContent onNavigate={() => setMobileNavOpen(false)} onLogout={handleLogout} />
          </aside>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        {/* Topbar */}
        <header className="flex h-16 shrink-0 items-center justify-between border-b border-gray-200 bg-white px-4 sm:px-6">
          <button
            type="button"
            className="rounded-md p-2 text-gray-500 hover:bg-gray-100 md:hidden"
            onClick={() => setMobileNavOpen(true)}
            aria-label="Open navigation"
          >
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M4 6h16M4 12h16M4 18h16" strokeLinecap="round" />
            </svg>
          </button>
          <div className="hidden md:block" />
          <div className="relative">
            <button
              type="button"
              onClick={() => setMenuOpen((o) => !o)}
              className="flex items-center gap-2 rounded-full"
              aria-haspopup="true"
              aria-expanded={menuOpen}
            >
              <span className="flex h-9 w-9 items-center justify-center rounded-full bg-brand-600 text-sm font-semibold text-white">
                {initial}
              </span>
            </button>
            {menuOpen && (
              <>
                <div className="fixed inset-0 z-10" onClick={() => setMenuOpen(false)} />
                <div className="absolute right-0 z-20 mt-2 w-56 rounded-lg border border-gray-200 bg-white py-1 shadow-lg">
                  <div className="border-b border-gray-100 px-4 py-3">
                    <p className="truncate text-sm font-medium text-gray-900">{displayName}</p>
                    <p className="truncate text-xs text-gray-500">{user?.email}</p>
                  </div>
                  <button
                    type="button"
                    onClick={handleLogout}
                    className="block w-full px-4 py-2 text-left text-sm text-gray-700 hover:bg-gray-50"
                  >
                    Logout
                  </button>
                </div>
              </>
            )}
          </div>
        </header>

        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8">
          <Outlet />
        </main>
      </div>
    </div>
  )
}

function SidebarContent({ onNavigate, onLogout }: { onNavigate: () => void; onLogout: () => void }) {
  const { user } = useAuth()
  const displayName =
    (user?.user_metadata?.full_name as string | undefined) || user?.email?.split('@')[0] || 'Admin'
  const initial = displayName.charAt(0).toUpperCase()

  return (
    <>
      <div className="flex h-16 shrink-0 items-center gap-2 border-b border-gray-200 px-5">
        <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-600 text-white">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
            <rect x="3" y="3" width="7" height="7" rx="1.5" fill="currentColor" />
            <rect x="14" y="3" width="7" height="7" rx="1.5" fill="currentColor" />
            <rect x="3" y="14" width="7" height="7" rx="1.5" fill="currentColor" />
            <rect x="14" y="14" width="7" height="7" rx="1.5" fill="currentColor" />
          </svg>
        </span>
        <span className="text-lg font-bold text-gray-900">QRPanel</span>
      </div>

      <nav className="flex-1 space-y-1 px-3 py-4">
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            onClick={onNavigate}
            className={({ isActive }) =>
              `flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors ${
                isActive ? 'bg-brand-600 text-white' : 'text-gray-600 hover:bg-gray-100'
              }`
            }
          >
            <item.icon />
            {item.label}
          </NavLink>
        ))}
      </nav>

      <div className="border-t border-gray-200 p-3">
        <div className="flex items-center gap-3 rounded-lg px-3 py-2">
          <span className="flex h-8 w-8 items-center justify-center rounded-full bg-brand-100 text-sm font-semibold text-brand-700">
            {initial}
          </span>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-medium text-gray-900">{displayName}</p>
            <p className="truncate text-xs text-gray-500">{user?.email}</p>
          </div>
        </div>
        <button
          type="button"
          onClick={onLogout}
          className="mt-1 flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium text-gray-600 hover:bg-gray-100"
        >
          <LogoutIcon />
          Logout
        </button>
      </div>
    </>
  )
}

function DashboardIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <rect x="3" y="3" width="8" height="8" rx="1.5" />
      <rect x="13" y="3" width="8" height="8" rx="1.5" />
      <rect x="3" y="13" width="8" height="8" rx="1.5" />
      <rect x="13" y="13" width="8" height="8" rx="1.5" />
    </svg>
  )
}
function CreateIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <rect x="3" y="3" width="18" height="18" rx="2" />
      <path d="M12 8v8M8 12h8" strokeLinecap="round" />
    </svg>
  )
}
function BulkIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <rect x="3" y="7" width="14" height="14" rx="1.5" />
      <path d="M7 7V5a2 2 0 012-2h10a2 2 0 012 2v10a2 2 0 01-2 2h-2" />
    </svg>
  )
}
function UploadIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M12 16V4M12 4l-4 4M12 4l4 4" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2" strokeLinecap="round" />
    </svg>
  )
}
function ManageIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <rect x="3" y="4" width="18" height="4" rx="1" />
      <rect x="3" y="10" width="18" height="4" rx="1" />
      <rect x="3" y="16" width="18" height="4" rx="1" />
    </svg>
  )
}
function LogoutIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M16 17l5-5-5-5M21 12H9" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}
