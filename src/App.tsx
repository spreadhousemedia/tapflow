import { lazy, Suspense } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { AuthProvider } from './contexts/AuthContext'
import { ProtectedRoute } from './components/ProtectedRoute'
import { AdminLayout } from './components/AdminLayout'
import { Spinner } from './components/Spinner'
import { Login } from './pages/Login'
import { QRRedirect } from './pages/public/QRRedirect'
import { UpdatePage } from './pages/public/UpdatePage'
import { NotFound } from './pages/public/NotFound'

const Dashboard = lazy(() => import('./pages/admin/Dashboard').then((m) => ({ default: m.Dashboard })))
const CreateQR = lazy(() => import('./pages/admin/CreateQR').then((m) => ({ default: m.CreateQR })))
const BulkQR = lazy(() => import('./pages/admin/BulkQR').then((m) => ({ default: m.BulkQR })))
const UploadCSV = lazy(() => import('./pages/admin/UploadCSV').then((m) => ({ default: m.UploadCSV })))
const ManageQR = lazy(() => import('./pages/admin/ManageQR').then((m) => ({ default: m.ManageQR })))
const AdminAccess = lazy(() => import('./pages/admin/AdminAccess').then((m) => ({ default: m.AdminAccess })))

function PageFallback() {
  return (
    <div className="flex h-64 items-center justify-center">
      <Spinner size={28} className="text-brand-600" />
    </div>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Suspense fallback={<PageFallback />}>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/update" element={<UpdatePage />} />
            <Route path="/q/:qrNumber" element={<QRRedirect />} />

            <Route path="/admin" element={<ProtectedRoute />}>
              <Route element={<AdminLayout />}>
                <Route index element={<Dashboard />} />
                <Route path="create" element={<CreateQR />} />
                <Route path="bulk" element={<BulkQR />} />
                <Route path="upload" element={<UploadCSV />} />
                <Route path="manage" element={<ManageQR />} />
                <Route path="access" element={<AdminAccess />} />
              </Route>
            </Route>

            <Route path="/" element={<Navigate to="/admin" replace />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </Suspense>
      </AuthProvider>
    </BrowserRouter>
  )
}
