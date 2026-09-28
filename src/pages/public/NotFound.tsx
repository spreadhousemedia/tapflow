import { Link } from 'react-router-dom'

export function NotFound() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-3 bg-gray-50 px-4 text-center">
      <h1 className="text-2xl font-bold text-gray-900">Page Not Found</h1>
      <p className="text-sm text-gray-500">The page you're looking for doesn't exist.</p>
      <Link to="/" className="mt-2 text-sm font-medium text-brand-600 hover:text-brand-700">
        Go home
      </Link>
    </div>
  )
}
