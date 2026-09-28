import type { QrStatus } from '../types'

export function StatusBadge({ status }: { status: QrStatus }) {
  const isActive = status === 'active'
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-medium ${
        isActive ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
      }`}
    >
      {isActive ? 'Active' : 'Inactive'}
    </span>
  )
}
