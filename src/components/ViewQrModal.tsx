import { useEffect, useState } from 'react'
import { generateQrDataUrl, downloadSingleQr } from '../lib/qr'
import { qrPublicUrl } from '../lib/config'
import { Spinner } from './Spinner'

export function ViewQrModal({ qrNumber, onClose }: { qrNumber: string; onClose: () => void }) {
  const [dataUrl, setDataUrl] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    let cancelled = false
    setDataUrl(null)
    generateQrDataUrl(qrNumber).then((url) => {
      if (!cancelled) setDataUrl(url)
    })
    return () => {
      cancelled = true
    }
  }, [qrNumber])

  async function handleCopy() {
    await navigator.clipboard.writeText(qrPublicUrl(qrNumber))
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4" role="dialog" aria-modal="true">
      <div className="w-full max-w-xs rounded-xl bg-white p-6 text-center shadow-lg">
        <h3 className="text-lg font-semibold text-gray-900">{qrNumber}</h3>

        <div className="mx-auto mt-4 flex h-56 w-56 items-center justify-center rounded-lg border border-gray-200 p-2">
          {dataUrl ? (
            <img src={dataUrl} alt={`QR code for ${qrNumber}`} className="h-full w-full object-contain" />
          ) : (
            <Spinner size={28} className="text-brand-600" />
          )}
        </div>

        <button
          type="button"
          onClick={handleCopy}
          className="mt-3 break-all text-xs text-gray-400 hover:text-brand-600"
          title="Copy link"
        >
          {copied ? 'Copied!' : qrPublicUrl(qrNumber)}
        </button>

        <div className="mt-5 flex justify-center gap-3">
          <button
            type="button"
            onClick={() => downloadSingleQr(qrNumber, 'png')}
            className="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
          >
            Download PNG
          </button>
          <button
            type="button"
            onClick={() => downloadSingleQr(qrNumber, 'svg')}
            className="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
          >
            Download SVG
          </button>
        </div>

        <button
          type="button"
          onClick={onClose}
          className="mt-4 w-full rounded-lg px-4 py-2 text-sm font-medium text-gray-500 hover:bg-gray-50"
        >
          Close
        </button>
      </div>
    </div>
  )
}
