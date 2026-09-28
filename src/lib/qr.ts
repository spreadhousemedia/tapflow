import QRCode from 'qrcode'
import JSZip from 'jszip'
import { saveAs } from 'file-saver'
import { qrPublicUrl } from './config'

const QR_PIXEL_SIZE = 512
const QR_MARGIN = 2
const LABEL_HEIGHT = 72

function escapeXml(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

/** QR image as a PNG data URL, with the QR number printed as a label underneath. */
export async function generateQrDataUrl(qrNumber: string): Promise<string> {
  const qrCanvas = document.createElement('canvas')
  await QRCode.toCanvas(qrCanvas, qrPublicUrl(qrNumber), {
    width: QR_PIXEL_SIZE,
    margin: QR_MARGIN,
    errorCorrectionLevel: 'M',
  })

  const canvas = document.createElement('canvas')
  canvas.width = QR_PIXEL_SIZE
  canvas.height = QR_PIXEL_SIZE + LABEL_HEIGHT
  const ctx = canvas.getContext('2d')!
  ctx.fillStyle = '#ffffff'
  ctx.fillRect(0, 0, canvas.width, canvas.height)
  ctx.drawImage(qrCanvas, 0, 0)
  ctx.fillStyle = '#111827'
  ctx.font = '600 30px Arial, Helvetica, sans-serif'
  ctx.textAlign = 'center'
  ctx.textBaseline = 'middle'
  ctx.fillText(qrNumber, canvas.width / 2, QR_PIXEL_SIZE + LABEL_HEIGHT / 2, canvas.width - 24)

  return canvas.toDataURL('image/png')
}

/** QR image as an SVG string, with the QR number printed as a label underneath. */
export async function generateQrSvg(qrNumber: string): Promise<string> {
  const rawSvg = await QRCode.toString(qrPublicUrl(qrNumber), { margin: QR_MARGIN, errorCorrectionLevel: 'M', type: 'svg' })
  const viewBoxMatch = rawSvg.match(/viewBox="0 0 (\d+) (\d+)"/)
  const moduleSize = viewBoxMatch ? parseInt(viewBoxMatch[1], 10) : 37
  const innerMatch = rawSvg.match(/<svg[^>]*>([\s\S]*)<\/svg>/)
  const innerContent = innerMatch ? innerMatch[1] : ''
  const totalHeight = QR_PIXEL_SIZE + LABEL_HEIGHT

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${QR_PIXEL_SIZE} ${totalHeight}" width="${QR_PIXEL_SIZE}" height="${totalHeight}">
<rect width="${QR_PIXEL_SIZE}" height="${totalHeight}" fill="#ffffff"/>
<g transform="scale(${QR_PIXEL_SIZE / moduleSize})">${innerContent}</g>
<text x="${QR_PIXEL_SIZE / 2}" y="${QR_PIXEL_SIZE + LABEL_HEIGHT / 2}" text-anchor="middle" dominant-baseline="middle" font-family="Arial, Helvetica, sans-serif" font-weight="600" font-size="30" fill="#111827">${escapeXml(qrNumber)}</text>
</svg>`
}

export async function downloadSingleQr(qrNumber: string, format: 'png' | 'svg'): Promise<void> {
  if (format === 'png') {
    const dataUrl = await generateQrDataUrl(qrNumber)
    const res = await fetch(dataUrl)
    const blob = await res.blob()
    saveAs(blob, `${qrNumber}.png`)
  } else {
    const svg = await generateQrSvg(qrNumber)
    saveAs(new Blob([svg], { type: 'image/svg+xml' }), `${qrNumber}.svg`)
  }
}

export async function downloadBulkQrZip(
  qrNumbers: string[],
  format: 'png' | 'svg',
  zipFileName: string,
  onProgress?: (done: number, total: number) => void,
): Promise<void> {
  const zip = new JSZip()
  for (let i = 0; i < qrNumbers.length; i++) {
    const num = qrNumbers[i]
    if (format === 'png') {
      const dataUrl = await generateQrDataUrl(num)
      zip.file(`${num}.png`, dataUrl.split(',')[1], { base64: true })
    } else {
      const svg = await generateQrSvg(num)
      zip.file(`${num}.svg`, svg)
    }
    onProgress?.(i + 1, qrNumbers.length)
  }
  const blob = await zip.generateAsync({ type: 'blob' })
  saveAs(blob, zipFileName)
}
