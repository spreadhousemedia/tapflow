import Papa from 'papaparse'
import { saveAs } from 'file-saver'

export type CsvRawRow = Record<string, string>

export function parseCsvFile(file: File): Promise<CsvRawRow[]> {
  return new Promise((resolve, reject) => {
    Papa.parse<CsvRawRow>(file, {
      header: true,
      skipEmptyLines: true,
      transformHeader: (h) => h.trim().toLowerCase(),
      complete: (results) => resolve(results.data),
      error: (err: Error) => reject(err),
    })
  })
}

export function downloadSampleCsv(): void {
  const sample = [
    'qr_number,qr_name,destination_url,password,batch_name',
    'Z100,Cafe Menu,https://example.com/menu,123456,September Batch',
    'Z101,Shop Location,https://maps.google.com,123456,September Batch',
    'Z102,Instagram,https://instagram.com/example,123456,September Batch',
  ].join('\n')
  saveAs(new Blob([sample], { type: 'text/csv;charset=utf-8' }), 'sample_qr_upload.csv')
}

export function downloadPasswordsCsv(rows: { qr_number: string; password: string }[], fileName: string): void {
  const lines = ['qr_number,password', ...rows.map((r) => `${r.qr_number},${r.password}`)]
  saveAs(new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' }), fileName)
}
