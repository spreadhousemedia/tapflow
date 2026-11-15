import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],

  build: {
    // Suppress source maps in production — never expose source code
    sourcemap: false,

    // Raise the warning threshold to suppress the false-positive for qrcode
    // (it's a single-purpose library that cannot be split further)
    chunkSizeWarningLimit: 600,

    rollupOptions: {
      output: {
        // Split large vendor libraries into separate cacheable chunks
        manualChunks(id) {
          // QR-code generation library — large but rarely changes
          if (id.includes('node_modules/qrcode')) return 'qr'

          // HTML-to-canvas for PDF/image export
          if (id.includes('node_modules/html2canvas')) return 'html2canvas'

          // DOMPurify — XSS sanitizer
          if (id.includes('node_modules/dompurify')) return 'purify'

          // jsPDF — PDF generation
          if (id.includes('node_modules/jspdf')) return 'jspdf'

          // JSZip — ZIP downloads
          if (id.includes('node_modules/jszip')) return 'jszip'

          // PapaParse — CSV parsing
          if (id.includes('node_modules/papaparse')) return 'csv'

          // FileSaver
          if (id.includes('node_modules/file-saver')) return 'filesaver'

          // Supabase client
          if (id.includes('node_modules/@supabase')) return 'supabase'

          // React ecosystem (react, react-dom, react-router-dom)
          if (
            id.includes('node_modules/react') ||
            id.includes('node_modules/react-dom') ||
            id.includes('node_modules/react-router')
          )
            return 'react-vendor'
        },
      },
    },
  },
})
