import UploadForm from '@/components/UploadForm'
import UploadsTable from '@/components/UploadsTable'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

const INFO = [
  ['Supported source', 'Zscaler', 'Web proxy logs (NSS web feed)'],
  ['Auto detection', 'Enabled', 'Format and compression detected from the content'],
] as const

export default function UploadsPage() {
  return (
    <main className="mx-auto flex w-full max-w-7xl flex-col gap-6 p-4 md:p-6">
      <div>
        <h1 className="page-title">Upload Logs</h1>
        <p className="page-subtitle">
          Upload Zscaler web proxy logs; each file is scanned in the background for threats and anomalies.
        </p>
      </div>

      <Card>
        <CardContent>
          <UploadForm />
        </CardContent>
      </Card>

      <div className="grid gap-4 sm:grid-cols-2">
        {INFO.map(([label, value, detail]) => (
          <div key={label} className="rounded-xl border bg-card px-5 py-4">
            <p className="label-caps">{label}</p>
            <p className="metric">{value}</p>
            <p className="text-sm text-muted-foreground">{detail}</p>
          </div>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Uploads</CardTitle>
        </CardHeader>
        <CardContent>
          <UploadsTable />
        </CardContent>
      </Card>
    </main>
  )
}
