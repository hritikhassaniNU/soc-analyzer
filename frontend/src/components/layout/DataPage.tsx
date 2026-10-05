import type { ReactNode } from 'react'
import { Link } from 'react-router'
import type { Upload } from '@/api/uploads'
import DatasetPicker from '@/components/layout/DatasetPicker'
import { useDataset } from '@/lib/dataset'

/** Frame for pages that show ONE upload's analysis (the dataset picked under the title). Handles the
 *  "nothing analyzed yet" and "that upload isn't available" cases once, for every such page. */
export default function DataPage({ title, children }: { title: string; children: (upload: Upload) => ReactNode }) {
  const { selected, uploadId, done, isPending, isError } = useDataset()

  let body: ReactNode
  if (isPending) body = <p className="text-sm text-muted-foreground">Loading…</p>
  else if (isError) body = <p className="text-sm text-destructive">Can't load the uploads.</p>
  else if (done.length === 0) {
    body = (
      <p className="text-sm text-muted-foreground">
        No analyzed uploads yet. <Link to="/uploads" className="underline">Upload a log file</Link> to start.
      </p>
    )
  } else if (selected === null) {
    body = (
      <p className="text-sm text-muted-foreground">
        Upload #{uploadId} isn't available here: it was deleted, failed, or is still being analyzed.{' '}
        <Link to={`/uploads/${uploadId}`} className="underline">See its details</Link>, or pick another dataset above.
      </p>
    )
  } else body = children(selected)

  return (
    <main className="mx-auto flex w-full max-w-7xl flex-col gap-6 p-4 md:p-6">
      {/* The dataset sits with the page it controls (D82), not in the app-wide top bar. */}
      <div className="flex flex-col gap-3">
        <h1 className="page-title">{title}</h1>
        <DatasetPicker />
      </div>
      {body}
    </main>
  )
}
