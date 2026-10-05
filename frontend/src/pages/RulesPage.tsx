import { useSearchParams } from 'react-router'
import { useRules } from '@/api/rules'
import DetectorTable from '@/components/rules/DetectorTable'
import ScoringPanel from '@/components/rules/ScoringPanel'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { LAYER_LABELS } from '@/lib/detectors'

const TABS = [['detectors', 'Detectors'], ['scoring', 'Scoring']] as const
type Tab = (typeof TABS)[number][0]

export default function RulesPage() {
  const rules = useRules()
  const [params, setParams] = useSearchParams()
  const tab: Tab = TABS.some(([v]) => v === params.get('tab')) ? (params.get('tab') as Tab) : 'detectors'

  function selectTab(value: string) {
    const next = new URLSearchParams(params)
    if (value === 'detectors') next.delete('tab')
    else next.set('tab', value)
    setParams(next) // in the URL: Back works
  }

  const data = rules.data
  const detectors = data?.detectors ?? []
  const enabled = detectors.filter((d) => d.enabled).length
  const tiles: [string, string, string][] = data ? [
    ['Detectors', String(detectors.length),
      Object.entries(LAYER_LABELS).map(([layer, label]) => `${detectors.filter((d) => d.layer === layer).length} ${label.toLowerCase()}`).join(' · ')],
    ['Enabled', `${enabled} of ${detectors.length}`, enabled === detectors.length ? 'All detectors run on new scans' : 'Switched-off detectors skip new scans'],
    ['Findings', detectors.reduce((n, d) => n + d.hits, 0).toLocaleString(), 'Across all cases, company-wide'],
  ] : []

  return (
    <main className="mx-auto flex w-full max-w-7xl flex-col gap-6 p-4 md:p-6">
      <div>
        <h1 className="page-title">Detection Rules</h1>
        <p className="page-subtitle">
          Everything the analyzer looks for, how it decides, and how findings become a case's risk.
        </p>
      </div>

      {rules.isPending && <p className="text-sm text-muted-foreground">Loading…</p>}
      {rules.isError && <p className="text-sm text-muted-foreground">Couldn't load the detection rules. Try again.</p>}
      {data && (
        <>
          <ul className="grid gap-4 sm:grid-cols-3">
            {tiles.map(([label, value, detail]) => (
              <li key={label} className="rounded-xl border bg-card px-5 py-4">
                <p className="label-caps">{label}</p>
                <p className="metric">{value}</p>
                <p className="text-xs text-muted-foreground">{detail}</p>
              </li>
            ))}
          </ul>

          <Tabs value={tab} onValueChange={selectTab}>
            <TabsList variant="line">
              {TABS.map(([value, label]) => <TabsTrigger key={value} value={value}>{label}</TabsTrigger>)}
            </TabsList>
            <TabsContent value="detectors"><DetectorTable detectors={detectors} /></TabsContent>
            <TabsContent value="scoring"><ScoringPanel scoring={data.scoring} /></TabsContent>
          </Tabs>
        </>
      )}
    </main>
  )
}
