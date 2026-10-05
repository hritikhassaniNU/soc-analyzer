import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, unwrap } from '@/api/client'
import type { components } from '@/api/schema'

export type RulesCatalog = components['schemas']['RulesCatalog']
export type Detector = components['schemas']['DetectorOut']

const rulesKey = ['rules'] as const

/** The detector catalog with company-wide hits, the scoring table and MITRE coverage. */
export function useRules() {
  return useQuery({
    queryKey: rulesKey,
    queryFn: () => unwrap(api.GET('/api/rules')),
    staleTime: 30_000,
  })
}

/** Switch a detector on/off for NEW scans. */
export function useSwitchDetector() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ kind, enabled }: { kind: string; enabled: boolean }) =>
      unwrap(api.PUT('/api/rules/{kind}', { params: { path: { kind } }, body: { enabled } })),
    onSuccess: (detector) =>
      queryClient.setQueryData<RulesCatalog>(rulesKey, (old) =>
        old && { ...old, detectors: old.detectors.map((d) => (d.kind === detector.kind ? detector : d)) },
      ),
  })
}
