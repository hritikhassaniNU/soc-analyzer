import { CircleCheck, CircleDashed, CircleDot } from 'lucide-react'
import { Link } from 'react-router'
import type { Investigation } from '@/api/investigations'
import { PRIORITY_META } from '@/lib/incidents'
import { STATUS_ICON_CLASS, STATUS_LABELS } from '@/lib/investigations'
import { userPath } from '@/lib/users'
import { cn } from '@/lib/utils'

/** Severity as a pill: icon in the priority color + the word in normal ink (never color alone). */
export function SeverityPill({ priority }: { priority: Investigation['priority'] }) {
  const { label, icon: Icon, iconClass } = PRIORITY_META[priority]
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold tracking-wide uppercase">
      <Icon className={cn('size-3.5', iconClass)} aria-hidden />
      {label}
    </span>
  )
}

const ENTITY_TYPES = { user: 'User', device: 'Device', ip: 'IP', domain: 'Domain' } as const

/** Entities grouped by type (D124): the type is said once ("Domains"), then its values as chips,
 *  instead of "DOMAIN x", "DOMAIN y", ... Domains/IPs/devices are plain text; users link to profiles. */
export function EntityChips({ entities }: { entities: Investigation['entities'] }) {
  const groups = (Object.keys(ENTITY_TYPES) as (keyof typeof ENTITY_TYPES)[])
    .map((type) => ({ type, names: entities.filter((e) => e.type === type).map((e) => e.name) }))
    .filter((g) => g.names.length > 0)
  return (
    <dl className="flex flex-col gap-2">
      {groups.map(({ type, names }) => (
        <div key={type} className="flex flex-col gap-1">
          <dt className="text-xs font-medium text-muted-foreground uppercase">
            {ENTITY_TYPES[type]}{names.length > 1 && 's'}
          </dt>
          <dd className="flex flex-wrap gap-1.5">
            {names.map((name) => (
              <span key={name} className="inline-flex max-w-full rounded-md bg-muted px-2 py-0.5 text-xs">
                {type === 'user' ? (
                  // A link inside clickable rows: don't also open the case.
                  <Link to={userPath(name)} className="truncate hover:underline" title={`${name}: user profile`}
                        onClick={(event) => event.stopPropagation()}>{name}</Link>
                ) : (
                  <span className="tech break-all">{name}</span>
                )}
              </span>
            ))}
          </dd>
        </div>
      ))}
    </dl>
  )
}


// Case status: its own icon shape + word (severity colors stay reserved for severity).
const STATUS_ICON = { open: CircleDot, investigating: CircleDashed, resolved: CircleCheck } as const

export function StatusPill({ status }: { status: Investigation['status'] }) {
  const Icon = STATUS_ICON[status]
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold tracking-wide uppercase">
      <Icon className={cn('size-3.5', STATUS_ICON_CLASS[status])} aria-hidden />
      {STATUS_LABELS[status]}
    </span>
  )
}
