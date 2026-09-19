import clsx from 'clsx';

const styles: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/25',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/25',
  medium: 'bg-amber-500/15 text-amber-400 border-amber-500/25',
  low: 'bg-slate-500/15 text-slate-400 border-slate-500/25',
  new: 'bg-aegis-500/15 text-aegis-300 border-aegis-500/25',
  triaging: 'bg-violet-500/15 text-violet-300 border-violet-500/25',
  investigating: 'bg-blue-500/15 text-blue-300 border-blue-500/25',
  resolved: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/25',
  dismissed: 'bg-slate-500/15 text-slate-400 border-slate-500/25',
  open: 'bg-aegis-500/15 text-aegis-300 border-aegis-500/25',
  contained: 'bg-teal-500/15 text-teal-300 border-teal-500/25',
  closed: 'bg-slate-500/15 text-slate-400 border-slate-500/25',
  healthy: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/25',
  warning: 'bg-amber-500/15 text-amber-400 border-amber-500/25',
  enforced: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/25',
  partial: 'bg-amber-500/15 text-amber-400 border-amber-500/25',
  active: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/25',
  expiring: 'bg-red-500/15 text-red-400 border-red-500/25'
};

export default function SeverityBadge({ value }: { value: string }) {
  return (
    <span className={clsx('badge border capitalize', styles[value] || styles.low)}>
      {value}
    </span>
  );
}
