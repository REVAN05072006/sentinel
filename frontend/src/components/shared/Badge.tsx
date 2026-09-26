import React from 'react';
import { SeverityLevel, ThreatStatus, ProtocolType } from '../../types/cybersecurity';

interface SeverityBadgeProps {
  severity: SeverityLevel;
  size?: 'sm' | 'md';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'sm' }) => {
  const styles = {
    CRITICAL: 'bg-rose-50 dark:bg-rose-500/10 text-rose-700 dark:text-rose-400 border-rose-200 dark:border-rose-500/30',
    HIGH: 'bg-amber-50 dark:bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-500/30',
    MEDIUM: 'bg-yellow-50 dark:bg-yellow-500/10 text-yellow-800 dark:text-yellow-300 border-yellow-200 dark:border-yellow-500/30',
    LOW: 'bg-blue-50 dark:bg-blue-500/10 text-blue-700 dark:text-blue-400 border-blue-200 dark:border-blue-500/30',
    INFO: 'bg-slate-100 dark:bg-slate-500/10 text-slate-700 dark:text-slate-400 border-slate-200 dark:border-slate-500/30'
  };

  const dots = {
    CRITICAL: 'bg-rose-500 animate-pulse',
    HIGH: 'bg-amber-500',
    MEDIUM: 'bg-yellow-500',
    LOW: 'bg-blue-500',
    INFO: 'bg-slate-400'
  };

  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-[11px]' : 'px-2.5 py-1 text-xs';

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border font-sans font-semibold uppercase tracking-wider ${styles[severity]} ${sizeClasses}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${dots[severity]}`} />
      {severity}
    </span>
  );
};

interface StatusBadgeProps {
  status: ThreatStatus | 'Active' | 'Investigating' | 'Resolved' | 'False Positive';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status }) => {
  const styles: Record<string, string> = {
    Active: 'bg-rose-50 dark:bg-rose-500/10 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-500/20',
    Investigating: 'bg-amber-50 dark:bg-amber-500/10 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-500/20',
    Mitigated: 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-500/20',
    Resolved: 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-500/20',
    Monitoring: 'bg-blue-50 dark:bg-blue-500/10 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-500/20',
    'False Positive': 'bg-slate-100 dark:bg-slate-500/10 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-500/20'
  };

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-sans font-medium border ${styles[status] || 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-700'}`}>
      {status}
    </span>
  );
};

export const ProtocolBadge: React.FC<{ protocol: ProtocolType }> = ({ protocol }) => {
  const styles: Record<ProtocolType, string> = {
    TCP: 'text-blue-700 dark:text-blue-300 bg-blue-50 dark:bg-blue-950/40 border-blue-200 dark:border-blue-800/50',
    UDP: 'text-indigo-700 dark:text-indigo-300 bg-indigo-50 dark:bg-indigo-950/40 border-indigo-200 dark:border-indigo-800/50',
    ICMP: 'text-purple-700 dark:text-purple-300 bg-purple-50 dark:bg-purple-950/40 border-purple-200 dark:border-purple-800/50',
    GRE: 'text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40 border-amber-200 dark:border-amber-800/50',
    ESP: 'text-emerald-700 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-800/50',
    OTHER: 'text-slate-700 dark:text-slate-300 bg-slate-50 dark:bg-slate-900/40 border-slate-200 dark:border-slate-800/50'
  };

  return (
    <span className={`px-1.5 py-0.5 rounded border text-[10px] font-mono font-bold tracking-wide ${styles[protocol]}`}>
      {protocol}
    </span>
  );
};

