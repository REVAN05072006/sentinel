import React from 'react';
import { LucideIcon, TrendingUp, TrendingDown, Minus } from 'lucide-react';
import { motion } from 'framer-motion';

interface MetricCardProps {
  title: string;
  value: string | number;
  change?: string;
  changeType?: 'positive' | 'negative' | 'neutral';
  subtext?: string;
  icon: LucideIcon;
  accentColor?: 'cyan' | 'red' | 'amber' | 'emerald' | 'purple';
  sparklineData?: number[];
  badge?: string;
}

export const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  change,
  changeType = 'positive',
  subtext,
  icon: Icon,
  accentColor = 'cyan',
  sparklineData = [12, 15, 13, 18, 22, 19, 24, 28, 26, 31],
  badge
}) => {
  const accentStyles = {
    cyan: {
      borderHover: 'hover:border-blue-500/40',
      iconBox: 'bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-200 dark:border-blue-500/30',
      sparkline: '#2563EB',
      glow: 'rgba(37, 99, 235, 0.08)',
      indicator: 'bg-blue-500'
    },
    red: {
      borderHover: 'hover:border-red-500/40',
      iconBox: 'bg-red-50 dark:bg-red-500/10 text-red-600 dark:text-red-400 border-red-200 dark:border-red-500/30',
      sparkline: '#EF4444',
      glow: 'rgba(239, 68, 68, 0.08)',
      indicator: 'bg-red-500'
    },
    amber: {
      borderHover: 'hover:border-amber-500/40',
      iconBox: 'bg-amber-50 dark:bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-200 dark:border-amber-500/30',
      sparkline: '#F59E0B',
      glow: 'rgba(245, 158, 11, 0.08)',
      indicator: 'bg-amber-500'
    },
    emerald: {
      borderHover: 'hover:border-emerald-500/40',
      iconBox: 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-200 dark:border-emerald-500/30',
      sparkline: '#10B981',
      glow: 'rgba(16, 185, 129, 0.08)',
      indicator: 'bg-emerald-500'
    },
    purple: {
      borderHover: 'hover:border-indigo-500/40',
      iconBox: 'bg-indigo-50 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border-indigo-200 dark:border-indigo-500/30',
      sparkline: '#6366F1',
      glow: 'rgba(99, 102, 241, 0.08)',
      indicator: 'bg-indigo-500'
    }
  };

  const style = accentStyles[accentColor];

  // Calculate sparkline points
  const minVal = Math.min(...sparklineData);
  const maxVal = Math.max(...sparklineData);
  const range = maxVal - minVal || 1;
  const height = 28;
  const width = 88;
  const points = sparklineData
    .map((val, idx) => {
      const x = (idx / (sparklineData.length - 1)) * width;
      const y = height - ((val - minVal) / range) * (height - 8) - 4;
      return `${x},${y}`;
    })
    .join(' ');

  return (
    <div 
      className={`glass-card rounded-2xl p-5 relative overflow-hidden group transition-all duration-200 ${style.borderHover}`}
    >
      {/* Subtle radial ambient accent */}
      <div 
        className="absolute top-0 right-0 w-28 h-28 rounded-full blur-2xl pointer-events-none opacity-40 group-hover:opacity-70 transition-opacity"
        style={{ backgroundColor: style.glow }}
      />

      {/* Header */}
      <div className="flex items-center justify-between relative z-10">
        <span className="text-xs font-semibold tracking-wider text-slate-500 dark:text-slate-400 uppercase font-sans">
          {title}
        </span>
        <div className="flex items-center gap-2">
          {badge && (
            <span className="text-[10px] font-medium font-sans px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
              {badge}
            </span>
          )}
          <div className={`p-2 rounded-xl border ${style.iconBox} transition-transform duration-200 group-hover:scale-105`}>
            <Icon className="w-4 h-4" />
          </div>
        </div>
      </div>

      {/* Metric Main Value + Sparkline */}
      <div className="mt-3 flex items-end justify-between gap-3 relative z-10">
        <div>
          <div className="text-2xl lg:text-3xl font-extrabold font-sans tracking-tight text-slate-900 dark:text-white">
            {value}
          </div>
        </div>

        {/* Crisp Sparkline */}
        <div className="w-[88px] h-7 overflow-visible opacity-85 group-hover:opacity-100 transition-opacity">
          <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-full overflow-visible">
            <polyline
              fill="none"
              stroke={style.sparkline}
              strokeWidth="2.25"
              strokeLinecap="round"
              strokeLinejoin="round"
              points={points}
            />
          </svg>
        </div>
      </div>

      {/* Footer / Trend Information */}
      <div className="mt-3.5 pt-3 border-t border-slate-100 dark:border-slate-800/80 flex items-center justify-between text-xs relative z-10 font-sans">
        {change ? (
          <div className="flex items-center gap-1 text-[11px]">
            {changeType === 'positive' && (
              <span className="flex items-center text-emerald-600 dark:text-emerald-400 font-semibold">
                <TrendingUp className="w-3 h-3 mr-1" />
                {change}
              </span>
            )}
            {changeType === 'negative' && (
              <span className="flex items-center text-red-600 dark:text-red-400 font-semibold">
                <TrendingDown className="w-3 h-3 mr-1" />
                {change}
              </span>
            )}
            {changeType === 'neutral' && (
              <span className="flex items-center text-slate-500 dark:text-slate-400 font-semibold">
                <Minus className="w-3 h-3 mr-1" />
                {change}
              </span>
            )}
            <span className="text-slate-400 dark:text-slate-500 ml-1 text-[11px]">vs last period</span>
          </div>
        ) : (
          <span className="text-slate-500 dark:text-slate-400 text-[11px] font-medium">{subtext}</span>
        )}

        <div className="flex items-center gap-1.5 text-[10px] text-slate-400 dark:text-slate-500 font-medium">
          <span className={`w-1.5 h-1.5 rounded-full ${style.indicator}`} />
          <span>LIVE STREAM</span>
        </div>
      </div>
    </div>
  );
};
