import React from 'react';
import { Shield } from 'lucide-react';

interface LogoProps {
  size?: 'sm' | 'md' | 'lg';
  showSubtitle?: boolean;
  showText?: boolean;
}

export const Logo: React.FC<LogoProps> = ({ 
  size = 'md', 
  showSubtitle = true, 
  showText = true 
}) => {
  const iconSizes = {
    sm: 'w-8 h-8',
    md: 'w-9 h-9',
    lg: 'w-10 h-10'
  };

  const textSizes = {
    sm: 'text-sm',
    md: 'text-base',
    lg: 'text-xl'
  };

  const shieldSizes = {
    sm: 'w-4 h-4',
    md: 'w-4.5 h-4.5',
    lg: 'w-5 h-5'
  };

  return (
    <div className="inline-flex items-center gap-3 select-none group cursor-pointer">
      {/* Precision Shield Icon */}
      <div className={`${iconSizes[size]} rounded-xl bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center shadow-xs shrink-0 group-hover:from-blue-500 group-hover:to-indigo-600 transition-all`}>
        <Shield className={`${shieldSizes[size]} text-white stroke-[2.25]`} />
      </div>

      {showText && (
        <div className="flex flex-col leading-none">
          <span className={`font-bold tracking-wider text-slate-900 dark:text-white ${textSizes[size]} font-sans`}>
            SENTINEL
          </span>
          {showSubtitle && (
            <span className="text-[9.5px] uppercase tracking-widest text-slate-500 dark:text-slate-400 font-sans mt-0.5 font-semibold">
              Cybersecurity
            </span>
          )}
        </div>
      )}
    </div>
  );
};
