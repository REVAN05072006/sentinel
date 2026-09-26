import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useToast } from '../../context/ToastContext';
import { ShieldCheck, AlertTriangle, AlertCircle, Info, X } from 'lucide-react';

export const ToastContainer: React.FC = () => {
  const { toasts, removeToast } = useToast();

  const iconMap = {
    info: <Info className="w-4 h-4 text-blue-500" />,
    success: <ShieldCheck className="w-4 h-4 text-emerald-500" />,
    warning: <AlertTriangle className="w-4 h-4 text-amber-500" />,
    danger: <AlertCircle className="w-4 h-4 text-rose-500" />
  };

  const borderMap = {
    info: 'border-blue-200 dark:border-blue-500/30 bg-white/95 dark:bg-slate-900/95 shadow-md',
    success: 'border-emerald-200 dark:border-emerald-500/30 bg-white/95 dark:bg-slate-900/95 shadow-md',
    warning: 'border-amber-200 dark:border-amber-500/30 bg-white/95 dark:bg-slate-900/95 shadow-md',
    danger: 'border-rose-200 dark:border-rose-500/30 bg-white/95 dark:bg-slate-900/95 shadow-md'
  };

  return (
    <div className="fixed bottom-5 right-5 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none font-sans">
      <AnimatePresence>
        {toasts.map(toast => (
          <motion.div
            key={toast.id}
            initial={{ opacity: 0, y: 20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, x: 50, scale: 0.9 }}
            transition={{ duration: 0.2 }}
            className={`pointer-events-auto flex items-start gap-3 p-4 rounded-xl border backdrop-blur-md ${borderMap[toast.type]}`}
          >
            <div className="mt-0.5 shrink-0">{iconMap[toast.type]}</div>
            <div className="flex-1 min-w-0">
              <div className="text-xs font-bold font-sans tracking-tight text-slate-900 dark:text-white">
                {toast.title}
              </div>
              {toast.message && (
                <div className="text-xs text-slate-600 dark:text-slate-400 mt-1 leading-relaxed font-sans">
                  {toast.message}
                </div>
              )}
            </div>
            <button
              onClick={() => removeToast(toast.id)}
              className="text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 p-0.5 rounded transition-colors"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
};
