import React, { useState, useEffect } from 'react';
import { 
  Search, 
  Bell, 
  Menu, 
  Clock, 
  ArrowRight,
  X,
  Sun,
  Moon
} from 'lucide-react';
import { useSecurity } from '../../context/SecurityContext';
import { useTheme } from '../../context/ThemeContext';

interface TopbarProps {
  onMenuClick: () => void;
}

export const Topbar: React.FC<TopbarProps> = ({ onMenuClick }) => {
  const { 
    alerts, 
    threats, 
    flows, 
    setActivePage, 
    navigateToFlow, 
    setInspectThreatModal,
    globalSearch,
    setGlobalSearch
  } = useSecurity();
  const { theme, toggleTheme } = useTheme();

  const [searchFocused, setSearchFocused] = useState(false);
  const [timeStr, setTimeStr] = useState('');

  const activeAlertCount = alerts.filter(a => a.status === 'Active' || a.status === 'Investigating').length;

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTimeStr(now.toTimeString().split(' ')[0] + ' UTC+05:30');
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const matchingThreats = globalSearch.trim()
    ? threats.filter(t => 
        t.sourceIp.includes(globalSearch) || 
        t.destinationIp.includes(globalSearch) || 
        t.threatType.toLowerCase().includes(globalSearch.toLowerCase()) ||
        t.id.toLowerCase().includes(globalSearch.toLowerCase())
      ).slice(0, 3)
    : [];

  const matchingFlows = globalSearch.trim()
    ? flows.filter(f => 
        f.sourceIp.includes(globalSearch) || 
        f.destinationIp.includes(globalSearch) || 
        f.id.toLowerCase().includes(globalSearch.toLowerCase())
      ).slice(0, 2)
    : [];

  return (
    <header className="h-16 bg-white/90 dark:bg-[#090d1a]/90 backdrop-blur-md border-b border-slate-200 dark:border-slate-800/80 px-4 lg:px-8 flex items-center justify-between sticky top-0 z-30 shadow-xs transition-colors duration-200">
      {/* Left side: Hamburger (mobile) + SOC Title */}
      <div className="flex items-center gap-3">
        <button
          onClick={onMenuClick}
          className="p-2 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white lg:hidden transition-colors"
        >
          <Menu className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-2.5">
          <span className="flex h-2 w-2 relative">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          <h1 className="text-sm lg:text-base font-bold text-slate-900 dark:text-white font-sans tracking-tight">
            Security Operations Center
          </h1>
          <span className="text-[11px] font-sans font-medium px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700 hidden xl:inline">
            Live SecOps Feed
          </span>
        </div>
      </div>

      {/* Center Search Bar */}
      <div className="relative flex-1 max-w-md mx-4 hidden md:block">
        <div className="relative">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 dark:text-slate-500" />
          <input
            type="text"
            value={globalSearch}
            onChange={(e) => setGlobalSearch(e.target.value)}
            onFocus={() => setSearchFocused(true)}
            placeholder="Search IP, flow, threat (e.g. 185.220.101.42)..."
            className="w-full pl-9 pr-14 py-2 rounded-xl bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700/80 text-xs font-mono text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all"
          />
          <span className="absolute right-3 top-1/2 -translate-y-1/2 text-[10px] font-mono text-slate-400 dark:text-slate-500 px-1.5 py-0.5 rounded bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 pointer-events-none">
            ⌘K
          </span>
          {globalSearch && (
            <button
              onClick={() => setGlobalSearch('')}
              className="absolute right-10 top-1/2 -translate-y-1/2 text-slate-400 dark:text-slate-500 hover:text-slate-600 dark:hover:text-slate-300"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Live Search Quick Results Overlay */}
        {searchFocused && (matchingThreats.length > 0 || matchingFlows.length > 0) && (
          <>
            <div 
              className="fixed inset-0 z-40" 
              onClick={() => setSearchFocused(false)} 
            />
            <div className="absolute left-0 right-0 top-full mt-2 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xl p-2.5 z-50 font-sans text-xs max-h-80 overflow-y-auto">
              <div className="text-[10px] uppercase text-blue-600 dark:text-blue-400 px-3 py-1 font-bold tracking-wider">
                Threat Matches
              </div>
              {matchingThreats.map(t => (
                <div
                  key={t.id}
                  onClick={() => {
                    setInspectThreatModal(t);
                    setSearchFocused(false);
                  }}
                  className="flex items-center justify-between p-2.5 rounded-xl hover:bg-slate-50 dark:hover:bg-slate-800/80 cursor-pointer transition-colors border border-transparent hover:border-slate-200 dark:hover:border-slate-700"
                >
                  <div>
                    <div className="text-slate-900 dark:text-white font-semibold flex items-center gap-2">
                      <span>{t.threatType}</span>
                      <span className="text-[10px] text-blue-600 dark:text-blue-400 font-mono font-bold">{t.id}</span>
                    </div>
                    <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5 font-mono">
                      {t.sourceIp} → {t.destinationIp}
                    </div>
                  </div>
                  <ArrowRight className="w-3.5 h-3.5 text-blue-500" />
                </div>
              ))}

              {matchingFlows.length > 0 && (
                <>
                  <div className="text-[10px] uppercase text-indigo-600 dark:text-indigo-400 px-3 py-1 font-bold tracking-wider border-t border-slate-100 dark:border-slate-800 mt-2">
                    Flow Matches
                  </div>
                  {matchingFlows.map(f => (
                    <div
                      key={f.id}
                      onClick={() => {
                        navigateToFlow(f.id);
                        setSearchFocused(false);
                      }}
                      className="flex items-center justify-between p-2.5 rounded-xl hover:bg-slate-50 dark:hover:bg-slate-800/80 cursor-pointer transition-colors border border-transparent hover:border-slate-200 dark:hover:border-slate-700"
                    >
                      <div>
                        <div className="text-slate-900 dark:text-white font-semibold">{f.id} ({f.protocol})</div>
                        <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5 font-mono">{f.sourceIp} → {f.destinationIp}</div>
                      </div>
                      <ArrowRight className="w-3.5 h-3.5 text-indigo-500" />
                    </div>
                  ))}
                </>
              )}
            </div>
          </>
        )}
      </div>

      {/* Right side: Clock, Theme toggle, Alerts, Profile */}
      <div className="flex items-center gap-2.5">
        {/* Live Clock */}
        <div className="hidden md:flex items-center gap-2 text-xs font-sans text-slate-600 dark:text-slate-300 bg-slate-50 dark:bg-slate-900 px-3 py-1.5 rounded-xl border border-slate-200 dark:border-slate-800">
          <Clock className="w-3.5 h-3.5 text-blue-500" />
          <span className="font-semibold font-mono text-[11px]">{timeStr || '01:21:36 UTC'}</span>
        </div>

        {/* Theme Toggle Button */}
        <button
          onClick={toggleTheme}
          className="p-2 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors shadow-xs"
          title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
        >
          {theme === 'dark' ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4 text-slate-600" />}
        </button>

        {/* Notification Bell */}
        <button
          onClick={() => setActivePage('alerts')}
          className="relative p-2 rounded-xl bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:border-blue-500 text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white transition-all shadow-xs"
          title="View Alerts"
        >
          <Bell className="w-4 h-4" />
          {activeAlertCount > 0 && (
            <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-red-500 ring-2 ring-white dark:ring-slate-900 animate-pulse" />
          )}
        </button>

        {/* User avatar */}
        <div 
          onClick={() => setActivePage('settings')}
          className="w-8 h-8 rounded-xl bg-blue-100 dark:bg-blue-950/80 border border-blue-200 dark:border-blue-800 flex items-center justify-center text-blue-600 dark:text-blue-300 font-sans font-bold text-xs cursor-pointer hover:border-blue-400 transition-all hover:scale-105"
          title="User Profile & Settings"
        >
          VS
        </div>
      </div>
    </header>
  );
};
