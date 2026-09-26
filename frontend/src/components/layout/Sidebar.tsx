import React from 'react';
import {
  LayoutDashboard,
  Activity,
  ShieldAlert,
  Search,
  BrainCircuit,
  Bell,
  FileText,
  Settings,
  Compass,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  LockKeyhole,
  Globe2,
  GitBranch,
  Siren
} from 'lucide-react';
import { useSecurity, PageId } from '../../context/SecurityContext';
import { Logo } from '../shared/Logo';

interface SidebarProps {
  collapsed: boolean;
  setCollapsed: (c: boolean) => void;
  mobileOpen: boolean;
  setMobileOpen: (o: boolean) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  collapsed,
  setCollapsed,
  mobileOpen,
  setMobileOpen
}) => {
  const { activePage, setActivePage, alerts } = useSecurity();

  const unreadAlerts = alerts.filter(
    a => a.status === 'Active' || a.status === 'Investigating'
  ).length;

  const navItems: {
    id: PageId;
    label: string;
    icon: any;
    badge?: number;
  }[] = [
    { id: 'dashboard', label: 'Security Overview', icon: LayoutDashboard },
    { id: 'traffic', label: 'Traffic Analysis', icon: Activity },
    { id: 'threats', label: 'Threat Detection', icon: ShieldAlert },
    { id: 'encrypted', label: 'Encrypted Traffic', icon: LockKeyhole },
    { id: 'dns', label: 'DNS Analysis', icon: Globe2 },
    { id: 'correlation', label: 'Attack Correlation', icon: GitBranch },
    { id: 'incidents', label: 'Incidents', icon: Siren },
    { id: 'ip-intel', label: 'IP Intelligence', icon: Search },
    { id: 'ai-insights', label: 'Detection Models', icon: BrainCircuit },
    { id: 'alerts', label: 'Alerts Queue', icon: Bell, badge: unreadAlerts },
    { id: 'reports', label: 'Audit Reports', icon: FileText }
  ];

  return (
    <>
      {/* Mobile Backdrop */}
      {mobileOpen && (
        <div
          onClick={() => setMobileOpen(false)}
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm lg:hidden"
        />
      )}

      {/* Sidebar Container */}
      <aside
        className={`fixed top-0 bottom-0 left-0 z-40 flex flex-col justify-between bg-white dark:bg-[#090d1a] border-r border-slate-200 dark:border-slate-800/80 shadow-xs dark:shadow-xl transition-all duration-300 ease-in-out overflow-x-hidden ${
          collapsed ? 'w-20' : 'w-64'
        } ${
          mobileOpen
            ? 'translate-x-0'
            : '-translate-x-full lg:translate-x-0'
        }`}
      >
        {/* Top Header & Logo */}
        <div>
          {collapsed ? (
            <div className="h-16 flex items-center justify-center border-b border-slate-100 dark:border-slate-800/70 px-2">
              <div
                onClick={() => {
                  setActivePage('landing');
                  setMobileOpen(false);
                }}
                className="flex items-center justify-center cursor-pointer hover:opacity-90 transition-opacity"
                title="Sentinel Cybersecurity Platform"
              >
                <Logo size="md" showSubtitle={false} showText={false} />
              </div>
            </div>
          ) : (
            <div className="h-16 flex items-center justify-between px-4 border-b border-slate-100 dark:border-slate-800/70">
              <div
                onClick={() => {
                  setActivePage('landing');
                  setMobileOpen(false);
                }}
                className="flex items-center cursor-pointer"
              >
                <Logo size="md" showSubtitle={true} showText={true} />
              </div>

              {/* Collapse toggle (Desktop only) */}
              <button
                onClick={() => setCollapsed(true)}
                className="hidden lg:flex p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 transition-colors shrink-0 cursor-pointer"
                title="Collapse sidebar"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
            </div>
          )}

          {/* Expand Button for Collapsed Mode */}
          {collapsed && (
            <div className="px-3 pt-2">
              <button
                onClick={() => setCollapsed(false)}
                className="w-full h-8 flex items-center justify-center rounded-xl bg-slate-50 dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 text-slate-400 hover:text-blue-500 dark:hover:text-blue-400 hover:border-blue-300 dark:hover:border-blue-700 hover:bg-slate-100 dark:hover:bg-slate-800/80 transition-all cursor-pointer shadow-2xs"
                title="Expand sidebar"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          )}

          {/* Navigation Links */}
          <nav className="p-3 space-y-1 mt-2">
            {navItems.map(item => {
              const Icon = item.icon;
              const isActive = activePage === item.id;

              return (
                <button
                  key={item.id}
                  onClick={() => {
                    setActivePage(item.id);
                    setMobileOpen(false);
                  }}
                  title={collapsed ? item.label : undefined}
                  className={`w-full flex items-center ${
                    collapsed ? 'justify-center px-0' : 'gap-3 px-3'
                  } py-2.5 rounded-xl font-sans text-xs font-medium transition-all duration-150 relative group cursor-pointer ${
                    isActive
                      ? 'bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-200/80 dark:border-blue-500/30 font-semibold shadow-xs'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-50 dark:hover:bg-slate-800/50 border border-transparent'
                  }`}
                >
                  <Icon
                    className={`w-4 h-4 shrink-0 transition-transform ${
                      isActive
                        ? 'text-blue-600 dark:text-blue-400'
                        : 'text-slate-400 dark:text-slate-500 group-hover:text-slate-700 dark:group-hover:text-slate-300'
                    }`}
                  />

                  {!collapsed && (
                    <span className="truncate tracking-tight">
                      {item.label}
                    </span>
                  )}

                  {/* Badges */}
                  {item.badge !== undefined && item.badge > 0 && (
                    collapsed ? (
                      <span className="absolute top-1.5 right-2 w-2 h-2 rounded-full bg-red-500 ring-2 ring-white dark:ring-[#090d1a]" />
                    ) : (
                      <span
                        className={`ml-auto text-[10px] font-bold px-1.5 py-0.5 rounded-full ${
                          isActive
                            ? 'bg-red-500 text-white shadow-xs'
                            : 'bg-red-50 dark:bg-red-950/60 text-red-600 dark:text-red-400 border border-red-200 dark:border-red-900/40'
                        }`}
                      >
                        {item.badge}
                      </span>
                    )
                  )}

                  {/* Active Indicator Bar */}
                  {isActive && (
                    <span className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-5 bg-blue-600 dark:bg-blue-400 rounded-r-full" />
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Bottom System & Profile Section */}
        <div className="p-3 border-t border-slate-100 dark:border-slate-800/70 space-y-2">
          {/* Quick Landing Overview Link */}
          <button
            onClick={() => {
              setActivePage('landing');
              setMobileOpen(false);
            }}
            title={collapsed ? 'Security Brief' : undefined}
            className={`w-full flex items-center ${
              collapsed ? 'justify-center px-0' : 'gap-3 px-3'
            } py-2 rounded-xl text-xs font-sans text-slate-600 dark:text-slate-400 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-slate-50 dark:hover:bg-slate-800/50 border border-slate-200/60 dark:border-slate-800/60 transition-all cursor-pointer`}
          >
            <Compass className="w-4 h-4 shrink-0 text-blue-500 dark:text-blue-400" />

            {!collapsed && (
              <span className="truncate flex items-center justify-between flex-1 font-medium">
                Security Brief
                <ExternalLink className="w-3 h-3 ml-1 opacity-60" />
              </span>
            )}
          </button>

          {/* Settings */}
          <button
            onClick={() => {
              setActivePage('settings');
              setMobileOpen(false);
            }}
            title={collapsed ? 'Settings' : undefined}
            className={`w-full flex items-center ${
              collapsed ? 'justify-center px-0' : 'gap-3 px-3'
            } py-2 rounded-xl font-sans text-xs font-medium transition-colors cursor-pointer ${
              activePage === 'settings'
                ? 'bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-200/80 dark:border-blue-500/30'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-50 dark:hover:bg-slate-800/50 border border-transparent'
            }`}
          >
            <Settings className="w-4 h-4 shrink-0 text-slate-400 dark:text-slate-500" />
            {!collapsed && <span>Settings</span>}
          </button>

          {/* System Status Pill */}
          <div
            className={`p-2.5 rounded-xl bg-slate-50 dark:bg-slate-900/80 border border-slate-200/80 dark:border-slate-800/80 text-[11px] font-sans ${
              collapsed ? 'flex items-center justify-center' : ''
            }`}
          >
            <div className="flex items-center gap-2.5">
              <span className="relative flex h-2 w-2 shrink-0">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>

              {!collapsed && (
                <div className="truncate">
                  <div className="text-slate-800 dark:text-slate-200 font-medium text-[11px]">
                    Passive Sensor
                  </div>
                  <div className="text-[10px] text-emerald-600 dark:text-emerald-400 font-semibold">
                    READ-ONLY / ONE-WAY
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* User Profile Card */}
          <div
            className={`flex items-center ${
              collapsed ? 'justify-center p-2' : 'gap-2.5 p-2'
            } rounded-xl bg-slate-50 dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800/80`}
          >
            <div className="w-7 h-7 rounded-lg bg-blue-100 dark:bg-blue-950/80 border border-blue-200 dark:border-blue-800 flex items-center justify-center text-blue-600 dark:text-blue-400 font-sans font-bold text-xs shrink-0">
              VS
            </div>

            {!collapsed && (
              <div className="min-w-0 flex-1">
                <div className="text-xs font-medium text-slate-800 dark:text-slate-200 truncate font-sans">
                  Cmdr. Vikram S.
                </div>
                <div className="text-[10px] text-slate-500 dark:text-slate-400 truncate font-sans">
                  SOC Lead
                </div>
              </div>
            )}
          </div>
        </div>
      </aside>
    </>
  );
};