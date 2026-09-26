import React, { useRef } from 'react';
import { Shield, Radio, Upload, Play, Network, LockKeyhole } from 'lucide-react';
import { Logo } from '../components/shared/Logo';
import { useSecurity } from '../context/SecurityContext';
import { useTheme } from '../context/ThemeContext';

export const LandingPage: React.FC = () => {
  const {
    startStream, scenario, setScenario, backendOnline, sourceMode, connection,
    interfaces, selectedInterface, setSelectedInterface, analyzePcap,
  } = useSecurity();
  const input = useRef<HTMLInputElement>(null);
  const { theme, toggleTheme } = useTheme();

  return (
    <div className="min-h-screen bg-[var(--bg-primary)] flex items-center justify-center p-6">
      <div className="w-full max-w-6xl">
        <div className="flex justify-between items-center mb-10">
          <Logo size="lg" />
          <button onClick={toggleTheme} className="text-xs px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-800">
            {theme === 'dark' ? 'Light' : 'Dark'} mode
          </button>
        </div>

        <div className="glass-card rounded-3xl p-8 lg:p-12">
          <div className="max-w-3xl">
            <div className="flex items-center gap-2 text-xs text-cyan-500 font-semibold">
              <span className="w-2 h-2 rounded-full bg-cyan-500 animate-pulse" /> PASSIVE / READ-ONLY ANALYTICS
            </div>
            <h1 className="text-4xl lg:text-6xl font-black tracking-tight mt-4">Sentinel</h1>
            <p className="text-xl text-slate-500 dark:text-slate-400 mt-3">
              AI-based detection of cyber threats in unidirectional IP traffic.
            </p>
            <p className="text-sm text-slate-500 mt-5 max-w-2xl">
              The frontend is connected directly to the Sentinel analytical backend. Every dashboard value below is derived from packet/flow metadata emitted by the backend.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-4 mt-10">
            <button onClick={() => startStream('demo')} className="p-5 rounded-2xl border border-blue-500/30 bg-blue-500/10 text-left">
              <Play className="w-5 h-5 text-blue-500" />
              <b className="block mt-4">Run backend demo</b>
              <span className="text-xs text-slate-500">Replay a detector scenario through the real pipeline.</span>
            </button>
            <button onClick={() => input.current?.click()} className="p-5 rounded-2xl border border-amber-500/30 bg-amber-500/10 text-left">
              <Upload className="w-5 h-5 text-amber-500" />
              <b className="block mt-4">Analyze a PCAP</b>
              <span className="text-xs text-slate-500">Send a capture to POST /analyze and inspect its output.</span>
            </button>
            <button onClick={() => startStream('live')} className="p-5 rounded-2xl border border-emerald-500/30 bg-emerald-500/10 text-left">
              <Radio className="w-5 h-5 text-emerald-500" />
              <b className="block mt-4">Capture live traffic</b>
              <span className="text-xs text-slate-500">Passive Npcap/Scapy capture; no probes or mitigation.</span>
            </button>
          </div>

          <input ref={input} type="file" accept=".pcap,.pcapng" className="hidden" onChange={e => e.target.files?.[0] && analyzePcap(e.target.files[0])} />

          <div className="mt-8 grid lg:grid-cols-3 gap-4">
            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800">
              <span className="text-[10px] uppercase text-slate-500">Backend</span>
              <b className={`block mt-1 ${backendOnline ? 'text-emerald-500' : 'text-rose-500'}`}>{backendOnline ? 'ONLINE' : 'OFFLINE'}</b>
            </div>
            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800">
              <span className="text-[10px] uppercase text-slate-500">Demo scenario</span>
              <select value={scenario} onChange={e => setScenario(e.target.value)} className="block mt-1 w-full bg-transparent font-semibold text-sm">
                <option value="normal">Baseline / Normal</option>
                <option value="syn">SYN Flood + Spoofed Sources</option>
                <option value="udp">UDP Reflection / Amplification</option>
                <option value="scan">Recon + Port Scan</option>
                <option value="dns">DGA + DNS Tunnelling</option>
                <option value="c2">Periodic C2 Beacon</option>
                <option value="encrypted">Encrypted Malware</option>
                <option value="exfil">Data Exfiltration</option>
                <option value="full-chain">Full Kill-Chain Demonstration</option>
              </select>
            </div>
            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800">
              <span className="text-[10px] uppercase text-slate-500">Live interface</span>
              <select value={selectedInterface} onChange={e => setSelectedInterface(e.target.value)} className="block mt-1 w-full bg-transparent font-semibold text-sm">
                <option value="">Select capture interface</option>
                {interfaces.map((x, i) => <option key={i} value={x.name}>{x.display_name || x.friendly_name || x.name}</option>)}
              </select>
            </div>
          </div>

          <div className="mt-8 flex flex-wrap gap-5 text-xs text-slate-500">
            <span className="flex items-center gap-2"><Shield className="w-4 h-4" /> No mitigation commands</span>
            <span className="flex items-center gap-2"><LockKeyhole className="w-4 h-4" /> No payload decryption</span>
            <span className="flex items-center gap-2"><Network className="w-4 h-4" /> One-way traffic model</span>
            <span>State: {connection}</span>
            <span>Source: {sourceMode}</span>
          </div>
        </div>
      </div>
    </div>
  );
};
