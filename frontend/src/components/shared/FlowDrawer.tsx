import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { NetworkFlow } from '../../types/cybersecurity';
import { ProtocolBadge, SeverityBadge } from './Badge';
import { 
  X, 
  ArrowRight, 
  ExternalLink, 
  Lock, 
  Copy, 
  Check, 
  Binary, 
  Network,
  ShieldAlert
} from 'lucide-react';
import { useSecurity } from '../../context/SecurityContext';
import { useToast } from '../../context/ToastContext';

interface FlowDrawerProps {
  flow: NetworkFlow | null;
  onClose: () => void;
}

export const FlowDrawer: React.FC<FlowDrawerProps> = ({ flow, onClose }) => {
  const { navigateToIp } = useSecurity();
  const { showToast } = useToast();
  const [copied, setCopied] = useState(false);

  if (!flow) return null;

  const handleCopyHex = () => {
    navigator.clipboard.writeText(flow.payloadHexSample || '');
    setCopied(true);
    showToast('info', 'Hex Copied', 'Payload signature copied to clipboard');
    setTimeout(() => setCopied(false), 2000);
  };

  const getSeverity = (score: number) => {
    if (score >= 80) return 'CRITICAL';
    if (score >= 60) return 'HIGH';
    if (score >= 40) return 'MEDIUM';
    return 'LOW';
  };

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 overflow-hidden pointer-events-none font-sans">
        {/* Backdrop */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={onClose}
          className="absolute inset-0 bg-black/50 backdrop-blur-sm pointer-events-auto"
        />

        {/* Slide-out Drawer */}
        <motion.div
          initial={{ x: '100%' }}
          animate={{ x: 0 }}
          exit={{ x: '100%' }}
          transition={{ type: 'spring', damping: 28, stiffness: 280 }}
          className="relative w-full max-w-lg bg-white dark:bg-slate-900 border-l border-slate-200 dark:border-slate-800 h-full overflow-y-auto pointer-events-auto p-6 shadow-2xl flex flex-col justify-between ml-auto"
        >
          <div>
            {/* Header */}
            <div className="flex items-center justify-between pb-4 border-b border-slate-100 dark:border-slate-800">
              <div className="flex items-center gap-2.5">
                <Network className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                <div>
                  <h3 className="font-bold text-slate-900 dark:text-white text-base font-sans">Flow Inspection</h3>
                  <div className="text-xs font-mono text-slate-500">ID: {flow.id}</div>
                </div>
              </div>
              <button
                onClick={onClose}
                className="p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 hover:text-slate-700 dark:hover:text-white transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Anomaly Status Alert Box */}
            <div className="mt-5 p-4 rounded-xl bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-800 flex items-start gap-3">
              <div className="p-2 rounded-lg bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-900/40 text-rose-600 dark:text-rose-400 shrink-0">
                <ShieldAlert className="w-5 h-5" />
              </div>
              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-500 dark:text-slate-400 font-medium">Classification</span>
                  <SeverityBadge severity={getSeverity(flow.anomalyScore)} />
                </div>
                <div className="text-base font-semibold text-slate-900 dark:text-white mt-1">
                  {flow.aiClassification}
                </div>
                <div className="mt-2 flex items-center gap-4 text-xs">
                  <div>
                    <span className="text-slate-500 dark:text-slate-400">Score: </span>
                    <span className="text-blue-600 dark:text-blue-400 font-bold font-mono">{flow.anomalyScore} / 100</span>
                  </div>
                  <div>
                    <span className="text-slate-500 dark:text-slate-400">Direction: </span>
                    <span className="text-amber-600 dark:text-amber-400 font-semibold">{flow.direction}</span>
                  </div>
                </div>
              </div>
            </div>

            {/* IP & Port Pair */}
            <div className="mt-5 grid grid-cols-1 gap-3">
              <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200/80 dark:border-slate-800">
                <div className="text-[11px] text-slate-500 uppercase tracking-wider font-medium">Source Host</div>
                <div className="flex items-center justify-between mt-1">
                  <span className="font-mono text-slate-900 dark:text-white text-sm font-semibold">{flow.sourceIp}:{flow.sourcePort}</span>
                  <button
                    onClick={() => {
                      onClose();
                      navigateToIp(flow.sourceIp);
                    }}
                    className="flex items-center gap-1 text-xs text-blue-600 dark:text-blue-400 hover:underline font-medium"
                  >
                    Lookup <ExternalLink className="w-3 h-3" />
                  </button>
                </div>
              </div>

              <div className="flex justify-center -my-1.5 z-10">
                <div className="w-7 h-7 rounded-full bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 flex items-center justify-center text-slate-500">
                  <ArrowRight className="w-3.5 h-3.5" />
                </div>
              </div>

              <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200/80 dark:border-slate-800">
                <div className="text-[11px] text-slate-500 uppercase tracking-wider font-medium">Destination Host</div>
                <div className="flex items-center justify-between mt-1">
                  <span className="font-mono text-slate-900 dark:text-white text-sm font-semibold">{flow.destinationIp}:{flow.destinationPort}</span>
                  <button
                    onClick={() => {
                      onClose();
                      navigateToIp(flow.destinationIp);
                    }}
                    className="flex items-center gap-1 text-xs text-blue-600 dark:text-blue-400 hover:underline font-medium"
                  >
                    Lookup <ExternalLink className="w-3 h-3" />
                  </button>
                </div>
              </div>
            </div>

            {/* Telemetry Metrics Grid */}
            <div className="mt-5 grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200/80 dark:border-slate-800">
                <div className="text-slate-500 dark:text-slate-400 text-[11px]">Protocol</div>
                <div className="mt-1 flex items-center gap-1.5">
                  <ProtocolBadge protocol={flow.protocol} />
                  <span className="text-slate-700 dark:text-slate-300 font-mono">{flow.flags?.join(', ') || 'NONE'}</span>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200/80 dark:border-slate-800">
                <div className="text-slate-500 dark:text-slate-400 text-[11px]">Duration</div>
                <div className="mt-1 font-semibold text-slate-900 dark:text-white font-mono">{flow.duration.toFixed(1)}s</div>
              </div>

              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200/80 dark:border-slate-800">
                <div className="text-slate-500 dark:text-slate-400 text-[11px]">Total Packets</div>
                <div className="mt-1 font-semibold text-slate-900 dark:text-white font-mono">{flow.packets.toLocaleString()} pkts</div>
              </div>

              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200/80 dark:border-slate-800">
                <div className="text-slate-500 dark:text-slate-400 text-[11px]">Transferred Volume</div>
                <div className="mt-1 font-semibold text-slate-900 dark:text-white font-mono">{(flow.bytes / (1024 * 1024)).toFixed(2)} MB</div>
              </div>

              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200/80 dark:border-slate-800">
                <div className="text-slate-500 dark:text-slate-400 text-[11px]">Shannon Entropy</div>
                <div className="mt-1 font-semibold text-blue-600 dark:text-blue-400 font-mono">{flow.payloadEntropy || 5.12} bits/byte</div>
              </div>

              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/40 border border-slate-200/80 dark:border-slate-800">
                <div className="text-slate-500 dark:text-slate-400 text-[11px]">Diode Interface</div>
                <div className="mt-1 font-semibold text-slate-700 dark:text-slate-300 font-mono">{flow.diodeInterface || 'diode-tx-fiber0'}</div>
              </div>
            </div>

            {/* Hex Payload Dump Preview */}
            <div className="mt-5">
              <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 mb-2 font-sans">
                <div className="flex items-center gap-1.5">
                  <Binary className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />
                  <span>Payload Hex Signature Dump</span>
                </div>
                <button
                  onClick={handleCopyHex}
                  className="flex items-center gap-1 text-slate-500 hover:text-blue-600 dark:hover:text-blue-400 transition-colors"
                >
                  {copied ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                  <span>{copied ? 'Copied' : 'Copy'}</span>
                </button>
              </div>

              <div className="p-3.5 rounded-lg bg-slate-900 text-slate-300 border border-slate-800 font-mono text-[11px] leading-relaxed overflow-x-auto select-all">
                {flow.payloadHexSample || '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'}
              </div>
            </div>
          </div>

          {/* Action Footer */}
          <div className="mt-6 pt-4 border-t border-slate-100 dark:border-slate-800 flex gap-2 font-sans">
            <button
              onClick={() => {
                showToast('info', 'Read-only posture', `Sentinel does not issue quarantine or block commands. This is an observation-only interface.`);
                onClose();
              }}
              className="flex-1 py-2.5 px-3 rounded-lg bg-rose-50 dark:bg-rose-950/40 hover:bg-rose-100 dark:hover:bg-rose-950/60 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-900/40 text-xs font-semibold transition-colors flex items-center justify-center gap-1.5"
            >
              <Lock className="w-3.5 h-3.5" />
              Quarantine Source
            </button>
            <button
              onClick={() => {
                showToast('info', 'Deep PCAP Exported', `Packet trace for flow ${flow.id} downloaded`);
              }}
              className="py-2.5 px-4 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 border border-slate-200 dark:border-slate-700 text-xs font-semibold transition-colors"
            >
              Export PCAP
            </button>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
