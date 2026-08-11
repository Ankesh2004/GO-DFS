"use client";

import { useEffect, useState } from "react";
import { getStatus, getPeers } from "@/lib/api";
import { Activity, Clock, ShieldAlert, ShieldCheck } from "lucide-react";

export default function NetworkPage() {
  const [healthMap, setHealthMap] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    setLoading(true);
    try {
      const status = await getStatus();
      setHealthMap(status.peerHealth || []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="p-8 space-y-6">
      <header className="mb-8 flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Peer Topology Map</h1>
          <p className="text-white/60">Real-time network health and routing</p>
        </div>
      </header>

      {loading && healthMap.length === 0 ? (
        <div className="text-white/40">Loading network data...</div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {healthMap.map((peer, i) => {
            const isHealthy = peer.status === "HEALTHY";
            return (
              <div key={i} className="bg-white/5 border border-white/10 rounded-xl p-6 relative overflow-hidden">
                {/* Background accent */}
                <div className={`absolute top-0 right-0 w-32 h-32 blur-3xl opacity-20 -mr-16 -mt-16 rounded-full ${isHealthy ? 'bg-emerald-500' : 'bg-rose-500'}`}></div>
                
                <div className="relative z-10">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                      {isHealthy ? (
                        <ShieldCheck className="w-6 h-6 text-emerald-400" />
                      ) : (
                        <ShieldAlert className="w-6 h-6 text-rose-400" />
                      )}
                      <h3 className="font-mono text-lg">{peer.addr}</h3>
                    </div>
                    <span className={`px-2 py-1 rounded text-xs font-bold tracking-wider ${isHealthy ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'}`}>
                      {peer.status}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-4 mt-6">
                    <div className="bg-black/30 rounded-lg p-3 border border-white/5">
                      <div className="text-white/50 text-xs uppercase tracking-wider mb-1 flex items-center gap-2">
                        <Activity className="w-3 h-3" />
                        Avg RTT
                      </div>
                      <div className="text-xl font-bold">{peer.avgRTTMs.toFixed(2)} ms</div>
                    </div>
                    
                    <div className="bg-black/30 rounded-lg p-3 border border-white/5">
                      <div className="text-white/50 text-xs uppercase tracking-wider mb-1 flex items-center gap-2">
                        <Clock className="w-3 h-3" />
                        Uptime Ratio
                      </div>
                      <div className="text-xl font-bold">{(peer.uptimeRatio * 100).toFixed(1)}%</div>
                    </div>
                  </div>

                  <div className="text-xs text-white/40 mt-4 flex justify-between">
                    <span>Missed Pings: {peer.missedPings}</span>
                    <span>Last Seen: {new Date(peer.lastSeen).toLocaleTimeString()}</span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
