"use client";

import { useEffect, useState } from "react";
import { getMetrics, getStatus } from "@/lib/api";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, LineChart, Line } from "recharts";
import { Database, AlertTriangle, ArrowUpRight, CheckCircle2 } from "lucide-react";

export default function MetricsPage() {
  const [status, setStatus] = useState<any>(null);
  const [metrics, setMetrics] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [statusData, metricsData] = await Promise.all([getStatus(), getMetrics()]);
        setStatus(statusData);
        setMetrics(metricsData);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    };
    
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  if (loading && !status) return <div className="p-8 text-white/40">Loading metrics...</div>;
  if (!status) return <div className="p-8 text-rose-400">Failed to load metrics.</div>;

  const rep = status.replication || {};
  const isHealthy = rep.underReplicated === 0 && rep.overReplicated === 0;

  // Prepare chart data for placement history (dummy aggregation based on timestamps)
  const placements = metrics?.placements || [];
  const evictions = metrics?.evictions || [];
  
  // Very simple timeline data
  const chartData = placements.slice(-20).map((p: any, i: number) => ({
    name: `T-${20-i}`,
    reward: p.Reward,
    qVal: p.QValue,
    latency: p.State ? p.State[0] : 0, 
    cost: p.State ? p.State[1] : 0,
  }));

  return (
    <div className="p-8 space-y-6">
      <header className="mb-8 flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Node Health Monitor</h1>
          <p className="text-white/60">Replication audits and Reinforcement Learning metrics</p>
        </div>
      </header>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-white/5 border border-white/10 rounded-xl p-6 relative overflow-hidden">
          <div className="relative z-10">
            <h3 className="text-white/60 font-medium mb-4 flex items-center gap-2">
              <Database className="w-4 h-4" />
              Replication Status
            </h3>
            
            <div className="flex items-end gap-4 mb-2">
              <div className="text-4xl font-bold">{rep.healthy}</div>
              <div className="text-emerald-400 font-medium mb-1">Healthy chunks</div>
            </div>
            
            <div className="text-sm mt-4 space-y-2">
              <div className="flex justify-between items-center text-rose-400">
                <span>Under-replicated:</span>
                <span className="font-bold bg-rose-400/20 px-2 py-0.5 rounded">{rep.underReplicated}</span>
              </div>
              <div className="flex justify-between items-center text-blue-400">
                <span>Over-replicated:</span>
                <span className="font-bold bg-blue-400/20 px-2 py-0.5 rounded">{rep.overReplicated}</span>
              </div>
            </div>
          </div>
          
          <div className="absolute right-0 top-0 h-full w-1/3 bg-gradient-to-l from-emerald-500/10 to-transparent"></div>
        </div>

        <div className="bg-white/5 border border-white/10 rounded-xl p-6 relative overflow-hidden">
          <div className="relative z-10">
            <h3 className="text-white/60 font-medium mb-4 flex items-center gap-2">
              <ArrowUpRight className="w-4 h-4" />
              RL Optimizer Status
            </h3>
            <div className="flex items-center gap-3 mb-4">
              {status.rl?.enabled ? (
                <span className="px-3 py-1 bg-emerald-500/20 text-emerald-400 rounded-full text-sm font-medium flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                  Active
                </span>
              ) : (
                <span className="px-3 py-1 bg-white/10 text-white/40 rounded-full text-sm font-medium">
                  Disabled
                </span>
              )}
            </div>
            
            {status.rl?.enabled && (
              <div className="text-sm text-white/50 space-y-1">
                <p>Total Placements: {metrics?.summary?.total_placements || 0}</p>
                <p>Total Evictions: {metrics?.summary?.total_evictions || 0}</p>
                <p className="truncate" title={status.rl?.sidecarURL}>Sidecar: {status.rl?.sidecarURL}</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Chart Section */}
      {status.rl?.enabled && chartData.length > 0 && (
        <div className="bg-white/5 border border-white/10 rounded-xl p-6 mt-8">
          <h3 className="text-white/80 font-medium mb-6">Recent RL Placements (Rewards & Q-Values)</h3>
          <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#ffffff20" vertical={false} />
                <XAxis dataKey="name" stroke="#ffffff60" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis yAxisId="left" stroke="#emerald-400" fontSize={12} tickLine={false} axisLine={false} tickFormatter={(v) => v.toFixed(2)} />
                <YAxis yAxisId="right" orientation="right" stroke="#blue-400" fontSize={12} tickLine={false} axisLine={false} tickFormatter={(v) => v.toFixed(2)} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#12121a', borderColor: '#ffffff20', borderRadius: '8px' }}
                  itemStyle={{ color: '#fff' }}
                />
                <Line yAxisId="left" type="monotone" dataKey="reward" stroke="#34d399" strokeWidth={2} dot={{ r: 4, fill: '#34d399' }} name="Reward" />
                <Line yAxisId="right" type="monotone" dataKey="qVal" stroke="#60a5fa" strokeWidth={2} dot={{ r: 4, fill: '#60a5fa' }} name="Q-Value" />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}
    </div>
  );
}
