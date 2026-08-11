import { getStatus, getId } from "@/lib/api";
import { Server, HardDrive, Network, Zap } from "lucide-react";

export default async function DashboardPage() {
  let status, id;
  try {
    [status, id] = await Promise.all([getStatus(), getId()]);
  } catch (error) {
    return (
      <div className="p-8">
        <div className="bg-red-500/10 border border-red-500/20 text-red-400 p-4 rounded-xl">
          <h2 className="text-lg font-bold">Connection Error</h2>
          <p>Failed to connect to the GO-DFS API. Is the daemon running?</p>
        </div>
      </div>
    );
  }

  const peersCount = status.peerHealth?.length || 0;
  const filesCount = status.storedFiles || 0;

  return (
    <div className="p-8 space-y-6">
      <header className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">Dashboard Overview</h1>
        <p className="text-white/60">Node {id.nodeID}</p>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white/5 border border-white/10 rounded-xl p-6 backdrop-blur-sm">
          <div className="flex items-center gap-3 mb-2">
            <Server className="w-5 h-5 text-blue-400" />
            <h3 className="font-medium text-white/80">Status</h3>
          </div>
          <p className="text-2xl font-bold text-emerald-400">Online</p>
          <p className="text-xs text-white/40 mt-1">{id.advertiseAddr}</p>
        </div>

        <div className="bg-white/5 border border-white/10 rounded-xl p-6 backdrop-blur-sm">
          <div className="flex items-center gap-3 mb-2">
            <Network className="w-5 h-5 text-purple-400" />
            <h3 className="font-medium text-white/80">Connected Peers</h3>
          </div>
          <p className="text-2xl font-bold">{peersCount}</p>
        </div>

        <div className="bg-white/5 border border-white/10 rounded-xl p-6 backdrop-blur-sm">
          <div className="flex items-center gap-3 mb-2">
            <HardDrive className="w-5 h-5 text-emerald-400" />
            <h3 className="font-medium text-white/80">Stored Files</h3>
          </div>
          <p className="text-2xl font-bold">{filesCount}</p>
        </div>

        <div className="bg-white/5 border border-white/10 rounded-xl p-6 backdrop-blur-sm">
          <div className="flex items-center gap-3 mb-2">
            <Zap className="w-5 h-5 text-rose-400" />
            <h3 className="font-medium text-white/80">Storage Tier</h3>
          </div>
          <p className="text-2xl font-bold uppercase">{status.storageProfile?.tier || "UNKNOWN"}</p>
          <p className="text-xs text-white/40 mt-1">Latency: {status.storageProfile?.latencyMs}ms</p>
        </div>
      </div>
    </div>
  );
}
