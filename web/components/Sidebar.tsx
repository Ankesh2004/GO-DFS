import Link from "next/link";
import { LayoutDashboard, Folder, Network, Activity } from "lucide-react";

export function Sidebar() {
  return (
    <aside className="w-64 border-r border-white/10 bg-black/50 backdrop-blur-md hidden md:flex flex-col h-screen fixed left-0 top-0">
      <div className="p-6 border-b border-white/10">
        <h1 className="text-xl font-bold tracking-tight bg-gradient-to-r from-blue-400 to-emerald-400 bg-clip-text text-transparent">
          GO-DFS
        </h1>
        <p className="text-xs text-white/50 mt-1 uppercase tracking-widest font-mono">Control Panel</p>
      </div>

      <nav className="flex-1 p-4 space-y-2">
        <Link
          href="/"
          className="flex items-center gap-3 px-4 py-3 rounded-xl text-white/70 hover:text-white hover:bg-white/5 transition-all group"
        >
          <LayoutDashboard className="w-5 h-5 group-hover:text-blue-400 transition-colors" />
          <span className="font-medium">Dashboard</span>
        </Link>

        <Link
          href="/files"
          className="flex items-center gap-3 px-4 py-3 rounded-xl text-white/70 hover:text-white hover:bg-white/5 transition-all group"
        >
          <Folder className="w-5 h-5 group-hover:text-emerald-400 transition-colors" />
          <span className="font-medium">File Browser</span>
        </Link>

        <Link
          href="/network"
          className="flex items-center gap-3 px-4 py-3 rounded-xl text-white/70 hover:text-white hover:bg-white/5 transition-all group"
        >
          <Network className="w-5 h-5 group-hover:text-purple-400 transition-colors" />
          <span className="font-medium">Topology Map</span>
        </Link>

        <Link
          href="/metrics"
          className="flex items-center gap-3 px-4 py-3 rounded-xl text-white/70 hover:text-white hover:bg-white/5 transition-all group"
        >
          <Activity className="w-5 h-5 group-hover:text-rose-400 transition-colors" />
          <span className="font-medium">Health Monitor</span>
        </Link>
      </nav>

      <div className="p-6 text-xs text-white/40 border-t border-white/10 font-mono">
        Status: <span className="text-emerald-400">Connected</span>
      </div>
    </aside>
  );
}
