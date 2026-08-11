"use client";

import { useEffect, useState, useRef } from "react";
import { listFiles, uploadFile, deleteFile } from "@/lib/api";
import { Upload, Trash2, File as FileIcon, Download, RefreshCw } from "lucide-react";

export default function FilesPage() {
  const [files, setFiles] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const fetchFiles = async () => {
    setLoading(true);
    try {
      const data = await listFiles();
      setFiles(data.files || []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFiles();
  }, []);

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files || e.target.files.length === 0) return;
    const file = e.target.files[0];
    
    setUploading(true);
    try {
      const formData = new FormData();
      formData.append("file", file);
      await uploadFile(formData);
      await fetchFiles(); // Refresh list
    } catch (err) {
      console.error("Upload failed", err);
      alert("Upload failed. See console.");
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  const handleDelete = async (cid: string) => {
    if (!confirm("Are you sure you want to delete this file?")) return;
    try {
      await deleteFile(cid);
      await fetchFiles();
    } catch (err) {
      console.error("Delete failed", err);
      alert("Delete failed. See console.");
    }
  };

  // Helper for bytes
  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="p-8">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">File Browser</h1>
          <p className="text-white/60">Manage your distributed files</p>
        </div>
        <div className="flex items-center gap-3">
          <button 
            onClick={fetchFiles}
            className="p-2 bg-white/5 hover:bg-white/10 rounded-xl transition-colors text-white/70"
            title="Refresh"
          >
            <RefreshCw className={`w-5 h-5 ${loading ? 'animate-spin' : ''}`} />
          </button>
          
          <input 
            type="file" 
            ref={fileInputRef} 
            onChange={handleUpload} 
            className="hidden" 
          />
          <button 
            onClick={() => fileInputRef.current?.click()}
            disabled={uploading}
            className="flex items-center gap-2 px-4 py-2 bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-400 rounded-xl transition-colors font-medium disabled:opacity-50"
          >
            <Upload className="w-4 h-4" />
            {uploading ? "Uploading..." : "Upload File"}
          </button>
        </div>
      </div>

      <div className="bg-white/5 border border-white/10 rounded-xl overflow-hidden">
        <table className="w-full text-left">
          <thead className="bg-white/5 border-b border-white/10">
            <tr>
              <th className="p-4 font-medium text-white/60">Name</th>
              <th className="p-4 font-medium text-white/60">CID</th>
              <th className="p-4 font-medium text-white/60">Size</th>
              <th className="p-4 font-medium text-white/60">Chunks</th>
              <th className="p-4 font-medium text-white/60 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {files.length === 0 ? (
              <tr>
                <td colSpan={5} className="p-8 text-center text-white/40">
                  {loading ? "Loading files..." : "No files found."}
                </td>
              </tr>
            ) : (
              files.map((f, i) => (
                <tr key={i} className="hover:bg-white/5 transition-colors">
                  <td className="p-4 flex items-center gap-3">
                    <FileIcon className="w-5 h-5 text-blue-400" />
                    <span className="font-medium">{f.original_name}</span>
                  </td>
                  <td className="p-4 text-xs font-mono text-white/50 truncate max-w-[200px]" title={f.cid}>
                    {f.cid}
                  </td>
                  <td className="p-4 text-white/70">{formatBytes(f.size)}</td>
                  <td className="p-4 text-white/70">{f.chunk_count}</td>
                  <td className="p-4 flex justify-end gap-2">
                    {/* Download Button */}
                    <a 
                      href={`/api/download/${f.cid}`}
                      download={f.original_name}
                      className="p-2 text-blue-400/70 hover:text-blue-400 hover:bg-blue-500/10 rounded-lg transition-colors"
                      title="Download"
                    >
                      <Download className="w-4 h-4" />
                    </a>
                    {/* Delete Button */}
                    <button 
                      onClick={() => handleDelete(f.cid)}
                      className="p-2 text-rose-400/70 hover:text-rose-400 hover:bg-rose-500/10 rounded-lg transition-colors"
                      title="Delete"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
