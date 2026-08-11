"use server";

import fs from "fs/promises";
import path from "path";

// Helper to find the token
async function getApiToken(): Promise<string> {
  if (process.env.API_TOKEN) return process.env.API_TOKEN;

  // Try to find the latest cas_ folder in the parent directory
  try {
    const parentDir = path.resolve(process.cwd(), "..");
    const dirs = await fs.readdir(parentDir);
    const casDirs = dirs.filter((d) => d.startsWith("cas_"));
    
    if (casDirs.length > 0) {
      // Find the first casDir with an api_token
      for (const casDir of casDirs) {
        const tokenPath = path.join(parentDir, casDir, "api_token");
        try {
          const token = await fs.readFile(tokenPath, "utf-8");
          return token.trim();
        } catch (e) {
          continue;
        }
      }
    }
  } catch (e) {
    // Ignore and fallback
  }

  return "";
}

const API_BASE_URL = process.env.GO_API_URL || "http://127.0.0.1:9000/api";

async function fetchGoApi(endpoint: string, options: RequestInit = {}) {
  const token = await getApiToken();
  const headers = new Headers(options.headers);
  if (token) {
    headers.set("X-Local-Auth", token);
  }

  const res = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers,
    cache: "no-store",
  });

  if (!res.ok) {
    let errorMessage = `HTTP error! status: ${res.status}`;
    try {
      const errorData = await res.json();
      if (errorData.error) {
        errorMessage = errorData.error;
      }
    } catch (e) {}
    throw new Error(errorMessage);
  }
  return res;
}

export async function getId() {
  const res = await fetchGoApi("/id");
  return res.json();
}

export async function getStatus() {
  const res = await fetchGoApi("/status");
  return res.json();
}

export async function getMetrics() {
  const res = await fetchGoApi("/metrics");
  return res.json();
}

export async function getPeers() {
  const res = await fetchGoApi("/peers");
  return res.json();
}

export async function listFiles() {
  const res = await fetchGoApi("/ls");
  return res.json();
}

export async function deleteFile(cid: string) {
  const res = await fetchGoApi(`/rm/${cid}`, { method: "DELETE" });
  return res.json();
}

export async function uploadFile(formData: FormData) {
  const res = await fetchGoApi("/put", {
    method: "POST",
    body: formData,
  });
  return res.json();
}
