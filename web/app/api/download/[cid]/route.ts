import { NextRequest, NextResponse } from "next/server";
import fs from "fs/promises";
import path from "path";

async function getApiToken(): Promise<string> {
  if (process.env.API_TOKEN) return process.env.API_TOKEN;

  try {
    const parentDir = path.resolve(process.cwd(), "..");
    const dirs = await fs.readdir(parentDir);
    const casDirs = dirs.filter((d) => d.startsWith("cas_"));
    
    if (casDirs.length > 0) {
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
  } catch (e) {}

  return "";
}

const API_BASE_URL = process.env.GO_API_URL || "http://127.0.0.1:9000/api";

export async function GET(
  request: NextRequest,
  { params }: { params: { cid: string } }
) {
  const cid = params.cid;
  const token = await getApiToken();

  try {
    const res = await fetch(`${API_BASE_URL}/get/${cid}`, {
      headers: token ? { "X-Local-Auth": token } : undefined,
    });

    if (!res.ok) {
      const errBody = await res.text();
      return new NextResponse(`Go API Error (${res.status}): ${errBody}`, { status: res.status });
    }

    const headers = new Headers();
    res.headers.forEach((value, key) => {
      // Avoid copying chunked encoding header which breaks Next.js responses
      if (key.toLowerCase() !== "transfer-encoding" && key.toLowerCase() !== "content-encoding") {
        headers.set(key, value);
      }
    });

    return new NextResponse(res.body as any, {
      status: res.status,
      headers,
    });
  } catch (error: any) {
    console.error("Proxy error:", error);
    return new NextResponse(`API Proxy Error: ${error?.message || "Unknown error"}`, { status: 500 });
  }
}
