/**
 * Telegram 上游访问与图片响应头的公共实现。
 * 原图（file/[id].js）与缩略图（thumb/[id].js）共用，避免两处逻辑漂移。
 */

import { asciiFileName, mimeForExt } from './security.js';

export const TELEGRAM_FILE_ID_MIN_LENGTH = 39;
export const DEFAULT_UPSTREAM_TIMEOUT_MS = 20000;

export function timeoutSignal(ms = DEFAULT_UPSTREAM_TIMEOUT_MS) {
  return typeof AbortSignal !== 'undefined' && AbortSignal.timeout
    ? AbortSignal.timeout(ms)
    : undefined;
}

/**
 * 换取 Telegram 文件路径。
 * file_path 基本稳定，缓存 1 小时可以省掉每次出图前的这次子请求。
 */
export async function getFilePath(env, fileId) {
  try {
    const url = `https://api.telegram.org/bot${env.TG_Bot_Token}/getFile?file_id=${encodeURIComponent(fileId)}`;
    const res = await fetch(url, {
      method: 'GET',
      signal: timeoutSignal(10000),
      cf: { cacheEverything: true, cacheTtl: 3600 },
    });
    if (!res.ok) return null;
    const data = await res.json();
    if (data?.ok && data.result?.file_path) return data.result.file_path;
    return null;
  } catch (error) {
    console.error('telegram: getFilePath failed', error?.message || error);
    return null;
  }
}

/**
 * 统一的图片响应头：
 *  - Content-Type 只由扩展名白名单推导，不信任上游
 *  - nosniff + CSP sandbox，杜绝被当网页/脚本执行
 */
export function buildImageHeaders({ ext, key, upstream, displayName, cacheSeconds = 31536000 }) {
  const headers = new Headers();

  const upstreamType = (upstream.headers.get('content-type') || '').toLowerCase();
  let contentType = mimeForExt(ext);
  if (!contentType) {
    // 历史遗留的无扩展名文件：只接受上游明确声明的图片类型
    contentType = upstreamType.startsWith('image/') ? upstreamType : 'application/octet-stream';
  }

  headers.set('Content-Type', contentType);
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Content-Security-Policy', "default-src 'none'; sandbox");
  headers.set('Cross-Origin-Resource-Policy', 'cross-origin');
  headers.set(
    'Content-Disposition',
    `inline; filename="${asciiFileName(displayName || key)}"`
  );
  headers.set('Cache-Control', `public, max-age=${cacheSeconds}, immutable`);

  for (const name of ['content-length', 'content-range', 'accept-ranges', 'etag', 'last-modified']) {
    const value = upstream.headers.get(name);
    if (value) headers.set(name, value);
  }

  return headers;
}
