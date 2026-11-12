/**
 * 统一安全工具：图片类型白名单 / 魔数校验 / 文件名清洗 / 响应头加固。
 *
 * 核心原则：客户端提供的 MIME、扩展名、文件名一律视为不可信输入，
 * 文件真实类型只以文件头（magic bytes）为准。
 */

/**
 * 允许的图片类型。故意排除以下几类：
 *  - SVG：本质是 XML，可内嵌 <script>/<foreignObject>，同源托管等于给自己开存储型 XSS；
 *  - ICO / TIFF：浏览器展示能力差，且 Telegram 无法当图片处理；
 *  - HEIC/HEIF：兼容性差，且容易被当作任意二进制容器。
 * 需要放宽时改这里，并在 PR 里说明原因。
 */
const IMAGE_TYPES = [
  { mime: 'image/jpeg', ext: 'jpg', alts: ['jpg', 'jpeg', 'jpe', 'jfif'] },
  { mime: 'image/png', ext: 'png', alts: ['png', 'apng'] },
  { mime: 'image/gif', ext: 'gif', alts: ['gif'] },
  { mime: 'image/webp', ext: 'webp', alts: ['webp'] },
  { mime: 'image/bmp', ext: 'bmp', alts: ['bmp', 'dib'] },
  { mime: 'image/avif', ext: 'avif', alts: ['avif'] },
];

const EXT_TO_TYPE = new Map();
for (const t of IMAGE_TYPES) {
  for (const alt of t.alts) EXT_TO_TYPE.set(alt, t);
}

/** 对外展示的允许类型清单，用于错误提示 */
export const ALLOWED_FORMATS_LABEL = 'JPG / PNG / GIF / WebP / BMP / AVIF';

/** 默认单文件上限：10 MB（Telegram sendPhoto 的硬上限） */
export const DEFAULT_MAX_UPLOAD_BYTES = 10 * 1024 * 1024;
/** 硬上限，即使环境变量填得更大也不会突破 */
export const HARD_MAX_UPLOAD_BYTES = 20 * 1024 * 1024;

function ascii(bytes, start, end) {
  let out = '';
  for (let i = start; i < end && i < bytes.length; i += 1) {
    out += String.fromCharCode(bytes[i]);
  }
  return out;
}

/**
 * 通过文件头判断真实图片类型。无法识别一律返回 null（=拒绝）。
 * @param {Uint8Array|ArrayBuffer} input
 * @returns {string|null} 规范化的 MIME
 */
export function sniffImageMime(input) {
  const b = input instanceof Uint8Array ? input : new Uint8Array(input || []);
  if (!b.length) return null;

  // JPEG: FF D8 FF
  if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image/jpeg';

  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (
    b.length >= 8 &&
    b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47 &&
    b[4] === 0x0d && b[5] === 0x0a && b[6] === 0x1a && b[7] === 0x0a
  ) return 'image/png';

  // GIF: GIF87a / GIF89a
  if (b.length >= 6 && ascii(b, 0, 3) === 'GIF') {
    const version = ascii(b, 3, 6);
    if (version === '87a' || version === '89a') return 'image/gif';
  }

  // WebP: RIFF....WEBP
  if (b.length >= 12 && ascii(b, 0, 4) === 'RIFF' && ascii(b, 8, 12) === 'WEBP') return 'image/webp';

  // BMP: 42 4D + 合理的文件头长度字段
  if (b.length >= 14 && b[0] === 0x42 && b[1] === 0x4d) return 'image/bmp';

  // AVIF: ....ftypavif / avis
  if (b.length >= 12 && ascii(b, 4, 8) === 'ftyp') {
    const brand = ascii(b, 8, 12);
    if (brand === 'avif' || brand === 'avis') return 'image/avif';
  }

  return null;
}

/** 按 MIME 取规范扩展名（不含点） */
export function canonicalExtForMime(mime) {
  const t = IMAGE_TYPES.find((item) => item.mime === mime);
  return t ? t.ext : null;
}

/** 按扩展名取规范化 MIME，非白名单返回 null */
export function mimeForExt(ext) {
  if (!ext) return null;
  const t = EXT_TO_TYPE.get(String(ext).toLowerCase());
  return t ? t.mime : null;
}

/** 扩展名是否在图片白名单内（含别名，如 jpeg） */
export function isAllowedExt(ext) {
  if (!ext) return false;
  return EXT_TO_TYPE.has(String(ext).toLowerCase());
}

/** 从文件名里取小写扩展名（不带点），没有则返回 '' */
export function extFromName(name) {
  if (typeof name !== 'string') return '';
  const base = name.split(/[\\/]/).pop() || '';
  const dot = base.lastIndexOf('.');
  if (dot <= 0 || dot === base.length - 1) return '';
  return base.slice(dot + 1).toLowerCase();
}

/**
 * 清洗文件名：去掉目录、控制字符、危险符号，强制使用白名单扩展名。
 * 返回值可直接写入 KV metadata 与 Content-Disposition。
 */
export function sanitizeFileName(name, ext) {
  const safeExt = isAllowedExt(ext) ? String(ext).toLowerCase() : 'jpg';
  let base = typeof name === 'string' ? name : '';
  base = base.split(/[\\/]/).pop() || '';
  base = base.replace(/[\u0000-\u001F\u007F]/g, '').trim();
  if (typeof base.normalize === 'function') base = base.normalize('NFC');
  const dot = base.lastIndexOf('.');
  if (dot > 0) base = base.slice(0, dot);
  base = base
    .replace(/[^\p{L}\p{N}._\- ]/gu, '_')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 80);
  if (!base || base === '.' || base === '..') base = 'image';
  return `${base}.${safeExt}`;
}

/**
 * 解析 /file/:key 的 key（形如 <fileId>.<ext> 或历史遗留的 <fileId>）。
 * 不合法返回 null —— 用于挡掉路径穿越、控制字符、超长垃圾。
 */
export function parseFileKey(raw) {
  if (typeof raw !== 'string') return null;
  const key = raw.trim();
  if (!key || key.length > 200) return null;
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]*(\.[A-Za-z0-9]{1,8})?$/.test(key)) return null;
  const dot = key.lastIndexOf('.');
  const id = dot > 0 ? key.slice(0, dot) : key;
  const ext = dot > 0 ? key.slice(dot + 1).toLowerCase() : '';
  return { id, key, ext };
}

/** 取真实客户端 IP（Cloudflare 头优先） */
export function clientIp(request) {
  const cf = request.headers.get('cf-connecting-ip');
  if (cf) return cf.trim().slice(0, 64);
  const xff = request.headers.get('x-forwarded-for');
  if (xff) return xff.split(',')[0].trim().slice(0, 64);
  return 'unknown';
}

/** 统一的 JSON 响应 */
export function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...extraHeaders,
    },
  });
}

/** 统一的 404（不区分「不存在」和「被拒绝」，避免探测） */
export function notFoundResponse() {
  return new Response('Not Found', {
    status: 404,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

/** Content-Disposition 的 ASCII 兜底名 */
export function asciiFileName(name) {
  const cleaned = String(name || 'image')
    .replace(/[^\x20-\x7E]/g, '_')
    .replace(/["\\]/g, '_');
  return cleaned || 'image';
}

/** 定长比较，避免凭据比较被计时侧信道利用 */
export async function constantTimeEquals(a, b) {
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(String(a ?? ''))),
    crypto.subtle.digest('SHA-256', enc.encode(String(b ?? ''))),
  ]);
  const va = new Uint8Array(ha);
  const vb = new Uint8Array(hb);
  let diff = va.length ^ vb.length;
  for (let i = 0; i < va.length; i += 1) diff |= va[i] ^ vb[i];
  return diff === 0;
}

/** 从环境变量读正整数，带上下限 */
export function intEnv(raw, fallback, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.min(Math.max(Math.floor(n), min), max);
}

/**
 * 跨站来源判定，用于后台接口防 CSRF。
 *
 * 背景：后台用 Basic 认证，浏览器会把凭据自动附加到同源请求上，
 * 因此第三方页面只要构造 <img src="https://站点/api/manage/delete/KEY">，
 * 就能借管理员的凭据执行删除/拉黑。校验做在源头。
 *
 * 返回 null 表示同源（或无法判定，如 curl 直连），否则返回原因。
 */
export function crossSiteReason(request, url) {
  const site = request.headers.get('sec-fetch-site');
  const origin = request.headers.get('origin');
  const referer = request.headers.get('referer');

  // 现代浏览器：明确标记为跨站
  if (site === 'cross-site') return 'sec-fetch-site=cross-site';
  // 带了 Origin 就必须与本服务同源
  if (origin && origin !== url.origin) return `origin=${origin}`;
  // 老浏览器兜底：只有 Referer 时按前缀判断
  if (!site && !origin && referer && !referer.startsWith(`${url.origin}/`)) {
    return `referer=${referer}`;
  }
  return null;
}

