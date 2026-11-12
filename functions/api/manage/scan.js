import { isAllowedExt, jsonResponse, parseFileKey } from '../../utils/security.js';

/**
 * 存量清理接口（需后台鉴权，由 ../manage/_middleware.js 保护）。
 *
 * 用途：项目已经被传过马/垃圾文件时，扫描 KV 里所有记录，
 * 找出扩展名不在图片白名单内的 key（.php / .html / .svg / .js ...）。
 *
 *   GET /api/manage/scan                     只报告，不改动任何数据
 *   GET /api/manage/scan?action=block        把命中的记录标记为黑名单（ListType=Block）
 *   GET /api/manage/scan?action=delete&confirm=yes   删除命中的 KV 记录
 *
 * 注意：delete 只删本站 KV 记录，Telegram 频道里的原始文件仍需手动删除。
 * KV 免费额度每天 1000 次写/删，建议分批（默认每批最多 100 条）。
 */

const DEFAULT_SCAN_LIMIT = 1000;
const MAX_SCAN_LIMIT = 5000;
const DEFAULT_ACTION_LIMIT = 100;
const MAX_ACTION_LIMIT = 500;

function clamp(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.min(Math.max(Math.floor(n), min), max);
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  if (!env?.img_url) {
    return jsonResponse({ error: '未绑定 KV（img_url），该功能不可用' }, 400);
  }

  const action = (url.searchParams.get('action') || 'report').toLowerCase();
  if (!['report', 'block', 'delete'].includes(action)) {
    return jsonResponse({ error: 'action 仅支持 report / block / delete' }, 400);
  }
  if (action === 'delete' && url.searchParams.get('confirm') !== 'yes') {
    return jsonResponse(
      { error: '删除操作需要显式确认：追加 &confirm=yes。建议先用 action=report 查看清单。' },
      400
    );
  }

  const scanLimit = clamp(url.searchParams.get('max'), DEFAULT_SCAN_LIMIT, 1, MAX_SCAN_LIMIT);
  const actionLimit = clamp(
    url.searchParams.get('limit'),
    DEFAULT_ACTION_LIMIT,
    1,
    MAX_ACTION_LIMIT
  );

  const suspicious = [];
  let scanned = 0;
  let cursor;
  let truncated = false;

  while (scanned < scanLimit) {
    const page = await env.img_url.list({ limit: Math.min(1000, scanLimit - scanned), cursor });
    if (!page || !Array.isArray(page.keys)) break;

    for (const entry of page.keys) {
      scanned += 1;
      const key = entry?.name;
      if (!key) continue;
      const parsed = parseFileKey(key);
      const bad = !parsed || (parsed.ext && !isAllowedExt(parsed.ext));
      if (bad) suspicious.push(key);
    }

    if (page.list_complete || !page.cursor) {
      cursor = undefined;
      break;
    }
    cursor = page.cursor;
    if (scanned >= scanLimit) {
      truncated = true;
      break;
    }
  }

  const result = {
    scanned,
    suspiciousCount: suspicious.length,
    truncated,
    nextCursor: cursor || null,
    suspicious: suspicious.slice(0, 200),
    suspiciousOverflow: Math.max(0, suspicious.length - 200),
    action,
    changed: 0,
    failed: [],
  };

  if (action === 'block' || action === 'delete') {
    const targets = suspicious.slice(0, actionLimit);
    for (const key of targets) {
      try {
        if (action === 'delete') {
          await env.img_url.delete(key);
        } else {
          const record = await env.img_url.getWithMetadata(key);
          const metadata = record?.metadata || {
            TimeStamp: Date.now(),
            ListType: 'Block',
            Label: 'None',
            liked: false,
            fileName: key,
            fileSize: 0,
          };
          metadata.ListType = 'Block';
          metadata.blockedReason = 'non-image-extension';
          metadata.blockedAt = Date.now();
          await env.img_url.put(key, '', { metadata });
        }
        result.changed += 1;
      } catch (error) {
        result.failed.push({ key, error: error?.message || String(error) });
      }
    }
  }

  return jsonResponse(result);
}
