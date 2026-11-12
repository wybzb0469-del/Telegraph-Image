import { jsonResponse } from '../../utils/security.js';
import { clearLogs, readLogs } from '../../utils/audit-log.js';

/**
 * 日志查询接口（由 ../manage/_middleware.js 鉴权 + CSRF 防护）。
 *
 *   GET    /api/manage/logs?limit=200&type=upload|rejected|blocked&q=关键词
 *   DELETE /api/manage/logs?confirm=yes&limit=200   清空（KV 删除额度每天 1000）
 */

const TYPE_ACTIONS = {
  upload: ['upload'],
  rejected: ['upload_rejected'],
  blocked: ['file_blocked'],
};

export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  const limit = Math.min(Math.max(Number(url.searchParams.get('limit')) || 200, 10), 500);
  const type = (url.searchParams.get('type') || 'all').toLowerCase();
  const keyword = (url.searchParams.get('q') || '').trim().toLowerCase();

  const result = await readLogs(env, { limit, cursor: url.searchParams.get('cursor') || undefined });

  let entries = result.entries;

  if (TYPE_ACTIONS[type]) {
    entries = entries.filter((e) => TYPE_ACTIONS[type].includes(e.action));
  }

  if (keyword) {
    entries = entries.filter((e) =>
      [e.ip, e.ua, e.fileKey, e.fileName, e.country, e.city, e.reason, e.code]
        .filter(Boolean)
        .some((v) => String(v).toLowerCase().includes(keyword))
    );
  }

  const stats = {
    upload: 0,
    rejected: 0,
    blocked: 0,
  };
  for (const e of entries) {
    if (e.action === 'upload') stats.upload += 1;
    if (e.action === 'upload_rejected') stats.rejected += 1;
    if (e.action === 'file_blocked') stats.blocked += 1;
  }

  return jsonResponse({
    enabled: result.enabled,
    total: entries.length,
    stats,
    complete: result.complete,
    cursor: result.cursor || null,
    entries,
  });
}

export async function onRequestDelete(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  if (url.searchParams.get('confirm') !== 'yes') {
    return jsonResponse({ error: '清空日志需要显式确认：追加 &confirm=yes' }, 400);
  }

  const limit = Math.min(Math.max(Number(url.searchParams.get('limit')) || 200, 1), 1000);
  const result = await clearLogs(env, { max: limit });

  return jsonResponse({ success: true, ...result });
}
