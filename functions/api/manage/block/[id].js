import { jsonResponse, parseFileKey } from '../../../utils/security.js';

/**
 * 加入黑名单（命中后 /file 侧直接跳拦截页）。
 * 相对旧版的改动：校验 key 形状、记录不存在时返回 404 而不是 500、
 * 不再把整个 env（含 Bot Token / 后台密码）打到日志里。
 */
export async function onRequest(context) {
  const { params, env } = context;

  const parsed = parseFileKey(params?.id);
  if (!parsed) return jsonResponse({ error: '非法的文件标识' }, 400);
  if (!env?.img_url) return jsonResponse({ error: '未绑定 KV' }, 400);

  const record = await env.img_url.getWithMetadata(parsed.key);
  if (!record?.metadata) {
    return jsonResponse({ error: `记录不存在: ${parsed.key}` }, 404);
  }

  const metadata = { ...record.metadata, ListType: 'Block' };
  await env.img_url.put(parsed.key, '', { metadata });

  return jsonResponse(metadata);
}
