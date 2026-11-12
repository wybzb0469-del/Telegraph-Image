import { jsonResponse, parseFileKey } from '../../../utils/security.js';

/**
 * 加入白名单（无视内容审查、无视白名单模式）。
 * 顺带修掉旧版的两个问题：key 未校验、metadata 为空时抛 500、以及 console.log(env)。
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

  const metadata = { ...record.metadata, ListType: 'White' };
  await env.img_url.put(parsed.key, '', { metadata });

  return jsonResponse(metadata);
}
