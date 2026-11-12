import {
  ALLOWED_FORMATS_LABEL,
  DEFAULT_MAX_UPLOAD_BYTES,
  HARD_MAX_UPLOAD_BYTES,
  canonicalExtForMime,
  jsonResponse,
  sanitizeFileName,
  sniffImageMime,
} from './utils/security.js';
import { enforceRateLimit, uploadRateRules } from './utils/rate-limit.js';
import { writeLog } from './utils/audit-log.js';

/**
 * 图片上传接口。
 *
 * 安全约束（与旧版的关键差异）：
 *  1. 先限流，再解析 body —— 超限请求不消耗内存；
 *  2. 文件类型只认文件头魔数，不认客户端 Content-Type；
 *  3. 扩展名由魔数推导，用户文件名只保留展示用主名，不参与路径/存储；
 *  4. 只有图片，没有 sendDocument 的"任意文件"后门（文档降级仅在图片已通过校验时使用）；
 *  5. 大小上限受 Content-Length 与实测 size 双重约束；
 *  6. 任何异常都返回 JSON（带 code），不会再出现无法解析的网关错误页；
 *  7. 成功与拒绝都会写一条审计日志（IP / 时间 / UA / 设备环境），可在后台查看。
 */

function maxUploadBytes(env) {
  const configured = Number(env?.MAX_UPLOAD_SIZE);
  if (Number.isFinite(configured) && configured > 0) {
    return Math.min(Math.floor(configured), HARD_MAX_UPLOAD_BYTES);
  }
  return DEFAULT_MAX_UPLOAD_BYTES;
}

export async function onRequestPost(context) {
  try {
    return await handleUpload(context);
  } catch (error) {
    // 兜底：无论哪里出错都回可解析的 JSON，前端才能显示真实原因
    console.error('upload: unhandled error', error?.stack || error?.message || error);
    void writeLog(context, {
      action: 'upload_rejected',
      ok: false,
      code: 'UPLOAD_FAILED',
      reason: 'unhandled exception',
      status: 500,
    });
    return jsonResponse(
      { error: '上传服务异常，请稍后重试（可访问 /api/health 自查）', code: 'UPLOAD_FAILED' },
      500
    );
  }
}

async function handleUpload(context) {
  const { request, env } = context;
  const startedAt = Date.now();

  /** 统一出口：写日志 + 返回 JSON */
  const fail = (payload, status, extra = {}) => {
    void writeLog(context, {
      action: 'upload_rejected',
      ok: false,
      code: payload.code || 'REJECTED',
      reason: payload.error,
      status,
      durationMs: Date.now() - startedAt,
      ...extra,
    });
    return jsonResponse(payload, status);
  };

  // 1) 限流：放在最前面，挡掉刷接口的请求
  const limited = await enforceRateLimit(context, {
    scope: 'upload',
    rules: uploadRateRules(env),
    kv: env?.RATE_LIMIT_KV || null,
  });
  if (limited) {
    void writeLog(context, {
      action: 'upload_rejected',
      ok: false,
      code: 'RATE_LIMITED',
      reason: 'rate limit exceeded',
      status: 429,
      durationMs: Date.now() - startedAt,
    });
    return limited;
  }

  if (!env?.TG_Bot_Token || !env?.TG_Chat_ID) {
    console.error('upload: TG_Bot_Token / TG_Chat_ID 未配置');
    return fail({ error: '服务端未配置上传凭据', code: 'CONFIG_MISSING' }, 500);
  }

  const maxBytes = maxUploadBytes(env);
  const tooLarge = () => {
    const mb = (maxBytes / 1024 / 1024).toFixed(1).replace(/\.0$/, '');
    return fail({ error: `文件过大，最大支持 ${mb} MB`, code: 'FILE_TOO_LARGE' }, 413);
  };

  // 2) 先看声明大小，避免把超大 body 读进内存
  const declaredLength = Number(request.headers.get('content-length'));
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes + 64 * 1024) {
    return tooLarge();
  }

  let formData;
  try {
    formData = await request.formData();
  } catch (error) {
    return fail(
      { error: '请求体解析失败，请使用 multipart/form-data 上传', code: 'BAD_FORM' },
      400
    );
  }

  const uploadFile = formData.get('file');
  if (!uploadFile || typeof uploadFile === 'string' || typeof uploadFile.arrayBuffer !== 'function') {
    return fail({ error: '未找到上传文件', code: 'NO_FILE' }, 400);
  }
  if (!uploadFile.size) {
    return fail({ error: '文件内容为空', code: 'EMPTY_FILE' }, 400);
  }
  if (uploadFile.size > maxBytes) {
    return tooLarge();
  }

  // 3) 魔数校验：唯一的类型判定依据
  let head;
  try {
    head = new Uint8Array(await uploadFile.slice(0, 64).arrayBuffer());
  } catch (error) {
    return fail({ error: '无法读取文件内容', code: 'READ_FAILED' }, 400);
  }

  const mime = sniffImageMime(head);
  if (!mime) {
    return fail(
      {
        error: `仅允许上传图片文件（${ALLOWED_FORMATS_LABEL}），其他类型一律拒绝`,
        code: 'NOT_IMAGE',
      },
      415,
      { fileName: uploadFile.name, fileSize: uploadFile.size, mime: uploadFile.type }
    );
  }

  const ext = canonicalExtForMime(mime);
  if (!ext) {
    return fail({ error: '不支持的图片格式', code: 'UNSUPPORTED_TYPE' }, 415);
  }

  // 4) 文件名由服务端生成；只有客户端声明的 MIME 与实测不符时才包一层 Blob 纠正它，
  //    正常情况下直接用原始对象，不做任何整块拷贝（大图上传更省内存和 CPU）。
  const fileName = sanitizeFileName(uploadFile.name, ext);
  const uploadBlob = uploadFile.type === mime ? uploadFile : new Blob([uploadFile], { type: mime });

  // 5) 交给 Telegram：只走图片通道
  const result = await sendToTelegram(uploadBlob, fileName, env);
  if (!result.success) {
    console.error('upload: telegram error', result.error);
    return fail(
      { error: result.error || '图片上传失败，请稍后重试', code: result.code || 'TG_FAILED' },
      502,
      { fileName, fileSize: uploadFile.size, mime }
    );
  }

  const ids = extractFileIds(result.data);
  if (!ids) {
    return fail({ error: '未能获取文件标识', code: 'NO_FILE_ID' }, 502, {
      fileName,
      fileSize: uploadFile.size,
      mime,
    });
  }

  const key = `${ids.fileId}.${ext}`;

  // 6) 记录元数据（KV 未绑定时跳过，不影响上传）
  if (env.img_url) {
    try {
      await env.img_url.put(key, '', {
        metadata: {
          TimeStamp: Date.now(),
          ListType: 'None',
          Label: 'None',
          liked: false,
          fileName,
          fileSize: uploadFile.size,
          mimeType: mime,
          // 后台网格用这张小图，别再去下原图
          thumbFileId: ids.thumbFileId || null,
        },
      });
    } catch (error) {
      console.error('upload: kv put failed', error?.message || error);
    }
  }

  void writeLog(context, {
    action: 'upload',
    ok: true,
    code: 'OK',
    status: 200,
    fileKey: key,
    fileName,
    fileSize: uploadFile.size,
    mime,
    durationMs: Date.now() - startedAt,
  });

  return jsonResponse([{ src: `/file/${key}` }], 200);
}

/** 非 POST 明确拒绝，避免落到静态资源兜底 */
export async function onRequestGet() {
  return jsonResponse({ error: '请使用 POST 上传', code: 'METHOD_NOT_ALLOWED' }, 405, {
    Allow: 'POST',
  });
}

/**
 * 从 Telegram 响应里取出「原图 file_id」与「最小缩略图 file_id」。
 * sendPhoto 会返回多档尺寸的 photo 数组；sendDocument 只有 document。
 */
function extractFileIds(response) {
  if (!response?.ok || !response.result) return null;
  const result = response.result;

  if (Array.isArray(result.photo) && result.photo.length) {
    const sorted = [...result.photo].sort((a, b) => (a.file_size || 0) - (b.file_size || 0));
    return {
      thumbFileId: sorted[0]?.file_id || null,
      fileId: sorted[sorted.length - 1]?.file_id || null,
    };
  }

  if (result.document) {
    return { fileId: result.document.file_id, thumbFileId: null };
  }

  return null;
}

/**
 * 只发送图片：优先 sendPhoto（Telegram 会压缩并生成预览）。
 * 仅当 Telegram 因尺寸/体积拒绝这张**已经通过魔数校验的图片**时，
 * 才降级为 sendDocument 保留原图 —— 降级路径不再接受任意文件。
 */
async function sendToTelegram(blob, fileName, env) {
  const apiBase = `https://api.telegram.org/bot${env.TG_Bot_Token}`;
  const timeoutMs = Math.min(Math.max(Number(env.UPLOAD_TIMEOUT_MS) || 15000, 3000), 25000);

  async function call(method, field) {
    const form = new FormData();
    form.append('chat_id', env.TG_Chat_ID);
    // 第三个参数覆盖 multipart 里的文件名，不需要为了改名重建一个 File
    form.append(field, blob, fileName);

    // 必须有超时：Telegram 不可达时不能让请求一直挂着，否则并发几个就能把实例拖死
    const signal = typeof AbortSignal !== 'undefined' && AbortSignal.timeout
      ? AbortSignal.timeout(timeoutMs)
      : undefined;

    const response = await fetch(`${apiBase}/${method}`, {
      method: 'POST',
      body: form,
      signal,
    });

    let data = null;
    try {
      data = await response.json();
    } catch (error) {
      data = null;
    }

    if (response.ok && data?.ok) {
      return { success: true, data };
    }
    return {
      success: false,
      fromTelegram: true,
      status: response.status,
      code: `TG_${response.status}`,
      error: data?.description || `Telegram 返回 ${response.status}`,
    };
  }

  let photoResult;
  try {
    photoResult = await call('sendPhoto', 'photo');
  } catch (error) {
    // 网络层失败（超时/连接被拒）不做降级重试，直接失败，避免双倍等待
    console.error('upload: sendPhoto network error', error?.name, error?.message || error);
    return {
      success: false,
      code: error?.name === 'TimeoutError' ? 'TG_TIMEOUT' : 'TG_UNREACHABLE',
      error:
        error?.name === 'TimeoutError'
          ? 'Telegram 响应超时，请稍后重试'
          : '无法连接 Telegram，请检查网络或访问 /api/health',
    };
  }
  if (photoResult.success) return photoResult;

  // 只有 Telegram 明确拒绝这张**已通过魔数校验的图片**时才转文档，仍然是同一张图片
  console.warn('upload: sendPhoto 失败，改用文档方式保留原图:', photoResult.error);
  try {
    const documentResult = await call('sendDocument', 'document');
    if (documentResult.success) return documentResult;
    return {
      success: false,
      code: documentResult.code,
      error: documentResult.error || '图片上传失败',
    };
  } catch (error) {
    console.error('upload: sendDocument network error', error?.name, error?.message || error);
    return { success: false, code: 'TG_UNREACHABLE', error: '无法连接 Telegram，请稍后重试' };
  }
}
