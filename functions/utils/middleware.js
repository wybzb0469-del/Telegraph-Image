// 遥测与错误上报已移除（去云依赖）：不再向任何外部服务发送数据。

/**
 * 统一异常兜底。
 * 只把通用信息返回给客户端，堆栈仅写日志 —— 避免内部实现细节外泄。
 */
export async function errorHandling(context) {
  try {
    return await context.next();
  } catch (error) {
    console.error('unhandled error:', error?.stack || error?.message || error);
    return new Response(JSON.stringify({ error: '服务内部错误' }), {
      status: 500,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
      },
    });
  }
}

export async function telemetryData(context) {
  return context.next();
}

export async function traceData(context, span, op, name) {
  // 遥测已移除，空实现
}
