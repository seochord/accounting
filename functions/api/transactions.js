// /api/transactions
// GET  : 저장된 거래 전체를 JSON으로 반환
// POST : 거래 배열 전체를 저장 (덮어쓰기 방식, last-write-wins)
//
// 필요한 설정 (Cloudflare 대시보드 > Pages 프로젝트 > Settings):
//   1) Functions > KV namespace bindings
//        변수 이름: LEDGER_KV   (반드시 이 이름이어야 아래 코드가 동작함)
//        네임스페이스: 새로 만든 KV 네임스페이스 선택 (Production / Preview 둘 다)
//   2) Settings > Environment variables (Secret)
//        변수 이름: LEDGER_PASSCODE
//        값: 원하는 접근 암호 (Production / Preview 둘 다 설정)
//        ※ 12자 이상의 긴 문장형 암호를 권장합니다.
//
// 보안 설계 요약
//   - 암호 비교는 SHA-256 해시 후 상수 시간(timing-safe) 비교
//   - 같은 IP에서 암호를 10회 틀리면 15분간 차단(무차별 대입 방지)
//   - 저장 시 허용된 필드만 남기고 형식/길이를 엄격히 검증(저장형 XSS·데이터 오염 방지)
//   - 덮어쓰기 직전 버전을 1개 보관(실수·오염 복구용)
//   - 오류 응답에 내부 오류 메시지를 노출하지 않음

const KV_KEY = "transactions";
const KV_BACKUP_KEY = "transactions:prev";

const MAX_BODY_BYTES = 5 * 1024 * 1024; // 요청 본문 최대 5MB
const MAX_TRANSACTIONS = 50000;
const MAX_AMOUNT = 1e13;
const FAIL_LIMIT = 10; // 허용 실패 횟수
const FAIL_WINDOW_SEC = 15 * 60; // 차단/집계 유지 시간

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const ID_RE = /^[A-Za-z0-9_.:-]{1,100}$/;

const BASE_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
};

function json(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...BASE_HEADERS, ...extraHeaders },
  });
}

function unauthorized() {
  return json({ error: "암호가 올바르지 않습니다." }, 401);
}

/* ---------- 인증 ---------- */

async function sha256(text) {
  const data = new TextEncoder().encode(text);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

// 길이가 같은 해시끼리 비교하므로 입력 길이·내용에 따른 시간 차이가 생기지 않는다.
async function safeEqual(a, b) {
  const [ha, hb] = await Promise.all([sha256(a), sha256(b)]);
  if (typeof crypto.subtle.timingSafeEqual === "function") {
    return crypto.subtle.timingSafeEqual(ha, hb);
  }
  let diff = 0;
  for (let i = 0; i < ha.length; i++) diff |= ha[i] ^ hb[i];
  return diff === 0;
}

function failKey(request) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  return "authfail:" + ip;
}

// 인증 성공이면 null, 실패면 보낼 Response를 반환한다.
async function authenticate(request, env) {
  const expected = env.LEDGER_PASSCODE || "";
  // 서버에 암호가 설정되지 않았으면(설정 누락) 접근을 막는다 — 열린 API 방지
  if (!expected) return unauthorized();

  const key = failKey(request);
  const failCount = parseInt((await env.LEDGER_KV.get(key)) || "0", 10) || 0;
  if (failCount >= FAIL_LIMIT) {
    return json(
      { error: "암호를 너무 많이 틀렸습니다. 15분 후 다시 시도해 주세요." },
      429,
      { "Retry-After": String(FAIL_WINDOW_SEC) }
    );
  }

  const provided = request.headers.get("X-Passcode") || "";
  if (!(await safeEqual(provided, expected))) {
    await env.LEDGER_KV.put(key, String(failCount + 1), {
      expirationTtl: FAIL_WINDOW_SEC,
    });
    return unauthorized();
  }

  if (failCount > 0) await env.LEDGER_KV.delete(key);
  return null;
}

/* ---------- 입력 검증 ---------- */

function optionalString(obj, field, max) {
  const v = obj[field];
  if (v === undefined || v === null) return { ok: true, value: undefined };
  if (typeof v !== "string" || v.length > max) return { ok: false };
  return { ok: true, value: v };
}

// 올바르면 허용 필드만 담은 새 객체를, 아니면 null을 반환한다.
function sanitizeTransaction(t) {
  if (!t || typeof t !== "object" || Array.isArray(t)) return null;
  if (typeof t.id !== "string" || !ID_RE.test(t.id)) return null;
  if (typeof t.date !== "string" || !DATE_RE.test(t.date)) return null;
  if (Number.isNaN(Date.parse(t.date))) return null;
  if (t.type !== "income" && t.type !== "expense") return null;
  if (typeof t.amount !== "number" || !Number.isFinite(t.amount)) return null;
  if (Math.abs(t.amount) > MAX_AMOUNT) return null;

  const account = optionalString(t, "account", 100);
  const memo = optionalString(t, "memo", 1000);
  const category = optionalString(t, "category", 100);
  if (!account.ok || !memo.ok || !category.ok) return null;
  if (t.categoryManual !== undefined && typeof t.categoryManual !== "boolean") {
    return null;
  }

  const clean = {
    id: t.id,
    date: t.date,
    type: t.type,
    amount: t.amount,
  };
  if (account.value !== undefined) clean.account = account.value;
  if (memo.value !== undefined) clean.memo = memo.value;
  if (category.value !== undefined) clean.category = category.value;
  if (t.categoryManual !== undefined) clean.categoryManual = t.categoryManual;
  return clean;
}

/* ---------- 핸들러 ---------- */

export async function onRequestGet(context) {
  const { request, env } = context;
  const denied = await authenticate(request, env);
  if (denied) return denied;

  try {
    const raw = await env.LEDGER_KV.get(KV_KEY);
    const transactions = raw ? JSON.parse(raw) : [];
    return json({ transactions });
  } catch (e) {
    console.error("GET /api/transactions 실패:", e);
    return json({ error: "불러오기에 실패했습니다." }, 500);
  }
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const denied = await authenticate(request, env);
  if (denied) return denied;

  try {
    // 본문 크기 제한 (헤더 선언값 + 실제 읽은 길이 모두 확인)
    const declared = parseInt(request.headers.get("Content-Length") || "0", 10);
    if (declared > MAX_BODY_BYTES) {
      return json({ error: "데이터가 너무 큽니다." }, 413);
    }
    const text = await request.text();
    if (text.length > MAX_BODY_BYTES) {
      return json({ error: "데이터가 너무 큽니다." }, 413);
    }

    let body;
    try {
      body = JSON.parse(text);
    } catch (_) {
      return json({ error: "JSON 형식이 올바르지 않습니다." }, 400);
    }

    const transactions = body && body.transactions;
    if (!Array.isArray(transactions)) {
      return json({ error: "형식이 올바르지 않습니다 (transactions 배열 필요)." }, 400);
    }
    if (transactions.length > MAX_TRANSACTIONS) {
      return json({ error: "거래 건수가 허용 범위를 넘었습니다." }, 413);
    }

    const clean = [];
    const seen = new Set();
    for (let i = 0; i < transactions.length; i++) {
      const c = sanitizeTransaction(transactions[i]);
      if (!c) {
        return json(
          { error: `거래 데이터 형식이 올바르지 않습니다. (${i + 1}번째 항목)` },
          400
        );
      }
      if (seen.has(c.id)) {
        return json({ error: `중복된 거래 ID가 있습니다. (${i + 1}번째 항목)` }, 400);
      }
      seen.add(c.id);
      clean.push(c);
    }

    // 덮어쓰기 전에 직전 버전을 1개 보관 — 실수·오염 시 KV에서 복구 가능
    const previous = await env.LEDGER_KV.get(KV_KEY);
    if (previous) await env.LEDGER_KV.put(KV_BACKUP_KEY, previous);

    await env.LEDGER_KV.put(KV_KEY, JSON.stringify(clean));
    return json({ ok: true, count: clean.length });
  } catch (e) {
    console.error("POST /api/transactions 실패:", e);
    return json({ error: "저장에 실패했습니다." }, 500);
  }
}
