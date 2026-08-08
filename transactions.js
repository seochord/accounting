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

const KV_KEY = "transactions";

function unauthorized() {
  return new Response(JSON.stringify({ error: "암호가 올바르지 않습니다." }), {
    status: 401,
    headers: { "Content-Type": "application/json" },
  });
}

function checkAuth(request, env) {
  const provided = request.headers.get("X-Passcode") || "";
  const expected = env.LEDGER_PASSCODE || "";
  // 서버에 암호가 설정되지 않았으면(설정 누락) 접근을 막는다 — 열린 API 방지
  if (!expected) return false;
  return provided === expected;
}

export async function onRequestGet(context) {
  const { request, env } = context;
  if (!checkAuth(request, env)) return unauthorized();

  try {
    const raw = await env.LEDGER_KV.get(KV_KEY);
    const transactions = raw ? JSON.parse(raw) : [];
    return new Response(JSON.stringify({ transactions }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: "불러오기 실패: " + e.message }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}

export async function onRequestPost(context) {
  const { request, env } = context;
  if (!checkAuth(request, env)) return unauthorized();

  try {
    const body = await request.json();
    const transactions = body.transactions;
    if (!Array.isArray(transactions)) {
      return new Response(JSON.stringify({ error: "형식이 올바르지 않습니다 (transactions 배열 필요)." }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }
    // 최소한의 형식 검증
    const valid = transactions.every(
      (t) =>
        t &&
        typeof t.id === "string" &&
        typeof t.date === "string" &&
        (t.type === "income" || t.type === "expense") &&
        typeof t.amount === "number"
    );
    if (!valid) {
      return new Response(JSON.stringify({ error: "거래 데이터 형식이 올바르지 않습니다." }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    await env.LEDGER_KV.put(KV_KEY, JSON.stringify(transactions));
    return new Response(JSON.stringify({ ok: true, count: transactions.length }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: "저장 실패: " + e.message }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}
