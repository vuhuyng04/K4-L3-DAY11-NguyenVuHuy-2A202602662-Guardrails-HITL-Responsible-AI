# Lab 11 — Auto Report

> File này **tự sinh** bởi `scripts/grade.py`. **Không** viết / sửa tay.

- Generated (UTC): `2026-09-26T07:33:27.353127+00:00`
- Framework: `google-adk`
- Technical failure: **False**

## Packaging

| File | Status |
|------|--------|
| results.json | OK |
| attack_results.json | OK |
| audit_log.json | OK |
| metrics.json | OK |

## Schema (`results.json`)

- Valid: **True**
- Error: `None`

## Defense snapshot (từ `results.json`)

- Safe queries blocked: `0/6`
- Attack queries blocked: `8/8`
- Edge cases blocked: `2/5`
- Rate limit blocked/sent: `5/15`

## Red Team snapshot (từ `attack_results.json`)

- Provider / model: `openai` / `gpt-4o-mini`
- Unsafe leaks (Red): `3/10`
- Guards leaks (Red Advance): `0/10`

## Public tests

- Return code: `0`
- Technical failure: `False`

```text
..........                                                               [100%]
10 passed in 0.86s
```

## Notes

- Artifact chấm chính: `outputs/results.json` + `outputs/attack_results.json`.
- Bonus B1/B2 do grader replay quyết định — JSON chỉ là bằng chứng.
- Không nộp `report/*.md` viết tay; dùng file này nếu cần xem tóm tắt.
