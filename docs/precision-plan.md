# ShipProof precision plan

Last reviewed: 2026-09-15

สถานะ: แผนเพิ่มความแม่นยำและลด false positive หลัง v0.10.0 เอกสารนี้ต่อยอดจาก [community validation](community-validation.md) และ [next development plan](next-development-plan.md) ไม่ได้แทนที่ทั้งสองฉบับ

ช่วงที่ 1, ช่วงที่ 2, 3.1, 3.2 และ 3.3 ทำครบใน working tree นี้แล้ว

## สรุป

ตัวเลข precision 1.0 ที่เผยแพร่อยู่มาจาก fixture ที่เขียนขึ้นในรีโปนี้ทั้งหมด ยังไม่มีการวัดบนโค้ดจริงที่มี label การทดลองเบื้องต้นบนไลบรารีโอเพนซอร์สที่โตเต็มที่พบว่า gate ค่า default block แพ็กเกจที่ควรผ่านถึง 11 จาก 15 แพ็กเกจ

สาเหตุหลักไม่ได้อยู่ที่กฎตัวใดตัวหนึ่ง แต่อยู่ที่โครงสร้าง คือ confidence ถูกกำหนดคงที่ต่อกฎ, กฎทั้งหมดเป็นหลักฐานระดับ pattern (L0) และ gate ไม่แยกหลักฐานอ่อนออกจากหลักฐานแข็ง

แผนนี้เรียงงานเป็นสามช่วง คือ วัดให้ได้ก่อน, แก้ engine และยกระดับการวัดให้ต่อเนื่อง ทุกช่วงมีเงื่อนไขที่ต้องผ่านก่อนไปต่อ

### ผลหลังแก้ engine บน corpus เดิม

วัดด้วย `python scripts/eval-clean-corpus.py --json --labels --write-baseline benchmarks/clean-corpus-baseline.json` บน Windows 11, Python 3.12.10, ShipProof 0.10.0, แพ็กเกจที่ pin ใน [clean-corpus.json](../benchmarks/clean-corpus.json) วันที่ 2026-09-15 ตัวเลขนี้เป็นผลการวัดบน corpus ที่ pin ไม่ใช่ precision claim สาธารณะ

| ตัวชี้วัด | Baseline ในแผนนี้ | หลังช่วงที่ 2 |
| :--- | ---: | ---: |
| แพ็กเกจที่ถูก `BLOCK` | 11 / 15 | 0 / 15 |
| findings ที่มีผลต่อ verdict (high และ medium, ไม่นับ advisory) | 45 | 10 |
| high risk-confidence | 71 / 98 | 1 / 63 |
| high หรือ critical app findings | 38 | 0 |
| กฎ high หรือ critical ที่เกิน FP budget | ยังไม่ได้วัด | 0 |
| scan profile | ไม่ได้แยก | library ทั้ง 15 |
| แพ็กเกจที่สแกนได้ | 15 รวมถึงกรณี license ที่เคยพลาด | 15 / 15 |

finding ที่เหลือส่วนใหญ่เป็น SP061 ระดับ advisory (low severity, low risk-confidence) สิบรายการที่เป็น gate คือ medium L0 ของ SP356, SP121, SP310, SP308 และ SP106 ถูก label เป็น `false_positive` หลังดูต้นทางแล้ว แผนข้อ 1.2 ผ่านเพราะไม่มีแถว high/critical ให้ label

## สิ่งที่ยืนยันแล้ว

- `python -m unittest discover -s tests -p test_*.py` ผ่านทั้งชุดบน Windows, Python 3.12.10, Node 24.15.0
- `python scripts/rule_assurance_report.py` รายงาน 635 กฎมี contract ครบ และ debt baseline ว่าง
- งานที่ยังไม่ commit ณ วันที่ตรวจ ได้แก่ trust-boundary audit, coverage ledger, baseline v2, การแก้ SP631, การจำกัด SP096–SP100 ให้ทำงานเฉพาะ Skill package และงานตามแผนนี้ ลำดับ commit ยังเป็นของมนุษย์ ไม่ได้ทำอัตโนมัติในรอบนี้

## การทดลองบน clean corpus

### วิธีทดลอง

สแกนแพ็กเกจที่ติดตั้งอยู่ในเครื่องด้วยค่า default ของ scanner และ `--allow-incomplete` โดยถือว่าเป็น clean baseline เพราะเป็นไลบรารีที่ใช้งานแพร่หลายและผ่านการรีวิวมามาก

```bash
SITE="$(python -c 'import site; print(site.getsitepackages()[-1])')"
for p in flask requests fastapi werkzeug httpx click jinja2 urllib3 pydantic; do
  python skills/audit-production-readiness/scripts/scan_repo.py "$SITE/$p" \
    --format json --allow-incomplete > "out/$p.json"
done
for p in body-parser cors ajv cookie cross-spawn debug; do
  python skills/audit-production-readiness/scripts/scan_repo.py "node_modules/$p" \
    --format json --allow-incomplete > "out/js-$p.json"
done
```

เวอร์ชันที่ใช้:

| Ecosystem | แพ็กเกจ |
| :--- | :--- |
| Python | flask 3.1.3, requests 2.33.1, fastapi 0.140.12, werkzeug 3.1.8, httpx 0.28.1, click 8.3.3, jinja2 3.1.6, urllib3 2.6.3, pydantic 2.13.3 |
| JavaScript | body-parser 2.3.0, cors 2.8.6, ajv 8.20.0, cookie 0.7.2, cross-spawn 7.0.6, debug 4.4.3 |

ข้อจำกัด: site-packages และ node_modules เป็นไฟล์ที่ติดตั้งแล้ว ไม่ใช่ source ที่ pin ด้วย commit บางแพ็กเกจมีไฟล์ build หรือ type definition ปนอยู่ ผลนี้ใช้ตั้ง baseline และจัดลำดับงานได้ แต่ยังไม่ใช่ precision claim

### ผลรวม

| ตัวชี้วัด | ค่า |
| :--- | ---: |
| ไฟล์ที่สแกน | 524 |
| findings ทั้งหมด (app scope ทั้งหมด) | 98 |
| severity high / medium / low | 38 / 7 / 53 |
| confidence high / medium | 71 / 27 |
| แพ็กเกจที่ exit 1 | 11 จาก 15 |

### กฎที่ยิงบ่อยที่สุด

| กฎ | ครั้ง | Severity / confidence | ตัวอย่างแรกที่พบ | ข้อสังเกต |
| :--- | ---: | :--- | :--- | :--- |
| SP061 | 53 | low / high | `except Exception:` ใน click | ครึ่งหนึ่งของ findings ทั้งหมด เป็นเกณฑ์ระดับ lint |
| SP140 | 11 | high / high | `hashlib.sha1(string)` ใน flask sessions | ใช้ derive key ไม่ได้ใช้เก็บรหัสผ่าน |
| SP101 | 10 | high / medium | `eval(compile(...))` ใน flask cli | template engine และ REPL ใช้ตามหน้าที่ |
| SP308 | 5 | medium / medium | `global _url_regex_cache` ใน pydantic | cache ขนาดคงที่ |
| SP106 | 4 | high / medium | `pickle.load(f)` ใน jinja2 bccache | อ่าน cache ของตัวเอง |
| SP636 | 3 | high / high | string `"text/event-stream"` ใน fastapi openapi | ไม่ได้เปิด stream จริง |
| SP117 | 3 | high / medium | `new Function(...)` ใน ajv | code generation คือหน้าที่ของไลบรารี |
| SP019 | 2 | high / medium | URL ตัวอย่างใน docstring ของ pydantic | อยู่ใน documentation string |
| SP505 | 1 | high / medium | `prompt = f"..."` ใน click termui | prompt ใน terminal ไม่ใช่ LLM |
| SP307 | 1 | high / high | `fnmatch.filter` ในลูปของ werkzeug | ไม่มีฐานข้อมูล |
| SP310 | 1 | high / high | `while True:` ใน urllib3 | มีเงื่อนไขออกและ backoff |

การทบทวนรอบนี้ดูเฉพาะตัวอย่างแรกของแต่ละกฎ ยังไม่ได้ label ทุก finding ประมาณการเบื้องต้นคือ high findings ที่น่าจะเป็นปัญหาจริงมีไม่เกิน 2 จาก 38 ต้องยืนยันด้วย label store ในช่วงที่ 1

### Self-scan บน Harness

สแกน repo Harness ได้ 3 findings ทั้งหมดเป็น false positive หรือ context-only:

- SP526 รายงานว่า chat history ไม่มี sliding window แต่ฟังก์ชันตัดประวัติอยู่ห่างออกไปประมาณ 20 บรรทัด
- SP099 นับ `anthropic_adapter_tests.py` เป็น app scope เพราะการตรวจ test scope ดูแค่ชื่อโฟลเดอร์
- SP061 อีกหนึ่งจุด

## สาเหตุเชิงโครงสร้าง

| # | สาเหตุ | หลักฐาน |
| :--- | :--- | :--- |
| 1 | confidence คงที่ต่อกฎ ไม่ได้คำนวณต่อ finding | 495 จาก 635 กฎกำหนด `high` ไว้ในนิยาม `--min-confidence high` จึงกรองได้น้อย |
| 2 | ทุกกฎมี regex pattern และ findings ส่วนใหญ่เป็น L0 | 635 จาก 635 กฎมี attribute `pattern` |
| 3 | severity เอียงไปทาง high และ critical | 476 กฎ (75%) รวมกับ gate default ที่ `high` ทำให้กฎ L0 ตัวเดียว block ทั้ง repo ได้ |
| 4 | context gating มีน้อย | `RULE_FRAMEWORK_HINTS` ครอบคลุม 16 กฎ และใช้กับกฎ pattern เพียง 1 กฎ |
| 5 | negative ใน contract เป็น near-miss สังเคราะห์ | เช่น SP101 ใช้ `!val(` เทียบกับ `eval(` พิสูจน์ขอบเขต regex แต่ไม่พิสูจน์ความเงียบบนโค้ดจริง |
| 6 | test scope ดูเฉพาะ path segment | `TEST_PATH_SEGMENTS` ไม่ครอบคลุม `*_test.py`, `*_tests.py`, `*.test.ts`, `*.spec.js`, `conftest.py` |
| 7 | ไม่มีที่เก็บ label | `eval-realworld.py` ทำเครื่องหมายทุก finding เป็น `unreviewed` และไม่มีเครื่องมืออ่าน review record |
| 8 | กฎเกรด lint ปนกับกฎความปลอดภัย | SP061 สร้าง 54% ของ findings บน clean corpus |

## หลักการของแผน

- วัดก่อนแก้ ทุกการเปลี่ยนแปลงของกฎต้องมีตัวเลขก่อนและหลังบน corpus เดียวกัน
- ไม่ลบกฎเพื่อให้ตัวเลขดูดี ให้ลด severity, เพิ่มเงื่อนไข หรือย้าย tier พร้อมบันทึกเหตุผล
- recall บน fixture เดิมต้องไม่ลดลง ถ้าลดต้องมีเหตุผลที่บันทึกไว้
- ความลับ (secret rules) ไม่ถูกลด confidence ด้วยกลไกใหม่ เว้นแต่มีหลักฐานเฉพาะ
- ค่า default ของ scanner ยังคง offline, read-only และไม่มี dependency เพิ่ม
- ตัวเลขที่เผยแพร่ต้องมาพร้อม corpus identity, จำนวนตัวอย่าง และ confusion matrix

## ช่วงที่ 1 วัดให้ได้

ระยะเวลาโดยประมาณ: 1–2 สัปดาห์

### 1.1 Clean-corpus benchmark

- สร้าง manifest `benchmarks/clean-corpus.json` ที่ pin เวอร์ชันแพ็กเกจ Python และ npm พร้อม license และ digest ของไฟล์ที่ติดตั้ง
- สร้างสคริปต์ `scripts/eval-clean-corpus.py` ที่ติดตั้งลง virtualenv และ `npm install --ignore-scripts` ในโฟลเดอร์ชั่วคราว แล้วสแกนด้วยค่า default
- เพิ่มใน `.github/workflows/benchmarks.yml` เป็น job รายสัปดาห์ และเก็บผลเป็น artifact
- เริ่มจาก 15 แพ็กเกจในการทดลองนี้ แล้วขยายเป็นอย่างน้อย 30 แพ็กเกจ ครอบคลุม Python, JavaScript/TypeScript, Go และ Rust

เงื่อนไขผ่าน:

- job ทำซ้ำได้และให้ fingerprint เดิมเมื่อ input เดิม
- ติดตั้งล้มเหลวหรือ digest ไม่ตรงคืน exit `2` ไม่ใช่ผ่านแบบเงียบ
- ผลของรอบแรกถูกบันทึกเป็น baseline ใน repo

### 1.2 Label store

- กำหนด schema `schemas/finding-label.schema.json` ตาม review record ใน community-validation.md
- เก็บ label เป็น JSONL ใน `benchmarks/labels/` คีย์ด้วย corpus, revision และ fingerprint
- label ที่อนุญาต: `true_positive`, `false_positive`, `needs_context`, `duplicate`
- เพิ่มคำสั่ง `eval-realworld.py --labels` และ `eval-clean-corpus.py --labels` ที่คำนวณ precision ต่อกฎ ต่อ severity และต่อ proof level
- finding ที่ไม่มี label ยังเป็น `unreviewed` และไม่ถูกนับเป็น true หรือ false

เงื่อนไขผ่าน:

- label ครบทุก high และ critical finding ของ clean corpus รอบแรก
- รายงานแสดง confusion matrix ต่อกฎพร้อมจำนวนตัวอย่าง

### 1.3 FP budget ต่อกฎ

- กฎที่มี false positive ตั้งแต่ 2 ครั้งและไม่มี true positive บน clean corpus ต้องได้รับการแก้ก่อน release ถัดไป
- ทางเลือกในการแก้เรียงตามลำดับ: เพิ่ม context gating, ลด confidence, ลด severity, ย้ายไป tier advisory
- บันทึกการตัดสินใจและตัวเลขก่อนหลังไว้ใน CHANGELOG

เงื่อนไขผ่าน:

- ไม่มีกฎ high หรือ critical ที่เกิน FP budget บน clean corpus

## ช่วงที่ 2 แก้ engine

ระยะเวลาโดยประมาณ: 2–4 สัปดาห์ เริ่มได้เมื่อช่วงที่ 1 ผ่าน

### 2.1 Confidence ต่อ finding

- แยก confidence เป็นสองค่า: `match_confidence` คือ pattern แมตช์แน่แค่ไหน และ `risk_confidence` คือมีหลักฐานว่าเป็นความเสี่ยงจริงแค่ไหน
- กฎ L0 เริ่มที่ `risk_confidence: medium` เป็นค่า default
- ยกเป็น `high` ได้เมื่อมีหลักฐานเสริมอย่างน้อยหนึ่งข้อ เช่น import ที่เกี่ยวข้องในไฟล์, source และ sink อยู่ในฟังก์ชันเดียวกัน, ไม่มี sanitizer ใกล้เคียง, อยู่ใน route handler ที่ระบุได้
- ลดเป็น `low` เมื่อพบหลักฐานหักล้าง เช่น `usedforsecurity=False`, อยู่ใน docstring, อยู่ในไฟล์ที่ระบุว่าเป็น code generator
- คง field `confidence` เดิมใน schema เป็นค่า `risk_confidence` เพื่อความเข้ากันได้ และเพิ่ม field ใหม่แบบ additive

เงื่อนไขผ่าน:

- สัดส่วน high confidence บน clean corpus ลดลงอย่างน้อยครึ่งหนึ่ง
- recall บน fixture battery ยังเป็น 1.0

### 2.2 Gate ตามระดับหลักฐาน

- finding ที่ block ได้ต้องมี proof level ตั้งแต่ L1 หรืออยู่ใน allowlist ของกฎ L0 ที่พิสูจน์แล้วว่าแม่น
- allowlist เริ่มจากกฎที่มีหลักฐานชัดในตัว เช่น secret ที่ผ่าน entropy check และ `DEBUG = True` ใน settings ของ production
- finding L0 ที่ไม่อยู่ใน allowlist ยังรายงาน แต่ verdict เป็น `REVIEW` ไม่ใช่ `BLOCK`
- เพิ่ม policy key `security.block_min_proof` ค่า default `L1` และให้ `check` ยังคงบังคับ floor ที่ไม่ลดต่ำกว่าค่า default

เงื่อนไขผ่าน:

- demo-api before ยังเป็น `BLOCK` และ after ยังเป็น `PASS_WITH_EVIDENCE`
- clean corpus ไม่มีแพ็กเกจที่ถูก `BLOCK` ด้วย finding ที่ label เป็น false positive

### 2.3 Context gating สำหรับกฎเฉพาะบริบท

ขยาย gating จาก 16 กฎ ให้ครอบคลุมกฎ scale, reliability และ AI ที่ขึ้นกับบริบท เริ่มจากกฎที่ยิงบน clean corpus:

| กฎ | เงื่อนไขที่ต้องเห็นก่อนรายงาน |
| :--- | :--- |
| SP307 | import ของ ORM หรือ database driver ในไฟล์เดียวกัน และ query call อยู่ในลูป |
| SP310 | `while True` ที่ไม่มี `sleep`, `wait`, `select`, `recv` หรือ `break` ในบล็อก |
| SP636 | การสร้าง streaming response จริง ไม่ใช่เพียง string MIME type |
| SP505 | import ของ SDK โมเดลภาษา และตัวแปรถูกส่งเข้า client call |
| SP526 | ไม่มีการ slice, pop, truncate หรือนับ token ของตัวแปรเดียวกันในฟังก์ชันเดียวกัน |
| SP140 | ค่าที่ hash ถูกใช้เป็นรหัสผ่าน, token หรือ signature และไม่มี `usedforsecurity=False` |
| SP101, SP117 | ไฟล์ไม่ได้อยู่ใน package ที่ประกาศตัวเป็น template engine หรือ code generator และ argument มาจาก request หรือ input ภายนอก |
| SP106 | path ของไฟล์ที่ deserialize มาจากภายนอก ไม่ใช่ cache ของโปรแกรมเอง |

เงื่อนไขผ่าน:

- แต่ละกฎที่แก้มี realistic negative เพิ่มใน contract อย่างน้อย 1 รายการ
- positive เดิมทั้งหมดยังยิง

### 2.4 Test scope และ library mode

- ขยายการตรวจ test scope ให้รวมชื่อไฟล์ `test_*.py`, `*_test.py`, `*_tests.py`, `conftest.py`, `*.test.{js,ts,jsx,tsx}`, `*.spec.{js,ts,jsx,tsx}` และ `__tests__/`
- เพิ่ม heuristic library mode เมื่อ repo ไม่มี entrypoint ของ application, route หรือ server listen ที่ตรวจพบ ให้กฎที่ออกแบบสำหรับ application ลด severity หนึ่งระดับและแสดงเหตุผลใน finding
- ให้ผู้ใช้ override ได้ด้วย policy `scan.profile: application | library`

เงื่อนไขผ่าน:

- self-scan Harness ไม่นับ `*_tests.py` เป็น app scope
- ไลบรารีใน clean corpus ถูกระบุเป็น library mode

### 2.5 String และ docstring

- ทุกกฎ pattern ที่ไม่ใช่ secret ต้องไม่ยิงใน docstring และ comment
- ทุกกฎ pattern ที่ไม่ได้ออกแบบเพื่อจับ string literal ต้องไม่ยิงเมื่อ match อยู่ใน string ทั้งหมด
- ใช้ tokenizer ที่มีอยู่แล้วของ Python และ JavaScript แทนการเพิ่ม regex ต่อกฎ

เงื่อนไขผ่าน:

- SP019 ไม่ยิงบน URL ตัวอย่างใน docstring
- adversarial corpus ยังผ่านทั้งสองทิศทาง

### 2.6 Tier และการรวม finding

- แยก tier เป็น `gate` สำหรับกฎที่มีผลต่อ verdict และ `advisory` สำหรับกฎเกรด lint
- ย้าย SP061 และกฎ low severity อื่นที่ไม่เกี่ยวกับความปลอดภัยไป `advisory`
- จำกัดจำนวน finding ต่อกฎต่อไฟล์ในรายงาน terminal และ Markdown โดยแสดงจำนวนที่ถูกรวม ส่วน JSON และ SARIF ยังเก็บครบ

เงื่อนไขผ่าน:

- findings ใน tier `gate` บน clean corpus ลดลงอย่างน้อย 50% เทียบ baseline ช่วงที่ 1
- ไม่มี finding ถูกซ่อนจาก JSON และ SARIF

## ช่วงที่ 3 วัดต่อเนื่อง

ระยะเวลาโดยประมาณ: ต่อเนื่องหลังช่วงที่ 2

### 3.1 Realistic negatives

- เปลี่ยน false positive ที่ label แล้วบน clean corpus ให้เป็น fixture ขนาดเล็กที่คง syntax สำคัญไว้ โดยไม่คัดลอกโค้ดของโครงการต้นทางเกินจำเป็น
- เพิ่ม metric ใหม่ใน `rule_assurance_report.py` แยกนับกฎที่มีแต่ near-miss negative กับกฎที่มี realistic negative
- ตั้ง debt baseline ใหม่สำหรับกฎ high และ critical ที่ยังไม่มี realistic negative และให้ baseline ลดได้อย่างเดียว

### 3.2 Line-level labels และการเทียบกับเครื่องมืออื่น

- [x] เพิ่ม line-level label ให้ cross-file corpora ตามที่ระบุไว้ใน [benchmarks](benchmarks.md)
- [x] รัน semgrep ด้วย ruleset ที่ผู้ใช้จัดเตรียมบน corpus เดียวกันใน Linux runner ตามแผนเดิม — งาน CI เป็น opt-in (`run-semgrep`) และใช้เฉพาะ ruleset ต้นฉบับในรีโปนี้ ไม่ได้คัดลอกกฎของ Semgrep
- [x] ประเมินการใช้ OWASP Benchmark หลังตรวจ license — ไม่นำเข้า เพราะ BenchmarkJava เป็น GPL-2.0 และ BenchmarkPython เป็น GPL-3.0 และชุด Java ไม่ตรงกับ default engine

### 3.3 Precision trend

- [x] เก็บผล clean corpus และ labeled corpus ทุกสัปดาห์เป็น artifact พร้อม scanner version
- [x] ตั้ง threshold แยกตาม tier และ severity ใน `benchmarks/precision-thresholds.json` และให้ `scripts/check-precision-trend.py` ตรวจทั้ง weekly artifact และ release workflow
- [x] ไม่เผยแพร่ตัวเลข precision ใน README จนกว่าจะมี confusion matrix และจำนวนตัวอย่างกำกับ — ยังไม่มี public precision claim

## ตัวชี้วัดความสำเร็จ

| ตัวชี้วัด | Baseline 2026-09-15 | เป้าหลังช่วงที่ 2 | ผลที่วัดได้ 2026-09-15 |
| :--- | ---: | ---: | ---: |
| แพ็กเกจ clean corpus ที่ถูก block | 11 / 15 | 0 จาก finding ที่ label เป็น false positive | 0 / 15 (ไม่มี high/critical ให้ label) |
| findings ที่มีผลต่อ verdict บน clean corpus | 45 (high และ medium) | ลดลงอย่างน้อย 50% | 10 (ลด 78%) |
| high confidence บน clean corpus | 71 / 98 | ลดลงอย่างน้อยครึ่งหนึ่ง | 1 / 63 |
| กฎ high และ critical ที่เกิน FP budget | ยังไม่ได้วัด | 0 | 0 |
| recall บน fixture battery | 1.0 | 1.0 | 1.0 (710 Python tests) |
| demo-api before / after | BLOCK / PASS | BLOCK / PASS | BLOCK / PASS |
| กฎที่มี realistic negative | ยังไม่ได้วัด | ทุกกฎที่แก้ในช่วงที่ 2 | กฎที่แก้ในช่วงที่ 2 มี realistic negative แล้ว |

## ความเสี่ยงและวิธีรับมือ

| ความเสี่ยง | วิธีรับมือ |
| :--- | :--- |
| เพิ่มเงื่อนไขแล้ว recall ลดลงแบบไม่รู้ตัว | fixture battery และ positive contracts เดิมเป็น gate บังคับทุก PR |
| clean corpus มีช่องโหว่จริงแฝงอยู่ | label เป็น `true_positive` ได้ และไม่ถือว่า corpus สะอาดโดยอัตโนมัติ |
| gate ตาม proof level ทำให้ผู้ใช้เดิมพลาดสิ่งที่เคย block | ประกาศใน CHANGELOG, ให้ policy คืนพฤติกรรมเดิมได้ และแสดง `REVIEW` ชัดเจนในรายงาน |
| library mode ถูกตรวจผิด | ให้ override ด้วย policy และแสดงเหตุผลการตรวจในรายงาน |
| label ของคนไม่สม่ำเสมอ | กำหนดคำอธิบาย label, ให้ reviewer สองคนสำหรับ high และ critical และบันทึกเหตุผลสั้นๆ |
| ต้นทุนการ label สูง | เริ่มเฉพาะ high และ critical บน clean corpus แล้วค่อยขยาย |

## ลำดับงานสัปดาห์แรก

1. Commit งานที่ยังค้างอยู่หลังผ่าน `npm run check` — ยังไม่ทำในรอบนี้ เพราะกติกาของรีโปคือ commit เมื่อมีการขอเท่านั้น
2. สร้าง `benchmarks/clean-corpus.json` จาก 15 แพ็กเกจในเอกสารนี้
3. เขียน `scripts/eval-clean-corpus.py` และเก็บผลรอบแรกเป็น baseline
4. กำหนด label schema และ label high findings ทั้ง 38 รายการ — หลังแก้ engine ไม่เหลือแถว high/critical ให้ label
5. สรุปกฎที่เกิน FP budget และเลือก 3 กฎแรกเข้าช่วงที่ 2 — ไม่มีกฎ high/critical ที่เกินงบ และช่วงที่ 2 ทำครบแล้ว
