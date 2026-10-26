"""Generate and open a self-contained local dashboard for output.csv."""
from __future__ import annotations
import argparse
import csv
import json
from pathlib import Path
import webbrowser

ROOT = Path(__file__).resolve().parent

TEMPLATE = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ghost Data Audit Dashboard</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#121a2c;--panel2:#172238;--line:#26344c;--muted:#9aabc4;--text:#edf3ff;--green:#34d399;--red:#fb7185;--amber:#fbbf24;--blue:#7dd3fc}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 10% 0%,#18294b 0,transparent 40%),var(--bg);color:var(--text);font:14px/1.45 Segoe UI,Arial,sans-serif}main{max-width:1450px;margin:0 auto;padding:32px 28px 50px}.eyebrow{color:var(--blue);font-size:11px;font-weight:700;letter-spacing:.16em;text-transform:uppercase}.head{display:flex;justify-content:space-between;align-items:end;gap:20px;margin-bottom:24px}h1{font-size:clamp(27px,4vw,38px);margin:7px 0 4px;letter-spacing:-.035em}.sub{color:var(--muted);margin:0}.local{border:1px solid #31517a;border-radius:999px;padding:8px 12px;color:#b6d9ff;white-space:nowrap;background:#132541}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:22px 0}.card,.panel{background:linear-gradient(145deg,rgba(24,35,57,.97),rgba(16,24,40,.97));border:1px solid var(--line);border-radius:16px;box-shadow:0 10px 30px #0002}.card{padding:17px 19px;position:relative;overflow:hidden}.card:after{content:"";position:absolute;width:90px;height:90px;border-radius:50%;right:-36px;top:-42px;background:var(--accent);opacity:.12;filter:blur(2px)}.card .label{font-size:12px;color:var(--muted)}.card strong{font-size:29px;display:block;margin:5px 0 0;letter-spacing:-.04em}.card small{color:var(--muted)}.green{--accent:var(--green)}.red{--accent:var(--red)}.amber{--accent:var(--amber)}.blue{--accent:var(--blue)}.overview{display:grid;grid-template-columns:310px 1fr;gap:14px;margin-bottom:15px}.panel{padding:18px 20px}.panel h2{font-size:15px;margin:0 0 15px}.chartrow{display:flex;align-items:center;gap:22px}.donut{width:130px;height:130px;border-radius:50%;background:conic-gradient(var(--green) 0 var(--g),var(--red) var(--g) var(--r),var(--amber) var(--r) 100%);display:grid;place-items:center;flex:none}.donut:after{content:"";width:88px;height:88px;border-radius:50%;background:#121a2c}.legend{display:grid;gap:10px;color:var(--muted);font-size:12px}.legend span{display:flex;align-items:center;gap:8px}.dot{height:9px;width:9px;border-radius:50%;display:inline-block}.legend b{color:var(--text);margin-left:auto;font-variant-numeric:tabular-nums}.note{color:var(--muted);font-size:12px;margin-top:14px}.bars{display:grid;gap:15px;margin:3px 0}.barhead{display:flex;justify-content:space-between;color:var(--muted);font-size:12px;margin-bottom:6px}.track{height:8px;border-radius:8px;background:#26344c;overflow:hidden}.fill{height:100%;border-radius:8px}.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:17px 0 11px}.search{flex:1;min-width:230px}input,select{background:#101a2c;color:var(--text);border:1px solid var(--line);border-radius:9px;padding:11px 12px;font:inherit;outline:none}input:focus,select:focus{border-color:#5da9ef;box-shadow:0 0 0 3px #348bea22}.resultcount{color:var(--muted);font-size:12px;margin-left:auto}.workarea{display:grid;grid-template-columns:minmax(380px,1.03fr) minmax(390px,.97fr);gap:14px;align-items:start}.tablewrap{overflow:auto;max-height:620px;padding:0}.tablewrap h2{padding:18px 18px 0;margin:0}.tablewrap table{border-collapse:collapse;width:100%;font-size:12px}.tablewrap th{position:sticky;top:0;background:#141f34;color:#9aabc4;text-align:left;font-weight:600;padding:11px 14px;border-bottom:1px solid var(--line);z-index:1}.tablewrap td{padding:10px 14px;border-bottom:1px solid #26344c88;vertical-align:middle}.tablewrap tbody tr{cursor:pointer;transition:background .13s}.tablewrap tbody tr:hover,.tablewrap tbody tr.active{background:#1b2c46}.caseid{font-weight:700;color:#d9eaff;font-variant-numeric:tabular-nums}.badge{display:inline-block;border-radius:999px;padding:4px 8px;font-size:10px;font-weight:700;letter-spacing:.035em;white-space:nowrap}.bcomplete{color:#82f4c3;background:#073b31}.bincomplete{color:#ff9aaa;background:#4a1e2a}.bna{color:#ffd774;background:#493915}.stepscount{font-variant-numeric:tabular-nums;color:var(--muted)}.detail{min-height:260px}.detailtop{display:flex;justify-content:space-between;align-items:start;gap:12px;border-bottom:1px solid var(--line);padding-bottom:14px;margin-bottom:14px}.detailtop h2{margin:0;font-size:18px}.detailmeta{color:var(--muted);font-size:12px;margin-top:4px}.steps{display:grid;gap:10px}.step{background:#111b2d;border:1px solid var(--line);border-radius:12px;padding:12px 13px}.steprow{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:7px}.phase{font-size:10px;letter-spacing:.06em;font-weight:700;color:#b7d9ff;background:#1c3552;border-radius:5px;padding:3px 6px}.op{font-weight:700;font-size:12px}.num{color:var(--muted);font-size:11px}.resource{font-family:Consolas,monospace;color:#a5f3fc;font-size:12px;overflow-wrap:anywhere}.stepmeta{font-size:11px;color:var(--muted);display:flex;flex-wrap:wrap;gap:7px 14px}.empty{color:var(--muted);padding:28px 14px;text-align:center}.footer{color:#7f91aa;font-size:11px;text-align:center;padding:20px 0 0}.pill{border:1px solid var(--line);border-radius:7px;padding:3px 7px;color:#c5d5eb}@media(max-width:900px){.overview{grid-template-columns:1fr}.chartrow{justify-content:flex-start}.workarea{grid-template-columns:1fr}.tablewrap{max-height:430px}}@media(max-width:620px){main{padding:20px 13px}.head{display:block}.local{display:inline-block;margin-top:14px}.cards{grid-template-columns:repeat(2,1fr);gap:9px}.card{padding:13px}.card strong{font-size:24px}.workarea{grid-template-columns:minmax(0,1fr)}.tablewrap th,.tablewrap td{padding:9px}.search{min-width:100%}.resultcount{margin-left:0}}
</style></head><body><main>
<header class="head"><div><div class="eyebrow">HackerRank Orchestrate · October 2026</div><h1>Ghost Data Audit</h1><p class="sub">Deletion status and evidence-backed next steps across the generated case file.</p></div><div class="local">● Local report · no data uploaded</div></header>
<section class="cards">
 <article class="card blue"><div class="label">Cases audited</div><strong id="total">0</strong><small>rows in output.csv</small></article>
 <article class="card green"><div class="label">Complete</div><strong id="complete">0</strong><small id="completePct">0% of all cases</small></article>
 <article class="card red"><div class="label">Incomplete</div><strong id="incomplete">0</strong><small id="incompletePct">0% of all cases</small></article>
 <article class="card amber"><div class="label">Not applicable</div><strong id="na">0</strong><small id="naPct">0% of all cases</small></article>
</section>
<section class="overview">
 <article class="panel"><h2>Status mix</h2><div class="chartrow"><div class="donut" id="donut"></div><div class="legend"><span><i class="dot" style="background:var(--green)"></i>Complete <b id="legc"></b></span><span><i class="dot" style="background:var(--red)"></i>Incomplete <b id="legi"></b></span><span><i class="dot" style="background:var(--amber)"></i>Not applicable <b id="legn"></b></span></div></div><div class="note">Share of all audited cases.</div></article>
 <article class="panel"><h2>Coverage at a glance</h2><div class="bars"><div><div class="barhead"><span>Complete</span><span id="bcText"></span></div><div class="track"><div class="fill" id="bc" style="background:var(--green)"></div></div></div><div><div class="barhead"><span>Incomplete</span><span id="biText"></span></div><div class="track"><div class="fill" id="bi" style="background:var(--red)"></div></div></div><div><div class="barhead"><span>Not applicable</span><span id="bnText"></span></div><div class="track"><div class="fill" id="bn" style="background:var(--amber)"></div></div></div></div><div class="note">Select a case to inspect its ordered findings, proposed remediation, and verification steps.</div></article>
</section>
<div class="toolbar"><input id="search" class="search" type="search" placeholder="Search case ID, resource, system, or operation…" aria-label="Search cases"><select id="filter" aria-label="Filter by status"><option value="ALL">All statuses</option><option value="COMPLETE">Complete</option><option value="INCOMPLETE">Incomplete</option><option value="NOT_APPLICABLE">Not applicable</option></select><span id="resultcount" class="resultcount"></span></div>
<section class="workarea"><article class="panel tablewrap"><h2>Cases</h2><table><thead><tr><th>Case</th><th>Status</th><th>Steps</th></tr></thead><tbody id="rows"></tbody></table><div id="empty" class="empty" hidden>No cases match this filter.</div></article><article id="detail" class="panel detail" aria-live="polite"></article></section>
<div class="footer">Generated locally from output.csv · Static dashboard · No external services</div>
</main><script>
const CASES=__DATA__;
const counts={COMPLETE:0,INCOMPLETE:0,NOT_APPLICABLE:0};for(const c of CASES)counts[c.deletion_status]=(counts[c.deletion_status]||0)+1;
const total=CASES.length,pct=n=>total?Math.round(n*100/total):0;
for(const [id,n] of [['total',total],['complete',counts.COMPLETE],['incomplete',counts.INCOMPLETE],['na',counts.NOT_APPLICABLE],['legc',counts.COMPLETE],['legi',counts.INCOMPLETE],['legn',counts.NOT_APPLICABLE]])document.getElementById(id).textContent=n.toLocaleString();
document.getElementById('completePct').textContent=pct(counts.COMPLETE)+'% of all cases';document.getElementById('incompletePct').textContent=pct(counts.INCOMPLETE)+'% of all cases';document.getElementById('naPct').textContent=pct(counts.NOT_APPLICABLE)+'% of all cases';
const g=pct(counts.COMPLETE),r=g+pct(counts.INCOMPLETE);document.getElementById('donut').style.setProperty('--g',g+'%');document.getElementById('donut').style.setProperty('--r',r+'%');
for(const [key,n] of [['c',counts.COMPLETE],['i',counts.INCOMPLETE],['n',counts.NOT_APPLICABLE]]){document.getElementById('b'+key).style.width=pct(n)+'%';document.getElementById('b'+key+'Text').textContent=n+' · '+pct(n)+'%'}
const tbody=document.getElementById('rows'),detail=document.getElementById('detail'),search=document.getElementById('search'),filter=document.getElementById('filter');let selected=CASES[0]?.case_id;
function badge(status){const b=document.createElement('span');b.className='badge '+(status==='COMPLETE'?'bcomplete':status==='INCOMPLETE'?'bincomplete':'bna');b.textContent=status.replace('_',' ');return b}
function showCase(c){selected=c.case_id;document.querySelectorAll('#rows tr').forEach(tr=>tr.classList.toggle('active',tr.dataset.id===selected));detail.replaceChildren();const top=document.createElement('div');top.className='detailtop';const title=document.createElement('div');const h=document.createElement('h2');h.textContent=c.case_id;title.append(h);const meta=document.createElement('div');meta.className='detailmeta';meta.textContent=c.steps.length+' ordered step'+(c.steps.length===1?'':'s');title.append(meta);top.append(title,badge(c.deletion_status));detail.append(top);if(!c.steps.length){const p=document.createElement('div');p.className='empty';p.textContent='No steps: this request is not applicable.';detail.append(p);return}const list=document.createElement('div');list.className='steps';for(const s of c.steps){const box=document.createElement('div');box.className='step';const row=document.createElement('div');row.className='steprow';const num=document.createElement('span');num.className='num';num.textContent='#'+s.step_no;const phase=document.createElement('span');phase.className='phase';phase.textContent=s.phase;const op=document.createElement('span');op.className='op';op.textContent=s.operation;row.append(num,phase,op);const res=document.createElement('div');res.className='resource';res.textContent=s.system_id+' / '+s.resource_id;const m=document.createElement('div');m.className='stepmeta';const state=document.createElement('span');state.textContent='State: '+s.state;const ev=document.createElement('span');ev.textContent='Evidence: '+(s.evidence_id||'planned');m.append(state,ev);box.append(row,res,m);list.append(box)}detail.append(list)}
function render(){const q=search.value.trim().toLowerCase(),f=filter.value;const shown=CASES.filter(c=>(f==='ALL'||c.deletion_status===f)&&(!q||(c.case_id+' '+c.deletion_status+' '+JSON.stringify(c.steps)).toLowerCase().includes(q)));tbody.replaceChildren();document.getElementById('empty').hidden=shown.length>0;document.getElementById('resultcount').textContent=shown.length.toLocaleString()+' of '+total.toLocaleString()+' cases';for(const c of shown){const tr=document.createElement('tr');tr.dataset.id=c.case_id;tr.classList.toggle('active',c.case_id===selected);tr.addEventListener('click',()=>showCase(c));const id=document.createElement('td');id.className='caseid';id.textContent=c.case_id;const st=document.createElement('td');st.append(badge(c.deletion_status));const n=document.createElement('td');n.className='stepscount';n.textContent=c.steps.length;tr.append(id,st,n);tbody.append(tr)}if(!shown.some(c=>c.case_id===selected)&&shown.length)showCase(shown[0]);else if(!shown.length)detail.replaceChildren()}
search.addEventListener('input',render);filter.addEventListener('change',render);render();if(CASES.length)showCase(CASES[0]);
</script></body></html>'''


def load_rows(csv_path: Path) -> list[dict]:
    records=[]
    with csv_path.open('r',encoding='utf-8-sig',newline='') as f:
        for row in csv.DictReader(f):
            steps=json.loads(row['steps_json'])
            records.append({'case_id':row['case_id'],'deletion_status':row['deletion_status'],'steps':steps})
    if not records:
        raise ValueError(f'No cases found in {csv_path}')
    return records


def build(csv_path: Path, html_path: Path) -> None:
    data=json.dumps(load_rows(csv_path),ensure_ascii=False,separators=(',',':')).replace('<','\\u003c')
    html=TEMPLATE.replace('__DATA__',data)
    html_path.write_text(html,encoding='utf-8')


def main() -> int:
    parser=argparse.ArgumentParser(description='Build a local interactive dashboard from output.csv')
    parser.add_argument('--input',type=Path,default=ROOT/'output.csv',help='Audit result CSV')
    parser.add_argument('--output',type=Path,default=ROOT/'dashboard.html',help='Generated dashboard HTML')
    parser.add_argument('--no-open',action='store_true',help='Generate without launching a browser')
    args=parser.parse_args()
    if not args.input.is_file():
        parser.error(f'Output file not found: {args.input}. Run python main.py first.')
    build(args.input.resolve(),args.output.resolve())
    print(f'Dashboard created: {args.output.resolve()}')
    if not args.no_open:
        webbrowser.open(args.output.resolve().as_uri())
        print('Opened the dashboard in your default browser.')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
