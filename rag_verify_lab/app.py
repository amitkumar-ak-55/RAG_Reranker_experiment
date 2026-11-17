from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, field_validator

from .config import settings
from .db import ArmResult, ExperimentRun, Finding, Image, Job, Question, VM, db_session, init_db
from .experiment.arms import ARMS
from .experiment.runner import run_experiment
from .jobs import job_queue
from .questions import export_jsonl, import_jsonl
from .reports import csv_report, json_manifest
from .sweep import run_sweep
from .images import SUGGESTIONS
from .vms import add_vm, container_start, container_stop, image_list, image_pull
from .verify.jev_health import jev_health

init_db()
app = FastAPI(title="rag-verify-lab")


class VMInput(BaseModel):
    name: str
    ip: str
    image_ref: str
    container_port: int
    port_range: str = "1-1024"
    notes: str = ""

    @field_validator("ip")
    @classmethod
    def valid_ip_or_cidr(cls, value: str) -> str:
        from .scan.nmap_runner import validate_target
        return validate_target(value)


class ImageInput(BaseModel):
    ref: str
    description: str = ""


class QuestionInput(BaseModel):
    text: str
    gold_answer: str = ""
    answerable: bool = True
    vm_id: int | None = None
    gold_finding_ids: list[int] = []


class JobInput(BaseModel):
    type: str
    target: str = ""
    ids: list[int] = []
    arms: list[str] = []
    authorized: bool = False


class ScanInput(BaseModel):
    target: str
    authorized: bool = False
    tools: list[str] = ["nmap", "nuclei"]

    @field_validator("target")
    @classmethod
    def valid_target(cls, value: str) -> str:
        from .scan.nmap_runner import validate_target
        return validate_target(value)


class AuthorizationInput(BaseModel):
    authorized: bool = False


def serialize(obj: Any) -> dict[str, Any]:
    result = {column.name: getattr(obj, column.name) for column in obj.__table__.columns}
    for key, value in result.items():
        if hasattr(value, "isoformat"):
            result[key] = value.isoformat()
    return result


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    return PAGE


@app.get("/api/config")
def config() -> dict[str, Any]:
    return {
        "settings": settings.snapshot(),
        "answer_configured": bool(settings.answer_model and settings.gemini_api_key and settings.gemini_base_url),
        "jev_configured": bool(settings.jev_model and settings.jev_api_key and settings.jev_base_url),
        "arms": ARMS,
    }


@app.get("/api/findings")
def findings() -> list[dict[str, Any]]:
    with db_session() as db:
        return [serialize(item) for item in db.query(Finding).order_by(Finding.id.desc()).limit(200)]


@app.get("/api/experiments")
def experiments() -> list[dict[str, Any]]:
    with db_session() as db:
        runs = db.query(ExperimentRun).order_by(ExperimentRun.id.desc()).limit(20).all()
        results = db.query(ArmResult).order_by(ArmResult.id.desc()).all()
        by_run: dict[int, list[dict[str, Any]]] = {}
        for result in results:
            by_run.setdefault(result.run_id, []).append(serialize(result))
        return [
            {
                **serialize(run),
                "config": json.loads(run.config_snapshot_json or "{}"),
                "results": by_run.get(run.id, []),
            }
            for run in runs
        ]


@app.get("/api/jev/health")
def jev_health_route() -> dict[str, object]:
    return jev_health()


@app.get("/api/vms")
def vms() -> list[dict[str, Any]]:
    with db_session() as db:
        return [serialize(v) for v in db.query(VM).all()]


@app.post("/api/vms")
def create_vm(data: VMInput) -> dict[str, Any]:
    return serialize(add_vm(data.model_dump()))


@app.post("/api/vms/{vm_id}/start")
def start_vm(vm_id: int) -> dict[str, int]:
    return {"job_id": job_queue.enqueue("start", str(vm_id), lambda: container_start(vm_id))}


@app.post("/api/vms/{vm_id}/stop")
def stop_vm(vm_id: int) -> dict[str, int]:
    return {"job_id": job_queue.enqueue("stop", str(vm_id), lambda: container_stop(vm_id))}


@app.delete("/api/vms/{vm_id}")
def delete_vm(vm_id: int) -> dict[str, bool]:
    with db_session() as db:
        vm = db.get(VM, vm_id)
        if not vm:
            raise HTTPException(404, "VM not found")
        db.delete(vm)
        db.commit()
    return {"deleted": True}


@app.get("/api/images")
def images() -> dict[str, Any]:
    return {"suggestions": [{"ref": ref, "container_port": port} for ref, port in SUGGESTIONS], "images": [serialize(i) for i in image_list()]}


@app.post("/api/images")
def create_image(data: ImageInput) -> dict[str, bool]:
    with db_session() as db:
        db.merge(Image(ref=data.ref, description=data.description, pulled=False))
        db.commit()
    return {"created": True}


@app.post("/api/images/pull")
def pull_image(data: ImageInput) -> dict[str, int]:
    return {"job_id": job_queue.enqueue("pull", data.ref, lambda: image_pull(data.ref))}


@app.get("/api/questions")
def questions() -> list[dict[str, Any]]:
    with db_session() as db:
        return [serialize(q) for q in db.query(Question).all()]


@app.post("/api/questions")
def create_question(data: QuestionInput) -> dict[str, Any]:
    with db_session() as db:
        question = Question(text=data.text, gold_answer=data.gold_answer, answerable=data.answerable, vm_id=data.vm_id, gold_finding_ids=json.dumps(data.gold_finding_ids))
        db.add(question)
        db.commit()
        db.refresh(question)
        return serialize(question)


@app.put("/api/questions/{question_id}")
def update_question(question_id: int, data: QuestionInput) -> dict[str, Any]:
    with db_session() as db:
        question = db.get(Question, question_id)
        if not question:
            raise HTTPException(404, "Question not found")
        question.text, question.gold_answer, question.answerable = data.text, data.gold_answer, data.answerable
        question.vm_id, question.gold_finding_ids = data.vm_id, json.dumps(data.gold_finding_ids)
        db.commit()
        return serialize(question)


@app.delete("/api/questions/{question_id}")
def delete_question(question_id: int) -> dict[str, bool]:
    with db_session() as db:
        question = db.get(Question, question_id)
        if not question:
            raise HTTPException(404, "Question not found")
        db.delete(question)
        db.commit()
    return {"deleted": True}



@app.post("/api/questions/import")
def questions_import(data: dict[str, str]) -> dict[str, int]:
    return {"count": import_jsonl(data.get("text", ""))}


@app.get("/api/questions/export", response_class=PlainTextResponse)
def questions_export() -> str:
    return export_jsonl()


@app.get("/api/jobs")
def jobs() -> list[dict[str, Any]]:
    with db_session() as db:
        return [serialize(j) for j in db.query(Job).order_by(Job.id.desc()).limit(30)]


@app.post("/api/jobs/{job_id}/cancel")
def cancel_job(job_id: int) -> dict[str, bool]:
    return {"cancelled": job_queue.cancel(job_id)}


@app.post("/api/run")
def run(data: JobInput) -> dict[str, int]:
    if data.type == "sweep" and not data.authorized:
        raise HTTPException(400, "Authorization is required to run a sweep")
    if data.type != "sweep" and any(arm in {"hybrid_jev", "jev_retrieval", "4", "E", "arm_4", "arm_e"} for arm in data.arms):
        health = jev_health()
        if not all(health[key] for key in ("configured", "reachable", "authenticated", "model_accepted")):
            raise HTTPException(503, {"message": "JEV health check failed", "health": health})
    if data.type == "sweep":
        job_id = job_queue.enqueue("sweep", json.dumps(data.ids), lambda: run_sweep(data.ids, lambda: job_queue.is_cancelled(job_id)), authorized=True, tools=["nmap"])
        return {"job_id": job_id}
    return {"job_id": job_queue.enqueue("experiment", "", lambda: run_experiment(data.arms, data.ids))}


def _scanme_vm() -> tuple[int, str]:
    with db_session() as db:
        vm = db.query(VM).filter(VM.name == "scanme.nmap.org").first()
        if vm:
            return vm.id, vm.port_range
        vm = VM(
            name="scanme.nmap.org",
            ip="scanme.nmap.org",
            image_ref="",
            container_port=0,
            host_port=None,
            port_range="1-1000",
            status="stopped",
            notes="Public target; Nmap only",
        )
        db.add(vm)
        db.commit()
        db.refresh(vm)
        return vm.id, vm.port_range


@app.post("/api/scanme")
def scanme(data: AuthorizationInput) -> dict[str, int]:
    if not data.authorized:
        raise HTTPException(400, "Authorization is required to scan this target")
    vm_id, port_range = _scanme_vm()
    return _enqueue_scan(vm_id, "scanme.nmap.org", port_range, authorized=True, tools=["nmap"])


@app.post("/api/scan")
def scan(data: ScanInput) -> dict[str, int]:
    if not data.authorized:
        raise HTTPException(400, "Authorization is required to scan this target")
    return _enqueue_scan(None, data.target, "1-1000", authorized=True, tools=data.tools)


@app.post("/api/scan/{vm_id}")
def scan_vm(vm_id: int, data: AuthorizationInput) -> dict[str, int]:
    if not data.authorized:
        raise HTTPException(400, "Authorization is required to scan this target")
    with db_session() as db:
        vm = db.get(VM, vm_id)
        if not vm:
            raise HTTPException(404, "VM not found")
        target = "scanme.nmap.org" if vm.name == "scanme.nmap.org" else vm.ip
        port_range = "1-1000" if vm.name == "scanme.nmap.org" else vm.port_range
    return _enqueue_scan(vm_id, target, port_range, authorized=True, tools=["nmap"])


def _enqueue_scan(vm_id: int | None, target: str, port_range: str, *, authorized: bool, tools: list[str]) -> dict[str, int]:
    from .scan.nmap_runner import target_ip, validate_target
    validate_target(target)

    hostname, resolved_ip = target_ip(target)
    tools = [tool for tool in tools if tool in {"nmap", "nuclei"}]
    if not tools:
        raise HTTPException(400, "At least one scan tool is required")

    def scan() -> str:
        from .scan.nmap_runner import run_nmap_result

        result = run_nmap_result(target, port_range)
        with db_session() as db:
            vm = db.get(VM, vm_id)
            if vm:
                vm.ip = result.resolved_ip
            all_findings = list(result.findings)
            nuclei_findings = []
            if "nuclei" in tools:
                from .scan.nuclei_runner import run_nuclei
                nuclei_findings = run_nuclei(target)
                all_findings.extend(nuclei_findings)
            for finding in all_findings:
                data = finding.as_dict()
                data["vm_id"] = vm_id
                data["ip"] = result.resolved_ip
                data["raw_json"] = json.dumps(data["raw_json"])
                db.add(Finding(**{key: data[key] for key in ("run_id", "scanner", "vm_id", "ip", "port", "protocol", "service", "cve_id", "title", "severity", "description", "raw_json")}))
            db.commit()
        return (
            f"Tools: {', '.join(tools)}; Nmap command: {' '.join(result.command)}; "
            f"exit code: {result.exit_code}; {len(all_findings)} findings; XML: {result.xml_path}"
        )

    return {
        "job_id": job_queue.enqueue(
            "scan",
            target,
            scan,
            target_hostname=hostname,
            resolved_ip=resolved_ip,
            public_target=hostname.lower().rstrip(".") == "scanme.nmap.org",
            authorized=authorized,
            tools=tools,
        )
    }


@app.get("/api/reports/{format}")
def reports(format: str) -> PlainTextResponse:
    with db_session() as db:
        rows = [serialize(r) for r in db.query(ArmResult).all()]
    if format == "csv":
        return PlainTextResponse(csv_report(rows), media_type="text/csv")
    if format == "json":
        return PlainTextResponse(json_manifest(rows), media_type="application/json")
    raise HTTPException(404, "Unsupported report format")


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>rag-verify-lab</title>
<style>
:root{font:14px system-ui,sans-serif;color:#20242a;background:#f5f7fa}*{box-sizing:border-box}body{margin:0}header{background:#fff;padding:16px 24px;border-bottom:1px solid #dfe3e8}main{max-width:1440px;margin:20px auto;padding:0 16px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,360px),1fr));gap:14px}.panel{min-width:0;background:#fff;border:1px solid #dfe3e8;border-radius:9px;padding:16px;overflow-wrap:anywhere}.wide{grid-column:1/-1}h2{font-size:18px;margin:0 0 12px}h3{font-size:15px;margin:18px 0 8px}.muted{color:#667085}.status{padding:8px 10px;background:#f0f4f8;border-radius:6px;margin:8px 0}input,button{padding:8px;margin:3px;border:1px solid #c8ced6;border-radius:5px}button{cursor:pointer;background:#edf3f8}button:disabled{cursor:not-allowed;opacity:.55}label{display:inline-block;margin:4px}form{margin:8px 0}.list{max-height:300px;overflow:auto}.item{padding:8px 4px;border-bottom:1px solid #edf0f3}.item small{display:block;color:#667085;margin-top:3px}.error{color:#9b1c1c}.ok{color:#176b3a}.run{border-top:1px solid #e2e6eb;padding:12px 0}.run summary{cursor:pointer;font-weight:650}.results{max-height:240px;overflow:auto}.result{padding:7px 0;border-bottom:1px solid #edf0f3}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse}td,th{padding:7px;border-bottom:1px solid #edf0f3;text-align:left;white-space:nowrap}.jobs{max-height:230px;overflow:auto}.job{padding:5px 0;border-bottom:1px solid #edf0f3}.running{background:#fff7df}.pill{display:inline-block;padding:2px 7px;border-radius:12px;background:#edf3f8;font-size:12px}
</style></head><body><header><b>rag-verify-lab</b> <span class="muted">claim verification for hybrid RAG security assessment</span></header><main>
<div class="grid">
<section class="panel"><h2>Loaded settings</h2><div id="config" class="muted">Loading configuration?</div><button onclick="testJev()">Test JEV</button><div id="jevhealth" class="muted"></div></section>
<section class="panel"><h2>Scan target</h2><form id="scanform"><input name="target" placeholder="IP or hostname" required><label><input name="authorized" type="checkbox" required> I am authorized to scan this target.</label><button id="scanbutton" disabled>Scan</button></form><p id="scanerror" class="muted"></p><button id="scanmebutton" disabled onclick="scanme()">Scan scanme.nmap.org (Nmap only)</button><form id="vmform"><input name="name" placeholder="name" required><input name="ip" placeholder="IP" required><input name="image_ref" placeholder="image" required><input name="container_port" type="number" placeholder="container port" required><input name="port_range" value="1-1024"><button>Add</button></form><div id="vms"></div></section>
<section class="panel"><h2>Images</h2><div id="images"></div></section>
<section class="panel"><h2>Findings from scans</h2><p id="finding-summary" class="muted">Loading findings?</p><div id="findings" class="list"></div></section>
<section class="panel"><h2>Questions &amp; Run</h2><form id="qform"><input name="text" placeholder="question" required><input name="gold_answer" placeholder="gold answer"><label><input name="answerable" type="checkbox" checked> answerable</label><button>Add question</button></form><div id="questions"></div><div><label><input id=armA type="checkbox" checked> A: LLM only</label><label><input id=armC type="checkbox" checked> C: Hybrid RAG</label><label><input id=armD type="checkbox" checked> D: Hybrid RAG + JEV</label><label><input id=armE type="checkbox" checked> E: JEV retrieval</label></div><button onclick="runExp()">Run selected arms</button><p class="muted">Scanning stores findings. Select questions and run arms separately to evaluate them.</p></section>
<section class="panel"><h2>Sweep</h2><input id="sweepids" placeholder="target IDs, comma separated"><label><input id="sweepauth" type="checkbox"> I am authorized to scan these targets.</label><button id="sweepbutton" onclick="sweep()" disabled>Run sweep</button><p class="muted">Runs sequentially; failures continue.</p></section>
<section class="panel wide"><h2>Recent jobs</h2><div id="jobs" class="jobs">Loading jobs?</div></section>
<section class="panel wide"><h2>Experiment history</h2><p class="muted">Runs are shown separately. Old provider errors remain in their original run and are not mixed into new results.</p><div id="runs">Loading experiments?</div><h3>Retrieval comparison ? latest run</h3><p id="skipped" class="muted"></p><div id="retrieval" class="table-wrap"></div><h3>Reports</h3><a href="/api/reports/csv">CSV</a> ? <a href="/api/reports/json">JSON manifest</a></section>
</div></main><script>
const api=(u,o)=>fetch(u,o).then(async r=>{let data=await r.json();if(!r.ok)throw data;return data});
function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function showError(e){return esc(e?.detail?.message||e?.detail||e?.message||'Request failed')}
function scanme(){api('/api/scanme',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({authorized:true})}).then(refresh).catch(e=>document.querySelector('#scanerror').textContent=showError(e))}
function submitScan(e){e.preventDefault();let d=Object.fromEntries(new FormData(e.target));d.authorized=e.target.authorized.checked;api('/api/scan',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(d)}).then(refresh).catch(err=>document.querySelector('#scanerror').textContent=showError(err))}
function showJev(h){document.querySelector('#jevhealth').innerHTML=['configured','reachable','authenticated','model_accepted'].map(k=>`<p>${h[k]?'PASS':'FAIL'} ${k}</p>`).join('')+`<p>HTTP ${esc(h.http_status??'n/a')} ? ${esc(h.error_message||'')}</p>`}
function testJev(){api('/api/jev/health').then(showJev).catch(e=>showJev(e.health||{error_message:showError(e)}))}
document.querySelector('#scanform').onsubmit=submitScan;
document.querySelector('#scanform').authorized.onchange=e=>{document.querySelector('#scanbutton').disabled=!e.target.checked;document.querySelector('#scanmebutton').disabled=!e.target.checked};
document.querySelector('#sweepauth').onchange=e=>document.querySelector('#sweepbutton').disabled=!e.target.checked;
async function refresh(){try{let [cfg,v,i,q,j,runs,findings]=await Promise.all([api('/api/config'),api('/api/vms'),api('/api/images'),api('/api/questions'),api('/api/jobs'),api('/api/experiments'),api('/api/findings')]);renderConfig(cfg);renderVMs(v);renderImages(i);renderQuestions(q);renderJobs(j);renderFindings(findings);renderRuns(runs)}catch(e){document.querySelector('#config').textContent='Dashboard refresh failed: '+showError(e)}}
function renderConfig(c){let s=c.settings;document.querySelector('#config').innerHTML=`<div class="status"><b>Answer model:</b> ${esc(s.answer_model||'not configured')} <span class="pill ${c.answer_configured?'ok':'error'}">${c.answer_configured?'configured':'not configured'}</span><small>Endpoint: ${esc(s.gemini_base_url||'not configured')}</small></div><div class="status"><b>JEV model:</b> ${esc(s.jev_model||'not configured')} <span class="pill ${c.jev_configured?'ok':'error'}">${c.jev_configured?'configured':'not configured'}</span><small>Settings are loaded when the server starts.</small></div>`}
function renderVMs(v){document.querySelector('#vms').innerHTML=v.map(x=>`<div class="item"><b>${esc(x.id)} ${esc(x.name)}</b> ? ${esc(x.ip)} ? ${esc(x.status)} ${x.host_port?`? ${esc(x.host_port)}`:''}<div><button onclick="act('/api/vms/${x.id}/start')">Start</button><button onclick="act('/api/vms/${x.id}/stop')">Stop</button><button onclick="scanVm(${x.id})">Scan</button></div></div>`).join('')}
function renderImages(i){document.querySelector('#images').innerHTML=i.suggestions.map(x=>`<div class="item">${esc(x.ref)} (${esc(x.container_port)})</div>`).join('')+i.images.map(x=>`<div class="item">${esc(x.ref)}: ${x.pulled?'pulled':'not pulled'} <button onclick="pull('${esc(x.ref)}')">Pull</button></div>`).join('')}
function renderQuestions(q){document.querySelector('#questions').innerHTML=q.map(x=>`<label><input class="q" type="checkbox" value="${x.id}"> ${x.id}: ${esc(x.text)}</label><br>`).join('')||'<p class="muted">No questions yet.</p>'}
function renderJobs(j){let visible=j.filter(x=>x.status==='queued'||x.status==='running').concat(j.filter(x=>x.status!=='queued'&&x.status!=='running').slice(0,8));document.querySelector('#sweepbutton').disabled=visible.some(x=>['queued','running'].includes(x.status))||!document.querySelector('#sweepauth').checked;document.querySelector('#jobs').innerHTML=visible.map(x=>`<div class="job ${x.status==='running'?'running':''}"><b>#${x.id} ${esc(x.type)}</b> ? ${esc(x.status)} ${x.target?`? ${esc(x.target)}`:''}<small>${esc(x.message||'')}</small>${['queued','running'].includes(x.status)?`<button onclick="act('/api/jobs/${x.id}/cancel')">Cancel</button>`:''}</div>`).join('')||'<p class="muted">No jobs yet.</p>'}
function renderFindings(rows){document.querySelector('#finding-summary').textContent=`${rows.length} stored finding${rows.length===1?'':'s'}${rows.length===200?' (showing latest 200)':''}. A scan with zero findings is still a completed scan.`;document.querySelector('#findings').innerHTML=rows.map(f=>`<div class="item"><b>${esc(f.title||f.service||'Finding')}</b> ${f.cve_id?`<span class="pill">${esc(f.cve_id)}</span>`:''}<small>${esc(f.scanner)} ? ${esc(f.ip)}${f.port?`:${esc(f.port)}`:''} ? ${esc(f.severity||'severity unknown')}</small><small>${esc(f.description||'No description recorded.')}</small></div>`).join('')||'<p class="muted">No findings have been stored yet.</p>'}
function renderRuns(runs){let host=document.querySelector('#runs');if(!runs.length){host.innerHTML='<p class="muted">No experiment runs yet. A scan does not automatically run the selected questions.</p>';document.querySelector('#retrieval').innerHTML='';document.querySelector('#skipped').textContent='';return}host.innerHTML=runs.map((run,index)=>{let cfg=run.config||{};let resultHtml=run.results.map(x=>`<div class="result"><b>${esc(x.arm)}</b> ? question ${x.question_id} ${x.error?`<div class="error">${esc(x.error)}</div>`:`<div>${esc(x.answer||'No answer text recorded.')}</div>`}</div>`).join('')||'<p class="muted">No arm results recorded.</p>';return `<details class="run" ${index===0?'open':''}><summary>Run #${run.id} ? ${esc(run.status)} ? ${esc(run.started_at)} ? model ${esc(cfg.answer_model||'not recorded')}</summary><div class="results">${resultHtml}</div></details>`}).join('');let latest=runs[0],retrieval=latest.results.filter(x=>['hybrid_rag','hybrid_jev','jev_retrieval'].includes(x.arm));document.querySelector('#skipped').textContent=`Run #${latest.id}: questions skipped for missing gold evidence: ${retrieval.filter(x=>x.gold_evidence_skipped).length}`;document.querySelector('#retrieval').innerHTML=retrieval.length?`<table><tr><th>Arm</th><th>Question</th><th>P@1</th><th>P@3</th><th>P@5</th><th>Retrieval ms</th><th>JEV calls</th></tr>${retrieval.map(x=>`<tr><td>${esc(x.arm)}</td><td>${x.question_id}</td><td>${x.precision_at_1??'n/a'}</td><td>${x.precision_at_3??'n/a'}</td><td>${x.precision_at_5??'n/a'}</td><td>${Number(x.retrieval_latency_ms||0).toFixed(1)}</td><td>${x.jev_calls??0}</td></tr>`).join('')}</table>`:'<p class="muted">No retrieval arm results in the latest run.</p>'}
function scanVm(id){if(!document.querySelector('#scanform').authorized.checked){alert('Check authorization before scanning');return}api('/api/scan/'+id,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({authorized:true})}).then(refresh).catch(e=>document.querySelector('#scanerror').textContent=showError(e))}
function act(u){api(u,{method:'POST'}).then(refresh).catch(e=>alert(showError(e)))}function pull(ref){api('/api/images/pull',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({ref})}).then(refresh).catch(e=>alert(showError(e)))}
function sweep(){let ids=document.querySelector('#sweepids').value.split(',').filter(Boolean).map(Number);api('/api/run',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({type:'sweep',ids,authorized:document.querySelector('#sweepauth').checked})}).then(refresh).catch(e=>alert(showError(e)))}
function runExp(){let ids=[...document.querySelectorAll('.q:checked')].map(x=>Number(x.value)),arms=[];if(document.querySelector('#armA').checked)arms.push('llm_only');if(document.querySelector('#armC').checked)arms.push('hybrid_rag');if(document.querySelector('#armD').checked)arms.push('hybrid_jev');if(document.querySelector('#armE').checked)arms.push('jev_retrieval');api('/api/run',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({type:'experiment',ids,arms})}).then(refresh).catch(e=>alert(showError(e)))}
document.querySelector('#vmform').onsubmit=e=>{e.preventDefault();let d=Object.fromEntries(new FormData(e.target));if(!/^(\\d{1,3}\\.){3}\\d{1,3}(\\/\\d{1,2})?$/.test(d.ip)){alert('Enter an IP or CIDR');return}api('/api/vms',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(d)}).then(refresh).catch(err=>alert(showError(err)))};
document.querySelector('#qform').onsubmit=e=>{e.preventDefault();let d=Object.fromEntries(new FormData(e.target));d.answerable=e.target.answerable.checked;api('/api/questions',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(d)}).then(refresh).catch(err=>alert(showError(err)))};
refresh();setInterval(refresh,3000);
</script></body></html>"""


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("rag_verify_lab.app:app", host="127.0.0.1", port=8000, reload=False)
