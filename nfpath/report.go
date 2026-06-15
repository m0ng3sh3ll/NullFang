package main

import (
	"database/sql"
	"fmt"
	"html"
	"os"
	"strings"
	"time"
)

type reportData struct {
	Generated    string
	CredCount    int
	HighCredCount int
	HostCount    int
	ServiceCount int
	DecisionCount int
	PendingCount int
	Credentials  []reportCred
	Hosts        []reportHost
	Services     []reportService
	Decisions    []reportDecision
	GraphNodes   string
	GraphEdges   string
}

type reportCred struct {
	Username      string
	PasswordClear string
	Hash          string
	Token         string
	ServiceType   string
	Confidence    string
	HostHint      string
	Context       string
}

type reportHost struct {
	Identifier     string
	IdentifierType string
	InferredType   string
	Confidence     string
	Note           string
}

type reportService struct {
	Name     string
	Type     string
	Endpoint string
	Port     int
}

type reportDecision struct {
	ID                int
	FilePath          string
	Host              string
	MatchReason       string
	InferredValue     string
	RecommendedAction string
	Priority          string
	Status            string
}

func runReport(nfpathDB *sql.DB, outPath string) error {
	d := &reportData{
		Generated: time.Now().Format("2006-01-02 15:04:05"),
	}

	nfpathDB.QueryRow("SELECT COUNT(*) FROM intel_credentials").Scan(&d.CredCount)
	nfpathDB.QueryRow("SELECT COUNT(*) FROM intel_credentials WHERE confidence='high'").Scan(&d.HighCredCount)
	nfpathDB.QueryRow("SELECT COUNT(*) FROM intel_hosts").Scan(&d.HostCount)
	nfpathDB.QueryRow("SELECT COUNT(*) FROM intel_services").Scan(&d.ServiceCount)
	nfpathDB.QueryRow("SELECT COUNT(*) FROM intel_decisions").Scan(&d.DecisionCount)
	nfpathDB.QueryRow("SELECT COUNT(*) FROM intel_decisions WHERE status='pending'").Scan(&d.PendingCount)

	rows, _ := nfpathDB.Query(`
		SELECT username, password_clear, hash, token, service_type, confidence, host_hint, context_note
		FROM intel_credentials
		ORDER BY CASE confidence WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END`)
	if rows != nil {
		for rows.Next() {
			var c reportCred
			var user, pass, hash, token, svc, conf, host, ctx sql.NullString
			rows.Scan(&user, &pass, &hash, &token, &svc, &conf, &host, &ctx)
			c.Username = user.String
			c.PasswordClear = pass.String
			c.Hash = hash.String
			c.Token = token.String
			c.ServiceType = svc.String
			c.Confidence = conf.String
			c.HostHint = host.String
			c.Context = ctx.String
			d.Credentials = append(d.Credentials, c)
		}
		rows.Close()
	}

	rows2, _ := nfpathDB.Query(`
		SELECT identifier, identifier_type, inferred_type, confidence, discovery_note
		FROM intel_hosts ORDER BY confidence`)
	if rows2 != nil {
		for rows2.Next() {
			var h reportHost
			var ident, itype, inferred, conf, note sql.NullString
			rows2.Scan(&ident, &itype, &inferred, &conf, &note)
			h.Identifier = ident.String
			h.IdentifierType = itype.String
			h.InferredType = inferred.String
			h.Confidence = conf.String
			h.Note = note.String
			d.Hosts = append(d.Hosts, h)
		}
		rows2.Close()
	}

	rows3, _ := nfpathDB.Query(`SELECT service_name, service_type, endpoint, port FROM intel_services`)
	if rows3 != nil {
		for rows3.Next() {
			var s reportService
			var name, stype, endpoint sql.NullString
			var port sql.NullInt64
			rows3.Scan(&name, &stype, &endpoint, &port)
			s.Name = name.String
			s.Type = stype.String
			s.Endpoint = endpoint.String
			if port.Valid {
				s.Port = int(port.Int64)
			}
			d.Services = append(d.Services, s)
		}
		rows3.Close()
	}

	rows4, _ := nfpathDB.Query(`
		SELECT id, file_path, host, match_reason, inferred_value, recommended_action, priority, status
		FROM intel_decisions
		ORDER BY CASE priority WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END`)
	if rows4 != nil {
		for rows4.Next() {
			var dec reportDecision
			var path, host, reason, inferred, action, pri, status sql.NullString
			rows4.Scan(&dec.ID, &path, &host, &reason, &inferred, &action, &pri, &status)
			dec.FilePath = path.String
			dec.Host = host.String
			dec.MatchReason = reason.String
			dec.InferredValue = inferred.String
			dec.RecommendedAction = action.String
			dec.Priority = pri.String
			dec.Status = status.String
			d.Decisions = append(d.Decisions, dec)
		}
		rows4.Close()
	}

	d.GraphNodes, d.GraphEdges = buildGraphJSON(d)

	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create report: %w", err)
	}
	defer f.Close()

	fmt.Fprint(f, renderHTML(d))
	fmt.Printf("[nfpath] Report written to %s\n", outPath)
	return nil
}

func buildGraphJSON(d *reportData) (nodes, edges string) {
	var nb, eb strings.Builder
	nodeID := 1

	hostIDs := make(map[string]int)
	credIDs := make(map[int]int) // index → graph id

	for _, h := range d.Hosts {
		hostIDs[h.Identifier] = nodeID
		colorMap := map[string]string{"high": "#ef4444", "medium": "#f97316", "low": "#6b7280"}
		color := colorMap[h.Confidence]
		if color == "" {
			color = "#6b7280"
		}
		if nodeID > 1 {
			nb.WriteString(",")
		}
		nb.WriteString(fmt.Sprintf(`{"id":%d,"label":%q,"group":"host","color":%q,"title":%q}`,
			nodeID, h.Identifier, color, html.EscapeString(h.InferredType)))
		nodeID++
	}

	for i, c := range d.Credentials {
		credIDs[i] = nodeID
		label := c.Username
		if c.ServiceType != "" {
			label += "\n" + c.ServiceType
		}
		colorMap := map[string]string{"high": "#22c55e", "medium": "#eab308", "low": "#6b7280"}
		color := colorMap[c.Confidence]
		if color == "" {
			color = "#6b7280"
		}
		if nodeID > 1 || len(d.Hosts) > 0 {
			nb.WriteString(",")
		}
		nb.WriteString(fmt.Sprintf(`{"id":%d,"label":%q,"group":"cred","color":%q,"title":%q}`,
			nodeID, label, color, html.EscapeString(c.Context)))

		// Edge: cred → host if host hint matches
		if c.HostHint != "" {
			if hid, ok := hostIDs[c.HostHint]; ok {
				eb.WriteString(fmt.Sprintf(`{"from":%d,"to":%d,"label":"authenticates"},`, nodeID, hid))
			}
		}
		nodeID++
	}
	_ = credIDs

	nodes = "[" + nb.String() + "]"
	e := strings.TrimSuffix(eb.String(), ",")
	edges = "[" + e + "]"
	return
}

func renderHTML(d *reportData) string {
	riskLevel := "LOW"
	riskColor := "#22c55e"
	if d.HighCredCount > 0 || d.DecisionCount > 3 {
		riskLevel = "HIGH"
		riskColor = "#ef4444"
	} else if d.CredCount > 0 {
		riskLevel = "MEDIUM"
		riskColor = "#f97316"
	}

	var credRows strings.Builder
	for _, c := range d.Credentials {
		fmt.Fprintf(&credRows, `
		<tr><td>%s</td><td>%s</td><td class="mono">%s</td><td class="mono">%s</td>
		<td>%s</td><td class="badge-%s">%s</td><td>%s</td></tr>`,
			he(c.Username), he(c.PasswordClear), he(truncate(c.Hash, 32)), he(truncate(c.Token, 32)),
			he(c.ServiceType), he(c.Confidence), he(c.Confidence), he(c.HostHint),
		)
	}

	var hostRows strings.Builder
	for _, h := range d.Hosts {
		fmt.Fprintf(&hostRows, `
		<tr><td>%s</td><td>%s</td><td>%s</td><td class="badge-%s">%s</td><td>%s</td></tr>`,
			he(h.Identifier), he(h.IdentifierType), he(h.InferredType),
			he(h.Confidence), he(h.Confidence), he(h.Note),
		)
	}

	var decRows strings.Builder
	for _, dec := range d.Decisions {
		fmt.Fprintf(&decRows, `
		<tr><td class="badge-pri-%s">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class="badge-status">%s</td></tr>`,
			he(dec.Priority), he(strings.ToUpper(dec.Priority)),
			he(dec.FilePath), he(dec.Host), he(dec.InferredValue), he(dec.RecommendedAction), he(dec.Status),
		)
	}

	// The graph script is built separately to avoid %% escaping issues inside the big template.
	graphScript := buildGraphScript(d.GraphNodes, d.GraphEdges)

	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>nfpath Intelligence Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0f172a;color:#e2e8f0;font-family:'Segoe UI',system-ui,sans-serif;font-size:14px}
.header{background:#1e293b;padding:24px 32px;border-bottom:1px solid #334155}
.header h1{font-size:22px;font-weight:700;color:#f8fafc;letter-spacing:.5px}
.header .sub{color:#94a3b8;font-size:13px;margin-top:4px}
.risk-badge{display:inline-block;padding:4px 12px;border-radius:4px;font-weight:700;font-size:13px;color:#fff;margin-left:12px;background:` + riskColor + `}
.exec{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;padding:24px 32px}
.stat-card{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:16px;text-align:center}
.stat-card .num{font-size:32px;font-weight:700;color:#f8fafc}
.stat-card .label{font-size:12px;color:#64748b;margin-top:4px;text-transform:uppercase;letter-spacing:.5px}
.section{padding:0 32px 32px}
details{background:#1e293b;border:1px solid #334155;border-radius:8px;margin-bottom:12px;overflow:hidden}
summary{padding:14px 18px;cursor:pointer;font-weight:600;color:#f1f5f9;list-style:none;display:flex;align-items:center;gap:8px}
summary::before{content:'▶';font-size:10px;color:#64748b;transition:.2s}
details[open] summary::before{content:'▼'}
.table-wrap{overflow-x:auto;padding:0 18px 18px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:8px 10px;color:#64748b;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid #334155}
td{padding:8px 10px;border-bottom:1px solid #1e293b;vertical-align:top;word-break:break-word;max-width:280px}
tr:hover td{background:#263147}
.mono{font-family:'Fira Code',monospace;font-size:12px;color:#a5b4fc}
.badge-high{color:#22c55e;font-weight:600}
.badge-medium{color:#eab308;font-weight:600}
.badge-low{color:#6b7280}
.badge-pri-critical{color:#ef4444;font-weight:700}
.badge-pri-high{color:#f97316;font-weight:700}
.badge-pri-medium{color:#eab308}
.badge-pri-low{color:#6b7280}
.badge-status{color:#94a3b8;font-size:12px}
#graph-wrap{position:relative;margin:0 18px 18px;border-radius:8px;overflow:hidden;background:#0a1628}
canvas#graph{display:block;width:100%;cursor:grab}
canvas#graph:active{cursor:grabbing}
.legend{display:flex;flex-wrap:wrap;gap:16px;padding:8px 18px;font-size:12px;color:#64748b}
.legend span{display:flex;align-items:center;gap:6px}
.dot{width:10px;height:10px;border-radius:50%;display:inline-block}
#tooltip{position:fixed;background:#1e293b;border:1px solid #334155;border-radius:6px;padding:8px 12px;
  font-size:12px;color:#e2e8f0;pointer-events:none;display:none;max-width:300px;z-index:99;white-space:pre-wrap}
</style>
</head>
<body>
<div id="tooltip"></div>
<div class="header">
  <h1>nfpath Intelligence Report <span class="risk-badge">` + riskLevel + `</span></h1>
  <div class="sub">Generated: ` + d.Generated + `</div>
</div>
<div class="exec">
  <div class="stat-card"><div class="num">` + fmt.Sprintf("%d", d.CredCount) + `</div><div class="label">Credentials</div></div>
  <div class="stat-card"><div class="num">` + fmt.Sprintf("%d", d.HighCredCount) + `</div><div class="label">High Confidence</div></div>
  <div class="stat-card"><div class="num">` + fmt.Sprintf("%d", d.HostCount) + `</div><div class="label">Hosts / Services</div></div>
  <div class="stat-card"><div class="num">` + fmt.Sprintf("%d", d.PendingCount) + `</div><div class="label">Decisions Pending</div></div>
</div>
<div class="section">
<details open>
  <summary>Intelligence Graph</summary>
  <div class="legend">
    <span><span class="dot" style="background:#ef4444"></span>High-confidence host</span>
    <span><span class="dot" style="background:#f97316"></span>Medium-confidence host</span>
    <span><span class="dot" style="background:#22c55e"></span>High-confidence credential</span>
    <span><span class="dot" style="background:#eab308"></span>Medium credential</span>
    <span><span class="dot" style="background:#38bdf8"></span>Service</span>
  </div>
  <div id="graph-wrap"><canvas id="graph" height="500"></canvas></div>
</details>
<details open>
  <summary>Credentials (` + fmt.Sprintf("%d", d.CredCount) + ` found)</summary>
  <div class="table-wrap">
  <table>
    <thead><tr><th>Username</th><th>Password</th><th>Hash</th><th>Token</th><th>Service</th><th>Confidence</th><th>Host</th></tr></thead>
    <tbody>` + credRows.String() + `</tbody>
  </table>
  </div>
</details>
<details>
  <summary>Hosts &amp; Services (` + fmt.Sprintf("%d", d.HostCount) + ` found)</summary>
  <div class="table-wrap">
  <table>
    <thead><tr><th>Identifier</th><th>Type</th><th>Inferred Service</th><th>Confidence</th><th>Source</th></tr></thead>
    <tbody>` + hostRows.String() + `</tbody>
  </table>
  </div>
</details>
<details open>
  <summary>Decision Table (` + fmt.Sprintf("%d", d.PendingCount) + ` pending operator action)</summary>
  <div class="table-wrap">
  <table>
    <thead><tr><th>Priority</th><th>File Path</th><th>Host</th><th>Inferred Value</th><th>Recommended Action</th><th>Status</th></tr></thead>
    <tbody>` + decRows.String() + `</tbody>
  </table>
  </div>
</details>
</div>
` + graphScript + `
</body>
</html>`
}

// buildGraphScript returns an inline <script> block that renders a force-directed
// graph on the canvas element using plain JS — no external dependencies.
func buildGraphScript(nodesJSON, edgesJSON string) string {
	return `<script>
(function(){
var nodesData=` + nodesJSON + `;
var edgesData=` + edgesJSON + `;
var canvas=document.getElementById('graph');
var tip=document.getElementById('tooltip');
var W=canvas.parentElement.clientWidth||800;
var H=500;
canvas.width=W;
canvas.height=H;
var ctx=canvas.getContext('2d');
if(!ctx||!nodesData.length){return;}

// init positions in a circle to avoid overlap
var n=nodesData.length;
nodesData.forEach(function(nd,i){
  nd.x=W/2+Math.cos(2*Math.PI*i/n)*Math.min(W,H)*0.35;
  nd.y=H/2+Math.sin(2*Math.PI*i/n)*Math.min(W,H)*0.35;
  nd.vx=0;nd.vy=0;nd.pinned=false;
});

// build adjacency for highlight
var adj={};
edgesData.forEach(function(e){
  if(!adj[e.from])adj[e.from]={};
  if(!adj[e.to])adj[e.to]={};
  adj[e.from][e.to]=true;
  adj[e.to][e.from]=true;
});

var iter=0;var maxIter=400;
function tick(){
  if(iter>=maxIter)return;iter++;
  for(var i=0;i<nodesData.length;i++){
    for(var j=i+1;j<nodesData.length;j++){
      var a=nodesData[i],b=nodesData[j];
      var dx=b.x-a.x,dy=b.y-a.y;
      var d=Math.sqrt(dx*dx+dy*dy)||1;
      var f=-3500/(d*d);
      var fx=f*dx/d,fy=f*dy/d;
      a.vx+=fx;a.vy+=fy;b.vx-=fx;b.vy-=fy;
    }
  }
  edgesData.forEach(function(e){
    var a=findNode(e.from),b=findNode(e.to);
    if(!a||!b)return;
    var dx=b.x-a.x,dy=b.y-a.y;
    var d=Math.sqrt(dx*dx+dy*dy)||1;
    var f=(d-130)*0.04;
    var fx=f*dx/d,fy=f*dy/d;
    if(!a.pinned){a.vx+=fx;a.vy+=fy;}
    if(!b.pinned){b.vx-=fx;b.vy-=fy;}
  });
  nodesData.forEach(function(nd){
    if(nd.pinned)return;
    nd.vx+=(W/2-nd.x)*0.004;
    nd.vy+=(H/2-nd.y)*0.004;
    nd.vx*=0.82;nd.vy*=0.82;
    nd.x=Math.max(22,Math.min(W-22,nd.x+nd.vx));
    nd.y=Math.max(22,Math.min(H-22,nd.y+nd.vy));
  });
}

function findNode(id){return nodesData.find(function(n){return n.id===id;});}

var hovered=null;var selected=null;
var panX=0,panY=0,panStart=null;

function draw(){
  ctx.clearRect(0,0,W,H);
  ctx.fillStyle='#0a1628';ctx.fillRect(0,0,W,H);
  ctx.save();ctx.translate(panX,panY);

  // edges
  edgesData.forEach(function(e){
    var a=findNode(e.from),b=findNode(e.to);
    if(!a||!b)return;
    var isHot=selected&&(selected.id===e.from||selected.id===e.to);
    ctx.beginPath();
    ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);
    ctx.strokeStyle=isHot?'#7dd3fc':'#334155';
    ctx.lineWidth=isHot?1.8:1.2;
    ctx.stroke();
    if(e.label&&isHot){
      ctx.fillStyle='#94a3b8';ctx.font='10px sans-serif';ctx.textAlign='center';
      ctx.fillText(e.label,(a.x+b.x)/2,(a.y+b.y)/2-5);
    }
  });

  // nodes
  nodesData.forEach(function(nd){
    var isSelected=selected&&selected.id===nd.id;
    var isAdj=selected&&adj[selected.id]&&adj[selected.id][nd.id];
    var dim=selected&&!isSelected&&!isAdj;
    var color=nd.color||'#475569';
    var r=20;
    // glow for selected/adjacent
    if(isSelected||isAdj){
      ctx.shadowColor=color;ctx.shadowBlur=12;
    } else {
      ctx.shadowBlur=0;
    }
    ctx.beginPath();ctx.arc(nd.x,nd.y,r,0,Math.PI*2);
    ctx.fillStyle=dim?'#1e293b':color;
    ctx.globalAlpha=dim?0.35:1;
    ctx.fill();
    ctx.shadowBlur=0;
    ctx.strokeStyle=nd===hovered?'#f8fafc':'#0f172a';
    ctx.lineWidth=nd===hovered?2.5:1.5;ctx.stroke();
    // label
    ctx.globalAlpha=dim?0.3:1;
    ctx.fillStyle='#f1f5f9';ctx.font='bold 10px sans-serif';ctx.textAlign='center';
    var lbl=nd.label||'';
    if(lbl.length>14)lbl=lbl.substring(0,13)+'…';
    // multi-line: split on \n
    var parts=lbl.split('\n');
    parts.forEach(function(p,i){ctx.fillText(p,nd.x,nd.y+4+(i-(parts.length-1)/2)*13);});
    ctx.globalAlpha=1;
  });

  ctx.restore();
}

function loop(){tick();draw();requestAnimationFrame(loop);}
loop();

// Interaction helpers
function canvasPos(ev){
  var r=canvas.getBoundingClientRect();
  return {x:(ev.clientX-r.left)-panX,y:(ev.clientY-r.top)-panY};
}
function nodeAt(x,y){
  return nodesData.find(function(nd){var dx=nd.x-x,dy=nd.y-y;return dx*dx+dy*dy<22*22;});
}

canvas.addEventListener('mousemove',function(ev){
  var p=canvasPos(ev);
  var nd=nodeAt(p.x,p.y);
  hovered=nd||null;
  if(nd&&nd.title){
    tip.style.display='block';
    tip.style.left=(ev.clientX+14)+'px';
    tip.style.top=(ev.clientY-10)+'px';
    tip.textContent=nd.label+'\n'+nd.title;
  } else {
    tip.style.display='none';
  }
  if(drag){drag.x=p.x;drag.y=p.y;}
  else if(panStart){
    panX+=ev.clientX-panStart.x;panY+=ev.clientY-panStart.y;
    panStart={x:ev.clientX,y:ev.clientY};
  }
});

var drag=null;
canvas.addEventListener('mousedown',function(ev){
  var p=canvasPos(ev);
  var nd=nodeAt(p.x,p.y);
  if(nd){drag=nd;nd.pinned=true;selected=nd;iter=0;}
  else{panStart={x:ev.clientX,y:ev.clientY};selected=null;}
});
canvas.addEventListener('mouseup',function(){
  if(drag){drag.pinned=false;drag=null;}
  panStart=null;
});
canvas.addEventListener('mouseleave',function(){
  tip.style.display='none';hovered=null;
  if(drag){drag.pinned=false;drag=null;}
  panStart=null;
});

// Resize
window.addEventListener('resize',function(){
  W=canvas.parentElement.clientWidth||800;canvas.width=W;iter=0;
});
})();
</script>`
}

func he(s string) string {
	return html.EscapeString(s)
}
