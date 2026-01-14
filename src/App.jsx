import { useState } from 'react'
import { Shield, Search, Globe, AlertTriangle, CheckCircle, Lock, Server, Mail, Network, Layout, DollarSign, FileText, ChevronRight, Activity, Zap, Cpu, Layers, Calendar, MapPin, FileCode, Eye, Database, Globe2, XCircle, ChevronDown, ChevronUp, Info } from 'lucide-react'

// --- COMPONENTS ---
const SectionHeader = ({ icon: Icon, title, subtitle }) => (
    <div className="mb-6">
        <h3 className="flex items-center gap-2">
            <Icon className="w-4 h-4 text-blue-400" />
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300">{title}</span>
        </h3>
        {subtitle && <p className="text-[10px] text-slate-500 mt-1 ml-6">{subtitle}</p>}
    </div>
);

const ScoringLegend = () => (
    <div className="bg-[#0b0f1a] border border-slate-800 rounded-xl p-4 mt-6">
        <h4 className="text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-3 flex items-center gap-2">
            <Info className="w-3 h-3" /> Scoring Logic
        </h4>
        <div className="grid grid-cols-2 gap-2 text-[10px]">
            <div className="flex justify-between text-slate-400"><span>A (90-100)</span> <span className="text-emerald-400">Optimal</span></div>
            <div className="flex justify-between text-slate-400"><span>B (80-89)</span> <span className="text-blue-400">Good</span></div>
            <div className="flex justify-between text-slate-400"><span>C (70-79)</span> <span className="text-amber-400">Warning</span></div>
            <div className="flex justify-between text-slate-400"><span>D-F (&lt;69)</span> <span className="text-rose-400">Critical</span></div>
        </div>
    </div>
);

const ComplianceBar = ({ label, data }) => {
    if (!data) return null;
    return (
        <div className="mb-6 last:mb-0">
            <div className="flex justify-between items-end mb-2">
                <span className="text-sm font-bold text-slate-200">{label}</span>
                <span className={`text-sm font-mono font-bold ${data.score > 80 ? 'text-emerald-400' : data.score > 50 ? 'text-amber-400' : 'text-rose-400'}`}>
                    {data.score}%
                </span>
            </div>
            <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden mb-3">
                <div className={`h-full rounded-full transition-all duration-1000 ${data.score > 80 ? 'bg-emerald-500' : data.score > 50 ? 'bg-amber-500' : 'bg-rose-500'}`} style={{ width: `${data.score}%` }}></div>
            </div>
            <div className="flex flex-wrap gap-2">
                {data.passing?.map((item, i) => (<span key={i} className="text-[10px] flex items-center gap-1 text-emerald-400/80 bg-emerald-950/30 px-2 py-0.5 rounded border border-emerald-900/50"><CheckCircle className="w-3 h-3" /> {item}</span>))}
                {data.failing?.map((item, i) => (<span key={i} className="text-[10px] flex items-center gap-1 text-rose-400/80 bg-rose-950/30 px-2 py-0.5 rounded border border-rose-900/50"><XCircle className="w-3 h-3" /> {item}</span>))}
            </div>
        </div>
    );
};

const DonutChart = ({ score, grade, color }) => {
  const radius = 80;
  const circumference = 2 * Math.PI * radius; 
  const offset = circumference - (score / 100) * circumference;
  return (
    <div className="relative w-64 h-64 flex items-center justify-center">
      <div className={`absolute inset-0 rounded-full blur-3xl opacity-10 ${color.bg.replace('bg-', 'bg-')}`}></div>
      <svg className="w-full h-full transform -rotate-90 drop-shadow-2xl">
        <circle cx="128" cy="128" r={radius} stroke="#1e293b" strokeWidth="16" fill="transparent" strokeLinecap="round" />
        <circle cx="128" cy="128" r={radius} stroke="currentColor" strokeWidth="16" fill="transparent" strokeLinecap="round" strokeDasharray={circumference} strokeDashoffset={offset} className={`transition-all duration-[1.5s] ease-out ${color.text}`} />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className={`text-8xl font-black tracking-tighter ${color.text} drop-shadow-lg`}>{grade}</span>
        <span className="text-slate-400 font-medium text-lg mt-[-5px]">{score} / 100</span>
      </div>
    </div>
  );
};

const HeatMap = ({ findings }) => {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    if(findings) findings.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });
    const getColor = (count, severity) => {
        if (count === 0) return 'bg-emerald-500/10 border-emerald-500/20 text-emerald-500';
        if (severity === 'Critical') return 'bg-rose-500 text-white shadow-lg shadow-rose-900/40';
        if (severity === 'High') return 'bg-orange-500 text-white shadow-lg shadow-orange-900/40';
        if (severity === 'Medium') return 'bg-amber-400 text-black shadow-lg shadow-amber-900/40';
        return 'bg-blue-500 text-white shadow-lg shadow-blue-900/40';
    };
    return (
        <div className="bg-[#0b0f1a] border border-slate-800 rounded-3xl p-6 h-full flex flex-col">
            <SectionHeader icon={Layout} title="Vulnerability Heat Map" />
            <div className="flex-1 grid grid-cols-2 gap-3">
                {['Critical', 'High', 'Medium', 'Low'].map(sev => (
                    <div key={sev} className={`rounded-2xl p-4 border flex flex-col justify-between transition-all ${getColor(counts[sev], sev)}`}><span className="text-xs font-bold uppercase tracking-wider opacity-80">{sev}</span><span className="text-4xl font-black">{counts[sev]}</span></div>
                ))}
            </div>
        </div>
    )
}

function App() {
  const [domain, setDomain] = useState('')
  const [loading, setLoading] = useState(false)
  const [report, setReport] = useState(null)
  const [showAllAssets, setShowAllAssets] = useState(false)

  const handleScan = async () => {
    if (!domain) return;
    setLoading(true);
    setReport(null);
    setShowAllAssets(false);
    try {
      const response = await fetch('https://riskprism-api.onrender.com/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domain })
      });
      const data = await response.json();
      setReport(data); 
    } catch (error) { alert("Backend Error. Is api.py running?"); }
    setLoading(false);
  };

  const getGradeStyle = (grade) => {
    if (grade === 'A') return { border: 'border-emerald-500/30', bg: 'bg-emerald-950/10', text: 'text-emerald-400', glow: 'shadow-[0_0_30px_-5px_rgba(16,185,129,0.3)]' };
    if (grade === 'B') return { border: 'border-blue-500/30', bg: 'bg-blue-950/10', text: 'text-blue-400', glow: 'shadow-[0_0_30px_-5px_rgba(59,130,246,0.3)]' };
    if (grade === 'C') return { border: 'border-amber-500/30', bg: 'bg-amber-950/10', text: 'text-amber-400', glow: 'shadow-[0_0_30px_-5px_rgba(245,158,11,0.3)]' };
    if (grade === 'N/A') return { border: 'border-slate-800', bg: 'bg-slate-900', text: 'text-slate-500', glow: '' };
    return { border: 'border-rose-500/30', bg: 'bg-rose-950/10', text: 'text-rose-400', glow: 'shadow-[0_0_30px_-5px_rgba(225,29,72,0.3)]' };
  };

  const estimateRisk = (score) => {
    if (score >= 90) return { val: "$15k - $50k", label: "Very Low", color: "text-emerald-400" };
    if (score >= 80) return { val: "$50k - $150k", label: "Low", color: "text-blue-400" };
    if (score >= 70) return { val: "$150k - $500k", label: "Moderate", color: "text-amber-400" };
    return { val: "$500k - $2.5M", label: "CRITICAL", color: "text-rose-500" };
  };

  const calculateCompliance = (report) => {
      if (!report) return { iso: { score: 0 }, nist: { score: 0 }, gdpr: { score: 0 } };
      
      const tech_score = report.score;
      const has_privacy = report.compliance?.privacy?.privacy_policy ? 1 : 0;
      const has_waf = report.compliance?.resilience?.waf !== "None" ? 1 : 0;
      const has_sec = report.security_txt ? 1 : 0;

      const iso_passing = [], iso_failing = [];
      if(has_sec) iso_passing.push("A.16 Incident Mgmt"); else iso_failing.push("A.16 Incident Mgmt");
      if(has_waf) iso_passing.push("A.12 Ops Security"); else iso_failing.push("A.12 Ops Security");
      if(tech_score > 70) iso_passing.push("A.10 Cryptography"); else iso_failing.push("A.10 Cryptography");

      const nist_passing = [], nist_failing = [];
      if(has_waf) nist_passing.push("Protect (PR.PT)"); else nist_failing.push("Protect (PR.PT)");
      if(report.findings.length < 5) nist_passing.push("Detect (DE.AE)"); else nist_failing.push("Detect (DE.AE)");

      const gdpr_passing = [], gdpr_failing = [];
      if(has_privacy) gdpr_passing.push("Art 12 Transparency"); else gdpr_failing.push("Art 12 Transparency");
      if(report.compliance?.privacy?.cookie_banner) gdpr_passing.push("Art 7 Consent"); else gdpr_failing.push("Art 7 Consent");

      return {
          iso: { score: Math.min(100, Math.round((tech_score * 0.7) + (has_waf * 30))), passing: iso_passing, failing: iso_failing },
          nist: { score: Math.min(100, Math.round((tech_score * 0.6) + (has_waf * 40))), passing: nist_passing, failing: nist_failing },
          gdpr: { score: Math.min(100, Math.round((tech_score * 0.2) + (has_privacy * 80))), passing: gdpr_passing, failing: gdpr_failing }
      };
  };

  const complianceScores = calculateCompliance(report);

  return (
    <div className="min-h-screen bg-[#02040a] text-slate-100 font-sans p-6 md:p-12 selection:bg-blue-500/30">
      <nav className="max-w-7xl mx-auto flex justify-between items-center mb-16">
        <div className="flex items-center gap-3 group cursor-pointer">
          <div className="bg-gradient-to-tr from-blue-600 to-cyan-500 p-2.5 rounded-xl shadow-lg shadow-blue-500/20 transition-all"><Shield className="w-6 h-6 text-white" /></div>
          <div className="flex flex-col"><h1 className="text-2xl font-bold tracking-tight text-white leading-none">Risk<span className="text-blue-500">Prism</span></h1><span className="text-[10px] font-medium text-slate-500 uppercase tracking-[0.2em] mt-1">Cyber Risk Intelligence</span></div>
        </div>
        <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-900 border border-slate-800 text-xs font-medium text-slate-400"><Activity className="w-3 h-3 text-emerald-500 animate-pulse" />System Operational</div>
      </nav>

      <div className="max-w-3xl mx-auto mb-20 relative z-10">
        <div className="absolute inset-0 bg-blue-500/20 blur-[90px] rounded-full opacity-20 pointer-events-none"></div>
        <div className="relative group">
           <input type="text" placeholder="Audit vendor (e.g. google.com)" className="w-full bg-[#0b0f1a]/80 backdrop-blur-xl border border-slate-800/60 rounded-2xl py-6 pl-16 pr-40 text-lg text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500/50 focus:ring-4 focus:ring-blue-500/10 transition-all shadow-2xl" value={domain} onChange={(e) => setDomain(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && handleScan()} />
           <Search className="absolute left-6 top-7 text-slate-500 w-6 h-6 group-focus-within:text-blue-400 transition-colors" />
           <button onClick={handleScan} disabled={loading} className="absolute right-3 top-3 bottom-3 bg-blue-600 hover:bg-blue-500 text-white px-8 rounded-xl text-sm font-semibold transition-all shadow-lg shadow-blue-600/20 hover:shadow-blue-600/40 disabled:opacity-50 disabled:grayscale">{loading ? 'Scanning...' : 'Run Audit'}</button>
        </div>
      </div>

      {report && (
        <div className="max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-12 gap-8 animate-in fade-in slide-in-from-bottom-8 duration-700">
          
          <div className={`col-span-1 lg:col-span-4 rounded-3xl p-8 relative overflow-hidden flex flex-col items-center border ${getGradeStyle(report.grade).border} bg-[#0b0f1a] ${getGradeStyle(report.grade).glow}`}>
            <div className={`absolute top-0 inset-x-0 h-40 bg-gradient-to-b ${report.grade === 'A' ? 'from-emerald-500/10' : report.grade === 'C' ? 'from-amber-500/10' : 'from-rose-500/10'} to-transparent opacity-40`}></div>
            <SectionHeader icon={Shield} title="Security Posture Rating" />
            <DonutChart score={report.score} grade={report.grade} color={getGradeStyle(report.grade)} />
            
            <div className="w-full mt-6 pt-6 border-t border-slate-800 grid grid-cols-2 gap-y-4 gap-x-2">
                <div className="col-span-2 flex justify-between items-center mb-2"><span className="text-[10px] uppercase font-bold text-slate-500">Status</span>{report.is_live ? <span className="text-[10px] bg-emerald-900/30 text-emerald-400 px-2 py-0.5 rounded border border-emerald-800">Online</span> : <span className="text-[10px] bg-rose-900/30 text-rose-400 px-2 py-0.5 rounded border border-rose-800">Unreachable</span>}</div>
                <div><span className="text-[10px] text-slate-500 uppercase tracking-wider block mb-1">Registrar</span><span className="text-xs text-slate-300 font-medium truncate block" title={report.identity.registrar}>{report.identity.registrar?.substring(0, 15) || "N/A"}...</span></div>
                <div><span className="text-[10px] text-slate-500 uppercase tracking-wider block mb-1">Location</span><span className="text-xs text-slate-300 font-medium flex items-center gap-1"><MapPin className="w-3 h-3" /> {report.identity.country || "N/A"}</span></div>
                <div><span className="text-[10px] text-slate-500 uppercase tracking-wider block mb-1">Domain Age</span><span className="text-xs text-slate-300 font-medium flex items-center gap-1"><Calendar className="w-3 h-3" /> {report.identity.age || 0} Years</span></div>
                <div><span className="text-[10px] text-slate-500 uppercase tracking-wider block mb-1">Encryption</span><span className="text-xs text-emerald-400 font-medium flex items-center gap-1"><Lock className="w-3 h-3" /> {report.tls_version || "N/A"}</span></div>
            </div>
            
            {/* BREAKDOWN BOX */}
            <div className="w-full mt-6 space-y-2">
                <h4 className="text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-2">Impact Drivers</h4>
                {report.breakdown && report.breakdown.length > 0 ? (
                    report.breakdown.slice(0, 3).map((item, i) => (
                        <div key={i} className="flex justify-between items-center text-xs p-2 rounded bg-slate-900/50 border border-slate-800">
                            <span className="text-slate-300 truncate w-4/5">{item.reason}</span>
                            <span className="text-rose-400 font-mono font-bold">-{item.points}</span>
                        </div>
                    ))
                ) : <span className="text-xs text-slate-500 italic">No major deductions.</span>}
            </div>
            <ScoringLegend />
          </div>

          <div className="col-span-1 lg:col-span-8 grid grid-cols-1 md:grid-cols-2 gap-6">
             <div className="md:col-span-2 bg-[#0b0f1a] border border-slate-800 rounded-3xl p-8 relative overflow-hidden">
                <div className="absolute top-0 left-0 w-1 h-full bg-blue-500"></div>
                <SectionHeader icon={FileText} title="CISO Executive Summary" />
                <p className="text-slate-300 text-lg font-light leading-relaxed italic">"{report.ai_summary}"</p>
             </div>
             <div className="bg-[#0b0f1a] border border-slate-800 rounded-3xl p-8 flex flex-col justify-center">
                <SectionHeader icon={DollarSign} title="Financial Impact (ALE)" />
                <div className="text-4xl font-bold text-slate-100 tracking-tight">{estimateRisk(report.score).val}</div>
                <div className="text-sm text-slate-500 mt-2">Risk Exposure: <span className={`${estimateRisk(report.score).color} font-bold`}>{estimateRisk(report.score).label}</span></div>
             </div>
             <HeatMap findings={report.findings || []} />
          </div>

          <div className="col-span-1 lg:col-span-12 grid grid-cols-1 md:grid-cols-3 gap-6">
             <div className="bg-[#0b0f1a] border border-slate-800 rounded-3xl p-6">
                <SectionHeader icon={Database} title="Framework Compliance" />
                <ComplianceBar label="ISO 27001" data={complianceScores.iso} />
                <ComplianceBar label="NIST CSF" data={complianceScores.nist} />
                <ComplianceBar label="GDPR" data={complianceScores.gdpr} />
             </div>
             <div className="bg-[#0b0f1a] border border-slate-800 rounded-3xl p-6">
                <SectionHeader icon={Eye} title="Privacy & Governance" />
                <div className="space-y-4">
                    <div className="flex justify-between items-center p-3 rounded-xl bg-[#02040a] border border-slate-800"><span className="text-sm text-slate-300">Privacy Policy</span>{report.compliance?.privacy?.privacy_policy ? <CheckCircle className="w-5 h-5 text-emerald-500" /> : <XCircle className="w-5 h-5 text-rose-500" />}</div>
                    <div className="flex justify-between items-center p-3 rounded-xl bg-[#02040a] border border-slate-800"><span className="text-sm text-slate-300">Cookie Banner</span>{report.compliance?.privacy?.cookie_banner ? <CheckCircle className="w-5 h-5 text-emerald-500" /> : <XCircle className="w-5 h-5 text-rose-500" />}</div>
                    <div className="p-3 rounded-xl bg-[#02040a] border border-slate-800"><span className="text-xs text-slate-500 block mb-2">Trust Signals</span><div className="flex flex-wrap gap-2">{report.compliance?.privacy?.trust_badges?.length > 0 ? (report.compliance.privacy.trust_badges.map(b => (<span key={b} className="text-[10px] bg-blue-900/30 text-blue-300 px-2 py-1 rounded border border-blue-800">{b}</span>))) : <span className="text-xs text-slate-600 italic">No badges found</span>}</div></div>
                </div>
             </div>
             <div className="bg-[#0b0f1a] border border-slate-800 rounded-3xl p-6">
                <SectionHeader icon={Globe2} title="Resilience & Infra" />
                <div className="space-y-3">
                    <div className="p-3 rounded-xl bg-[#02040a] border border-slate-800"><span className="text-xs text-slate-500 block mb-1">WAF / CDN Provider</span><span className="text-sm font-bold text-white flex items-center gap-2">{report.compliance?.resilience?.waf === "None" ? <Zap className="w-4 h-4 text-amber-500" /> : <CheckCircle className="w-4 h-4 text-emerald-500" />}{report.compliance?.resilience?.waf}</span></div>
                    <div className="p-3 rounded-xl bg-[#02040a] border border-slate-800"><div className="flex justify-between"><span className="text-sm text-slate-300">DNSSEC Signing</span>{report.compliance?.resilience?.dnssec ? <span className="text-xs bg-emerald-900/30 text-emerald-400 px-2 py-1 rounded">Active</span> : <span className="text-xs bg-slate-800 text-slate-500 px-2 py-1 rounded">Inactive</span>}</div></div>
                    <div className="p-3 rounded-xl bg-[#02040a] border border-slate-800"><span className="text-xs text-slate-500 block mb-2">Detected Tech</span><div className="flex flex-wrap gap-2">{report.technologies?.slice(0,4).map((t, i) => (<span key={i} className="text-[10px] text-slate-400 border border-slate-700 px-2 py-1 rounded">{t.name}</span>))}</div></div>
                </div>
             </div>
          </div>

          <div className="col-span-1 lg:col-span-12">
             <div className="bg-[#0b0f1a] border border-slate-800 rounded-3xl p-6">
                <SectionHeader icon={Activity} title="Risk Category Scorecard" />
                <div className="grid grid-cols-2 md:grid-cols-7 gap-3">
                    {report.category_grades && Object.entries(report.category_grades).map(([cat, grade]) => {
                    const style = getGradeStyle(grade);
                    return (
                        <div key={cat} className={`rounded-xl p-4 border ${style.border} ${style.bg}`}>
                            <div className="text-[10px] text-slate-400 uppercase tracking-wider mb-2 h-8 leading-tight">{cat}</div>
                            <div className={`text-3xl font-bold ${style.text}`}>{grade}</div>
                        </div>
                    )
                    })}
                </div>
             </div>
          </div>
          
          <div className="col-span-1 lg:col-span-8 bg-[#0b0f1a] border border-slate-800 rounded-3xl p-8">
             <div className="flex items-center justify-between mb-6"><SectionHeader icon={AlertTriangle} title="Compliance Violations" subtitle={`${report.findings?.length || 0} Issues Detected`} /></div>
             <div className="space-y-4">
               {report.findings?.map((f, i) => (
                 <div key={i} className="group flex flex-col md:flex-row gap-5 p-5 rounded-2xl bg-[#02040a] border border-slate-800/50 hover:border-slate-700 transition-colors">
                    <div className="min-w-[4px] rounded-full bg-gradient-to-b from-slate-700 to-transparent"></div>
                    <div className="flex-1">
                       <div className="flex justify-between items-start mb-1">
                          <div className="flex items-center gap-2"><h4 className="text-slate-200 font-bold group-hover:text-blue-400 transition-colors">{f.title}</h4><span className="text-[10px] font-mono text-slate-500 bg-slate-900 border border-slate-800 px-2 py-0.5 rounded">{f.category}</span></div>
                          <span className={`text-[10px] font-bold px-2 py-1 rounded uppercase tracking-wide ${f.severity === 'Critical' || f.severity === 'High' ? 'bg-rose-500/10 text-rose-500' : f.severity === 'Medium' ? 'bg-amber-500/10 text-amber-500' : 'bg-emerald-500/10 text-emerald-500'}`}>{f.severity}</span>
                       </div>
                       <p className="text-slate-400 text-sm mb-3 font-light leading-relaxed">{f.description}</p>
                       <div className="flex flex-wrap gap-2">
                          {f.compliance?.iso !== "-" && <div className="inline-flex items-center gap-2 px-3 py-1 rounded bg-[#0f172a] border border-indigo-500/20 text-indigo-400 text-xs font-medium"><span className="w-1 h-1 rounded-full bg-indigo-500"></span>ISO {f.compliance.iso}</div>}
                          {f.compliance?.nist !== "-" && <div className="inline-flex items-center gap-2 px-3 py-1 rounded bg-[#0f172a] border border-blue-500/20 text-blue-400 text-xs font-medium"><span className="w-1 h-1 rounded-full bg-blue-500"></span>NIST {f.compliance.nist}</div>}
                          {f.compliance?.mitre !== "-" && <div className="inline-flex items-center gap-2 px-3 py-1 rounded bg-[#0f172a] border border-rose-500/20 text-rose-400 text-xs font-medium"><span className="w-1 h-1 rounded-full bg-rose-500"></span>MITRE {f.compliance.mitre.split(' ')[0]}</div>}
                       </div>
                    </div>
                 </div>
               ))}
             </div>
          </div>

          <div className="col-span-1 lg:col-span-4 space-y-6">
             <div className="bg-[#0b0f1a] border border-slate-800 rounded-3xl p-6">
                <SectionHeader icon={Mail} title="Brand Defense" />
                <div className="space-y-3">
                   <div className="p-4 rounded-xl bg-[#02040a] border border-slate-800">
                      <div className="flex justify-between mb-2"><span className="text-xs text-slate-500">DMARC Policy</span>{report.email_security?.dmarc?.includes("reject") ? <CheckCircle className="w-4 h-4 text-emerald-500" /> : <Zap className="w-4 h-4 text-amber-500" />}</div>
                      <code className="text-[10px] text-slate-400 break-all font-mono leading-relaxed block">{report.email_security?.dmarc || "No DMARC Record"}</code>
                   </div>
                </div>
             </div>
             
             <div className="bg-[#0b0f1a] border border-slate-800 rounded-3xl p-6">
                <SectionHeader icon={Network} title="Attack Surface" />
                <div className={`transition-all duration-500 ${showAllAssets ? 'max-h-60 overflow-y-auto pr-2' : ''}`}>
                   <div className="flex flex-wrap gap-2">
                       {report.subdomains?.length > 0 ? (
                          (showAllAssets ? report.subdomains : report.subdomains.slice(0, 8)).map((sub, i) => (
                             <div key={i} className="px-3 py-1.5 rounded-lg bg-[#02040a] border border-pink-500/20 text-pink-300 text-xs font-mono truncate max-w-full">{sub}</div>
                          ))
                       ) : <span className="text-slate-500 text-xs italic">No hidden assets detected.</span>}
                   </div>
                </div>
                {report.subdomains?.length > 8 && (
                   <button onClick={() => setShowAllAssets(!showAllAssets)} className="mt-4 pt-4 border-t border-slate-800 w-full flex justify-between items-center text-xs text-slate-400 cursor-pointer hover:text-white transition-colors"><span>{showAllAssets ? "Show Less" : `View all ${report.subdomains.length} assets`}</span>{showAllAssets ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}</button>
                )}
             </div>
          </div>

        </div>
      )}
    </div>
  )
}

export default App
