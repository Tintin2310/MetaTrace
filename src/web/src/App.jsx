import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  Network, Activity, ShieldAlert, Cpu, Database, 
  Eye, Globe, TrendingUp, Download, ShieldCheck, 
  LayoutDashboard, Terminal, Settings, AlertTriangle, Search,
  Monitor, Smartphone, HardDrive, Shield, Zap,
  Wifi, WifiOff, RefreshCw, SignalHigh
} from 'lucide-react';
import Plot from 'react-plotly.js';

function App() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedIp, setSelectedIp] = useState(null);
  const [targetDomain, setTargetDomain] = useState('');
  const [currentView, setCurrentView] = useState('dashboard'); // 'dashboard', 'lab', 'settings'
  
  // Forensic Lab State
  const [labStatus, setLabStatus] = useState('Idle');
  const [labLogs, setLabLogs] = useState([]);
  const [nearbyDevices, setNearbyDevices] = useState([]);
  const [isScanning, setIsScanning] = useState(false);

  // Settings State
  const [settings, setSettings] = useState({
    deepInspection: true,
    autoUnmask: false,
    threatGuard: true,
    sensorSensitivity: 75
  });

  const fetchData = async () => {
    try {
      const response = await axios.get('http://127.0.0.1:8000/api/dashboard');
      setData(response.data);
      setLoading(false);
    } catch (err) {
      console.error(err);
      setError(err.message || 'Failed to fetch data');
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="flex bg-[#05050a] h-screen items-center justify-center text-primary">
        <div className="flex flex-col items-center">
          <Activity className="animate-spin mb-4" size={48} />
          <h2 className="text-xl font-bold tracking-[0.3em] uppercase animate-pulse">Initializing System Core</h2>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex bg-background h-screen items-center justify-center text-danger">
        <div className="glass-panel p-8 text-center max-w-lg border-danger/30">
          <ShieldAlert className="mx-auto mb-4" size={48} />
          <h2 className="text-2xl font-bold mb-2 uppercase tracking-tighter">Link Failure</h2>
          <p className="text-textMuted">{error}</p>
          <p className="text-sm mt-4 text-textMuted/70 font-mono">RETRYING UPLINK...</p>
        </div>
      </div>
    );
  }

  const { statistics, attributions, summaries, raw_metadata, charts, vpn_analysis, threat_feed, entropy_scores, metadata_extraction, packet_extraction } = data;

  const plotlyLayout = {
    paper_bgcolor: 'transparent',
    plot_bgcolor: 'transparent',
    font: { color: '#E2E8F0', family: 'Inter' },
    xaxis: { gridcolor: 'rgba(255,255,255,0.05)', zeroline: false },
    yaxis: { gridcolor: 'rgba(255,255,255,0.05)', zeroline: false },
  };

  const triggerNearbyScan = async () => {
    setIsScanning(true);
    setLabStatus('SCANNING');
    try {
      const resp = await axios.get('http://127.0.0.1:8000/api/scan/nearby');
      setNearbyDevices(resp.data.devices);
      setLabLogs(prev => [...prev, {
        time: new Date().toLocaleTimeString(),
        event: `PROXIMITY_SCAN_SUCCESS`,
        payload: `${resp.data.devices.length} nodes found`,
        status: 'SUCCESS'
      }]);
      setLabStatus('COMPLETED');
    } catch (err) {
      setLabStatus('ERROR');
    } finally {
      setIsScanning(false);
    }
  };

  const triggerDNSLeak = async () => {
    // If a domain is typed, the "Trigger" button should perform the deep unmasking
    // instead of just a generic simulated probe message.
    if (targetDomain.trim()) {
      handleForensicLookup();
      return;
    }

    setLabStatus('LEAKING');
    try {
      const resp = await axios.post('http://127.0.0.1:8000/api/forensics/dns_leak');
      setLabLogs(prev => [...prev, {
        time: new Date().toLocaleTimeString(),
        event: `DNS_LEAK_PROBE_SENT`,
        payload: resp.data.message,
        status: 'SUCCESS'
      }]);
    } catch (err) {
      console.error(err);
    } finally {
      setLabStatus('IDLE');
    }
  };

  const handleForensicLookup = async () => {
    const domain = targetDomain.trim();
    if (!domain) return;
    
    setLabStatus('UNMASKING');
    setLabLogs(prev => [...prev, {
      time: new Date().toLocaleTimeString(),
      event: `NSLOOKUP_INITIALIZED`,
      payload: `Target: ${domain}`,
      status: 'PROCESS'
    }]);

    try {
      const resp = await axios.post('http://127.0.0.1:8000/api/forensics/nslookup', { domain });
      if (resp.data.leak_detected || resp.data.unmasked_data) {
        const leakIP = resp.data.unmasked_data?.real_ip || resp.data.resolved_ip;
        setLabLogs(prev => [...prev, {
          time: new Date().toLocaleTimeString(),
          event: `UNMASKING_SUCCESS`,
          payload: `Real IP: ${leakIP}`,
          status: 'CRITICAL'
        }]);
      } else {
        setLabLogs(prev => [...prev, {
          time: new Date().toLocaleTimeString(),
          event: `RESOLVED`,
          payload: `Mapping to ${resp.data.resolved_ip}`,
          status: 'SUCCESS'
        }]);
      }
      // Refresh global state immediately to reflect the new leak
      fetchData();
    } catch (err) {
      console.error("Forensic Lookup Error:", err);
      setLabStatus('ERROR');
    } finally {
      setLabStatus('IDLE');
    }
  };

  const resetLab = async () => {
    try {
      await axios.post('http://127.0.0.1:8000/api/reset_lab');
      setLabLogs([]);
      // The dashboard data will refresh on the next interval
      // but we can force it here if needed.
    } catch (err) {
      console.error("Failed to reset lab:", err);
    }
  };

  return (
    <div className="flex min-h-screen bg-[#05050a] text-textMain overflow-hidden font-sans">
      {/* Sidebar Navigation */}
      <nav className="w-20 lg:w-64 bg-black/40 border-r border-white/5 flex flex-col p-4 z-50 backdrop-blur-3xl">
        <div className="flex items-center gap-3 mb-12 px-2">
          <div className="p-2 bg-primary rounded-lg shadow-[0_0_15px_rgba(66,133,244,0.6)]">
            <Network size={24} className="text-white" />
          </div>
          <span className="hidden lg:block font-black text-xl tracking-tighter text-white">META<span className="text-primary">TRACE</span></span>
        </div>

        <div className="flex-1 space-y-2">
          <SidebarLink 
            active={currentView === 'dashboard'} 
            onClick={() => setCurrentView('dashboard')}
            icon={<LayoutDashboard size={20} />} 
            label="Dashboard" 
          />
          <SidebarLink 
            active={currentView === 'lab'} 
            onClick={() => setCurrentView('lab')}
            icon={<Terminal size={20} />} 
            label="Forensic Lab" 
          />
          <SidebarLink 
            active={currentView === 'settings'} 
            onClick={() => setCurrentView('settings')}
            icon={<Settings size={20} />} 
            label="System Config" 
          />
        </div>

        <div className="pt-4 border-t border-white/5 space-y-4">
          <div className="px-2 py-3 rounded-xl bg-white/5 border border-white/5">
            <div className="flex items-center gap-2 mb-2">
              <div className={`w-2 h-2 rounded-full ${statistics?.vpn_active ? 'bg-success animate-pulse shadow-[0_0_8px_#10b981]' : 'bg-danger shadow-[0_0_8px_#ef4444]'}`}></div>
              <span className="text-[10px] font-bold text-white/70 uppercase lg:block hidden">Uplink Status</span>
            </div>
            <div className="text-[10px] font-mono text-textMuted lg:block hidden">
              {statistics?.vpn_active ? statistics.vpn_interface : 'NO_TUNNEL_DETECTED'}
            </div>
          </div>
          
          <button 
            onClick={() => window.open('http://127.0.0.1:8000/api/export/report')}
            className="w-full flex items-center gap-3 p-3 rounded-xl bg-primary/10 border border-primary/20 text-primary hover:bg-primary/20 transition-all group"
          >
            <Download size={18} className="group-hover:scale-110 transition-transform" />
            <span className="hidden lg:block text-[10px] font-black uppercase tracking-widest">Hashed Report</span>
          </button>
        </div>
      </nav>

      {/* Main Content Area */}
      <main className="flex-1 overflow-y-auto custom-scrollbar relative p-6 lg:p-10">
        <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-primary/5 blur-[120px] rounded-full -translate-y-1/2 translate-x-1/2 pointer-events-none"></div>
        
        {currentView === 'dashboard' && (
          <div className="space-y-8 animate-in fade-in duration-500">
            <div className="flex justify-between items-end">
              <div>
                <h2 className="text-3xl font-black tracking-tighter text-white">SYSTEM <span className="text-primary">SNAPSHOT</span></h2>
                <p className="text-textMuted text-sm font-medium">Real-time endpoint behavioral analysis and OS fingerprinting.</p>
              </div>
              <div className="flex gap-4 items-center">
                <div className="hidden lg:flex gap-6 mr-6 border-r border-white/10 pr-6 items-center">
                  <div className="flex flex-col items-end">
                    <span className="text-[9px] font-black uppercase text-white/30">Throughput</span>
                    <span className="text-xs font-mono text-success font-black tracking-tighter animate-pulse">
                      {statistics?.throughput?.kbps || "0.00"} <span className="text-[9px] opacity-60">Kbps</span>
                    </span>
                  </div>
                  <div className="flex flex-col items-end">
                    <span className="text-[9px] font-black uppercase text-white/30">Packets/s</span>
                    <span className="text-xs font-mono text-primary font-black tracking-tighter">
                      {statistics?.throughput?.pps || "0.00"} <span className="text-[9px] opacity-60">PPS</span>
                    </span>
                  </div>
                </div>
                <StatBadge label="Packets" value={statistics?.total_packets || 0} icon={<Database size={14} />} />
                <StatBadge label="Endpoints" value={statistics?.unique_endpoints || 0} icon={<Globe size={14} />} />
              </div>
            </div>

            {/* Dashboard Integration: Proximity Discovery and Forensic Tables */}
            <div className="grid grid-cols-12 gap-6">
              {/* Nearby Discovery */}
              <div className="col-span-12 lg:col-span-4 bg-white/5 border border-white/5 rounded-3xl p-6 flex flex-col gap-6">
                    <h3 className="text-sm font-black uppercase tracking-widest text-primary flex items-center gap-2">
                      <Monitor size={18} /> Network Proximity
                    </h3>
                    <div className="flex gap-2">
                      <button 
                        disabled={isScanning}
                        onClick={triggerNearbyScan}
                        className="p-2 rounded-lg bg-primary/20 text-primary hover:bg-primary/30 transition-all disabled:opacity-50"
                        title="Scan Neighbors"
                      >
                        {isScanning ? <Activity className="animate-spin" size={16} /> : <RefreshCw size={16} />}
                      </button>
                      <button 
                        disabled={isScanning}
                        onClick={triggerNearbyScan}
                        className="px-3 py-1 text-[10px] font-black uppercase bg-primary text-white rounded-lg hover:bg-primary/80 transition-all flex items-center gap-2"
                      >
                        <Zap size={12} /> Deep Probe
                      </button>
                    </div>

                 <div className="flex-1 overflow-y-auto max-h-[300px] space-y-3 custom-scrollbar">
                    {nearbyDevices && nearbyDevices.length > 0 ? (
                      nearbyDevices.map((device, i) => (
                        <div key={i} className="bg-black/40 border border-white/5 p-4 rounded-xl flex items-center justify-between group hover:border-primary/30 transition-all">
                          <div className="flex items-center gap-3">
                            <Smartphone size={16} className="text-primary opacity-50 group-hover:opacity-100" />
                            <div className="flex flex-col">
                              <span className="text-xs font-bold text-white">{device.ip}</span>
                              <span className="text-[9px] text-textMuted font-mono">{device.mac}</span>
                            </div>
                          </div>
                          <div className="text-[9px] font-mono text-primary font-bold">DISCOVERED</div>
                        </div>
                      ))
                    ) : (
                      <div className="h-full flex flex-col items-center justify-center opacity-30 text-center py-10">
                        <Monitor size={32} className="mb-2" />
                        <p className="text-[10px] uppercase font-bold">No proximity data</p>
                      </div>
                    )}
                 </div>
              </div>

              {/* Metadata Extraction Table */}
              <div className="col-span-12 lg:col-span-8 bg-white/5 border border-white/5 rounded-3xl p-6">
                <h3 className="text-sm font-black uppercase tracking-widest text-accent mb-6 flex items-center gap-2">
                  <Database size={18} /> Metadata Extraction
                </h3>
                <div className="bg-black/40 border border-white/5 rounded-xl overflow-hidden overflow-y-auto max-h-[300px] custom-scrollbar">
                  <table className="w-full text-left text-[10px] font-mono">
                    <thead className="bg-white/5 text-textMuted uppercase sticky top-0 z-10">
                      <tr>
                        <th className="p-3">Source</th>
                        <th className="p-3">Extracted Data</th>
                        <th className="p-3">Real IP</th>
                        <th className="p-3">Risk</th>
                      </tr>
                    </thead>
                    <tbody>
                      {metadata_extraction && metadata_extraction.length > 0 ? (
                        metadata_extraction.map((item, i) => (
                          <tr key={i} className="border-t border-white/5 hover:bg-white/5 transition-colors">
                            <td className="p-3 text-primary">{item.source}</td>
                            <td className="p-3 text-white truncate max-w-[200px]">{item.data}</td>
                            <td className="p-3 text-danger">{item.real_ip || '---'}</td>
                            <td className={`p-3 font-bold ${item.severity === 'CRITICAL' ? 'text-danger' : 'text-accent'}`}>{item.severity || 'HIGH'}</td>
                          </tr>
                        ))
                      ) : (
                        <tr><td colSpan="4" className="p-10 text-center opacity-30 uppercase tracking-[0.2em]">No Metadata Leaks Intercepted</td></tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Packets Extracted Table */}
              <div className="col-span-12 bg-white/5 border border-white/5 rounded-3xl p-6">
                <h3 className="text-sm font-black uppercase tracking-widest text-primary mb-6 flex items-center gap-2">
                  <Zap size={18} /> Packets Extracted (Live Analysis)
                </h3>
                <div className="bg-black/40 border border-white/5 rounded-xl overflow-hidden overflow-y-auto max-h-[300px] custom-scrollbar">
                  <table className="w-full text-left text-[10px] font-mono">
                    <thead className="bg-white/5 text-textMuted uppercase sticky top-0 z-10">
                      <tr>
                        <th className="p-3">Timestamp</th>
                        <th className="p-3">Application</th>
                        <th className="p-3">Source IP</th>
                        <th className="p-3">Destination IP</th>
                        <th className="p-3">Confidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {packet_extraction && packet_extraction.length > 0 ? (
                        packet_extraction.map((item, i) => (
                          <tr key={i} className="border-t border-white/5 hover:bg-white/5 transition-colors">
                            <td className="p-3 text-textMuted">{item.timestamp}</td>
                            <td className="p-3 text-white font-bold">{item.app}</td>
                            <td className="p-3 text-primary">{item.source_ip || '---'}</td>
                            <td className="p-3 text-primary">{item.dest_ip || '---'}</td>
                            <td className="p-3 text-success">{(item.confidence * 100).toFixed(0)}%</td>
                          </tr>
                        ))
                      ) : (
                        <tr><td colSpan="5" className="p-10 text-center opacity-30 uppercase tracking-[0.2em]">No Application Packets Decoded</td></tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-12 gap-6">
              <div className="col-span-12 xl:col-span-8 space-y-6">
                <div className="glass-panel p-6 h-[760px] relative overflow-hidden group">
                   <div className="absolute inset-0 bg-gradient-to-t from-primary/5 to-transparent pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity"></div>
                   <div className="scanline"></div>
                   <h3 className="text-xs font-black uppercase tracking-widest text-primary mb-6 flex items-center gap-2">
                    <Network size={14} /> Global Topology & Attribution Map
                   </h3>
                   <div className="h-full w-full -mt-4">
                    {charts?.network_graph ? (
                      <Plot
                        data={charts.network_graph.data}
                        layout={{ ...charts.network_graph.layout, ...plotlyLayout, margin: { t: 0, b: 0, l: 0, r: 0 }, autosize: true }}
                        useResizeHandler={true}
                        className="w-full h-full"
                        config={{ displayModeBar: false }}
                      />
                    ) : <LoadingPlaceholder />}
                   </div>
                </div>
              </div>

              <div className="col-span-12 xl:col-span-4 space-y-6">
                {/* Live Threat Intelligence */}
                <div className="glass-panel p-6 h-[220px] bg-gradient-to-br from-[#100a0a] to-black border-danger/10">
                   <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-danger mb-4 flex items-center gap-2">
                    <ShieldAlert size={14} className="animate-pulse" /> Global Threat Feed
                   </h3>
                   <div className="space-y-3 overflow-hidden">
                      {threat_feed?.map((item, i) => (
                        <div key={i} className="flex items-center justify-between gap-3 animate-in slide-in-from-right duration-500" style={{ animationDelay: `${i*100}ms` }}>
                          <div className="flex flex-col min-w-0">
                            <span className="text-[9px] font-mono text-textMuted uppercase">{item.time} - {item.node}</span>
                            <span className="text-[10px] font-bold text-white truncate">{item.event}</span>
                          </div>
                          <span className={`px-2 py-0.5 rounded-full text-[8px] font-black ${item.risk === 'CRITICAL' ? 'bg-danger text-white' : 'bg-danger/20 text-danger'}`}>
                            {item.risk}
                          </span>
                        </div>
                      ))}
                   </div>
                </div>

                <div className="glass-panel p-6 h-[260px] flex flex-col">
                  <h3 className="text-xs font-black uppercase tracking-widest text-white mb-4 flex justify-between items-center">
                    <span>Detected Endpoints</span>
                    <span className="bg-primary/20 text-primary px-2 py-0.5 rounded text-[9px]">{Object.keys(attributions || {}).length} Targets</span>
                  </h3>
                  <div className="flex-1 overflow-y-auto custom-scrollbar pr-2 space-y-3">
                    {Object.entries(attributions || {}).map(([ip, attr]) => (
                      <EndpointCard 
                        key={ip} 
                        ip={ip} 
                        attr={attr} 
                        selected={selectedIp === ip}
                        onClick={() => setSelectedIp(ip === selectedIp ? null : ip)}
                      />
                    ))}
                  </div>
                </div>

                <div className="glass-panel p-6 h-[400px] flex flex-col">
                  <h3 className="text-xs font-black uppercase tracking-widest text-primary mb-4">Forensic Intelligence</h3>
                  {selectedIp ? (
                    <div className="animate-in slide-in-from-right-4 duration-300 flex-1 flex flex-col min-h-0">
                      <div className="bg-black/40 p-3 rounded-xl border border-white/5 mb-4 flex justify-between items-center shrink-0">
                        <div>
                          <div className="text-[10px] text-textMuted uppercase font-bold mb-1">Target Identity</div>
                          <div className="text-white font-mono font-bold tracking-widest">{selectedIp}</div>
                        </div>
                        <div className="text-right">
                          <div className="text-[9px] text-textMuted uppercase font-bold">Risk Level</div>
                          <div className={`text-xs font-black ${(entropy_scores?.[selectedIp] || 0) > 0.7 ? 'text-danger' : 'text-accent'}`}>
                            {(entropy_scores?.[selectedIp] || 0) > 0.7 ? 'HIGH_THREAT' : 'SUSPICIOUS'}
                          </div>
                        </div>
                      </div>
                      
                      <div className="grid grid-cols-2 gap-3 mb-4 shrink-0">
                        <div className="bg-white/5 p-3 rounded-xl border border-white/5">
                          <div className="text-[9px] text-textMuted uppercase font-bold mb-1">p0f / OS Metrics</div>
                          <div className="text-[11px] font-mono text-white/80">TTL: {attributions[selectedIp]?.context?.ttl || 64}</div>
                          <div className="text-[11px] font-mono text-white/80">WIN: {attributions[selectedIp]?.context?.window_size || 5840}</div>
                        </div>
                        <div className="bg-white/5 p-3 rounded-xl border border-white/5 flex flex-col justify-center">
                          <div className="text-[9px] text-textMuted uppercase font-bold mb-1">Anonymization</div>
                          <div className="w-full h-1.5 bg-white/10 rounded-full mt-1 overflow-hidden">
                            <div 
                              className="h-full bg-primary transition-all duration-1000" 
                              style={{ width: `${(entropy_scores?.[selectedIp] || 0) * 100}%` }}
                            ></div>
                          </div>
                          <div className="text-[9px] font-mono text-white/40 mt-1 uppercase">Entropy: {(entropy_scores?.[selectedIp] || 0.5).toFixed(2)}</div>
                        </div>
                      </div>

                      <div className="text-[11px] text-textMuted leading-relaxed forensic-summary overflow-y-auto flex-1 custom-scrollbar pr-2 min-h-0"
                           dangerouslySetInnerHTML={{ __html: summaries[selectedIp]?.replace(/\*\*(.*?)\*\*/g, '<b class="text-white">$1</b>') }} />
                    </div>
                  ) : (
                    <div className="flex flex-col items-center justify-center h-full opacity-30">
                      <Search size={40} className="mb-4" />
                      <p className="text-sm font-bold uppercase tracking-widest text-center">Select target IP for<br/>deep analysis</p>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {currentView === 'lab' && (
          <div className="space-y-8 animate-in slide-in-from-bottom-6 duration-500">
             <div className="flex justify-between items-end">
              <div>
                <h2 className="text-3xl font-black tracking-tighter text-white uppercase italic">Forensic <span className="text-danger">Lab</span></h2>
                <p className="text-textMuted text-sm font-medium">VPN De-anonymization & Split-Tunneling leakage analysis.</p>
              </div>
              <div className={`px-4 py-2 rounded-xl border ${statistics?.vpn_active ? 'bg-success/10 border-success/30 text-success' : 'bg-danger/10 border-danger/30 text-danger'} flex items-center gap-2 text-xs font-black uppercase tracking-widest`}>
                {statistics?.vpn_active ? <ShieldCheck size={16} /> : <ShieldAlert size={16} />}
                {statistics?.vpn_active ? 'VPN Tunnel Active' : 'VPN Tunnel Offline'}
              </div>
            </div>

            <div className="grid grid-cols-12 gap-8">
              <div className="col-span-12 lg:col-span-5 space-y-6">
                <div className="glass-panel p-8 space-y-6 border-primary/20 bg-gradient-to-br from-[#0c0c14] to-black">
                  <div className="space-y-4">
                    <div className="space-y-2">
                      <label className="text-[10px] font-black uppercase text-primary tracking-widest opacity-70">Target Endpoint Identification</label>
                      <div className="relative group">
                        <Terminal className="absolute left-4 top-1/2 -translate-y-1/2 text-primary opacity-50 group-hover:opacity-100 transition-opacity" size={20} />
                        <input 
                          type="text" 
                          placeholder="nslookup target (e.g. proton.me)"
                          className="w-full bg-black/60 border border-white/10 rounded-xl py-4 pl-12 pr-4 text-white font-mono text-sm focus:border-primary focus:outline-none transition-all focus:shadow-[0_0_20px_rgba(66,133,244,0.1)]"
                          value={targetDomain}
                          onChange={(e) => setTargetDomain(e.target.value)}
                          onKeyDown={(e) => e.key === 'Enter' && handleForensicLookup()}
                        />
                      </div>
                    </div>

                    <button 
                      onClick={triggerDNSLeak}
                      className={`w-full py-5 rounded-2xl font-black uppercase tracking-widest text-sm transition-all shadow-xl flex items-center justify-center gap-3
                      bg-danger hover:bg-danger/80 text-white shadow-danger/20`}
                    >
                      <ShieldAlert size={18} /> Trigger DNS Leak Probe
                    </button>
                  </div>

                  {!statistics?.vpn_active && (
                    <div className="p-4 rounded-xl bg-danger/10 border border-danger/30 flex items-start gap-4 animate-pulse">
                      <AlertTriangle className="text-danger shrink-0" size={20} />
                      <div className="text-xs text-danger font-medium leading-relaxed">
                        <b>SECURITY GUARD ACTIVE:</b> Unmasking logic is strictly disabled when no VPN tunnel is detected to prevent false attribution.
                      </div>
                    </div>
                  )}

                  <div className="pt-4 space-y-4">
                     <div className="flex justify-between items-center">
                        <h4 className="text-[10px] font-black uppercase text-white/40 tracking-widest">Process Logs</h4>
                        <button 
                          onClick={() => setLabLogs([])}
                          className="text-[9px] font-black text-primary hover:text-white uppercase tracking-tighter"
                        >Clear Logs</button>
                     </div>
                     <div className="h-[200px] overflow-y-auto custom-scrollbar bg-black/40 border border-white/5 rounded-xl p-4 font-mono text-[10px] space-y-2">
                        {labLogs.length === 0 && <div className="text-white/20">Waiting for forensic trigger...</div>}
                        {labLogs.map((log, i) => (
                          <div key={i} className="flex gap-4">
                            <span className="text-primary">[{log.time}]</span>
                            <span className="text-accent">{log.event}</span>
                            <span className="text-textMuted truncate">{log.payload}</span>
                          </div>
                        ))}
                     </div>
                  </div>
                </div>
              </div>

              <div className="col-span-12 lg:col-span-7">
                <div className="glass-panel border-white/5 min-h-[600px] flex flex-col p-6">
                  <h3 className="text-xs font-black uppercase tracking-widest text-primary mb-6 flex justify-between items-center">
                    <span>Leaked Metadata & Tor Insights</span>
                    <div className="flex gap-4 items-center">
                      <button 
                        onClick={resetLab}
                        className="text-[10px] font-black text-danger hover:text-white uppercase tracking-widest bg-danger/10 px-3 py-1 rounded-lg border border-danger/20 transition-all"
                      >
                        Reset Evidence
                      </button>
                      <span className="bg-danger/20 text-danger px-2 py-0.5 rounded text-[9px] animate-pulse">LIVE EXFIL DATA</span>
                    </div>
                  </h3>
                  
                  <div className="flex-1 space-y-6 overflow-y-auto max-h-[500px] pr-2 custom-scrollbar">
                    {/* Tor Correlation Section */}
                    {vpn_analysis?.tor_correlation?.length > 0 && (
                      <div className="space-y-3">
                         <h4 className="text-[10px] font-black uppercase text-accent tracking-widest flex items-center gap-2">
                           <Globe size={14} /> Tor Exit Node Matches
                         </h4>
                         {vpn_analysis.tor_correlation.map((tor, i) => (
                           <div key={i} className="bg-accent/10 border border-accent/20 p-3 rounded-xl flex justify-between items-center">
                              <span className="text-xs font-mono text-white font-bold">{tor.ip}</span>
                              <span className="text-[9px] font-black bg-accent text-black px-2 py-0.5 rounded uppercase">{tor.type} NODE</span>
                           </div>
                         ))}
                      </div>
                    )}

                    {/* Infrastructure Breadcrumbing Section */}
                    {vpn_analysis?.infra_mapping?.length > 0 && (
                      <div className="space-y-3 border-t border-white/5 pt-4">
                         <h4 className="text-[10px] font-black uppercase text-primary tracking-widest flex items-center gap-2">
                           <HardDrive size={14} /> Infrastructure Breadcrumbing
                         </h4>
                         {vpn_analysis.infra_mapping.map((infra, i) => (
                           <div key={i} className="bg-primary/5 border border-primary/10 p-4 rounded-xl space-y-2">
                              <div className="text-[10px] text-textMuted font-bold uppercase tracking-tighter">Malicious Pivot for {infra.ip}</div>
                              <div className="flex flex-wrap gap-2">
                                 {infra.related_nodes.map((node, j) => (
                                   <span key={j} className="text-[10px] font-mono text-primary bg-primary/10 px-2 py-0.5 rounded-md border border-primary/20 italic">{node}</span>
                                 ))}
                              </div>
                           </div>
                         ))}
                      </div>
                    )}

                    <div className="border-t border-white/5 pt-4 space-y-4">
                      {vpn_analysis?.leaks && vpn_analysis.leaks.length > 0 ? (
                        vpn_analysis.leaks.map((leak, i) => (
                        <div key={i} className="bg-white/5 border border-white/5 p-5 rounded-2xl hover:border-danger/30 transition-all hover:bg-danger/5">
                           <div className="flex justify-between mb-4">
                              <span className="text-xs font-black text-danger uppercase tracking-tighter flex items-center gap-2">
                                <ShieldAlert size={14} /> {leak.source}
                              </span>
                              <span className="text-[10px] font-mono text-textMuted">{leak.timestamp}</span>
                           </div>
                           <div className="text-sm font-mono text-white/90 mb-4 break-all">LEAK_CONTEXT: {leak.data}</div>
                           <div className="grid grid-cols-2 gap-4">
                              <div className="bg-black/40 p-3 rounded-xl border border-white/5 flex flex-col gap-1">
                                 <span className="text-[9px] font-bold text-textMuted uppercase tracking-widest">Target Endpoint</span>
                                 <span className="text-sm font-black text-primary font-mono truncate">{leak.endpoint || '---'}</span>
                              </div>
                              <div className="bg-black/60 p-3 rounded-xl border border-danger/20 flex flex-col gap-1 shadow-inner relative overflow-hidden group/ip">
                                 <div className="absolute inset-0 bg-danger/5 animate-pulse opacity-50"></div>
                                 <span className="text-[9px] font-bold text-danger/60 uppercase tracking-widest relative z-10">Exposed User IP</span>
                                 <span className="text-base font-black text-danger font-mono tracking-wider relative z-10">{leak.real_ip || 'UNKNOWN'}</span>
                              </div>
                           </div>
                        </div>
                      ))
                    ) : (
                      <div className="h-full flex flex-col items-center justify-center opacity-30 text-center py-20">
                        <Terminal size={48} className="mb-4" />
                        <p className="text-sm font-bold uppercase tracking-[0.2em]">VPN/Tor Lab Idle</p>
                        <p className="text-[10px] mt-2">Monitoring encrypted tunnels for leaks...</p>
                      </div>
                    )}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {currentView === 'settings' && (
          <div className="space-y-8 animate-in slide-in-from-bottom-6 duration-500">
            <div>
              <h2 className="text-3xl font-black tracking-tighter text-white">SYSTEM <span className="text-primary">CONFIG</span></h2>
              <p className="text-textMuted text-sm font-medium">Fine-tune the MetaTrace induction engine and forensic depth.</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              <div className="glass-panel p-8 space-y-8">
                <h3 className="text-sm font-black uppercase text-primary tracking-[0.2em] border-b border-white/10 pb-4">Detection Engine</h3>
                <SettingsToggle 
                  label="Deep Packet Inspection" 
                  description="Enables structural analysis of encrypted tunnels to identify protocol signatures."
                  enabled={settings.deepInspection}
                  onClick={() => setSettings({...settings, deepInspection: !settings.deepInspection})}
                />
                <SettingsToggle 
                  label="Automatic VPN Unmasking" 
                  description="Attempts to trigger passive DNS leaks automatically when a VPN is detected."
                  enabled={settings.autoUnmask}
                  onClick={() => setSettings({...settings, autoUnmask: !settings.autoUnmask})}
                />
                <div className="space-y-4 pt-4">
                  <div className="flex justify-between items-center px-4">
                    <span className="text-xs font-bold text-white uppercase tracking-wider">Sensor Sensitivity</span>
                    <span className="text-primary font-mono text-sm">{settings.sensorSensitivity}%</span>
                  </div>
                  <input 
                    type="range" 
                    className="w-full h-1 bg-white/10 rounded-lg appearance-none cursor-pointer accent-primary"
                    value={settings.sensorSensitivity}
                    onChange={(e) => setSettings({...settings, sensorSensitivity: e.target.value})}
                  />
                </div>
              </div>

              <div className="glass-panel p-8 space-y-8">
                <h3 className="text-sm font-black uppercase text-accent tracking-[0.2em] border-b border-white/10 pb-4">Security & OSINT</h3>
                <SettingsToggle 
                  label="Real-time Threat Guard" 
                  description="Cross-reference all discovered IPs with global malicious entity databases."
                  enabled={settings.threatGuard}
                  onClick={() => setSettings({...settings, threatGuard: !settings.threatGuard})}
                />
                <div className="bg-black/40 p-6 rounded-2xl border border-white/5 space-y-4">
                   <div className="flex items-center gap-3 text-white">
                      <Shield className="text-primary" size={24} />
                      <div className="flex flex-col">
                        <span className="text-[10px] font-black uppercase tracking-widest text-textMuted">Product Version</span>
                        <span className="text-lg font-black tracking-tighter italic">METATRACE PRO v3.0</span>
                      </div>
                   </div>
                   <button className="w-full py-3 bg-white/5 hover:bg-white/10 border border-white/5 rounded-xl text-[10px] font-black tracking-widest uppercase transition-all">
                      Check for signature updates
                   </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

function SidebarLink({ icon, label, active = false, onClick }) {
  return (
    <button 
      onClick={onClick}
      className={`w-full flex items-center gap-4 p-3 rounded-xl transition-all group ${active ? 'bg-primary text-white shadow-lg shadow-primary/20' : 'text-textMuted hover:bg-white/5 hover:text-white'}`}
    >
      <div className={`${active ? 'text-white' : 'group-hover:text-primary'} transition-colors`}>{icon}</div>
      <span className="hidden lg:block text-sm font-bold tracking-tight">{label}</span>
      {active && <div className="ml-auto w-1 h-4 bg-white/20 rounded-full hidden lg:block"></div>}
    </button>
  );
}

function StatBadge({ label, value, icon, color = "text-primary" }) {
  return (
    <div className="bg-white/5 border border-white/5 px-4 py-2 rounded-xl flex items-center gap-3">
      <div className={`${color} opacity-70`}>{icon}</div>
      <div className="flex flex-col">
        <span className="text-[10px] font-bold text-textMuted uppercase tracking-tighter -mb-1">{label}</span>
        <span className="text-lg font-black text-white">{value}</span>
      </div>
    </div>
  );
}

function EndpointCard({ ip, attr, selected, onClick }) {
  const getIcon = (type) => {
    if (type?.includes("Windows")) return <Monitor className="text-[#00A4EF]" size={16} />;
    if (type?.includes("Android") || type?.includes("iPhone")) return <Smartphone className="text-[#3DDC84]" size={16} />;
    if (type?.includes("Infrastructure") || type?.includes("Network")) return <HardDrive className="text-accent" size={16} />;
    return <Globe className="text-primary" size={16} />;
  };

  return (
    <div 
      onClick={onClick}
      className={`p-4 rounded-2xl cursor-pointer border-2 transition-all ${selected ? 'bg-primary/10 border-primary shadow-[0_0_20px_rgba(66,133,244,0.2)]' : 'bg-black/20 border-white/5 hover:border-white/10'}`}
    >
      <div className="flex justify-between items-start mb-2">
        <div className="flex items-center gap-2">
          {getIcon(attr.context?.device_type)}
          <div className="text-sm font-mono font-bold text-white tracking-widest">{ip}</div>
        </div>
        <div className="bg-white/5 px-2 py-0.5 rounded text-[9px] font-black text-white/50 lowercase">{(attr.confidence * 100).toFixed(0)}%</div>
      </div>
      <div className="flex justify-between items-end mt-2">
        <div className={`text-[10px] font-black uppercase tracking-tight ${selected ? 'text-primary' : 'text-textMuted'}`}>{attr.predicted_network}</div>
        <div className="text-[9px] font-bold text-white/40 font-mono">{attr.context?.device_type || 'Scanning...'}</div>
      </div>
    </div>
  );
}

function SettingsToggle({ label, description, enabled, onClick }) {
  return (
    <div className="flex items-center justify-between group p-2 hover:bg-white/5 rounded-xl transition-all">
      <div className="flex flex-col gap-1">
        <span className="text-sm font-bold text-white tracking-tight">{label}</span>
        <span className="text-xs text-textMuted max-w-xs">{description}</span>
      </div>
      <button 
        onClick={onClick}
        className={`w-12 h-6 rounded-full relative transition-all duration-300 ${enabled ? 'bg-primary shadow-[0_0_10px_rgba(66,133,244,0.5)]' : 'bg-white/10'}`}
      >
        <div className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-all duration-300 ${enabled ? 'left-7' : 'left-1'}`}></div>
      </button>
    </div>
  );
}

function LoadingPlaceholder() {
  return (
    <div className="flex flex-col h-full items-center justify-center opacity-30">
      <Activity className="animate-spin mb-2" size={32} />
      <span className="text-[10px] font-bold uppercase tracking-widest">Syncing Data Streams</span>
    </div>
  );
}

export default App;

