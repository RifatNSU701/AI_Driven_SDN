import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

void main() {
  runApp(const SdnCyberSocApp());
}

class SdnCyberSocApp extends StatelessWidget {
  const SdnCyberSocApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'AI-SDN Cyber-SOC v3.0',
      debugShowCheckedModeBanner: false,
      theme: ThemeData.dark(useMaterial3: true).copyWith(
        scaffoldBackgroundColor: const Color(0xFF050811),
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFF22D3EE),
          secondary: Color(0xFF34D399),
          surface: Color(0xFF0F172A),
          error: Color(0xFFF43F5E),
        ),
      ),
      home: const MobileSocShell(),
    );
  }
}

class MobileSocShell extends StatefulWidget {
  const MobileSocShell({super.key});

  @override
  State<MobileSocShell> createState() => _MobileSocShellState();
}

class _MobileSocShellState extends State<MobileSocShell> {
  int currentTab = 0;
  String apiBase = 'http://127.0.0.1:8000';
  String operatorName = 'admin (ADMIN)';
  String activeModel = 'Ensemble Voting (All 5 Models)';
  bool isConnected = false;
  Timer? _timer;

  Map<String, dynamic> stats = {
    'total_events': 0,
    'quarantines': 0,
    'rate_limits': 0,
    'avg_latency_ms': 0.04,
    'blocked_ips': [],
    'rate_limited_ips': [],
    'control_plane': {
      'controller_cpu_pct': 8.4,
      'controller_ram_mb': 312.0,
      'ovs_active_flows': 4,
      'estimated_throughput_kbps': 0.0,
    },
  };

  List<dynamic> events = [];
  List<dynamic> benchmarks = [];
  List<dynamic> policies = [];
  List<dynamic> audits = [];
  Map<String, dynamic> robustness = {};
  Map<String, dynamic>? selectedForensicEvent;

  final TextEditingController fwIpCtrl = TextEditingController(text: '10.0.0.3');
  final TextEditingController fwRateCtrl = TextEditingController(text: '512');
  final TextEditingController fwReasonCtrl = TextEditingController(text: 'Mobile SOC OpenFlow Policy');
  String fwAction = 'quarantine';
  String fwProto = 'ip';

  final List<String> models = const [
    'Ensemble Voting (All 5 Models)',
    'Random Forest',
    'Gradient Boosting',
    'Deep Neural Network (MLP)',
    'Isolation Forest',
    'Baseline Threshold',
  ];

  @override
  void initState() {
    super.initState();
    fetchAllData();
    _timer = Timer.periodic(const Duration(seconds: 2), (_) => fetchAllData());
  }

  @override
  void dispose() {
    _timer?.cancel();
    fwIpCtrl.dispose();
    fwRateCtrl.dispose();
    fwReasonCtrl.dispose();
    super.dispose();
  }

  Future<void> fetchAllData() async {
    try {
      final res = await Future.wait([
        http.get(Uri.parse('$apiBase/api/stats')).timeout(const Duration(seconds: 2)),
        http.get(Uri.parse('$apiBase/api/events?limit=50')).timeout(const Duration(seconds: 2)),
        http.get(Uri.parse('$apiBase/api/models')).timeout(const Duration(seconds: 2)),
        http.get(Uri.parse('$apiBase/api/policies')).timeout(const Duration(seconds: 2)),
        http.get(Uri.parse('$apiBase/api/audit')).timeout(const Duration(seconds: 2)),
        http.get(Uri.parse('$apiBase/api/robustness')).timeout(const Duration(seconds: 2)),
      ]);

      if (res[0].statusCode == 200 && mounted) {
        final st = jsonDecode(res[0].body);
        final ev = jsonDecode(res[1].body) as List<dynamic>;
        final md = jsonDecode(res[2].body);
        final pol = jsonDecode(res[3].body) as List<dynamic>;
        final aud = jsonDecode(res[4].body) as List<dynamic>;
        final rob = jsonDecode(res[5].body) as Map<String, dynamic>;

        setState(() {
          isConnected = true;
          stats = st;
          events = ev.reversed.toList();
          benchmarks = md['benchmarks'] ?? [];
          policies = pol;
          audits = aud;
          robustness = rob;
          activeModel = st['active_model'] ?? activeModel;
          if (selectedForensicEvent == null && events.isNotEmpty) {
            selectedForensicEvent = events.first;
          }
        });
      }
    } catch (_) {
      if (mounted) setState(() => isConnected = false);
    }
  }

  Future<void> simulate(String scenario) async {
    try {
      final r = await http.post(
        Uri.parse('$apiBase/api/simulate'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'scenario': scenario}),
      );
      if (r.statusCode == 200) {
        await fetchAllData();
        if (events.isNotEmpty) {
          setState(() => selectedForensicEvent = events.first);
        }
      }
    } catch (_) {}
  }

  Future<void> switchModel(String modelName) async {
    try {
      await http.post(
        Uri.parse('$apiBase/api/models/select'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'model_name': modelName}),
      );
      await fetchAllData();
    } catch (_) {}
  }

  Future<void> enforcePolicy() async {
    try {
      await http.post(
        Uri.parse('$apiBase/api/policies/enforce'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'target_ip': fwIpCtrl.text.trim(),
          'rule_type': fwAction,
          'rate_kbps': int.tryParse(fwRateCtrl.text.trim()) ?? 512,
          'protocol': fwProto,
          'reason': fwReasonCtrl.text.trim(),
        }),
      );
      await fetchAllData();
    } catch (_) {}
  }

  Future<void> unblockIp(String ip) async {
    try {
      await http.post(
        Uri.parse('$apiBase/api/policies/unblock'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'target_ip': ip}),
      );
      await fetchAllData();
    } catch (_) {}
  }

  Future<void> runRobustnessSuite() async {
    try {
      await http.post(Uri.parse('$apiBase/api/robustness/run'));
      await fetchAllData();
    } catch (_) {}
  }

  Future<void> clearEvents() async {
    try {
      await http.delete(Uri.parse('$apiBase/api/events/clear'));
      setState(() => selectedForensicEvent = null);
      await fetchAllData();
    } catch (_) {}
  }

  void openServerModal() {
    final userCtrl = TextEditingController(text: 'admin');
    final passCtrl = TextEditingController(text: 'Admin@SDN2026');
    final urlCtrl = TextEditingController(text: apiBase);

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: const Color(0xFF0F172A),
      builder: (ctx) => Padding(
        padding: EdgeInsets.only(
          left: 16,
          right: 16,
          top: 16,
          bottom: MediaQuery.of(ctx).viewInsets.bottom + 20,
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('🔐 Cyber-SOC JWT Login & Endpoint Config',
                style: TextStyle(fontSize: 15, fontWeight: FontWeight.bold)),
            const SizedBox(height: 12),
            TextField(
              controller: urlCtrl,
              decoration: const InputDecoration(
                labelText: 'FastAPI Server URL (USB = http://127.0.0.1:8000)',
                border: OutlineInputBorder(),
                isDense: true,
              ),
            ),
            const SizedBox(height: 10),
            TextField(
              controller: userCtrl,
              decoration: const InputDecoration(
                labelText: 'Operator Username',
                border: OutlineInputBorder(),
                isDense: true,
              ),
            ),
            const SizedBox(height: 10),
            TextField(
              controller: passCtrl,
              obscureText: true,
              decoration: const InputDecoration(
                labelText: 'Password',
                border: OutlineInputBorder(),
                isDense: true,
              ),
            ),
            const SizedBox(height: 12),
            SizedBox(
              width: double.infinity,
              child: ElevatedButton(
                onPressed: () async {
                  setState(() => apiBase = urlCtrl.text.trim());
                  try {
                    final r = await http.post(
                      Uri.parse('$apiBase/api/auth/login'),
                      headers: {'Content-Type': 'application/json'},
                      body: jsonEncode({
                        'username': userCtrl.text.trim(),
                        'password': passCtrl.text,
                      }),
                    );
                    if (r.statusCode == 200) {
                      final d = jsonDecode(r.body);
                      setState(() {
                        operatorName = '${d['user']['username']} (${d['user']['role'].toString().toUpperCase()})';
                      });
                    }
                  } catch (_) {}
                  if (ctx.mounted) Navigator.pop(ctx);
                  fetchAllData();
                },
                child: const Text('Authenticate & Sync'),
              ),
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final cp = stats['control_plane'] ?? {};
    final List blocked = stats['blocked_ips'] ?? [];
    final List throttled = stats['rate_limited_ips'] ?? [];
    final List allIsolated = [...blocked, ...throttled];

    return Scaffold(
      appBar: AppBar(
        backgroundColor: const Color(0xFF0F172A),
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Text('🛡️ AI-SDN Cyber-SOC v3.0',
                    style: TextStyle(fontSize: 15, fontWeight: FontWeight.bold)),
                const SizedBox(width: 8),
                Container(
                  width: 8,
                  height: 8,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: isConnected ? Colors.greenAccent : Colors.orangeAccent,
                  ),
                ),
              ],
            ),
            Text(
              'CPU: ${cp['controller_cpu_pct'] ?? 8.4}% • RAM: ${cp['controller_ram_mb'] ?? 312}MB • OVS Flows: ${cp['ovs_active_flows'] ?? 4}',
              style: const TextStyle(fontSize: 10.5, color: Colors.cyanAccent),
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.delete_sweep_outlined),
            tooltip: 'Reset Telemetry',
            onPressed: clearEvents,
          ),
          IconButton(
            icon: const Icon(Icons.manage_accounts_outlined),
            tooltip: 'Login & Server Settings',
            onPressed: openServerModal,
          ),
        ],
      ),
      body: IndexedStack(
        index: currentTab,
        children: [
          _buildCommandCenterTab(allIsolated),
          _buildXaiForensicsTab(),
          _buildFirewallTab(),
          _buildRobustnessAndAuditTab(),
        ],
      ),
      bottomNavigationBar: NavigationBar(
        selectedIndex: currentTab,
        backgroundColor: const Color(0xFF0F172A),
        onDestinationSelected: (idx) => setState(() => currentTab = idx),
        destinations: const [
          NavigationDestination(icon: Icon(Icons.radar), label: 'Command'),
          NavigationDestination(icon: Icon(Icons.psychology), label: 'XAI Lab'),
          NavigationDestination(icon: Icon(Icons.security), label: 'Firewall'),
          NavigationDestination(icon: Icon(Icons.verified_outlined), label: 'Robustness'),
        ],
      ),
    );
  }

  Widget _buildCommandCenterTab(List allIsolated) {
    final bool hasThreat = allIsolated.isNotEmpty;
    return RefreshIndicator(
      onRefresh: fetchAllData,
      child: ListView(
        padding: const EdgeInsets.all(12),
        children: [
          Container(
            padding: const EdgeInsets.all(11),
            decoration: BoxDecoration(
              color: hasThreat ? const Color(0xFF4C0519) : const Color(0xFF064E3B).withOpacity(0.45),
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: hasThreat ? Colors.redAccent : Colors.greenAccent),
            ),
            child: Text(
              hasThreat
                  ? 'THREAT CONTAINED: Host(s) ${allIsolated.join(", ")} enforced on OVS s1. Tap chip below to unblock.'
                  : 'NETWORK HEALTHY: OpenFlow 1.3 Switch s1 operating at 0% benign packet loss.',
              style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w600),
            ),
          ),
          const SizedBox(height: 10),
          GridView.count(
            crossAxisCount: 2,
            crossAxisSpacing: 8,
            mainAxisSpacing: 8,
            childAspectRatio: 2.2,
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            children: [
              _kpiTile('Telemetry Windows', '${stats['total_events']}', Colors.cyanAccent),
              _kpiTile('Quarantines', '${stats['quarantines']}', Colors.redAccent),
              _kpiTile('ML Latency', '${stats['avg_latency_ms']} ms', Colors.greenAccent),
              _kpiTile('Enforced Hosts', '${allIsolated.length}', Colors.amberAccent),
            ],
          ),
          const SizedBox(height: 10),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 2),
            decoration: BoxDecoration(
              color: const Color(0xFF0F172A),
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: Colors.white12),
            ),
            child: DropdownButtonHideUnderline(
              child: DropdownButton<String>(
                value: models.contains(activeModel) ? activeModel : models.first,
                isExpanded: true,
                items: models
                    .map((m) => DropdownMenuItem(value: m, child: Text('Engine: $m', style: const TextStyle(fontSize: 12.5))))
                    .toList(),
                onChanged: (val) {
                  if (val != null) switchModel(val);
                },
              ),
            ),
          ),
          const SizedBox(height: 10),
          const Text('⚡ 6-CLASS SDN TRAFFIC & ATTACK GENERATOR',
              style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Colors.grey)),
          const SizedBox(height: 6),
          Wrap(
            spacing: 6,
            runSpacing: 6,
            children: [
              _simButton('🟢 Normal (h2)', 'benign', Colors.teal),
              _simButton('🌿 Mint VM', 'mint_benign', Colors.green),
              _simButton('🔵 iperf3 Burst', 'high_vol', Colors.blue),
              _simButton('🕵️ Stealth Scan', 'stealth_scan', Colors.amber),
              _simButton('🟠 Nmap Scan', 'port_scan', Colors.orange),
              _simButton('🔴 SYN Flood', 'syn_flood', Colors.redAccent),
              _simButton('💥 UDP Flood', 'udp_flood', Colors.deepOrange),
              _simButton('🐉 Kali Attack', 'kali_attack', Colors.purpleAccent),
            ],
          ),
          const SizedBox(height: 10),
          if (allIsolated.isNotEmpty) ...[
            const Text('🛡️ ACTIVE CONTAINMENT (TAP TO UNBLOCK)',
                style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Colors.redAccent)),
            const SizedBox(height: 6),
            Wrap(
              spacing: 8,
              children: allIsolated
                  .map((ip) => ActionChip(
                        avatar: const Icon(Icons.lock_open, size: 14, color: Colors.white),
                        backgroundColor: Colors.red.shade900,
                        label: Text('Unblock $ip', style: const TextStyle(fontSize: 11.5)),
                        onPressed: () => unblockIp(ip.toString()),
                      ))
                  .toList(),
            ),
            const SizedBox(height: 10),
          ],
          const Text('🚨 LIVE TELEMETRY (TAP ANY CARD FOR XAI FORENSICS)',
              style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Colors.grey)),
          const SizedBox(height: 6),
          ...events.take(25).map((e) {
            final bool isBlock = e['action'] == 'quarantine';
            return Card(
              color: const Color(0xFF0F172A),
              margin: const EdgeInsets.only(bottom: 8),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(8),
                side: BorderSide(color: isBlock ? Colors.redAccent.withOpacity(0.5) : Colors.white10),
              ),
              child: InkWell(
                onTap: () {
                  setState(() {
                    selectedForensicEvent = e;
                    currentTab = 1;
                  });
                },
                child: Padding(
                  padding: const EdgeInsets.all(10),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          Text('${e['src_ip']} → ${e['dst_ip']}',
                              style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13)),
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                            decoration: BoxDecoration(
                              color: isBlock ? Colors.redAccent.withOpacity(0.2) : Colors.greenAccent.withOpacity(0.2),
                              borderRadius: BorderRadius.circular(4),
                            ),
                            child: Text(
                              '${e['action']} • ${e['threat_type']}'.toUpperCase(),
                              style: TextStyle(
                                fontSize: 10,
                                fontWeight: FontWeight.bold,
                                color: isBlock ? Colors.redAccent : Colors.greenAccent,
                              ),
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 4),
                      Text(
                        'Rate: ${e['pkt_rate']} p/s | Ports: ${e['unique_dst_ports']} | Drift Z: ${e['drift_index'] ?? '-'} | ${e['inference_latency_ms']} ms',
                        style: const TextStyle(fontSize: 11, color: Colors.white70),
                      ),
                      const SizedBox(height: 3),
                      Text(
                        '${e['explanation'] ?? ''}',
                        style: const TextStyle(fontSize: 11, color: Colors.cyanAccent),
                      ),
                    ],
                  ),
                ),
              ),
            );
          }),
        ],
      ),
    );
  }

  Widget _buildXaiForensicsTab() {
    final ev = selectedForensicEvent ?? (events.isNotEmpty ? events.first : null);
    final Map<String, dynamic> xai = (ev != null && ev['xai_contributions'] != null)
        ? Map<String, dynamic>.from(ev['xai_contributions'])
        : {'flow_count': 20.0, 'pkt_rate': 20.0, 'byte_rate': 15.0, 'mean_pkt_size': 15.0, 'unique_dst_ports': 15.0, 'syn_ratio': 15.0};
    final Map<String, dynamic> votes = (ev != null && ev['model_votes'] != null)
        ? Map<String, dynamic>.from(ev['model_votes'])
        : {};

    return ListView(
      padding: const EdgeInsets.all(12),
      children: [
        const Text('🔬 MATHEMATICAL PER-FLOW XAI ATTRIBUTION',
            style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: Colors.cyanAccent)),
        const SizedBox(height: 8),
        if (ev == null)
          const Text('Trigger any traffic scenario on the Command tab to inspect mathematical XAI weights.')
        else
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: const Color(0xFF0F172A),
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: Colors.white12),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('${ev['src_ip']} → ${ev['dst_ip']} [${ev['threat_type'].toString().toUpperCase()}]',
                    style: const TextStyle(fontSize: 14, fontWeight: FontWeight.bold)),
                const SizedBox(height: 4),
                Text('Drift Z-Score: ${ev['drift_index'] ?? 0.5} • Action: ${ev['action'].toString().toUpperCase()}',
                    style: const TextStyle(fontSize: 11.5, color: Colors.amberAccent)),
                const SizedBox(height: 8),
                Text('${ev['explanation']}', style: const TextStyle(fontSize: 11.5, color: Colors.white70)),
                const Divider(height: 20),
                ...xai.entries.map((entry) {
                  final double pct = double.tryParse(entry.value.toString()) ?? 0.0;
                  return Padding(
                    padding: const EdgeInsets.only(bottom: 8),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            Text(entry.key, style: const TextStyle(fontSize: 11.5, fontFamily: 'monospace')),
                            Text('$pct%', style: const TextStyle(fontSize: 11.5, fontWeight: FontWeight.bold, color: Colors.cyanAccent)),
                          ],
                        ),
                        const SizedBox(height: 3),
                        LinearProgressIndicator(
                          value: (pct / 100.0).clamp(0.0, 1.0),
                          backgroundColor: Colors.white10,
                          color: Colors.cyanAccent,
                          minHeight: 6,
                        ),
                      ],
                    ),
                  );
                }),
                if (votes.isNotEmpty) ...[
                  const SizedBox(height: 8),
                  const Text('5-Detector Consensus Votes:', style: TextStyle(fontSize: 11, color: Colors.grey)),
                  const SizedBox(height: 6),
                  Wrap(
                    spacing: 6,
                    runSpacing: 6,
                    children: votes.entries.map((v) {
                      final bool flagged = v.value == 1;
                      return Container(
                        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                        decoration: BoxDecoration(
                          color: flagged ? Colors.redAccent.withOpacity(0.2) : Colors.greenAccent.withOpacity(0.2),
                          borderRadius: BorderRadius.circular(6),
                        ),
                        child: Text(
                          '${v.key}: ${flagged ? "ANOMALY" : "NORMAL"}',
                          style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: flagged ? Colors.redAccent : Colors.greenAccent),
                        ),
                      );
                    }).toList(),
                  ),
                ],
              ],
            ),
          ),
        const SizedBox(height: 16),
        const Text('📊 5-ALGORITHM BENCHMARK TABLE (5,000 FLOWS)',
            style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: Colors.cyanAccent)),
        const SizedBox(height: 8),
        ...benchmarks.map((b) => Card(
              color: const Color(0xFF0F172A),
              margin: const EdgeInsets.only(bottom: 6),
              child: ListTile(
                dense: true,
                title: Text('${b['model']}', style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13)),
                subtitle: Text(
                  'Precision: ${b['precision']} | Recall: ${b['recall']} | FPR: ${b['false_positive_rate']}',
                  style: const TextStyle(fontSize: 11),
                ),
                trailing: Text(
                  'F1: ${b['f1_score']}\n${b['latency_ms_per_sample']} ms',
                  textAlign: TextAlign.right,
                  style: const TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Colors.greenAccent),
                ),
              ),
            )),
      ],
    );
  }

  Widget _buildFirewallTab() {
    return ListView(
      padding: const EdgeInsets.all(12),
      children: [
        const Text('🔥 OPENFLOW 1.3 FLOW & METER RULE BUILDER',
            style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: Colors.cyanAccent)),
        const SizedBox(height: 8),
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: const Color(0xFF0F172A),
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: Colors.white12),
          ),
          child: Column(
            children: [
              TextField(
                controller: fwIpCtrl,
                decoration: const InputDecoration(labelText: 'Target Source IP', isDense: true, border: OutlineInputBorder()),
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  Expanded(
                    child: DropdownButtonFormField<String>(
                      value: fwAction,
                      decoration: const InputDecoration(labelText: 'Action', isDense: true, border: OutlineInputBorder()),
                      items: const [
                        DropdownMenuItem(value: 'quarantine', child: Text('Quarantine (Drop)')),
                        DropdownMenuItem(value: 'rate_limit', child: Text('Rate-Limit (Meter)')),
                        DropdownMenuItem(value: 'whitelist', child: Text('Whitelist')),
                      ],
                      onChanged: (v) => setState(() => fwAction = v ?? 'quarantine'),
                    ),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: TextField(
                      controller: fwRateCtrl,
                      keyboardType: TextInputType.number,
                      decoration: const InputDecoration(labelText: 'Rate (kbps)', isDense: true, border: OutlineInputBorder()),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 10),
              Row(
                children: [
                  Expanded(
                    child: ElevatedButton.icon(
                      icon: const Icon(Icons.gavel, size: 16),
                      label: const Text('Install OpenFlow Rule'),
                      onPressed: enforcePolicy,
                    ),
                  ),
                  const SizedBox(width: 8),
                  ElevatedButton(
                    style: ElevatedButton.styleFrom(backgroundColor: Colors.green.shade800),
                    onPressed: () => unblockIp(fwIpCtrl.text.trim()),
                    child: const Text('Unblock IP'),
                  ),
                ],
              ),
            ],
          ),
        ),
        const SizedBox(height: 14),
        const Text('🛡️ ACTIVE OPENFLOW 1.3 POLICY RULES',
            style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: Colors.cyanAccent)),
        const SizedBox(height: 6),
        ...policies.map((p) => Card(
              color: const Color(0xFF0F172A),
              margin: const EdgeInsets.only(bottom: 6),
              child: ListTile(
                dense: true,
                title: Text('${p['target_ip']} • ${p['rule_type'].toString().toUpperCase()}',
                    style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 12.5)),
                subtitle: Text('Priority: ${p['priority']} • ${p['reason']}', style: const TextStyle(fontSize: 11)),
                trailing: p['rule_type'] != 'whitelist'
                    ? TextButton(
                        onPressed: () => unblockIp(p['target_ip'].toString()),
                        child: const Text('Unblock', style: TextStyle(color: Colors.greenAccent)),
                      )
                    : const Text('Protected', style: TextStyle(fontSize: 11, color: Colors.grey)),
              ),
            )),
      ],
    );
  }

  Widget _buildRobustnessAndAuditTab() {
    final List scenarios = robustness['scenarios'] ?? [];
    return ListView(
      padding: const EdgeInsets.all(12),
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(
              '🧪 ROBUSTNESS: ${robustness['pass_rate_pct'] ?? 100}% (${robustness['max_throughput_flows_per_sec'] ?? 117758} flows/s)',
              style: const TextStyle(fontSize: 11.5, fontWeight: FontWeight.bold, color: Colors.greenAccent),
            ),
            ElevatedButton(
              onPressed: runRobustnessSuite,
              child: const Text('Re-Run Suite', style: TextStyle(fontSize: 11)),
            ),
          ],
        ),
        const SizedBox(height: 8),
        ...scenarios.map((s) => Card(
              color: const Color(0xFF0F172A),
              margin: const EdgeInsets.only(bottom: 6),
              child: ListTile(
                dense: true,
                title: Text('${s['name']}', style: const TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
                subtitle: Text('${s['category']} • Expected: ${s['expected']} • Actual: ${s['actual']}',
                    style: const TextStyle(fontSize: 11)),
                trailing: Text(
                  s['passed'] == true ? 'PASS\n${s['latency_ms']}ms' : 'FAIL',
                  textAlign: TextAlign.right,
                  style: const TextStyle(fontSize: 10.5, fontWeight: FontWeight.bold, color: Colors.greenAccent),
                ),
              ),
            )),
        const SizedBox(height: 14),
        const Text('📋 ROLE-BASED SOC OPERATOR AUDIT TRAIL',
            style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: Colors.cyanAccent)),
        const SizedBox(height: 6),
        ...audits.take(15).map((a) => Card(
              color: const Color(0xFF0F172A),
              margin: const EdgeInsets.only(bottom: 6),
              child: ListTile(
                dense: true,
                title: Text('${a['action']} (${a['username']} - ${a['role']})',
                    style: const TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
                subtitle: Text('${a['details']} • ${a['timestamp']}', style: const TextStyle(fontSize: 11)),
              ),
            )),
      ],
    );
  }

  Widget _kpiTile(String title, String value, Color color) {
    return Container(
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: const Color(0xFF0F172A),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: Colors.white12),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Text(title, style: const TextStyle(fontSize: 11, color: Colors.white60)),
          const SizedBox(height: 3),
          Text(value, style: TextStyle(fontSize: 17, fontWeight: FontWeight.bold, color: color)),
        ],
      ),
    );
  }

  Widget _simButton(String label, String scenario, Color color) {
    return ElevatedButton(
      style: ElevatedButton.styleFrom(
        backgroundColor: color.withOpacity(0.22),
        foregroundColor: Colors.white,
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
        textStyle: const TextStyle(fontSize: 11, fontWeight: FontWeight.bold),
      ),
      onPressed: () => simulate(scenario),
      child: Text(label),
    );
  }
}