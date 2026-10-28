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
      title: 'AI-SDN Mobile SOC',
      debugShowCheckedModeBanner: false,
      theme: ThemeData.dark(useMaterial3: true).copyWith(
        scaffoldBackgroundColor: const Color(0xFF070B14),
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFF22D3EE),
          secondary: Color(0xFF34D399),
          surface: Color(0xFF0F172A),
          error: Color(0xFFF43F5E),
        ),
      ),
      home: const MobileSocDashboard(),
    );
  }
}

class MobileSocDashboard extends StatefulWidget {
  const MobileSocDashboard({super.key});

  @override
  State<MobileSocDashboard> createState() => _MobileSocDashboardState();
}

class _MobileSocDashboardState extends State<MobileSocDashboard> {
  String apiBase = 'http://127.0.0.1:8000';
  String operatorName = 'SOC Operator';
  String activeModel = 'Ensemble Voting (All 5 Models)';
  bool autoRefresh = true;
  bool isConnected = false;
  Timer? _timer;

  Map<String, dynamic> stats = {
    'total_events': 0,
    'quarantines': 0,
    'avg_latency_ms': 0.111,
    'blocked_ips': [],
    'system_status': 'NETWORK HEALTHY',
  };
  List<dynamic> events = [];

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
    fetchSocData();
    _timer = Timer.periodic(const Duration(seconds: 2), (_) {
      if (autoRefresh) fetchSocData();
    });
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  Future<void> fetchSocData() async {
    try {
      final results = await Future.wait([
        http.get(Uri.parse('$apiBase/api/stats')).timeout(const Duration(seconds: 2)),
        http.get(Uri.parse('$apiBase/api/events?limit=35')).timeout(const Duration(seconds: 2)),
      ]);

      if (results[0].statusCode == 200 && mounted) {
        final st = jsonDecode(results[0].body);
        final ev = jsonDecode(results[1].body);
        setState(() {
          isConnected = true;
          stats = st;
          events = ev.reversed.toList();
          activeModel = st['active_model'] ?? activeModel;
        });
      }
    } catch (_) {
      if (mounted) {
        setState(() => isConnected = false);
      }
    }
  }

  Future<void> triggerSimulation(String scenario) async {
    try {
      await http.post(
        Uri.parse('$apiBase/api/simulate'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'scenario': scenario}),
      );
      await fetchSocData();
    } catch (_) {}
  }

  Future<void> changeModel(String modelName) async {
    try {
      await http.post(
        Uri.parse('$apiBase/api/models/select'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'model_name': modelName}),
      );
      await fetchSocData();
    } catch (_) {}
  }

  Future<void> unblockIp(String ip) async {
    try {
      await http.post(
        Uri.parse('$apiBase/api/policies/unblock'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'target_ip': ip}),
      );
      await fetchSocData();
    } catch (_) {}
  }

  Future<void> clearEvents() async {
    try {
      await http.delete(Uri.parse('$apiBase/api/events/clear'));
      await fetchSocData();
    } catch (_) {}
  }

  void openLoginModal() {
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
            const Text('🔐 SOC Operator Login & Server Config',
                style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
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
                labelText: 'Username',
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
                        operatorName = '${d['user']['username']} (${d['user']['role']})';
                      });
                    }
                  } catch (_) {}
                  if (ctx.mounted) Navigator.pop(ctx);
                  fetchSocData();
                },
                child: const Text('Connect & Sign In'),
              ),
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final List blockedIps = stats['blocked_ips'] ?? [];
    final bool hasThreat = blockedIps.isNotEmpty;

    return Scaffold(
      appBar: AppBar(
        backgroundColor: const Color(0xFF0F172A),
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Text('🛡️ AI-SDN Threat Protection',
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
            Text('$operatorName • $activeModel',
                style: const TextStyle(fontSize: 11, color: Colors.cyanAccent)),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.delete_sweep_outlined),
            tooltip: 'Clear Log',
            onPressed: clearEvents,
          ),
          IconButton(
            icon: const Icon(Icons.manage_accounts_outlined),
            tooltip: 'Login & API Settings',
            onPressed: openLoginModal,
          ),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: fetchSocData,
        child: ListView(
          padding: const EdgeInsets.all(12),
          children: [
            // GUIDED STATUS BANNER
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: hasThreat
                    ? const Color(0xFF4C0519)
                    : const Color(0xFF064E3B).withOpacity(0.45),
                borderRadius: BorderRadius.circular(10),
                border: Border.all(
                  color: hasThreat ? Colors.redAccent : Colors.greenAccent,
                ),
              ),
              child: Row(
                children: [
                  Icon(
                    hasThreat ? Icons.gpp_bad : Icons.verified_user,
                    color: hasThreat ? Colors.redAccent : Colors.greenAccent,
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      hasThreat
                          ? 'THREAT CONTAINED: Host(s) ${blockedIps.join(", ")} quarantined via OpenFlow priority=100 drop rule. Tap host chip below to unblock.'
                          : 'NETWORK HEALTHY: All SDN switches and hosts operating with 0% packet loss.',
                      style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w600),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 12),

            // KPI CARDS
            GridView.count(
              crossAxisCount: 2,
              crossAxisSpacing: 8,
              mainAxisSpacing: 8,
              childAspectRatio: 2.1,
              shrinkWrap: true,
              physics: const NeverScrollableScrollPhysics(),
              children: [
                _kpiTile('Telemetry Windows', '${stats['total_events']}', Colors.cyanAccent),
                _kpiTile('Quarantines', '${stats['quarantines']}', Colors.redAccent),
                _kpiTile('Inference Latency', '${stats['avg_latency_ms']} ms', Colors.greenAccent),
                _kpiTile('Isolated Hosts', '${blockedIps.length}', Colors.amberAccent),
              ],
            ),
            const SizedBox(height: 12),

            // MODEL SELECTOR
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
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
                      .map((m) => DropdownMenuItem(
                            value: m,
                            child: Text('Algorithm: $m', style: const TextStyle(fontSize: 13)),
                          ))
                      .toList(),
                  onChanged: (val) {
                    if (val != null) changeModel(val);
                  },
                ),
              ),
            ),
            const SizedBox(height: 12),

            // ONE-TAP TRAFFIC & ATTACK SIMULATOR
            const Text('⚡ ONE-TAP SDN TRAFFIC SIMULATOR',
                style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Colors.grey)),
            const SizedBox(height: 6),
            Wrap(
              spacing: 6,
              runSpacing: 6,
              children: [
                _simButton('🟢 Normal (h2)', 'benign', Colors.teal),
                _simButton('🌿 Mint VM', 'mint_benign', Colors.green),
                _simButton('🔵 iperf3 Burst', 'high_vol', Colors.blue),
                _simButton('🟠 Port Scan', 'port_scan', Colors.orange),
                _simButton('🔴 SYN Flood', 'syn_flood', Colors.redAccent),
                _simButton('🐉 Kali Attack', 'kali_attack', Colors.purpleAccent),
              ],
            ),
            const SizedBox(height: 12),

            // QUARANTINED HOSTS (TAP TO UNBLOCK)
            if (blockedIps.isNotEmpty) ...[
              const Text('🛡️ ACTIVE QUARANTINES (TAP TO UNBLOCK)',
                  style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Colors.redAccent)),
              const SizedBox(height: 6),
              Wrap(
                spacing: 8,
                children: blockedIps
                    .map((ip) => ActionChip(
                          avatar: const Icon(Icons.lock_open, size: 15, color: Colors.white),
                          backgroundColor: Colors.red.shade900,
                          label: Text('Unblock $ip', style: const TextStyle(fontSize: 12)),
                          onPressed: () => unblockIp(ip.toString()),
                        ))
                    .toList(),
              ),
              const SizedBox(height: 12),
            ],

            // LIVE SECURITY & EXPLAINABLE AI STREAM
            const Text('🚨 LIVE SECURITY & EXPLAINABLE AI (XAI) LOG',
                style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, color: Colors.grey)),
            const SizedBox(height: 6),
            ...events.take(20).map((e) {
              final bool isBlock = e['action'] == 'quarantine';
              return Card(
                color: const Color(0xFF0F172A),
                margin: const EdgeInsets.only(bottom: 8),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(8),
                  side: BorderSide(
                    color: isBlock ? Colors.redAccent.withOpacity(0.5) : Colors.white10,
                  ),
                ),
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
                            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                            decoration: BoxDecoration(
                              color: isBlock
                                  ? Colors.redAccent.withOpacity(0.2)
                                  : Colors.greenAccent.withOpacity(0.2),
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
                        'Rate: ${e['pkt_rate']} pkts/s | Ports: ${e['unique_dst_ports']} | Latency: ${e['inference_latency_ms']} ms | Time: ${e['time']}',
                        style: const TextStyle(fontSize: 11, color: Colors.white70),
                      ),
                      if ((e['explanation'] ?? '').toString().isNotEmpty) ...[
                        const SizedBox(height: 4),
                        Text(
                          'XAI: ${e['explanation']}',
                          style: const TextStyle(fontSize: 11, color: Colors.cyanAccent),
                        ),
                      ],
                    ],
                  ),
                ),
              );
            }),
          ],
        ),
      ),
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
          const SizedBox(height: 4),
          Text(value, style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold, color: color)),
        ],
      ),
    );
  }

  Widget _simButton(String label, String scenario, Color color) {
    return ElevatedButton(
      style: ElevatedButton.styleFrom(
        backgroundColor: color.withOpacity(0.2),
        foregroundColor: Colors.white,
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
        textStyle: const TextStyle(fontSize: 11, fontWeight: FontWeight.bold),
      ),
      onPressed: () => triggerSimulation(scenario),
      child: Text(label),
    );
  }
}