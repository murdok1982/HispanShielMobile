import 'dart:async';
import 'dart:math';
import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
void main() {
  runApp(const HispaShieldDashboard());
}

// ---------------------------------------------------------------------------
// Data models
// ---------------------------------------------------------------------------

enum SensorKind { camera, microphone, gps, accelerometer, gyroscope, barometer }

extension SensorKindX on SensorKind {
  String get label {
    switch (this) {
      case SensorKind.camera:       return 'Camera';
      case SensorKind.microphone:   return 'Microphone';
      case SensorKind.gps:         return 'GPS';
      case SensorKind.accelerometer: return 'Accelerometer';
      case SensorKind.gyroscope:   return 'Gyroscope';
      case SensorKind.barometer:   return 'Barometer';
    }
  }

  IconData get icon {
    switch (this) {
      case SensorKind.camera:       return Icons.camera_alt;
      case SensorKind.microphone:   return Icons.mic;
      case SensorKind.gps:         return Icons.gps_fixed;
      case SensorKind.accelerometer: return Icons.speed;
      case SensorKind.gyroscope:   return Icons.rotate_90_degrees_cw;
      case SensorKind.barometer:   return Icons.compress;
    }
  }
}

class SensorStatus {
  final SensorKind kind;
  final bool active;
  final String? packageName;
  final DateTime? since;

  const SensorStatus({
    required this.kind,
    required this.active,
    this.packageName,
    this.since,
  });
}

class AppNetworkPolicy {
  final String packageName;
  final int uid;
  final bool denyAll;
  final List<String> allowedDomains;
  final int blockedAttempts;

  const AppNetworkPolicy({
    required this.packageName,
    required this.uid,
    required this.denyAll,
    required this.allowedDomains,
    required this.blockedAttempts,
  });
}

enum ProfileKind { personal, work, guest }

extension ProfileKindX on ProfileKind {
  String get label {
    switch (this) {
      case ProfileKind.personal: return 'Personal';
      case ProfileKind.work:     return 'Work';
      case ProfileKind.guest:    return 'Guest';
    }
  }

  IconData get icon {
    switch (this) {
      case ProfileKind.personal: return Icons.person;
      case ProfileKind.work:     return Icons.work;
      case ProfileKind.guest:    return Icons.person_outline;
    }
  }

  Color get color {
    switch (this) {
      case ProfileKind.personal: return Colors.blue;
      case ProfileKind.work:     return Colors.green;
      case ProfileKind.guest:    return Colors.orange;
    }
  }
}

enum AuditSeverity { info, warning, critical }

class AuditLogEntry {
  final DateTime timestamp;
  final AuditSeverity severity;
  final String daemon;
  final String message;

  const AuditLogEntry({
    required this.timestamp,
    required this.severity,
    required this.daemon,
    required this.message,
  });

  Color get color {
    switch (severity) {
      case AuditSeverity.info:     return Colors.blue;
      case AuditSeverity.warning:  return Colors.orange;
      case AuditSeverity.critical: return Colors.red;
    }
  }
}

// ---------------------------------------------------------------------------
// Mock data service (simulates Unix socket data from daemons)
// ---------------------------------------------------------------------------

class SecurityDataService {
  final _random = Random();

  Future<List<SensorStatus>> fetchSensorStatus() async {
    await Future.delayed(const Duration(milliseconds: 50));
    return [
      SensorStatus(
        kind: SensorKind.camera,
        active: _random.nextBool() && _random.nextBool(),
        packageName: 'com.example.camera',
        since: DateTime.now().subtract(const Duration(minutes: 2)),
      ),
      SensorStatus(kind: SensorKind.microphone, active: false),
      SensorStatus(
        kind: SensorKind.gps,
        active: true,
        packageName: 'com.example.maps',
        since: DateTime.now().subtract(const Duration(minutes: 10)),
      ),
      SensorStatus(kind: SensorKind.accelerometer, active: false),
      SensorStatus(kind: SensorKind.gyroscope, active: false),
      SensorStatus(kind: SensorKind.barometer, active: false),
    ];
  }

  Future<List<AppNetworkPolicy>> fetchNetworkPolicies() async {
    await Future.delayed(const Duration(milliseconds: 80));
    return [
      const AppNetworkPolicy(
        packageName: 'com.example.browser',
        uid: 10100,
        denyAll: false,
        allowedDomains: ['*.mozilla.org', '*.firefox.com'],
        blockedAttempts: 14,
      ),
      const AppNetworkPolicy(
        packageName: 'com.example.social',
        uid: 10101,
        denyAll: false,
        allowedDomains: ['api.social.net'],
        blockedAttempts: 238,
      ),
      const AppNetworkPolicy(
        packageName: 'com.evil.tracker',
        uid: 10102,
        denyAll: true,
        allowedDomains: [],
        blockedAttempts: 1452,
      ),
    ];
  }

  Future<List<AuditLogEntry>> fetchAuditLog() async {
    await Future.delayed(const Duration(milliseconds: 100));
    final now = DateTime.now();
    return [
      AuditLogEntry(
        timestamp: now.subtract(const Duration(seconds: 5)),
        severity: AuditSeverity.warning,
        daemon: 'npd',
        message: 'UID 10102 attempted access to doubleclick.net — BLOCKED',
      ),
      AuditLogEntry(
        timestamp: now.subtract(const Duration(seconds: 12)),
        severity: AuditSeverity.info,
        daemon: 'sensor-guard',
        message: 'UID 10050 GPS access token granted (TTL 300s)',
      ),
      AuditLogEntry(
        timestamp: now.subtract(const Duration(seconds: 31)),
        severity: AuditSeverity.critical,
        daemon: 'profile-isolation',
        message: 'Cross-profile bind-mount detected: /data/user/0 → /data/user/10 ALERT',
      ),
      AuditLogEntry(
        timestamp: now.subtract(const Duration(minutes: 2)),
        severity: AuditSeverity.info,
        daemon: 'gms-proxy',
        message: 'Stripped advertisingId from FCM payload (UID 10055)',
      ),
      AuditLogEntry(
        timestamp: now.subtract(const Duration(minutes: 5)),
        severity: AuditSeverity.warning,
        daemon: 'baseband-proxy',
        message: 'AT+CLAC blocked for UID 10088',
      ),
      AuditLogEntry(
        timestamp: now.subtract(const Duration(minutes: 12)),
        severity: AuditSeverity.info,
        daemon: 'auto-reboot',
        message: 'Next scheduled reboot in 14h 32m (daily 03:00)',
      ),
    ];
  }
}

// ---------------------------------------------------------------------------
// App root
// ---------------------------------------------------------------------------

class HispaShieldDashboard extends StatelessWidget {
  const HispaShieldDashboard({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'HispaShield',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF1A73E8),
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
        fontFamily: 'RobotoMono',
      ),
      darkTheme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF1A73E8),
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
      ),
      themeMode: ThemeMode.dark,
      home: const MainNavigationPage(),
    );
  }
}

// ---------------------------------------------------------------------------
// Navigation shell
// ---------------------------------------------------------------------------

class MainNavigationPage extends StatefulWidget {
  const MainNavigationPage({super.key});

  @override
  State<MainNavigationPage> createState() => _MainNavigationPageState();
}

class _MainNavigationPageState extends State<MainNavigationPage> {
  int _selectedIndex = 0;
  final _service = SecurityDataService();

  final List<_NavItem> _navItems = const [
    _NavItem(icon: Icons.shield_outlined, selectedIcon: Icons.shield, label: 'Overview'),
    _NavItem(icon: Icons.sensors_outlined, selectedIcon: Icons.sensors, label: 'Sensors'),
    _NavItem(icon: Icons.network_check_outlined, selectedIcon: Icons.network_check, label: 'Network'),
    _NavItem(icon: Icons.person_pin_outlined, selectedIcon: Icons.person_pin, label: 'Profiles'),
    _NavItem(icon: Icons.receipt_long_outlined, selectedIcon: Icons.receipt_long, label: 'Audit Log'),
  ];

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Row(
          children: [
            Icon(Icons.shield, color: Color(0xFF1A73E8)),
            SizedBox(width: 8),
            Text('HispaShield', style: TextStyle(fontWeight: FontWeight.bold)),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: () => setState(() {}),
            tooltip: 'Refresh',
          ),
          IconButton(
            icon: const Icon(Icons.settings_outlined),
            onPressed: () => _showSettings(context),
            tooltip: 'Settings',
          ),
        ],
      ),
      body: IndexedStack(
        index: _selectedIndex,
        children: [
          OverviewPage(service: _service),
          SensorPage(service: _service),
          NetworkPolicyPage(service: _service),
          ProfilePage(),
          AuditLogPage(service: _service),
        ],
      ),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _selectedIndex,
        onDestinationSelected: (i) => setState(() => _selectedIndex = i),
        destinations: _navItems.map((item) => NavigationDestination(
          icon: Icon(item.icon),
          selectedIcon: Icon(item.selectedIcon),
          label: item.label,
        )).toList(),
      ),
    );
  }

  void _showSettings(BuildContext context) {
    showModalBottomSheet(
      context: context,
      builder: (ctx) => const _SettingsSheet(),
    );
  }
}

class _NavItem {
  final IconData icon;
  final IconData selectedIcon;
  final String label;
  const _NavItem({required this.icon, required this.selectedIcon, required this.label});
}

// ---------------------------------------------------------------------------
// Overview page
// ---------------------------------------------------------------------------

class OverviewPage extends StatefulWidget {
  final SecurityDataService service;
  const OverviewPage({super.key, required this.service});

  @override
  State<OverviewPage> createState() => _OverviewPageState();
}

class _OverviewPageState extends State<OverviewPage> {
  late Timer _timer;

  @override
  void initState() {
    super.initState();
    _timer = Timer.periodic(const Duration(seconds: 10), (_) => setState(() {}));
  }

  @override
  void dispose() {
    _timer.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _SecurityScoreCard(),
          const SizedBox(height: 16),
          Text('Daemon Status', style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 8),
          _DaemonStatusGrid(),
          const SizedBox(height: 16),
          Text('Recent Activity', style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 8),
          FutureBuilder<List<AuditLogEntry>>(
            future: widget.service.fetchAuditLog(),
            builder: (ctx, snap) {
              if (!snap.hasData) return const CircularProgressIndicator();
              return Column(
                children: snap.data!.take(3).map((e) => _AuditEntryTile(entry: e)).toList(),
              );
            },
          ),
        ],
      ),
    );
  }
}

class _SecurityScoreCard extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Row(
          children: [
            Stack(
              alignment: Alignment.center,
              children: [
                SizedBox(
                  width: 80, height: 80,
                  child: CircularProgressIndicator(
                    value: 0.87,
                    strokeWidth: 8,
                    backgroundColor: Colors.grey.shade800,
                    color: Colors.green,
                  ),
                ),
                const Text('87', style: TextStyle(fontSize: 22, fontWeight: FontWeight.bold)),
              ],
            ),
            const SizedBox(width: 20),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('Security Score', style: Theme.of(context).textTheme.titleLarge),
                  const SizedBox(height: 4),
                  const Text('Good — all critical daemons running', style: TextStyle(color: Colors.green)),
                  const SizedBox(height: 8),
                  const Text('1 warning: cross-profile mount alert', style: TextStyle(color: Colors.orange, fontSize: 12)),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _DaemonStatusGrid extends StatelessWidget {
  final _daemons = const [
    ('NPD', 'Network Policy', true),
    ('Sensor Guard', 'Sensor Guard', true),
    ('Settings Core', 'Secure Settings', true),
    ('Profile ISO', 'Profile Isolation', true),
    ('GMS Proxy', 'GMS Compat', true),
    ('Auto-Reboot', 'Auto Reboot', true),
    ('BB Proxy', 'Baseband Proxy', true),
    ('Media ISO', 'Media Isolate', true),
  ];

  const _DaemonStatusGrid({super.key});

  @override
  Widget build(BuildContext context) {
    return GridView.builder(
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: 2,
        crossAxisSpacing: 8,
        mainAxisSpacing: 8,
        childAspectRatio: 2.5,
      ),
      itemCount: _daemons.length,
      itemBuilder: (ctx, i) {
        final d = _daemons[i];
        return Card(
          color: d.$3
              ? Colors.green.withOpacity(0.1)
              : Colors.red.withOpacity(0.1),
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
            child: Row(
              children: [
                Icon(
                  d.$3 ? Icons.check_circle : Icons.error,
                  color: d.$3 ? Colors.green : Colors.red,
                  size: 20,
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Text(d.$1, style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 12)),
                      Text(d.$3 ? 'Running' : 'Stopped',
                          style: TextStyle(
                            fontSize: 11,
                            color: d.$3 ? Colors.green : Colors.red,
                          )),
                    ],
                  ),
                ),
              ],
            ),
          ),
        );
      },
    );
  }
}

// ---------------------------------------------------------------------------
// Sensor access page
// ---------------------------------------------------------------------------

class SensorPage extends StatefulWidget {
  final SecurityDataService service;
  const SensorPage({super.key, required this.service});

  @override
  State<SensorPage> createState() => _SensorPageState();
}

class _SensorPageState extends State<SensorPage> {
  @override
  Widget build(BuildContext context) {
    return FutureBuilder<List<SensorStatus>>(
      future: widget.service.fetchSensorStatus(),
      builder: (ctx, snap) {
        if (snap.connectionState == ConnectionState.waiting) {
          return const Center(child: CircularProgressIndicator());
        }
        if (snap.hasError) {
          return Center(child: Text('Error: ${snap.error}'));
        }
        final statuses = snap.data!;
        return ListView(
          padding: const EdgeInsets.all(16),
          children: [
            Text('Sensor Access Status', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            ...statuses.map((s) => _SensorTile(status: s)),
          ],
        );
      },
    );
  }
}

class _SensorTile extends StatelessWidget {
  final SensorStatus status;
  const _SensorTile({required this.status});

  @override
  Widget build(BuildContext context) {
    final fmt = DateFormat('HH:mm:ss');
    return Card(
      child: ListTile(
        leading: Container(
          width: 40, height: 40,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: status.active
                ? Colors.red.withOpacity(0.2)
                : Colors.grey.withOpacity(0.2),
          ),
          child: Icon(
            status.kind.icon,
            color: status.active ? Colors.red : Colors.grey,
          ),
        ),
        title: Text(status.kind.label),
        subtitle: status.active
            ? Text('Active: ${status.packageName ?? "unknown"} since ${status.since != null ? fmt.format(status.since!) : "?"}',
                style: const TextStyle(color: Colors.orange))
            : const Text('Idle', style: TextStyle(color: Colors.green)),
        trailing: status.active
            ? Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                decoration: BoxDecoration(
                  color: Colors.red.withOpacity(0.2),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: const Text('ACTIVE', style: TextStyle(color: Colors.red, fontSize: 11)),
              )
            : null,
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Network policy page
// ---------------------------------------------------------------------------

class NetworkPolicyPage extends StatefulWidget {
  final SecurityDataService service;
  const NetworkPolicyPage({super.key, required this.service});

  @override
  State<NetworkPolicyPage> createState() => _NetworkPolicyPageState();
}

class _NetworkPolicyPageState extends State<NetworkPolicyPage> {
  @override
  Widget build(BuildContext context) {
    return FutureBuilder<List<AppNetworkPolicy>>(
      future: widget.service.fetchNetworkPolicies(),
      builder: (ctx, snap) {
        if (snap.connectionState == ConnectionState.waiting) {
          return const Center(child: CircularProgressIndicator());
        }
        final policies = snap.data ?? [];
        return ListView(
          padding: const EdgeInsets.all(16),
          children: [
            Text('Network Policy per App', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            ...policies.map((p) => _PolicyTile(policy: p)),
          ],
        );
      },
    );
  }
}

class _PolicyTile extends StatelessWidget {
  final AppNetworkPolicy policy;
  const _PolicyTile({required this.policy});

  @override
  Widget build(BuildContext context) {
    return Card(
      child: ExpansionTile(
        leading: Icon(
          policy.denyAll ? Icons.block : Icons.check_circle_outline,
          color: policy.denyAll ? Colors.red : Colors.green,
        ),
        title: Text(policy.packageName, style: const TextStyle(fontSize: 14)),
        subtitle: Text(
          policy.denyAll ? 'All network blocked' : '${policy.allowedDomains.length} allowed domain(s)',
          style: TextStyle(color: policy.denyAll ? Colors.red : Colors.blue),
        ),
        trailing: Chip(
          label: Text('${policy.blockedAttempts} blocked'),
          backgroundColor: Colors.orange.withOpacity(0.2),
          labelStyle: const TextStyle(color: Colors.orange, fontSize: 11),
        ),
        children: [
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('UID: ${policy.uid}', style: const TextStyle(fontSize: 12, color: Colors.grey)),
                const SizedBox(height: 4),
                if (policy.allowedDomains.isNotEmpty) ...[
                  const Text('Allowed domains:', style: TextStyle(fontSize: 12)),
                  ...policy.allowedDomains.map((d) => Padding(
                    padding: const EdgeInsets.only(left: 16, top: 2),
                    child: Row(
                      children: [
                        const Icon(Icons.check, size: 14, color: Colors.green),
                        const SizedBox(width: 4),
                        Text(d, style: const TextStyle(fontSize: 12, fontFamily: 'monospace')),
                      ],
                    ),
                  )),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Profile switcher page
// ---------------------------------------------------------------------------

class ProfilePage extends StatefulWidget {
  const ProfilePage({super.key});

  @override
  State<ProfilePage> createState() => _ProfilePageState();
}

class _ProfilePageState extends State<ProfilePage> {
  ProfileKind _activeProfile = ProfileKind.personal;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Active Profile', style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 16),
          ...ProfileKind.values.map((p) => _ProfileTile(
            profile: p,
            isActive: p == _activeProfile,
            onSelect: () => setState(() => _activeProfile = p),
          )),
          const SizedBox(height: 24),
          Text('Cross-Profile Policy', style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 8),
          const Card(
            child: Padding(
              padding: EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  _PolicyRow(from: 'Personal', to: 'Work', allowed: false),
                  _PolicyRow(from: 'Work', to: 'Personal', allowed: false),
                  _PolicyRow(from: 'Guest', to: 'Personal', allowed: false),
                  _PolicyRow(from: 'Guest', to: 'Work', allowed: false),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _ProfileTile extends StatelessWidget {
  final ProfileKind profile;
  final bool isActive;
  final VoidCallback onSelect;

  const _ProfileTile({required this.profile, required this.isActive, required this.onSelect});

  @override
  Widget build(BuildContext context) {
    return Card(
      color: isActive ? profile.color.withOpacity(0.15) : null,
      child: ListTile(
        leading: Container(
          width: 40, height: 40,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: profile.color.withOpacity(0.3),
          ),
          child: Icon(profile.icon, color: profile.color),
        ),
        title: Text(profile.label),
        subtitle: Text(isActive ? 'Currently active' : 'Inactive'),
        trailing: isActive
            ? const Icon(Icons.check_circle, color: Colors.green)
            : ElevatedButton(
                onPressed: onSelect,
                child: const Text('Switch'),
              ),
      ),
    );
  }
}

class _PolicyRow extends StatelessWidget {
  final String from;
  final String to;
  final bool allowed;

  const _PolicyRow({required this.from, required this.to, required this.allowed});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          Icon(allowed ? Icons.arrow_forward : Icons.block, size: 16,
              color: allowed ? Colors.green : Colors.red),
          const SizedBox(width: 8),
          Text('$from → $to: ', style: const TextStyle(fontSize: 13)),
          Text(
            allowed ? 'Allowed' : 'Blocked',
            style: TextStyle(color: allowed ? Colors.green : Colors.red, fontSize: 13),
          ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Audit log page
// ---------------------------------------------------------------------------

class AuditLogPage extends StatefulWidget {
  final SecurityDataService service;
  const AuditLogPage({super.key, required this.service});

  @override
  State<AuditLogPage> createState() => _AuditLogPageState();
}

class _AuditLogPageState extends State<AuditLogPage> {
  AuditSeverity? _filter;

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
          child: Row(
            children: [
              Text('Filter:', style: Theme.of(context).textTheme.labelLarge),
              const SizedBox(width: 8),
              ...[null, AuditSeverity.info, AuditSeverity.warning, AuditSeverity.critical].map(
                (sev) => Padding(
                  padding: const EdgeInsets.only(right: 4),
                  child: FilterChip(
                    label: Text(sev == null ? 'All' : sev.name.toUpperCase()),
                    selected: _filter == sev,
                    onSelected: (_) => setState(() => _filter = sev),
                  ),
                ),
              ),
            ],
          ),
        ),
        Expanded(
          child: FutureBuilder<List<AuditLogEntry>>(
            future: widget.service.fetchAuditLog(),
            builder: (ctx, snap) {
              if (snap.connectionState == ConnectionState.waiting) {
                return const Center(child: CircularProgressIndicator());
              }
              var entries = snap.data ?? [];
              if (_filter != null) {
                entries = entries.where((e) => e.severity == _filter).toList();
              }
              if (entries.isEmpty) {
                return const Center(child: Text('No log entries'));
              }
              return ListView.builder(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                itemCount: entries.length,
                itemBuilder: (ctx, i) => _AuditEntryTile(entry: entries[i]),
              );
            },
          ),
        ),
      ],
    );
  }
}

class _AuditEntryTile extends StatelessWidget {
  final AuditLogEntry entry;
  const _AuditEntryTile({required this.entry});

  @override
  Widget build(BuildContext context) {
    final fmt = DateFormat('HH:mm:ss');
    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: ListTile(
        dense: true,
        leading: Icon(
          entry.severity == AuditSeverity.critical
              ? Icons.error
              : entry.severity == AuditSeverity.warning
                  ? Icons.warning_amber
                  : Icons.info_outline,
          color: entry.color,
          size: 20,
        ),
        title: Text(entry.message, style: const TextStyle(fontSize: 13)),
        subtitle: Text(
          '${fmt.format(entry.timestamp)} · ${entry.daemon}',
          style: const TextStyle(fontSize: 11, color: Colors.grey),
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Settings bottom sheet
// ---------------------------------------------------------------------------

class _SettingsSheet extends StatelessWidget {
  const _SettingsSheet();

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(24),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Settings', style: Theme.of(context).textTheme.headlineSmall),
          const SizedBox(height: 16),
          ListTile(
            leading: const Icon(Icons.refresh),
            title: const Text('Daemon socket path'),
            subtitle: const Text('/run/hispashield/'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () {},
          ),
          ListTile(
            leading: const Icon(Icons.security),
            title: const Text('Policy file location'),
            subtitle: const Text('/data/hispashield/'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () {},
          ),
          ListTile(
            leading: const Icon(Icons.timer),
            title: const Text('Log retention'),
            subtitle: const Text('30 days'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () {},
          ),
          const SizedBox(height: 8),
          const Divider(),
          const SizedBox(height: 8),
          Text(
            'HispaShield Privacy Dashboard v1.0.0\nBuilt for AOSP 14 / Pixel 8',
            style: Theme.of(context).textTheme.bodySmall?.copyWith(color: Colors.grey),
          ),
        ],
      ),
    );
  }
}
