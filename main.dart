// Documents Manager
// Apne documents ek jagah, PIN/fingerprint lock ke peeche.
// Har file AES se encrypt hoti hai. Sab kuch phone me hi rehta hai.

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:cunning_document_scanner/cunning_document_scanner.dart';
import 'package:encrypt/encrypt.dart' as enc;
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:image_picker/image_picker.dart';
import 'package:local_auth/local_auth.dart';
import 'package:pdf/widgets.dart' as pw;
import 'package:open_filex/open_filex.dart';
import 'package:path_provider/path_provider.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const DocsApp());
}

/* ------------------------------------------------------------------ */
/*  Models                                                             */
/* ------------------------------------------------------------------ */

class DocFolder {
  String id;
  String name;
  DocFolder(this.id, this.name);

  Map<String, dynamic> toJson() => {'id': id, 'name': name};
  factory DocFolder.fromJson(Map<String, dynamic> m) =>
      DocFolder(m['id'] as String, m['name'] as String);
}

class DocFile {
  String id;
  String folderId;
  String name;
  int size;
  int created;
  DocFile(this.id, this.folderId, this.name, this.size, this.created);

  Map<String, dynamic> toJson() =>
      {'id': id, 'folderId': folderId, 'name': name, 'size': size, 'created': created};
  factory DocFile.fromJson(Map<String, dynamic> m) => DocFile(
        m['id'] as String,
        m['folderId'] as String,
        m['name'] as String,
        (m['size'] as num).toInt(),
        (m['created'] as num).toInt(),
      );
}

/* ------------------------------------------------------------------ */
/*  Vault: storage + encryption                                        */
/* ------------------------------------------------------------------ */

class Vault {
  static late Directory _root;
  static late File _index;
  static List<DocFolder> folders = [];
  static List<DocFile> files = [];
  static enc.Encrypter? _enc;

  static bool get isUnlocked => _enc != null;

  static Future<void> init() async {
    final d = await getApplicationDocumentsDirectory();
    _root = Directory('${d.path}/vault');
    if (!_root.existsSync()) _root.createSync(recursive: true);
    _index = File('${d.path}/index.json');
    await _load();
  }

  static Future<void> _load() async {
    if (!_index.existsSync()) {
      folders = [];
      files = [];
      return;
    }
    try {
      final m = jsonDecode(await _index.readAsString()) as Map<String, dynamic>;
      folders = (m['folders'] as List)
          .map((e) => DocFolder.fromJson(e as Map<String, dynamic>))
          .toList();
      files = (m['files'] as List)
          .map((e) => DocFile.fromJson(e as Map<String, dynamic>))
          .toList();
    } catch (_) {
      folders = [];
      files = [];
    }
  }

  static Future<void> save() async {
    await _index.writeAsString(jsonEncode({
      'folders': folders.map((e) => e.toJson()).toList(),
      'files': files.map((e) => e.toJson()).toList(),
    }));
  }

  static void unlockWith(String pin, String salt) {
    final k = sha256.convert(utf8.encode('$pin|$salt')).bytes;
    _enc = enc.Encrypter(
        enc.AES(enc.Key(Uint8List.fromList(k)), mode: enc.AESMode.cbc));
  }

  static void lock() => _enc = null;

  static Future<void> writeEncrypted(String id, Uint8List bytes) async {
    final iv = enc.IV.fromSecureRandom(16);
    final out = _enc!.encryptBytes(bytes, iv: iv);
    final b = BytesBuilder()
      ..add(iv.bytes)
      ..add(out.bytes);
    await File('${_root.path}/$id').writeAsBytes(b.toBytes());
  }

  static Future<Uint8List> readDecrypted(String id) async {
    final raw = await File('${_root.path}/$id').readAsBytes();
    final iv = enc.IV(Uint8List.fromList(raw.sublist(0, 16)));
    final body = enc.Encrypted(Uint8List.fromList(raw.sublist(16)));
    return Uint8List.fromList(_enc!.decryptBytes(body, iv: iv));
  }

  static Future<void> removeBlob(String id) async {
    final f = File('${_root.path}/$id');
    if (f.existsSync()) await f.delete();
  }

  static String newId() {
    final r = Random.secure();
    return '${DateTime.now().millisecondsSinceEpoch.toRadixString(36)}'
        '${List.generate(6, (_) => r.nextInt(36).toRadixString(36)).join()}';
  }
}

/* ------------------------------------------------------------------ */
/*  Public copy: phone ke andar dikhne wala folder                     */
/* ------------------------------------------------------------------ */

class PublicCopy {
  static const String base = '/storage/emulated/0/Documents Manager';

  static Future<bool> ensurePermission() async {
    if (await Permission.manageExternalStorage.isGranted) return true;
    final s = await Permission.manageExternalStorage.request();
    if (s.isGranted) return true;
    final s2 = await Permission.storage.request();
    return s2.isGranted;
  }

  static Future<String?> write(
      String folderName, String fileName, Uint8List bytes) async {
    try {
      final dir = Directory('$base/$folderName');
      if (!dir.existsSync()) dir.createSync(recursive: true);
      final f = File('${dir.path}/$fileName');
      await f.writeAsBytes(bytes);
      return f.path;
    } catch (_) {
      return null;
    }
  }

  static Future<void> remove(String folderName, String fileName) async {
    try {
      final f = File('$base/$folderName/$fileName');
      if (f.existsSync()) await f.delete();
    } catch (_) {}
  }
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

String fmtSize(int b) {
  if (b < 1024) return '$b B';
  if (b < 1048576) return '${(b / 1024).toStringAsFixed(0)} KB';
  return '${(b / 1048576).toStringAsFixed(1)} MB';
}

const _months = [
  'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'
];

String fmtDate(int ms) {
  final d = DateTime.fromMillisecondsSinceEpoch(ms);
  return '${d.day} ${_months[d.month - 1]} ${d.year}';
}

List<String> splitName(String n) {
  final i = n.lastIndexOf('.');
  return i > 0 ? [n.substring(0, i), n.substring(i)] : [n, ''];
}

void snack(BuildContext c, String msg) {
  ScaffoldMessenger.of(c)
    ..hideCurrentSnackBar()
    ..showSnackBar(SnackBar(content: Text(msg)));
}

/* ------------------------------------------------------------------ */
/*  App root                                                           */
/* ------------------------------------------------------------------ */

class DocsApp extends StatelessWidget {
  const DocsApp({super.key});

  @override
  Widget build(BuildContext context) {
    final scheme = ColorScheme.fromSeed(
      seedColor: const Color(0xFF125650),
      brightness: Brightness.light,
    );
    final dark = ColorScheme.fromSeed(
      seedColor: const Color(0xFF125650),
      brightness: Brightness.dark,
    );
    return MaterialApp(
      title: 'Documents Manager',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(colorScheme: scheme, useMaterial3: true),
      darkTheme: ThemeData(colorScheme: dark, useMaterial3: true),
      home: const Gate(),
    );
  }
}

/* ------------------------------------------------------------------ */
/*  Gate: setup / unlock / home                                        */
/* ------------------------------------------------------------------ */

class Gate extends StatefulWidget {
  const Gate({super.key});
  @override
  State<Gate> createState() => _GateState();
}

class _GateState extends State<Gate> with WidgetsBindingObserver {
  bool _ready = false;
  bool _hasPin = false;
  DateTime? _pausedAt;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _boot();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  Future<void> _boot() async {
    await Vault.init();
    final p = await SharedPreferences.getInstance();
    setState(() {
      _hasPin = p.getString('salt') != null;
      _ready = true;
    });
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState s) {
    if (s == AppLifecycleState.paused) {
      _pausedAt = DateTime.now();
    } else if (s == AppLifecycleState.resumed) {
      if (Vault.isUnlocked &&
          _pausedAt != null &&
          DateTime.now().difference(_pausedAt!).inSeconds > 60) {
        Vault.lock();
        setState(() {});
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    if (!_ready) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }
    if (!_hasPin) {
      return SetPinScreen(onDone: () => setState(() => _hasPin = true));
    }
    if (!Vault.isUnlocked) {
      return UnlockScreen(onDone: () => setState(() {}));
    }
    return HomeScreen(onLock: () {
      Vault.lock();
      setState(() {});
    });
  }
}

/* ------------------------------------------------------------------ */
/*  PIN screens                                                        */
/* ------------------------------------------------------------------ */

class _PinPad extends StatelessWidget {
  final String value;
  final void Function(String) onKey;
  final VoidCallback onSubmit;
  const _PinPad(
      {required this.value, required this.onKey, required this.onSubmit});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    Widget key(String label, {VoidCallback? tap, Color? bg, Color? fg}) {
      return SizedBox(
        width: 74,
        height: 66,
        child: Material(
          color: bg ?? cs.surfaceContainerHighest,
          shape: const CircleBorder(),
          child: InkWell(
            customBorder: const CircleBorder(),
            onTap: tap ?? () => onKey(label),
            child: Center(
              child: Text(label,
                  style: TextStyle(fontSize: 22, color: fg ?? cs.onSurface)),
            ),
          ),
        ),
      );
    }

    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        for (final row in [
          ['1', '2', '3'],
          ['4', '5', '6'],
          ['7', '8', '9'],
        ])
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 6),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [for (final k in row) Padding(padding: const EdgeInsets.symmetric(horizontal: 7), child: key(k))],
            ),
          ),
        Padding(
          padding: const EdgeInsets.symmetric(vertical: 6),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 7),
                  child: key('\u232B',
                      tap: () => onKey('del'), bg: Colors.transparent)),
              Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 7),
                  child: key('0')),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 7),
                child: key('\u2192',
                    tap: onSubmit,
                    bg: cs.primary,
                    fg: cs.onPrimary),
              ),
            ],
          ),
        ),
      ],
    );
  }
}

Widget _dots(BuildContext c, int n) {
  final cs = Theme.of(c).colorScheme;
  final count = n < 4 ? 4 : n;
  return Row(
    mainAxisAlignment: MainAxisAlignment.center,
    children: List.generate(
      count,
      (i) => Container(
        margin: const EdgeInsets.symmetric(horizontal: 6),
        width: 13,
        height: 13,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          color: i < n ? cs.primary : Colors.transparent,
          border: Border.all(color: i < n ? cs.primary : cs.outline, width: 1.5),
        ),
      ),
    ),
  );
}

class SetPinScreen extends StatefulWidget {
  final VoidCallback onDone;
  const SetPinScreen({super.key, required this.onDone});
  @override
  State<SetPinScreen> createState() => _SetPinScreenState();
}

class _SetPinScreenState extends State<SetPinScreen> {
  String pin = '';
  String first = '';
  bool confirming = false;
  String msg = '';

  void _key(String k) {
    setState(() {
      msg = '';
      if (k == 'del') {
        if (pin.isNotEmpty) pin = pin.substring(0, pin.length - 1);
      } else if (pin.length < 8) {
        pin += k;
      }
    });
  }

  Future<void> _submit() async {
    if (pin.length < 4) {
      setState(() => msg = 'Kam se kam 4 ank daaliye');
      return;
    }
    if (!confirming) {
      setState(() {
        first = pin;
        pin = '';
        confirming = true;
      });
      return;
    }
    if (pin != first) {
      setState(() {
        msg = 'PIN match nahi hua, phir se';
        pin = '';
        first = '';
        confirming = false;
      });
      return;
    }
    final r = Random.secure();
    final salt =
        List.generate(16, (_) => r.nextInt(256).toRadixString(16).padLeft(2, '0'))
            .join();
    final check = sha256.convert(utf8.encode('$pin|$salt|check')).toString();
    final p = await SharedPreferences.getInstance();
    await p.setString('salt', salt);
    await p.setString('check', check);
    await p.setBool('publicCopy', true);
    Vault.unlockWith(pin, salt);
    if (Vault.folders.isEmpty) {
      Vault.folders.add(DocFolder(Vault.newId(), 'Personal'));
      await Vault.save();
    }
    widget.onDone();
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(Icons.lock_outline, size: 46, color: cs.primary),
                const SizedBox(height: 14),
                const Text('Documents Manager',
                    style: TextStyle(fontSize: 26, fontWeight: FontWeight.w700)),
                const SizedBox(height: 8),
                Text(
                  confirming
                      ? 'Wahi PIN dobara daaliye'
                      : 'Apne documents ke liye PIN banaiye',
                  style: TextStyle(color: cs.onSurfaceVariant),
                ),
                const SizedBox(height: 28),
                _dots(context, pin.length),
                const SizedBox(height: 10),
                SizedBox(
                  height: 22,
                  child: Text(msg, style: TextStyle(color: cs.error)),
                ),
                const SizedBox(height: 6),
                _PinPad(value: pin, onKey: _key, onSubmit: _submit),
                const SizedBox(height: 18),
                Text(
                  'PIN bhool gaye to documents wapas nahi milenge.\nKahin likh kar rakh lijiye.',
                  textAlign: TextAlign.center,
                  style: TextStyle(fontSize: 12, color: cs.onSurfaceVariant),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class UnlockScreen extends StatefulWidget {
  final VoidCallback onDone;
  const UnlockScreen({super.key, required this.onDone});
  @override
  State<UnlockScreen> createState() => _UnlockScreenState();
}

class _UnlockScreenState extends State<UnlockScreen> {
  String pin = '';
  String msg = '';

  @override
  void initState() {
    super.initState();
    _tryBiometric();
  }

  Future<void> _tryBiometric() async {
    final p = await SharedPreferences.getInstance();
    if (p.getString('bioPin') == null) return;
    try {
      final auth = LocalAuthentication();
      if (!await auth.isDeviceSupported()) return;
      final ok = await auth.authenticate(
        localizedReason: 'Documents Manager kholne ke liye',
        options: const AuthenticationOptions(
            biometricOnly: true, stickyAuth: true, useErrorDialogs: true),
      );
      if (ok) {
        final saved = p.getString('bioPin')!;
        Vault.unlockWith(saved, p.getString('salt')!);
        widget.onDone();
      }
    } catch (_) {}
  }

  void _key(String k) {
    setState(() {
      msg = '';
      if (k == 'del') {
        if (pin.isNotEmpty) pin = pin.substring(0, pin.length - 1);
      } else if (pin.length < 8) {
        pin += k;
      }
    });
  }

  Future<void> _submit() async {
    final p = await SharedPreferences.getInstance();
    final salt = p.getString('salt')!;
    final check = p.getString('check')!;
    if (sha256.convert(utf8.encode('$pin|$salt|check')).toString() != check) {
      setState(() {
        msg = 'Galat PIN';
        pin = '';
      });
      return;
    }
    Vault.unlockWith(pin, salt);
    widget.onDone();
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(Icons.lock_outline, size: 46, color: cs.primary),
                const SizedBox(height: 14),
                const Text('Documents Manager',
                    style: TextStyle(fontSize: 26, fontWeight: FontWeight.w700)),
                const SizedBox(height: 8),
                Text('PIN daal kar khol dijiye',
                    style: TextStyle(color: cs.onSurfaceVariant)),
                const SizedBox(height: 28),
                _dots(context, pin.length),
                const SizedBox(height: 10),
                SizedBox(
                    height: 22, child: Text(msg, style: TextStyle(color: cs.error))),
                const SizedBox(height: 6),
                _PinPad(value: pin, onKey: _key, onSubmit: _submit),
                const SizedBox(height: 12),
                TextButton.icon(
                  onPressed: _tryBiometric,
                  icon: const Icon(Icons.fingerprint),
                  label: const Text('Fingerprint se kholein'),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

/* ------------------------------------------------------------------ */
/*  Home: folder list                                                  */
/* ------------------------------------------------------------------ */

class HomeScreen extends StatefulWidget {
  final VoidCallback onLock;
  const HomeScreen({super.key, required this.onLock});
  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  String query = '';

  Future<void> _newFolder() async {
    final ctrl = TextEditingController();
    final name = await showDialog<String>(
      context: context,
      builder: (c) => AlertDialog(
        title: const Text('Naya folder'),
        content: TextField(
          controller: ctrl,
          autofocus: true,
          decoration: const InputDecoration(
            hintText: 'Jaise: Aadhaar, Bank, Marksheet',
          ),
          onSubmitted: (v) => Navigator.pop(c, v),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(c), child: const Text('Rehne dein')),
          FilledButton(
              onPressed: () => Navigator.pop(c, ctrl.text),
              child: const Text('Banayein')),
        ],
      ),
    );
    if (name == null || name.trim().isEmpty) return;
    Vault.folders.add(DocFolder(Vault.newId(), name.trim()));
    await Vault.save();
    setState(() {});
  }

  Future<void> _folderMenu(DocFolder f) async {
    final count = Vault.files.where((x) => x.folderId == f.id).length;
    final a = await showModalBottomSheet<String>(
      context: context,
      builder: (c) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(title: Text(f.name), subtitle: Text('$count document')),
            const Divider(height: 1),
            ListTile(
                leading: const Icon(Icons.drive_file_rename_outline),
                title: const Text('Naam badlein'),
                onTap: () => Navigator.pop(c, 'rename')),
            ListTile(
                leading: const Icon(Icons.delete_outline),
                title: const Text('Folder delete karein'),
                onTap: () => Navigator.pop(c, 'delete')),
          ],
        ),
      ),
    );
    if (a == 'rename') {
      final ctrl = TextEditingController(text: f.name);
      final n = await showDialog<String>(
        context: context,
        builder: (c) => AlertDialog(
          title: const Text('Naam badlein'),
          content: TextField(controller: ctrl, autofocus: true),
          actions: [
            TextButton(
                onPressed: () => Navigator.pop(c),
                child: const Text('Rehne dein')),
            FilledButton(
                onPressed: () => Navigator.pop(c, ctrl.text),
                child: const Text('Badlein')),
          ],
        ),
      );
      if (n != null && n.trim().isNotEmpty) {
        f.name = n.trim();
        await Vault.save();
        setState(() {});
      }
    } else if (a == 'delete') {
      final ok = await _confirm(context, 'Ye folder delete karein?',
          '${f.name}${count > 0 ? ' aur iske andar ke $count document' : ''} hamesha ke liye hat jayenge.');
      if (ok != true) return;
      for (final x in Vault.files.where((x) => x.folderId == f.id).toList()) {
        await Vault.removeBlob(x.id);
        await PublicCopy.remove(f.name, x.name);
        Vault.files.remove(x);
      }
      Vault.folders.remove(f);
      await Vault.save();
      setState(() {});
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final q = query.trim().toLowerCase();
    final hits = q.isEmpty
        ? <DocFile>[]
        : Vault.files.where((f) => f.name.toLowerCase().contains(q)).toList();
    final total = Vault.files.fold<int>(0, (a, f) => a + f.size);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Mere documents'),
        actions: [
          IconButton(
            icon: const Icon(Icons.settings_outlined),
            tooltip: 'Settings',
            onPressed: () async {
              await Navigator.push(context,
                  MaterialPageRoute(builder: (_) => const SettingsScreen()));
              setState(() {});
            },
          ),
          IconButton(
            icon: const Icon(Icons.lock_outline),
            tooltip: 'Lock karein',
            onPressed: widget.onLock,
          ),
        ],
      ),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
            child: TextField(
              decoration: const InputDecoration(
                prefixIcon: Icon(Icons.search),
                hintText: 'Document ka naam dhoondein',
                border: OutlineInputBorder(),
                isDense: true,
              ),
              onChanged: (v) => setState(() => query = v),
            ),
          ),
          if (q.isEmpty)
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
              child: Align(
                alignment: Alignment.centerLeft,
                child: Text(
                  Vault.files.isEmpty
                      ? 'Sab kuch is phone me locked rehta hai'
                      : '${Vault.files.length} document \u00B7 ${fmtSize(total)}',
                  style: TextStyle(fontSize: 12, color: cs.onSurfaceVariant),
                ),
              ),
            ),
          Expanded(
            child: q.isNotEmpty
                ? (hits.isEmpty
                    ? const _Empty('Kuch nahi mila', 'Dusre naam se try kijiye')
                    : ListView(
                        children: hits
                            .map((f) => FileTile(
                                  file: f,
                                  folderName: Vault.folders
                                      .firstWhere((x) => x.id == f.folderId,
                                          orElse: () => DocFolder('', ''))
                                      .name,
                                  onChanged: () => setState(() {}),
                                ))
                            .toList(),
                      ))
                : (Vault.folders.isEmpty
                    ? const _Empty('Abhi koi folder nahi',
                        'Neeche se pehla folder banaiye')
                    : ListView.builder(
                        padding: const EdgeInsets.only(bottom: 90),
                        itemCount: Vault.folders.length,
                        itemBuilder: (c, i) {
                          final f = Vault.folders[i];
                          final n = Vault.files
                              .where((x) => x.folderId == f.id)
                              .length;
                          return ListTile(
                            leading: Icon(Icons.folder, color: cs.primary),
                            title: Text(f.name),
                            subtitle: Text('$n document'),
                            trailing: IconButton(
                              icon: const Icon(Icons.more_vert),
                              onPressed: () => _folderMenu(f),
                            ),
                            onTap: () async {
                              await Navigator.push(
                                  context,
                                  MaterialPageRoute(
                                      builder: (_) => FolderScreen(folder: f)));
                              setState(() {});
                            },
                          );
                        },
                      )),
          ),
        ],
      ),
      floatingActionButton: q.isEmpty
          ? FloatingActionButton.extended(
              onPressed: _newFolder,
              icon: const Icon(Icons.create_new_folder_outlined),
              label: const Text('Naya folder'),
            )
          : null,
    );
  }
}

class _Empty extends StatelessWidget {
  final String title;
  final String sub;
  const _Empty(this.title, this.sub);
  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(title, style: const TextStyle(fontSize: 17)),
            const SizedBox(height: 6),
            Text(sub,
                textAlign: TextAlign.center,
                style: TextStyle(color: cs.onSurfaceVariant)),
          ],
        ),
      ),
    );
  }
}

/* ------------------------------------------------------------------ */
/*  Folder screen: upload + file list                                  */
/* ------------------------------------------------------------------ */

class FolderScreen extends StatefulWidget {
  final DocFolder folder;
  const FolderScreen({super.key, required this.folder});
  @override
  State<FolderScreen> createState() => _FolderScreenState();
}

class _FolderScreenState extends State<FolderScreen> {
  bool busy = false;

  /// Naam poochho, phir encrypt karke save karo. true = save hua.
  Future<bool> _askNameAndSave(
      String suggested, String ext, Uint8List bytes, String info) async {
    if (!mounted) return false;
    final ctrl = TextEditingController(text: suggested);
    final newName = await showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (c) => AlertDialog(
        title: const Text('Naam rakhiye'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: ctrl,
              autofocus: true,
              decoration: const InputDecoration(
                  labelText: 'Document ka naam', border: OutlineInputBorder()),
              onSubmitted: (v) => Navigator.pop(c, v),
            ),
            const SizedBox(height: 10),
            Align(
              alignment: Alignment.centerLeft,
              child: Text(info, style: const TextStyle(fontSize: 12)),
            ),
          ],
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(c), child: const Text('Chhod dein')),
          FilledButton(
              onPressed: () => Navigator.pop(c, ctrl.text),
              child: const Text('Save karein')),
        ],
      ),
    );
    if (newName == null || newName.trim().isEmpty) return false;

    setState(() => busy = true);
    try {
      final p = await SharedPreferences.getInstance();
      final wantPublic = p.getBool('publicCopy') ?? true;
      final id = Vault.newId();
      final finalName = newName.trim() + ext;
      await Vault.writeEncrypted(id, bytes);
      Vault.files.add(DocFile(id, widget.folder.id, finalName, bytes.length,
          DateTime.now().millisecondsSinceEpoch));
      await Vault.save();
      if (wantPublic && await PublicCopy.ensurePermission()) {
        await PublicCopy.write(widget.folder.name, finalName, bytes);
      }
      if (mounted) snack(context, 'Save ho gaya');
    } catch (_) {
      if (mounted) snack(context, 'Save nahi hua');
    }
    if (mounted) setState(() => busy = false);
    return true;
  }

  /* ---------------- file se upload ---------------- */

  Future<void> _pickFiles() async {
    final res = await FilePicker.platform.pickFiles(allowMultiple: true);
    if (res == null) return;

    for (int i = 0; i < res.files.length; i++) {
      final picked = res.files[i];
      if (picked.path == null) continue;
      final parts = splitName(picked.name);
      final info = '${parts[1].isEmpty ? 'file' : parts[1]} \u00B7 '
          '${fmtSize(picked.size)}'
          '${res.files.length > 1 ? ' \u00B7 ${i + 1}/${res.files.length}' : ''}';
      final bytes = await File(picked.path!).readAsBytes();
      await _askNameAndSave(parts[0], parts[1], bytes, info);
    }
  }

  /* ---------------- camera se scan ---------------- */

  Future<void> _scan() async {
    List<String> pages = [];

    // Pehle asli scanner — kinare apne aap detect hote hain.
    try {
      final r = await CunningDocumentScanner.getPictures();
      if (r != null) pages = r;
    } catch (_) {
      pages = [];
    }

    // Agar scanner na chale to seedha camera.
    if (pages.isEmpty) {
      try {
        final x = await ImagePicker()
            .pickImage(source: ImageSource.camera, imageQuality: 85);
        if (x != null) pages = [x.path];
      } catch (_) {}
    }
    if (pages.isEmpty) return;

    setState(() => busy = true);
    Uint8List bytes;
    try {
      final doc = pw.Document();
      for (final path in pages) {
        final img = pw.MemoryImage(await File(path).readAsBytes());
        doc.addPage(
          pw.Page(
            build: (c) =>
                pw.Center(child: pw.Image(img, fit: pw.BoxFit.contain)),
          ),
        );
      }
      bytes = Uint8List.fromList(await doc.save());
    } catch (_) {
      if (mounted) {
        setState(() => busy = false);
        snack(context, 'Scan PDF nahi ban paya');
      }
      return;
    }
    if (mounted) setState(() => busy = false);

    final now = DateTime.now();
    final suggested = 'Scan ${fmtDate(now.millisecondsSinceEpoch)}';
    final info = '${pages.length} page \u00B7 PDF \u00B7 ${fmtSize(bytes.length)}';
    await _askNameAndSave(suggested, '.pdf', bytes, info);
  }

  /* ---------------- add menu ---------------- */

  Future<void> _addMenu() async {
    final a = await showModalBottomSheet<String>(
      context: context,
      builder: (c) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const ListTile(title: Text('Document add karein')),
            const Divider(height: 1),
            ListTile(
              leading: const Icon(Icons.document_scanner_outlined),
              title: const Text('Camera se scan karein'),
              subtitle: const Text('Kaagaz ki photo, kinare apne aap kategi'),
              onTap: () => Navigator.pop(c, 'scan'),
            ),
            ListTile(
              leading: const Icon(Icons.attach_file),
              title: const Text('Phone se file chunein'),
              subtitle: const Text('PDF, photo, jo bhi ho'),
              onTap: () => Navigator.pop(c, 'file'),
            ),
          ],
        ),
      ),
    );
    if (a == 'scan') await _scan();
    if (a == 'file') await _pickFiles();
  }

  @override
  Widget build(BuildContext context) {
    final files = Vault.files
        .where((f) => f.folderId == widget.folder.id)
        .toList()
      ..sort((a, b) => b.created.compareTo(a.created));

    return Scaffold(
      appBar: AppBar(title: Text(widget.folder.name)),
      body: Stack(
        children: [
          files.isEmpty
              ? const _Empty('Ye folder khaali hai',
                  'Neeche wale button se scan kijiye ya file chuniye')
              : ListView(
                  padding: const EdgeInsets.only(bottom: 90),
                  children: files
                      .map((f) => FileTile(
                            file: f,
                            folderName: widget.folder.name,
                            onChanged: () => setState(() {}),
                          ))
                      .toList(),
                ),
          if (busy)
            const Positioned(
                left: 0, right: 0, top: 0, child: LinearProgressIndicator()),
        ],
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: busy ? null : _addMenu,
        icon: const Icon(Icons.add),
        label: const Text('Document add karein'),
      ),
    );
  }
}

/* ------------------------------------------------------------------ */
/*  File tile + actions                                                */
/* ------------------------------------------------------------------ */

class FileTile extends StatelessWidget {
  final DocFile file;
  final String folderName;
  final VoidCallback onChanged;
  const FileTile(
      {super.key,
      required this.file,
      required this.folderName,
      required this.onChanged});

  String get _ext {
    final e = splitName(file.name)[1].replaceAll('.', '').toUpperCase();
    return e.isEmpty ? 'FILE' : (e.length > 4 ? e.substring(0, 4) : e);
  }

  Future<void> _open(BuildContext context) async {
    try {
      final bytes = await Vault.readDecrypted(file.id);
      final tmp = await getTemporaryDirectory();
      final f = File('${tmp.path}/${file.name}');
      await f.writeAsBytes(bytes);
      await OpenFilex.open(f.path);
    } catch (_) {
      if (context.mounted) snack(context, 'File khul nahi payi');
    }
  }

  Future<void> _menu(BuildContext context) async {
    final a = await showModalBottomSheet<String>(
      context: context,
      builder: (c) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
                title: Text(file.name),
                subtitle:
                    Text('${fmtSize(file.size)} \u00B7 ${fmtDate(file.created)}')),
            const Divider(height: 1),
            ListTile(
                leading: const Icon(Icons.open_in_new),
                title: const Text('Kholein'),
                onTap: () => Navigator.pop(c, 'open')),
            ListTile(
                leading: const Icon(Icons.drive_file_rename_outline),
                title: const Text('Naam badlein'),
                onTap: () => Navigator.pop(c, 'rename')),
            ListTile(
                leading: const Icon(Icons.drive_file_move_outline),
                title: const Text('Dusre folder me le jaayein'),
                onTap: () => Navigator.pop(c, 'move')),
            ListTile(
                leading: const Icon(Icons.save_alt),
                title: const Text('Phone folder me copy karein'),
                onTap: () => Navigator.pop(c, 'export')),
            ListTile(
                leading: const Icon(Icons.delete_outline),
                title: const Text('Delete karein'),
                onTap: () => Navigator.pop(c, 'delete')),
          ],
        ),
      ),
    );
    if (!context.mounted || a == null) return;

    if (a == 'open') {
      await _open(context);
    } else if (a == 'rename') {
      final parts = splitName(file.name);
      final ctrl = TextEditingController(text: parts[0]);
      final n = await showDialog<String>(
        context: context,
        builder: (c) => AlertDialog(
          title: const Text('Naam badlein'),
          content: TextField(controller: ctrl, autofocus: true),
          actions: [
            TextButton(
                onPressed: () => Navigator.pop(c),
                child: const Text('Rehne dein')),
            FilledButton(
                onPressed: () => Navigator.pop(c, ctrl.text),
                child: const Text('Badlein')),
          ],
        ),
      );
      if (n != null && n.trim().isNotEmpty) {
        await PublicCopy.remove(folderName, file.name);
        file.name = n.trim() + parts[1];
        await Vault.save();
        onChanged();
      }
    } else if (a == 'move') {
      final others =
          Vault.folders.where((x) => x.id != file.folderId).toList();
      if (others.isEmpty) {
        if (context.mounted) snack(context, 'Aur koi folder nahi hai');
        return;
      }
      final t = await showModalBottomSheet<DocFolder>(
        context: context,
        builder: (c) => SafeArea(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const ListTile(title: Text('Kahan le jaana hai?')),
              const Divider(height: 1),
              ...others.map((o) => ListTile(
                  leading: const Icon(Icons.folder_outlined),
                  title: Text(o.name),
                  onTap: () => Navigator.pop(c, o))),
            ],
          ),
        ),
      );
      if (t != null) {
        await PublicCopy.remove(folderName, file.name);
        file.folderId = t.id;
        await Vault.save();
        onChanged();
      }
    } else if (a == 'export') {
      if (!await PublicCopy.ensurePermission()) {
        if (context.mounted) {
          snack(context, 'Storage permission chahiye');
        }
        return;
      }
      final bytes = await Vault.readDecrypted(file.id);
      final path = await PublicCopy.write(folderName, file.name, bytes);
      if (context.mounted) {
        snack(context,
            path != null ? 'Documents Manager folder me copy ho gaya' : 'Copy nahi hua');
      }
    } else if (a == 'delete') {
      final ok = await _confirm(context, 'Ye document delete karein?',
          '${file.name} hamesha ke liye hat jayega.');
      if (ok != true) return;
      await Vault.removeBlob(file.id);
      await PublicCopy.remove(folderName, file.name);
      Vault.files.remove(file);
      await Vault.save();
      onChanged();
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return ListTile(
      leading: Container(
        width: 40,
        height: 46,
        alignment: Alignment.center,
        decoration: BoxDecoration(
          color: cs.surfaceContainerHighest,
          borderRadius: BorderRadius.circular(5),
        ),
        child: Text(_ext,
            style: TextStyle(
                fontSize: 10, fontWeight: FontWeight.w600, color: cs.primary)),
      ),
      title: Text(file.name, maxLines: 1, overflow: TextOverflow.ellipsis),
      subtitle: Text('${fmtSize(file.size)} \u00B7 ${fmtDate(file.created)}'),
      trailing: IconButton(
          icon: const Icon(Icons.more_vert), onPressed: () => _menu(context)),
      onTap: () => _open(context),
    );
  }
}

Future<bool?> _confirm(BuildContext c, String title, String body) {
  return showDialog<bool>(
    context: c,
    builder: (d) => AlertDialog(
      title: Text(title),
      content: Text(body),
      actions: [
        TextButton(
            onPressed: () => Navigator.pop(d, false),
            child: const Text('Rehne dein')),
        FilledButton(
            onPressed: () => Navigator.pop(d, true),
            child: const Text('Delete karein')),
      ],
    ),
  );
}

/* ------------------------------------------------------------------ */
/*  Settings                                                           */
/* ------------------------------------------------------------------ */

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});
  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  bool publicCopy = true;
  bool bio = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final p = await SharedPreferences.getInstance();
    setState(() {
      publicCopy = p.getBool('publicCopy') ?? true;
      bio = p.getString('bioPin') != null;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: ListView(
        children: [
          SwitchListTile(
            value: publicCopy,
            title: const Text('Phone folder me copy rakhein'),
            subtitle: const Text(
                'Har upload ki ek copy "Documents Manager" folder me bhi jayegi. '
                'Ye copy lock ke bahar hoti hai — koi bhi app dekh sakti hai.'),
            onChanged: (v) async {
              final p = await SharedPreferences.getInstance();
              await p.setBool('publicCopy', v);
              setState(() => publicCopy = v);
            },
          ),
          const Divider(height: 1),
          SwitchListTile(
            value: bio,
            title: const Text('Fingerprint se kholein'),
            subtitle: const Text('PIN ke saath fingerprint bhi chalega'),
            onChanged: (v) async {
              final p = await SharedPreferences.getInstance();
              if (!v) {
                await p.remove('bioPin');
                setState(() => bio = false);
                return;
              }
              final ctrl = TextEditingController();
              final pin = await showDialog<String>(
                context: context,
                builder: (c) => AlertDialog(
                  title: const Text('Apna PIN confirm kijiye'),
                  content: TextField(
                    controller: ctrl,
                    autofocus: true,
                    obscureText: true,
                    keyboardType: TextInputType.number,
                  ),
                  actions: [
                    TextButton(
                        onPressed: () => Navigator.pop(c),
                        child: const Text('Rehne dein')),
                    FilledButton(
                        onPressed: () => Navigator.pop(c, ctrl.text),
                        child: const Text('Confirm')),
                  ],
                ),
              );
              if (pin == null) return;
              final salt = p.getString('salt')!;
              final check = p.getString('check')!;
              if (sha256.convert(utf8.encode('$pin|$salt|check')).toString() !=
                  check) {
                if (context.mounted) snack(context, 'Galat PIN');
                return;
              }
              await p.setString('bioPin', pin);
              setState(() => bio = true);
            },
          ),
          const Divider(height: 1),
          const ListTile(
            title: Text('Kaise surakshit hai'),
            subtitle: Text(
                'Har file AES-256 se encrypt hoti hai aur chaabi aapke PIN se banti hai. '
                'Koi server nahi, koi internet nahi — sab kuch is phone me. '
                'PIN bhool gaye to documents wapas nahi milenge.'),
          ),
          const Divider(height: 1),
          const ListTile(
            title: Text('Phone folder ka rasta'),
            subtitle: Text('Internal storage \u203A Documents Manager'),
          ),
        ],
      ),
    );
  }
}
