import 'package:flutter/material.dart';
import 'package:device_verifier/device_verifier.dart';

void main() => runApp(const MyApp());

/// device_verifier 단독 검증용 예제.
///
/// 실기(루팅 기기 + frida)에서 '보안 검사 실행'을 누르면 후킹 신호/판정, 루팅, 에뮬레이터
/// 결과를 그대로 표시한다. 앱 통합 전 플러그인 자체를 검증하는 용도(enforcement 없음).
class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  final DeviceVerifier _guard = DeviceVerifier();
  String _result = '아래 "보안 검사 실행" 을 눌러 결과를 확인하세요.';

  Future<void> _scan() async {
    final buf = StringBuffer();
    try {
      final v = await _guard.scanHooks();
      buf.writeln('[후킹] blocked=${v.blocked}  detected=${v.detected}');
      buf.writeln('signals: ${v.signals.isEmpty ? "(없음)" : v.signals.join(", ")}');
    } catch (e) {
      // 채널 오류 시 앱은 fail-closed 처리해야 함(여기선 표시만).
      buf.writeln('[후킹] 검사 오류(앱은 fail-closed): $e');
    }
    try {
      buf.writeln('[루팅] ${await _guard.isRooted()}');
      buf.writeln('[에뮬레이터] ${await _guard.isEmulator()}');
    } catch (e) {
      buf.writeln('[루팅/에뮬] 오류: $e');
    }
    if (mounted) setState(() => _result = buf.toString());
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text('device_verifier example')),
        body: Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Text(_result, textAlign: TextAlign.center),
                const SizedBox(height: 24),
                ElevatedButton(
                  onPressed: _scan,
                  child: const Text('보안 검사 실행'),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
