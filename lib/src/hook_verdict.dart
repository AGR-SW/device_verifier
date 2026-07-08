import 'hook_signals.dart';

/// 후킹(Frida/Xposed) 가중 판정 결과 ("복수 신호 가중 판정").
///
/// - [blocked]: 차단 판정. 강신호 1개 이상 OR 약신호 2개 이상 OR 채널 오류(fail-closed).
/// - [detected]: 약신호라도 감지됨 (차단되지 않아도 감사 로그 대상).
/// - [signals]: 걸린 신호 코드(비식별 문자열) — 오탐 분석/감사 로그용.
///
/// NOTE: 판정만 제공한다. 차단 다이얼로그·감사 로그·i18n·앱 종료 등 enforcement 는
/// 소비 앱이 담당한다(플러그인은 탐지+판정까지).
class HookVerdict {
  const HookVerdict({required this.blocked, required this.detected, required this.signals});

  /// 네이티브 신호를 가중 판정한다.
  ///
  /// 강신호 1개 이상 OR 약신호 2개 이상 → 차단. 단일 약신호로는 차단하지 않는다(오탐 억제).
  factory HookVerdict.fromSignals(HookSignals signals) {
    final blocked = signals.strong.isNotEmpty || signals.weak.length >= 2;
    return HookVerdict(blocked: blocked, detected: !signals.isEmpty, signals: signals.all);
  }

  /// 채널 오류 등 검사 불가 시 fail-closed 차단 판정(앱의 루팅 검사 정책과 일관되게 쓰도록 제공).
  const HookVerdict.failClosed()
      : blocked = true,
        detected = true,
        signals = const ['channel_error'];

  final bool blocked;
  final bool detected;
  final List<String> signals;
}
