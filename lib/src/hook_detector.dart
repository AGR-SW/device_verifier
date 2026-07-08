import 'package:flutter/services.dart';

import 'hook_signals.dart';

/// 네이티브(Kotlin/Swift) 후킹 탐지기를 감싸는 Dart 래퍼.
///
/// 채널: 기본 [defaultChannel], 메서드 `detectHooks`.
/// - 탐지 로직 자체는 네이티브에 있다(Dart 는 Frida 로 후킹되기 쉽다).
/// - 채널 오류는 여기서 삼키지 않고 던진다 → 상위(앱 SecurityGuard)에서 fail-closed 처리.
class HookDetector {
  HookDetector({String? channel})
      : _channel = MethodChannel(channel ?? defaultChannel);

  /// 앱 패키지에 종속되지 않는 중립 채널명(네이티브 플러그인과 일치).
  static const String defaultChannel = 'angelrobotics/device_verifier';

  final MethodChannel _channel;

  /// 네이티브에서 후킹 신호를 수집해 반환한다.
  ///
  /// 채널 오류 시 [PlatformException] / [MissingPluginException] 등을 그대로 던진다.
  Future<HookSignals> detect() async {
    final result = await _channel.invokeMapMethod<String, dynamic>('detectHooks');
    if (result == null) {
      // 네이티브가 null 을 돌려주면 신뢰할 수 없는 응답 → 오류로 승격(fail-closed 유도).
      throw PlatformException(code: 'NULL_RESULT', message: 'detectHooks returned null');
    }
    return HookSignals(
      strong: _stringList(result['strong']),
      weak: _stringList(result['weak']),
    );
  }

  static List<String> _stringList(dynamic raw) {
    if (raw is List) {
      return raw.map((e) => e.toString()).toList(growable: false);
    }
    return const [];
  }
}
