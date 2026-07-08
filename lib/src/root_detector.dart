import 'package:safe_device/safe_device.dart';

/// 루팅/탈옥·에뮬레이터 로컬 탐지 (safe_device 래핑).
///
/// **raw 반환** — 예외를 삼키거나 fail-closed 하지 않는다. 예외 시 차단으로 간주하는
/// fail-closed 정책과 release-mode 게이트(개발 편의)는 소비 앱이 결정한다(정책 이중화 방지).
class RootDetector {
  RootDetector._();

  /// 루팅/탈옥 여부. (`safe_device.isJailBroken`)
  static Future<bool> isRooted() => SafeDevice.isJailBroken;

  /// 에뮬레이터 여부. (`safe_device.isRealDevice` 반전)
  static Future<bool> isEmulator() async => !(await SafeDevice.isRealDevice);
}
