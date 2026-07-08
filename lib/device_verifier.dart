/// device_verifier — 후킹(Frida/Xposed)·루팅/탈옥·에뮬레이터 로컬 탐지 공유 플러그인.
///
/// pro_app_flutter / M20(angellegs) 공용. **탐지 + 가중 판정까지만** 제공하고,
/// 차단 다이얼로그·감사 로그·i18n·앱 종료·체크포인트/스로틀·fail-closed 정책 등
/// enforcement 는 각 앱이 담당한다(플러그인에 앱 의존성을 끌어오지 않기 위함).
///
/// ```dart
/// final guard = DeviceVerifier();
/// final verdict = await guard.scanHooks();   // 후킹 가중 판정
/// final rooted = await guard.isRooted();      // 루팅/탈옥 (raw)
/// final emulator = await guard.isEmulator();  // 에뮬레이터 (raw)
/// final tabletOk = guard.isFormFactorSupported(shortestSideDp); // 태블릿 게이트(설정형)
/// ```
library;

import 'src/hook_detector.dart';
import 'src/hook_signals.dart';
import 'src/hook_verdict.dart';
import 'src/root_detector.dart';

export 'src/hook_signals.dart';
export 'src/hook_verdict.dart';

/// 후킹·루팅·에뮬레이터·태블릿 폼팩터 검증 진입점. 탐지·판정만 수행(raw), enforcement 는 앱 책임.
class DeviceVerifier {
  /// [channel] 로 네이티브 채널명을 주입할 수 있다(기본 [HookDetector.defaultChannel]).
  ///
  /// [requireTablet] — 태블릿(폼팩터) 게이트 on/off. 앱별 설정(예: pro=true, M20=false).
  /// [minTabletShortestSideDp] — 태블릿 판정 임계(최단변 dp, 기본 600 = sw600dp).
  DeviceVerifier({
    String? channel,
    this.requireTablet = false,
    this.minTabletShortestSideDp = 600,
  }) : _detector = HookDetector(channel: channel);

  final HookDetector _detector;

  /// 태블릿 폼팩터 게이트 사용 여부(앱별 설정).
  final bool requireTablet;

  /// 태블릿 판정 임계값(화면 최단변 논리 dp).
  final double minTabletShortestSideDp;

  /// 네이티브 후킹 신호(강/약)를 수집한다.
  ///
  /// 채널 오류 시 예외를 던진다 → 앱이 [HookVerdict.failClosed] 로 fail-closed 처리.
  Future<HookSignals> detectHooks() => _detector.detect();

  /// 후킹 가중 판정(강신호 1개 이상 OR 약신호 2개 이상 → blocked)까지 한 번에 수행하는 편의 API.
  Future<HookVerdict> scanHooks() async =>
      HookVerdict.fromSignals(await _detector.detect());

  /// 루팅/탈옥 여부(raw). fail-closed 는 앱이 결정.
  Future<bool> isRooted() => RootDetector.isRooted();

  /// 에뮬레이터 여부(raw). release-mode 게이트는 앱이 결정.
  Future<bool> isEmulator() => RootDetector.isEmulator();

  /// 폼팩터(태블릿) 게이트 통과 여부.
  ///
  /// [requireTablet]=false 면 항상 `true`(게이트 off — 예: M20).
  /// true 면 [shortestSideDp]가 [minTabletShortestSideDp] 이상일 때만 `true`(예: pro).
  /// 앱은 `MediaQuery.of(context).size.shortestSide` 를 넘겨 호출(값만 받는 순수 판정).
  bool isFormFactorSupported(double shortestSideDp) =>
      !requireTablet || shortestSideDp >= minTabletShortestSideDp;
}
