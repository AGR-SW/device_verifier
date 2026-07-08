# device_verifier

후킹(Frida/Xposed)·루팅/탈옥·에뮬레이터·태블릿 폼팩터를 **로컬에서 검증**하는 공유 Flutter 플러그인.
`pro_app_flutter` / `M20(angellegs)` 공용.

- **탐지·판정만** 제공한다. 차단 화면·감사 로그·i18n·앱 종료·fail-closed 정책 등 enforcement 는 소비 앱이 담당한다.
- 후킹 탐지 로직은 네이티브(Kotlin/Swift)에 둔다(Dart 는 Frida 로 후킹되기 쉬움).
- 외부 통신 없음(병원 폐쇄망 전제) — 기기 내부 신호만 사용.

## API
```dart
final v = DeviceVerifier(requireTablet: true); // 태블릿 게이트 앱별 토글(기본 false)

final verdict = await v.scanHooks();            // 후킹 가중 판정 (강1 또는 약2 → blocked)
final rooted  = await v.isRooted();             // 루팅/탈옥 (raw)
final emu     = await v.isEmulator();           // 에뮬레이터 (raw)
final okSize  = v.isFormFactorSupported(dp);    // 태블릿 폼팩터 (MediaQuery shortestSide dp)
```
