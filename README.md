# device_verifier

기기 신뢰성(**후킹 · 루팅/탈옥 · 에뮬레이터 · 태블릿 폼팩터**)을 **기기 내부에서 로컬 검증**하는 공유 Flutter 플러그인.
`pro_app_flutter` / `M20(angellegs)` 공용.

## 무엇을 하나
- 위 4가지를 **탐지하고 판정(raw / 가중)까지만** 제공한다.
- 차단 화면 · 감사 로그 · i18n · 앱 종료 · 체크포인트/스로틀 · fail-closed 정책 등 **enforcement 는 소비 앱**이 담당한다(플러그인에 앱 의존성을 끌어오지 않기 위함).
- **외부 통신 없음** — 병원 폐쇄망 전제. `/proc` · 로드된 라이브러리 · 로컬 소켓 · PackageManager 등 **기기 내부 신호만** 사용(RASP/텔레메트리 미사용).
- 후킹 탐지는 **네이티브(Kotlin/Swift)** 에 둔다 — Dart 코드는 Frida 로 후킹되기 쉬우므로.

## 무엇을 탐지하나

### 1. 후킹 (Frida / Xposed / LSPosed / Substrate) — 네이티브
걸린 신호를 **강(strong) / 약(weak)** 으로 분류해 반환하고, `HookVerdict` 가 가중 판정한다.
**강신호 1개 이상 OR 약신호 2개 이상 → `blocked`** (단일 약신호는 오탐 억제로 미차단).

**Android** — 강신호

| 코드 | 근거 |
|---|---|
| `frida_maps` | `/proc/self/maps` 의 frida / gum-js-loop / libgadget 매핑 |
| `frida_thread_gumjs` | `/proc/self/task/*/comm` 의 `gum-js-loop` 스레드 |
| `xposed_bridge_class` | `de.robv.android.xposed.XposedBridge` 클래스 로드 가능 |
| `xposed_maps` | maps 의 xposed / lsposed / riru / zygisk / edxp / substrate |
| `xposed_stacktrace` | 현재 콜스택에 주입된 Xposed / LSPosed 프레임 |

**Android** — 약신호

| 코드 | 근거 |
|---|---|
| `frida_thread_glib` | `gmain` / `gdbus` 스레드 (정상 glib 여지) |
| `frida_port` | frida-server 기본 포트(27042/27043) 로컬 연결 가능 |
| `frida_tmpfile` | `/data/local/tmp/` 의 frida-server 잔존 파일 |
| `xposed_package` | Xposed / LSPosed 관리자 앱 설치 (Android 11+ 가시성 제한으로 약신호) |

**iOS**

- 강신호: `frida_dylib`(frida/gadget) · `substrate_dylib`(substrate/substitute/libhooker) · `cycript_dylib`(cycript/cynject) — 로드된 dylib 이름 흔적
- 약신호: `dyld_insert`(`DYLD_INSERT_LIBRARIES` 주입) · `frida_port`(27042/27043 로컬 연결)

> 채널 오류 등 검사 불가 시 `HookVerdict.failClosed()`(신호 `channel_error`, `blocked=true`)로 앱이 fail-closed 처리.

### 2. 루팅 / 탈옥
`safe_device.isJailBroken` — **raw** 반환(fail-closed 여부는 앱이 결정).

### 3. 에뮬레이터
`safe_device.isRealDevice` 반전 — **raw** 반환(release-mode 게이트는 앱이 결정).

### 4. 태블릿 폼팩터 (앱별 토글)
`isFormFactorSupported(shortestSideDp)` — 화면 최단변 논리 dp 가 임계(기본 600 = `sw600dp`) 이상인지.
`requireTablet=false` 면 게이트 off(항상 통과, 예: M20), `true` 면 태블릿만 통과(예: pro). 외부 신호 없이 값만 받아 판정하는 순수 함수.

## API
```dart
final v = DeviceVerifier(requireTablet: true); // 태블릿 게이트 앱별 토글(기본 false)

final verdict = await v.scanHooks();     // 후킹 가중 판정 (강1 또는 약2 → blocked)
final signals = await v.detectHooks();   // 후킹 원시 신호(강/약)만
final rooted  = await v.isRooted();      // 루팅/탈옥 (raw)
final emu     = await v.isEmulator();    // 에뮬레이터 (raw)
final okSize  = v.isFormFactorSupported(dp); // 태블릿 폼팩터 (MediaQuery shortestSide dp)
```

## 소비 (git 의존성)
```yaml
dependencies:
  device_verifier:
    git:
      url: https://github.com/AGR-SW/device_verifier.git
      ref: v0.1.0
```
