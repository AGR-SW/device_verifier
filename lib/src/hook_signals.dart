/// 네이티브 후킹 탐지 채널의 원시 결과 (강/약 신호 코드 목록).
class HookSignals {
  const HookSignals({required this.strong, required this.weak});

  /// 사실상 오탐이 없는 결정적 신호(예: `frida_maps`, `xposed_bridge_class`, `frida_dylib`).
  final List<String> strong;

  /// 단독으로는 오탐 여지가 있는 신호(예: `frida_port`, `xposed_package`, `dyld_insert`).
  final List<String> weak;

  /// 강신호 + 약신호 전체(감사 로그용).
  List<String> get all => [...strong, ...weak];

  bool get isEmpty => strong.isEmpty && weak.isEmpty;
}
