import Flutter
import UIKit

/// device_verifier: 후킹(Frida/Substrate 등) 로컬 탐지 플러그인.
///
/// 탐지 로직은 `SecurityDetector`(네이티브)에 둔다. 이 플러그인은 채널을 등록하고
/// 강/약 신호를 그대로 Dart 로 반환할 뿐, 판정·차단·감사 로그는 하지 않는다(앱 책임).
public class DeviceVerifierPlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
    // 앱 패키지에 종속되지 않는 중립 채널명(pro/M20 공용).
    let channel = FlutterMethodChannel(name: "angelrobotics/device_verifier", binaryMessenger: registrar.messenger())
    let instance = DeviceVerifierPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "detectHooks":
      // dylib 열거·소켓 접근이 포함되므로 메인 스레드를 막지 않도록 백그라운드 수행 후 메인 회신.
      DispatchQueue.global(qos: .userInitiated).async {
        let payload = SecurityDetector.detectHooks()
        DispatchQueue.main.async { result(payload) }
      }
    default:
      result(FlutterMethodNotImplemented)
    }
  }
}
