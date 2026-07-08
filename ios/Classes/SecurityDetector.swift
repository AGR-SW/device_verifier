import Foundation
import MachO

/// 후킹(Frida)·탈옥 후킹툴(Substrate 등) 활성 환경 로컬 탐지기 (정의서 8.5).
///
/// - **외부 통신 없음**: 병원 폐쇄망 전제. 로드된 dylib 목록·환경변수·로컬 소켓 등
///   기기 내부 신호만으로 판정한다. RASP/텔레메트리 미사용.
/// - 탈옥 자체(Cydia 등)는 Dart 측 `safe_device.isJailBroken` 이 이미 커버하므로,
///   여기서는 **후킹 프레임워크 주입 신호**에 집중한다.
/// - 판정은 하지 않고 강/약 신호 코드만 반환한다(가중 판정·감사 로그는 Dart 측).
enum SecurityDetector {

    /// 강신호/약신호 코드 목록을 담은 페이로드 반환.
    static func detectHooks() -> [String: [String]] {
        var strong = Set<String>()
        var weak = Set<String>()

        detectSuspiciousDylibs(&strong)
        detectDyldInsert(&weak)
        detectFridaPort(&weak)

        return ["strong": Array(strong), "weak": Array(weak)]
    }

    /// 로드된 이미지(dylib) 이름에 후킹 프레임워크 흔적이 있는지 (강신호).
    private static func detectSuspiciousDylibs(_ strong: inout Set<String>) {
        let count = _dyld_image_count()
        for i in 0..<count {
            guard let cName = _dyld_get_image_name(i) else { continue }
            let name = String(cString: cName).lowercased()
            if name.contains("frida") || name.contains("gadget") {
                strong.insert("frida_dylib")
            }
            if name.contains("substrate") || name.contains("substitute") || name.contains("libhooker") {
                strong.insert("substrate_dylib")
            }
            if name.contains("cycript") || name.contains("cynject") {
                strong.insert("cycript_dylib")
            }
        }
    }

    /// `DYLD_INSERT_LIBRARIES` 주입 여부 (약신호).
    private static func detectDyldInsert(_ weak: inout Set<String>) {
        if let v = getenv("DYLD_INSERT_LIBRARIES"), String(cString: v).isEmpty == false {
            weak.insert("dyld_insert")
        }
    }

    /// frida-server 기본 포트(27042/27043) 로컬 연결 가능 여부 (약신호).
    private static func detectFridaPort(_ weak: inout Set<String>) {
        for port: UInt16 in [27042, 27043] {
            if canConnectLocalhost(port: port) {
                weak.insert("frida_port")
                return
            }
        }
    }

    private static func canConnectLocalhost(port: UInt16) -> Bool {
        let sock = socket(AF_INET, SOCK_STREAM, 0)
        if sock < 0 { return false }
        defer { close(sock) }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")

        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return result == 0
    }
}
