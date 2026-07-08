package com.angelrobotics.device_verifier

import android.content.Context
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket

/**
 * 후킹(Frida/Xposed/LSPosed) 활성 환경 로컬 탐지기 (정의서 8.5).
 *
 * - **외부 통신 없음**: 병원 폐쇄망 전제. 기기 내부(`/proc`, 클래스로더, 로컬 소켓, PackageManager)
 *   신호만으로 판정한다. RASP/텔레메트리 미사용.
 * - 탐지 로직을 네이티브(Kotlin)에 두는 이유: Dart 코드는 Frida 로 후킹되기 쉽다.
 * - 판정은 하지 않고 **걸린 신호를 강/약으로 분류해 그대로 반환**한다(가중 판정·감사 로그는 Dart 측).
 *   - 강신호(strong): 사실상 오탐이 없는 결정적 증거 → Dart 가 즉시 차단.
 *   - 약신호(weak): 단독으로는 오탐 여지 → Dart 가 합산(2개 이상)했을 때만 차단.
 *
 * best-effort 한계: Frida 가 이 탐지 코드 자체를 후킹할 수 있다. 로봇 측 인증(7.3)·통신 암호화와
 * 다층 방어로 보완한다(정의서 잔여 위험).
 */
object SecurityDetector {

    /** 탐지 결과: 강신호/약신호 코드 목록(비식별 문자열). */
    data class Result(val strong: List<String>, val weak: List<String>)

    fun detectHooks(context: Context): Result {
        val strong = mutableSetOf<String>()
        val weak = mutableSetOf<String>()

        detectFridaMaps(strong)
        detectFridaThreads(strong, weak)
        detectFridaPorts(weak)
        detectFridaTempFiles(weak)
        detectXposedBridgeClass(strong)
        detectXposedMaps(strong)
        detectXposedStackTrace(strong)
        detectXposedPackages(context, weak)

        return Result(strong.toList(), weak.toList())
    }

    // ──────────────────────────── Frida ────────────────────────────

    /** `/proc/self/maps` 에 매핑된 frida 라이브러리 흔적 (강신호). */
    private fun detectFridaMaps(strong: MutableSet<String>) {
        try {
            val maps = File("/proc/self/maps").readText().lowercase()
            val tokens = listOf("frida", "frida-agent", "frida-gadget", "gum-js-loop", "libgadget")
            if (tokens.any { maps.contains(it) }) strong.add("frida_maps")
        } catch (_: Throwable) {
            // /proc 접근 불가는 신호로 치지 않는다(정상 기기에서도 정책상 막힐 수 있음).
        }
    }

    /**
     * `/proc/self/task/<tid>/comm` 의 스레드명 흔적.
     * - `gum-js-loop`: frida-gum 전용 → 강신호.
     * - `gmain`/`gdbus`: frida 기본 스레드지만 정상 glib 환경 여지 → 약신호.
     */
    private fun detectFridaThreads(strong: MutableSet<String>, weak: MutableSet<String>) {
        try {
            val taskDir = File("/proc/self/task")
            val comms = taskDir.listFiles()?.mapNotNull { tid ->
                try {
                    File(tid, "comm").readText().trim()
                } catch (_: Throwable) {
                    null
                }
            } ?: emptyList()
            if (comms.any { it == "gum-js-loop" }) strong.add("frida_thread_gumjs")
            if (comms.any { it == "gmain" || it == "gdbus" }) weak.add("frida_thread_glib")
        } catch (_: Throwable) {
        }
    }

    /** frida-server 기본 포트(27042/27043) 로컬 연결 가능 여부 (약신호). */
    private fun detectFridaPorts(weak: MutableSet<String>) {
        for (port in intArrayOf(27042, 27043)) {
            var socket: Socket? = null
            try {
                socket = Socket()
                socket.connect(InetSocketAddress("127.0.0.1", port), 120)
                if (socket.isConnected) {
                    weak.add("frida_port")
                    return
                }
            } catch (_: Throwable) {
                // 연결 실패 = 정상.
            } finally {
                try {
                    socket?.close()
                } catch (_: Throwable) {
                }
            }
        }
    }

    /** frida-server 가 흔히 떨어뜨리는 임시 파일 (약신호). */
    private fun detectFridaTempFiles(weak: MutableSet<String>) {
        val paths = listOf(
            "/data/local/tmp/re.frida.server",
            "/data/local/tmp/frida-server",
            "/data/local/tmp/frida",
        )
        try {
            if (paths.any { File(it).exists() }) weak.add("frida_tmpfile")
        } catch (_: Throwable) {
        }
    }

    // ──────────────────────────── Xposed / LSPosed ────────────────────────────

    /** XposedBridge 클래스 로드 가능 여부 — 후킹 프레임워크 주입의 결정적 증거 (강신호). */
    private fun detectXposedBridgeClass(strong: MutableSet<String>) {
        try {
            Class.forName("de.robv.android.xposed.XposedBridge")
            strong.add("xposed_bridge_class")
        } catch (_: ClassNotFoundException) {
            // 정상.
        } catch (_: Throwable) {
        }
    }

    /** `/proc/self/maps` 에 매핑된 Xposed 계열 모듈 흔적 (강신호). */
    private fun detectXposedMaps(strong: MutableSet<String>) {
        try {
            val maps = File("/proc/self/maps").readText().lowercase()
            val tokens = listOf("xposed", "lsposed", "riru", "zygisk", "edxp", "substrate")
            if (tokens.any { maps.contains(it) }) strong.add("xposed_maps")
        } catch (_: Throwable) {
        }
    }

    /** 현재 콜스택에 주입된 Xposed/LSPosed 프레임 흔적 (강신호). */
    private fun detectXposedStackTrace(strong: MutableSet<String>) {
        try {
            val frames = Throwable().stackTrace
            val hit = frames.any {
                val n = it.className.lowercase()
                n.contains("de.robv.android.xposed") || n.contains("xposed") || n.contains("lsposed")
            }
            if (hit) strong.add("xposed_stacktrace")
        } catch (_: Throwable) {
        }
    }

    /**
     * Xposed/LSPosed 관리자 앱 설치 여부 (약신호).
     * Android 11+ 패키지 가시성 제한으로 설치돼 있어도 안 잡힐 수 있어 약신호로만 취급한다.
     */
    private fun detectXposedPackages(context: Context, weak: MutableSet<String>) {
        val packages = listOf(
            "de.robv.android.xposed.installer",
            "org.lsposed.manager",
            "io.github.lsposed.manager",
            "io.github.libxposed.api",
            "me.weishu.exp",
            "org.meowcat.edxposed.manager",
        )
        val pm = context.packageManager
        for (pkg in packages) {
            try {
                pm.getPackageInfo(pkg, 0)
                weak.add("xposed_package")
                return
            } catch (_: Throwable) {
                // 미설치 = 정상.
            }
        }
    }
}
