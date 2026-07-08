package com.angelrobotics.device_verifier

import android.content.Context
import android.os.Handler
import android.os.Looper
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result

/**
 * device_verifier: 후킹(Frida/Xposed/LSPosed) 로컬 탐지 플러그인.
 *
 * 탐지 로직 자체는 [SecurityDetector](네이티브)에 둔다(Dart 는 Frida 로 후킹되기 쉬움).
 * 이 플러그인은 채널을 등록하고 네이티브 신호를 강/약으로 분류해 그대로 Dart 로 반환할 뿐,
 * 가중 판정·차단·감사 로그는 하지 않는다(앱 enforcement 책임).
 */
class DeviceVerifierPlugin :
    FlutterPlugin,
    MethodCallHandler {
    private lateinit var channel: MethodChannel
    private lateinit var appContext: Context
    private val mainHandler = Handler(Looper.getMainLooper())

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        appContext = binding.applicationContext
        channel = MethodChannel(binding.binaryMessenger, CHANNEL)
        channel.setMethodCallHandler(this)
    }

    override fun onMethodCall(
        call: MethodCall,
        result: Result
    ) {
        if (call.method == "detectHooks") {
            // /proc 읽기·소켓 connect 가 포함되므로 메인 스레드를 막지 않도록
            // 백그라운드에서 수행 후 메인 스레드로 회신.
            Thread {
                try {
                    val r = SecurityDetector.detectHooks(appContext)
                    val payload = mapOf("strong" to r.strong, "weak" to r.weak)
                    mainHandler.post { result.success(payload) }
                } catch (e: Throwable) {
                    mainHandler.post { result.error("DETECT_FAILED", e.message, null) }
                }
            }.start()
        } else {
            result.notImplemented()
        }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    private companion object {
        /** 앱 패키지에 종속되지 않는 중립 채널명(pro/M20 공용). */
        const val CHANNEL = "angelrobotics/device_verifier"
    }
}
