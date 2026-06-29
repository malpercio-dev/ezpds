package app.tauri.auth_session

import android.app.Activity
import android.content.Intent
import androidx.activity.result.ActivityResult
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin

@InvokeArg
class StartArgs {
    lateinit var authUrl: String
    lateinit var callbackUrlScheme: String
}

@TauriPlugin
class AuthSessionPlugin(private val activity: Activity) : Plugin(activity) {

    @Command
    fun start(invoke: Invoke) {
        val args = invoke.parseArgs(StartArgs::class.java)

        val intent = Intent(activity, AuthSessionActivity::class.java).apply {
            putExtra(AuthSessionActivity.EXTRA_AUTH_URL, args.authUrl)
        }

        // Tauri's startActivityForResult passes the Invoke through to the
        // @ActivityCallback method automatically — no need to store it.
        startActivityForResult(invoke, intent, "onAuthResult")
    }

    @ActivityCallback
    private fun onAuthResult(invoke: Invoke, result: ActivityResult) {
        if (result.resultCode == Activity.RESULT_OK && result.data != null) {
            val callbackUrl = result.data!!.getStringExtra(AuthSessionActivity.EXTRA_CALLBACK_URL)
            if (callbackUrl != null) {
                val ret = JSObject()
                ret.put("url", callbackUrl)
                invoke.resolve(ret)
            } else {
                invoke.reject("Auth session completed without a callback URL")
            }
        } else if (result.resultCode == Activity.RESULT_CANCELED) {
            invoke.reject("user_cancelled")
        } else {
            val error = result.data?.getStringExtra(AuthSessionActivity.EXTRA_ERROR)
                ?: "Auth session failed"
            invoke.reject(error)
        }
    }
}
