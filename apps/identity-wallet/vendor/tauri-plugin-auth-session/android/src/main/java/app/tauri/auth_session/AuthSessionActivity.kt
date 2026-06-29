package app.tauri.auth_session

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.browser.customtabs.CustomTabsIntent

/**
 * Transparent bridge activity that launches Chrome Custom Tabs for OAuth
 * and captures the callback URL via intent filter.
 *
 * Consumer apps must declare an intent filter on this Activity in their
 * AndroidManifest.xml with their app-specific callback scheme.
 */
class AuthSessionActivity : Activity() {
    private var resumed = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Process was killed during auth — can't resume, ask user to retry
        if (savedInstanceState != null) {
            setResult(RESULT_CANCELED)
            finish()
            return
        }

        val authUrl = intent.getStringExtra(EXTRA_AUTH_URL)
        if (authUrl == null) {
            returnError("Missing auth URL")
            return
        }

        try {
            val customTabsIntent = CustomTabsIntent.Builder().build()
            customTabsIntent.launchUrl(this, Uri.parse(authUrl))
        } catch (_: ActivityNotFoundException) {
            returnError("No browser available to handle authentication")
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)

        // Reset flag so onResume doesn't cancel
        resumed = false

        val callbackUrl = intent.data?.toString()
        if (callbackUrl != null) {
            val result = Intent().apply {
                putExtra(EXTRA_CALLBACK_URL, callbackUrl)
            }
            setResult(RESULT_OK, result)
        } else {
            setResult(RESULT_CANCELED)
        }
        finish()
    }

    override fun onResume() {
        super.onResume()

        if (resumed) {
            // Second resume without onNewIntent = user pressed back
            setResult(RESULT_CANCELED)
            finish()
            return
        }
        resumed = true
    }

    private fun returnError(message: String) {
        val result = Intent().apply {
            putExtra(EXTRA_ERROR, message)
        }
        setResult(RESULT_FIRST_USER, result)
        finish()
    }

    companion object {
        const val EXTRA_AUTH_URL = "auth_url"
        const val EXTRA_CALLBACK_URL = "callback_url"
        const val EXTRA_ERROR = "error"
    }
}
