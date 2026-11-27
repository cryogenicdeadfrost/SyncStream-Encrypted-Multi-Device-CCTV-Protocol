package org.syncstream.test

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    private lateinit var status: TextView

    external fun nativeConnect(host: String, port: Int, keyHex: String): String
    external fun nativeCommand(command: Int): String

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val host = EditText(this).apply {
            hint = "Bridge IP address"
            setText("192.168.1.100")
        }
        val port = EditText(this).apply {
            hint = "Port"
            setText("39170")
            inputType = 2
        }
        val key = EditText(this).apply {
            hint = "32-byte test key, hex"
            setText(TEST_KEY)
        }
        val connect = Button(this).apply { text = "Connect" }
        val ping = Button(this).apply { text = "Ping / Status" }
        status = TextView(this).apply { text = "Disconnected" }

        connect.setOnClickListener {
            status.text = nativeConnect(
                host.text.toString(),
                port.text.toString().toIntOrNull() ?: 39170,
                key.text.toString()
            )
        }

        ping.setOnClickListener {
            status.text = nativeCommand(4)
        }

        setContentView(
            LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(32, 48, 32, 48)
                addView(host)
                addView(port)
                addView(key)
                addView(connect)
                addView(ping)
                addView(status)
            }
        )
    }

    companion object {
        init {
            System.loadLibrary("syncstream_android")
        }

        // DEBUG ONLY. Replace with a provisioned per-device credential before production.
        const val TEST_KEY = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    }
}
