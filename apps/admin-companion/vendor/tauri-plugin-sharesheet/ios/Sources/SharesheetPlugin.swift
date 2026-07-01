// Copyright 2019-2023 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

import LocalAuthentication
import SwiftRs
import Tauri
import UIKit
import WebKit
import SwiftUI
import UIKit
import Foundation

struct SharesheetOptions: Decodable {
  let text: String
}

class SharesheetPlugin: Plugin {
  var webview: WKWebView?
  public override func load(webview: WKWebView) {
    self.webview = webview
  }

  @objc func shareText(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(SharesheetOptions.self)

    DispatchQueue.main.async {
      // Fail fast when there is no view controller to present from. Without a
      // presenter the sheet can never open, and silently returning would strand
      // the JS `await share(text)` promise forever. Rejecting lets the caller's
      // catch run and fall back to copy-only.
      guard let presenter = self.manager.viewController else {
        invoke.reject("No view controller available to present the share sheet")
        return
      }

      let activityViewController = UIActivityViewController(
        activityItems: [args.text], applicationActivities: nil)

      // Always settle the invoke when the sheet finishes so the JS promise never
      // hangs: reject on an activity error, resolve otherwise. A user dismissal
      // (completed == false) is a successful round-trip, so it resolves too.
      activityViewController.completionWithItemsHandler = { _, _, _, activityError in
        if let activityError = activityError {
          invoke.reject(
            "Share sheet failed: \(activityError.localizedDescription)", error: activityError)
        } else {
          invoke.resolve()
        }
      }

      // Display as a popover on iPad as required by Apple. The source view only
      // anchors the popover; fall back to the presenter's view when the webview
      // is unavailable rather than force-unwrapping it.
      if let popover = activityViewController.popoverPresentationController {
        // The explicit `UIView` type forces the non-optional `??` overload: with
        // `presenter.view` being `UIView!`, an inferred type would resolve to
        // `UIView?` and `.bounds` below would not type-check.
        let sourceView: UIView = self.webview ?? presenter.view
        popover.sourceView = sourceView
        popover.sourceRect = CGRect(
          x: sourceView.bounds.midX, y: sourceView.bounds.midY, width: 0, height: 0)
      }

      presenter.present(activityViewController, animated: true, completion: nil)
    }
  }
}

@_cdecl("init_plugin_sharesheet")
func initPlugin() -> Plugin {
  return SharesheetPlugin()
}
