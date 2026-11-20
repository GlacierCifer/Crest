import ObjectiveC
import UIKit

/// Takes the form assistant iOS puts above the keyboard for a webpage field.
///
/// WebKit hands the assistant to its private content view as that view's
/// `inputAccessoryView`, and no public API turns it off. This override answers
/// nil for it, so a phone's screen is all page while typing. A system that
/// renames the view leaves the assistant in place rather than breaking the app.
@MainActor
enum MobileKeyboardAccessoryHider {
    private static var isInstalled = false

    /// Installs the override once, after WebKit has loaded its content view.
    static func installIfNeeded() {
        guard !isInstalled else { return }
        isInstalled = true
        guard let contentView = NSClassFromString("WKContentView") else { return }
        let selector = #selector(getter: UIResponder.inputAccessoryView)
        let answer: @convention(block) (AnyObject) -> UIView? = { _ in nil }
        let implementation = imp_implementationWithBlock(answer)
        if class_addMethod(contentView, selector, implementation, "@@:") { return }
        if let method = class_getInstanceMethod(contentView, selector) {
            method_setImplementation(method, implementation)
        }
    }
}
