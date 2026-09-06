//
//  CodeSigningInfo.swift
//  Shared
//

import Foundation
import Security

/// Information about the current process's code signature.
enum CodeSigningInfo {
    /// The team identifier of the current process's code signature,
    /// or nil if the process is unsigned or ad-hoc signed.
    static let teamIdentifier: String? = {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else {
            return nil
        }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
            return nil
        }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, [], &info) == errSecSuccess,
        let infoDict = info as? [String: Any] else {
            return nil
        }
        return infoDict[kSecCodeInfoTeamIdentifier as String] as? String
    }()

    /// Whether the current process's code signature has a team identifier.
    /// Ad-hoc signed builds (such as local builds without a signing
    /// certificate) have no team, so same-team XPC peer requirements
    /// cannot be satisfied and must not be enforced.
    static var hasTeamIdentifier: Bool {
        teamIdentifier != nil
    }
}
