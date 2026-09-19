// by cipher.org.uk
import Foundation
import CryptoKit
import Security

/// Optional password protection for exported bug-tracker backups.
///
/// An encrypted backup has this binary layout:
///   magic ("CEBACK" 6 bytes) | salt (16) | nonce (12) | tag (16) | ciphertext
/// The ciphertext is the JSON payload encrypted with AES-GCM using a key derived
/// from the user's password and the per-file random salt (SHA-256 stretching).
/// Because the magic header is always present, import can detect encryption and
/// prompt for a password. The app's own local bug store is unaffected.
enum BackupCrypto {
    private static let magic: [UInt8] = Array("CEBACK".utf8)
    private static let saltSize = 16
    private static let nonceSize = 12
    private static let tagSize = 16
    private static let headerSize = magic.count + saltSize + nonceSize + tagSize

    static func isEncrypted(_ data: Data) -> Bool {
        data.count >= headerSize && Array(data.prefix(magic.count)) == magic
    }

    /// Encrypts a JSON payload with a password. Returns the full backup file bytes.
    static func seal(_ jsonData: Data, password: String) throws -> Data {
        guard !password.isEmpty else { throw BackupError.emptyPassword }
        var salt = [UInt8](repeating: 0, count: saltSize)
        _ = SecRandomCopyBytes(kSecRandomDefault, salt.count, &salt)

        var nonceBytes = [UInt8](repeating: 0, count: nonceSize)
        _ = SecRandomCopyBytes(kSecRandomDefault, nonceBytes.count, &nonceBytes)

        let key = deriveKey(password: password, salt: Data(salt))
        let nonce = try AES.GCM.Nonce(data: Data(nonceBytes))
        let sealed = try AES.GCM.seal(jsonData, using: key, nonce: nonce)

        var out = Data(magic)
        out.append(contentsOf: salt)
        out.append(contentsOf: nonceBytes)
        out.append(sealed.tag)
        out.append(sealed.ciphertext)
        return out
    }

    /// Decrypts a backup file. Throws `BackupError.wrongPassword` on invalid password.
    static func open(_ backupData: Data, password: String) throws -> Data {
        guard isEncrypted(backupData) else { throw BackupError.notEncrypted }
        let magicCount = magic.count
        let salt = Data(backupData[magicCount ..< magicCount + saltSize])
        let nonceBytes = Data(backupData[magicCount + saltSize ..< magicCount + saltSize + nonceSize])
        let tagStart = magicCount + saltSize + nonceSize
        let tag = Data(backupData[tagStart ..< tagStart + tagSize])
        let ciphertext = Data(backupData[(tagStart + tagSize)...])

        let key = deriveKey(password: password, salt: salt)
        guard let nonce = try? AES.GCM.Nonce(data: nonceBytes) else { throw BackupError.corrupted }
        let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        do {
            return try AES.GCM.open(box, using: key)
        } catch {
            throw BackupError.wrongPassword
        }
    }

    /// Derives a 256-bit AES key from the password + salt using repeated SHA-256.
    private static func deriveKey(password: String, salt: Data) -> SymmetricKey {
        var digestData = Data()
        digestData.append(salt)
        digestData.append(Data(password.utf8))
        for _ in 0..<10_000 {
            digestData = Data(SHA256.hash(data: digestData))
        }
        return SymmetricKey(data: digestData)
    }
}

enum BackupError: Error, LocalizedError {
    case emptyPassword
    case notEncrypted
    case corrupted
    case wrongPassword

    var errorDescription: String? {
        switch self {
        case .emptyPassword: return "The password cannot be empty."
        case .notEncrypted: return "The file is not an encrypted Karma Pro backup."
        case .corrupted: return "The backup file is corrupted or unreadable."
        case .wrongPassword: return "The password is incorrect."
        }
    }
}
