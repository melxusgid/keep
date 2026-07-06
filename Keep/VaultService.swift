import Foundation
import CryptoKit
import SQLite3

// MARK: - Argon2id C Bridge

/// Argon2 error codes from argon2.h
private let ARGON2_OK = 0
private let ARGON2_VERIFIER_ERROR = -35

/// Wraps the C argon2id key derivation function.
/// Matches the Python implementation: memory_cost=19456, iterations=3, parallelism=1
private func argon2id(password: String, salt: Data, length: Int = 32) throws -> Data {
    let passwordBytes = Array(password.utf8)
    let saltBytes = [UInt8](salt)

    var hash = [UInt8](repeating: 0, count: length)

    let result = argon2id_hash_raw(
        UInt32(3),              // t_cost = 3 iterations
        UInt32(19456),          // m_cost = 19 MB (OWASP minimum)
        UInt32(1),              // parallelism = 1
        passwordBytes,          // pwd
        passwordBytes.count,    // pwdlen
        saltBytes,              // salt
        saltBytes.count,        // saltlen
        &hash,                  // hash output buffer
        hash.count              // hashlen
    )

    guard result == ARGON2_OK else {
        throw VaultError.cryptoFailed("Argon2id derivation failed (code: \(result))")
    }

    return Data(hash)
}

// MARK: - Error Types

enum VaultError: Error, LocalizedError {
    case notFound(String)
    case locked
    case cryptoFailed(String)
    case fileCorrupt(String)
    case databaseError(String)
    case wrongPassword
    case noVault

    var errorDescription: String? {
        switch self {
        case .notFound(let name): return "Secret '\(name)' not found"
        case .locked: return "Vault is locked"
        case .cryptoFailed(let msg): return "Crypto error: \(msg)"
        case .fileCorrupt(let msg): return "Vault file corrupt: \(msg)"
        case .databaseError(let msg): return "Database error: \(msg)"
        case .wrongPassword: return "Wrong password or corrupt vault"
        case .noVault: return "No vault found. Initialize first."
        }
    }
}

// MARK: - Data Models

struct SecretItem: Identifiable, Codable {
    var id: String { name }
    let name: String
    let value: String
    let createdAt: Date
    let updatedAt: Date
    let note: String
}

struct AuditEntry: Identifiable, Codable {
    let id: Int64
    let action: String
    let secretName: String?
    let context: String
    let timestamp: Date
}

struct VaultStats {
    let secretCount: Int
    let auditCount: Int
    let vaultName: String
    let unlocked: Bool
}

// MARK: - Vault Service

/// Swift-native encrypted secrets vault. File format matches the Python `keep` CLI:
///
///     ~/.keep/vault.enc
///     [salt: 16 bytes][nonce: 12 bytes][AES-256-GCM encrypted SQLite DB: rest]
///
/// The salt is stored in the clear (prevents rainbow tables). The key is derived
/// from password + salt via Argon2id. Each secret inside the DB gets its own
/// unique nonce on encryption (per-secret encryption inside the envelope).
 actor VaultService {

    // MARK: - Constants

    static let vaultDir = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".keep")
    static let vaultPath = vaultDir.appendingPathComponent("vault.enc")

    static let saltSize = 16
    static let nonceSize = 12
    static let keySize = 32 // 256-bit
    static let defaultAutoLock: TimeInterval = 900 // 15 minutes

    // MARK: - State

    private var key: SymmetricKey?
    private var db: OpaquePointer?
    private var autoLockTimer: Timer?
    private var autoLockInterval: TimeInterval = defaultAutoLock
    private var auditBuffer: [(action: String, target: String, context: String, timestamp: Date)] = []

    // MARK: - Init

    func setAutoLock(seconds: TimeInterval) {
        autoLockInterval = seconds
        if key != nil {
            bumpTimer()
        }
    }

    // MARK: - File Paths

    nonisolated static func ensureVaultDir() throws {
        try FileManager.default.createDirectory(
            at: vaultDir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
    }

    // MARK: - Initialization

    func initialize(password: String, name: String = "default") throws {
        try Self.ensureVaultDir()

        let salt = Data((0..<Self.saltSize).map { _ in UInt8.random(in: 0...255) })
        let derivedKey = try argon2id(password: password, salt: salt)
        let symKey = SymmetricKey(data: derivedKey)

        // Build the database in memory
        var memDb: OpaquePointer?
        guard sqlite3_open_v2(":memory:", &memDb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil) == SQLITE_OK,
              let memDb else {
            throw VaultError.databaseError("Failed to create in-memory database")
        }

        defer { sqlite3_close(memDb) }

        try executeSQL(memDb, """
            CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
            INSERT INTO meta VALUES ('name', '\(name.replacingOccurrences(of: "'", with: "''"))');
            INSERT INTO meta VALUES ('created', '\(Date().timeIntervalSince1970)');
            INSERT INTO meta VALUES ('version', '1');
            CREATE TABLE secrets (
                name TEXT PRIMARY KEY,
                encrypted_blob BLOB NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                metadata TEXT DEFAULT '{}'
            );
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                secret_name TEXT,
                context TEXT,
                timestamp REAL NOT NULL
            );
        """)

        // Serialize DB to bytes
        let plaintext = try serializeDB(memDb)
        let sealedBox = try AES.GCM.seal(plaintext, using: symKey)

        // Write vault file: salt(16) + sealedBox.combined (nonce+ciphertext+tag)
        var vaultData = Data()
        vaultData.append(salt)
        vaultData.append(sealedBox.combined!)

        try vaultData.write(to: Self.vaultPath, options: .atomic)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: Self.vaultPath.path
        )

        // Open as unlocked
        self.key = symKey
        try loadDB(plaintext)
        log(action: "init", target: "_vault")
    }

    // MARK: - Lock / Unlock

    func unlock(password: String) throws {
        guard FileManager.default.fileExists(atPath: Self.vaultPath.path) else {
            throw VaultError.noVault
        }

        let vaultData = try Data(contentsOf: Self.vaultPath)

        guard vaultData.count >= Self.saltSize + Self.nonceSize + 1 else {
            throw VaultError.fileCorrupt("Vault file too small")
        }

        let salt = Data(vaultData[0..<Self.saltSize])
        let combined = Data(vaultData[Self.saltSize...])

        let derivedKey = try argon2id(password: password, salt: salt)
        let symKey = SymmetricKey(data: derivedKey)

        let sealedBox: AES.GCM.SealedBox

        do {
            sealedBox = try AES.GCM.SealedBox(combined: combined)
        } catch {
            throw VaultError.wrongPassword
        }

        let plaintext: Data
        do {
            plaintext = try AES.GCM.open(sealedBox, using: symKey)
        } catch {
            throw VaultError.wrongPassword
        }

        self.key = symKey
        try loadDB(plaintext)
        log(action: "unlock", target: "_vault")
        bumpTimer()
    }

    func lock() {
        cancelTimer()
        if let db = db {
            flushAudit()
            try? syncToDisk()
            sqlite3_close(db)
            self.db = nil
        }
        // Wipe key
        key = nil
    }

    var isLocked: Bool {
        key == nil
    }

    // MARK: - Secret Operations

    func set(name: String, value: String, note: String = "") throws {
        try requireUnlocked()
        guard let key = key else { throw VaultError.locked }

        let now = Date().timeIntervalSince1970
        let meta = "{\"note\":\"\(note.replacingOccurrences(of: "\"", with: "\\\""))\"}"
        let plaintext = try JSONSerialization.data(withJSONObject: ["v": value, "note": note])

        // Encrypt with its own nonce
        let sealedBox = try AES.GCM.seal(plaintext, using: key)
        let blob = sealedBox.combined!

        // Check if exists
        var stmt: OpaquePointer?
        let query = "SELECT created_at FROM secrets WHERE name = ?"
        guard sqlite3_prepare_v2(db, query, -1, &stmt, nil) == SQLITE_OK else {
            throw VaultError.databaseError("Failed to prepare select")
        }
        defer { sqlite3_finalize(stmt) }

        sqlite3_bind_text(stmt, 1, (name as NSString).utf8String, -1, nil)
        let exists = sqlite3_step(stmt) == SQLITE_ROW
        let created: Double
        if exists {
            created = sqlite3_column_double(stmt, 0)
        } else {
            created = now
        }
        sqlite3_finalize(stmt)
        stmt = nil

        let blobData = blob as NSData
        let insert = "INSERT OR REPLACE INTO secrets (name, encrypted_blob, created_at, updated_at, metadata) VALUES (?, ?, ?, ?, ?)"
        guard sqlite3_prepare_v2(db, insert, -1, &stmt, nil) == SQLITE_OK else {
            throw VaultError.databaseError("Failed to prepare insert")
        }
        defer { sqlite3_finalize(stmt) }

        sqlite3_bind_text(stmt, 1, (name as NSString).utf8String, -1, nil)
        sqlite3_bind_blob(stmt, 2, blobData.bytes, Int32(blobData.length), nil)
        sqlite3_bind_double(stmt, 3, created)
        sqlite3_bind_double(stmt, 4, now)
        sqlite3_bind_text(stmt, 5, (meta as NSString).utf8String, -1, nil)

        guard sqlite3_step(stmt) == SQLITE_DONE else {
            throw VaultError.databaseError("Failed to insert secret")
        }

        log(action: "set", target: name)
        bumpTimer()
    }

    func get(name: String) throws -> String? {
        try requireUnlocked()
        guard let key = key else { throw VaultError.locked }

        var stmt: OpaquePointer?
        let query = "SELECT encrypted_blob FROM secrets WHERE name = ?"
        guard sqlite3_prepare_v2(db, query, -1, &stmt, nil) == SQLITE_OK else {
            throw VaultError.databaseError("Failed to prepare get")
        }
        defer { sqlite3_finalize(stmt) }

        sqlite3_bind_text(stmt, 1, (name as NSString).utf8String, -1, nil)

        guard sqlite3_step(stmt) == SQLITE_ROW else {
            return nil
        }

        guard let blobPtr = sqlite3_column_blob(stmt, 0) else {
            return nil
        }
        let blobLen = sqlite3_column_bytes(stmt, 0)
        let blobData = Data(bytes: blobPtr, count: Int(blobLen))

        let sealedBox = try AES.GCM.SealedBox(combined: blobData)
        let plaintext = try AES.GCM.open(sealedBox, using: key)
        let json = try JSONSerialization.jsonObject(with: plaintext) as? [String: Any]
        let value = json?["v"] as? String

        log(action: "get", target: name)
        bumpTimer()
        return value
    }

    func list() throws -> [SecretItem] {
        try requireUnlocked()

        var stmt: OpaquePointer?
        let query = "SELECT name, created_at, updated_at, metadata FROM secrets ORDER BY name"
        guard sqlite3_prepare_v2(db, query, -1, &stmt, nil) == SQLITE_OK else {
            throw VaultError.databaseError("Failed to prepare list")
        }
        defer { sqlite3_finalize(stmt) }

        var items: [SecretItem] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            let name = String(cString: sqlite3_column_text(stmt, 0))
            let createdAt = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 1))
            let updatedAt = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 2))
            let metaStr = String(cString: sqlite3_column_text(stmt, 3))
            let metaData = try? JSONSerialization.jsonObject(with: metaStr.data(using: .utf8) ?? Data()) as? [String: Any]
            let note = metaData?["note"] as? String ?? ""

            items.append(SecretItem(
                name: name,
                value: "", // Values not decrypted on list — needs explicit get
                createdAt: createdAt,
                updatedAt: updatedAt,
                note: note
            ))
        }

        log(action: "list", target: "_all")
        bumpTimer()
        return items
    }

    func delete(name: String) throws -> Bool {
        try requireUnlocked()

        var stmt: OpaquePointer?
        let query = "DELETE FROM secrets WHERE name = ?"
        guard sqlite3_prepare_v2(db, query, -1, &stmt, nil) == SQLITE_OK else {
            throw VaultError.databaseError("Failed to prepare delete")
        }
        defer { sqlite3_finalize(stmt) }

        sqlite3_bind_text(stmt, 1, (name as NSString).utf8String, -1, nil)
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            throw VaultError.databaseError("Failed to delete secret")
        }

        let changes = Int(sqlite3_changes(db))
        if changes > 0 {
            log(action: "delete", target: name)
            bumpTimer()
            return true
        }
        return false
    }

    func rotate(name: String, length: Int = 32) throws -> String? {
        let byteCount = max(length / 2, 16)
        var bytes = [UInt8](repeating: 0, count: byteCount)
        let status = SecRandomCopyBytes(kSecRandomDefault, byteCount, &bytes)
        guard status == errSecSuccess else {
            throw VaultError.cryptoFailed("Failed to generate random bytes")
        }
        let newValue = bytes.map { String(format: "%02x", $0) }.joined()
        try set(name: name, value: newValue)
        log(action: "rotate", target: name)
        return newValue
    }

    func exportAll() throws -> [String: String] {
        try requireUnlocked()
        let items = try list()
        var result: [String: String] = [:]
        for item in items {
            if let val = try get(name: item.name) {
                result[item.name] = val
            }
        }
        log(action: "export", target: "_vault")
        return result
    }

    // MARK: - Audit

    private nonisolated func log(action: String, target: String, context: String? = nil) {
        Task { await self._log(action: action, target: target, context: context) }
    }

    private func _log(action: String, target: String, context: String? = nil) {
        auditBuffer.append((
            action: action,
            target: target,
            context: context ?? "pid:\(ProcessInfo.processInfo.processIdentifier)",
            timestamp: Date()
        ))
        if auditBuffer.count >= 10 {
            flushAudit()
        }
    }

    private func flushAudit() {
        guard let db = db, !auditBuffer.isEmpty else { return }

        for entry in auditBuffer {
            var stmt: OpaquePointer?
            let insert = "INSERT INTO audit_log (action, secret_name, context, timestamp) VALUES (?, ?, ?, ?)"
            guard sqlite3_prepare_v2(db, insert, -1, &stmt, nil) == SQLITE_OK else { continue }
            sqlite3_bind_text(stmt, 1, (entry.action as NSString).utf8String, -1, nil)
            sqlite3_bind_text(stmt, 2, (entry.target as NSString).utf8String, -1, nil)
            sqlite3_bind_text(stmt, 3, (entry.context as NSString).utf8String, -1, nil)
            sqlite3_bind_double(stmt, 4, entry.timestamp.timeIntervalSince1970)
            sqlite3_step(stmt)
            sqlite3_finalize(stmt)
        }
        auditBuffer.removeAll()
    }

    func getAuditLog(limit: Int = 50) throws -> [AuditEntry] {
        try requireUnlocked()

        var stmt: OpaquePointer?
        let query = "SELECT id, action, secret_name, context, timestamp FROM audit_log ORDER BY timestamp DESC LIMIT ?"
        guard sqlite3_prepare_v2(db, query, -1, &stmt, nil) == SQLITE_OK else {
            throw VaultError.databaseError("Failed to prepare audit query")
        }
        defer { sqlite3_finalize(stmt) }

        sqlite3_bind_int64(stmt, 1, Int64(limit))

        var entries: [AuditEntry] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            let id = sqlite3_column_int64(stmt, 0)
            let action = String(cString: sqlite3_column_text(stmt, 1))
            let secretName: String? = sqlite3_column_type(stmt, 2) != SQLITE_NULL
                ? String(cString: sqlite3_column_text(stmt, 2)) : nil
            let context = String(cString: sqlite3_column_text(stmt, 3))
            let timestamp = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 4))

            entries.append(AuditEntry(
                id: id,
                action: action,
                secretName: secretName,
                context: context,
                timestamp: timestamp
            ))
        }
        return entries
    }

    // MARK: - Status

    func stats() throws -> VaultStats {
        try requireUnlocked()

        var secretCount: Int = 0
        var auditCount: Int = 0
        var vaultName: String = "default"

        var stmt: OpaquePointer?
        if sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM secrets", -1, &stmt, nil) == SQLITE_OK {
            if sqlite3_step(stmt) == SQLITE_ROW {
                secretCount = Int(sqlite3_column_int64(stmt, 0))
            }
            sqlite3_finalize(stmt)
            stmt = nil
        }

        if sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM audit_log", -1, &stmt, nil) == SQLITE_OK {
            if sqlite3_step(stmt) == SQLITE_ROW {
                auditCount = Int(sqlite3_column_int64(stmt, 0))
            }
            sqlite3_finalize(stmt)
            stmt = nil
        }

        if sqlite3_prepare_v2(db, "SELECT value FROM meta WHERE key='name'", -1, &stmt, nil) == SQLITE_OK {
            if sqlite3_step(stmt) == SQLITE_ROW {
                vaultName = String(cString: sqlite3_column_text(stmt, 0))
            }
            sqlite3_finalize(stmt)
        }

        return VaultStats(
            secretCount: secretCount,
            auditCount: auditCount,
            vaultName: vaultName,
            unlocked: !isLocked
        )
    }

    // MARK: - Database Internals

    private nonisolated func executeSQL(_ db: OpaquePointer?, _ sql: String) throws {
        var errMsg: UnsafeMutablePointer<CChar>?
        let rc = sqlite3_exec(db, (sql as NSString).utf8String, nil, nil, &errMsg)
        guard rc == SQLITE_OK else {
            let msg = errMsg.map { String(cString: $0) } ?? "Unknown error"
            sqlite3_free(errMsg)
            throw VaultError.databaseError(msg)
        }
    }

    private func serializeDB(_ db: OpaquePointer?) throws -> Data {
        // Open a backup destination in memory
        var destDb: OpaquePointer?
        guard sqlite3_open_v2(":memory:", &destDb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil) == SQLITE_OK,
              let destDb else {
            throw VaultError.databaseError("Failed to open backup destination")
        }

        let backup = sqlite3_backup_init(destDb, "main", db, "main")
        guard backup != nil else {
            sqlite3_close(destDb)
            throw VaultError.databaseError("Failed to initialize backup")
        }

        sqlite3_backup_step(backup, Int32(-1)) // Full backup
        sqlite3_backup_finish(backup)

        // Dump to bytes
        var size: Int64 = 0
        guard let bytes = sqlite3_serialize(destDb, "main", &size, 0) else {
            sqlite3_close(destDb)
            throw VaultError.databaseError("Failed to serialize database")
        }

        let data = Data(bytes: bytes, count: Int(size))
        sqlite3_free(bytes)
        sqlite3_close(destDb)
        return data
    }

    private func loadDB(_ plaintext: Data) throws {
        // Create in-memory database from serialized data
        var memDb: OpaquePointer?
        guard sqlite3_open_v2(":memory:", &memDb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil) == SQLITE_OK,
              let memDb else {
            throw VaultError.databaseError("Failed to open in-memory database")
        }

        // Deserialize into the new database
        let rc = plaintext.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) -> Int32 in
            let ptr = UnsafeMutablePointer(mutating: bytes.bindMemory(to: UInt8.self).baseAddress)
            return sqlite3_deserialize(memDb, "main", ptr,
                                       Int64(plaintext.count), Int64(plaintext.count),
                                       UInt32(SQLITE_DESERIALIZE_READONLY) | UInt32(SQLITE_DESERIALIZE_FREEONCLOSE))
        }

        guard rc == SQLITE_OK else {
            sqlite3_close(memDb)
            throw VaultError.databaseError("Failed to deserialize database")
        }

        // Now copy to a writable in-memory DB
        var writableDb: OpaquePointer?
        guard sqlite3_open_v2(":memory:", &writableDb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil) == SQLITE_OK,
              let writableDb else {
            sqlite3_close(memDb)
            throw VaultError.databaseError("Failed to open writable database")
        }

        let backup = sqlite3_backup_init(writableDb, "main", memDb, "main")
        guard backup != nil else {
            sqlite3_close(memDb)
            sqlite3_close(writableDb)
            throw VaultError.databaseError("Failed to initialize restore backup")
        }

        sqlite3_backup_step(backup, -1)
        sqlite3_backup_finish(backup)
        sqlite3_close(memDb)

        self.db = writableDb
    }

    private func syncToDisk() throws {
        guard let key = key, let db = db else { return }

        flushAudit()
        let plaintext = try serializeDB(db)

        // Read salt from existing vault file
        let vaultData = try Data(contentsOf: Self.vaultPath)
        let salt = Data(vaultData[0..<Self.saltSize])

        let sealedBox = try AES.GCM.seal(plaintext, using: key)

        var newData = Data()
        newData.append(salt)
        newData.append(sealedBox.combined!)

        try newData.write(to: Self.vaultPath, options: .atomic)
    }

    private func requireUnlocked() throws {
        guard !isLocked else { throw VaultError.locked }
    }

    // MARK: - Auto-lock Timer

    private func bumpTimer() {
        cancelTimer()
        guard autoLockInterval > 0 else { return }
        autoLockTimer = Timer.scheduledTimer(
            withTimeInterval: autoLockInterval,
            repeats: false
        ) { [weak self] _ in
            Task { [weak self] in
                await self?.lock()
            }
        }
    }

    private func cancelTimer() {
        autoLockTimer?.invalidate()
        autoLockTimer = nil
    }
}
