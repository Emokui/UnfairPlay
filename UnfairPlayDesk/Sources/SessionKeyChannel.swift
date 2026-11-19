import Foundation
import Security
import Darwin

// One private socket per verified worker. Its first byte selects read, create-if-missing,
// or delete. The reply is a status byte followed by the key or a displayable error.
final class SessionKeyChannel {
    private static let queue = DispatchQueue(label: "local.unfairplay.desk.session-keys")
    private static var keys: [UUID: Data] = [:] // accessed only on queue
    let child: FileHandle
    private let parent: FileHandle
    private let socketLock = NSLock()
    private var cancelled = false
    private var closed = false

    init() throws {
        var sockets: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0 else {
            throw DeskError("无法打开账户密钥通道。")
        }
        parent = FileHandle(fileDescriptor: sockets[0], closeOnDealloc: true)
        child = FileHandle(fileDescriptor: sockets[1], closeOnDealloc: true)
        var one: Int32 = 1
        guard fcntl(sockets[0], F_SETFD, FD_CLOEXEC) == 0,
              fcntl(sockets[1], F_SETFD, FD_CLOEXEC) == 0,
              setsockopt(sockets[0], SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout.size(ofValue: one))) == 0 else {
            throw DeskError("无法配置账户密钥通道。")
        }
    }

    func serve(account: UUID, deleting: Bool) {
        // Wait independently of the key queue: the worker may prompt for
        // a password or migrate legacy items before sending its request.
        try? child.close()
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            defer {
                socketLock.withLock {
                    closed = true
                    try? parent.close()
                }
            }
            guard let request = (try? parent.read(upToCount: 1))?.first else { return }
            let result: Result<Data, Error>? = Self.queue.sync {
                guard !socketLock.withLock({ cancelled }) else { return nil }
                return Result {
                    if deleting && request == 68 { // D
                        try Self.remove(account)
                        return Data()
                    }
                    if !deleting && (request == 82 || request == 67) { // R or C
                        return try Self.key(account, create: request == 67)
                    }
                    throw DeskError("无效的账户密钥请求。")
                }
            }
            guard let result else { return }
            switch result {
            case .success(let response):
                if (try? parent.write(contentsOf: Data([0]))) != nil {
                    try? parent.write(contentsOf: response)
                }
            case .failure(let error):
                try? parent.write(contentsOf: Data([1]) + Data(error.localizedDescription.utf8))
            }
        }
    }

    func cancel() {
        socketLock.withLock {
            guard !closed, !cancelled else { return }
            cancelled = true
            // Wake any pending I/O. The serving task owns the final close.
            _ = shutdown(parent.fileDescriptor, SHUT_RDWR)
        }
    }

    static func forget(_ id: UUID) {
        queue.async { keys.removeValue(forKey: id) }
    }

    private static func query(_ id: UUID) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: "ipatool-auth.service." + id.uuidString.lowercased(),
         kSecAttrAccount as String: "session-master-v1"]
    }

    private static func key(_ id: UUID, create: Bool) throws -> Data {
        // Create is requested under ipatool's profile lock only when no encrypted
        // file exists. An external CLI revoke might have removed our cached key.
        if !create, let key = keys[id] { return key }
        keys.removeValue(forKey: id)
        var lookup = query(id)
        lookup[kSecMatchLimit as String] = kSecMatchLimitOne
        lookup[kSecReturnData as String] = true
        var value: CFTypeRef?
        let status = SecItemCopyMatching(lookup as CFDictionary, &value)
        let result: Data
        if status == errSecItemNotFound && create {
            var bytes = Data(count: 32)
            let generated = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
            try check(generated)
            var item = query(id)
            item[kSecValueData as String] = bytes
            item[kSecAttrLabel as String] = "UnfairPlay · 账户会话密钥"
            try check(SecItemAdd(item as CFDictionary, nil))
            result = bytes
        } else {
            if status == errSecItemNotFound { throw DeskError("此账户的会话密钥缺失，请清除此账户登陆后重新登录。") }
            try check(status)
            guard let data = value as? Data, data.count == 32 else {
                throw DeskError("此账户的会话密钥无效，请清除此账户登陆后重新登录。")
            }
            result = data
        }
        let storage = UnsafeMutableRawPointer.allocate(byteCount: 32, alignment: 1)
        result.copyBytes(to: storage.assumingMemoryBound(to: UInt8.self), count: 32)
        let cached = Data(bytesNoCopy: storage, count: 32, deallocator: .custom { pointer, count in
            _ = memset_s(pointer, count, 0, count)
            pointer.deallocate()
        })
        keys[id] = cached
        return cached
    }

    private static func remove(_ id: UUID) throws {
        keys.removeValue(forKey: id)
        let status = SecItemDelete(query(id) as CFDictionary)
        if status != errSecItemNotFound { try check(status) }
    }

    private static func check(_ status: OSStatus) throws {
        guard status != errSecSuccess else { return }
        let message = SecCopyErrorMessageString(status, nil) as String? ?? String(status)
        throw DeskError("无法访问账户钥匙串（\(message)）。")
    }
}
