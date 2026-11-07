import Foundation

// Arkivoperationer (komprimera/packa upp) för SFTP-filhanteraren. SFTP
// version 3 har ingen egen arkivsemantik — det här shellar ut till tar/zip
// över en vanlig exec-kanal, samma mönster som DockerService.swift.
// Sökvägar VALIDERAS INTE mot en whitelist (som DockerService gör för
// containerreferenser) eftersom filnamn legitimt kan innehålla mellanslag/
// unicode/etc — istället citeras varje sökväg för sig med enkla citattecken
// (POSIX-shell-säkert), annars vore en fil döpt `"; rm -rf ~ #"` en injektion.

public enum ArchiveOperations {
    /// Enkla citattecken runt `s`, med inbäddade `'` eskapade som `'\''`
    /// (stänger citatet, ett litterlat-eskapat citattecken, öppnar igen) —
    /// standard POSIX-shell-säkert sätt att citera GODTYCKLIG text, oavsett
    /// mellanslag eller specialtecken.
    static func shellQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    public static func createTarGzCommand(paths: [String], archiveName: String, in directory: String) -> String {
        let quotedPaths = paths.map(shellQuote).joined(separator: " ")
        return "cd \(shellQuote(directory)) && tar czf \(shellQuote(archiveName)) -- \(quotedPaths)"
    }

    public static func extractTarGzCommand(archiveName: String, in directory: String) -> String {
        "cd \(shellQuote(directory)) && tar xzf \(shellQuote(archiveName))"
    }

    /// `zip`, till skillnad från `tar -f`, tar arkivnamnet som ett RENT
    /// positionellt argument — inte kopplat till en flagga som konsumerar
    /// sitt värde oavsett innehåll. Två separata, EMPIRISKT verifierade
    /// motmedel krävs därför:
    /// 1. `--` FÖRE sökvägslistan (EFTER arkivnamnet — `zip` vägrar uttryckligen
    ///    "-- before archive name") skyddar filnamn som börjar med `-`
    ///    (t.ex. en fil döpt `-T`, som annars tolkas som zips egen
    ///    testarkiv-flagga och ger "Nothing to do!" istället för att
    ///    packas).
    /// 2. `./`-prefix på arkivnamnet SJÄLVT (helt användarstyrt i UI:t)
    ///    löser samma problem för namnet — `--` fungerar INTE där (zip
    ///    vägrar starta), men `./-namn.zip` gör namnet otvetydigt till en
    ///    sökväg istället för en flaggsträng.
    public static func createZipCommand(paths: [String], archiveName: String, in directory: String) -> String {
        let quotedPaths = paths.map(shellQuote).joined(separator: " ")
        let safeArchiveName = "./" + archiveName
        return "cd \(shellQuote(directory)) && zip -r -q \(shellQuote(safeArchiveName)) -- \(quotedPaths)"
    }

    /// Extract through directory descriptors so existing symlinks cannot redirect writes.
    /// The remote host needs Python 3 with POSIX dir_fd and O_NOFOLLOW support.
    public static func extractZipCommand(archiveName: String, in directory: String) -> String {
        let script = #"""
        import os, secrets, shutil, stat, sys, zipfile

        # Validate the complete member list before making any destination changes.
        with zipfile.ZipFile(sys.argv[1]) as archive:
            members = []
            for info in archive.infolist():
                name = info.orig_filename
                if "\x00" in name or name.startswith("/"):
                    raise ValueError("Unsafe ZIP member path")
                parts = [part for part in name.split("/") if part not in ("", ".")]
                if ".." in parts or (not parts and not info.is_dir()):
                    raise ValueError("Unsafe ZIP member path")
                mode = (info.external_attr >> 16) if info.create_system == 3 else 0
                kind = stat.S_IFMT(mode)
                if kind not in (0, stat.S_IFREG, stat.S_IFDIR) or (kind == stat.S_IFDIR) != info.is_dir() and kind != 0:
                    raise ValueError("Unsupported ZIP member type")
                members.append((info, parts, mode))

            # zipfile never yields more than a member's declared size (it fails the CRC
            # check instead), so the declared total bounds what extraction can write.
            needed = sum(info.file_size for info, _, _ in members)
            if needed > shutil.disk_usage(".").free:
                raise OSError("Not enough free space to extract the archive")

            root = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            mask = os.umask(0)
            os.umask(mask)
            try:
                for info, parts, mode in members:
                    parent = os.dup(root)
                    try:
                        for part in parts if info.is_dir() else parts[:-1]:
                            try:
                                os.mkdir(part, 0o777, dir_fd=parent)
                            except FileExistsError:
                                pass
                            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                            os.close(parent)
                            parent = child
                        if info.is_dir():
                            continue
                        try:
                            existing = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
                        except FileNotFoundError:
                            pass
                        else:
                            if not stat.S_ISREG(existing.st_mode):
                                raise ValueError("Unsafe ZIP destination")
                        # Write a new inode, then replace the destination. This also avoids
                        # modifying a file outside the root through an existing hard link.
                        temp = ".skerry-" + secrets.token_hex(16)
                        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
                        try:
                            with os.fdopen(fd, "wb") as target, archive.open(info) as source:
                                shutil.copyfileobj(source, target)
                                os.fchmod(target.fileno(), ((mode & 0o777) if mode else 0o666) & ~mask)
                            os.replace(temp, parts[-1], src_dir_fd=parent, dst_dir_fd=parent)
                        finally:
                            try:
                                os.unlink(temp, dir_fd=parent)
                            except FileNotFoundError:
                                pass
                    finally:
                        os.close(parent)
            finally:
                os.close(root)
        """#
        return "cd \(shellQuote(directory)) && python3 -c \(shellQuote(script)) \(shellQuote("./" + archiveName))"
    }

    // MARK: - Körning över SSH

    public static func createTarGz(
        paths: [String], archiveName: String, in directory: String, over session: SSHSession
    ) async throws {
        _ = try await session.run(createTarGzCommand(paths: paths, archiveName: archiveName, in: directory))
    }

    public static func extractTarGz(archiveName: String, in directory: String, over session: SSHSession) async throws {
        _ = try await session.run(extractTarGzCommand(archiveName: archiveName, in: directory))
    }

    public static func createZip(
        paths: [String], archiveName: String, in directory: String, over session: SSHSession
    ) async throws {
        _ = try await session.run(createZipCommand(paths: paths, archiveName: archiveName, in: directory))
    }

    public static func extractZip(archiveName: String, in directory: String, over session: SSHSession) async throws {
        _ = try await session.run(extractZipCommand(archiveName: archiveName, in: directory))
    }
}
