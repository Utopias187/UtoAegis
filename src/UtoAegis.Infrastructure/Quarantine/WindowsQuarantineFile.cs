using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace UtoAegis.Infrastructure.Quarantine;

internal sealed partial class WindowsQuarantineFile : IDisposable
{
    private const uint GenericRead = 0x80000000;
    private const uint Delete = 0x00010000;
    private const uint ShareRead = 0x00000001;
    private const uint OpenExisting = 3;
    private const uint SequentialScan = 0x08000000;
    private const uint OpenReparsePoint = 0x00200000;
    private const uint DirectoryAttribute = 0x00000010;
    private const uint ReparsePointAttribute = 0x00000400;
    private const int FileDispositionInfoClass = 4;

    private readonly SafeFileHandle _handle;

    private WindowsQuarantineFile(SafeFileHandle handle, FileStream stream)
    {
        _handle = handle;
        Stream = stream;
    }

    public FileStream Stream { get; }

    public static WindowsQuarantineFile Open(string path)
    {
        var handle = CreateFile(
            path,
            GenericRead | Delete,
            ShareRead,
            IntPtr.Zero,
            OpenExisting,
            SequentialScan | OpenReparsePoint,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error);
        }

        if (!GetFileInformationByHandle(handle, out var information))
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error);
        }

        if ((information.FileAttributes & (DirectoryAttribute | ReparsePointAttribute)) != 0)
        {
            handle.Dispose();
            throw new NotSupportedException(
                "Quarantine accepts regular files and does not follow reparse points.");
        }

        return new WindowsQuarantineFile(
            handle,
            new FileStream(handle, FileAccess.Read, 1024 * 1024, isAsync: false));
    }

    public void MarkForDeletion()
    {
        var information = new FileDispositionInformation { DeleteFile = 1 };
        if (!SetFileInformationByHandle(
                _handle,
                FileDispositionInfoClass,
                in information,
                (uint)Marshal.SizeOf<FileDispositionInformation>()))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    public void Dispose() => Stream.Dispose();

    [LibraryImport(
        "kernel32.dll",
        EntryPoint = "CreateFileW",
        SetLastError = true,
        StringMarshalling = StringMarshalling.Utf16)]
    private static partial SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation fileInformation);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetFileInformationByHandle(
        SafeFileHandle file,
        int fileInformationClass,
        in FileDispositionInformation fileInformation,
        uint bufferSize);

    [StructLayout(LayoutKind.Sequential)]
    private struct FileDispositionInformation
    {
        public int DeleteFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public FileTime CreationTime;
        public FileTime LastAccessTime;
        public FileTime LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime
    {
        public uint LowDateTime;
        public uint HighDateTime;
    }
}
