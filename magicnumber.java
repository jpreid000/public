// Image formats
new MagicSignature(new byte[]{0x47, 0x49, 0x46, 0x38, 0x37, 0x61}, 0, "image/gif"),       // GIF87a
new MagicSignature(new byte[]{0x47, 0x49, 0x46, 0x38, 0x39, 0x61}, 0, "image/gif"),       // GIF89a
new MagicSignature(new byte[]{(byte)0xFF, (byte)0xD8, (byte)0xFF}, 0, "image/jpeg"),      // JPEG/JPG/PJPEG
new MagicSignature(new byte[]{(byte)0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, 0, "image/png"), // PNG
new MagicSignature(new byte[]{0x49, 0x49, 0x2A, 0x00}, 0, "image/tiff"),                 // TIFF little-endian
new MagicSignature(new byte[]{0x4D, 0x4D, 0x00, 0x2A}, 0, "image/tiff"),                 // TIFF big-endian
new MagicSignature(new byte[]{0x42, 0x4D}, 0, "image/bmp"),                              // BMP

// PDF
new MagicSignature(new byte[]{0x25, 0x50, 0x44, 0x46}, 0, "application/pdf"),            // PDF

// MS Office (old formats)
new MagicSignature(new byte[]{(byte)0xD0, (byte)0xCF, 0x11, (byte)0xE0, (byte)0xA1, (byte)0xB1, 0x1A, (byte)0xE1}, 0, "application/msword"), // DOC, XLS, PPT
// Note: The magic above applies for msword, ms-excel, ms-powerpoint, and ms-outlook (all "OLE2" files). 
// You may want to assign this to "application/vnd.ms-office" and then determine the specific type by extension.


// MS Office (new formats, all are ZIP-based)
new MagicSignature(new byte[]{0x50, 0x4B, 0x03, 0x04}, 0, "application/zip"),           // ZIP, DOCX, XLSX, PPTX
// Note: Need to check [Content_Types].xml within for real content, but this magic works as a first filter.


// RTF
new MagicSignature(new byte[]{0x7B, 0x5C, 0x72, 0x74, 0x66}, 0, "application/rtf"),     // RTF ("{\rtf")

// Outlook MSG (compound file, same as old Office)
new MagicSignature(new byte[]{(byte)0xD0, (byte)0xCF, 0x11, (byte)0xE0, (byte)0xA1, (byte)0xB1, 0x1A, (byte)0xE1}, 0, "application/vnd.ms-outlook"),

// RFC822 E-mail (no standard magic number, could check for "From " at start, but unreliable)

// MPEG Video
new MagicSignature(new byte[]{0x00, 0x00, 0x01, (byte)0xBA}, 0, "video/mpeg"),          // MPEG PS
new MagicSignature(new byte[]{0x00, 0x00, 0x01, (byte)0xB3}, 0, "video/mpeg"),          // MPEG

// QuickTime MOV
new MagicSignature(new byte[]{0x00, 0x00, 0x00, 0x14, 0x66, 0x74, 0x79, 0x70, 0x71, 0x74, 0x20, 0x20}, 0, "video/quicktime"), // MOV
// (But better to check offset 4 for "ftypqt  ")

// AVI
new MagicSignature(new byte[]{0x52, 0x49, 0x46, 0x46}, 0, "video/x-msvideo"),           // AVI ("RIFF" ... "AVI " at offset 8)

// 3GP
new MagicSignature(new byte[]{0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x33, 0x67, 0x70, 0x35}, 0, "video/3gpp"), // 3GP
// (Check offset 4 for "ftyp3gp5")

// MP4
new MagicSignature(new byte[]{0x66, 0x74, 0x79, 0x70}, 4, "video/mp4"),                 // MP4 ("ftyp" at offset 4)

// FLV
new MagicSignature(new byte[]{0x46, 0x4C, 0x56}, 0, "video/x-flv"),                     // FLV

// MPEG TS
new MagicSignature(new byte[]{0x47}, 0, "video/mp2t"),                                  // MPEG-TS (188-byte packets, but header is 0x47)

// WMV
new MagicSignature(new byte[]{0x30, 0x26, (byte)0xB2, 0x75, 0x8E, 0x66, (byte)0xCF, 0x11, (byte)0xA6, (byte)0xD9}, 0, "video/x-ms-wmv"), // WMV

// WAV (RIFF)
new MagicSignature(new byte[]{0x52, 0x49, 0x46, 0x46}, 0, "audio/wav"),                 // WAV ("RIFF" ... "WAVE" at offset 8)

// WMA (ASF/WMF container)
new MagicSignature(new byte[]{0x30, 0x26, (byte)0xB2, 0x75, 0x8E, 0x66, (byte)0xCF, 0x11, (byte)0xA6, (byte)0xD9}, 0, "audio/x-ms-wma"), // WMA (ASF/WMF header)

// Plain text, XML, CSV: NO magic number.  
// Heuristic: Check if file starts with "<?xml" (XML), ASCII/UTF8 chars and commas (CSV), or is generally printable (plain text).

new MagicSignature(new byte[]{0x45, 0x50, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x44, 0x49, 0x20}, 0, "image/vnd.ms-modi"),

import java.io.FileInputStream;
import java.io.IOException;
import java.util.*;

public class MagicNumberDetector {

    static class MagicSignature {
        final byte[] signature;
        final int offset; // Offset to check the signature
        final String mimeType;

        MagicSignature(byte[] signature, int offset, String mimeType) {
            this.signature = signature;
            this.offset = offset;
            this.mimeType = mimeType;
        }
    }

    static List<MagicSignature> signatures = List.of(
        new MagicSignature(new byte[]{0x25, 0x50, 0x44, 0x46}, 0, "application/pdf"),
        new MagicSignature(new byte[]{(byte)0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, 0, "image/png"),
        new MagicSignature(new byte[]{(byte)0xFF, (byte)0xD8, (byte)0xFF}, 0, "image/jpeg"),
        new MagicSignature(new byte[]{0x47, 0x49, 0x46, 0x38, 0x37, 0x61}, 0, "image/gif"), // GIF87a
        new MagicSignature(new byte[]{0x47, 0x49, 0x46, 0x38, 0x39, 0x61}, 0, "image/gif"), // GIF89a
        new MagicSignature(new byte[]{0x50, 0x4B, 0x03, 0x04}, 0, "application/zip"),
        new MagicSignature(new byte[]{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00}, 0, "application/x-rar-compressed"),
        new MagicSignature(new byte[]{0x37, 0x7A, (byte)0xBC, (byte)0xAF, 0x27, 0x1C}, 0, "application/x-7z-compressed"),
        new MagicSignature(new byte[]{(byte)0xD0, (byte)0xCF, 0x11, (byte)0xE0, (byte)0xA1, (byte)0xB1, 0x1A, (byte)0xE1}, 0, "application/vnd.ms-office"),
        new MagicSignature(new byte[]{0x49, 0x44, 0x33}, 0, "audio/mpeg"), // MP3 with ID3
        new MagicSignature(new byte[]{0x4D, 0x5A}, 0, "application/x-msdownload"), // EXE
        new MagicSignature(new byte[]{0x7F, 0x45, 0x4C, 0x46}, 0, "application/x-elf"), // ELF
        new MagicSignature(new byte[]{0x66, 0x74, 0x79, 0x70}, 4, "video/mp4") // MP4 (ftyp at offset 4)
    );

    public static String detectMimeType(String filePath) throws IOException {
        int maxLen = signatures.stream().mapToInt(s -> s.signature.length + s.offset).max().orElse(0);
        try (FileInputStream is = new FileInputStream(filePath)) {
            byte[] fileHeader = new byte[maxLen];
            int read = is.read(fileHeader);
            if (read == -1) return "empty";

            for (MagicSignature sig : signatures) {
                if (read < sig.offset + sig.signature.length) continue;
                boolean match = true;
                for (int i = 0; i < sig.signature.length; i++) {
                    if (fileHeader[sig.offset + i] != sig.signature[i]) {
                        match = false;
                        break;
                    }
                }
                if (match) return sig.mimeType;
            }
        }
        return "unknown or plain text";
    }

    public static void main(String[] args) throws IOException {
        System.out.println(detectMimeType("testfile.pdf"));
    }
}
