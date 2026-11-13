package fairplay

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"os"
	"testing"
)

func BenchmarkOutputCompression(b *testing.B) {
	data := bytes.Repeat([]byte("synthetic ARM64 workload and inline data table\x00\xff"), 200000)
	if source := os.Getenv("DESK_PUBLIC_COMPRESSION_SAMPLE"); source != "" {
		var err error
		data, err = os.ReadFile(source)
		if err != nil {
			b.Fatal(err)
		}
	}
	for _, level := range []int{flate.BestSpeed, 3, flate.DefaultCompression} {
		b.Run(fmt.Sprint(level), func(b *testing.B) {
			var dst bytes.Buffer
			w, err := flate.NewWriter(&dst, level)
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(data)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				dst.Reset()
				w.Reset(&dst)
				if _, err = w.Write(data); err != nil {
					b.Fatal(err)
				}
				if err = w.Close(); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(dst.Len()), "compressed-bytes")
			reader := flate.NewReader(bytes.NewReader(dst.Bytes()))
			restored, err := io.ReadAll(reader)
			reader.Close()
			if err != nil || !bytes.Equal(restored, data) {
				b.Fatal("compression round-trip failed", err)
			}
		})
	}
}
func BenchmarkPageDecryption(b *testing.B) {
	deriver := newPageKeyDeriver([16]byte{1, 2, 3})
	for _, pages := range []int{1, 4, 16, 64, 256} {
		image := encryptedImage{layout: machoLayout{cryptSize: uint32(pages * pageBytes)}}
		data := make([]byte, pages*pageBytes)
		records := make([][32]byte, pages)
		b.Run(fmt.Sprintf("%d/current", pages), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := decryptPagesInPlace(data, image, records, deriver); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("%d/serial", pages), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				for n := 0; n < pages; n++ {
					key := deriver.pageKey(records[n][:16], uint64(n*pageBytes))
					block, _ := aes.NewCipher(key[:])
					cipher.NewCBCDecrypter(block, records[n][16:]).CryptBlocks(data[n*pageBytes:(n+1)*pageBytes], data[n*pageBytes:(n+1)*pageBytes])
				}
			}
		})
	}
}
