// cpc — copy files from each subfolder of <source> into <dest>/<subfolder>/,
// with a live progress bar. Skips directories deeper than one level.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func main() {
	src := flag.String("src", "", "source folder (contains subfolders to copy from)")
	dst := flag.String("dst", "", "destination folder")
	flag.Usage = func() {
		fmt.Println(`cpc — copy files from subfolders with progress

Usage:
  cpc -src <source> -dst <destination>
  cpc <source> <destination>

Copies only files (not nested directories) from each immediate subfolder
of <source> into a same-named subfolder of <destination>.`)
	}
	flag.Parse()

	if *src == "" && flag.NArg() >= 1 {
		*src = flag.Arg(0)
	}
	if *dst == "" && flag.NArg() >= 2 {
		*dst = flag.Arg(1)
	}

	if *src == "" || *dst == "" {
		flag.Usage()
		os.Exit(1)
	}
	if err := run(*src, *dst); err != nil {
		fmt.Fprintf(os.Stderr, "\033[0;31m✗ %s\033[0m\n", err)
		os.Exit(1)
	}
}

func run(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("source: %w", err)
	}
	if !srcInfo.IsDir() {
		return errors.New("source must be a directory")
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return fmt.Errorf("destination: %w", err)
	}

	subdirs, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range subdirs {
		if !e.IsDir() {
			continue
		}
		if err := copyOneSubfolder(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
			return err
		}
	}
	fmt.Println("\033[0;32m✓ Transfer complete\033[0m")
	return nil
}

func copyOneSubfolder(srcSub, dstSub string) error {
	if err := os.MkdirAll(dstSub, 0o755); err != nil {
		return err
	}
	files, err := flatFiles(srcSub)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return nil
	}
	fmt.Printf("\033[1;34m●\033[0m %s → %s (%d files)\n", srcSub, dstSub, len(files))
	for i, f := range files {
		if err := copyFile(f, filepath.Join(dstSub, filepath.Base(f))); err != nil {
			return err
		}
		printProgress(i+1, len(files), filepath.Base(f))
	}
	fmt.Println()
	return nil
}

func flatFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Type().IsRegular() {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out, nil
}

func copyFile(src, dst string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	defer s.Close()
	d, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer d.Close()
	if _, err := io.Copy(d, s); err != nil {
		return err
	}
	if info, err := s.Stat(); err == nil {
		_ = os.Chmod(dst, info.Mode())
	}
	return nil
}

func printProgress(cur, total int, current string) {
	pct := 100 * cur / total
	width := 30
	filled := width * cur / total
	bar := ""
	for i := 0; i < width; i++ {
		if i < filled {
			bar += "█"
		} else {
			bar += "·"
		}
	}
	if len(current) > 40 {
		current = current[:37] + "..."
	}
	fmt.Printf("\r  [%s] %3d%% %s        ", bar, pct, current)
}
