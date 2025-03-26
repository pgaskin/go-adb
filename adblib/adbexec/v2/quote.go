package adbexec

import "github.com/pgaskin/go-adb/internal/android"

// Quote quotes arguments for the shell.
func Quote(args ...string) string {
	return android.QuoteShell(args...)
}
