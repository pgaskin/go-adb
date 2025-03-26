package android

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

// https://cs.android.com/android/platform/superproject/main/+/main:external/mksh/src/lex.c;drc=2e46594a0b7f5014d1a6751020dabe80e576c954
// https://cs.android.com/android/platform/superproject/main/+/main:external/mksh/src/eval.c;drc=a5d35a625a246b18a75388646d6b9b861c6dda4b

// QuoteShell quotes the provided arguments for /system/bin/sh.
func QuoteShell(arg ...string) string {
	var b bytes.Buffer
	for i, a := range arg {
		if i != 0 {
			b.WriteByte(' ')
		}
		quote(a, &b)
	}
	return b.String()
}

const (
	specialChars      = "\\'\"`${[|&;<>()*?!"
	extraSpecialChars = " \t\n"
	prefixChars       = "~"
)

// based on [go-shellquote], but modified to work better with the android shell
//
// original implementation Copyright (C) 2014 Kevin Ballard
//
// [go-shellquote]: https://github.com/kballard/go-shellquote/blob/95032a82bc518f77982ea72343cc1ade730072f0/quote.go
func quote(word string, buf *bytes.Buffer) {
	// We want to try to produce a "nice" output. As such, we will
	// backslash-escape most characters, but if we encounter a space, or if we
	// encounter an extra-special char (which doesn't work with
	// backslash-escaping) we switch over to quoting the whole word. We do this
	// with a space because it's typically easier for people to read multi-word
	// arguments when quoted with a space rather than with ugly backslashes
	// everywhere.
	origLen := buf.Len()

	if len(word) == 0 {
		// oops, no content
		buf.WriteString("''")
		return
	}

	cur, prev := word, word
	atStart := true
	for len(cur) > 0 {
		c, l := utf8.DecodeRuneInString(cur)
		cur = cur[l:]
		if strings.ContainsRune(specialChars, c) || (atStart && strings.ContainsRune(prefixChars, c)) {
			// copy the non-special chars up to this point
			if len(cur) < len(prev) {
				buf.WriteString(prev[0 : len(prev)-len(cur)-l])
			}
			buf.WriteByte('\\')
			buf.WriteRune(c)
			prev = cur
		} else if strings.ContainsRune(extraSpecialChars, c) {
			// start over in quote mode
			buf.Truncate(origLen)
			goto quote
		}
		atStart = false
	}
	if len(prev) > 0 {
		buf.WriteString(prev)
	}
	return

quote:
	// quote mode
	// Use single-quotes, but if we find a single-quote in the word, we need
	// to terminate the string, emit an escaped quote, and start the string up
	// again
	inQuote := false
	for len(word) > 0 {
		i := strings.IndexRune(word, '\'')
		if i == -1 {
			break
		}
		if i > 0 {
			if !inQuote {
				buf.WriteByte('\'')
				inQuote = true
			}
			buf.WriteString(word[0:i])
		}
		word = word[i+1:]
		if inQuote {
			buf.WriteByte('\'')
			inQuote = false
		}
		buf.WriteString("\\'")
	}
	if len(word) > 0 {
		if !inQuote {
			buf.WriteByte('\'')
		}
		buf.WriteString(word)
		buf.WriteByte('\'')
	}
}
