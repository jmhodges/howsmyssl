/*
The MIT License (MIT)

Copyright (c) 2014 Alex Saskevich

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package util

import (
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	maxURLRuneCount = 2083
	minURLRuneCount = 3

	IP           = `(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))`
	URLSchema    = `((ftp|tcp|udp|wss?|https?):\/\/)`
	URLUsername  = `(\S+(:\S*)?@)`
	URLPath      = `((\/|\?|#)[^\s]*)`
	URLPort      = `(:(\d{1,5}))`
	URLIP        = `([1-9]\d?|1\d\d|2[01]\d|22[0-3])(\.(1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.([0-9]\d?|1\d\d|2[0-4]\d|25[0-4]))`
	URLSubdomain = `((www\.)|([a-zA-Z0-9]+([-_\.]?[a-zA-Z0-9])*[a-zA-Z0-9]\.[a-zA-Z0-9]+))`
)

var (
	URL   = `^` + URLSchema + `?` + URLUsername + `?` + `((` + URLIP + `|(\[` + IP + `\])|(([a-zA-Z0-9]([a-zA-Z0-9-_]+)?[a-zA-Z0-9]([-\.][a-zA-Z0-9]+)*)|(` + URLSubdomain + `?))?(([a-zA-Z\x{00a1}-\x{ffff}0-9]+-?-?)*[a-zA-Z\x{00a1}-\x{ffff}0-9]+)(?:\.([a-zA-Z\x{00a1}-\x{ffff}]{1,}))?))\.?` + URLPort + `?` + URLPath + `?$`
	rxURL = regexp.MustCompile(URL)
)

// IsURL check if the string is an URL.
// This function is (graciously) adopted from
// https://github.com/asaskevich/govalidator to avoid needing a full dependency on
// `govalidator` for the one `IsURL` function.
func IsURL(str string) bool {
	if str == "" || utf8.RuneCountInString(str) >= maxURLRuneCount || len(str) <= minURLRuneCount || strings.HasPrefix(str, ".") {
		return false
	}
	if isPlainHostname(str) {
		return true
	}
	strTemp := str
	if strings.Contains(str, ":") && !strings.Contains(str, "://") {
		// support no indicated urlscheme but with colon for port number
		// http:// is appended so url.Parse will succeed, strTemp used so it does not impact rxURL.MatchString
		strTemp = "http://" + str
	}
	u, err := url.Parse(strTemp)
	if err != nil {
		return false
	}
	if strings.HasPrefix(u.Host, ".") {
		return false
	}
	if u.Host == "" && (u.Path != "" && !strings.Contains(u.Path, ".")) {
		return false
	}
	return rxURL.MatchString(str)
}

// isPlainHostname reports whether str, which has already passed the length and
// leading-dot guards of IsURL, is certainly accepted by IsURL because it is a
// plain ASCII multi-label hostname. It exists only to skip url.Parse and rxURL
// for the overwhelmingly common case of DNS names.
//
// The result is one-sided: true means IsURL would return true; false means
// "not sure" and the caller must run the full url.Parse and rxURL check.
// Anything outside the shapes below, including names that rxURL would accept,
// returns false.
//
// The check is a deterministic finite automaton (fastStart, fastStep,
// fastAccept) over the alphabet [A-Za-z0-9.-]; any other byte goes to the dead
// state. All counters in the state are bounded, so the state space is finite,
// and TestFastPathLanguageInclusion in isURL_proof_test.go decides language
// inclusion against rxURL exactly, for every string length.
//
// Derivation from rxURL. For input made only of [A-Za-z0-9.-] the scheme,
// username, port and path groups cannot match (they need one of "://", "@",
// ":", "/", "?" or "#"), and url.Parse cannot fail, never yields a Host, and
// leaves a Path that contains a dot, so only the host part decides:
//
//	[P] C [ "." TLD ] [ "." ]
//
// where C is one or more alphanumerics with hyphen runs of at most two,
// starting and ending alphanumeric (no dots), TLD is one or more letters and P
// is either empty or "[A-Za-z0-9][A-Za-z0-9-_]*[A-Za-z0-9]([-.][A-Za-z0-9]+)*"
// (the "www." and subdomain alternatives are not used here). The rules below
// each build one such match, so they are sufficient and deliberately not
// necessary:
//
//   - a trailing dot is left to the regexp (its "\.?" would accept one, but the
//     last label must then end with a letter or digit, which excludes it here);
//   - letters are ASCII letters of either case;
//   - the name has at least four bytes, at least two labels and no empty label
//     (so no leading or doubled dot), and every label starts and ends with a
//     letter or digit;
//   - the last label is TLD and contains letters only;
//   - with two labels, the first label is C: hyphen runs of at most two;
//   - with three or more labels, P covers the first label (at least two
//     characters, any hyphens), every middle label (hyphen runs of at most
//     one, since P continues with single-hyphen "-x" or ".x" pieces) and the
//     first character of the second-to-last label together with the dot
//     before it; C is the rest of the second-to-last label, so that label
//     needs at least two characters, an alphanumeric second character and
//     hyphen runs of at most two.
//
// The regexp imposes no per-label or per-name length cap; the overall length
// bounds are the guards in IsURL.
func isPlainHostname(str string) bool {
	st := fastStart
	for i := 0; i < len(str); i++ {
		var ok bool
		if st, ok = fastStep(st, str[i]); !ok {
			return false
		}
	}
	return fastAccept(st)
}

// fastState is a state of the plain hostname automaton. The zero value is the
// start state. Every field is bounded, so there are finitely many states; the
// dead state is the one with dead set and every other field zero.
//
// A name is a dot-separated sequence of labels. The label being read is
// described by pos, run, hy1Bad, hy2Bad, secBad and nonLetter; completed
// labels are folded into done, firstA, firstB, midBad, prevOK and prevMid so
// that the rule that applies to a label (first, middle, second-to-last, last)
// can be decided once the end of the name is known.
type fastState struct {
	dead bool

	// total is the number of bytes read, capped at 4.
	total uint8
	// done is the number of completed labels, capped at 2.
	done uint8

	// firstA: the first label has hyphen runs of at most two (rule for a
	// two-label name). firstB: it has at least two characters (rule for three
	// or more labels).
	firstA, firstB bool
	// midBad: some middle label has a hyphen run of two or more.
	midBad bool
	// prevOK: the last completed label (not the first) satisfies the
	// second-to-last rule. prevMid: it satisfies the middle rule.
	prevOK, prevMid bool

	// pos is the length of the current label, capped at 2.
	pos uint8
	// run is the current hyphen run, capped at 3.
	run uint8
	// hy1Bad: the current label had a hyphen run of two or more. hy2Bad: of
	// three or more.
	hy1Bad, hy2Bad bool
	// secBad: the second character of the current label is a hyphen.
	secBad bool
	// nonLetter: the current label has a character that is not a letter.
	nonLetter bool
}

var fastStart fastState

var fastDead = fastState{dead: true}

// fastStep returns the state after reading b from st, and false when the
// result is the dead state.
func fastStep(st fastState, b byte) (fastState, bool) {
	if st.dead {
		return fastDead, false
	}
	if st.total < 4 {
		st.total++
	}
	switch {
	case isASCIIAlnum(b):
		if st.pos < 2 {
			st.pos++
		}
		st.run = 0
		if !isASCIILetter(b) {
			st.nonLetter = true
		}
	case b == '-':
		if st.pos == 0 {
			return fastDead, false
		}
		if st.pos == 1 {
			st.secBad = true
			st.pos = 2
		}
		if st.run < 3 {
			st.run++
		}
		st.hy1Bad = st.hy1Bad || st.run >= 2
		st.hy2Bad = st.hy2Bad || st.run >= 3
		st.nonLetter = true
	case b == '.':
		if st.pos == 0 || st.run != 0 {
			return fastDead, false
		}
		okA := !st.hy2Bad
		okSecond := st.pos >= 2 && !st.secBad && okA
		switch st.done {
		case 0:
			st.firstA, st.firstB = okA, st.pos >= 2
			st.done = 1
		case 1:
			st.done = 2
		default:
			st.midBad = st.midBad || !st.prevMid
		}
		st.prevOK, st.prevMid = okSecond, !st.hy1Bad
		st.pos, st.run = 0, 0
		st.hy1Bad, st.hy2Bad, st.secBad, st.nonLetter = false, false, false, false
	default:
		return fastDead, false
	}
	return st, true
}

// fastAccept reports whether the bytes read so far form a plain hostname: at
// least four bytes, a last label of letters only that ends in a letter, and
// the rules for the labels before it.
func fastAccept(st fastState) bool {
	if st.dead || st.total < 4 || st.pos == 0 || st.run != 0 || st.nonLetter {
		return false
	}
	switch st.done {
	case 0:
		return false
	case 1:
		return st.firstA
	default:
		return st.firstB && !st.midBad && st.prevOK
	}
}

func isASCIILetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isASCIIAlnum(c byte) bool {
	return isASCIILetter(c) || c >= '0' && c <= '9'
}
