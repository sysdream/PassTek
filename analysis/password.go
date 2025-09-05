package analysis

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"password-analyzer/utils"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// AnalyzePasswords scans the password file located at filename, computes a
// broad set of statistics (length distribution, complexity, patterns, token
// frequency, reuse, …) and returns them wrapped inside a utils.Data value
// along with any error encountered while reading. The function expects one
// plaintext password per line.
func AnalyzePasswords(filename string, minCharOccurences int) (utils.Data, error) {
	// Extract “base words” exactly like Pipal’s basic checker: sequences of
	// 4 or more alphabetic characters. Digits/symbols are ignored here – they
	// are handled later by the deleet() transformation which converts common
	// leet-speak characters (e.g. “0”→"o", "4"→"a") to their alphabetic
	// equivalents.

	tokenRegex := regexp.MustCompile(`[A-Za-z01345$!|@é]{4,}`)
	data := utils.Data{
		Stats: utils.Stats{
			CrackedCount: 0,
			Lengths:      make(map[int]int),
			Complexity:   make(map[int]int),
			Patterns:     make(map[string]int),
			Mostreuse:    make(map[string]int),
			TokenCount:   make(map[string]int),
		},
		Labels: utils.Labels{},
	}

	file, err := os.Open(filename)
	if err != nil {
		return data, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineCount := 0 // track number of non-empty password lines
	for scanner.Scan() {
		line := scanner.Text()
		matchingStrings := tokenRegex.FindAllString(line, -1)
		if line == "" {
			continue
		}
		lineCount++
		length, category := countCategories(line)
		var pattern []rune
		data.Stats.Lengths[length]++
		data.Stats.Complexity[category]++
		data.Stats.Mostreuse[line]++
		data.Stats.CrackedCount++

		// Get password pattern (l,u,d,s)
		for _, r := range line {
			pattern = append(pattern, classifyChar(r))
		}
		data.Stats.Patterns[string(pattern)]++

		// reads passwords and counts all alphanumeric and special char tokens
		for _, matched := range matchingStrings {
			lowermatched := strings.ToLower(matched)

			unLeeted := Unleet(lowermatched)
			if len(unLeeted) >= minCharOccurences {
				data.Stats.TokenCount[unLeeted]++
			}
		}
	}

	sortedEntries := utils.SortMapByValueDesc(data.Stats.TokenCount)
	sortedEntries = utils.MergeIntoSmaller(sortedEntries)

	// --- Alternative analysis: strip leet-derived suffix (i,e,a,s,o) when length remains ≥4 ---
	truncatedCounts := make(map[string]int, len(data.Stats.TokenCount))
	for tk, val := range data.Stats.TokenCount {
		base := truncateLeetSuffix(tk)
		if len(base) >= minCharOccurences {
			truncatedCounts[base] += val
		} else {
			truncatedCounts[tk] += val
		}
	}
	truncatedEntries := utils.MergeIntoSmaller(utils.SortMapByValueDesc(truncatedCounts))

	// Keep the analysis whose most frequent token has the highest count
	chosenEntries := sortedEntries
	if getMaxCount(truncatedEntries) > getMaxCount(sortedEntries) {
		chosenEntries = truncatedEntries
	}

	// Update TokenCount map with consolidated values
	data.Stats.TokenCount = make(map[string]int, len(chosenEntries))
	for _, entry := range chosenEntries {
		data.Stats.TokenCount[entry.Key] = entry.Value
	}

	// Ensure the file contained at least two valid password lines to avoid downstream crashes
	if lineCount < 2 {
		return data, fmt.Errorf("Password file must contain at least 2 passwords")
	}

	// total reused passwords count
	data.Stats.CrackedReuseCount = 0
	for _, n := range data.Stats.Mostreuse {
		if n > 1 {
			data.Stats.CrackedReuseCount += n
		}
	}

	return data, scanner.Err()
}

func countCategories(password string) (int, int) {
	var hasLower, hasUpper, hasDigit, hasSpecial bool

	for _, c := range password {
		switch {
		case classifyChar(c) == 'l':
			hasLower = true
		case classifyChar(c) == 'u':
			hasUpper = true
		case classifyChar(c) == 'd':
			hasDigit = true
		case classifyChar(c) != 'l' && classifyChar(c) != 'd' && classifyChar(c) != 'u':
			hasSpecial = true
		}
	}

	count := 0
	if hasLower {
		count++
	}
	if hasUpper {
		count++
	}
	if hasDigit {
		count++
	}
	if hasSpecial {
		count++
	}

	return len(password), count
}

func classifyChar(r rune) rune {
	switch {
	case unicode.IsUpper(r):
		return 'u'
	case unicode.IsLower(r):
		return 'l'
	case unicode.IsDigit(r):
		return 'd'
	default:
		return 's'
	}
}

// AnalyzeHashes parses a pwdump-style text file whose lines follow the
// pattern `username:rid:lmhash:nthash:::`. It returns aggregated hash
// statistics (total, unique, reused ‑ LM presence, …). Malformed lines are
// skipped silently.
func AnalyzeHashes(hashFile string) (utils.HashStats, error) {
	const emptyLM = "aad3b435b51404eeaad3b435b51404ee"   // canonical disabled LM hash
	const emptyNTLM = "31d6cfe0d16ae931b73c59d7e0c089c0" // NTLM hash of empty string

	f, err := os.Open(hashFile)
	if err != nil {
		return utils.HashStats{}, fmt.Errorf("[utils][ComputeHashStats] cannot open %s: %w", hashFile, err)
	}
	defer f.Close()

	var stats utils.HashStats
	ntlmSeen := make(map[string]int)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue // skip malformed lines
		}

		lm := parts[2]
		ntlm := parts[3]

		// NTLM accounting
		isEmptyNTLM := ntlm == "" || strings.EqualFold(ntlm, emptyNTLM)
		if isEmptyNTLM {
			stats.EmptyNTLMHashes++
		}
		stats.TotalNTLMHashes++
		if _, ok := ntlmSeen[ntlm]; !ok {
			ntlmSeen[ntlm] = 1
		} else {
			ntlmSeen[ntlm]++
		}

		// LM accounting (real LM hashes present?)
		if lm != "" && !strings.EqualFold(lm, emptyLM) {
			stats.IsLM++
		}
	}

	// get uniq ntlm hashes
	for _, count := range ntlmSeen {
		if count == 1 {
			stats.UniqueNTLMHashes++
		}
	}

	if err := scanner.Err(); err != nil {
		return utils.HashStats{}, fmt.Errorf("[!][utils][ComputeHashStats] scan error: %w", err)
	}

	stats.ReusedNTLMHashes = stats.TotalNTLMHashes - stats.UniqueNTLMHashes

	return stats, nil
}

// EvaluateRisk takes a variable list of percentage metrics (password reuse,
// weak length share, cracked-rate …) and turns them into a single textual
// risk level (Low/Medium/High/Critical) plus the averaged score. All input
// metrics are weighted evenly; tweak the function if you need a different
// balance.
func EvaluateRisk(lang string, percentages ...float64) (string, float64) {
	if len(percentages) == 0 {
		return "N/A", 0
	}

	// Compute the average of supplied percentages
	sum := 0.0
	for _, p := range percentages {
		sum += p
	}
	score := sum / float64(len(percentages)) // still 0–100 range if inputs are

	score = math.Round(score*100) / 100 // round to 2 decimals

	var riskLabels utils.Labels

	filePath := fmt.Sprintf("lang/%s.json", lang)

	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("[!][EvaluateRisk] Failed to open language file: %s", err)
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(&riskLabels); err != nil {
		log.Printf("[!][EvaluateRisk]Failed to decode language JSON: %s", err)
	}

	switch {
	case score < 25:
		return riskLabels.Risk.Low, score
	case score < 50:
		return riskLabels.Risk.Medium, score
	case score < 75:
		return riskLabels.Risk.High, score
	default:
		return riskLabels.Risk.Critical, score
	}
}

// Common leet-speak substitutions
var leetMap = map[rune]rune{
	'0': 'o',
	'1': 'i',
	'3': 'e',
	'4': 'a',
	'5': 's',
	'$': 's',
	'!': 'i',
	'|': 'i',
	'@': 'a',
	'é': 'e',
	'è': 'e',
	'à': 'a',
	'ù': 'u',
	'ç': 'c',
	'ï': 'i',
}

// deleet converts common leet-speak characters to their alphabetic
// equivalents so that words such as “p@ssw0rd” and “p4ssword” collapse to the
// same base form “password”.
func Unleet(token string) string {
	var b strings.Builder
	for _, r := range token {
		if repl, ok := leetMap[r]; ok {
			b.WriteRune(repl)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// truncateLeetSuffix removes the final rune when it equals one of the common
// leet-speak replacements (i,e,a,s,o). If no truncation rule applies, the
// token is returned unchanged.
func truncateLeetSuffix(token string) string {
	if len(token) < 5 { // need at least 4 chars after cut
		return token
	}
	switch token[len(token)-1] {
	case 'i', 'e', 'a', 's', 'o':
		return token[:len(token)-1]
	default:
		return token
	}
}

// getMaxCount returns the highest Value among a slice of Entry. Returns 0
// when the slice is empty.
func getMaxCount(entries []utils.Entry) int {
	if len(entries) == 0 {
		return 0
	}
	return entries[0].Value // entries are sorted desc
}

// NtlmHash returns the NTLM hash of the given string.
func NtlmHash(password string) string {
	// Convert string to UTF-16LE
	utf16Chars := utf16.Encode([]rune(password))
	bytes := make([]byte, len(utf16Chars)*2)
	for i, v := range utf16Chars {
		bytes[i*2] = byte(v)
		bytes[i*2+1] = byte(v >> 8)
	}

	// Compute MD4 hash
	h := md4.New()
	h.Write(bytes)
	return hex.EncodeToString(h.Sum(nil))
}

// This function reads a hash file (username:RID:LM:NT:::)
// and returns the list of usernames equal to their hash.
func UsernameAsPass(hashFile string) ([]string, error) {

	file, err := os.Open(hashFile)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w", hashFile, err)
	}
	defer file.Close()

	var matches []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue // malformed line
		}

		// Extract bare username (strip optional domain prefix)
		account := parts[0]
		if idx := strings.LastIndex(account, "\\"); idx != -1 {
			account = account[idx+1:]
		}

		ntlmHash := strings.ToLower(parts[3])
		if ntlmHash == "" {
			continue // empty NTLM field
		}

		if strings.EqualFold(NtlmHash(account), ntlmHash) {
			matches = append(matches, account)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan error: %w", err)
	}

	return matches, nil
}
