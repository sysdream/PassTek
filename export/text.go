// Package export turns the raw statistics produced by the analysis package
// into human-readable reports (text, HTML, Excel, screenshots …).
package export

import (
	"fmt"
	"os"

	"password-analyzer/utils"
)

// ToText writes a `report.txt` file inside outputDir that summarises the
// supplied statistics in plain-text form. All labels come from the
// localised Labels struct so the same function can serve multiple languages.
// The helper is used when the user requests the "text" (or "all") output
// mode on the command line.
func ToText(stats utils.Stats, outputDir string, top int, labels utils.Labels) error {
	f, err := os.Create(outputDir + "/report.txt")
	if err != nil {
		return err
	}
	defer f.Close()

	// Hash analysis
	if stats.Hashes.IsHash {
		fmt.Fprintf(f, "\n=== %s ===\n", labels.Hash.Title)

		hashWidth := utils.MaxLabelLength(
			labels.Hash.TotalNTLM,
			labels.Hash.UniqueNTLM,
			labels.Hash.Reused,
			labels.Hash.LM,
			labels.Hash.EmptyNTLM,
			labels.Hash.UserEqualHash,
		)

		fmtStr := fmt.Sprintf("%%-%ds : %%d\n", hashWidth)
		fmt.Fprintf(f, fmtStr, labels.Hash.TotalNTLM, stats.Hashes.TotalNTLMHashes)
		fmt.Fprintf(f, fmtStr, labels.Hash.Cracked, stats.CrackedCount)
		fmt.Fprintf(f, fmtStr, labels.Hash.UniqueNTLM, stats.Hashes.UniqueNTLMHashes)
		fmt.Fprintf(f, fmtStr, labels.Hash.Reused, stats.Hashes.ReusedNTLMHashes)
		fmt.Fprintf(f, fmtStr, labels.Hash.LM, stats.Hashes.IsLM)
		fmt.Fprintf(f, fmtStr, labels.Hash.EmptyNTLM, stats.Hashes.EmptyNTLMHashes)
		if len(stats.Hashes.UserEqualHash) > 0 {
			fmt.Fprintf(f, fmtStr, labels.Hash.UserEqualHash, len(stats.Hashes.UserEqualHash))
		}
	}

	lengthWidth := utils.MaxLabelLength(
		labels.Length.Short,
		labels.Length.Exact8,
		labels.Length.Exact9,
		labels.Length.Exact10,
		labels.Length.Long,
	)

	// Reuse summary (reused vs unique) if no hash is provided
	if !stats.Hashes.IsHash {
		fmt.Fprintf(f, "\n=== %s ===\n", labels.Reuse.Title)
		reuseWidth := utils.MaxLabelLength(labels.Reuse.Short, labels.Reuse.Unique)
		fmtStrReuse := fmt.Sprintf("%%-%ds : %%d\n", reuseWidth)
		uniqueCount := stats.CrackedCount - stats.Hashes.ReusedNTLMHashes
		fmt.Fprintf(f, fmtStrReuse, labels.Reuse.Total, stats.CrackedCount)
		fmt.Fprintf(f, fmtStrReuse, labels.Reuse.Unique, uniqueCount)
		fmt.Fprintf(f, fmtStrReuse, labels.Reuse.Short, stats.Hashes.ReusedNTLMHashes)
	}

	// Length analysis
	fmt.Fprintf(f, "\n=== %s ===\n", labels.Length.Title)
	fmt.Fprintf(f, fmt.Sprintf("%%-%ds : %%d\n", lengthWidth), labels.Length.Short, utils.SumLengthRange(stats.Lengths, 0, 7))
	fmt.Fprintf(f, fmt.Sprintf("%%-%ds : %%d\n", lengthWidth), labels.Length.Exact8, stats.Lengths[8])
	fmt.Fprintf(f, fmt.Sprintf("%%-%ds : %%d\n", lengthWidth), labels.Length.Exact9, stats.Lengths[9])
	fmt.Fprintf(f, fmt.Sprintf("%%-%ds : %%d\n", lengthWidth), labels.Length.Exact10, stats.Lengths[10])
	fmt.Fprintf(f, fmt.Sprintf("%%-%ds : %%d\n", lengthWidth), labels.Length.Long, utils.SumLengthRange(stats.Lengths, 11, 100))

	complexityWidth := utils.MaxLabelLength(
		labels.Complexity.One,
		labels.Complexity.Two,
		labels.Complexity.Three,
		labels.Complexity.Four,
	)

	// Complexity analysis
	fmt.Fprintf(f, "\n=== %s ===\n", labels.Complexity.Title)
	fmt.Fprintf(f, fmt.Sprintf("%%-%ds : %%d\n", complexityWidth), labels.Complexity.One, stats.Complexity[1])
	fmt.Fprintf(f, fmt.Sprintf("%%-%ds : %%d\n", complexityWidth), labels.Complexity.Two, stats.Complexity[2])
	fmt.Fprintf(f, fmt.Sprintf("%%-%ds : %%d\n", complexityWidth), labels.Complexity.Three, stats.Complexity[3])
	fmt.Fprintf(f, fmt.Sprintf("%%-%ds : %%d\n", complexityWidth), labels.Complexity.Four, stats.Complexity[4])

	// Occurrences analysis
	fmt.Fprintf(f, "\n=== "+labels.Occurrences.Title+" ===\n")
	sortedWords := utils.SortMapByValueDesc(stats.TokenCount)
	maxLenWords := utils.GetMaxLength(stats.TokenCount)
	for _, s := range sortedWords[:top] {
		fmt.Fprintf(f, "%-*s : %d\n", maxLenWords, s.Key, s.Value)
	}

	// Pattern analysis
	fmt.Fprintf(f, "\n=== "+labels.Pattern.Title+" === (l = "+labels.Pattern.L+", u = "+labels.Pattern.U+", d = "+labels.Pattern.D+", s = "+labels.Pattern.S+")\n")
	sortedPattern := utils.SortMapByValueDesc(stats.Patterns)
	maxLenPattern := utils.GetMaxLength(stats.Patterns)

	// %-*s aligns the password to the left with dynamic width
	for _, s := range sortedPattern[:top] {
		fmt.Fprintf(f, "%-*s : %d\n", maxLenPattern, s.Key, s.Value)
	}

	// Most reuse analysis
	fmt.Fprintf(f, "\n=== "+labels.Mostreuse.Title+" ===\n")
	sortedReuse := utils.SortMapByValueDesc(stats.Mostreuse)
	maxLen := utils.GetMaxLength(stats.Mostreuse)

	// %-*s aligns the password to the left with dynamic width
	for _, s := range sortedReuse[:top] {
		fmt.Fprintf(f, "%-*s : %d\n", maxLen, s.Key, s.Value)
	}
	return nil
}
