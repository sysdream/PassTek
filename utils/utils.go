package utils

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	htmltemplate "html/template"
	"image"
	"image/png"
	"math"
	"os"
	"reflect"
	"sort"
	"strings"
	ttemplate "text/template"

	"golang.org/x/image/draw"

	"github.com/yarlson/pin"
)

type Spinner struct {
	pin    *pin.Pin
	cancel context.CancelFunc
}

// Entry holds a key-value pair from a map[string]int.
type Entry struct {
	Key   string
	Value int
}

type Content struct {
	Title htmltemplate.HTML `json:"title"`
	Text  htmltemplate.HTML `json:"text"`
}

type Cells struct {
	A1 string `json:"A1"`
	B1 string `json:"B1"`
}

type HashStats struct {
	TotalNTLMHashes  int
	UniqueNTLMHashes int
	ReusedNTLMHashes int
	IsLM             int
	IsHash           bool
	EmptyNTLMHashes  int
	UserEqualHash    []string // Users with username equal hash
}

// Stats contains the statistics resulting from password analysis.
type Stats struct {
	CrackedCount      int            // Total number of Crackedpasswords
	TotalCount        int            // Total number of passwords/hashes
	Lengths           map[int]int    // Password lengths
	Complexity        map[int]int    // Password complexity
	Patterns          map[string]int // Patterns (e.g., "l" lower, "u" uper, "d" decimal, "s" special)
	Mostreuse         map[string]int // Password reuse counts
	CrackedReuseCount int            // Cracked password reuse counts
	TotalReuseCount   int            // Total password reuse counts
	TokenCount        map[string]int // words most used
	Hashes            HashStats      // Hash statistics
	GlobalPercent     float64        // Global percent
	Risk              string         // Risk
	Top               int            // Top number to be displayed
}

// Labels holds all translation strings structured by category.
// This structure matches the shape of your JSON translation files.
type Labels struct {
	Html struct {
		GlobalTitle  string `json:"global_title"`
		IsLogo       string
		Logo64       string
		Icon64       string
		IsClientLogo string
		ClientLogo64 string
		Summary      Content `json:"summary"`
		Length       Content `json:"length"`
		Complexity   Content `json:"complexity"`
		Occurrences  Content `json:"occurrences"`
		Patterns     Content `json:"patterns"`
		Mostreuse    Content `json:"mostreuse"`
		Reuse        Content `json:"reuse"`
		Remediation  Content `json:"remediation"`
	} `json:"html"`

	Length struct {
		A1      string `json:"A1"`
		B1      string `json:"B1"`
		Title   string `json:"title"`
		Short   string `json:"short"`
		Exact8  string `json:"exact8"`
		Exact9  string `json:"exact9"`
		Exact10 string `json:"exact10"`
		Long    string `json:"long"`
	} `json:"Length"`

	Complexity struct {
		A1    string `json:"A1"`
		B1    string `json:"B1"`
		Title string `json:"title"`
		One   string `json:"one"`
		Two   string `json:"two"`
		Three string `json:"three"`
		Four  string `json:"four"`
	} `json:"Complexity"`

	Occurrences struct {
		Title string `json:"title"`
		A1    string `json:"A1"`
		B1    string `json:"B1"`
	} `json:"Occurrences"`

	Pattern struct {
		Title string `json:"title"`
		A1    string `json:"A1"`
		B1    string `json:"B1"`
		L     string `json:"l"`
		U     string `json:"u"`
		S     string `json:"s"`
		D     string `json:"d"`
	} `json:"Pattern"`

	Mostreuse struct {
		Title string `json:"title"`
		Short string `json:"short"`
		A1    string `json:"A1"`
		B1    string `json:"B1"`
	} `json:"Mostreuse"`

	Reuse struct {
		Title  string `json:"title"`
		Total  string `json:"total"`
		Short  string `json:"short"`
		Unique string `json:"unique"`
		A1     string `json:"A1"`
		B1     string `json:"B1"`
	} `json:"Reuse"`

	Hash struct {
		TotalNTLM     string `json:"totalNTLM"`
		Cracked       string `json:"cracked"`
		UniqueNTLM    string `json:"uniqueNTLM"`
		Reused        string `json:"reused"`
		LM            string `json:"lm"`
		EmptyNTLM     string `json:"emptyNTLM"`
		Title         string `json:"title"`
		UserEqualHash string `json:"userEqualHash"`
	} `json:"Hash"`

	TotalCracked struct {
		Title string `json:"title"`
	} `json:"TotalCracked"`

	Total struct {
		Title string `json:"title"`
	} `json:"Total"`

	Risk struct {
		Low      string `json:"low"`
		Medium   string `json:"medium"`
		High     string `json:"high"`
		Critical string `json:"critical"`
	} `json:"Risk"`
}

// Hold all data labels + stats
type Data struct {
	Stats  Stats
	Labels Labels
}

// Percent returns part expressed as a percentage of the provided total,
// rounded to one decimal place. If total is zero the function returns 0 to
// avoid a division-by-zero error.
func Percent(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return math.Round((float64(part)/float64(total))*1000) / 10
}

// InsertStats takes the computed statistics along with the chosen language
// code and injects those numbers into the corresponding translation JSON
// template. The merged data are written to a temporary file named
// "tmp-<lang>.json" that downstream renderers (HTML, Excel, etc.) can load.
func InsertStats(lang string, data Data) error {

	filePath := fmt.Sprintf("lang/%s.json", lang)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("Language file not found: %s", lang)
	}

	funcMap := ttemplate.FuncMap{
		"sortMapByValueDesc": SortMapByValueDesc,
		"percent":            Percent,
		// Added alias to support existing templates using `formatPercent`
		"formatPercent": func(part, total int) float64 {
			if total == 0 {
				return 0
			}
			return math.Round((float64(part)/float64(total))*1000) / 10
		},
		"sumLengthRange": SumLengthRange,
		"escapeHTML":     func(s string) string { return html.EscapeString(s) },
		// Override the default index function with a safe variant that
		// returns nil instead of panicking when the requested element is
		// out of range. This prevents template execution errors on small
		// datasets.
		"index": func(item interface{}, i int) interface{} {
			v := reflect.ValueOf(item)
			switch v.Kind() {
			case reflect.Slice, reflect.Array:
				if i >= 0 && i < v.Len() {
					return v.Index(i).Interface()
				}
				// Out-of-range → return zero value of element type so that
				// subsequent field access (e.g., .Key, .Value) and type
				// assertions do not panic. Works for struct element types.
				zero := reflect.Zero(v.Type().Elem())
				return zero.Interface()
			case reflect.Map:
				keyVal := reflect.ValueOf(i)
				val := v.MapIndex(keyVal)
				if val.IsValid() {
					return val.Interface()
				}
				zero := reflect.Zero(v.Type().Elem())
				return zero.Interface()
			default:
				return nil
			}
		},
	}

	statsTmpl := ttemplate.Must(ttemplate.New("report").Funcs(funcMap).ParseFiles(filePath))

	out, err := os.Create("tmp-" + lang + ".json")
	if err != nil {
		return err
	}
	defer out.Close()

	// No need to use .ExecuteTemplate, unless you want to specify a name:
	err = statsTmpl.ExecuteTemplate(out, lang+".json", data)
	if err != nil {
		return err
	}

	return nil
}

// LoadLabels opens the temporary language file generated by InsertStats and
// unmarshals its JSON content into a Labels structure which is then returned
// to the caller. An error is returned if the file cannot be read or decoded.
func LoadLabels(lang string) (Labels, error) {
	var labels Labels

	filePath := fmt.Sprintf("tmp-%s.json", lang)

	file, err := os.Open(filePath)
	if err != nil {
		return labels, fmt.Errorf("[!][LoadLabels] Failed to open language file: %w", err)
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(&labels); err != nil {
		return labels, fmt.Errorf("[!][LoadLabels]Failed to decode language JSON: %w", err)
	}

	return labels, nil
}

// SumLengthRange calculates the sum of values in a map where the keys fall within a specified range.
func SumLengthRange(m map[int]int, min, max int) int {
	total := 0
	for k, v := range m {
		if k >= min && k <= max {
			total += v
		}
	}
	return total
}

// GetMaxLength returns the length of the longest key in the provided map.
// It is used to calculate padding when printing aligned text tables.
func GetMaxLength(m map[string]int) int {
	maxLen := 0
	for key := range m {
		if len(key) > maxLen {
			maxLen = len(key)
		}
	}
	return maxLen
}

// SplitOutputTypes converts a comma-separated list such as "text,html" into
// a slice of individual strings, trimming surrounding whitespace from each
// element.
func SplitOutputTypes(raw string) []string {
	var types []string
	for _, t := range strings.Split(raw, ",") {
		types = append(types, strings.TrimSpace(t))
	}
	return types
}

// SortMapByValueDesc takes a map[string]int and returns a slice of Entry,
// sorted by Value from highest to lowest.
func SortMapByValueDesc(m map[string]int) []Entry {
	entries := make([]Entry, 0, len(m))
	for k, v := range m {
		entries = append(entries, Entry{Key: k, Value: v})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Value > entries[j].Value
	})

	return entries
}

// MaxLabelLength returns the length of the longest string among the supplied
// label arguments.
func MaxLabelLength(labels ...string) int {
	max := 0
	for _, label := range labels {
		if len(label) > max {
			max = len(label)
		}
	}
	return max
}

// ImageToBase64 reads the file located at path and returns its contents as a
// base-64 encoded string. This is useful for embedding images directly into
// HTML without needing separate asset files.
func ImageToBase64(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("[ImageToBase64] failed to read file %s: %w", path, err)
	}

	encoded := base64.StdEncoding.EncodeToString(data)
	return encoded, nil
}

// MaskPassword anonymises a password by keeping the first two and last two
// characters visible and replacing the characters in between with '*'.
// If the password length is 4 or less, it is returned unchanged. UTF-8
// runes are respected so multi-byte characters are handled correctly.
func MaskPassword(pw string) string {
	runes := []rune(pw)
	n := len(runes)
	if n <= 4 {
		return pw
	}
	masked := strings.Repeat("*", n-4)
	return string(runes[:2]) + masked + string(runes[n-2:])
}

// MaskStats applies password masking to statistics maps that expose plaintext
// passwords so they can be safely displayed. Only the keys are masked; counts
// remain intact.
func MaskStats(s *Stats) {
	// Mask Mostreuse map keys
	maskedReuse := make(map[string]int, len(s.Mostreuse))
	for k, v := range s.Mostreuse {
		maskedReuse[MaskPassword(k)] = v
	}
	s.Mostreuse = maskedReuse
	// Occurrence keywords remain visible, do not mask
}

// SanitizeStats escapes HTML special characters in keys of statistics maps that are rendered
// into the HTML report. This prevents JavaScript/HTML injection when the keys originate from
// untrusted sources such as cracked passwords. The values are left untouched so the numerical
// statistics remain accurate.
func SanitizeStats(s *Stats) {
	sanitizeMap := func(src map[string]int) map[string]int {
		dst := make(map[string]int, len(src))
		for k, v := range src {
			dst[html.EscapeString(k)] = v
		}
		return dst
	}

	if s == nil {
		return
	}

	s.Mostreuse = sanitizeMap(s.Mostreuse)
	s.TokenCount = sanitizeMap(s.TokenCount)
}

// ResizeAndBase64 loads an image file, resizes it to the specified width and
// height, and returns the result as a base64-encoded PNG data string.
func ResizeAndBase64(path string, width, height int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open image: %w", err)
	}
	defer f.Close()

	img, _, err := image.Decode(f)
	if err != nil {
		return "", fmt.Errorf("decode image: %w", err)
	}

	// If width/height not provided, keep original.
	if width == 0 {
		width = img.Bounds().Dx()
	}
	if height == 0 {
		height = img.Bounds().Dy()
	}

	dst := image.NewRGBA(image.Rect(0, 0, width, height))
	// Use high-quality scaler.
	draw.CatmullRom.Scale(dst, dst.Bounds(), img, img.Bounds(), draw.Over, nil)

	var buf bytes.Buffer
	if err := png.Encode(&buf, dst); err != nil {
		return "", fmt.Errorf("encode png: %w", err)
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// New creates a new colored spinner instance with a custom message.
func NewSpinner(message string) *Spinner {
	s := &Spinner{
		pin: pin.New(message,
			pin.WithSpinnerColor(pin.ColorCyan),
			pin.WithTextColor(pin.ColorMagenta),
			pin.WithDoneSymbol('✔'),
			pin.WithFailSymbol('✖'),
		),
	}
	return s
}

// Start begins the spinner animation.
func (s *Spinner) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.pin.Start(ctx)
}

// UpdateMessage changes the current spinner message.
func (s *Spinner) UpdateMessage(newMessage string) {
	s.pin.UpdateMessage(newMessage)
}

// Stop stops the spinner with a success message.
func (s *Spinner) Stop(finalMessage string) {
	if s.cancel != nil {
		s.cancel()
	}
	s.pin.Stop(finalMessage)
}

// Fail stops the spinner with a failure message.
func (s *Spinner) Fail(failureMessage string) {
	if s.cancel != nil {
		s.cancel()
	}
	s.pin.Fail(failureMessage)
}

func MergeIntoSmaller(entities []Entry) []Entry {
	skip := make(map[int]bool)

	for i := 0; i < len(entities); i++ {
		if skip[i] {
			continue
		}
		for j := 0; j < len(entities); j++ {
			if i == j || skip[j] {
				continue
			}
			// If entities[i].Key contains entities[j].Key,
			// then merge i into j (add i's value to j, remove i)
			if strings.Contains(entities[i].Key, entities[j].Key) {
				entities[j].Value += entities[i].Value
				skip[i] = true
				break // i is merged, no need to continue
			}
		}
	}

	// Collect remaining (non-skipped) entities
	var result []Entry
	for i, e := range entities {
		if !skip[i] {
			result = append(result, e)
		}
	}
	return result
}
