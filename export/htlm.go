package export

import (
	"html/template"
	"log"
	"math"
	"os"
	"password-analyzer/utils"
)

// ToHtml renders an HTML report using the Go `html/template` engine and the
// pre-built template found under `export/template/template.html`. The final
// document is written to `outputDir/report.html` and includes interactive
// charts (AmCharts) and language-specific strings provided via the Data
// structure.
func ToHtml(stats utils.Stats, outputDir string, data utils.Data) {

	funcMap := template.FuncMap{
		"sumLengthRange":     utils.SumLengthRange,
		"sortMapByValueDesc": utils.SortMapByValueDesc,
		"add":                func(a, b int) int { return a + b },
		"percent": func(part, total int) float64 {
			if total == 0 {
				return 0
			}
			return math.Round((float64(part)/float64(total))*1000) / 10 // one decimal place
		},
		"sub": func(a, b int) int {
			return a - b
		},
	}

	langTmpl := template.Must(template.New("report").Funcs(funcMap).ParseFiles("export/template/template.html"))

	path := outputDir + "/report.html"
	out, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer out.Close()

	// No need to use .ExecuteTemplate, unless you want to specify a name:
	err = langTmpl.ExecuteTemplate(out, "template.html", data)
	if err != nil {
		log.Fatalf("[!][ToHtml][ExecuteTemplate] Failed to execute template: %v", err)
	}
}
