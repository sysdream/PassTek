package export

import (
	"fmt"
	"log"
	"password-analyzer/utils"

	"github.com/xuri/excelize/v2"
)

// ToExcel produces a nicely-formatted `report.xlsx` workbook that contains
// the core statistics as raw tables and also embeds a series of 3-D pie
// charts for quick visual inspection. The workbook is stored in outputDir.
// The caller may specify how many top elements (words, patterns, …) should
// be included via the top parameter – currently the function still uses a
// hard-coded value of 5 but we keep the argument to allow future changes
// without breaking the signature.
func ToExcel(stats utils.Stats, outputDir string, top int, labels utils.Labels) {
	// Create a new Excel file
	f := excelize.NewFile()

	// Create Sheets
	err := f.SetSheetName("Sheet1", labels.Length.A1)
	if err != nil {
		log.Fatalf("[!][ToExcel][SetSheetName] Failed to rename sheet1: %v", err)
	}

	f.NewSheet(labels.Complexity.A1)
	f.NewSheet(labels.Occurrences.A1)
	f.NewSheet(labels.Pattern.A1)
	f.NewSheet(labels.Reuse.Short)
	f.NewSheet(labels.Mostreuse.Short)

	f.SetColWidth(labels.Length.A1, "A", "A", 25)
	f.SetColWidth(labels.Complexity.A1, "A", "A", 25)
	f.SetColWidth(labels.Occurrences.A1, "A", "A", 25)
	f.SetColWidth(labels.Pattern.A1, "A", "A", 25)
	f.SetColWidth(labels.Reuse.Short, "A", "A", 25)
	f.SetColWidth(labels.Mostreuse.Short, "A", "A", 25)

	// Variables used to compute the number of data rows for dynamic charts
	var occRows, patternRows, reuseRows int

	// Fill data into Excel -> Length
	f.SetCellValue(labels.Length.A1, "A1", labels.Length.A1)
	f.SetCellValue(labels.Length.A1, "B1", labels.Length.B1)

	f.SetCellValue(labels.Length.A1, "A"+string(rune(2+'0')), labels.Length.Short)
	f.SetCellValue(labels.Length.A1, "A"+string(rune(3+'0')), labels.Length.Exact8)
	f.SetCellValue(labels.Length.A1, "A"+string(rune(4+'0')), labels.Length.Exact9)
	f.SetCellValue(labels.Length.A1, "A"+string(rune(5+'0')), labels.Length.Exact10)
	f.SetCellValue(labels.Length.A1, "A"+string(rune(6+'0')), labels.Length.Long)

	f.SetCellValue(labels.Length.A1, "B"+string(rune(2+'0')), utils.SumLengthRange(stats.Lengths, 0, 7))
	f.SetCellValue(labels.Length.A1, "B"+string(rune(3+'0')), stats.Lengths[8])
	f.SetCellValue(labels.Length.A1, "B"+string(rune(4+'0')), stats.Lengths[9])
	f.SetCellValue(labels.Length.A1, "B"+string(rune(5+'0')), stats.Lengths[10])
	f.SetCellValue(labels.Length.A1, "B"+string(rune(6+'0')), utils.SumLengthRange(stats.Lengths, 11, 100))

	// Fill data into Excel -> Complexité
	f.SetCellValue(labels.Complexity.A1, "A1", labels.Complexity.A1)
	f.SetCellValue(labels.Complexity.A1, "B1", labels.Complexity.B1)

	f.SetCellValue(labels.Complexity.A1, "A"+string(rune(2+'0')), labels.Complexity.One)
	f.SetCellValue(labels.Complexity.A1, "A"+string(rune(3+'0')), labels.Complexity.Two)
	f.SetCellValue(labels.Complexity.A1, "A"+string(rune(4+'0')), labels.Complexity.Three)
	f.SetCellValue(labels.Complexity.A1, "A"+string(rune(5+'0')), labels.Complexity.Four)

	for i := 1; i < 5; i++ {
		f.SetCellValue(labels.Complexity.A1, "B"+string(rune(i+1+'0')), stats.Complexity[i])
	}

	// Fill data into Excel -> Occurrences
	f.SetCellValue(labels.Occurrences.A1, "A1", labels.Occurrences.A1)
	f.SetCellValue(labels.Occurrences.A1, "B1", labels.Occurrences.B1)

	sortedWords := utils.SortMapByValueDesc(stats.TokenCount)
	occRows = top
	if len(sortedWords) < occRows {
		occRows = len(sortedWords)
	}
	for i := 0; i < occRows; i++ {
		row := i + 2
		f.SetCellValue(labels.Occurrences.A1, fmt.Sprintf("A%d", row), sortedWords[i].Key)
		f.SetCellValue(labels.Occurrences.A1, fmt.Sprintf("B%d", row), sortedWords[i].Value)
	}

	// Fill data into Excel -> Patterns
	f.SetCellValue(labels.Pattern.A1, "A1", labels.Pattern.A1)
	f.SetCellValue(labels.Pattern.A1, "B1", labels.Pattern.B1)

	sortedPattern := utils.SortMapByValueDesc(stats.Patterns)
	patternRows = top
	if len(sortedPattern) < patternRows {
		patternRows = len(sortedPattern)
	}
	for i := 0; i < patternRows; i++ {
		row := i + 2
		f.SetCellValue(labels.Pattern.A1, fmt.Sprintf("A%d", row), sortedPattern[i].Key)
		f.SetCellValue(labels.Pattern.A1, fmt.Sprintf("B%d", row), sortedPattern[i].Value)
	}

	// Fill data into Excel -> Most reuse password
	f.SetCellValue(labels.Mostreuse.Short, "A1", labels.Mostreuse.A1)
	f.SetCellValue(labels.Mostreuse.Short, "B1", labels.Mostreuse.B1)

	sortedReuse := utils.SortMapByValueDesc(stats.Mostreuse)

	reuseRows = 0
	for i := 0; i < len(sortedReuse) && reuseRows < top; i++ {
		row := reuseRows + 2
		f.SetCellValue(labels.Mostreuse.Short, fmt.Sprintf("A%d", row), sortedReuse[i].Key)
		f.SetCellValue(labels.Mostreuse.Short, fmt.Sprintf("B%d", row), sortedReuse[i].Value)
		if sortedReuse[i].Value > 1 {
			stats.CrackedReuseCount += sortedReuse[i].Value
		}
		reuseRows++
	}

	// Fill data into Excel -> reuse
	// TODO dynamic

	f.SetCellValue(labels.Reuse.Short, "A1", labels.Reuse.A1)
	f.SetCellValue(labels.Reuse.Short, "B1", labels.Reuse.B1)
	f.SetCellValue(labels.Reuse.Short, "A2", labels.Reuse.Short)
	f.SetCellValue(labels.Reuse.Short, "B2", stats.Hashes.ReusedNTLMHashes)
	f.SetCellValue(labels.Reuse.Short, "A3", labels.Reuse.Unique)
	f.SetCellValue(labels.Reuse.Short, "B3", stats.Hashes.UniqueNTLMHashes)

	makePie(f, labels.Length.A1, labels.Length.Title, 6)
	makePie(f, labels.Complexity.A1, labels.Complexity.Title, 6)
	if occRows > 0 {
		makePie(f, labels.Occurrences.A1, labels.Occurrences.Title, occRows+1)
	}
	if patternRows > 0 {
		makePie(f, labels.Pattern.A1, labels.Pattern.Title, patternRows+1)
	}
	// Reuse sheet has only 2 data rows (A2/A3)
	makePie(f, labels.Reuse.Short, labels.Reuse.Title, 3)
	if reuseRows > 0 {
		makePie(f, labels.Mostreuse.Short, labels.Mostreuse.Title, reuseRows+1)
	}

	// Save the Excel file
	if err := f.SaveAs(outputDir + "/report.xlsx"); err != nil {
		log.Fatalf("[!][ToExcel][SaveAs] Failed to save Excel file: %v", err)
	}
}

// makePie is a small helper that appends a 3-D pie chart to the given sheet.
// It is kept unexported because chart generation is an internal detail of
// the Excel export logic.
func makePie(f *excelize.File, sheet string, title string, rows int) {
	// Add a pie chart
	if err := f.AddChart(sheet, "D2", &excelize.Chart{
		Type: excelize.Pie3D,
		Series: []excelize.ChartSeries{
			{
				Name:              "'" + sheet + "'" + "!$B$1",
				Categories:        fmt.Sprintf("'%s'!$A$2:$A$%d", sheet, rows),
				Values:            fmt.Sprintf("'%s'!$B$2:$B$%d", sheet, rows),
				DataLabelPosition: excelize.ChartDataLabelsPositionOutsideEnd,
			},
		},
		Title: []excelize.RichTextRun{
			{
				Text: title,
			},
		},
		PlotArea: excelize.ChartPlotArea{
			ShowPercent: true,
			ShowVal:     true,
		},
		Dimension: excelize.ChartDimension{
			Width:  1000,
			Height: 550,
		},
	}); err != nil {
		log.Fatalf("[!][ToExcel][makePie][AddChart] Failed to add chart: %v", err)
	}
}
