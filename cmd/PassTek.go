package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"password-analyzer/analysis"
	"password-analyzer/export"
	"password-analyzer/utils"

	"github.com/leaanthony/spinner"
)

func main() {
	// -----------------------
	// Command-line arguments
	// -----------------------
	passwordFile := flag.String("p", "", "Password file (one per line)")
	outputTypes := flag.String("f", "all", "Output types (text, html, excel, screenshot, all)")
	lang := flag.String("l", "fr", "Output language (en,fr)")
	outputDir := flag.String("o", "output", "Output directory")
	hashFile := flag.String("H", "", "Hash file (username:rid:lmhash:nthash:::)")
	logo := flag.String("L", "img/logo_sysdream.png", "Company logo file (png)")
	clientLogo := flag.String("cL", "", "Client logo file (png)")
	maskPasswords := flag.Bool("anon", false, "Anonymize passwords (show first 2 and last 2 characters)")
	minCharOccurences := flag.Int("min", 5, "Minimum number of characters to be considered as an occurrence")
	top := flag.Int("top", 5, "Top N entries to display in charts and tables")
	flag.Parse()

	fmt.Println(`
     ▗▄▄▖  ▗▄▖  ▗▄▄▖ ▗▄▄▖▗▄▄▄▖▗▄▄▄▖▗▖ ▗▖
     ▐▌ ▐▌▐▌ ▐▌▐▌   ▐▌     █  ▐▌   ▐▌▗▞▘
     ▐▛▀▘ ▐▛▀▜▌ ▝▀▚▖ ▝▀▚▖  █  ▐▛▀▀▘▐▛▚▖ 
     ▐▌   ▐▌ ▐▌▗▄▄▞▘▗▄▄▞▘  █  ▐▙▄▄▖▐▌ ▐▌                     
                                 
            Made with 🍉 by leco`)

	fmt.Println("\x1b[34m==============================================\033[0m")
	s := spinner.New("Starting Up")
	s.Start()

	// Remove temporary language files on exit
	defer func() {
		file := fmt.Sprintf("tmp-%s.json", *lang)
		_ = os.Remove(file)
	}()

	// Security: simple path-traversal prevention for -o flag
	baseDir, _ := os.Getwd()
	outAbs, err := filepath.Abs(*outputDir)
	if err != nil {
		s.Errorf("Something went wrong")
		log.Fatalf("[!][main] cannot resolve output directory: %v", err)
	}
	rel, err := filepath.Rel(baseDir, outAbs)
	if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		s.Errorf("Something went wrong")
		log.Fatal("[!][main] invalid -o path: outside working directory is not allowed")
	}
	*outputDir = rel // cleaned safe relative path

	if *passwordFile == "" {
		s.Errorf("Something went wrong")
		log.Fatal("[!][main] Please specify an input file using -p")
	}
	if *outputDir == "" {
		s.Errorf("Something went wrong")
		log.Fatal("[!][main] Please specify an output directory using -o")
	}

	err = os.Mkdir(*outputDir, 0755)
	if err != nil && !os.IsExist(err) {
		// Any error other than “already exists”
		s.Errorf("Something went wrong")
		log.Printf("[!][main] Cannot create %s: %v", *outputDir, err)
	}

	s.UpdateMessage("Analyzing passwords")
	data, err := analysis.AnalyzePasswords(*passwordFile, *minCharOccurences)
	if err != nil {
		s.Errorf("Something went wrong")
		log.Fatalf("[!][main][AnalyzePasswords] Error reading passwords: %v", err)
	}
	data.Stats.Top = *top

	if *hashFile != "" {
		s.UpdateMessage("Analyzing hashes")
		data.Stats.Hashes, err = analysis.AnalyzeHashes(*hashFile)
		if err != nil {
			s.Errorf("Something went wrong")
			log.Fatalf("[!][main][AnalyzeHashes] Error reading hashes: %v", err)
		}
		data.Stats.Hashes.IsHash = true

		// Detect accounts where password equals their username
		data.Stats.Hashes.UserEqualHash, err = analysis.UsernameAsPass(*hashFile)
		if err != nil {
			s.Errorf("Something went wrong")
			log.Printf("[!][main][UsersWithUsernameEqualHash] %v", err)
		}

		// Sanity check: the hash file must not contain fewer entries than the password list
		if data.Stats.Hashes.TotalNTLMHashes < data.Stats.CrackedCount {
			s.Errorf("Something went wrong")
			log.Fatalf("[!][main] Hash file contains fewer lines (%d) than password file (%d)", data.Stats.Hashes.TotalNTLMHashes, data.Stats.CrackedCount)
		}
	} else {
		// No hash file provided – derive comparable stats from cracked passwords so that templates work.
		fmt.Println("\x1b[33m[WARNING]\x1b[37m No hash file (-H) provided: some hash-based statistics will be based on password cracked data and may be less representative.")
		data.Stats.Hashes.TotalNTLMHashes = data.Stats.CrackedCount
		data.Stats.Hashes.ReusedNTLMHashes = data.Stats.CrackedReuseCount
		data.Stats.Hashes.UniqueNTLMHashes = data.Stats.CrackedCount - data.Stats.CrackedReuseCount
		data.Stats.Hashes.IsHash = false
	}

	s.UpdateMessage("Risk evaluation")
	// Evaluate risk and global percent if hash file or not
	if data.Stats.Hashes.IsHash {
		data.Stats.Risk, data.Stats.GlobalPercent = analysis.EvaluateRisk(
			*lang,
			utils.Percent(data.Stats.Hashes.ReusedNTLMHashes, data.Stats.Hashes.TotalNTLMHashes),
			utils.Percent(data.Stats.Complexity[1]+data.Stats.Complexity[2]+data.Stats.Complexity[3], data.Stats.CrackedCount),
			utils.Percent(utils.SumLengthRange(data.Stats.Lengths, 0, 10), data.Stats.CrackedCount),
			utils.Percent(data.Stats.CrackedCount, data.Stats.Hashes.TotalNTLMHashes),
		)
	} else {
		data.Stats.Risk, data.Stats.GlobalPercent = analysis.EvaluateRisk(
			*lang,
			utils.Percent(data.Stats.Hashes.ReusedNTLMHashes, data.Stats.Hashes.TotalNTLMHashes),
			utils.Percent(data.Stats.Complexity[1]+data.Stats.Complexity[2]+data.Stats.Complexity[3], data.Stats.CrackedCount),
			utils.Percent(utils.SumLengthRange(data.Stats.Lengths, 0, 10), data.Stats.CrackedCount),
		)
	}

	// Apply masking if requested
	if *maskPasswords {
		s.UpdateMessage("Masking passwords")
		utils.MaskStats(&data.Stats)
	}

	// Note: HTML escaping is now handled directly in the language templates via the
	// escapeHTML helper, so we keep the raw statistics here for correct legend display.

	// Insert stats into json file
	err = utils.InsertStats(*lang, data)
	if err != nil {
		s.Errorf("Something went wrong")
		log.Fatalf("[!][main][InsertStats] Error templating json file: %v", err)
	}

	// Load labels from json file
	data.Labels, err = utils.LoadLabels(*lang)
	if err != nil {
		s.Errorf("Something went wrong")
		log.Fatalf("[!][main][LoadLabels] Error loading language file: %v", err)
	}

	// Load logos (after loading labels) else hidden img
	if *logo == "" {
		data.Labels.Html.IsLogo = "hidden"
	} else {
		data.Labels.Html.Logo64, err = utils.ImageToBase64(*logo)
		if err != nil {
			s.Errorf("Something went wrong")
			log.Fatalf("[!][main][ImageToBase64] Error loading logo: %v", err)
		}

	}
	if *clientLogo == "" {
		data.Labels.Html.IsClientLogo = "hidden"
	} else {
		data.Labels.Html.ClientLogo64, err = utils.ImageToBase64(*clientLogo)
		if err != nil {
			s.Errorf("Something went wrong")
			log.Fatalf("[!][main][ImageToBase64] Error loading client logo: %v", err)
		}
	}

	for _, output := range utils.SplitOutputTypes(*outputTypes) {
		switch output {
		case "text":
			s.UpdateMessage("Generating text report")
			export.ToText(data.Stats, *outputDir, *top, data.Labels)
			s.Success("[+] Saved text report to " + *outputDir + "/report.txt")
		case "html":
			s.UpdateMessage("Generating HTML report")
			export.ToHtml(data.Stats, *outputDir, data)
			s.Success("[+] Saved HTML report to " + *outputDir + "/report.html")
		case "excel":
			s.UpdateMessage("Generating Excel report")
			export.ToExcel(data.Stats, *outputDir, *top, data.Labels)
			s.Success("[+] Saved Excel report to " + *outputDir + "/report.xlsx")
		case "screenshot":
			err := os.Mkdir(*outputDir+"/screenshots", 0755)
			if err != nil && !os.IsExist(err) {
				// Any error other than “already exists”
				s.Errorf("Something went wrong")
				log.Fatalf("[!][main] Cannot create %s: %v", *outputDir+"/screenshots", err)
			}
			s.UpdateMessage("Generating screenshots")
			export.ToPNG(data.Stats, data.Labels, *outputDir)
			s.Success("[+] Saved screenshots to " + *outputDir + "/screenshots")
		case "pdf":
			s.UpdateMessage("Generating PDF report")
			export.ToHtml(data.Stats, *outputDir, data)
			export.ToPDF(*outputDir)
			s.Success("[+] Saved PDF report to " + *outputDir + "/report.pdf")
			// Remove report.html file once PDF is generated
			err := os.Remove(*outputDir + "/report.html")
			if err != nil {
				s.Errorf("Something went wrong")
				log.Fatalf("[!][main][Remove] Cannot remove %s: %v", *outputDir+"/report.html", err)
			}
		case "all":
			err := os.Mkdir(*outputDir+"/screenshots", 0755)
			if err != nil && !os.IsExist(err) {
				// Any error other than “already exists”
				s.Errorf("Something went wrong")
				log.Fatalf("[!][main] Cannot create %s: %v", *outputDir, err)
			}
			s.UpdateMessage("Generating text report")
			time.Sleep(2 * time.Second)
			export.ToText(data.Stats, *outputDir, *top, data.Labels)
			s.Success("[+] Saved text report to " + *outputDir + "/report.txt")
			s.Start("Generating HTML report")
			time.Sleep(2 * time.Second)
			export.ToHtml(data.Stats, *outputDir, data)
			s.Success("[+] Saved HTML report to " + *outputDir + "/report.html")
			s.Start("Generating PDF report")
			time.Sleep(2 * time.Second)
			export.ToPDF(*outputDir)
			s.Success("[+] Saved PDF report to " + *outputDir + "/report.pdf")
			s.Start("Generating Excel report")
			time.Sleep(2 * time.Second)
			export.ToExcel(data.Stats, *outputDir, *top, data.Labels)
			s.Success("[+] Saved Excel report to " + *outputDir + "/report.xlsx")
			s.Start("Generating screenshots")
			time.Sleep(2 * time.Second)
			export.ToPNG(data.Stats, data.Labels, *outputDir)
			s.Success("[+] Saved screenshots to " + *outputDir + "/screenshots")
		default:
			s.Errorf("Something went wrong")
			log.Fatalf("[!][main] Unknown output type: %s\n", output)
		}
	}
	fmt.Print("\x1b[34m==============================================\033[0m\n\n")
}
