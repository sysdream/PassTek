package export

import (
	"context"
	"log"
	"os"
	"password-analyzer/utils"
	"path/filepath"
	"sync"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// ToPNG spins up a headless Chrome instance (via chromedp), loads the
// previously-generated HTML report and captures PNG screenshots of each
// chart element. The images are saved under `outputDir/screenshots/` and are
// primarily intended for inclusion in other documents (presentations, PDFs,
// …).
func ToPNG(stats utils.Stats, labels utils.Labels, outputDir string) {

	// Get the current executable's directory
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("[!][ToPNG] Error getting executable path: %v", err)
	}
	exeDir := filepath.Dir(exePath)

	// Look for HTML file in same folder
	htmlFile := filepath.Join(exeDir, outputDir+"/report.html")
	if _, err := os.Stat(htmlFile); err != nil {
		log.Fatalf("[!][ToPNG] HTML file not found: %s\n[!][ToPNG] Please make sure the 'template.html' in the export folder and that you are not using go run.", htmlFile)
	}

	// List of chart div IDs and desired output PNG filenames (built conditionally)
	charts := []struct {
		ID   string
		File string
	}{}

	charts = append(charts, struct{ ID, File string }{"chart-length", outputDir + "/screenshots/chart-" + labels.Length.A1 + ".png"})
	charts = append(charts, struct{ ID, File string }{"chart-complexity", outputDir + "/screenshots/chart-" + labels.Complexity.A1 + ".png"})

	// Add occurrences chart only if we have more than 1 token occurrence
	if len(stats.TokenCount) > 1 {
		charts = append(charts, struct{ ID, File string }{"chart-top-passwords", outputDir + "/screenshots/chart-" + labels.Occurrences.A1 + ".png"})
	}

	charts = append(charts, struct{ ID, File string }{"chart-patterns", outputDir + "/screenshots/chart-" + labels.Pattern.A1 + ".png"})
	charts = append(charts, struct{ ID, File string }{"chart-reused", outputDir + "/screenshots/chart-" + labels.Reuse.Short + ".png"})
	charts = append(charts, struct{ ID, File string }{"chart-mostreused", outputDir + "/screenshots/chart-" + labels.Mostreuse.Short + ".png"})

	// Create Chrome headless context
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	content, err := os.ReadFile(htmlFile)
	if err != nil {
		log.Fatalf("[!][ToPNG] Error reading HTML file: %v", err)
	}

	// Load page blank page and inject HTML content (workarount error with chromerdp unknown IPAddressSpace value: Local)
	err = chromedp.Run(ctx,
		chromedp.Navigate("about:blank"),
		chromedp.ActionFunc(func(ctx context.Context) error {
			lctx, cancel := context.WithCancel(ctx)
			defer cancel()
			var wg sync.WaitGroup
			wg.Add(1)

			chromedp.ListenTarget(lctx, func(ev interface{}) {
				if _, ok := ev.(*page.EventLoadEventFired); ok {
					cancel()
					wg.Done()
				}
			})

			frameTree, err := page.GetFrameTree().Do(lctx)
			if err != nil {
				return err
			}

			if err := page.SetDocumentContent(frameTree.Frame.ID, string(content)).Do(ctx); err != nil {
				return err
			}

			wg.Wait()
			return nil
		}),
		// wait for all charts to render
		chromedp.Sleep(5*time.Second), // Wait for JS/charts to render; increase if needed
		// Hide amCharts export menu so it does not appear on PNG captures
		chromedp.Evaluate(`Array.from(document.querySelectorAll('.amcharts-amexport-menu')).forEach(el => el.style.display = 'none')`, nil),
	)
	if err != nil {
		log.Fatalf("[!][ToPNG][Run] Error loading HTML: %v", err)
	}

	// Loop through each chart and capture as PNG
	for _, chart := range charts {
		var buf []byte
		err := chromedp.Run(ctx,
			emulation.SetDeviceMetricsOverride(1920, 900, 1.0, false). // 1920x900 is the size of the screen for the screenshot
											WithScreenOrientation(&emulation.ScreenOrientation{
					Type:  emulation.OrientationTypePortraitPrimary,
					Angle: 0,
				}),
			chromedp.Screenshot("#"+chart.ID, &buf, chromedp.NodeVisible, chromedp.ByID),
		)
		if err != nil {
			log.Fatalf("[!][ToPNG][Run] Error capturing %s: %v", chart.ID, err)
			continue
		}
		err = os.WriteFile(filepath.Join(exeDir, chart.File), buf, 0644)
		if err != nil {
			log.Fatalf("[!][ToPNG] Error writing file %s: %v", chart.File, err)
			continue
		}
	}
}
